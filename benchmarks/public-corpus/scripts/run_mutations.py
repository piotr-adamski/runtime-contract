"""Controlled, value-blind witnesses derived from pinned corpus deployment patterns."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
from pathlib import Path

from common import write_json

APP = 'import os\nos.environ["DATABASE_URL"]\n'
COMPOSE = "services:\n  app:\n    environment:\n      DATABASE_URL: ${DATABASE_URL}\n"
KUBE = "apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec:\n  containers:\n    - name: app\n      envFrom:\n        - configMapRef: {name: absent}\n"


def cases() -> list[dict[str, object]]:
    pydantic = 'from pydantic_settings import BaseSettings\nfrom pydantic import Field\nclass Settings(BaseSettings):\n    connection: str = Field(..., validation_alias="DATABASE_URL")\n'
    return [
        {
            "id": "missing-delivery",
            "before": {"app.py": APP, "compose.yaml": COMPOSE},
            "after": {"app.py": APP, "compose.yaml": "services:\n  app:\n    image: python\n"},
            "rule": "RTC001",
            "status": "complete",
        },
        {
            "id": "wrong-phase",
            "before": {
                "app.py": APP,
                "Dockerfile": "FROM python\nENV DATABASE_URL=${DATABASE_URL}\n",
            },
            "after": {"app.py": APP, "Dockerfile": "FROM python\nARG DATABASE_URL\n"},
            "rule": "RTC010",
            "status": "complete",
        },
        {
            "id": "sensitive-literal",
            "before": {
                "app.py": APP.replace("DATABASE_URL", "SECRET_TOKEN"),
                "compose.yaml": COMPOSE.replace("DATABASE_URL", "SECRET_TOKEN"),
            },
            "after": {
                "app.py": APP.replace("DATABASE_URL", "SECRET_TOKEN"),
                "compose.yaml": "services:\n  app:\n    environment:\n      SECRET_TOKEN: controlled-nonsecret-mutation-witness\n",
            },
            "rule": "RTC002",
            "status": "complete",
        },
        {
            "id": "pydantic-alias",
            "before": {"app.py": pydantic, "compose.yaml": COMPOSE},
            "after": {
                "app.py": pydantic.replace('"DATABASE_URL"', '"ALIAS_CHANGED"'),
                "compose.yaml": COMPOSE,
            },
            "rule": "RTC001",
            "status": "complete",
        },
        {
            "id": "dynamic-name",
            "before": {"app.py": APP, "compose.yaml": COMPOSE},
            "after": {
                "app.py": 'import os\nname = "DATABASE_URL"\nos.environ[name]\n',
                "compose.yaml": COMPOSE,
            },
            "rule": "RTC006",
            "status": "partial",
        },
        {
            "id": "unresolved-envfrom",
            "before": {
                "app.py": APP,
                "pod.yaml": KUBE,
                "config.yaml": 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: absent}\ndata: {DATABASE_URL: ""}\n',
            },
            "after": {"app.py": APP, "pod.yaml": KUBE},
            "rule": "RTC009",
            "status": "complete",
        },
        {
            "id": "cross-component-delivery",
            "before": {
                "app/app.py": APP,
                "app/compose.yaml": COMPOSE,
                "other/empty.py": "pass\n",
                "runtime-contract.yaml": "version: 1\nroots: {app: app, other: other}\n",
            },
            "after": {
                "app/app.py": APP,
                "other/compose.yaml": COMPOSE,
                "other/empty.py": "pass\n",
                "runtime-contract.yaml": "version: 1\nroots: {app: app, other: other}\n",
            },
            "rule": "RTC001",
            "status": "complete",
        },
        {
            "id": "conflicting-default",
            "before": {
                "app.py": 'import os\nos.getenv("MODE", "fallback")\n',
                "Dockerfile": "FROM python\nENV MODE=one\n",
            },
            "after": {
                "app.py": 'import os\nos.getenv("MODE", "fallback")\n',
                "Dockerfile": "FROM python\nENV MODE=one\n",
                "Dockerfile.alternative": "FROM python\nENV MODE=two\n",
            },
            "rule": "RTC007",
            "status": "complete",
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        subprocess.check_output([str(args.cli), "--version"], text=True).strip()
        != "runtime-contract 0.1.2"
    ):
        raise ValueError("mutation baseline version mismatch")
    rows = []
    for case in cases():
        observations = {}
        for state in ("before", "after"):
            root = args.workspace / str(case["id"]) / state
            root.mkdir(parents=True)
            files = case[state]
            assert isinstance(files, dict)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            completed = subprocess.run(
                [str(args.cli), "scan", str(root), "--format", "json"],
                capture_output=True,
                env={"PATH": os.defpath, "LANG": "C.UTF-8"},
                timeout=30,
            )
            report = json.loads(completed.stdout)
            observations[state] = {
                "status": report["status"],
                "exit_code": completed.returncode,
                "rules": sorted({item["rule_id"] for item in report["findings"]}),
                "diagnostics": sorted({item["code"] for item in report["diagnostics"]}),
                "consumers": report["summary"]["consumers"],
                "providers": report["summary"]["providers"],
            }
        patch = []
        for name in sorted(set(case["before"]) | set(case["after"])):  # type: ignore[arg-type]
            old = case["before"].get(name, "")  # type: ignore[union-attr]
            new = case["after"].get(name, "")  # type: ignore[union-attr]
            patch.extend(
                difflib.unified_diff(
                    old.splitlines(True),
                    new.splitlines(True),
                    fromfile="before/" + name,
                    tofile="after/" + name,
                )
            )
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / f"{case['id']}.patch").write_text("".join(patch))
        matched = (
            case["rule"] in observations["after"]["rules"]
            and observations["after"]["status"] == case["status"]
        )
        rows.append(
            {
                "id": case["id"],
                "expected_rule": case["rule"],
                "expected_status": case["status"],
                "observed": observations,
                "expectation_met": matched,
                "control_excludes_expected_rule": case["rule"]
                not in observations["before"]["rules"],
            }
        )
    write_json(args.output / "results.json", rows)
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
