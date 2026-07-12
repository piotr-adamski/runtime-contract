#!/usr/bin/env python3
"""Run the four-command E2E matrix from an installed wheel outside the checkout."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Outcome:
    code: int
    stdout: str
    stderr: str


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain(value: str) -> str:
    return ANSI_ESCAPE.sub("", value)


def run(binary: Path, cwd: Path, *arguments: str) -> Outcome:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = ""
    environment["PYTHONHASHSEED"] = "1"
    completed = subprocess.run(
        [str(binary), *arguments],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return Outcome(completed.returncode, completed.stdout, completed.stderr)


def require(outcome: Outcome, code: int, *, report: bool) -> None:
    if outcome.code != code:
        raise RuntimeError(
            f"unexpected exit code {outcome.code}, expected {code}: {outcome.stderr[:300]}"
        )
    if report and (not outcome.stdout or outcome.stderr):
        raise RuntimeError("report command did not use stdout exclusively")
    if not report and (outcome.stdout or not outcome.stderr):
        raise RuntimeError("error command did not use stderr exclusively")
    if "SUPER_SECRET_CANARY" in outcome.stdout + outcome.stderr:
        raise RuntimeError("E2E output exposed the redaction canary")


def require_help(outcome: Outcome, *fragments: str) -> None:
    if outcome.code or not outcome.stdout or outcome.stderr:
        raise RuntimeError("installed CLI help did not use stdout exclusively")
    if any(fragment not in plain(outcome.stdout) for fragment in fragments):
        raise RuntimeError("installed CLI help is missing a required first-use fragment")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    fixture = args.fixture.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix="runtime-contract-wheel-e2e-") as value:
        root = Path(value)
        venv = root / "venv"
        subprocess.run(["uv", "venv", "--python", args.python, str(venv)], check=True)
        python = venv / "bin/python"
        subprocess.run(["uv", "pip", "install", "--python", str(python), str(wheel)], check=True)
        binary = venv / "bin/runtime-contract"
        workspace = root / "workspace"
        workspace.mkdir()
        full = workspace / "full-stack"
        shutil.copytree(fixture, full)
        clean = workspace / "clean"
        clean.mkdir()
        (clean / "app.py").write_text(
            'import os\nos.getenv("OPTIONAL", "safe-placeholder")\n', encoding="utf-8"
        )
        defective = workspace / "defective"
        defective.mkdir()
        (defective / "app.py").write_text('import os\nos.environ["REQUIRED"]\n', encoding="utf-8")
        invalid = workspace / "invalid-config"
        invalid.mkdir()
        (invalid / "runtime-contract.yaml").write_text(
            "version: 99\nvalue: SUPER_SECRET_CANARY\n", encoding="utf-8"
        )
        corrupt = workspace / "corrupt"
        corrupt.mkdir()
        (corrupt / "app.py").write_bytes(b"\xff")

        require_help(
            run(binary, workspace, "--help"),
            "runtime-contract scan .",
            "built-in defaults < YAML",
        )
        for command in ("scan", "check", "explain", "diff"):
            require_help(
                run(binary, workspace, command, "--help"),
                "Examples:",
                f"runtime-contract {command}",
            )
        typo = run(binary, workspace, "sacn")
        require(typo, 2, report=False)
        if "Did you mean 'scan'?" not in plain(typo.stderr):
            raise RuntimeError("installed CLI did not suggest the intended command")
        option_typo = run(binary, workspace, "scan", "--formt", "json")
        require(option_typo, 2, report=False)
        if "Possible options: --format" not in plain(option_typo.stderr):
            raise RuntimeError("installed CLI did not suggest the intended option")

        for output_format in ("text", "json", "sarif"):
            require(
                run(binary, workspace, "scan", str(full), "--format", output_format),
                0,
                report=True,
            )
            require(
                run(binary, workspace, "check", str(defective), "--format", output_format),
                1,
                report=True,
            )
            require(
                run(binary, workspace, "scan", str(corrupt), "--format", output_format),
                2,
                report=True,
            )
        for output_format in ("text", "json"):
            explain = run(
                binary, workspace, "explain", "RTC001", str(defective), "--format", output_format
            )
            require(explain, 0, report=True)
            difference = run(
                binary, workspace, "diff", str(clean), str(defective), "--format", output_format
            )
            require(difference, 0, report=True)

        require(
            run(binary, workspace, "explain", "RTC001", str(defective), "--format", "sarif"),
            2,
            report=False,
        )
        require(
            run(binary, workspace, "diff", str(clean), str(defective), "--format", "sarif"),
            2,
            report=False,
        )
        require(run(binary, workspace, "scan", str(invalid)), 2, report=False)
        require(run(binary, workspace, "check", str(invalid)), 2, report=False)
        require(run(binary, workspace, "explain", "RTC001", str(invalid)), 2, report=False)
        require(run(binary, workspace, "diff", str(invalid), str(clean)), 2, report=False)
        clean_scan = run(binary, workspace, "scan", str(clean), "--format", "json")
        require(clean_scan, 0, report=True)
        clean_check = run(binary, workspace, "check", str(clean), "--format", "json")
        require(clean_check, 0, report=True)
        if json.loads(clean_scan.stdout)["status"] != "complete":
            raise RuntimeError("clean wheel scan was not complete")
        source = run(
            python, workspace, "-c", "import runtime_contract; print(runtime_contract.__file__)"
        )
        if source.code or str(fixture.parents[2]) in source.stdout:
            raise RuntimeError("E2E imported runtime-contract from the checkout")
    print("wheel four-command E2E: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
