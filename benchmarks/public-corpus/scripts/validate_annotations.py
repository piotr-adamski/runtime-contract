"""Validate complete annotation coverage and the public security-redaction boundary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import BASE, SECURITY_REASON, slug
from jsonschema import Draft202012Validator


def validate(rows: list[dict[str, Any]], measurements: list[dict[str, Any]], raw: Path) -> None:
    schema = json.loads((BASE / "schemas/annotation.schema.json").read_text())
    validator = Draft202012Validator(schema)
    expected = {}
    for run in measurements:
        name = slug(run) + "." + run["mode"]
        path = raw / f"{name}.json"
        if run["status"] == "technical_failure":
            continue
        report = json.loads(path.read_text())
        keys = {item["id"]: item["name"] for item in report["contract"]["config_keys"]}
        for finding in report["findings"]:
            identity = (run["repository"], run["mode"], finding["id"])
            if identity in expected:
                raise ValueError("duplicate raw finding identity")
            expected[identity] = (run, finding, keys)
    observed = set()
    for row in rows:
        validator.validate(row)
        identity = (row["repository"], row["mode"], row["finding_id"])
        if identity in observed:
            raise ValueError("duplicate annotation")
        observed.add(identity)
        if identity not in expected:
            raise ValueError("annotation has no matching raw finding")
        run, finding, keys = expected[identity]
        if (
            row["rule_id"] != finding["rule_id"]
            or row["severity"] != finding["severity"]
            or row["sha"] != run["sha"]
        ):
            raise ValueError("annotation metadata does not match raw finding")
        sensitive = finding["rule_id"] in {"RTC002", "RTC003"}
        if sensitive != row["security_withheld"]:
            raise ValueError("security annotation must be withheld")
        if sensitive and any(
            row[key] is not None for key in ("location", "key", "component", "phase")
        ):
            raise ValueError("security annotation exposes source metadata")
        if sensitive and row["reason"] != SECURITY_REASON:
            raise ValueError("security annotation reason must use the public-safe template")
        if not sensitive:
            location = finding["primary_location"]
            references = {
                "location": f"{location['path']}:{location.get('start_line') or 1}",
                "key": keys.get(finding["config_key_id"]),
                "component": finding["component"],
                "phase": finding["phase"],
            }
            if any(row[key] != value for key, value in references.items()):
                raise ValueError("annotation references do not match raw finding")
        if any(marker in json.dumps(row) for marker in ("/home/", "/tmp/", "file://")):
            raise ValueError("annotation contains private runner path")
    if observed != set(expected):
        raise ValueError("annotations do not cover every finding exactly once")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--annotations", type=Path, required=True)
    args = parser.parse_args()
    measurements = json.loads((args.workspace / "raw/measurements.json").read_text())
    rows = json.loads(args.annotations.read_text())
    validate(rows, measurements, args.workspace / "raw")
    print(f"validated {len(rows)} annotations")


if __name__ == "__main__":
    main()
