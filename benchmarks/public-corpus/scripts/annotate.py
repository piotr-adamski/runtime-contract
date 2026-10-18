"""Apply documented conservative technical triage; this is not independent human ground truth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import SECURITY_REASON, slug, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runs = json.loads((args.workspace / "raw/measurements.json").read_text())
    annotations = []
    for run in runs:
        if run["status"] == "technical_failure":
            continue
        report = json.loads(
            (args.workspace / "raw" / f"{slug(run)}.{run['mode']}.json").read_text()
        )
        keys = {key["id"]: key["name"] for key in report["contract"]["config_keys"]}
        environments = {item["id"]: item for item in report["contract"]["environments"]}
        for finding in report["findings"]:
            rule = finding["rule_id"]
            sensitive = rule in {"RTC002", "RTC003"}
            location = finding["primary_location"]
            source = location["path"]
            target = environments.get(finding["environment_id"], {}).get("target", "implicit")
            verdict, confidence = "cannot_determine", "low"
            reason = f"Source {source} is assigned to target {target}. Static repository evidence alone does not prove runtime delivery, feature enablement or a production defect; maintainer adjudication is pending."
            if sensitive:
                reason = SECURITY_REASON
            elif rule in {"RTC006", "RTC011"}:
                verdict, confidence = "unsupported_pattern", "high"
                reason = f"The report identifies a dynamic name or custom settings source in {source}; non-execution intentionally prevents resolution. This is a documented analysis boundary, not a demonstrated application defect."
            elif rule == "RTC005":
                reason = f"Declaration in {source} has no detected consumer within component {finding['component']}. Other-language consumers, wrappers and separate component roots remain possible; stale configuration is not proven."
            elif rule == "RTC007":
                reason = f"Ambiguous providers or declarations in {source} may belong to alternative deployment variants. Values are not retained, and an incompatible real-world default cannot be independently established."
            elif rule == "RTC001" and run["mode"] == "out-of-the-box":
                owner = None
                if run[
                    "repository"
                ] == "GoogleCloudPlatform/microservices-demo" and source.startswith("src/"):
                    owner = source.split("/")[1]
                    unrelated = (
                        target.startswith("default/Deployment/")
                        and target.rsplit("/", 1)[-1] != owner
                    )
                elif run[
                    "repository"
                ] == "fastapi/full-stack-fastapi-template" and source.startswith("backend/app/"):
                    owner = "backend"
                    unrelated = target in {"db", "adminer", "proxy", "mailpit", "playwright"}
                elif run["repository"] == "healthchecks/healthchecks" and source.startswith("hc/"):
                    owner = "web"
                    unrelated = target == "db"
                else:
                    unrelated = False
                if unrelated:
                    verdict, confidence = "false_positive", "high"
                    reason = f"Component mapping mismatch: {source} belongs to service {owner}, but the finding demands its key on unrelated target {target}. Checked against the pinned source/deployment layout; this is a provisional technical judgment pending human review."
            annotations.append(
                {
                    "repository": run["repository"],
                    "sha": run["sha"],
                    "mode": run["mode"],
                    "finding_id": finding["id"],
                    "rule_id": rule,
                    "severity": finding["severity"],
                    "component": None if sensitive else finding["component"],
                    "phase": None if sensitive else finding["phase"],
                    "location": None
                    if sensitive
                    else f"{source}:{location.get('start_line') or 1}",
                    "key": None if sensitive else keys.get(finding["config_key_id"]),
                    "verdict": verdict,
                    "confidence": confidence,
                    "reason": reason,
                    "reviewer": "Codex AI-assisted technical triage",
                    "reviewed_on": "2026-10-18",
                    "second_review": "pending",
                    "security_withheld": sensitive,
                }
            )
    write_json(
        args.output,
        sorted(annotations, key=lambda row: (row["repository"], row["mode"], row["finding_id"])),
    )
    print(f"prepared {len(annotations)} provisional technical annotations")


if __name__ == "__main__":
    main()
