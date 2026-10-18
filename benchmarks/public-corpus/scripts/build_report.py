"""Export reviewed pilot data and reproduce every public aggregate from those data."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from common import BASE, slug, write_json
from validate_annotations import validate


def fresh_output(out: Path) -> None:
    if out.is_symlink() or (out.exists() and any(out.iterdir())):
        raise ValueError("public output directory must be fresh or empty")
    out.mkdir(parents=True, exist_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--annotations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.workspace / "raw"
    runs = json.loads((raw / "measurements.json").read_text())
    annotations = json.loads(args.annotations.read_text())
    validate(annotations, runs, raw)
    if len(runs) != 20 or len({run["repository"] for run in runs}) != 10:
        raise ValueError("pilot must contain ten repositories and twenty runs")
    if any(not run["deterministic"] or not run["source_unchanged"] for run in runs):
        raise ValueError("non-deterministic report or source mutation")
    out = args.output
    fresh_output(out)
    diagnostics = Counter()
    withheld = 0
    for run in runs:
        label = slug(run) + "." + run["mode"]
        payload = (raw / f"{label}.json").read_bytes()
        if run["status"] == "technical_failure":
            run["public_raw"] = False
            continue
        report = json.loads(payload)
        diagnostics.update(item["code"] for item in report["diagnostics"])
        sensitive = any(item["rule_id"] in {"RTC002", "RTC003"} for item in report["findings"])
        run["public_raw"] = not sensitive
        if sensitive:
            withheld += 1
        else:
            if any(marker in payload for marker in (b"/home/", b"/tmp/", b"file://")):
                raise ValueError("raw report contains private runner path")
            destination = out / "reports" / f"{label}.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
    write_json(out / "measurements.json", runs)
    write_json(out / "environment.json", json.loads((raw / "environment.json").read_text()))
    write_json(out / "annotations.json", annotations)
    write_json(out / "diagnostics.json", dict(sorted(diagnostics.items())))
    verdicts = Counter(item["verdict"] for item in annotations)
    by_rule = Counter(item["rule_id"] for item in annotations)
    status = Counter(run["status"] for run in runs)
    human_pending = sum(item["second_review"] != "human-reviewed" for item in annotations)
    technical_reviewed = sum(
        item["second_review"] in {"technical-reviewed", "human-reviewed"} for item in annotations
    )
    mutations = json.loads((BASE / "mutations/results.json").read_text())
    mutation_passes = sum(
        item["expectation_met"] and item["control_excludes_expected_rule"] for item in mutations
    )
    write_json(
        out / "aggregates.json",
        {
            "runs": len(runs),
            "repositories": 10,
            "statuses": dict(status),
            "findings": len(annotations),
            "verdicts": dict(verdicts),
            "by_rule": dict(by_rule),
            "withheld_raw_reports": withheld,
            "human_review_pending": human_pending,
            "second_technical_reviewed": technical_reviewed,
            "decision": "HOLD",
            "validated_precision": None,
            "population_recall": None,
            "mutation_exact_expectations_met": mutation_passes,
            "mutation_cases": len(mutations),
        },
    )
    lines = [
        "# Public-repository pilot — 0.1.2",
        "",
        "Decision: **HOLD before expanding to 75 repositories**.",
        "",
        "The ten-repository pilot is complete as a technical experiment. Annotations are AI-assisted",
        "technical assessments, not independent human ground truth. This report makes no validated",
        "precision, population recall, security-vulnerability or production-outage claim.",
        "",
        f"Runs: {len(runs)}; findings: {len(annotations)}; statuses: `{dict(status)}`.",
        f"Raw reports withheld for security triage: {withheld}; human adjudications pending: {human_pending}.",
        f"Second technical review covered {technical_reviewed} findings; this is AI review, not human ground truth.",
        "",
        "| Repository | Mode | Status | Findings | Median seconds | Peak RSS KiB |",
        "|---|---|---|---:|---:|---:|",
    ]
    for run in runs:
        lines.append(
            f"| {run['repository']} | {run['mode']} | {run['status']} | {run['summary'].get('findings', 0)} | {run['median_seconds']:.3f} | {run['peak_rss_kib']} |"
        )
    lines.extend(
        [
            "",
            "## Aggregate reproduction",
            "",
            "`measurements.json`, `annotations.json` and `diagnostics.json` are the aggregate inputs.",
            "Every finding has exactly one annotation. RTC002/RTC003 rows use opaque IDs and omit",
            "source/key metadata; affected raw reports remain private. Uncontrolled stderr is withheld.",
            "",
            "| Verdict | Count |",
            "|---|---:|",
        ]
    )
    lines.extend(f"| {key} | {value} |" for key, value in sorted(verdicts.items()))
    lines.extend(
        [
            "",
            "## Controlled mutations",
            "",
            f"Exact expected rule and completeness matched: **{mutation_passes}/{len(mutations)}**.",
            "All controls exclude the expected rule. These are synthetic witnesses, not population recall.",
            "See [patches, provenance and results](../../mutations/README.md).",
            "",
            "| Witness | Expected | Observed after | Match |",
            "|---|---|---|---|",
        ]
    )
    for mutation in mutations:
        lines.append(
            f"| {mutation['id']} | {mutation['expected_rule']} / {mutation['expected_status']} | {', '.join(mutation['observed']['after']['rules']) or 'none'} / {mutation['observed']['after']['status']} | {mutation['expectation_met']} |"
        )
    lines.extend(["", "## Performance", ""])
    for mode in ("out-of-the-box", "configured"):
        times = sorted(run["median_seconds"] for run in runs if run["mode"] == mode)
        p50 = (times[4] + times[5]) / 2
        p95 = times[math.ceil(0.95 * len(times)) - 1]
        lines.append(
            f"- {mode}: p50 {p50:.3f}s; nearest-rank p95 {p95:.3f}s; includes partial/failed scans."
        )
    lines.extend(
        [
            "",
            "## Quality backlog and resumption conditions",
            "",
            "1. Diagnose generic JSON/YAML discovery as Kubernetes, preserving explicit opt-in behavior.",
            "2. Diagnose modern Python syntax under the recorded Python 3.11 parser and supported Dockerfile aliases.",
            "3. Improve component/target mapping and explain missing delivery without implying a runtime outage.",
            "4. Add static wrapper/alias handling only after ranking the observed dynamic diagnostics.",
            "5. Finish private security triage and independent human adjudication before precision claims.",
            "",
            "Ranking is by reliability impact first; diagnostic frequencies are in `diagnostics.json`.",
            "HOLD is required because unsupported parsing and unresolved judgments remain; scale only after",
            "a bounded parser/mapping correction, an identical-SHA rerun and a feasible human-review plan.",
            "",
            "## Limitations",
            "",
            "The pilot is intentionally small and not statistically representative. Configured scopes omit",
            "tests/examples only where declared in committed configuration; compare scope as well as counts.",
            "Acquisition omits real dotenv/private-key/generated files, symlinks and oversized files; receipts",
            "record those exclusions. Complete scan status covers acquired selected inputs only. RSS and time",
            "depend on host contention; this run is observational, not a dedicated-host performance claim.",
            "Controlled fixture mutations measure the selected cases, not population recall. The 75-repository",
            "study and its final publication remain future work.",
            "",
        ]
    )
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
    entries = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out).as_posix()}"
            )
    (out / "SHA256SUMS").write_text("\n".join(entries) + "\n")
    print(f"exported {len(runs)} runs, {len(annotations)} annotations; HOLD")


if __name__ == "__main__":
    main()
