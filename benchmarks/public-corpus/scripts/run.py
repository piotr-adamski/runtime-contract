"""Run frozen 0.1.2: one warm-up and three measurements per repository and mode."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import time
from pathlib import Path

from common import BASE, corpus, slug, tree_digest, write_json


def limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (1_073_741_824, 1_073_741_824))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (134_217_728, 134_217_728))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    args = parser.parse_args()
    manifest = corpus(args.corpus)
    cli = args.cli.resolve(strict=True)
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}
    version = subprocess.check_output([str(cli), "--version"], env=env, text=True).strip()
    if version != "runtime-contract 0.1.2":
        raise ValueError("benchmark baseline must be exactly runtime-contract 0.1.2")
    output = args.workspace / "raw"
    output.mkdir(parents=True, exist_ok=True)
    write_json(
        output / "environment.json",
        {
            "cli": version,
            "os": platform.system(),
            "architecture": platform.machine(),
            "cpu_count": os.cpu_count(),
            "timeout_seconds": 45,
            "cpu_seconds": 30,
            "address_space_bytes": 1_073_741_824,
            "warmups": 1,
            "measured_runs": 3,
            "manifest_sha256": hashlib.sha256(args.corpus.read_bytes()).hexdigest(),
            "python": subprocess.check_output(
                [str(cli.parent / "python"), "--version"], env=env, text=True
            ).strip(),
        },
    )
    results = []
    for item in manifest["repositories"]:
        name = slug(item)
        source = args.workspace / "sources" / name
        receipt = json.loads((args.workspace / "receipts" / f"{name}.json").read_text())
        if receipt["sha"] != item["sha"] or tree_digest(source) != receipt["tree_sha256"]:
            raise ValueError("source identity drift")
        for mode in ("out-of-the-box", "configured"):
            label = f"{name}.{mode}"
            mode_root = args.workspace / "runs" / label
            if mode_root.exists():
                raise ValueError("run already exists; use a fresh workspace to avoid mixed results")
            shutil.copytree(source, mode_root)
            config = BASE / "configs" / f"{name}.yaml"
            if mode == "configured":
                shutil.copyfile(config, mode_root / "runtime-contract.yaml")
            before = tree_digest(mode_root)
            reports, samples, errors = [], [], []
            for number in range(4):
                rss_path = output / f"{label}.rss"
                command = [
                    "/usr/bin/time",
                    "-f",
                    "%M",
                    "-o",
                    str(rss_path),
                    str(cli),
                    "scan",
                    str(mode_root),
                    "--format",
                    "json",
                ]
                start = time.monotonic()
                try:
                    completed = subprocess.run(
                        command, capture_output=True, env=env, timeout=45, preexec_fn=limits
                    )
                    raw, stderr, exit_code = (
                        completed.stdout,
                        completed.stderr,
                        completed.returncode,
                    )
                except subprocess.TimeoutExpired:
                    raw, stderr, exit_code = b"", b"bounded scan timeout", 124
                elapsed = time.monotonic() - start
                try:
                    report = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    report = None
                reports.append(raw)
                errors.append(stderr)
                if number:
                    rss_text = rss_path.read_text().splitlines()[-1] if rss_path.exists() else ""
                    samples.append(
                        {
                            "seconds": round(elapsed, 6),
                            "exit_code": exit_code,
                            "peak_rss_kib": int(rss_text) if rss_text.isdigit() else None,
                        }
                    )
            if tree_digest(mode_root) != before:
                raise ValueError("scanner changed source tree")
            deterministic = all(raw == reports[0] for raw in reports)
            (output / f"{label}.json").write_bytes(reports[-1])
            # Never store uncontrolled exception output: retain only bounded, redacted stderr metadata.
            (output / f"{label}.stderr.txt").write_text(
                ""
                if not any(errors)
                else "stderr withheld for review; see stderr_bytes in measurements\n"
            )
            result = {
                "repository": item["repository"],
                "sha": item["sha"],
                "mode": mode,
                "status": report.get("status", "technical_failure")
                if report
                else "technical_failure",
                "summary": report.get("summary", {}) if report else {},
                "samples": samples,
                "median_seconds": statistics.median(row["seconds"] for row in samples),
                "peak_rss_kib": max((row["peak_rss_kib"] or 0) for row in samples),
                "report_sha256": hashlib.sha256(reports[-1]).hexdigest(),
                "deterministic": deterministic,
                "source_unchanged": True,
                "stderr_bytes": [len(error) for error in errors],
                "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()
                if mode == "configured"
                else None,
                "acquisition": receipt,
            }
            results.append(result)
            write_json(output / "measurements.json", results)
            print(
                f"{label}: {result['status']}, {result['summary'].get('findings', 0)} findings",
                flush=True,
            )


if __name__ == "__main__":
    main()
