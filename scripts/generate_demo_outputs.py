"""Generate or verify the committed offline broken/fixed demo outputs."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples" / "demo"
OUTPUTS = DEMO / "outputs"
FORMATS = {"terminal": "text", "json": "json", "sarif": "sarif"}


def render(state: str, output_format: str) -> bytes:
    environment = {**os.environ, "NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "120"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "runtime_contract",
            "scan",
            str(DEMO / state),
            "--format",
            output_format,
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    if result.stderr:
        raise RuntimeError(f"unexpected stderr for {state}/{output_format}: {result.stderr!r}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = {
        OUTPUTS / f"{state}.{extension}": render(state, output_format)
        for state in ("broken", "fixed")
        for extension, output_format in FORMATS.items()
    }
    if args.check:
        stale = [
            path
            for path, content in expected.items()
            if not path.is_file() or path.read_bytes() != content
        ]
        if stale:
            print(
                "Demo outputs are stale:", *(path.relative_to(ROOT) for path in stale), sep="\n- "
            )
            return 1
        print("Demo outputs: PASS")
        return 0
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=OUTPUTS.parent) as temporary:
        staging = Path(temporary)
        for path, content in expected.items():
            staged = staging / path.name
            staged.write_bytes(content)
        for staged in staging.iterdir():
            staged.replace(OUTPUTS / staged.name)
    print("Demo outputs generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
