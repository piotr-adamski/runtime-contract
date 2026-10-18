"""Acquire immutable public GitHub archives without executing project code or extracting secrets."""

from __future__ import annotations

import argparse
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

from common import corpus, slug, tree_digest, write_json

MAX_ARCHIVE = 64 * 1_048_576
MAX_TREE = 256 * 1_048_576
MAX_FILE = 4 * 1_048_576
MAX_FILES = 20_000


def acquire(item: dict[str, object], destination: Path) -> dict[str, object]:
    repository, sha = str(item["repository"]), str(item["sha"])
    url = f"https://codeload.github.com/{repository}/tar.gz/{sha}"
    request = urllib.request.Request(url, headers={"User-Agent": "runtime-contract-public-pilot"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE or destination.exists():
        raise ValueError("archive budget exceeded or destination already exists")
    expected = repository.split("/")[1] + "-" + sha
    total, count = 0, 0
    excluded: dict[str, int] = {}
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != expected or ".." in parts or "\\" in member.name:
                raise ValueError("archive identity or containment mismatch")
            relative = Path(*parts[1:])
            if not member.isfile():
                if not member.isdir():
                    excluded["non_regular"] = excluded.get("non_regular", 0) + 1
                continue
            name = relative.name
            if (
                any(part.startswith(".env") and part != ".env.example" for part in relative.parts)
                or name.endswith((".pem", ".key", ".p12", ".pfx"))
                or any(
                    part in {".git", "node_modules", ".next", ".open-next"}
                    for part in relative.parts
                )
            ):
                excluded["private_or_generated"] = excluded.get("private_or_generated", 0) + 1
                continue
            if member.size > MAX_FILE:
                excluded["oversized_file"] = excluded.get("oversized_file", 0) + 1
                continue
            total += member.size
            count += 1
            if total > MAX_TREE or count > MAX_FILES:
                raise ValueError("expanded archive budget exceeded")
            stream = archive.extractfile(member)
            assert stream is not None
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.read(MAX_FILE + 1))
    return {
        "repository": repository,
        "sha": sha,
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "tree_sha256": tree_digest(destination),
        "files": count,
        "bytes": total,
        "excluded": excluded,
        "hooks_executed": False,
        "submodules_initialized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    for item in corpus(args.corpus)["repositories"]:
        name = slug(item)
        receipt = args.workspace / "receipts" / f"{name}.json"
        destination = args.workspace / "sources" / name
        if receipt.exists():
            import json

            old = json.loads(receipt.read_text())
            if old["sha"] != item["sha"] or old["tree_sha256"] != tree_digest(destination):
                raise ValueError("existing acquisition drift")
            print(f"verified {name}", flush=True)
            continue
        result = acquire(item, destination)
        write_json(receipt, result)
        print(f"acquired {name}: {result['files']} files", flush=True)


if __name__ == "__main__":
    main()
