"""Shared public-corpus validation and bounded, value-blind acquisition."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

BASE = Path(__file__).resolve().parents[1]
SECURITY_REASON = "Sensitive-source finding requires private maintainer security triage; no value was inspected and no vulnerability is asserted. All source identifiers are withheld."


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def corpus(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema = json.loads((BASE / "schemas/corpus.schema.json").read_text())
    Draft202012Validator(schema).validate(value)
    names = [item["repository"] for item in value["repositories"]]
    if len(names) != len(set(names)):
        raise ValueError("duplicate repository")
    return value


def slug(item: dict[str, Any]) -> str:
    name = item["repository"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
        raise ValueError("invalid public GitHub repository")
    return name.replace("/", "--")


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("unexpected symlink in acquired tree")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
