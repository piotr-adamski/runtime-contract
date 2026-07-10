#!/usr/bin/env python3
"""Enforce owner-only CI paths and protected pyproject sections for pull requests."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

OWNER = "piotr-adamski"
REPOSITORY = "piotr-adamski/runtime-contract"
PROTECTED_PREFIXES = (
    ".github/workflows/",
    ".github/actions/",
    "scripts/ci/",
)
PROTECTED_FILES = {"scripts/quality-gates.sh"}
PROTECTED_TOML_PATHS = (
    ("build-system",),
    ("project", "requires-python"),
    ("project", "scripts"),
    ("dependency-groups", "dev"),
    ("tool", "ruff"),
    ("tool", "ruff", "lint"),
    ("tool", "mypy"),
    ("tool", "pytest", "ini_options"),
    ("tool", "coverage"),
)
MISSING = object()


@dataclass(frozen=True)
class PullRequestMetadata:
    author_login: str
    head_repository: str
    head_sha: str
    head_ref: str
    base_repository: str
    base_ref: str

    @property
    def is_owner_same_repository(self) -> bool:
        return (
            self.author_login == OWNER
            and self.head_repository == REPOSITORY
            and self.base_repository == REPOSITORY
        )


def parse_pull_request_metadata(payload: Any) -> PullRequestMetadata:
    try:
        metadata = PullRequestMetadata(
            author_login=payload["user"]["login"],
            head_repository=payload["head"]["repo"]["full_name"],
            head_sha=payload["head"]["sha"],
            head_ref=payload["head"]["ref"],
            base_repository=payload["base"]["repo"]["full_name"],
            base_ref=payload["base"]["ref"],
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("pull request metadata is incomplete") from exc
    if not all(
        (
            metadata.author_login,
            metadata.head_repository,
            metadata.head_sha,
            metadata.head_ref,
            metadata.base_repository,
            metadata.base_ref,
        )
    ):
        raise ValueError("pull request metadata contains empty required fields")
    return metadata


def is_protected_path(path: str) -> bool:
    return path in PROTECTED_FILES or path.startswith(PROTECTED_PREFIXES)


def _get_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return MISSING
        current = current[key]
    return current


def protected_toml_changes(base_text: str, head_text: str) -> list[str]:
    try:
        base = tomllib.loads(base_text)
        head = tomllib.loads(head_text)
    except (tomllib.TOMLDecodeError, TypeError) as exc:
        raise ValueError(f"pyproject.toml is invalid: {exc}") from exc
    changed: list[str] = []
    for path in PROTECTED_TOML_PATHS:
        if _get_path(base, path) != _get_path(head, path):
            changed.append(".".join(path))
    return changed


def evaluate_policy(
    metadata: PullRequestMetadata,
    changed_paths: list[str],
    base_pyproject: str | None = None,
    head_pyproject: str | None = None,
) -> list[str]:
    if metadata.is_owner_same_repository:
        return []
    violations = [
        f"protected path changed by non-owner PR: {path}"
        for path in changed_paths
        if is_protected_path(path)
    ]
    if "pyproject.toml" in changed_paths:
        if base_pyproject is None or head_pyproject is None:
            violations.append("pyproject.toml content is unavailable")
        else:
            try:
                changes = protected_toml_changes(base_pyproject, head_pyproject)
            except ValueError as exc:
                violations.append(str(exc))
            else:
                violations.extend(
                    f"protected pyproject section changed: {path}" for path in changes
                )
    return violations


class GitHubApi:
    def __init__(self, api_url: str, token: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.token = token

    def get_json(self, path: str) -> Any:
        request = Request(
            f"{self.api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "runtime-contract-policy",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ValueError(f"GitHub API read failed for {path}: {exc}") from exc

    def changed_paths(self, repository: str, number: int) -> list[str]:
        paths: list[str] = []
        page = 1
        while True:
            payload = self.get_json(
                f"/repos/{repository}/pulls/{number}/files?per_page=100&page={page}"
            )
            if not isinstance(payload, list):
                raise ValueError("GitHub changed-files response is not a list")
            for entry in payload:
                try:
                    path = entry["filename"]
                except (KeyError, TypeError) as exc:
                    raise ValueError("changed-file metadata is incomplete") from exc
                if not isinstance(path, str) or not path:
                    raise ValueError("changed-file path is invalid")
                paths.append(path)
            if len(payload) < 100:
                return paths
            page += 1
            if page > 30:
                raise ValueError("changed-files pagination exceeded the fail-closed limit")

    def text_file(self, repository: str, path: str, ref: str) -> str:
        payload = self.get_json(
            f"/repos/{repository}/contents/{quote(path, safe='/')}?ref={quote(ref, safe='')}"
        )
        try:
            if payload["encoding"] != "base64" or payload["type"] != "file":
                raise ValueError("content response is not a base64 file")
            raw = base64.b64decode(payload["content"], validate=True)
            return raw.decode("utf-8")
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"cannot decode untrusted text file {path}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--api-url", default="https://api.github.com")
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.repository != REPOSITORY:
        print(f"Policy: ERROR: unexpected repository {args.repository!r}", file=sys.stderr)
        return 1
    token = os.environ.get(args.token_env)
    if not token:
        print(
            f"Policy: ERROR: token environment variable {args.token_env!r} is unavailable",
            file=sys.stderr,
        )
        return 1
    api = GitHubApi(args.api_url, token)
    try:
        payload = api.get_json(f"/repos/{args.repository}/pulls/{args.pull_request}")
        metadata = parse_pull_request_metadata(payload)
        if metadata.base_ref != args.base_ref or metadata.base_repository != REPOSITORY:
            raise ValueError("pull request base metadata does not match the trusted base")
        changed_paths = api.changed_paths(args.repository, args.pull_request)
        base_text: str | None = None
        head_text: str | None = None
        if "pyproject.toml" in changed_paths and not metadata.is_owner_same_repository:
            base_text = Path("pyproject.toml").read_text(encoding="utf-8")
            head_text = api.text_file(metadata.head_repository, "pyproject.toml", metadata.head_sha)
        violations = evaluate_policy(metadata, changed_paths, base_text, head_text)
    except (OSError, ValueError) as exc:
        print(f"Policy: ERROR: {exc}", file=sys.stderr)
        return 1

    if violations:
        for violation in violations:
            print(f"Policy: FAIL: {violation}", file=sys.stderr)
        return 1
    print(f"Policy: PASS: {len(changed_paths)} changed file(s) evaluated without executing PR code")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
