#!/usr/bin/env python3
"""Validate DCO trailers for every commit in an exact BASE..HEAD range."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass

IDENTITY_RE = re.compile(r"^(?P<name>[^<>\r\n]+?)\s*<(?P<email>[^<>\s]+)>$")
TRAILER_RE = re.compile(r"^(?P<key>Signed-off-by|Co-authored-by):\s*(?P<value>.*)$", re.I)
TRAILER_PREFIX_RE = re.compile(r"^(Signed-off-by|Co-authored-by)\b", re.I)
DEPENDABOT_NAME = "dependabot[bot]"
DEPENDABOT_DOMAIN = "users.noreply.github.com"


@dataclass(frozen=True)
class Identity:
    name: str
    email: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.name.casefold(), self.email.casefold())


@dataclass(frozen=True)
class Commit:
    sha: str
    author: Identity
    parents: tuple[str, ...]
    message: str


def parse_identity(value: str, label: str) -> Identity:
    match = IDENTITY_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"malformed {label} identity: {value!r}")
    name = match.group("name").strip()
    email = match.group("email").strip()
    if not name or not email:
        raise ValueError(f"empty {label} name or email")
    return Identity(name=name, email=email)


def parse_trailers(message: str) -> tuple[list[Identity], list[Identity]]:
    lines = message.rstrip("\n").splitlines()
    trailer_start = len(lines)
    while trailer_start > 0 and lines[trailer_start - 1].strip():
        trailer_start -= 1
    trailer_lines = lines[trailer_start:]

    for line in lines[:trailer_start]:
        if TRAILER_PREFIX_RE.match(line):
            raise ValueError("DCO/co-author trailer is not in the final trailer block")

    signoffs: list[Identity] = []
    coauthors: list[Identity] = []
    for line in trailer_lines:
        if not TRAILER_PREFIX_RE.match(line):
            continue
        match = TRAILER_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed trailer: {line!r}")
        identity = parse_identity(match.group("value"), match.group("key"))
        target = signoffs if match.group("key").casefold() == "signed-off-by" else coauthors
        target.append(identity)
    return signoffs, coauthors


def _duplicates(identities: list[Identity]) -> set[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    duplicates: set[tuple[str, str]] = set()
    for identity in identities:
        if identity.key in seen:
            duplicates.add(identity.key)
        seen.add(identity.key)
    return duplicates


def validate_commit(commit: Commit, allow_dependabot: bool = False) -> list[str]:
    if len(commit.parents) > 1:
        return ["merge commits are not allowed"]
    try:
        signoffs, coauthors = parse_trailers(commit.message)
    except ValueError as exc:
        return [str(exc)]

    errors: list[str] = []
    if _duplicates(signoffs):
        errors.append("duplicate Signed-off-by trailer")
    if _duplicates(coauthors):
        errors.append("duplicate Co-authored-by trailer")

    dependabot_exception = (
        allow_dependabot
        and commit.author.name == DEPENDABOT_NAME
        and commit.author.email.casefold().endswith(f"@{DEPENDABOT_DOMAIN}")
    )
    if allow_dependabot and not dependabot_exception:
        errors.append("Dependabot identity is ambiguous or invalid")

    required = [] if dependabot_exception else [commit.author]
    required.extend(coauthors)
    signoff_keys = {identity.key for identity in signoffs}
    for identity in required:
        if identity.key not in signoff_keys:
            errors.append(f"missing matching Signed-off-by for {identity.name} <{identity.email}>")

    permitted = {identity.key for identity in required}
    if dependabot_exception:
        permitted.add(commit.author.key)
    for signoff in signoffs:
        if signoff.key not in permitted:
            errors.append(
                f"Signed-off-by is for an unrelated identity: {signoff.name} <{signoff.email}>"
            )
    return errors


def read_commits(base: str, head: str) -> list[Commit]:
    separator = "\x1f"
    record = "\x1e"
    result = subprocess.run(
        [
            "git",
            "log",
            f"--format=%H{separator}%an{separator}%ae{separator}%P{separator}%B{record}",
            f"{base}..{head}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "git log failed")
    commits: list[Commit] = []
    for raw_record in result.stdout.split(record):
        raw_record = raw_record.strip("\n")
        if not raw_record:
            continue
        fields = raw_record.split(separator, 4)
        if len(fields) != 5:
            raise ValueError("unexpected git log record")
        sha, author_name, author_email, parents, message = fields
        commits.append(
            Commit(
                sha=sha,
                author=Identity(author_name, author_email),
                parents=tuple(parents.split()),
                message=message,
            )
        )
    return commits


def resolve_commit(value: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"{value}^{{commit}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"commit is unavailable: {value}")
    return result.stdout.strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--allow-dependabot", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.allow_dependabot:
        import os

        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_ACTOR") != DEPENDABOT_NAME
        ):
            print(
                "DCO: ERROR: --allow-dependabot requires trusted GitHub Actions metadata",
                file=sys.stderr,
            )
            return 1
    try:
        base = resolve_commit(args.base)
        head = resolve_commit(args.head)
        commits = read_commits(base, head)
    except ValueError as exc:
        print(f"DCO: ERROR: {exc}", file=sys.stderr)
        return 1
    if not commits:
        print(f"DCO: PASS: no commits in {base}..{head}")
        return 0

    failed = False
    for commit in commits:
        errors = validate_commit(commit, allow_dependabot=args.allow_dependabot)
        if errors:
            failed = True
            for error in errors:
                print(f"DCO: FAIL: {commit.sha}: {error}", file=sys.stderr)
        else:
            print(f"DCO: PASS: {commit.sha}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
