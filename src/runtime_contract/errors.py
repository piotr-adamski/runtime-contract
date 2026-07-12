"""Explicit boundary for messages reviewed as safe for public CLI output."""

from __future__ import annotations

import re

_FIXED_MESSAGES = frozenset(
    {
        "configuration path must remain relative to the project root",
        "invalid execution setting",
        "project path is inaccessible",
        "project path must be a readable directory",
        "unknown environment",
    }
)
_UNKNOWN_ROOT = re.compile(
    r"^unknown root: [A-Za-z][A-Za-z0-9_-]{0,63}; available roots: "
    r"[A-Za-z][A-Za-z0-9_-]{0,63}(?:, [A-Za-z][A-Za-z0-9_-]{0,63})*$"
)


class PublicError(ValueError):
    """A technical error whose message is intentionally safe and value-free."""

    def __init__(self, message: str) -> None:
        if message not in _FIXED_MESSAGES and _UNKNOWN_ROOT.fullmatch(message) is None:
            raise ValueError("unregistered public error message")
        super().__init__(message)


__all__ = ["PublicError"]
