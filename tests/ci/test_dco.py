"""Unit tests for the repository DCO policy."""

import pytest

from scripts.ci.check_dco import Commit, Identity, parse_trailers, validate_commit

AUTHOR = Identity("Alice Example", "alice@example.com")


def commit(
    message: str, *, author: Identity = AUTHOR, parents: tuple[str, ...] = ("base",)
) -> Commit:
    return Commit(sha="abc123", author=author, parents=parents, message=message)


def test_accepts_matching_author_signoff() -> None:
    assert (
        validate_commit(commit("Subject\n\nSigned-off-by: Alice Example <alice@example.com>")) == []
    )


def test_requires_author_signoff() -> None:
    errors = validate_commit(commit("Subject"))

    assert errors == ["missing matching Signed-off-by for Alice Example <alice@example.com>"]


@pytest.mark.parametrize(
    "message",
    [
        "Subject\n\nSigned-off-by: Alice Example <other@example.com>",
        "Subject\n\nSigned-off-by: Other Person <alice@example.com>",
        "Subject\n\nSigned-off-by: Other Person <other@example.com>",
    ],
)
def test_rejects_signoff_for_a_different_identity(message: str) -> None:
    errors = validate_commit(commit(message))

    assert any("missing matching" in error for error in errors)
    assert any("unrelated identity" in error for error in errors)


def test_requires_matching_signoff_for_each_coauthor() -> None:
    message = """Subject

Co-authored-by: Bob Example <bob@example.com>
Signed-off-by: Alice Example <alice@example.com>
Signed-off-by: Bob Example <bob@example.com>"""

    assert validate_commit(commit(message)) == []


def test_rejects_unsigned_coauthor() -> None:
    message = """Subject

Co-authored-by: Bob Example <bob@example.com>
Signed-off-by: Alice Example <alice@example.com>"""

    assert validate_commit(commit(message)) == [
        "missing matching Signed-off-by for Bob Example <bob@example.com>"
    ]


def test_rejects_duplicate_trailers() -> None:
    message = """Subject

Signed-off-by: Alice Example <alice@example.com>
Signed-off-by: Alice Example <alice@example.com>"""

    assert "duplicate Signed-off-by trailer" in validate_commit(commit(message))


def test_rejects_duplicate_coauthors() -> None:
    message = """Subject

Co-authored-by: Bob Example <bob@example.com>
Co-authored-by: Bob Example <bob@example.com>
Signed-off-by: Alice Example <alice@example.com>
Signed-off-by: Bob Example <bob@example.com>"""

    assert "duplicate Co-authored-by trailer" in validate_commit(commit(message))


@pytest.mark.parametrize(
    "message",
    [
        "Subject\n\nSigned-off-by Alice Example <alice@example.com>",
        "Subject\n\nSigned-off-by: <alice@example.com>",
        "Signed-off-by: Alice Example <alice@example.com>\n\nSubject",
    ],
)
def test_rejects_malformed_or_misplaced_trailers(message: str) -> None:
    with pytest.raises(ValueError):
        parse_trailers(message)


def test_rejects_merge_commit() -> None:
    assert validate_commit(commit("Subject", parents=("one", "two"))) == [
        "merge commits are not allowed"
    ]


def test_dependabot_exception_requires_explicit_flag_and_exact_identity() -> None:
    bot = Identity("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")

    assert validate_commit(commit("Update dependency", author=bot), allow_dependabot=True) == []
    assert validate_commit(commit("Update dependency", author=bot), allow_dependabot=False)


def test_dependabot_mode_rejects_a_human_commit_even_with_valid_dco() -> None:
    message = "Subject\n\nSigned-off-by: Alice Example <alice@example.com>"

    assert "Dependabot identity is ambiguous or invalid" in validate_commit(
        commit(message), allow_dependabot=True
    )


@pytest.mark.parametrize(
    "bot",
    [
        Identity("dependabot", "49699333+dependabot@users.noreply.github.com"),
        Identity("dependabot[bot]", "dependabot@example.com"),
        Identity("Dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com"),
    ],
)
def test_dependabot_exception_fails_closed_for_ambiguous_identity(bot: Identity) -> None:
    errors = validate_commit(commit("Update dependency", author=bot), allow_dependabot=True)

    assert errors
