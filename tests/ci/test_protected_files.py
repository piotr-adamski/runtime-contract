"""Deterministic tests for the pull-request policy evaluator."""

from pathlib import Path

import pytest

from scripts.ci.protected_files import (
    PullRequestMetadata,
    evaluate_policy,
    parse_pull_request_metadata,
    protected_toml_changes,
)

FIXTURES = Path(__file__).parent / "fixtures"


def metadata(author: str, head_repository: str) -> PullRequestMetadata:
    return PullRequestMetadata(
        author_login=author,
        head_repository=head_repository,
        head_sha="a" * 40,
        head_ref="feature",
        base_repository="piotr-adamski/runtime-contract",
        base_ref="main",
    )


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_external_fork_cannot_change_protected_path() -> None:
    violations = evaluate_policy(
        metadata("contributor", "contributor/runtime-contract"),
        [".github/workflows/ci.yml"],
    )

    assert violations == ["protected path changed by non-owner PR: .github/workflows/ci.yml"]


def test_external_fork_can_change_product_source() -> None:
    assert (
        evaluate_policy(
            metadata("contributor", "contributor/runtime-contract"),
            ["src/runtime_contract/cli.py"],
        )
        == []
    )


def test_owner_same_repository_can_change_workflow() -> None:
    assert (
        evaluate_policy(
            metadata("piotr-adamski", "piotr-adamski/runtime-contract"),
            [".github/workflows/ci.yml"],
        )
        == []
    )


def test_other_collaborator_same_repository_cannot_change_workflow() -> None:
    violations = evaluate_policy(
        metadata("collaborator", "piotr-adamski/runtime-contract"),
        [".github/workflows/ci.yml"],
    )

    assert violations


@pytest.mark.parametrize(
    ("needle", "replacement", "expected"),
    [
        ('build-backend = "uv_build"', 'build-backend = "setuptools.build_meta"', "build-system"),
        ('requires-python = ">=3.11"', 'requires-python = ">=3.12"', "project.requires-python"),
        (
            'runtime-contract = "runtime_contract.cli:main"',
            'runtime-contract = "other:main"',
            "project.scripts",
        ),
        ('dev = ["pytest>=9.1.1,<10"]', 'dev = ["pytest"]', "dependency-groups.dev"),
        ("line-length = 100", "line-length = 120", "tool.ruff"),
        ('select = ["E4", "F"]', 'select = ["F"]', "tool.ruff.lint"),
        ("strict = true", "strict = false", "tool.mypy"),
        ('testpaths = ["tests"]', "testpaths = []", "tool.pytest.ini_options"),
        ("branch = true", "branch = false", "tool.coverage"),
    ],
)
def test_external_pr_cannot_weaken_protected_toml_sections(
    needle: str, replacement: str, expected: str
) -> None:
    base = fixture("pyproject-base.toml")
    head = base.replace(needle, replacement)

    assert expected in protected_toml_changes(base, head)
    violations = evaluate_policy(
        metadata("contributor", "contributor/runtime-contract"),
        ["pyproject.toml"],
        base,
        head,
    )
    assert any(expected in violation for violation in violations)


def test_dependency_change_is_allowed_with_lockfile() -> None:
    violations = evaluate_policy(
        metadata("contributor", "contributor/runtime-contract"),
        ["pyproject.toml", "uv.lock"],
        fixture("pyproject-base.toml"),
        fixture("pyproject-dependency-change.toml"),
    )

    assert violations == []


def test_malformed_toml_fails_closed() -> None:
    violations = evaluate_policy(
        metadata("contributor", "contributor/runtime-contract"),
        ["pyproject.toml"],
        fixture("pyproject-base.toml"),
        "[project\ninvalid",
    )

    assert violations and "invalid" in violations[0]


def test_missing_pull_request_metadata_fails_closed() -> None:
    with pytest.raises(ValueError, match="incomplete"):
        parse_pull_request_metadata({"user": {"login": "contributor"}})
