"""File discovery contract tests."""

from __future__ import annotations

import json
import os
import socket
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from pathspec import GitIgnoreSpec

from runtime_contract import discovery as discovery_module
from runtime_contract.discovery import (
    DEFAULT_EXCLUDED_DIRECTORIES,
    CandidateKind,
    DiscoveryError,
    DiscoveryErrorCode,
    discover,
)


def write(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def config(root: Path, include: list[str] | None = None, exclude: list[str] | None = None) -> None:
    lines = ["version: 1"]
    if include is not None:
        if include:
            lines.extend(("include:", *(f"  - {json.dumps(item)}" for item in include)))
        else:
            lines.append("include: []")
    if exclude is not None:
        if exclude:
            lines.extend(("exclude:", *(f"  - {json.dumps(item)}" for item in exclude)))
        else:
            lines.append("exclude: []")
    write(root / "runtime-contract.yaml", "\n".join(lines) + "\n")


def paths(root: Path) -> list[str]:
    return [item.path for item in discover(root).candidates]


def assert_code(root: Path, code: DiscoveryErrorCode) -> DiscoveryError:
    with pytest.raises(DiscoveryError) as caught:
        discover(root)
    assert caught.value.code is code
    return caught.value


def test_empty_directory_is_credible(tmp_path: Path) -> None:
    result = discover(tmp_path)
    assert result.candidates == ()
    assert result.config_path is None


def test_invalid_roots(tmp_path: Path) -> None:
    assert_code(tmp_path / "missing", DiscoveryErrorCode.INVALID_ROOT)
    assert_code(write(tmp_path / "file"), DiscoveryErrorCode.INVALID_ROOT)
    assert_code(tmp_path / "broken", DiscoveryErrorCode.INVALID_ROOT)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_root_can_be_directory_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    write(target / "app.py")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    result = discover(link)
    assert [item.path for item in result.candidates] == ["app.py"]
    assert result.canonical_root == target.resolve()
    assert result.logical_root == link


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("a.py", CandidateKind.PYTHON),
        ("a.js", CandidateKind.JAVASCRIPT),
        ("a.jsx", CandidateKind.JAVASCRIPT),
        ("a.mjs", CandidateKind.JAVASCRIPT),
        ("a.cjs", CandidateKind.JAVASCRIPT),
        ("a.ts", CandidateKind.JAVASCRIPT),
        ("a.mts", CandidateKind.JAVASCRIPT),
        ("a.cts", CandidateKind.JAVASCRIPT),
        ("a.tsx", CandidateKind.JAVASCRIPT),
        ("Dockerfile", CandidateKind.DOCKERFILE),
        ("Dockerfile.prod", CandidateKind.DOCKERFILE),
        ("compose.yaml", CandidateKind.COMPOSE),
        ("compose.dev.yml", CandidateKind.COMPOSE),
        ("docker-compose.yaml", CandidateKind.COMPOSE),
        ("docker-compose.prod.yml", CandidateKind.COMPOSE),
        ("a.yaml", CandidateKind.KUBERNETES),
        ("a.yml", CandidateKind.KUBERNETES),
        ("a.json", CandidateKind.KUBERNETES),
        (".env.example", CandidateKind.ENV_EXAMPLE),
    ],
)
def test_supported_candidates(tmp_path: Path, name: str, kind: CandidateKind) -> None:
    write(tmp_path / name)
    result = discover(tmp_path)
    assert [(item.path, item.kind) for item in result.candidates] == [(name, kind)]


@pytest.mark.parametrize(
    "name",
    [
        "README.md",
        "app.txt",
        "app.PY",
        "Dockerfilex",
        ".env",
        ".env.local",
        ".env.prod",
    ],
)
def test_unsupported_and_secret_env_files_are_rejected(tmp_path: Path, name: str) -> None:
    write(tmp_path / name)
    assert paths(tmp_path) == []


def test_hidden_files_and_directories_are_scanned(tmp_path: Path) -> None:
    write(tmp_path / ".hidden" / ".app.py")
    assert paths(tmp_path) == [".hidden/.app.py"]


def test_root_and_nested_gitignore_with_negation_and_precedence(tmp_path: Path) -> None:
    write(tmp_path / ".gitignore", "*.py\n!keep.py\n")
    write(tmp_path / "drop.py")
    write(tmp_path / "keep.py")
    write(tmp_path / "nested" / ".gitignore", "!nested.py\n")
    write(tmp_path / "nested" / "nested.py")
    assert paths(tmp_path) == ["keep.py", "nested/nested.py"]


def test_git_info_and_global_excludes_have_no_effect(tmp_path: Path) -> None:
    write(tmp_path / ".git" / "info" / "exclude", "*.py\n")
    write(tmp_path / "app.py")
    assert paths(tmp_path) == ["app.py"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_symlinked_gitignore_is_not_read(tmp_path: Path) -> None:
    rules = write(tmp_path / "rules", "*.py\n")
    (tmp_path / ".gitignore").symlink_to(rules)
    write(tmp_path / "app.py")
    assert paths(tmp_path) == ["app.py"]


@pytest.mark.parametrize("directory", sorted(DEFAULT_EXCLUDED_DIRECTORIES))
def test_each_default_exclusion(tmp_path: Path, directory: str) -> None:
    write(tmp_path / directory / "app.py")
    assert paths(tmp_path) == []


@pytest.mark.parametrize("directory", ["target", "out", "generated"])
def test_non_default_broad_names_are_scanned(tmp_path: Path, directory: str) -> None:
    write(tmp_path / directory / "app.py")
    assert paths(tmp_path) == [f"{directory}/app.py"]


def test_git_is_hard_excluded(tmp_path: Path) -> None:
    write(tmp_path / ".git" / "app.py")
    config(tmp_path, include=[".git/app.py"])
    assert_code(tmp_path, DiscoveryErrorCode.ALL_INCLUDED_REJECTED)


def test_include_allowlist_and_override_filters(tmp_path: Path) -> None:
    write(tmp_path / ".gitignore", "ignored/\n")
    write(tmp_path / "ignored" / "app.py")
    write(tmp_path / "node_modules" / "pkg" / "Dockerfile")
    write(tmp_path / "other.py")
    config(tmp_path, include=["ignored/app.py", "node_modules/pkg/Dockerfile"])
    assert paths(tmp_path) == ["ignored/app.py", "node_modules/pkg/Dockerfile"]


def test_exclude_wins_and_prunes(tmp_path: Path) -> None:
    write(tmp_path / "blocked" / "app.py")
    config(tmp_path, include=["blocked/app.py"], exclude=["blocked/"])
    assert_code(tmp_path, DiscoveryErrorCode.ALL_INCLUDED_REJECTED)


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "   ",
        "!app.py",
        "a\\b.py",
        "../a.py",
        "a/../b.py",
        "C:/a.py",
        "C:\\a.py",
        "//server/share",
        "a\0b",
    ],
)
@pytest.mark.parametrize("field", ["include", "exclude"])
def test_invalid_yaml_patterns(tmp_path: Path, pattern: str, field: str) -> None:
    write(tmp_path / "app.py")
    config(tmp_path, **{field: [pattern]})
    assert_code(tmp_path, DiscoveryErrorCode.INVALID_PATTERN)


def test_anchored_and_gitwildmatch_patterns(tmp_path: Path) -> None:
    write(tmp_path / "app.py")
    write(tmp_path / "deep" / "app.py")
    config(tmp_path, include=["/app.py"])
    assert paths(tmp_path) == ["app.py"]


def test_basename_include_can_descend_into_default_exclusion(tmp_path: Path) -> None:
    write(tmp_path / "node_modules" / "app.py")
    config(tmp_path, include=["*.py"])
    assert paths(tmp_path) == ["node_modules/app.py"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_safe_file_and_directory_symlinks_and_deduplication(tmp_path: Path) -> None:
    write(tmp_path / "z-real" / "app.py")
    (tmp_path / "a-dir").symlink_to(tmp_path / "z-real", target_is_directory=True)
    (tmp_path / "b.py").symlink_to(tmp_path / "z-real" / "app.py")
    result = discover(tmp_path)
    assert [item.path for item in result.candidates] == ["a-dir/app.py"]
    assert result.stats.deduplicated_directories == 1
    assert result.stats.deduplicated_files == 1


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_outside_and_broken_symlinks(tmp_path: Path) -> None:
    outside = write(tmp_path.parent / f"{tmp_path.name}-outside.py")
    (tmp_path / "outside.py").symlink_to(outside)
    assert_code(tmp_path, DiscoveryErrorCode.OUTSIDE_ROOT_SYMLINK)
    (tmp_path / "outside.py").unlink()
    (tmp_path / "broken.py").symlink_to(tmp_path / "missing.py")
    result = discover(tmp_path)
    assert result.candidates == ()
    assert result.stats.skipped_broken_symlinks == 1


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_symlink_cycle_is_detected_without_recursion(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    write(directory / "app.py")
    (directory / "cycle").symlink_to(directory, target_is_directory=True)
    result = discover(tmp_path)
    assert paths(tmp_path) == ["dir/app.py"]
    assert result.stats.deduplicated_directories == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is unavailable")
def test_fifo_and_socket_are_never_opened(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.py")
    socket_path = tmp_path / "socket.py"
    server = socket.socket(socket.AF_UNIX)
    try:
        server.bind(str(socket_path))
        result = discover(tmp_path)
    finally:
        server.close()
    assert result.candidates == ()
    assert result.stats.skipped_special_files == 2


def test_sorting_is_utf8_nfc_and_creation_order_independent(tmp_path: Path) -> None:
    for name in ["z.py", "ą.py", "A.py", "a.py"]:
        write(tmp_path / name)
    representable = {unicodedata.normalize("NFC", entry.name) for entry in tmp_path.iterdir()}
    expected = sorted(representable, key=lambda value: value.encode())
    assert paths(tmp_path) == expected


def test_unicode_is_normalized_and_collisions_fail(tmp_path: Path) -> None:
    decomposed = "e\u0301.py"
    write(tmp_path / decomposed)
    assert paths(tmp_path) == [unicodedata.normalize("NFC", decomposed)]
    composed = "é.py"
    if composed != decomposed:
        entries_before = len(list(tmp_path.iterdir()))
        write(tmp_path / composed)
        if len(list(tmp_path.iterdir())) == entries_before:
            assert paths(tmp_path) == [composed]
        else:
            assert_code(tmp_path, DiscoveryErrorCode.UNICODE_COLLISION)


def test_spaces_and_non_ascii_names(tmp_path: Path) -> None:
    write(tmp_path / "zażółć gęślą.py")
    assert paths(tmp_path) == ["zażółć gęślą.py"]


def test_ten_thousand_entries_and_deep_iterative_tree(tmp_path: Path) -> None:
    bulk = tmp_path / "bulk"
    bulk.mkdir()
    for index in range(10_000):
        (bulk / f"entry-{index:05}.txt").touch()
    deep = tmp_path
    for _ in range(300):
        deep /= "d"
    write(deep / "app.py")
    assert paths(tmp_path) == [str((deep / "app.py").relative_to(tmp_path)).replace(os.sep, "/")]


def test_traversal_failure_is_not_partial_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "a.py")
    write(tmp_path / "blocked" / "b.py")
    original = os.scandir

    def guarded(path: os.PathLike[str] | str) -> Any:
        if Path(path).name == "blocked":
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(os, "scandir", guarded)
    assert_code(tmp_path, DiscoveryErrorCode.INACCESSIBLE_PATH)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_revalidation_detects_symlink_target_and_inode_changes(tmp_path: Path) -> None:
    first = write(tmp_path / "first.py")
    second = write(tmp_path / "second.py")
    link = tmp_path / "a.py"
    link.symlink_to(first)
    item = next(item for item in discover(tmp_path).candidates if item.path == "a.py")
    link.unlink()
    link.symlink_to(second)
    with pytest.raises(DiscoveryError) as target_error:
        item.revalidate(tmp_path.resolve())
    assert target_error.value.code is DiscoveryErrorCode.FILESYSTEM_MUTATION

    direct = next(item for item in discover(tmp_path).candidates if item.path == "first.py")
    replacement = write(tmp_path / "replacement.py")
    assert replacement.stat().st_ino != first.stat().st_ino
    os.replace(replacement, first)
    with pytest.raises(DiscoveryError) as inode_error:
        direct.revalidate(tmp_path.resolve())
    assert inode_error.value.code is DiscoveryErrorCode.FILESYSTEM_MUTATION


def test_revalidation_success_missing_and_type_change(tmp_path: Path) -> None:
    candidate = write(tmp_path / "app.py")
    item = discover(tmp_path).candidates[0]
    assert item.revalidate(tmp_path.resolve()) == candidate.resolve()
    candidate.unlink()
    with pytest.raises(DiscoveryError) as missing:
        item.revalidate(tmp_path.resolve())
    assert missing.value.code is DiscoveryErrorCode.FILESYSTEM_MUTATION

    candidate.mkdir()
    with pytest.raises(DiscoveryError) as changed_type:
        item.revalidate(tmp_path.resolve())
    assert changed_type.value.code is DiscoveryErrorCode.FILESYSTEM_MUTATION


def test_relative_logical_root_revalidates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path / "app.py")
    monkeypatch.chdir(tmp_path.parent)
    relative_root = Path(tmp_path.name)
    result = discover(relative_root)
    assert result.candidates[0].revalidate(tmp_path.resolve()) == (tmp_path / "app.py").resolve()


def test_public_serialization_never_leaks_absolute_paths(tmp_path: Path) -> None:
    write(tmp_path / "app.py")
    result = discover(tmp_path)
    serialized = result.to_public_json()
    assert str(tmp_path) not in serialized
    assert json.loads(serialized) == {
        "candidates": [{"kind": "python", "path": "app.py"}],
        "config_path": None,
    }


def test_root_config_is_separate_and_immune_to_filters(tmp_path: Path) -> None:
    config(tmp_path, include=["missing.py"], exclude=["runtime-contract.yaml"])
    with pytest.raises(DiscoveryError) as caught:
        discover(tmp_path)
    assert caught.value.code is DiscoveryErrorCode.INCLUDE_MATCHED_NOTHING
    config(tmp_path, include=[], exclude=["runtime-contract.yaml"])
    result = discover(tmp_path)
    assert result.config_path is not None
    assert result.config_path.path == "runtime-contract.yaml"
    assert result.candidates == ()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_config_symlink_must_be_safe(tmp_path: Path) -> None:
    actual = write(tmp_path / "config-source.yaml", "version: 1\n")
    (tmp_path / "runtime-contract.yaml").symlink_to(actual)
    safe_result = discover(tmp_path)
    assert safe_result.config_path is not None
    assert safe_result.candidates == ()
    (tmp_path / "runtime-contract.yaml").unlink()
    outside = write(tmp_path.parent / f"{tmp_path.name}-config", "version: 1\n")
    (tmp_path / "runtime-contract.yaml").symlink_to(outside)
    assert_code(tmp_path, DiscoveryErrorCode.UNSAFE_CONFIG_SYMLINK)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_broken_config_symlink_is_typed(tmp_path: Path) -> None:
    (tmp_path / "runtime-contract.yaml").symlink_to(tmp_path / "missing")
    assert_code(tmp_path, DiscoveryErrorCode.UNSAFE_CONFIG_SYMLINK)


def test_include_failure_modes_are_distinct(tmp_path: Path) -> None:
    config(tmp_path, include=["missing.py"])
    assert_code(tmp_path, DiscoveryErrorCode.INCLUDE_MATCHED_NOTHING)
    write(tmp_path / "unsupported.txt")
    config(tmp_path, include=["unsupported.txt"])
    assert_code(tmp_path, DiscoveryErrorCode.ALL_INCLUDED_REJECTED)


@pytest.mark.parametrize(
    "content",
    ["", "[]\n", "version: 2\n", "version: 1\nunknown: true\n", "version: 1\ninclude: app.py\n"],
)
def test_invalid_config_is_typed(tmp_path: Path, content: str) -> None:
    write(tmp_path / "runtime-contract.yaml", content)
    assert_code(tmp_path, DiscoveryErrorCode.INVALID_CONFIG)


def test_invalid_config_encoding_is_typed(tmp_path: Path) -> None:
    (tmp_path / "runtime-contract.yaml").write_bytes(b"\xff")
    assert_code(tmp_path, DiscoveryErrorCode.INVALID_CONFIG)


def test_entry_metadata_failure_is_typed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path / "app.py")

    class BrokenEntry:
        name = "app.py"
        path = str(tmp_path / "app.py")

        def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
            del follow_symlinks
            raise PermissionError("denied")

    monkeypatch.setattr(os, "scandir", lambda path: [BrokenEntry()])
    assert_code(tmp_path, DiscoveryErrorCode.INACCESSIBLE_PATH)


def test_entry_resolution_failure_is_typed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = write(tmp_path / "app.py")
    original_resolve = Path.resolve

    def broken_resolve(path: Path, *args: Any, **kwargs: Any) -> Path:
        if path == candidate:
            raise PermissionError("denied")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", broken_resolve)
    assert_code(tmp_path, DiscoveryErrorCode.INACCESSIBLE_PATH)


def test_config_and_gitignore_resource_errors_are_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = write(tmp_path / "runtime-contract.yaml", "version: 1\n")
    original_lstat = Path.lstat

    def broken_config_lstat(path: Path) -> os.stat_result:
        if path == config_path:
            raise PermissionError("denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", broken_config_lstat)
    assert_code(tmp_path, DiscoveryErrorCode.INACCESSIBLE_PATH)
    monkeypatch.setattr(Path, "lstat", original_lstat)
    config_path.unlink()

    ignore = write(tmp_path / ".gitignore", "*.py\n")

    def broken_ignore_lstat(path: Path) -> os.stat_result:
        if path == ignore:
            raise PermissionError("denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", broken_ignore_lstat)
    assert_code(tmp_path, DiscoveryErrorCode.INACCESSIBLE_PATH)


def test_gitignore_read_failure_and_pattern_compile_failure_are_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ignore = write(tmp_path / ".gitignore", "*.py\n")
    original_read_text = Path.read_text

    def broken_read(path: Path, *args: Any, **kwargs: Any) -> str:
        if path == ignore:
            raise PermissionError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", broken_read)
    assert_code(tmp_path, DiscoveryErrorCode.TRAVERSAL_FAILURE)
    monkeypatch.setattr(Path, "read_text", original_read_text)
    config(tmp_path, include=["*.py"])

    def broken_compile(lines: Any) -> Any:
        del lines
        raise ValueError("bad pattern")

    monkeypatch.setattr(GitIgnoreSpec, "from_lines", broken_compile)
    assert_code(tmp_path, DiscoveryErrorCode.INVALID_PATTERN)


def test_internal_scope_and_root_stat_error_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layer = discovery_module._IgnoreLayer("nested", GitIgnoreSpec.from_lines(["*.py"]))
    assert not discovery_module._ignored((layer,), "sibling/app.py", False)

    original_stat = Path.stat

    def broken_root_stat(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        if path == tmp_path.resolve():
            raise PermissionError("denied")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", broken_root_stat)
    assert_code(tmp_path, DiscoveryErrorCode.INVALID_ROOT)
