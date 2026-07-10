"""Safe and deterministic discovery of runtime-contract input files."""

from __future__ import annotations

import heapq
import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

import yaml
from pathspec import GitIgnoreSpec


class DiscoveryErrorCode(StrEnum):
    INVALID_ROOT = "invalid_root"
    INACCESSIBLE_PATH = "inaccessible_path"
    INVALID_PATTERN = "invalid_pattern"
    UNSAFE_CONFIG_SYMLINK = "unsafe_config_symlink"
    OUTSIDE_ROOT_SYMLINK = "outside_root_symlink"
    FILESYSTEM_MUTATION = "filesystem_mutation"
    UNICODE_COLLISION = "unicode_normalization_collision"
    TRAVERSAL_FAILURE = "resource_traversal_failure"
    INCLUDE_MATCHED_NOTHING = "include_matched_nothing"
    ALL_INCLUDED_REJECTED = "all_included_paths_rejected"
    INVALID_CONFIG = "invalid_config"


class DiscoveryError(RuntimeError):
    """A stable technical discovery failure suitable for mapping to CLI exit 2."""

    def __init__(self, code: DiscoveryErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class CandidateKind(StrEnum):
    CONFIG = "config"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    KUBERNETES = "kubernetes"
    ENV_EXAMPLE = "env_example"


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> FileIdentity:
        return cls(device=value.st_dev, inode=value.st_ino)


@dataclass(frozen=True, slots=True)
class DiscoveryItem:
    """A candidate plus private data required for TOCTOU revalidation."""

    path: str
    kind: CandidateKind
    identity: FileIdentity
    _resolved_path: Path = field(repr=False, compare=False)
    _logical_path: Path = field(repr=False, compare=False)

    def to_public_dict(self) -> dict[str, str]:
        return {"path": self.path, "kind": self.kind.value}

    def revalidate(self, canonical_root: Path) -> Path:
        """Re-resolve and verify this file immediately before a parser opens it."""

        try:
            resolved = self._logical_path.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError) as error:
            _raise(
                DiscoveryErrorCode.FILESYSTEM_MUTATION,
                f"candidate changed before read: {self.path}",
                error,
            )
        if not _contained(resolved, canonical_root) or not stat.S_ISREG(metadata.st_mode):
            raise DiscoveryError(
                DiscoveryErrorCode.FILESYSTEM_MUTATION,
                f"candidate changed type or target before read: {self.path}",
            )
        if FileIdentity.from_stat(metadata) != self.identity or resolved != self._resolved_path:
            raise DiscoveryError(
                DiscoveryErrorCode.FILESYSTEM_MUTATION,
                f"candidate identity changed before read: {self.path}",
            )
        return resolved


@dataclass(frozen=True, slots=True)
class DiscoveryStats:
    skipped_special_files: int = 0
    skipped_broken_symlinks: int = 0
    deduplicated_files: int = 0
    deduplicated_directories: int = 0


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    logical_root: Path
    canonical_root: Path = field(repr=False)
    candidates: tuple[DiscoveryItem, ...]
    config_path: DiscoveryItem | None
    stats: DiscoveryStats

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "candidates": [item.to_public_dict() for item in self.candidates],
            "config_path": self.config_path.path if self.config_path else None,
        }

    def to_public_json(self) -> str:
        return json.dumps(self.to_public_dict(), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True, slots=True)
class _Config:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _IgnoreLayer:
    base: str
    spec: GitIgnoreSpec


@dataclass(order=True, slots=True)
class _DirectoryJob:
    sort_key: bytes
    logical_relative: str = field(compare=False)
    logical_path: Path = field(compare=False)
    resolved_path: Path = field(compare=False)
    ignore_layers: tuple[_IgnoreLayer, ...] = field(compare=False)


DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "vendor",
        "dist",
        "build",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".next",
        "coverage",
        "htmlcov",
    }
)

_CODE_SUFFIXES = {
    ".py": CandidateKind.PYTHON,
    ".js": CandidateKind.JAVASCRIPT,
    ".jsx": CandidateKind.JAVASCRIPT,
    ".mjs": CandidateKind.JAVASCRIPT,
    ".cjs": CandidateKind.JAVASCRIPT,
    ".ts": CandidateKind.JAVASCRIPT,
    ".tsx": CandidateKind.JAVASCRIPT,
}
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[/\\]")


def discover(root: str | os.PathLike[str]) -> DiscoveryResult:
    """Discover supported files under *root* without reading candidate contents."""

    logical_root = Path(root)
    canonical_root, root_stat = _validate_root(logical_root)
    config_item, config = _load_root_config(logical_root, canonical_root)
    include = _compile_filter_patterns(config.include, "include")
    exclude = _compile_filter_patterns(config.exclude, "exclude")

    stats = {"special": 0, "broken": 0, "files": 0, "directories": 0}
    seen_directories: set[FileIdentity] = set()
    candidates_by_identity: dict[FileIdentity, DiscoveryItem] = {}
    normalized_raw_paths: dict[str, str] = {}
    include_matched_existing = False
    include_rejected = False

    seen_directories.add(FileIdentity.from_stat(root_stat))
    jobs = [
        _DirectoryJob(
            b"",
            "",
            logical_root,
            canonical_root,
            _load_gitignore(logical_root, ""),
        )
    ]

    while jobs:
        job = heapq.heappop(jobs)
        try:
            entries = list(os.scandir(job.logical_path))
        except OSError as error:
            _raise(
                DiscoveryErrorCode.INACCESSIBLE_PATH,
                f"cannot read directory: {job.logical_relative or '.'}",
                error,
            )
        entries.sort(
            key=lambda entry: _sort_key(_report_path(_join(job.logical_relative, entry.name)))
        )
        for entry in entries:
            raw_relative = _join(job.logical_relative, entry.name)
            reported = _report_path(raw_relative)
            _register_normalized_path(normalized_raw_paths, raw_relative, reported)
            if reported == "runtime-contract.yaml" or entry.name == ".gitignore":
                continue
            if _is_hard_env_name(entry.name):
                include_rejected |= bool(include and include.match_file(raw_relative))
                include_matched_existing |= bool(include and include.match_file(raw_relative))
                continue

            try:
                link_metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                _raise(
                    DiscoveryErrorCode.INACCESSIBLE_PATH, f"cannot inspect path: {reported}", error
                )

            is_link = stat.S_ISLNK(link_metadata.st_mode)
            if is_link:
                try:
                    resolved = Path(entry.path).resolve(strict=True)
                    metadata = resolved.stat()
                except (OSError, RuntimeError):
                    stats["broken"] += 1
                    continue
                if not _contained(resolved, canonical_root):
                    raise DiscoveryError(
                        DiscoveryErrorCode.OUTSIDE_ROOT_SYMLINK,
                        f"symlink target is outside the analysis root: {reported}",
                    )
            else:
                try:
                    resolved = Path(entry.path).resolve(strict=True)
                except (OSError, RuntimeError) as error:
                    _raise(
                        DiscoveryErrorCode.INACCESSIBLE_PATH,
                        f"cannot resolve path: {reported}",
                        error,
                    )
                metadata = link_metadata

            is_directory = stat.S_ISDIR(metadata.st_mode)
            matched_include = bool(
                include and include.match_file(raw_relative + ("/" if is_directory else ""))
            )
            include_matched_existing |= matched_include
            hard_git = entry.name == ".git" and is_directory
            excluded = bool(
                exclude and exclude.match_file(raw_relative + ("/" if is_directory else ""))
            )
            if hard_git or excluded:
                descendant_selected = is_directory and _include_can_match_descendant(
                    config.include, raw_relative
                )
                include_matched_existing |= matched_include or descendant_selected
                include_rejected |= matched_include or descendant_selected
                continue

            ignored = _ignored(job.ignore_layers, raw_relative, is_directory)
            default_excluded = is_directory and entry.name in DEFAULT_EXCLUDED_DIRECTORIES
            if is_directory:
                if (ignored or default_excluded) and not _include_can_match_descendant(
                    config.include, raw_relative
                ):
                    continue
                identity = FileIdentity.from_stat(metadata)
                if identity in seen_directories:
                    stats["directories"] += 1
                    continue
                seen_directories.add(identity)
                layers = job.ignore_layers + _load_gitignore(Path(entry.path), raw_relative)
                heapq.heappush(
                    jobs,
                    _DirectoryJob(
                        _sort_key(reported), raw_relative, Path(entry.path), resolved, layers
                    ),
                )
                continue

            if not stat.S_ISREG(metadata.st_mode):
                stats["special"] += 1
                include_rejected |= matched_include
                continue
            if include and not matched_include:
                continue
            if ignored and not matched_include:
                continue
            kind = _classify(entry.name)
            if kind is None:
                include_rejected |= matched_include
                continue

            identity = FileIdentity.from_stat(metadata)
            if config_item is not None and identity == config_item.identity:
                continue
            item = DiscoveryItem(reported, kind, identity, resolved, Path(entry.path))
            previous = candidates_by_identity.get(identity)
            if previous is not None:
                stats["files"] += 1
                if _sort_key(item.path) < _sort_key(previous.path):
                    candidates_by_identity[identity] = item
            else:
                candidates_by_identity[identity] = item

    if include and not include_matched_existing:
        raise DiscoveryError(
            DiscoveryErrorCode.INCLUDE_MATCHED_NOTHING,
            "include patterns matched no existing path",
        )
    if include and not candidates_by_identity:
        raise DiscoveryError(
            DiscoveryErrorCode.ALL_INCLUDED_REJECTED,
            "all paths selected by include were rejected",
        )

    candidates = tuple(
        sorted(candidates_by_identity.values(), key=lambda item: _sort_key(item.path))
    )
    return DiscoveryResult(
        logical_root=logical_root,
        canonical_root=canonical_root,
        candidates=candidates,
        config_path=config_item,
        stats=DiscoveryStats(
            stats["special"], stats["broken"], stats["files"], stats["directories"]
        ),
    )


def _validate_root(logical_root: Path) -> tuple[Path, os.stat_result]:
    try:
        canonical = logical_root.resolve(strict=True)
        metadata = canonical.stat()
    except (OSError, RuntimeError) as error:
        _raise(
            DiscoveryErrorCode.INVALID_ROOT,
            "analysis root does not exist or is inaccessible",
            error,
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise DiscoveryError(DiscoveryErrorCode.INVALID_ROOT, "analysis root must be a directory")
    return canonical, metadata


def _load_root_config(
    logical_root: Path, canonical_root: Path
) -> tuple[DiscoveryItem | None, _Config]:
    path = logical_root / "runtime-contract.yaml"
    try:
        path.lstat()
    except FileNotFoundError:
        return None, _Config()
    except OSError as error:
        _raise(DiscoveryErrorCode.INACCESSIBLE_PATH, "cannot inspect runtime-contract.yaml", error)
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as error:
        _raise(DiscoveryErrorCode.UNSAFE_CONFIG_SYMLINK, "runtime-contract.yaml is broken", error)
    if not _contained(resolved, canonical_root) or not stat.S_ISREG(metadata.st_mode):
        raise DiscoveryError(
            DiscoveryErrorCode.UNSAFE_CONFIG_SYMLINK,
            "runtime-contract.yaml must resolve to a regular file inside the analysis root",
        )
    try:
        loaded = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        _raise(
            DiscoveryErrorCode.INVALID_CONFIG,
            "runtime-contract.yaml is not valid UTF-8 YAML",
            error,
        )
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise DiscoveryError(DiscoveryErrorCode.INVALID_CONFIG, "configuration must be a mapping")
    version = loaded.get("version")
    if version != 1 or isinstance(version, bool):
        raise DiscoveryError(
            DiscoveryErrorCode.INVALID_CONFIG, "configuration version must equal 1"
        )
    allowed = {
        "version",
        "include",
        "exclude",
        "secret_patterns",
        "rules",
        "profiles",
        "components",
    }
    unknown = set(loaded) - allowed
    if unknown:
        raise DiscoveryError(
            DiscoveryErrorCode.INVALID_CONFIG, "configuration contains unknown fields"
        )
    include = _string_list(loaded.get("include", []), "include")
    exclude = _string_list(loaded.get("exclude", []), "exclude")
    identity = FileIdentity.from_stat(metadata)
    item = DiscoveryItem("runtime-contract.yaml", CandidateKind.CONFIG, identity, resolved, path)
    return item, _Config(include, exclude)


def _string_list(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise DiscoveryError(
            DiscoveryErrorCode.INVALID_CONFIG,
            f"configuration {field_name} must be a list of strings",
        )
    return tuple(value)


def _compile_filter_patterns(patterns: Sequence[str], field_name: str) -> GitIgnoreSpec | None:
    if not patterns:
        return None
    for pattern in patterns:
        stripped = pattern.strip()
        parts = PurePosixPath(stripped.lstrip("/")).parts
        if (
            not stripped
            or "\0" in pattern
            or stripped.startswith("!")
            or "\\" in pattern
            or ".." in parts
            or stripped.startswith("//")
            or _WINDOWS_ABSOLUTE.match(stripped)
        ):
            raise DiscoveryError(
                DiscoveryErrorCode.INVALID_PATTERN,
                f"invalid {field_name} pattern",
            )
    try:
        return GitIgnoreSpec.from_lines(patterns)
    except ValueError as error:
        _raise(DiscoveryErrorCode.INVALID_PATTERN, f"invalid {field_name} pattern", error)


def _load_gitignore(directory: Path, relative: str) -> tuple[_IgnoreLayer, ...]:
    path = directory / ".gitignore"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return ()
    except OSError as error:
        _raise(
            DiscoveryErrorCode.INACCESSIBLE_PATH,
            f"cannot inspect {_join(relative, '.gitignore')}",
            error,
        )
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return ()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        return (_IgnoreLayer(relative, GitIgnoreSpec.from_lines(lines)),)
    except (OSError, UnicodeError, ValueError) as error:
        _raise(
            DiscoveryErrorCode.TRAVERSAL_FAILURE,
            f"cannot read {_join(relative, '.gitignore')}",
            error,
        )


def _ignored(layers: Iterable[_IgnoreLayer], path: str, is_directory: bool) -> bool:
    state: bool | None = None
    for layer in layers:
        if layer.base:
            prefix = layer.base + "/"
            if not path.startswith(prefix):
                continue
            scoped = path[len(prefix) :]
        else:
            scoped = path
        result = layer.spec.check_file(scoped + ("/" if is_directory else ""))
        if result.include is not None:
            state = result.include
    return bool(state)


def _include_can_match_descendant(patterns: Sequence[str], directory: str) -> bool:
    prefix = directory.rstrip("/") + "/"
    for pattern in patterns:
        plain = pattern.lstrip("/")
        static = re.split(r"[*?[]", plain, maxsplit=1)[0]
        if static.startswith(prefix) or prefix.startswith(static.rstrip("/") + "/"):
            return True
        if not static or "/" not in plain:
            return True
    return False


def _classify(name: str) -> CandidateKind | None:
    if name == ".env.example":
        return CandidateKind.ENV_EXAMPLE
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return CandidateKind.DOCKERFILE
    if re.fullmatch(r"(?:docker-)?compose[^/]*\.ya?ml", name):
        return CandidateKind.COMPOSE
    suffix = Path(name).suffix
    if suffix in _CODE_SUFFIXES:
        return _CODE_SUFFIXES[suffix]
    if suffix in {".yaml", ".yml", ".json"}:
        return CandidateKind.KUBERNETES
    return None


def _is_hard_env_name(name: str) -> bool:
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def _register_normalized_path(mapping: dict[str, str], raw: str, reported: str) -> None:
    previous = mapping.get(reported)
    if previous is not None and previous != raw:
        raise DiscoveryError(
            DiscoveryErrorCode.UNICODE_COLLISION,
            f"multiple filesystem paths normalize to the same reported path: {reported}",
        )
    mapping[reported] = raw


def _contained(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _join(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _report_path(path: str) -> str:
    return unicodedata.normalize("NFC", path.replace(os.sep, "/"))


def _sort_key(path: str) -> bytes:
    return path.encode("utf-8")


def _raise(code: DiscoveryErrorCode, message: str, cause: BaseException) -> NoReturn:
    raise DiscoveryError(code, message) from cause
