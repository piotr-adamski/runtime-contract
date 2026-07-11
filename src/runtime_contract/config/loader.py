"""Strict YAML loading, diagnostics, and filesystem validation."""

from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError
from yaml.nodes import MappingNode, Node, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, DocumentStartToken, TagToken

from runtime_contract.config.models import RuntimeContractConfig, SourceType


@dataclass(frozen=True, order=True, slots=True)
class ConfigError:
    """Stable public configuration diagnostic."""

    pointer: str
    code: str
    line: int
    column: int
    message: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "code": self.code,
            "pointer": self.pointer,
            "line": self.line,
            "column": self.column,
            "message": self.message,
        }


class ConfigValidationError(RuntimeError):
    """One or more deterministic configuration diagnostics."""

    def __init__(self, errors: list[ConfigError]) -> None:
        self.errors = tuple(sorted(errors, key=lambda item: (item.pointer.encode(), item.code)))
        super().__init__("configuration validation failed")


@dataclass(frozen=True, slots=True)
class ConfigDocument:
    config: RuntimeContractConfig
    path: Path
    locations: dict[str, tuple[int, int]]


def _escape(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _pointer(location: tuple[object, ...]) -> str:
    return "/" + "/".join(_escape(item) for item in location) if location else "/"


def _locations_and_duplicates(node: Node) -> tuple[dict[str, tuple[int, int]], list[ConfigError]]:
    locations: dict[str, tuple[int, int]] = {
        "/": (node.start_mark.line + 1, node.start_mark.column + 1)
    }
    duplicates: list[ConfigError] = []

    def visit(current: Node, path: tuple[object, ...]) -> None:
        locations[_pointer(path)] = (current.start_mark.line + 1, current.start_mark.column + 1)
        if isinstance(current, MappingNode):
            seen: set[str] = set()
            for key_node, value_node in current.value:
                key = key_node.value
                child = (*path, key)
                locations[_pointer(child)] = (
                    key_node.start_mark.line + 1,
                    key_node.start_mark.column + 1,
                )
                if key == "<<":
                    duplicates.append(
                        ConfigError(
                            _pointer(child),
                            "yaml_merge_key",
                            key_node.start_mark.line + 1,
                            key_node.start_mark.column + 1,
                            "YAML merge keys are not supported.",
                        )
                    )
                elif key in seen:
                    duplicates.append(
                        ConfigError(
                            _pointer(child),
                            "yaml_duplicate_key",
                            key_node.start_mark.line + 1,
                            key_node.start_mark.column + 1,
                            "Duplicate mapping key.",
                        )
                    )
                seen.add(key)
                visit(value_node, child)
        elif isinstance(current, SequenceNode):
            for index, child_node in enumerate(current.value):
                visit(child_node, (*path, index))

    visit(node, ())
    return locations, duplicates


def _location_for(pointer: str, locations: dict[str, tuple[int, int]]) -> tuple[int, int]:
    candidate = pointer
    while candidate not in locations and candidate != "/":
        candidate = candidate.rsplit("/", 1)[0] or "/"
    return locations.get(candidate, (1, 1))


def _syntax_error(error: BaseException) -> ConfigValidationError:
    mark = getattr(error, "problem_mark", None)
    line, column = (mark.line + 1, mark.column + 1) if mark is not None else (1, 1)
    return ConfigValidationError(
        [ConfigError("/", "yaml_syntax", line, column, "Invalid YAML syntax.")]
    )


def parse_strict_yaml(text: str) -> tuple[object, dict[str, tuple[int, int]]]:
    """Parse one safe YAML document after rejecting non-data YAML features."""

    try:
        tokens = list(yaml.scan(text))
        documents = [token for token in tokens if isinstance(token, DocumentStartToken)]
        if len(documents) > 1:
            token = documents[1]
            raise ConfigValidationError(
                [
                    ConfigError(
                        "/",
                        "yaml_multiple_documents",
                        token.start_mark.line + 1,
                        token.start_mark.column + 1,
                        "Exactly one YAML document is supported.",
                    )
                ]
            )
        forbidden = next(
            (token for token in tokens if isinstance(token, (AnchorToken, AliasToken, TagToken))),
            None,
        )
        if forbidden is not None:
            code = {
                AnchorToken: "yaml_anchor",
                AliasToken: "yaml_alias",
                TagToken: "yaml_tag",
            }[type(forbidden)]
            raise ConfigValidationError(
                [
                    ConfigError(
                        "/",
                        code,
                        forbidden.start_mark.line + 1,
                        forbidden.start_mark.column + 1,
                        "YAML anchors, aliases, and explicit tags are not supported.",
                    )
                ]
            )
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except ConfigValidationError:
        raise
    except yaml.YAMLError as error:  # pragma: no cover - compose already parsed the same input
        raise _syntax_error(error) from None
    if len(nodes) > 1:
        second = nodes[1]
        assert second is not None
        raise ConfigValidationError(
            [
                ConfigError(
                    "/",
                    "yaml_multiple_documents",
                    second.start_mark.line + 1,
                    second.start_mark.column + 1,
                    "Exactly one YAML document is supported.",
                )
            ]
        )
    if len(nodes) != 1 or nodes[0] is None:
        raise ConfigValidationError(
            [ConfigError("/", "config_type", 1, 1, "Configuration must be a mapping.")]
        )
    locations, structural_errors = _locations_and_duplicates(nodes[0])
    if structural_errors:
        raise ConfigValidationError(structural_errors)
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as error:  # pragma: no cover - compose already parsed the same input
        raise _syntax_error(error) from None
    return loaded, locations


def _pydantic_errors(
    error: ValidationError, locations: dict[str, tuple[int, int]]
) -> list[ConfigError]:
    result: list[ConfigError] = []
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        location = tuple(part for part in item["loc"] if part != "root")
        pointer = _pointer(location)
        line, column = _location_for(pointer, locations)
        error_type = str(item["type"])
        if error_type == "extra_forbidden":
            code, message = "unknown_field", "Unknown configuration field."
        elif location == ("version",):
            code, message = "invalid_version", "version must be the integer 1."
        else:
            code, message = "invalid_value", str(item["msg"])
        result.append(ConfigError(pointer, code, line, column, message))
    return result


def _contained(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _filesystem_errors(config: RuntimeContractConfig, logical_root: Path) -> list[ConfigError]:
    errors: list[ConfigError] = []
    canonical_root = logical_root.resolve(strict=True)
    canonical_targets: dict[Path, str] = {}
    for name, target in config.effective_roots().items():
        path = logical_root / target.path
        pointer = f"/roots/{_escape(name)}/path" if config.roots is not None else "/roots"
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            errors.append(ConfigError(pointer, "root_inaccessible", 1, 1, "Root is inaccessible."))
            continue
        if not _contained(resolved, canonical_root) or not stat.S_ISDIR(metadata.st_mode):
            errors.append(
                ConfigError(
                    pointer,
                    "root_unsafe",
                    1,
                    1,
                    "Root must resolve to a directory inside the project root.",
                )
            )
            continue
        if resolved in canonical_targets:
            errors.append(
                ConfigError(
                    pointer,
                    "root_alias",
                    1,
                    1,
                    "Roots must not resolve to the same canonical target.",
                )
            )
        canonical_targets[resolved] = name
    for environment_name, environment in config.environments.items():
        for index, source in enumerate(environment.sources):
            root = config.effective_roots()[source.root]
            target_root = (logical_root / root.path).resolve(strict=False)
            source_path = target_root / source.path
            pointer = f"/environments/{_escape(environment_name)}/sources/{index}/path"
            try:
                resolved = source_path.resolve(strict=True)
                metadata = resolved.stat()
            except (OSError, RuntimeError):
                errors.append(
                    ConfigError(pointer, "source_inaccessible", 1, 1, "Source is inaccessible.")
                )
                continue
            if not _contained(resolved, target_root) or not stat.S_ISREG(metadata.st_mode):
                errors.append(
                    ConfigError(
                        pointer,
                        "source_unsafe",
                        1,
                        1,
                        "Source must be a regular file inside its root.",
                    )
                )
                continue
            suffix = resolved.suffix.lower()
            compose_file = bool(re.fullmatch(r"(?:docker-)?compose[^/]*\.ya?ml", resolved.name))
            supported_yaml = suffix in {".yaml", ".yml", ".json"}
            type_matches = (
                (source.type is SourceType.AUTO and supported_yaml)
                or (source.type is SourceType.COMPOSE and compose_file)
                or (source.type is SourceType.KUBERNETES and supported_yaml)
            )
            if not type_matches:
                errors.append(
                    ConfigError(
                        pointer,
                        "source_type",
                        1,
                        1,
                        "Source type must match a supported source file.",
                    )
                )
    return errors


def load_config(
    logical_root: Path, *, require: bool = False, config_path: Path | None = None
) -> ConfigDocument | None:
    """Load and validate the sole root configuration without parent search."""

    path = logical_root / (config_path or Path("runtime-contract.yaml"))
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if require:
            raise ConfigValidationError(
                [ConfigError("/", "config_missing", 1, 1, "Configuration file was not found.")]
            ) from None
        return None
    except OSError:  # pragma: no cover - platform-specific lstat failure
        raise ConfigValidationError(
            [ConfigError("/", "config_read", 1, 1, "Cannot inspect configuration file.")]
        ) from None
    try:
        canonical_root = logical_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except (OSError, RuntimeError):  # pragma: no cover - concurrent filesystem mutation
        raise ConfigValidationError(
            [
                ConfigError(
                    "/", "config_unsafe", 1, 1, "Configuration path is not a safe regular file."
                )
            ]
        ) from None
    if not _contained(resolved, canonical_root) or not stat.S_ISREG(resolved_metadata.st_mode):
        raise ConfigValidationError(
            [
                ConfigError(
                    "/", "config_unsafe", 1, 1, "Configuration path is not a safe regular file."
                )
            ]
        )
    try:
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ConfigValidationError(
            [ConfigError("/", "config_read", 1, 1, "Cannot read configuration file as UTF-8.")]
        ) from None
    loaded, locations = parse_strict_yaml(text)
    try:
        config = RuntimeContractConfig.model_validate(loaded)
    except ValidationError as error:
        raise ConfigValidationError(_pydantic_errors(error, locations)) from None
    filesystem_errors = _filesystem_errors(config, logical_root)
    if filesystem_errors:
        located = [
            ConfigError(
                item.pointer, item.code, *_location_for(item.pointer, locations), item.message
            )
            for item in filesystem_errors
        ]
        raise ConfigValidationError(located)
    del metadata
    return ConfigDocument(config, resolved, locations)


def errors_json(error: ConfigValidationError) -> str:
    return json.dumps(
        {"valid": False, "errors": [item.as_dict() for item in error.errors]}, sort_keys=True
    )
