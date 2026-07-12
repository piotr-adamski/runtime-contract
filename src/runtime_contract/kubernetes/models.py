"""Public immutable models for static Kubernetes workload traversal."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import unicodedata
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from runtime_contract.domain import Severity, SourceLocation


class _KubernetesModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
    )


class KubernetesLoadStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class KubernetesWorkloadKind(StrEnum):
    POD = "Pod"
    DEPLOYMENT = "Deployment"
    STATEFUL_SET = "StatefulSet"
    DAEMON_SET = "DaemonSet"
    JOB = "Job"
    CRON_JOB = "CronJob"


class KubernetesContainerKind(StrEnum):
    CONTAINER = "container"
    INIT_CONTAINER = "init_container"


class KubernetesEnvSourceKind(StrEnum):
    VALUE = "value"
    SECRET_KEY_REF = "secret_key_ref"
    CONFIG_MAP_KEY_REF = "config_map_key_ref"
    FIELD_REF = "field_ref"
    RESOURCE_FIELD_REF = "resource_field_ref"


class KubernetesEnvFromSourceKind(StrEnum):
    SECRET_REF = "secret_ref"
    CONFIG_MAP_REF = "config_map_ref"


class KubernetesObjectKind(StrEnum):
    CONFIG_MAP = "ConfigMap"
    SECRET = "Secret"


class KubernetesObjectKeyField(StrEnum):
    DATA = "data"
    STRING_DATA = "stringData"
    BINARY_DATA = "binaryData"


class KubernetesReferenceKind(StrEnum):
    SECRET_KEY_REF = "secret_key_ref"
    CONFIG_MAP_KEY_REF = "config_map_key_ref"
    SECRET_REF = "secret_ref"
    CONFIG_MAP_REF = "config_map_ref"


class KubernetesDiagnosticCode(StrEnum):
    INVALID_ENCODING = "invalid_encoding"
    INVALID_YAML = "invalid_yaml"
    DUPLICATE_KEY = "duplicate_key"
    UNSUPPORTED_TAG = "unsupported_tag"
    CYCLIC_ALIAS = "cyclic_alias"
    SAFETY_LIMIT = "safety_limit"
    INVALID_DOCUMENT = "invalid_document"
    MISSING_API_VERSION = "missing_api_version"
    MISSING_KIND = "missing_kind"
    UNSUPPORTED_RESOURCE = "unsupported_resource"
    INVALID_METADATA = "invalid_metadata"
    MISSING_WORKLOAD_NAME = "missing_workload_name"
    MISSING_POD_SPEC = "missing_pod_spec"
    INVALID_CONTAINERS = "invalid_containers"
    INVALID_CONTAINER = "invalid_container"
    DUPLICATE_CONTAINER_NAME = "duplicate_container_name"
    INVALID_ENV = "invalid_env"
    INVALID_ENV_ENTRY = "invalid_env_entry"
    DUPLICATE_ENV_NAME = "duplicate_env_name"
    INVALID_ENV_SOURCE = "invalid_env_source"
    INVALID_ENV_REFERENCE = "invalid_env_reference"
    INVALID_ENV_FROM = "invalid_env_from"
    INVALID_ENV_FROM_SOURCE = "invalid_env_from_source"
    INVALID_ENV_FROM_REFERENCE = "invalid_env_from_reference"
    INVALID_OBJECT_KEYS = "invalid_object_keys"
    DUPLICATE_OBJECT_IDENTITY = "duplicate_object_identity"


_SEVERITIES = {code: Severity.ERROR for code in KubernetesDiagnosticCode}
_SEVERITIES[KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE] = Severity.INFO


class KubernetesInput(_KubernetesModel):
    path: str
    content: bytes = Field(repr=False, exclude=True)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        value = unicodedata.normalize("NFC", value)
        if (
            not value
            or "\0" in value
            or "\\" in value
            or value.startswith("/")
            or re.match(r"^[A-Za-z]:", value)
        ):
            raise ValueError("path must be a non-empty relative POSIX path")
        normalized = posixpath.normpath(value)
        if normalized in {"", ".", ".."} or normalized.startswith("../"):
            raise ValueError("path must remain within the logical root")
        return normalized


def _validate_metadata_text(value: str | None) -> str | None:
    if value is not None and "\0" in value:
        raise ValueError("Kubernetes metadata cannot contain NUL")
    return value


class KubernetesEnvBinding(_KubernetesModel):
    """One value-blind ``env`` declaration attached to a container."""

    name: str
    index: int = Field(ge=0)
    source_kind: KubernetesEnvSourceKind
    reference_name: str | None = None
    reference_key: str | None = None
    optional: bool | None = None
    field_api_version: str | None = None
    field_path: str | None = None
    resource_container: str | None = None
    resource: str | None = None
    divisor: str | None = None
    location: SourceLocation
    source_location: SourceLocation

    _metadata_text = field_validator(
        "name",
        "reference_name",
        "reference_key",
        "field_api_version",
        "field_path",
        "resource_container",
        "resource",
        "divisor",
    )(_validate_metadata_text)

    @model_validator(mode="after")
    def validate_source_shape(self) -> KubernetesEnvBinding:
        if not self.name or "=" in self.name:
            raise ValueError("environment name must be non-empty and cannot contain '='")
        if self.location.path != self.source_location.path:
            raise ValueError("binding locations must use the same path")
        reference = (self.reference_name, self.reference_key, self.optional)
        field = (self.field_api_version, self.field_path)
        resource = (self.resource_container, self.resource, self.divisor)
        if self.source_kind is KubernetesEnvSourceKind.VALUE:
            if any(item is not None for item in (*reference, *field, *resource)):
                raise ValueError("value bindings cannot expose source metadata")
        elif self.source_kind in {
            KubernetesEnvSourceKind.SECRET_KEY_REF,
            KubernetesEnvSourceKind.CONFIG_MAP_KEY_REF,
        }:
            if (
                not self.reference_name
                or not self.reference_key
                or self.optional is None
                or any(item is not None for item in (*field, *resource))
            ):
                raise ValueError("key references require name, key, and optional only")
        elif self.source_kind is KubernetesEnvSourceKind.FIELD_REF:
            if not self.field_path or any(item is not None for item in (*reference, *resource)):
                raise ValueError("fieldRef requires field_path metadata only")
        elif not self.resource or any(item is not None for item in (*reference, *field)):
            raise ValueError("resourceFieldRef requires resource metadata only")
        return self


class KubernetesEnvFromSource(_KubernetesModel):
    """One unresolved, value-blind ``envFrom`` source attached to a container."""

    source_kind: KubernetesEnvFromSourceKind
    index: int = Field(ge=0)
    reference_name: str
    optional: bool
    prefix: str = ""
    location: SourceLocation
    source_location: SourceLocation

    _metadata_text = field_validator("reference_name", "prefix")(_validate_metadata_text)

    @model_validator(mode="after")
    def validate_source_shape(self) -> KubernetesEnvFromSource:
        if not self.reference_name:
            raise ValueError("envFrom reference name must be non-empty")
        if self.location.path != self.source_location.path:
            raise ValueError("envFrom locations must use the same path")
        return self


class KubernetesContainerContext(_KubernetesModel):
    path: str
    document_index: int
    api_version: str
    workload_kind: KubernetesWorkloadKind
    workload_name: str
    namespace: str
    container_kind: KubernetesContainerKind
    container_name: str
    container_index: int
    workload_location: SourceLocation
    container_location: SourceLocation
    env: tuple[KubernetesEnvBinding, ...] = ()
    env_from: tuple[KubernetesEnvFromSource, ...] = ()

    @model_validator(mode="after")
    def locations_match_path(self) -> KubernetesContainerContext:
        if self.workload_location.path != self.path or self.container_location.path != self.path:
            raise ValueError("locations must use the context path")
        env_locations = (
            location for item in self.env for location in (item.location, item.source_location)
        )
        env_from_locations = (
            location for item in self.env_from for location in (item.location, item.source_location)
        )
        if any(location.path != self.path for location in (*env_locations, *env_from_locations)):
            raise ValueError("environment locations must use the context path")
        return self


class KubernetesObjectKeyPresence(_KubernetesModel):
    """A key name observed in a local ConfigMap or Secret, never its value."""

    name: str
    field: KubernetesObjectKeyField
    location: SourceLocation

    _metadata_text = field_validator("name")(_validate_metadata_text)

    @model_validator(mode="after")
    def validate_name(self) -> KubernetesObjectKeyPresence:
        if not self.name or "=" in self.name:
            raise ValueError("object key name must be non-empty and cannot contain '='")
        return self


class KubernetesObjectPresence(_KubernetesModel):
    """Value-blind identity and key-name inventory for one local object."""

    path: str
    document_index: int = Field(ge=1)
    api_version: str
    object_kind: KubernetesObjectKind
    name: str
    namespace: str
    location: SourceLocation
    keys: tuple[KubernetesObjectKeyPresence, ...] = ()

    _metadata_text = field_validator("api_version", "name", "namespace")(_validate_metadata_text)

    @model_validator(mode="after")
    def canonicalize(self) -> KubernetesObjectPresence:
        if not self.name or not self.namespace:
            raise ValueError("object name and namespace must be non-empty")
        if self.location.path != self.path or any(
            item.location.path != self.path for item in self.keys
        ):
            raise ValueError("object locations must use the object path")
        keys = tuple(sorted(self.keys, key=lambda item: item.name.encode("utf-8")))
        if len({item.name for item in keys}) != len(keys):
            raise ValueError("object key names must be unique")
        if keys != self.keys:
            object.__setattr__(self, "keys", keys)
        return self

    def identity(self) -> tuple[str, str, str]:
        return self.namespace, self.object_kind.value, self.name


class KubernetesSourceStatus(_KubernetesModel):
    path: str
    status: KubernetesLoadStatus


class KubernetesReferenceResolution(_KubernetesModel):
    """Presence-only link from a workload reference to a same-namespace local object."""

    path: str
    document_index: int = Field(ge=1)
    namespace: str
    workload_kind: KubernetesWorkloadKind
    workload_name: str
    container_name: str
    reference_kind: KubernetesReferenceKind
    source_index: int = Field(ge=0)
    reference_name: str
    reference_key: str | None = None
    optional: bool
    prefix: str = ""
    resolved_object: bool
    resolved_key: bool | None = None
    resolved_keys: tuple[str, ...] = ()
    location: SourceLocation
    source_location: SourceLocation

    _metadata_text = field_validator(
        "namespace",
        "workload_name",
        "container_name",
        "reference_name",
        "reference_key",
        "prefix",
    )(_validate_metadata_text)

    @model_validator(mode="after")
    def validate_shape(self) -> KubernetesReferenceResolution:
        if (
            not self.namespace
            or not self.workload_name
            or not self.container_name
            or not self.reference_name
        ):
            raise ValueError("reference identity fields must be non-empty")
        if self.location.path != self.path or self.source_location.path != self.path:
            raise ValueError("reference locations must use the reference path")
        key_reference = self.reference_kind in {
            KubernetesReferenceKind.SECRET_KEY_REF,
            KubernetesReferenceKind.CONFIG_MAP_KEY_REF,
        }
        if key_reference:
            if (
                not self.reference_key
                or self.resolved_key is None
                or self.prefix
                or self.resolved_keys
            ):
                raise ValueError("key references require one key result and no bulk metadata")
        elif self.reference_key is not None or self.resolved_key is not None:
            raise ValueError("bulk references cannot expose a single-key result")
        if not self.resolved_object and (self.resolved_key or self.resolved_keys):
            raise ValueError("an unresolved object cannot resolve keys")
        keys = tuple(sorted(set(self.resolved_keys), key=lambda item: item.encode("utf-8")))
        if keys != self.resolved_keys:
            object.__setattr__(self, "resolved_keys", keys)
        return self


class KubernetesDiagnostic(_KubernetesModel):
    id: str = ""
    code: KubernetesDiagnosticCode
    severity: Severity
    location: SourceLocation
    parameters: tuple[tuple[str, str], ...] = ()
    rule_id: str | None = None

    @model_validator(mode="after")
    def canonicalize(self) -> KubernetesDiagnostic:
        if self.severity is not _SEVERITIES[self.code]:
            raise ValueError("diagnostic severity does not match its code")
        parameters = tuple(sorted(self.parameters))
        if len({key for key, _ in parameters}) != len(parameters):
            raise ValueError("diagnostic parameter keys must be unique")
        if self.code is KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE:
            if self.rule_id != "RTC012":
                raise ValueError("unsupported_resource requires RTC012")
        elif self.rule_id is not None:
            raise ValueError("only unsupported_resource has a rule id")
        if parameters != self.parameters:
            object.__setattr__(self, "parameters", parameters)
        expected = self.calculate_id(self.code, self.location, parameters, self.rule_id)
        if self.id and self.id != expected:
            raise ValueError("id does not match diagnostic identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        code: KubernetesDiagnosticCode,
        location: SourceLocation,
        parameters: tuple[tuple[str, str], ...],
        rule_id: str | None,
    ) -> str:
        payload = {
            "code": code.value,
            "location": location.identity(),
            "parameters": parameters,
            "rule_id": rule_id,
        }
        return (
            "kubernetes-diagnostic-"
            + hashlib.sha256(
                json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
        )


class KubernetesTraversalResult(_KubernetesModel):
    status: KubernetesLoadStatus
    contexts: tuple[KubernetesContainerContext, ...] = ()
    objects: tuple[KubernetesObjectPresence, ...] = ()
    resolutions: tuple[KubernetesReferenceResolution, ...] = ()
    sources: tuple[KubernetesSourceStatus, ...] = ()
    diagnostics: tuple[KubernetesDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> KubernetesTraversalResult:
        contexts = tuple(
            sorted(
                self.contexts,
                key=lambda item: (
                    item.path.encode("utf-8"),
                    item.document_index,
                    item.namespace,
                    item.workload_kind.value,
                    item.workload_name,
                    item.container_kind.value,
                    item.container_index,
                    item.container_name,
                ),
            )
        )
        diagnostics = tuple(sorted(self.diagnostics, key=lambda item: item.id))
        objects = tuple(
            sorted(
                self.objects,
                key=lambda item: (
                    item.path.encode("utf-8"),
                    item.document_index,
                    item.namespace,
                    item.object_kind.value,
                    item.name,
                ),
            )
        )
        sources = tuple(sorted(self.sources, key=lambda item: item.path.encode("utf-8")))
        resolutions = tuple(
            sorted(
                self.resolutions,
                key=lambda item: (
                    item.path.encode("utf-8"),
                    item.document_index,
                    item.namespace,
                    item.workload_kind.value,
                    item.workload_name,
                    item.container_name,
                    item.reference_kind.value,
                    item.source_index,
                ),
            )
        )
        if len({item.path for item in sources}) != len(sources):
            raise ValueError("source paths must be unique")
        if self.status is KubernetesLoadStatus.FAILED and (
            self.contexts or self.objects or self.resolutions
        ):
            raise ValueError("failed traversal cannot expose contexts, objects, or resolutions")
        if contexts != self.contexts:
            object.__setattr__(self, "contexts", contexts)
        if objects != self.objects:
            object.__setattr__(self, "objects", objects)
        if resolutions != self.resolutions:
            object.__setattr__(self, "resolutions", resolutions)
        if sources != self.sources:
            object.__setattr__(self, "sources", sources)
        if diagnostics != self.diagnostics:
            object.__setattr__(self, "diagnostics", diagnostics)
        return self


__all__ = [
    "KubernetesContainerContext",
    "KubernetesContainerKind",
    "KubernetesDiagnostic",
    "KubernetesDiagnosticCode",
    "KubernetesEnvBinding",
    "KubernetesEnvFromSource",
    "KubernetesEnvFromSourceKind",
    "KubernetesEnvSourceKind",
    "KubernetesInput",
    "KubernetesLoadStatus",
    "KubernetesObjectKeyField",
    "KubernetesObjectKeyPresence",
    "KubernetesObjectKind",
    "KubernetesObjectPresence",
    "KubernetesReferenceKind",
    "KubernetesReferenceResolution",
    "KubernetesSourceStatus",
    "KubernetesTraversalResult",
    "KubernetesWorkloadKind",
]
