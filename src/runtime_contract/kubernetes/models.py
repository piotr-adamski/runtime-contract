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
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


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


_SEVERITIES = {code: Severity.ERROR for code in KubernetesDiagnosticCode}
_SEVERITIES[KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE] = Severity.INFO


class KubernetesInput(_KubernetesModel):
    path: str
    content: bytes = Field(repr=False)

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

    @model_validator(mode="after")
    def locations_match_path(self) -> KubernetesContainerContext:
        if self.workload_location.path != self.path or self.container_location.path != self.path:
            raise ValueError("locations must use the context path")
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
        if self.status is KubernetesLoadStatus.FAILED and self.contexts:
            raise ValueError("failed traversal cannot expose contexts")
        if contexts != self.contexts:
            object.__setattr__(self, "contexts", contexts)
        if diagnostics != self.diagnostics:
            object.__setattr__(self, "diagnostics", diagnostics)
        return self


__all__ = [
    "KubernetesContainerContext",
    "KubernetesContainerKind",
    "KubernetesDiagnostic",
    "KubernetesDiagnosticCode",
    "KubernetesInput",
    "KubernetesLoadStatus",
    "KubernetesTraversalResult",
    "KubernetesWorkloadKind",
]
