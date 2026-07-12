"""Strict, immutable, value-blind source-to-sink graph models."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from runtime_contract.domain import Phase


class _FlowModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class FlowNodeKind(StrEnum):
    CONFIG_KEY = "config_key"
    CONSUMER = "consumer"
    ENVIRONMENT = "environment"
    PROVIDER = "provider"


class FlowEdgeKind(StrEnum):
    CONSUMER_REQUIRES_KEY = "consumer_requires_key"
    KEY_DECLARED_BY = "key_declared_by"
    KEY_DELIVERED_BY = "key_delivered_by"
    DELIVERY_DECLARED_BY = "delivery_declared_by"
    PROVIDER_TARGETS_ENVIRONMENT = "provider_targets_environment"


class FlowNode(_FlowModel):
    id: str = ""
    kind: FlowNodeKind
    fact_id: str

    @model_validator(mode="after")
    def validate_identity(self) -> FlowNode:
        if not self.fact_id:
            raise ValueError("fact_id must be non-empty")
        expected = self.calculate_id(self.kind, self.fact_id)
        if self.id and self.id != expected:
            raise ValueError("id does not match FlowNode identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(kind: FlowNodeKind, fact_id: str) -> str:
        return _flow_id("flow-node-", (("kind", kind.value), ("fact_id", fact_id)))


class FlowEdge(_FlowModel):
    id: str = ""
    kind: FlowEdgeKind
    source_node_id: str
    target_node_id: str
    component: str
    config_key_id: str | None = None
    environment_id: str | None = None
    phase: Phase | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> FlowEdge:
        if (
            not self.source_node_id
            or not self.target_node_id
            or self.source_node_id == self.target_node_id
            or not self.component
        ):
            raise ValueError("edge endpoints and component must be valid")
        if self.kind is FlowEdgeKind.CONSUMER_REQUIRES_KEY:
            if self.config_key_id is None or self.environment_id is not None or self.phase is None:
                raise ValueError("consumer edge requires key and phase without environment")
        elif self.kind is FlowEdgeKind.KEY_DECLARED_BY:
            if (
                self.config_key_id is None
                or self.environment_id is not None
                or self.phase is not Phase.NOT_APPLICABLE
            ):
                raise ValueError("key declaration edge requires key and not_applicable phase")
        elif self.kind is FlowEdgeKind.KEY_DELIVERED_BY:
            if self.config_key_id is None or self.environment_id is None or self.phase is None:
                raise ValueError("delivery edge requires key, environment, and phase")
        elif self.kind is FlowEdgeKind.DELIVERY_DECLARED_BY:
            if self.config_key_id is None or self.environment_id is None or self.phase is None:
                raise ValueError("declaration edge requires delivery context")
        elif self.environment_id is None or self.phase is None:
            raise ValueError("environment edge requires environment and phase")
        expected = self.calculate_id(
            self.kind,
            self.source_node_id,
            self.target_node_id,
            self.component,
            self.config_key_id,
            self.environment_id,
            self.phase,
        )
        if self.id and self.id != expected:
            raise ValueError("id does not match FlowEdge identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        kind: FlowEdgeKind,
        source_node_id: str,
        target_node_id: str,
        component: str,
        config_key_id: str | None,
        environment_id: str | None,
        phase: Phase | None,
    ) -> str:
        return _flow_id(
            "flow-edge-",
            (
                ("kind", kind.value),
                ("source_node_id", source_node_id),
                ("target_node_id", target_node_id),
                ("component", component),
                ("config_key_id", config_key_id or ""),
                ("environment_id", environment_id or ""),
                ("phase", phase.value if phase is not None else ""),
            ),
        )


class FlowTrace(_FlowModel):
    consumer_id: str
    config_key_id: str
    provider_id: str | None = None
    declaration_provider_id: str | None = None
    environment_id: str | None = None
    consumer_phase: Phase
    provider_phase: Phase | None = None


class FlowGraph(_FlowModel):
    nodes: tuple[FlowNode, ...] = ()
    edges: tuple[FlowEdge, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> FlowGraph:
        nodes = tuple(sorted(self.nodes, key=lambda item: item.id))
        edges = tuple(sorted(self.edges, key=lambda item: item.id))
        if len({item.id for item in nodes}) != len(nodes):
            raise ValueError("flow node IDs must be unique")
        if len({item.id for item in edges}) != len(edges):
            raise ValueError("flow edge IDs must be unique")
        by_id = {item.id: item for item in nodes}
        expected_shapes = {
            FlowEdgeKind.CONSUMER_REQUIRES_KEY: (
                FlowNodeKind.CONSUMER,
                FlowNodeKind.CONFIG_KEY,
            ),
            FlowEdgeKind.KEY_DELIVERED_BY: (
                FlowNodeKind.CONFIG_KEY,
                FlowNodeKind.PROVIDER,
            ),
            FlowEdgeKind.KEY_DECLARED_BY: (
                FlowNodeKind.CONFIG_KEY,
                FlowNodeKind.PROVIDER,
            ),
            FlowEdgeKind.DELIVERY_DECLARED_BY: (
                FlowNodeKind.PROVIDER,
                FlowNodeKind.PROVIDER,
            ),
            FlowEdgeKind.PROVIDER_TARGETS_ENVIRONMENT: (
                FlowNodeKind.PROVIDER,
                FlowNodeKind.ENVIRONMENT,
            ),
        }
        for edge in edges:
            source = by_id.get(edge.source_node_id)
            target = by_id.get(edge.target_node_id)
            if source is None or target is None:
                raise ValueError("flow edge references a missing node")
            if (source.kind, target.kind) != expected_shapes[edge.kind]:
                raise ValueError("flow edge node kinds do not match edge kind")
        if nodes != self.nodes:
            object.__setattr__(self, "nodes", nodes)
        if edges != self.edges:
            object.__setattr__(self, "edges", edges)
        return self

    def consumer_ids(self, config_key_id: str) -> tuple[str, ...]:
        node_by_id = {item.id: item for item in self.nodes}
        return tuple(
            sorted(
                node_by_id[item.source_node_id].fact_id
                for item in self.edges
                if item.kind is FlowEdgeKind.CONSUMER_REQUIRES_KEY
                and item.config_key_id == config_key_id
            )
        )

    def delivery_provider_ids(
        self, config_key_id: str, *, environment_id: str | None = None
    ) -> tuple[str, ...]:
        node_by_id = {item.id: item for item in self.nodes}
        return tuple(
            sorted(
                node_by_id[item.target_node_id].fact_id
                for item in self.edges
                if item.kind is FlowEdgeKind.KEY_DELIVERED_BY
                and item.config_key_id == config_key_id
                and (environment_id is None or item.environment_id == environment_id)
            )
        )

    def declaration_provider_ids(self, config_key_id: str) -> tuple[str, ...]:
        node_by_id = {item.id: item for item in self.nodes}
        return tuple(
            sorted(
                {
                    node_by_id[item.target_node_id].fact_id
                    for item in self.edges
                    if item.kind is FlowEdgeKind.KEY_DECLARED_BY
                    and item.config_key_id == config_key_id
                }
            )
        )

    def traces_for_consumer(self, consumer_id: str) -> tuple[FlowTrace, ...]:
        node_by_id = {item.id: item for item in self.nodes}
        consumer_node = next(
            (
                item
                for item in self.nodes
                if item.kind is FlowNodeKind.CONSUMER and item.fact_id == consumer_id
            ),
            None,
        )
        if consumer_node is None:
            return ()
        consume_edges = [
            item
            for item in self.edges
            if item.kind is FlowEdgeKind.CONSUMER_REQUIRES_KEY
            and item.source_node_id == consumer_node.id
        ]
        traces: list[FlowTrace] = []
        for consume in consume_edges:
            assert consume.config_key_id is not None
            assert consume.phase is not None
            deliveries = [
                item
                for item in self.edges
                if item.kind is FlowEdgeKind.KEY_DELIVERED_BY
                and item.source_node_id == consume.target_node_id
            ]
            if not deliveries:
                traces.append(
                    FlowTrace(
                        consumer_id=consumer_id,
                        config_key_id=consume.config_key_id,
                        consumer_phase=consume.phase,
                    )
                )
                continue
            for delivery in deliveries:
                declarations = [
                    item
                    for item in self.edges
                    if item.kind is FlowEdgeKind.DELIVERY_DECLARED_BY
                    and item.source_node_id == delivery.target_node_id
                ]
                provider_id = node_by_id[delivery.target_node_id].fact_id
                if not declarations:
                    traces.append(
                        FlowTrace(
                            consumer_id=consumer_id,
                            config_key_id=consume.config_key_id,
                            provider_id=provider_id,
                            environment_id=delivery.environment_id,
                            consumer_phase=consume.phase,
                            provider_phase=delivery.phase,
                        )
                    )
                    continue
                for declaration in declarations:
                    traces.append(
                        FlowTrace(
                            consumer_id=consumer_id,
                            config_key_id=consume.config_key_id,
                            provider_id=provider_id,
                            declaration_provider_id=node_by_id[declaration.target_node_id].fact_id,
                            environment_id=delivery.environment_id,
                            consumer_phase=consume.phase,
                            provider_phase=delivery.phase,
                        )
                    )
        return tuple(
            sorted(
                traces,
                key=lambda item: (
                    item.config_key_id,
                    item.environment_id or "",
                    item.provider_id or "",
                    item.declaration_provider_id or "",
                ),
            )
        )


def _flow_id(prefix: str, fields: tuple[tuple[str, str], ...]) -> str:
    payload = {key: value for key, value in fields}
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return prefix + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "FlowEdge",
    "FlowEdgeKind",
    "FlowGraph",
    "FlowNode",
    "FlowNodeKind",
    "FlowTrace",
]
