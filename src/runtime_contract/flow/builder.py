"""Pure deterministic graph construction from a canonical facts-only Contract."""

from __future__ import annotations

from runtime_contract.domain import Contract, ProviderRole
from runtime_contract.flow.models import (
    FlowEdge,
    FlowEdgeKind,
    FlowGraph,
    FlowNode,
    FlowNodeKind,
)


def build_flow_graph(contract: Contract, /) -> FlowGraph:
    """Build source-to-sink edges using canonical fact IDs, never variable names or values."""

    nodes: dict[str, FlowNode] = {}
    fact_nodes: dict[str, FlowNode] = {}

    def add_node(kind: FlowNodeKind, fact_id: str) -> FlowNode:
        node = FlowNode(kind=kind, fact_id=fact_id)
        nodes[node.id] = node
        fact_nodes[fact_id] = node
        return node

    for config_key in contract.config_keys:
        add_node(FlowNodeKind.CONFIG_KEY, config_key.id)
    for consumer in contract.consumers:
        add_node(FlowNodeKind.CONSUMER, consumer.id)
    for environment in contract.environments:
        add_node(FlowNodeKind.ENVIRONMENT, environment.id)
    for provider in contract.providers:
        add_node(FlowNodeKind.PROVIDER, provider.id)

    edges: dict[str, FlowEdge] = {}

    def add_edge(edge: FlowEdge) -> None:
        edges[edge.id] = edge

    for consumer in contract.consumers:
        add_edge(
            FlowEdge(
                kind=FlowEdgeKind.CONSUMER_REQUIRES_KEY,
                source_node_id=fact_nodes[consumer.id].id,
                target_node_id=fact_nodes[consumer.config_key_id].id,
                component=consumer.component,
                config_key_id=consumer.config_key_id,
                phase=consumer.phase,
            )
        )

    declarations: dict[str, list[str]] = {}
    for provider in contract.providers:
        if provider.role is ProviderRole.DECLARATION and provider.config_key_id is not None:
            declarations.setdefault(provider.config_key_id, []).append(provider.id)
            add_edge(
                FlowEdge(
                    kind=FlowEdgeKind.KEY_DECLARED_BY,
                    source_node_id=fact_nodes[provider.config_key_id].id,
                    target_node_id=fact_nodes[provider.id].id,
                    component=provider.component,
                    config_key_id=provider.config_key_id,
                    phase=provider.phase,
                )
            )

    for provider in contract.providers:
        if provider.role is not ProviderRole.DELIVERY:
            continue
        assert provider.environment_id is not None
        add_edge(
            FlowEdge(
                kind=FlowEdgeKind.PROVIDER_TARGETS_ENVIRONMENT,
                source_node_id=fact_nodes[provider.id].id,
                target_node_id=fact_nodes[provider.environment_id].id,
                component=provider.component,
                config_key_id=provider.config_key_id,
                environment_id=provider.environment_id,
                phase=provider.phase,
            )
        )
        if provider.config_key_id is None:
            continue
        add_edge(
            FlowEdge(
                kind=FlowEdgeKind.KEY_DELIVERED_BY,
                source_node_id=fact_nodes[provider.config_key_id].id,
                target_node_id=fact_nodes[provider.id].id,
                component=provider.component,
                config_key_id=provider.config_key_id,
                environment_id=provider.environment_id,
                phase=provider.phase,
            )
        )
        for declaration_id in declarations.get(provider.config_key_id, ()):
            add_edge(
                FlowEdge(
                    kind=FlowEdgeKind.DELIVERY_DECLARED_BY,
                    source_node_id=fact_nodes[provider.id].id,
                    target_node_id=fact_nodes[declaration_id].id,
                    component=provider.component,
                    config_key_id=provider.config_key_id,
                    environment_id=provider.environment_id,
                    phase=provider.phase,
                )
            )
    return FlowGraph(nodes=tuple(nodes.values()), edges=tuple(edges.values()))


__all__ = ["build_flow_graph"]
