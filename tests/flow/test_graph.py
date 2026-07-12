"""Deterministic source-to-sink graph contract for D2.09."""

from __future__ import annotations

from itertools import permutations

import pytest
from pydantic import ValidationError

from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Contract,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    RequirementSource,
    SecretSource,
    SourceLocation,
)
from runtime_contract.flow import (
    FlowEdge,
    FlowEdgeKind,
    FlowGraph,
    FlowNode,
    FlowNodeKind,
    build_flow_graph,
)


def key(name: str = "API_URL", component: str = "api") -> ConfigKey:
    return ConfigKey(
        name=name,
        component=component,
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=True,
    )


def environment(component: str = "api", target: str = "compose/api") -> Environment:
    return Environment(
        component=component,
        target=target,
        kind=EnvironmentKind.COMPOSE_SERVICE,
        profile=Profile.STAGING,
    )


def consumer(item: ConfigKey, line: int = 1) -> Consumer:
    return Consumer(
        config_key_id=item.id,
        component=item.component,
        phase=Phase.RUNTIME,
        required=True,
        requirement_source=RequirementSource.DETECTED_DEFAULT,
        access_kind=ConsumerAccessKind.PYTHON_OS_GETENV,
        location=SourceLocation(path="src/app.py", start_line=line),
        has_literal_fallback=False,
    )


def declaration(item: ConfigKey, line: int = 1) -> Provider:
    return Provider(
        config_key_id=item.id,
        component=item.component,
        role=ProviderRole.DECLARATION,
        phase=Phase.NOT_APPLICABLE,
        mechanism=ProviderMechanism.ENV_EXAMPLE,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path=".env.example", start_line=line),
    )


def delivery(item: ConfigKey, target: Environment, line: int = 1) -> Provider:
    return Provider(
        config_key_id=item.id,
        component=item.component,
        environment_id=target.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path="compose.yaml", start_line=line),
    )


def full_contract() -> tuple[Contract, ConfigKey, Consumer, Environment, Provider, Provider]:
    item = key()
    use = consumer(item)
    target = environment()
    source = declaration(item)
    provide = delivery(item, target)
    return (
        Contract(
            config_keys=(item,),
            environments=(target,),
            consumers=(use,),
            providers=(source, provide),
        ),
        item,
        use,
        target,
        source,
        provide,
    )


def test_full_chain_answers_where_used_and_where_from() -> None:
    contract, item, use, target, source, provide = full_contract()

    graph = build_flow_graph(contract)

    assert len(graph.nodes) == 5
    assert {edge.kind for edge in graph.edges} == set(FlowEdgeKind)
    assert graph.consumer_ids(item.id) == (use.id,)
    assert graph.delivery_provider_ids(item.id) == (provide.id,)
    assert graph.delivery_provider_ids(item.id, environment_id=target.id) == (provide.id,)
    assert graph.delivery_provider_ids(item.id, environment_id="missing") == ()
    assert graph.declaration_provider_ids(item.id) == (source.id,)
    assert graph.traces_for_consumer("missing") == ()
    assert graph.traces_for_consumer(use.id)[0].model_dump() == {
        "consumer_id": use.id,
        "config_key_id": item.id,
        "provider_id": provide.id,
        "declaration_provider_id": source.id,
        "environment_id": target.id,
        "consumer_phase": Phase.RUNTIME,
        "provider_phase": Phase.RUNTIME,
    }


def test_missing_delivery_and_missing_declaration_produce_explicit_open_paths() -> None:
    item = key()
    use = consumer(item)
    no_delivery = build_flow_graph(Contract(config_keys=(item,), consumers=(use,)))
    assert no_delivery.traces_for_consumer(use.id)[0].provider_id is None

    target = environment()
    provide = delivery(item, target)
    no_declaration = build_flow_graph(
        Contract(
            config_keys=(item,),
            environments=(target,),
            consumers=(use,),
            providers=(provide,),
        )
    )
    trace = no_declaration.traces_for_consumer(use.id)[0]
    assert trace.provider_id == provide.id
    assert trace.declaration_provider_id is None


def test_unresolved_bulk_keeps_environment_boundary_without_claiming_a_key() -> None:
    target = environment()
    bulk = Provider(
        component="api",
        environment_id=target.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=ProviderMechanism.COMPOSE_ENV_FILE,
        evidence_kind=EvidenceKind.UNRESOLVED_BULK,
        location=SourceLocation(path="compose.yaml", start_line=1),
    )
    graph = build_flow_graph(Contract(environments=(target,), providers=(bulk,)))

    assert len(graph.nodes) == 2
    assert [(item.kind, item.config_key_id) for item in graph.edges] == [
        (FlowEdgeKind.PROVIDER_TARGETS_ENVIRONMENT, None)
    ]


def test_component_identity_prevents_same_name_cross_links() -> None:
    api = key("SHARED", "api")
    web = key("SHARED", "web")
    api_use = consumer(api)
    web_target = environment("web", "compose/web")
    web_delivery = delivery(web, web_target)
    graph = build_flow_graph(
        Contract(
            config_keys=(api, web),
            environments=(web_target,),
            consumers=(api_use,),
            providers=(web_delivery,),
        )
    )

    assert graph.consumer_ids(api.id) == (api_use.id,)
    assert graph.delivery_provider_ids(api.id) == ()
    assert graph.delivery_provider_ids(web.id) == (web_delivery.id,)
    assert graph.traces_for_consumer(api_use.id)[0].provider_id is None


@pytest.mark.parametrize(
    ("access_kind", "mechanism", "phase", "environment_kind"),
    [
        (
            ConsumerAccessKind.PYTHON_OS_GETENV,
            ProviderMechanism.DOCKERFILE_ENV,
            Phase.RUNTIME,
            EnvironmentKind.IMPLICIT,
        ),
        (
            ConsumerAccessKind.NODE_PROCESS_ENV,
            ProviderMechanism.COMPOSE_ENVIRONMENT,
            Phase.RUNTIME,
            EnvironmentKind.COMPOSE_SERVICE,
        ),
        (
            ConsumerAccessKind.PYTHON_OS_ENVIRON,
            ProviderMechanism.KUBERNETES_ENV,
            Phase.RUNTIME,
            EnvironmentKind.KUBERNETES_WORKLOAD,
        ),
        (
            ConsumerAccessKind.NODE_PROCESS_ENV,
            ProviderMechanism.DOCKERFILE_ARG,
            Phase.BUILD,
            EnvironmentKind.IMPLICIT,
        ),
    ],
)
def test_supported_platform_facts_form_the_same_id_safe_chain(
    access_kind: ConsumerAccessKind,
    mechanism: ProviderMechanism,
    phase: Phase,
    environment_kind: EnvironmentKind,
) -> None:
    item = key()
    use = consumer(item).model_copy(update={"access_kind": access_kind, "phase": phase, "id": ""})
    use = Consumer.model_validate(use.model_dump())
    target = Environment(
        component=item.component,
        target=f"target/{mechanism.value}",
        kind=environment_kind,
        profile=Profile.STAGING,
    )
    provide = Provider(
        config_key_id=item.id,
        component=item.component,
        environment_id=target.id,
        role=ProviderRole.DELIVERY,
        phase=phase,
        mechanism=mechanism,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path="platform.input", start_line=1),
    )
    graph = build_flow_graph(
        Contract(
            config_keys=(item,),
            environments=(target,),
            consumers=(use,),
            providers=(provide,),
        )
    )

    trace = graph.traces_for_consumer(use.id)[0]
    assert trace.provider_id == provide.id
    assert trace.environment_id == target.id
    assert trace.consumer_phase is phase
    assert trace.provider_phase is phase


def test_graph_is_deterministic_for_every_fact_order() -> None:
    contract, *_ = full_contract()
    expected = build_flow_graph(contract).model_dump_json()
    for providers in permutations(contract.providers):
        changed = contract.model_copy(update={"providers": providers})
        canonical = Contract.model_validate(changed.model_dump())
        assert build_flow_graph(canonical).model_dump_json() == expected


def test_models_reject_bad_ids_edges_and_missing_or_wrong_kind_nodes() -> None:
    node = FlowNode(kind=FlowNodeKind.CONFIG_KEY, fact_id="key-id")
    with pytest.raises(ValidationError, match="fact_id"):
        FlowNode(kind=FlowNodeKind.CONFIG_KEY, fact_id="")
    with pytest.raises(ValidationError, match="FlowNode identity"):
        FlowNode(id="wrong", kind=FlowNodeKind.CONFIG_KEY, fact_id="key-id")
    with pytest.raises(ValidationError, match="endpoints"):
        FlowEdge(
            kind=FlowEdgeKind.CONSUMER_REQUIRES_KEY,
            source_node_id=node.id,
            target_node_id=node.id,
            component="api",
            config_key_id="key-id",
            phase=Phase.RUNTIME,
        )
    with pytest.raises(ValidationError, match="consumer edge"):
        FlowEdge(
            kind=FlowEdgeKind.CONSUMER_REQUIRES_KEY,
            source_node_id="a",
            target_node_id="b",
            component="api",
        )
    edge = FlowEdge(
        kind=FlowEdgeKind.CONSUMER_REQUIRES_KEY,
        source_node_id="consumer-node",
        target_node_id=node.id,
        component="api",
        config_key_id="key-id",
        phase=Phase.RUNTIME,
    )
    with pytest.raises(ValidationError, match="missing node"):
        FlowGraph(nodes=(node,), edges=(edge,))
    consumer_node = FlowNode(kind=FlowNodeKind.CONSUMER, fact_id="consumer-id")
    wrong_edge = edge.model_copy(
        update={"id": "", "source_node_id": node.id, "target_node_id": consumer_node.id}
    )
    wrong_edge = FlowEdge.model_validate(wrong_edge.model_dump())
    with pytest.raises(ValidationError, match="node kinds"):
        FlowGraph(nodes=(node, consumer_node), edges=(wrong_edge,))


@pytest.mark.parametrize(
    ("kind", "config_key_id", "environment_id", "phase", "message"),
    [
        (
            FlowEdgeKind.KEY_DECLARED_BY,
            "key-id",
            "unexpected",
            Phase.NOT_APPLICABLE,
            "key declaration edge",
        ),
        (FlowEdgeKind.KEY_DELIVERED_BY, "key-id", None, Phase.RUNTIME, "delivery edge"),
        (
            FlowEdgeKind.DELIVERY_DECLARED_BY,
            "key-id",
            None,
            Phase.RUNTIME,
            "declaration edge",
        ),
        (
            FlowEdgeKind.PROVIDER_TARGETS_ENVIRONMENT,
            None,
            None,
            Phase.RUNTIME,
            "environment edge",
        ),
    ],
)
def test_each_edge_kind_rejects_missing_context(
    kind: FlowEdgeKind,
    config_key_id: str | None,
    environment_id: str | None,
    phase: Phase,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        FlowEdge(
            kind=kind,
            source_node_id="source",
            target_node_id="target",
            component="api",
            config_key_id=config_key_id,
            environment_id=environment_id,
            phase=phase,
        )


def test_edge_identity_and_duplicate_graph_ids_are_rejected() -> None:
    consumer_node = FlowNode(kind=FlowNodeKind.CONSUMER, fact_id="consumer-id")
    key_node = FlowNode(kind=FlowNodeKind.CONFIG_KEY, fact_id="key-id")
    edge = FlowEdge(
        kind=FlowEdgeKind.CONSUMER_REQUIRES_KEY,
        source_node_id=consumer_node.id,
        target_node_id=key_node.id,
        component="api",
        config_key_id="key-id",
        phase=Phase.RUNTIME,
    )
    with pytest.raises(ValidationError, match="FlowEdge identity"):
        FlowEdge.model_validate(edge.model_dump() | {"id": "wrong"})
    with pytest.raises(ValidationError, match="flow node IDs"):
        FlowGraph(nodes=(consumer_node, consumer_node))
    with pytest.raises(ValidationError, match="flow edge IDs"):
        FlowGraph(nodes=(consumer_node, key_node), edges=(edge, edge))


def test_empty_graph_and_public_shape_contain_no_values_or_names() -> None:
    assert build_flow_graph(Contract()) == FlowGraph()
    graph = build_flow_graph(full_contract()[0])
    serialized = graph.model_dump_json()
    assert "API_URL" not in serialized
    assert "value" not in serialized.casefold()
