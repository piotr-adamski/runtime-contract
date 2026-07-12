# Source-to-sink graph

`runtime_contract.flow` exposes a pure graph derived from a canonical facts-only `Contract`:

```python
from runtime_contract.flow import build_flow_graph

graph = build_flow_graph(contract)
consumers = graph.consumer_ids(config_key_id)
deliveries = graph.delivery_provider_ids(config_key_id, environment_id=environment_id)
declarations = graph.declaration_provider_ids(config_key_id)
traces = graph.traces_for_consumer(consumer_id)
```

Nodes reference existing configuration-key, consumer, provider, and environment fact IDs. Edges
represent consumer requirements, declarations, deliveries, delivery-to-declaration provenance, and
provider targets. Edge identity includes its component, key, environment, and phase context where
applicable. The builder therefore never joins two facts only because their variable names match.

The graph contains no variable names, values, source snippets, absolute paths, or host data. A
keyed provider can connect a key to a target environment. An unresolved bulk provider can connect
only to its environment, because claiming any individual key would exceed the available evidence.
Declaration and delivery gaps remain explicit as open traces with `null` provider fields.

`ScanResult.flow_graph` is optional in the v1 JSON Schema for compatibility with early v1 reports.
The strict reader rebuilds an omitted graph from `contract`; writers always emit it. A supplied
graph must exactly equal the deterministic graph derived from the same contract, and summary node
and edge counts must match. The builder performs no filesystem, environment, process, cluster,
clock, randomness, or network access.
