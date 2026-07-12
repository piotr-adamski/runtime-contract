# Domain model

The stable v1 domain API is available directly from `runtime_contract.domain`:

```python
from runtime_contract.domain import ConfigKey, Consumer, Contract, Environment, Finding, Provider, SourceLocation
```

Public enums and type aliases are exported from the same module. Deep imports are not required.

`Contract` is a facts-only aggregate. Parsers will eventually produce configuration keys,
environments, consumers, and providers. `Finding` is deliberately separate: a later rule engine
will derive findings from facts, and later renderers will turn rule identifiers and structural
parameters into English messages.

The contract schema identifier is `runtime-contract/contract/v1`. Its JSON Schema uses
`urn:runtime-contract:contract:v1`. The shorter identifier `runtime-contract/v1` remains reserved
for a future report that will contain separate contract and findings sections.

All models are frozen, reject unknown fields, and use strict validation. Nested collections are
immutable tuples and serialize as JSON arrays. Optional fields remain present as JSON `null`.
Canonical serialization uses `model_dump(mode="json", exclude_none=False)` or the equivalent
`model_dump_json` call.

Entity identifiers are full SHA-256 hashes of fixed-order, compact JSON identity objects. They do
not depend on parser discovery order, locale, timestamps, tool versions, or absolute roots. The v1
compatibility rule is that field semantics, enum values, identity inputs, and the committed schema
remain stable for every `runtime-contract/contract/v1` document.

The model stores names, safe identifiers, relative locations, and structural facts only. It never
stores environment-variable values, secret values, literal fallback values, source snippets, or
source line contents.

`Contract` remains the facts-only source of truth. The separate `runtime_contract.flow` API derives
an immutable query graph from those facts without changing their identities or semantics. A
`ScanResult` validates that its graph is exactly the graph implied by its embedded contract.
