# Rule and analyzer diagnostic catalog

`runtime-contract` keeps product findings and technical analyzer diagnostics as two separate,
value-safe contracts. Findings use the stable `RTC001`–`RTC012` identifiers. Technical diagnostics
describe whether static evidence could be collected reliably and never replace an RTC finding.

## Finding rules

| ID | Name | Default severity | Rationale | Manual remediation |
|---|---|---|---|---|
| RTC001 | REQUIRED_NOT_PROVIDED | error | A required variable is not delivered to a selected target in the required phase. | Provide it to every selected target in that phase, or explicitly make it optional. |
| RTC002 | SECRET_LITERAL | error | A non-placeholder literal for a sensitive variable can expose a secret. | Replace it with an approved placeholder, pass-through reference, or secret-backed delivery. |
| RTC003 | PRIVATE_KEY_CONTENT | error | Private-key material is sensitive regardless of its variable name. | Remove it from the repository and rotate the affected key outside this tool. |
| RTC004 | UNDOCUMENTED_VARIABLE | warning | A code consumer is absent from the component's documenting source. | Add a value-free declaration to the documenting source. |
| RTC005 | UNUSED_DECLARATION | warning | A declaration has no statically detected consumer. | Remove it or document the unsupported consumption pattern. |
| RTC006 | DYNAMIC_REFERENCE | warning | A computed name cannot be resolved safely by static analysis. | Use a static access or document the intentional limitation. |
| RTC007 | CONFLICTING_DEFAULT | warning | Static sources describe incompatible fallback behavior. | Choose one intended default and align sources. |
| RTC008 | OPTIONAL_NOT_PROVIDED | info | An optional variable has no matching delivery. | Do nothing when omission is intentional; otherwise add delivery. |
| RTC009 | DELIVERY_UNVERIFIABLE | error | A bulk provider cannot prove one required key. | Add a statically verifiable key or an explicit valueless `provides` entry. |
| RTC010 | PHASE_MISMATCH | error | Delivery exists only outside the consumer's required phase. | Move or duplicate delivery into the required phase. |
| RTC011 | CUSTOM_SETTINGS_SOURCE | warning | Dynamic Pydantic Settings sources require code execution to resolve. | Expose a static alias/prefix or document the limitation. |
| RTC012 | UNSUPPORTED_K8S_RESOURCE | info | The resource is outside the supported v0.1 Kubernetes set. | Use a supported plain manifest or native tooling for that resource. |

The executable source of truth is `runtime_contract.rules.RULE_CATALOG`. It contains English,
render-ready rationale and manual remediation without source values, secrets, timestamps, absolute
paths, or environment-specific state.

## Compatibility policy

- A published RTC identifier is never reused for a different condition.
- Name, default severity, rationale meaning, and remediation meaning are stable within v0.1.x.
- Wording may receive non-semantic corrections; a semantic change requires a documented breaking
  release decision.
- New rules require a new unique ID, a catalog entry, a golden fixture, tests, and format metadata.
- Configuration may change effective severity or disable a rule only under its validated reason
  contract; it does not mutate the catalog default.

## Technical analyzer diagnostics

`runtime_contract.analysis.DIAGNOSTIC_CATALOG` covers parser, safety, read, normalization, and
unsupported-input conditions. These codes have their own fixed severity map and remediation text.
They report reliability of analysis rather than product contract drift. `RTC011` and `RTC012` may
be represented by analyzer diagnostics during parsing and later rendered as stable RTC findings by
the rule engine; the two model types remain distinct.
