# RTC001–RTC012 rule reference

This is the canonical human reference for every v0.1 finding rule. Runtime metadata in
`runtime_contract.rules` owns IDs, names, default severity, rationale, and remediation; tests keep
this document synchronized with that catalog. Configuration may override effective severity or
suppress a scoped finding but never changes the catalog default.

## RTC001 — Required variable not provided (`error`)

**Why:** a required consumer has no statically proven provider in the selected target and phase.
**Incorrect:** `os.environ["DATABASE_URL"]` exists, but the target has no runtime delivery.
**Correct:** the same target declares `DATABASE_URL` through an explicit value-blind provider.
**Remediation:** provide it to every selected target in the required phase, or explicitly make the
requirement optional.

## RTC002 — Secret has a literal value (`error`)

**Why:** a non-placeholder literal for a sensitive key can expose a secret.
**Incorrect:** `API_TOKEN: production-token-text` in a checked-in manifest.
**Correct:** an empty/example placeholder, pass-through declaration, or Secret reference.
**Remediation:** remove the literal, rotate any exposed credential outside this tool, and use a
secret-backed delivery mechanism.

## RTC003 — Private-key content detected (`error`)

**Why:** private-key material is sensitive regardless of filename or variable name.
**Incorrect:** a PEM private-key block in a supported source.
**Correct:** only a structural reference to a key managed outside the repository.
**Remediation:** remove the material and rotate the affected key; configuration cannot allow it.

## RTC004 — Variable is not documented (`warning`)

**Why:** code consumes a key absent from its component's documenting source.
**Incorrect:** code reads `FEATURE_FLAG` while `.env.example` omits it.
**Correct:** `.env.example` declares `FEATURE_FLAG=` without a real value.
**Remediation:** add a value-free declaration or document why the consumption pattern is unsupported.

## RTC005 — Declaration has no consumer (`warning`)

**Why:** a documented/provider key has no statically detected consumer in the component.
**Incorrect:** `.env.example` retains obsolete `LEGACY_URL=`.
**Correct:** remove it, or add the real supported static consumer if the declaration is current.
**Remediation:** delete stale delivery or confirm and document an unsupported consumption pattern.

## RTC006 — Variable reference is dynamic (`warning`)

**Why:** a computed name cannot be resolved without guessing or executing code.
**Incorrect:** `os.getenv(prefix + "_URL")` or `process.env[name]`.
**Correct:** `os.getenv("SERVICE_URL")` or `process.env.SERVICE_URL`.
**Remediation:** use a static name or accept and document the analysis limitation.

## RTC007 — Static defaults conflict (`warning`)

**Why:** static sources describe incompatible fallback/default behavior for one key.
**Incorrect:** code defaults `LOG_LEVEL` to `info` while another consumer defaults it to `debug`.
**Correct:** all declarations agree on one contract, or omit the fallback consistently.
**Remediation:** choose the intended default and align every static source.

## RTC008 — Optional variable not provided (`info`)

**Why:** an optional consumer has no delivery in the selected target/phase.
**Incorrect:** treat this informational omission as proof of a deployment failure.
**Correct:** intentionally omit it when the code has valid optional behavior.
**Remediation:** no action if intentional; otherwise add matching delivery.

## RTC009 — Bulk delivery cannot be verified (`error`)

**Why:** `env_file` or unresolved `envFrom` may deliver a key but cannot prove that it does.
**Incorrect:** rely on an unread `env_file` as proof for required `DATABASE_URL`.
**Correct:** declare the key explicitly or use configured value-free `provides` metadata.
**Remediation:** add statically verifiable delivery for the selected target.

## RTC010 — Delivery phase does not match (`error`)

**Why:** a required key exists only in a different phase from its consumer.
**Incorrect:** Docker `ARG API_URL` is the only delivery for a runtime consumer.
**Correct:** deliver `API_URL` at runtime, or move the consumer requirement to build time.
**Remediation:** move or duplicate delivery into the required phase.

## RTC011 — Custom Settings source is dynamic (`warning`)

**Why:** executable Pydantic Settings source customization cannot be resolved statically.
**Incorrect:** assume a custom source hook proves a field's runtime delivery.
**Correct:** expose a static field alias/prefix and model delivery in supported configuration.
**Remediation:** make the contract static or document the intentional limitation.

## RTC012 — Kubernetes resource is unsupported (`info`)

**Why:** the resource kind is outside the plain v0.1 workload/key-source set.
**Incorrect:** expect an operator CRD or rendered Helm chart to be interpreted as a Pod template.
**Correct:** supply a supported plain Pod, Deployment, StatefulSet, DaemonSet, Job, or CronJob.
**Remediation:** analyze rendered plain manifests or assess the resource with its native tooling.

Use `runtime-contract explain RTC001` (or another ID) for the same catalog metadata from the
installed CLI. Finding IDs can be explained from a canonical JSON report or project directory.
