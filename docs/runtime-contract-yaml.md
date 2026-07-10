# `runtime-contract.yaml` version 1

`runtime-contract.yaml` is the single, local configuration file for a project. The CLI reads it
only from `<logical-root>/runtime-contract.yaml`; it does not search parent directories, merge
configuration files, load remote references, or perform version migration.

Editor integrations may associate [`schemas/runtime-contract.schema.json`](../schemas/runtime-contract.schema.json)
with the file. For example, VS Code users can add this workspace setting without changing CLI
behavior:

```json
{
  "yaml.schemas": {
    "./schemas/runtime-contract.schema.json": "runtime-contract.yaml"
  }
}
```

## Header and YAML subset

The only accepted header is the integer `version: 1`. The field is required. Strings, floating
point values, booleans, missing values, and future versions are rejected without coercion.

The input must be one YAML document made of plain mappings, sequences, and supported scalar values.
Duplicate keys, merge keys, custom or explicit tags, anchors, aliases, multiple documents, and
unknown fields are rejected. Parsing uses a safe loader and errors never expose raw exceptions or
absolute private paths.

## Fields

- `include` and `exclude` are ordered lists of path globs. Global filters run before root filters.
- `roots` maps names matching `[A-Za-z][A-Za-z0-9_-]{0,63}` to a relative path string or an object
  containing `path`, `include`, and `exclude`. Missing `roots` means `default: "."`. `default` is
  reserved for that path. Canonical targets must be distinct directories inside the project root.
- `environments` maps profile names to a non-empty `roots` list and optional `sources`. Sources have
  `root`, `type` (`auto`, `compose`, or `kubernetes`), a relative `path`, and an optional unique list
  of variable names in `provides`. Profiles do not inherit.
- `classifications.variables` maps exact, case-sensitive variable names to one rule or a non-empty
  ordered list. `classifications.patterns` is an ordered list of whole-name, case-sensitive globs.
  Later matching rules override earlier rules field by field; exact variables always win. Rules may
  set `secret`, `required`, `roots`, and `environments`. Exact rules may additionally set
  `allow_literal` and `reason`; `allow_literal: true` requires a non-blank reason and never suppresses
  private-key findings.
- `severity_overrides` is an ordered list containing a registered `rule`, `severity` (`error`,
  `warning`, or `info`), and optional root/environment selectors. Later matching entries win.
- `suppressions` require a unique `id`, registered `rule`, non-blank `reason`, and at least one of
  `variable`, path glob, `roots`, or `environments`. `expires` is an ISO calendar date. An expired
  entry produces a warning and does not hide a finding.
- `execution` may contain `environment`, `format` (`text`, `json`, or `sarif`), `fail_on` (`error`,
  `warning`, `info`, or `never`), and a relative report path. Defaults are text, error, no selected
  environment, and no report file.

## Execution precedence

The precedence is defaults, YAML, the four variables below, and explicit CLI arguments. Only
execution settings can be overridden. There is no automatic environment-to-model mapping.

- `RUNTIME_CONTRACT_ENVIRONMENT`
- `RUNTIME_CONTRACT_FORMAT`
- `RUNTIME_CONTRACT_FAIL_ON`
- `RUNTIME_CONTRACT_REPORT`

The CLI reports the effective value and its source where diagnostics expose execution settings.
Values are configuration metadata, never secret values.

## Validation

```text
runtime-contract config validate [PATH]
runtime-contract config validate [PATH] --format json
python scripts/generate_config_schema.py --check
```

Successful validation exits 0. Configuration, resource, unsupported SARIF validation, and unknown
environment errors exit 2. Diagnostics contain a stable code, JSON Pointer, and one-based YAML line
and column. Collectable errors are sorted by UTF-8 JSON Pointer and code; an unrecoverable YAML
syntax error is reported alone.

See [`examples/minimal/runtime-contract.yaml`](../examples/minimal/runtime-contract.yaml) and
[`examples/full/runtime-contract.yaml`](../examples/full/runtime-contract.yaml).
