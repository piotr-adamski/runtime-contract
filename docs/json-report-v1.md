# JSON scan report v1

`runtime-contract scan PATH --format json` emits the public automation API identified by
`schema_id: "runtime-contract/v1"` and integer `schema_version: 1`. Use `--output report.json` for
an atomic file write instead of stdout.

The canonical top-level object contains exactly these required fields:

```json
{
  "schema_id": "runtime-contract/v1",
  "schema_version": 1,
  "metadata": {"tool": "runtime-contract", "tool_version": "0.1.0.dev0", "command": "scan"},
  "inputs": {"root": ".", "config": null, "environment": null, "selected_roots": [], "include": [], "exclude": [], "fail_on": "error"},
  "status": "complete",
  "summary": {},
  "contract": {},
  "diagnostics": [],
  "findings": [],
  "files": []
}
```

The full field contract is the JSON Schema Draft 2020-12 at
[`schemas/runtime-contract-scan-result-v1.schema.json`](../schemas/runtime-contract-scan-result-v1.schema.json).
The canonical golden document is
[`examples/reports/runtime-contract-v1.json`](../examples/reports/runtime-contract-v1.json).
Consumers and providers remain exclusively inside the facts-only `contract`. Findings have their
public typed shape but remain empty until the rules engine is implemented.

Optional scalar values without a value are JSON `null`; empty sequences are `[]`, empty maps are
`{}`, and required fields are never omitted. Paths are NFC, relative POSIX paths contained by the
scan root; the public root is always `.`. Reports contain no timestamp, duration, UUID, hostname,
user, process ID, current working directory, absolute host path, source snippets, or file contents.

The project canonical serialization is UTF-8 without BOM, recursively sorted object keys, compact
separators, no NaN or infinities, and exactly one final LF. Array ordering is deterministic. This is
the runtime-contract canonical format, not a claim of RFC 8785/JCS compliance.

## Compatibility policy

A newer v1 reader must accept older v1 documents. The public `parse_json_report(str | bytes)`
reader accepts the exact flat D1.12 shape and normalizes it to the canonical D1.13 model; writers
emit only the canonical shape. A new optional v1 field is permitted only when the newer reader has
a deterministic default for older documents. Removing, renaming, retyping, changing meaning or
requiredness, changing identity or sorting, changing `null` interpretation, or making an enum
change that can alter automation interpretation requires `runtime-contract/v2`.

Version 2 requires a separate model, `$id`, schema file, and explicit adapter. Package versions and
JSON format versions evolve independently. Older readers are not required to read newer v1
documents.
