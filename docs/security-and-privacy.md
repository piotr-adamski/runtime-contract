# Security and privacy model

This document is the public security contract for runtime-contract v0.1. The scanner treats every
repository and configuration file as untrusted data. It is a local, codebase-only static analyzer;
it has no server, account, telemetry, update check, or remote service.

## Threat model

Protected assets are the scanned source tree, adjacent host files, secret values, report integrity,
and local CPU/memory availability. Relevant attackers can control repository paths and bytes,
`runtime-contract.yaml`, YAML/JSON structure, symlinks, regex classification rules, and terminal
metadata. The caller controls explicit CLI options and the destination selected with `--output`.

Trust boundaries are:

1. untrusted project bytes entering discovery and parsers;
2. filesystem metadata used to keep reads inside the canonical project root;
3. normalized facts entering deterministic evaluation and renderers;
4. stdout/stderr or an explicitly selected atomic output file leaving the process.

The principal threats are code execution through parsers, traversal or symlink escape, unsafe YAML,
regex or parser denial of service, secret-value disclosure, source-tree mutation, nondeterministic
reports, and unexpected network or process activity.

## Data read

Discovery reads metadata under the selected root, `.gitignore`, an optional root
`runtime-contract.yaml`, and supported candidates only: exact `.env.example`, Dockerfile,
Python, JavaScript/TypeScript, Compose YAML, and supported Kubernetes YAML/JSON. It skips real
`.env*`, `.git`, dependency/build directories, binary/unsupported files, and symlinks escaping the
canonical root. Candidate identity is revalidated immediately before reading.

The scanner does not read the ambient environment to resolve project variables, Git history,
Docker, Kubernetes, external secret stores, credentials, or network resources.

## Data emitted

Reports contain relative POSIX paths, structural metadata, names of configuration variables,
locations, rule identifiers, severities, deterministic opaque IDs, and value-free remediation.
They do not contain source snippets, provider values, secret values or fragments, absolute host
paths, usernames, hostnames, process identifiers, timestamps, or exception text.

Reports go to stdout. Technical diagnostics go to stderr. A file is written only when the caller
explicitly selects `--output` (or its documented configuration equivalent); the write is atomic.
Without an output option, `scan`, `check`, `explain`, and `diff` preserve every source-tree file,
mode, modification time, and byte hash.

## Security controls

- Runtime imports are statically guarded against network, subprocess, logging, and dynamic
  `eval`/`exec` capability. Project code is parsed as data and never imported or executed.
- Configuration uses PyYAML `SafeLoader`; explicit tags, anchors, aliases, merge keys, duplicate
  keys, multiple documents, and files over 1 MiB fail closed.
- Compose rejects remote, absolute, escaping, cyclic, and unsupported include/extends paths.
- Discovery rejects configuration/root/source traversal and outside-root symlinks.
- Dockerfile, `.env.example`, Compose, Kubernetes, Python, and JavaScript/TypeScript inputs have
  pre-read size limits. Kubernetes also bounds YAML depth, nodes, aliases, documents, scalar size,
  objects, keys, containers, and environment entries.
- User classification regexes are ASCII, at most 256 characters, forbid grouping, lookarounds,
  backreferences, adjacent quantifiers, and more than one unbounded quantifier.
- One redaction boundary maps technical failures to registered public messages without retaining
  exception strings, arguments, causes, reprs, or tracebacks.
- Golden and process tests cover terminal, JSON, SARIF, stdout/stderr separation, determinism,
  relative paths, value redaction, traversal, parser safety limits, and read-only integrity.

## Telemetry and external transmission

There is no telemetry, analytics, crash reporting, remote configuration, update request, network
client, or background process. Normal CLI operation performs no network connection and sends no
repository metadata anywhere. CI or a caller may separately upload a generated SARIF artifact;
that external action is outside the runtime package and remains under caller control.

## Residual limitations

Static analysis cannot prove runtime behavior, dynamic variable names, external bulk-provider
contents, or the safety of dependencies and tools that invoke runtime-contract. Resource limits
reduce denial-of-service risk but cannot make parsing untrusted input cost-free. The explicit
output destination is caller-authorized mutation; choose a disposable report path and do not point
it at a source file. Dependency/CVE and release supply-chain review are separate release gates.

Security issues must follow [SECURITY.md](../SECURITY.md). This model was reviewed on 2026-07-12;
no active pentest, external target, credential, container, or production runtime was used.
