# Pilot and incremental-adoption iteration

Scope: the ten-repository technical pilot and new/worsened-finding PR gates. Classification:
isolated developer tooling. Public repository content remains English and value-blind.

Acceptance requirements:

1. Freeze protocol, full SHAs and minimal component configurations before scanning public 0.1.2.
2. Retain all twenty out-of-the-box/configured outcomes, warm-up/three measurements, stderr metadata,
   reproducibility digests, source integrity and declared exclusions.
3. Annotate every finding, keep security-sensitive evidence private, distinguish AI technical
   review from human ground truth, test controlled mutations and decide GO/HOLD for expansion.
4. Add `check --baseline`, compatible scope/policy/version checks, line-independent occurrence
   matching, worsening-severity detection, thresholds and fail-closed incomplete-analysis handling.
5. Retain all current findings in text/JSON/SARIF; retain normal `check` and informational `diff`.
6. Add injection-safe Action input forwarding, meaningful regression/E2E tests and current docs.
7. Pass repository quality, compatibility and distribution checks; publish code/docs/pilot on GitHub.

The [pilot protocol](../benchmarks/public-corpus/protocol.md) defines the research boundary.
The [baseline guide](baseline.md) defines trusted-input and failure semantics. A technical pilot
ending HOLD still meets this iteration's experiment requirement; it does not finish the final
75-repository study or provide independent human acceptance. Publishing a new PyPI version is
a separate destination from the requested GitHub publication.
