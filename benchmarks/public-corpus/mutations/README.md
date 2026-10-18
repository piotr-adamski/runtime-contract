# Controlled witnesses

Eight minimal before/after fixtures isolate patterns present in the pinned corpus: Python/Compose
delivery (Bakerydemo), Python build/runtime delivery (Healthchecks), Pydantic aliases (FastAPI),
dynamic names (Healthchecks), Kubernetes envFrom (the corpus' Kubernetes deployment stratum),
and component separation (Docmost/FastAPI). These are synthetic witnesses derived from those
patterns, not patches claimed to break the original applications or population recall estimates.

No subject application is executed. All values in patches are deliberately public, synthetic,
nonsecret witnesses. The default-conflict case uses unordered Dockerfile declarations in the same
implicit target; the analyzer reports ambiguity without retaining or comparing values. Pydantic uses explicit
ellipsis to isolate alias handling from other field-requiredness heuristics.

`results.json` distinguishes expected diagnostics from observed results, including misses. An
alternative missing-delivery rule is not counted as the expected phase-specific diagnostic.
Every before state must exclude the expected rule; consumer/provider counts expose vacuous tests.
No mutation failure is repaired by changing the frozen 0.1.2 product.

Reproduce with a fresh workspace:

```sh
uv run python benchmarks/public-corpus/scripts/run_mutations.py \
  --cli /tmp/runtime-contract-pilot/venv/bin/runtime-contract \
  --workspace /tmp/runtime-contract-mutations \
  --output /tmp/runtime-contract-mutation-results
```
