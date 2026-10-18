# Public-repository pilot

The [protocol](protocol.md) freezes the baseline at **0.1.2**. Corpus and configurations are
committed before measurement. Tools require the project's locked development dependencies;
the measured CLI must be a separate installation of public 0.1.2.

```sh
uv venv /tmp/runtime-contract-pilot/venv
uv pip install --python /tmp/runtime-contract-pilot/venv/bin/python runtime-contract==0.1.2
uv run python benchmarks/public-corpus/scripts/acquire.py \
  --corpus benchmarks/public-corpus/corpus.yaml --workspace /tmp/runtime-contract-pilot
uv run python benchmarks/public-corpus/scripts/run.py \
  --corpus benchmarks/public-corpus/corpus.yaml --workspace /tmp/runtime-contract-pilot \
  --cli /tmp/runtime-contract-pilot/venv/bin/runtime-contract
```

Use a fresh workspace for a new measurement; acquisition may resume only when its receipt and
tree digest match. Never commit the workspace or raw security-sensitive reports. The public export
contains only reviewed, value-blind data. Timing and RSS naturally vary across machines.
