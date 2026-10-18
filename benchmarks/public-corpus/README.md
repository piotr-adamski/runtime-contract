# Public-repository pilot

The [protocol](protocol.md) freezes the baseline at **0.1.2**. Corpus and configurations are
committed before measurement. Tools require the project's locked development dependencies;
the measured CLI must be a separate installation of public 0.1.2.

Read the [pilot report](results/pilot-20261018/report.md),
[corpus metadata errata](corpus-errata.json) and [mutation witnesses](mutations/README.md).
The technical experiment ends **HOLD**; annotations are provisional AI assessments and all
human adjudication remains pending. The final 75-repository study is future scope.

```sh
uv venv /tmp/runtime-contract-pilot/venv
uv pip install --python /tmp/runtime-contract-pilot/venv/bin/python runtime-contract==0.1.2
uv run python benchmarks/public-corpus/scripts/acquire.py \
  --corpus benchmarks/public-corpus/corpus.yaml --workspace /tmp/runtime-contract-pilot
uv run python benchmarks/public-corpus/scripts/run.py \
  --corpus benchmarks/public-corpus/corpus.yaml --workspace /tmp/runtime-contract-pilot \
  --cli /tmp/runtime-contract-pilot/venv/bin/runtime-contract
uv run python benchmarks/public-corpus/scripts/annotate.py \
  --workspace /tmp/runtime-contract-pilot --output /tmp/runtime-contract-pilot/annotations.json
uv run python benchmarks/public-corpus/scripts/validate_annotations.py \
  --workspace /tmp/runtime-contract-pilot --annotations /tmp/runtime-contract-pilot/annotations.json
uv run python benchmarks/public-corpus/scripts/build_report.py \
  --workspace /tmp/runtime-contract-pilot --annotations /tmp/runtime-contract-pilot/annotations.json \
  --output /tmp/runtime-contract-pilot/public-results
```

Use a fresh workspace for a new measurement; acquisition may resume only when its receipt and
tree digest match. Never commit the workspace or raw security-sensitive reports. The public export
contains only reviewed, value-blind data. Timing and RSS naturally vary across machines.
