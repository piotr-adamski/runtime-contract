#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/quality-gates.sh [--full] [--base-ref <ref>] [--allow-dependabot]

Run the complete Python 3.14 quality gates. --full additionally verifies Python 3.11-3.14.
The default comparison base is the merge base of HEAD and origin/main.
EOF
}

full=false
base_ref=""
allow_dependabot=false
while (($#)); do
  case "$1" in
    --full)
      full=true
      shift
      ;;
    --base-ref)
      if (($# < 2)) || [[ -z "$2" ]]; then
        echo "quality-gates: --base-ref requires a value" >&2
        exit 2
      fi
      base_ref=$2
      shift 2
      ;;
    --allow-dependabot)
      allow_dependabot=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "quality-gates: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

stage() {
  printf '\n==> %s\n' "$1"
}

if [[ ${QUALITY_GATES_TEST_MODE:-0} == 1 ]]; then
  echo "quality-gates: controlled test mode PASS"
  exit 0
fi

stage "Environment"
if ! command -v uv >/dev/null 2>&1; then
  echo "quality-gates: uv is not installed" >&2
  exit 1
fi
uv_output=$(uv --version)
echo "$uv_output"
uv_version=${uv_output#uv }
uv_version=${uv_version%% *}
IFS=. read -r uv_major uv_minor uv_patch uv_extra <<<"$uv_version"
if [[ $uv_major != 0 || $uv_minor != 11 || -n ${uv_extra:-} || ! $uv_patch =~ ^[0-9]+$ || $uv_patch -lt 28 ]]; then
  echo "quality-gates: uv $uv_version is outside the supported range >=0.11.28,<0.12" >&2
  exit 1
fi
uv python install 3.14
uv run --python 3.14 python --version

if [[ -n $base_ref ]]; then
  if ! base_sha=$(git rev-parse --verify "${base_ref}^{commit}" 2>/dev/null); then
    echo "quality-gates: base ref is unavailable: $base_ref" >&2
    exit 1
  fi
else
  if ! git remote get-url origin >/dev/null 2>&1; then
    echo "quality-gates: required remote 'origin' is unavailable" >&2
    exit 1
  fi
  if ! git rev-parse --verify "origin/main^{commit}" >/dev/null 2>&1; then
    echo "quality-gates: required ref origin/main is unavailable" >&2
    exit 1
  fi
  if ! base_sha=$(git merge-base HEAD origin/main); then
    echo "quality-gates: no merge base exists for HEAD and origin/main" >&2
    exit 1
  fi
fi
head_sha=$(git rev-parse --verify HEAD^{commit})
if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
  echo "quality-gates: resolved base commit is unavailable: $base_sha" >&2
  exit 1
fi
echo "Comparison range: ${base_sha}..${head_sha}"

stage "Lockfile"
uv lock --check
lock_before=$(git hash-object uv.lock)
uv sync --locked --all-groups --python 3.14
lock_after=$(git hash-object uv.lock)
if [[ $lock_before != "$lock_after" ]]; then
  echo "quality-gates: uv sync modified uv.lock" >&2
  exit 1
fi

stage "Formatting, lint, and typing"
uv run --python 3.14 ruff format --check .
uv run --python 3.14 ruff check .
uv run --python 3.14 mypy --strict src tests

stage "Configuration schema and examples"
uv run --python 3.14 python scripts/generate_config_schema.py --check
uv run --python 3.14 python scripts/generate_analysis_schema.py --check
uv run --python 3.14 python scripts/generate_scan_schema.py --check
uv run --python 3.14 python -c \
  'from runtime_contract.scan.schema import generate_schema_bytes; assert generate_schema_bytes() == generate_schema_bytes()'
uv run --python 3.14 runtime-contract config validate examples/minimal
uv run --python 3.14 runtime-contract config validate examples/full --format json >/dev/null
for scan_format in text json sarif; do
  first=$(mktemp)
  second=$(mktemp)
  uv run --python 3.14 runtime-contract scan examples/scan-flow --format "$scan_format" >"$first"
  uv run --python 3.14 runtime-contract scan examples/scan-flow --format "$scan_format" >"$second"
  cmp "$first" "$second"
  rm -f "$first" "$second"
done
scan_tmp=$(mktemp -d)
uv run --python 3.14 runtime-contract scan examples/scan-flow --root api --format json \
  >"$scan_tmp/api.json"
uv run --python 3.14 python -m json.tool "$scan_tmp/api.json" >/dev/null
uv run --python 3.14 python -c \
  'import json,sys; from jsonschema import Draft202012Validator; schema=json.load(open("schemas/runtime-contract-scan-result-v1.schema.json", encoding="utf-8")); Draft202012Validator(schema).validate(json.load(open(sys.argv[1], encoding="utf-8")))' \
  "$scan_tmp/api.json"
uv run --python 3.14 runtime-contract scan examples/scan-flow --format json \
  --output "$scan_tmp/scan.json"
uv run --python 3.14 python -m json.tool "$scan_tmp/scan.json" >/dev/null
cmp "$scan_tmp/scan.json" <(uv run --python 3.14 runtime-contract scan examples/scan-flow --format json)
uv run --python 3.14 runtime-contract scan examples/report-fixture --format json \
  >"$scan_tmp/golden.json"
cmp "$scan_tmp/golden.json" examples/reports/runtime-contract-v1.json
cmp "$scan_tmp/golden.json" <(uv run --python 3.14 runtime-contract scan examples/report-fixture --format json)
mkdir "$scan_tmp/invalid"
printf '\377' >"$scan_tmp/invalid/app.py"
set +e
uv run --python 3.14 runtime-contract scan "$scan_tmp/invalid" --format json \
  >"$scan_tmp/failed.json"
scan_failed_status=$?
set -e
if [[ $scan_failed_status != 2 ]]; then
  echo "scan negative smoke: expected exit 2, got $scan_failed_status" >&2
  exit 1
fi
uv run --python 3.14 python -m json.tool "$scan_tmp/failed.json" >/dev/null
uv run --python 3.14 python -c \
  'import json,sys; from jsonschema import Draft202012Validator; schema=json.load(open("schemas/runtime-contract-scan-result-v1.schema.json", encoding="utf-8")); Draft202012Validator(schema).validate(json.load(open(sys.argv[1], encoding="utf-8")))' \
  "$scan_tmp/failed.json"
rm -rf "$scan_tmp"

stage "Tests and product coverage"
uv run --python 3.14 pytest \
  --cov=runtime_contract \
  --cov-branch \
  --cov-report=term-missing \
  --cov-report=xml:coverage.xml
uv run --python 3.14 python scripts/ci/check_branch_coverage.py coverage.xml

stage "Changed product line coverage"
uv run --python 3.14 diff-cover coverage.xml \
  --compare-branch "$base_sha" \
  --diff-range-notation '..' \
  --fail-under=100

stage "DCO"
dco_args=(--base "$base_sha" --head "$head_sha")
if [[ $allow_dependabot == true ]]; then
  dco_args+=(--allow-dependabot)
fi
uv run --python 3.14 python scripts/ci/check_dco.py "${dco_args[@]}"

stage "Build and distribution validation"
rm -rf dist
uv build
uv run --python 3.14 python scripts/ci/verify_artifacts.py dist

smoke_distribution() {
  local python_version=$1
  local distribution=$2
  local label=$3
  local temp_dir
  temp_dir=$(mktemp -d)
  uv venv --python "$python_version" "$temp_dir/venv"
  uv pip install --python "$temp_dir/venv/bin/python" "$distribution"
  uv pip install --python "$temp_dir/venv/bin/python" 'jsonschema>=4.26,<5'
  uv pip check --python "$temp_dir/venv/bin/python"
  cp -R examples/scan-flow "$temp_dir/fixture"
  (
    cd "$temp_dir"
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'import importlib.metadata; import runtime_contract; assert importlib.metadata.version("runtime-contract") == "0.1.0.dev0"'
    PYTHONPATH= "$temp_dir/venv/bin/python" -m runtime_contract --version
    PYTHONPATH= "$temp_dir/venv/bin/runtime-contract" --help >/dev/null
    for command in scan check explain diff config; do
      PYTHONPATH= "$temp_dir/venv/bin/runtime-contract" "$command" --help >/dev/null
    done
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'from runtime_contract.config.schema import schema_bytes; assert schema_bytes()'
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'from runtime_contract.analysis import Analyzer, AnalyzerInput, AnalyzerRegistry, AnalysisDiagnostic, AnalysisResult, AnalysisCompleteness, DiagnosticCode, Confidence, FactKind, FactObservation, ClassificationResolver, EffectiveClassification, DecisionSource, AnalyzerNotRegisteredError, AnalyzerExecutionError, ComposeAnalyzer, DotenvAnalyzer, DockerfileAnalyzer; from runtime_contract.analysis.schema import schema_bytes; assert schema_bytes() and Analyzer and ClassificationResolver and ComposeAnalyzer and DotenvAnalyzer and DockerfileAnalyzer'
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'from runtime_contract.normalization import NormalizationError, NormalizationErrorCode, normalize_observations; assert normalize_observations(()).model_dump_json() and NormalizationError and NormalizationErrorCode'
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'from runtime_contract.kubernetes import KubernetesInput, KubernetesTraversalResult, traverse_kubernetes_workloads; result=traverse_kubernetes_workloads(KubernetesInput(path="pod.yaml", content=b"apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: web}]}\n")); assert KubernetesTraversalResult and result.contexts[0].container_name == "web"'
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'import importlib; modules=("runtime_contract", "runtime_contract.analysis", "runtime_contract.domain", "runtime_contract.kubernetes", "runtime_contract.normalization", "runtime_contract.scan"); assert all(getattr(importlib.import_module(name), exported) is not None for name in modules for exported in importlib.import_module(name).__all__)'
    for scan_format in text json sarif; do
      PYTHONHASHSEED=1 PYTHONPATH= "$temp_dir/venv/bin/runtime-contract" scan fixture \
        --format "$scan_format" >"$scan_format.first"
      PYTHONHASHSEED=2 PYTHONPATH= "$temp_dir/venv/bin/runtime-contract" scan fixture \
        --format "$scan_format" >"$scan_format.second"
      cmp "$scan_format.first" "$scan_format.second"
      PYTHONPATH= "$temp_dir/venv/bin/runtime-contract" scan fixture --format "$scan_format" \
        --output "$scan_format.output"
      cmp "$scan_format.first" "fixture/$scan_format.output"
    done
    PYTHONPATH= "$temp_dir/venv/bin/python" -c \
      'import json; from jsonschema import Draft202012Validator; from runtime_contract.scan.schema import schema_bytes; Draft202012Validator(json.loads(schema_bytes())).validate(json.load(open("json.first", encoding="utf-8")))'
  )
  rm -rf "$temp_dir"
  echo "$label smoke test: PASS on Python $python_version"
}

wheel=$(find dist -maxdepth 1 -type f -name '*.whl' -print)
sdist=$(find dist -maxdepth 1 -type f -name '*.tar.gz' -print)
stage "Python 3.14 sdist smoke"
smoke_distribution 3.14 "$sdist" "sdist"

if [[ $full == true ]]; then
  stage "Python 3.11-3.14 compatibility"
  for python_version in 3.11 3.12 3.13 3.14; do
    uv python install "$python_version"
    uv run --isolated --python "$python_version" pytest
    smoke_distribution "$python_version" "$wheel" "wheel"
  done
  smoke_distribution 3.14 "$sdist" "sdist"
fi

stage "Result"
echo "quality-gates: PASS"
