from pathlib import Path

from runtime_contract.analysis.dockerfile import MAX_DOCKERFILE_BYTES
from runtime_contract.analysis.dotenv import MAX_DOTENV_BYTES
from runtime_contract.compose import (
    MAX_COMPOSE_BYTES,
    MAX_PROJECT_BYTES,
    MAX_REFERENCE_DEPTH,
)
from runtime_contract.compose import (
    MAX_SCALAR_BYTES as MAX_COMPOSE_SCALAR_BYTES,
)
from runtime_contract.compose import (
    MAX_YAML_DEPTH as MAX_COMPOSE_YAML_DEPTH,
)
from runtime_contract.compose import (
    MAX_YAML_NODES as MAX_COMPOSE_YAML_NODES,
)
from runtime_contract.config.loader import MAX_CONFIG_BYTES
from runtime_contract.kubernetes import (
    MAX_KUBERNETES_BYTES,
    MAX_YAML_DOCUMENTS,
)
from runtime_contract.kubernetes import (
    MAX_YAML_DEPTH as MAX_KUBERNETES_YAML_DEPTH,
)
from runtime_contract.kubernetes import (
    MAX_YAML_NODES as MAX_KUBERNETES_YAML_NODES,
)
from runtime_contract.kubernetes.loader import MAX_SCALAR_BYTES as MAX_KUBERNETES_SCALAR_BYTES
from runtime_contract.scan.engine import MAX_SOURCE_BYTES

REPO = Path(__file__).resolve().parents[2]


def test_public_resource_budget_contract_matches_runtime_limits() -> None:
    assert MAX_SOURCE_BYTES == 4 * 1024 * 1024
    assert {
        MAX_CONFIG_BYTES,
        MAX_COMPOSE_BYTES,
        MAX_KUBERNETES_BYTES,
        MAX_DOCKERFILE_BYTES,
        MAX_DOTENV_BYTES,
    } == {1024 * 1024}
    assert MAX_PROJECT_BYTES == 8 * 1024 * 1024
    assert MAX_REFERENCE_DEPTH == 32
    assert MAX_COMPOSE_YAML_DEPTH == MAX_KUBERNETES_YAML_DEPTH == 64
    assert MAX_COMPOSE_YAML_NODES == MAX_KUBERNETES_YAML_NODES == 10_000
    assert MAX_COMPOSE_SCALAR_BYTES == MAX_KUBERNETES_SCALAR_BYTES == 64 * 1024
    assert MAX_YAML_DOCUMENTS == 256

    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for statement in (
        "## Resource budgets and limits",
        "limited to 4 MiB each",
        "limited to 1 MiB each",
        "limited to 8 MiB",
        "limited to 32 levels",
        "depth of 64",
        "10,000 nodes",
        "64 KiB per scalar",
        "at most 256 documents",
        "500 components and 1,000 supported files",
        "median below 8 seconds",
        "byte-identical JSON",
    ):
        assert statement in readme
