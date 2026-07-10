"""Shared analyzer inputs."""

from __future__ import annotations

import pytest

from runtime_contract.analysis import AnalyzerInput
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import Profile
from tests.analysis.doubles import StaticResolver


@pytest.fixture
def analyzer_input() -> AnalyzerInput:
    return AnalyzerInput(
        path="src/settings.py",
        kind=CandidateKind.PYTHON,
        content=b"required",
        component="api",
        root="app",
        profile=Profile.PROD,
        resolver=StaticResolver(),
    )
