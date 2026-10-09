"""Shared fixtures for purple-team-lab tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PLANS = ROOT / "plans"


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def sample_plan() -> dict:
    path = sorted(PLANS.glob("*.yml"))[0]
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture
def tmp_plan(tmp_path: Path, sample_plan: dict) -> Path:
    """Write a mutable copy of a valid plan into a temporary directory."""
    target = tmp_path / "ptl-999-fixture.yml"
    sample_plan = dict(sample_plan)
    sample_plan["id"] = "PTL-999"
    target.write_text(yaml.safe_dump(sample_plan, sort_keys=False), encoding="utf-8")
    return target
