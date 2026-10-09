"""Integration checks against the committed plans."""

from __future__ import annotations

from pathlib import Path

import yaml

from tools.render_coverage import render
from tools.validate_plans import discover, validate_plan


def test_all_plans_valid() -> None:
    paths = discover()
    assert paths, "expected at least one plan"
    for path in paths:
        errors = validate_plan(path)
        assert errors == [], f"{path.name}: {errors}"


def test_plan_ids_unique() -> None:
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"] for p in discover()]
    assert len(ids) == len(set(ids))


def test_coverage_render_matches_committed(repo_root: Path) -> None:
    plans = []
    for path in discover():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["_path"] = path.relative_to(repo_root).as_posix()
        plans.append(data)
    expected = render(plans)
    actual = (repo_root / "docs" / "coverage.md").read_text(encoding="utf-8")
    assert actual == expected
