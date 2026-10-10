"""Tests for tools/render_coverage.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import render_coverage as rc


def test_main_check_up_to_date(capsys: pytest.CaptureFixture[str]) -> None:
    assert rc.main(["--check"]) == 0
    assert "up to date" in capsys.readouterr().out


def test_main_write_and_stale_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "repo"
    plans = root / "plans"
    docs = root / "docs"
    plans.mkdir(parents=True)
    docs.mkdir()
    # Copy one real plan so render has content.
    sample = sorted(Path(rc.PLANS).glob("*.yml"))[0]
    (plans / sample.name).write_text(sample.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(rc, "ROOT", root)
    monkeypatch.setattr(rc, "PLANS", plans)
    monkeypatch.setattr(rc, "OUTPUT", docs / "coverage.md")
    assert rc.main([]) == 0
    assert (docs / "coverage.md").is_file()
    assert "wrote" in capsys.readouterr().out
    assert rc.main(["--check"]) == 0
    (docs / "coverage.md").write_text("stale\n", encoding="utf-8")
    assert rc.main(["--check"]) == 1
    assert "stale" in capsys.readouterr().err


def test_render_marks_empty_mitigations_and_yara() -> None:
    plans = [
        {
            "id": "PTL-999",
            "_path": "plans/ptl-999.yml",
            "technique": "T1547.001",
            "additional_techniques": [],
            "tactic": "persistence",
            "detection_strategies": ["DET0001"],
            "detections": [
                {"path": "rules/sigma/demo.yml", "coverage": "expected-match"},
                {"path": "rules/yara/demo.yar", "coverage": "partial"},
            ],
            "mitigations": [],
        }
    ]
    text = rc.render(plans)
    assert "PTL-999" in text
    assert "demo (partial)" in text
    assert "—" in text
