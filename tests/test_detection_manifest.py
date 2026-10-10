"""Tests for tools/detection_manifest.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import detection_manifest as dm

FAKE_REPO = Path(__file__).resolve().parent / "fixtures" / "fake-detection-rules"


def test_render_lists_sigma_and_yara() -> None:
    content = dm.render(FAKE_REPO)
    assert content.startswith("kind,path,rule_id,name,techniques\n")
    assert "sigma,rules/sigma/windows/proc_creation_win_demo.yml," in content
    assert "T1059.001" in content
    assert "yara,rules/yara/demo_rule.yar,22222222-2222-2222-2222-222222222222,Demo_Yara_Rule," in content
    assert "T1105" in content


def test_yara_rejects_multiple_rules(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    yara = repo / "rules" / "yara"
    yara.mkdir(parents=True)
    (repo / "rules" / "sigma").mkdir(parents=True)
    (yara / "bad.yar").write_text("rule A {}\nrule B {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one rule"):
        dm.yara_rows(repo)


def test_main_write_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "manifest.csv"
    assert dm.main(["--repo", str(FAKE_REPO), "--output", str(output)]) == 0
    assert output.is_file()
    assert "wrote" in capsys.readouterr().out
    assert dm.main(["--repo", str(FAKE_REPO), "--output", str(output), "--check"]) == 0
    assert "up to date" in capsys.readouterr().out
    output.write_text("stale\n", encoding="utf-8")
    assert dm.main(["--repo", str(FAKE_REPO), "--output", str(output), "--check"]) == 1
    assert "stale" in capsys.readouterr().err
