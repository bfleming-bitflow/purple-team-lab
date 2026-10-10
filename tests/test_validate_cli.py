"""In-process CLI and additional failure paths for tools/validate_plans.py."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools import validate_plans as vp


def test_main_validates_all_plans(capsys: pytest.CaptureFixture[str]) -> None:
    assert vp.main([]) == 0
    assert "valid" in capsys.readouterr().out


def test_main_explicit_plan() -> None:
    path = sorted(vp.discover())[0]
    assert vp.main([str(path)]) == 0


def test_main_no_plans(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(vp, "discover", list)
    assert vp.main([]) == 1
    assert "no plans found" in capsys.readouterr().err


def test_load_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "ptl-999-x.yml"
    path.write_text("- just a list\n", encoding="utf-8")
    assert "YAML mapping" in "\n".join(vp.validate_plan(path))


def test_schema_error_short_circuits(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    del data["title"]
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    errors = vp.validate_plan(tmp_plan)
    assert any(e.startswith("schema:") for e in errors)
    assert len(errors) == 1 or all(e.startswith("schema:") for e in errors)


def test_unknown_tactic_shortname(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["tactic"] = "not-a-real-tactic"
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert any("not a current ATT&CK tactic shortname" in e for e in vp.validate_plan(tmp_plan))


def test_unknown_data_component_and_strategy(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["telemetry"][0]["data_component"] = "DC9999"
    data["detection_strategies"] = ["DET9999"]
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    errors = "\n".join(vp.validate_plan(tmp_plan))
    assert "not a current ATT&CK data component" in errors
    assert "not a current ATT&CK detection strategy" in errors


def test_strategy_must_cover_technique(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    # DET0363 covers T1003.001; pick a plan that is not that technique and force DET0363
    # Use a strategy that exists but does not cover the plan technique.
    strategies = vp.detection_strategies()
    foreign = next(sid for sid, techs in strategies.items() if data["technique"] not in techs and techs)
    data["detection_strategies"] = [foreign]
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert any("does not cover any technique" in e for e in vp.validate_plan(tmp_plan))


def test_mitigation_errors(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["mitigations"] = [
        {"id": "M9999", "name": "Nope", "description": "x" * 20},
        {"id": "M1038", "name": "Wrong Name", "description": "x" * 20},
    ]
    # Ensure technique has some applicable mitigations so empty-list rule is not the only path
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    errors = "\n".join(vp.validate_plan(tmp_plan))
    assert "not a current ATT&CK mitigation" in errors
    assert "is named" in errors and "not 'Wrong Name'" in errors


def test_missing_required_mitigations(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    # Skip if this plan's technique has no ATT&CK mitigations (e.g. T1547.001)
    applicable: set[str] = set()
    for technique in [data["technique"], *data.get("additional_techniques", [])]:
        applicable |= vp.technique_mitigations().get(technique, set())
        applicable |= vp.technique_mitigations().get(technique.split(".")[0], set())
    if not applicable:
        pytest.skip("fixture plan technique has no ATT&CK mitigations")
    data["mitigations"] = []
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert any("list at least one" in e for e in vp.validate_plan(tmp_plan))


def test_detection_technique_mismatch(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["detections"][0]["techniques"] = ["T9999.001"]
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    errors = "\n".join(vp.validate_plan(tmp_plan))
    assert "not tagged with" in errors or "not a technique of this plan" in errors


def test_empty_command_and_disallowed_executable(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["procedure"] = [
        {
            "name": "Empty",
            "description": "Empty command for coverage.",
            "command": "   ",
            "shell": "cmd",
            "elevation_required": False,
        },
        {
            "name": "Curl",
            "description": "Disallowed executable for coverage.",
            "command": "curl.exe http://files.lab.test/a",
            "shell": "cmd",
            "elevation_required": False,
        },
    ]
    tmp_plan.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    errors = "\n".join(vp.validate_plan(tmp_plan))
    assert "no executable token" in errors
    assert "not in the safe allowlist" in errors


def test_validate_duplicate_plan_ids(
    tmp_path: Path, sample_plan: dict, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("ptl-999-a.yml", "ptl-999-b.yml"):
        data = dict(sample_plan)
        data["id"] = "PTL-999"
        (tmp_path / name).write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert vp.validate([tmp_path / "ptl-999-a.yml", tmp_path / "ptl-999-b.yml"]) == 1
    assert "duplicate plan id" in capsys.readouterr().err


def test_display_falls_back_outside_root(tmp_path: Path) -> None:
    path = tmp_path / "outside.yml"
    path.write_text("x: 1\n", encoding="utf-8")
    assert vp._display(path) == str(path)
