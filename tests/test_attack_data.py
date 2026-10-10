"""Tests for tools/attack_data.py against a minimal STIX fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import attack_data as ad

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "minimal-attack-bundle.json"


@pytest.fixture
def bundle() -> ad.Bundle:
    return ad.Bundle(json.loads(FIXTURE.read_text(encoding="utf-8"))["objects"])


def test_build_emits_vendored_outputs(bundle: ad.Bundle) -> None:
    files = ad.build(bundle)
    assert set(files) == {*ad.OUTPUTS, "ATTACK_VERSION"}
    assert files["ATTACK_VERSION"] == "19.2\n"
    techniques = files["attack-enterprise-techniques.csv"]
    assert techniques.startswith("technique_id,name,tactics\n")
    assert "T1547.001,Registry Run Keys,persistence\n" in techniques
    assert "T9999" not in techniques
    assert "T9998" not in techniques
    tactics = files["attack-enterprise-tactics.csv"]
    assert "TA0003,persistence,Persistence\n" in tactics
    assert "M1038,Execution Prevention\n" in files["attack-enterprise-mitigations.csv"]
    assert "T1547.001,M1038\n" in files["attack-enterprise-technique-mitigations.csv"]
    assert "DC0032,Process Creation\n" in files["attack-enterprise-data-components.csv"]
    assert "DET0001,Detect Run Keys,T1547.001\n" in files["attack-enterprise-detection-strategies.csv"]
    assert "AN0001,DET0001,Windows,DC0032\n" in files["attack-enterprise-analytics.csv"]


def test_generators_cover_mitigations_and_detections(bundle: ad.Bundle) -> None:
    assert "M1038,Execution Prevention\n" in ad.mitigations(bundle)
    assert "CAPEC-1" not in ad.mitigations(bundle)
    assert "T1547.001,M1038\n" in ad.technique_mitigations(bundle)
    assert "DC0032,Process Creation\n" in ad.data_components(bundle)
    assert "DET0001,Detect Run Keys,T1547.001\n" in ad.detection_strategies(bundle)
    assert "AN0001,DET0001,Windows,DC0032\n" in ad.analytics(bundle)


def test_version_requires_single_collection() -> None:
    with pytest.raises(ValueError, match="exactly one x-mitre-collection"):
        ad.Bundle([]).version()


def test_main_write_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert ad.main(["--bundle", str(FIXTURE), "--output-dir", str(tmp_path)]) == 0
    assert "wrote" in capsys.readouterr().out
    assert ad.main(["--bundle", str(FIXTURE), "--output-dir", str(tmp_path), "--check"]) == 0
    assert "reference data matches ATT&CK 19.2" in capsys.readouterr().out
    (tmp_path / "ATTACK_VERSION").write_text("0.0\n", encoding="utf-8")
    assert ad.main(["--bundle", str(FIXTURE), "--output-dir", str(tmp_path), "--check"]) == 1
    assert "out of date" in capsys.readouterr().err
