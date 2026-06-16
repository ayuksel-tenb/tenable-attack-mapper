"""Navigator layer is structurally valid v4.x and pipeline wiring holds."""

from __future__ import annotations

from tenable_attack_mapper.navigator import build_layer
from tenable_attack_mapper.pipeline import findings_for_techniques, map_findings


def test_layer_has_required_v4_keys(config, findings):
    result = map_findings(config, findings)
    layer = result.layer

    assert layer["versions"]["layer"].startswith("4.")
    assert layer["domain"] == "enterprise-attack"
    assert isinstance(layer["techniques"], list)
    assert layer["gradient"]["maxValue"] == 100

    for tech in layer["techniques"]:
        assert tech["techniqueID"].startswith("T")
        assert 0 <= tech["score"] <= 100
        assert "metadata" in tech


def test_pipeline_maps_known_findings(config, findings):
    result = map_findings(config, findings)
    assert result.summary["findings_mapped"] >= 2
    assert result.summary["mappings_semantic"] == 0  # semantic disabled
    technique_ids = {s.technique_id for s in result.scores}
    assert "T1190" in technique_ids


def test_findings_for_techniques_includes_subtechniques():
    from tenable_attack_mapper.models import TechniqueMapping

    mappings = [
        TechniqueMapping("p1", "T1190", "deterministic", 0.95, "r"),
        TechniqueMapping("p2", "T1059.007", "semantic", 0.6, "r"),
    ]
    result = findings_for_techniques(mappings, ["T1190", "T1059"])
    assert result["T1190"] == ["p1"]
    assert result["T1059"] == ["p2"]  # base ID matches the sub-technique


def test_empty_findings_yields_empty_layer(config):
    result = map_findings(config, [])
    assert result.layer["techniques"] == []
    assert result.summary["findings_total"] == 0
