"""Reconcile prefers deterministic, flags low confidence, and scores by VPR."""

from __future__ import annotations

from tenable_attack_mapper.mapping import reconcile, score_techniques
from tenable_attack_mapper.models import Finding, TechniqueMapping


def _det(plugin, tech, conf=0.95):
    return TechniqueMapping(plugin, tech, "deterministic", conf, "chain:cve-cwe-capec-attack")


def _sem(plugin, tech, conf):
    return TechniqueMapping(plugin, tech, "semantic", conf, "semantic:keyword")


def test_deterministic_wins_over_semantic_duplicate():
    merged = reconcile(
        [_det("p1", "T1190")],
        [_sem("p1", "T1190", 0.4)],
        confidence_threshold=0.5,
    )
    assert len(merged) == 1
    assert merged[0].source == "deterministic"
    assert merged[0].needs_review is False


def test_low_confidence_semantic_is_flagged():
    merged = reconcile([], [_sem("p1", "T1059", 0.3)], confidence_threshold=0.5)
    assert merged[0].needs_review is True


def test_scoring_weights_by_vpr_and_normalizes_to_100():
    findings = {
        "p1": Finding("p1", "high vpr", vpr_score=10.0, count=5),
        "p2": Finding("p2", "low vpr", vpr_score=2.0, count=1),
    }
    mappings = [_det("p1", "T1190"), _det("p2", "T1059")]
    scores = score_techniques(mappings, findings, confidence_threshold=0.5)

    top = scores[0]
    assert top.technique_id == "T1190"  # highest exposure ranks first
    assert top.score == 100.0           # normalized peak
    assert all(0.0 <= s.score <= 100.0 for s in scores)


def test_extract_json_array_handles_fences():
    from tenable_attack_mapper.mapping.semantic import _extract_json_array

    fenced = '```json\n[{"plugin_id": "1", "mappings": []}]\n```'
    assert _extract_json_array(fenced) == [{"plugin_id": "1", "mappings": []}]
    assert _extract_json_array("no json here") == []


def test_semantic_backend_factory_selects_claude(config):
    from tenable_attack_mapper.mapping.semantic import (
        ClaudeCliSemanticMapper,
        build_semantic_mapper,
    )

    config.semantic_backend = "claude"
    mapper = build_semantic_mapper(config, None)
    assert isinstance(mapper, ClaudeCliSemanticMapper)


def test_semantic_model_params_are_model_aware():
    """Haiku rejects adaptive thinking/effort; Opus accepts them."""
    from tenable_attack_mapper.mapping.semantic import SemanticMapper

    haiku = SemanticMapper(api_key="x", model="claude-haiku-4-5")._model_params()
    assert "thinking" not in haiku
    assert "effort" not in haiku["output_config"]
    assert haiku["output_config"]["format"]["type"] == "json_schema"

    opus = SemanticMapper(api_key="x", model="claude-opus-4-8")._model_params()
    assert opus["thinking"]["type"] == "adaptive"
    assert opus["output_config"]["effort"]


def test_default_vpr_used_when_missing():
    findings = {"p1": Finding("p1", "no vpr", vpr_score=None, count=1)}
    scores = score_techniques([_det("p1", "T1190")], findings, confidence_threshold=0.5)
    assert scores[0].total_vpr > 0  # DEFAULT_VPR applied
