"""Deterministic chain resolves known CVEs and leaves unknowns unmapped."""

from __future__ import annotations

from tenable_attack_mapper.mapping import DeterministicMapper


def test_log4shell_maps_to_exploit_public_facing(config, findings):
    mapper = DeterministicMapper(config.data_dir, use_nvd=False)
    mappings = mapper.map_finding(findings[0])

    technique_ids = {m.technique_id for m in mappings}
    # CVE-2021-44228 -> CWE-917 -> CAPEC-242 -> T1190 / T1203
    assert "T1190" in technique_ids

    for mapping in mappings:
        assert mapping.source == "deterministic"
        assert mapping.confidence > 0.9
        assert mapping.reason_code == "chain:cve-cwe-capec-attack"
        assert "->" in mapping.evidence  # full audit trail recorded


def test_finding_without_cve_yields_no_deterministic_mapping(config, findings):
    mapper = DeterministicMapper(config.data_dir, use_nvd=False)
    assert mapper.map_finding(findings[2]) == []


def test_unknown_cve_is_ignored(config):
    from tenable_attack_mapper.models import Finding

    mapper = DeterministicMapper(config.data_dir, use_nvd=False)
    finding = Finding(plugin_id="x", plugin_name="x", cves=["CVE-0000-0000"])
    assert mapper.map_finding(finding) == []
