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


def test_cwe_attack_bridge_adds_coverage(config):
    """A CVE whose CWE has no CAPEC chain still maps via the direct bridge."""
    from tenable_attack_mapper.models import Finding

    mapper = DeterministicMapper(config.data_dir, use_nvd=False)
    # CVE-2021-34527 (PrintNightmare) -> CWE-269. CWE-269 is in both the CAPEC
    # chain and the bridge; the bridge guarantees T1068 coverage.
    finding = Finding(plugin_id="p", plugin_name="PrintNightmare", cves=["CVE-2021-34527"])
    techniques = {m.technique_id for m in mapper.map_finding(finding)}
    assert "T1068" in techniques

    for m in mapper.map_finding(finding):
        assert m.reason_code in ("chain:cve-cwe-capec-attack", "chain:cve-cwe-attack")
        assert m.confidence >= 0.8


def test_finding_without_cve_yields_no_deterministic_mapping(config, findings):
    mapper = DeterministicMapper(config.data_dir, use_nvd=False)
    assert mapper.map_finding(findings[2]) == []


def test_unknown_cve_is_ignored(config):
    from tenable_attack_mapper.models import Finding

    mapper = DeterministicMapper(config.data_dir, use_nvd=False)
    finding = Finding(plugin_id="x", plugin_name="x", cves=["CVE-0000-0000"])
    assert mapper.map_finding(finding) == []
