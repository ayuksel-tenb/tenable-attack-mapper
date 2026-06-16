"""Deterministic CVE -> CWE -> CAPEC -> ATT&CK mapping.

This is the *primary* evidence source. Where an authoritative chain exists, the
resulting mapping is high-confidence and fully auditable: every link records the
exact CVE/CWE/CAPEC trail in its ``evidence`` field.

The CVE -> CWE hop prefers a live NVD lookup when enabled and reachable, and
falls back to the bundled ``cve_cwe.json`` seed table otherwise. The remaining
hops are served entirely from the local MITRE-derived tables.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import Finding, TechniqueMapping

# Confidence assigned to a complete deterministic chain. It is high but not 1.0:
# taxonomy mappings are authoritative yet still a generalization of attacker
# behaviour, so we leave headroom above it for nothing and below it for semantic.
DETERMINISTIC_CONFIDENCE = 0.95


class DeterministicMapper:
    """Resolves findings to techniques via the CVE/CWE/CAPEC/ATT&CK chain."""

    def __init__(self, data_dir: Path, *, use_nvd: bool | None = None):
        self._cve_cwe = _load_table(data_dir / "cve_cwe.json")
        self._cwe_capec = _load_table(data_dir / "cwe_capec.json")
        self._capec_attack = _load_table(data_dir / "capec_attack.json")
        if use_nvd is None:
            use_nvd = _as_bool(os.getenv("TASC_USE_NVD"), default=False)
        self._use_nvd = use_nvd
        self._nvd_cache: dict[str, list[str]] = {}

    def map_finding(self, finding: Finding) -> list[TechniqueMapping]:
        """Return deterministic mappings for one finding (possibly empty)."""
        mappings: dict[str, TechniqueMapping] = {}

        for cve in finding.cves:
            for cwe in self._cwes_for(cve):
                for capec in self._cwe_capec.get(cwe, []):
                    for technique in self._capec_attack.get(capec, []):
                        evidence = f"{cve} -> {cwe} -> {capec} -> {technique}"
                        existing = mappings.get(technique)
                        if existing is None:
                            mappings[technique] = TechniqueMapping(
                                plugin_id=finding.plugin_id,
                                technique_id=technique,
                                source="deterministic",
                                confidence=DETERMINISTIC_CONFIDENCE,
                                reason_code="chain:cve-cwe-capec-attack",
                                evidence=evidence,
                            )
                        elif evidence not in existing.evidence:
                            # Accumulate alternate trails to the same technique.
                            existing.evidence += f"; {evidence}"

        return list(mappings.values())

    def _cwes_for(self, cve: str) -> list[str]:
        cve = cve.strip().upper()
        if self._use_nvd:
            live = self._nvd_lookup(cve)
            if live:
                return live
        return self._cve_cwe.get(cve, [])

    def _nvd_lookup(self, cve: str) -> list[str]:
        """Best-effort live CVE -> CWE lookup against the public NVD API.

        Failures (offline, rate-limited, unknown CVE) return an empty list so the
        caller transparently falls back to the seed table. Network access is the
        only optional dependency here; everything else is local.
        """
        if cve in self._nvd_cache:
            return self._nvd_cache[cve]

        cwes: list[str] = []
        try:  # urllib keeps this dependency-free.
            import urllib.request

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            req = urllib.request.Request(url, headers={"User-Agent": "tenable-attack-mapper"})
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                payload = json.load(resp)
            for vuln in payload.get("vulnerabilities", []):
                for weakness in vuln.get("cve", {}).get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        value = desc.get("value", "")
                        if value.upper().startswith("CWE-"):
                            cwes.append(value.upper())
        except Exception:  # pragma: no cover - network/parse best effort
            cwes = []

        deduped = list(dict.fromkeys(cwes))
        self._nvd_cache[cve] = deduped
        return deduped


def _load_table(path: Path) -> dict[str, list[str]]:
    """Load a reference JSON table, ignoring ``_comment`` metadata keys."""
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    return {
        key: list(value)
        for key, value in raw.items()
        if not key.startswith("_") and isinstance(value, list)
    }


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
