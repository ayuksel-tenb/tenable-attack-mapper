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

# Confidence for the full CVE->CWE->CAPEC->ATT&CK taxonomy chain. High but not
# 1.0: taxonomy mappings are authoritative yet still a generalization.
CHAIN_CONFIDENCE = 0.95
# Confidence for the direct CVE->CWE->ATT&CK bridge. A notch lower because the
# CWE->technique link is a weakness-class generalization, not a per-pattern
# taxonomy mapping — still well above the review threshold, still deterministic.
BRIDGE_CONFIDENCE = 0.8


class DeterministicMapper:
    """Resolves findings to techniques via the CVE/CWE/(CAPEC)/ATT&CK chains.

    Two deterministic paths run per CWE:
      * the authoritative ``CVE -> CWE -> CAPEC -> ATT&CK`` taxonomy chain, and
      * a denser direct ``CVE -> CWE -> ATT&CK`` bridge for the common weakness
        classes the CAPEC chain doesn't reach.
    The higher-confidence path wins per technique; both trails are recorded.
    """

    def __init__(self, data_dir: Path, *, use_nvd: bool | None = None):
        self._cve_cwe = _load_table(data_dir / "cve_cwe.json")
        self._cwe_capec = _load_table(data_dir / "cwe_capec.json")
        self._capec_attack = _load_table(data_dir / "capec_attack.json")
        self._cwe_attack = _load_table(data_dir / "cwe_attack.json")
        if use_nvd is None:
            use_nvd = _as_bool(os.getenv("TASC_USE_NVD"), default=False)
        self._use_nvd = use_nvd
        # Persistent CVE->CWE cache so a one-time NVD enrichment survives across
        # runs (NVD live lookups are rate-limited; this makes later runs instant).
        self._nvd_cache_path = Path(
            os.getenv("TASC_NVD_CACHE", str(data_dir / ".nvd_cache.json"))
        )
        self._nvd_cache: dict[str, list[str]] = _load_table(self._nvd_cache_path)

    def map_finding(self, finding: Finding) -> list[TechniqueMapping]:
        """Return deterministic mappings for one finding (possibly empty)."""
        mappings: dict[str, TechniqueMapping] = {}

        for cve in finding.cves:
            for cwe in self._cwes_for(cve):
                # Path A: full CAPEC taxonomy chain (highest confidence).
                for capec in self._cwe_capec.get(cwe, []):
                    for technique in self._capec_attack.get(capec, []):
                        self._record(
                            mappings, finding, technique,
                            confidence=CHAIN_CONFIDENCE,
                            reason_code="chain:cve-cwe-capec-attack",
                            evidence=f"{cve} -> {cwe} -> {capec} -> {technique}",
                        )
                # Path B: direct CWE -> ATT&CK bridge (denser coverage).
                for technique in self._cwe_attack.get(cwe, []):
                    self._record(
                        mappings, finding, technique,
                        confidence=BRIDGE_CONFIDENCE,
                        reason_code="chain:cve-cwe-attack",
                        evidence=f"{cve} -> {cwe} -> {technique}",
                    )

        return list(mappings.values())

    @staticmethod
    def _record(mappings, finding, technique, *, confidence, reason_code, evidence):
        """Insert/merge one technique mapping, keeping the highest confidence."""
        existing = mappings.get(technique)
        if existing is None:
            mappings[technique] = TechniqueMapping(
                plugin_id=finding.plugin_id,
                technique_id=technique,
                source="deterministic",
                confidence=confidence,
                reason_code=reason_code,
                evidence=evidence,
            )
            return
        if evidence not in existing.evidence:
            existing.evidence += f"; {evidence}"
        if confidence > existing.confidence:
            existing.confidence = confidence
            existing.reason_code = reason_code

    def _cwes_for(self, cve: str) -> list[str]:
        """Resolve a CVE to CWEs: offline seed + persistent cache, then (optionally)
        a live NVD lookup only for genuine misses."""
        cve = cve.strip().upper()
        cwes: list[str] = list(self._cve_cwe.get(cve, []))
        for c in self._nvd_cache.get(cve, []):
            if c not in cwes:
                cwes.append(c)
        if not cwes and self._use_nvd:
            cwes = self._nvd_lookup(cve)
        return cwes

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

            headers = {"User-Agent": "tenable-attack-mapper"}
            api_key = os.getenv("NVD_API_KEY")
            if api_key:
                headers["apiKey"] = api_key
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            req = urllib.request.Request(url, headers=headers)
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

    def save_cache(self) -> None:
        """Persist the CVE->CWE cache so future runs skip the NVD round-trips."""
        if not self._nvd_cache:
            return
        try:
            self._nvd_cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._nvd_cache_path.open("w", encoding="utf-8") as fh:
                json.dump(self._nvd_cache, fh)
        except OSError:  # pragma: no cover - best effort
            pass


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
