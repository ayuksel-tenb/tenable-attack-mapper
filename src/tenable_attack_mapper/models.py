"""Core data structures shared across the pipeline.

These are plain dataclasses with ``to_dict`` helpers so the whole pipeline can be
serialized to JSON without any framework coupling.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Finding:
    """A single open vulnerability finding pulled from Security Center."""

    plugin_id: str
    plugin_name: str
    severity: str = ""
    vpr_score: float | None = None
    cves: list[str] = field(default_factory=list)
    description: str = ""
    # How many hosts/instances this finding was observed on (drives weighting).
    count: int = 1

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "severity": self.severity,
            "vpr_score": self.vpr_score,
            "cves": list(self.cves),
            "description": self.description,
            "count": self.count,
        }


@dataclass(slots=True)
class TechniqueMapping:
    """One finding -> one ATT&CK technique link, with provenance.

    Every mapping — deterministic or semantic — carries a ``confidence`` float in
    [0, 1] and a ``reason_code`` so an analyst can audit exactly why the link
    exists. ``source`` is ``"deterministic"`` or ``"semantic"``.
    """

    plugin_id: str
    technique_id: str
    source: str
    confidence: float
    reason_code: str
    # Optional human-readable trail, e.g. "CVE-2021-44228 -> CWE-917 -> CAPEC-242 -> T1190".
    evidence: str = ""
    needs_review: bool = False

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "technique_id": self.technique_id,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "reason_code": self.reason_code,
            "evidence": self.evidence,
            "needs_review": self.needs_review,
        }


@dataclass(slots=True)
class TechniqueScore:
    """Aggregated, per-technique score used for the Navigator layer intensity."""

    technique_id: str
    score: float
    finding_count: int
    total_vpr: float
    max_confidence: float
    sources: list[str] = field(default_factory=list)
    plugin_ids: list[str] = field(default_factory=list)
    needs_review: bool = False

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "score": round(self.score, 3),
            "finding_count": self.finding_count,
            "total_vpr": round(self.total_vpr, 2),
            "max_confidence": round(self.max_confidence, 3),
            "sources": list(self.sources),
            "plugin_ids": list(self.plugin_ids),
            "needs_review": self.needs_review,
        }
