"""Merge, de-duplicate, score, and flag ATT&CK mappings.

Two responsibilities:

1. :func:`reconcile` — combine the deterministic and semantic mapping sets,
   de-duplicate per (finding, technique) preferring the deterministic source,
   and flag any mapping below the confidence threshold as ``needs-review``.
2. :func:`score_techniques` — aggregate the kept mappings into per-technique
   scores weighted by VPR and finding count, normalized to 0-100 for the
   Navigator layer intensity.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..models import Finding, TechniqueMapping, TechniqueScore

# VPR used when a finding has no VPR score, so untriaged findings still count.
DEFAULT_VPR = 5.0


def reconcile(
    deterministic: Iterable[TechniqueMapping],
    semantic: Iterable[TechniqueMapping],
    *,
    confidence_threshold: float,
) -> list[TechniqueMapping]:
    """Combine both layers into one de-duplicated, flagged mapping list.

    Deterministic mappings win on conflict: if both layers link the same finding
    to the same technique, the semantic duplicate is dropped (its rationale is
    folded into the deterministic mapping's evidence for transparency).
    """
    merged: dict[tuple[str, str], TechniqueMapping] = {}

    # Deterministic first so it owns each (plugin, technique) key.
    for mapping in deterministic:
        merged[(mapping.plugin_id, mapping.technique_id)] = mapping

    for mapping in semantic:
        key = (mapping.plugin_id, mapping.technique_id)
        existing = merged.get(key)
        if existing is None:
            merged[key] = mapping
        elif existing.source == "deterministic" and mapping.evidence:
            note = f"semantic-agrees: {mapping.evidence}"
            if note not in existing.evidence:
                existing.evidence = (existing.evidence + f" | {note}").strip(" |")

    for mapping in merged.values():
        mapping.needs_review = mapping.confidence < confidence_threshold

    return list(merged.values())


def score_techniques(
    mappings: Iterable[TechniqueMapping],
    findings_by_plugin: dict[str, Finding],
    *,
    confidence_threshold: float,
) -> list[TechniqueScore]:
    """Aggregate mappings into per-technique scores (intensity 0-100).

    Weighting: each contributing finding adds ``effective_vpr * confidence`` to
    the technique's raw weight, where ``effective_vpr`` falls back to
    :data:`DEFAULT_VPR`. The host ``count`` amplifies prevalence. Raw weights are
    then normalized so the highest-exposure technique scores 100.
    """
    acc: dict[str, _Accumulator] = {}

    for mapping in mappings:
        finding = findings_by_plugin.get(mapping.plugin_id)
        vpr = (finding.vpr_score if finding else None) or DEFAULT_VPR
        count = finding.count if finding else 1

        bucket = acc.setdefault(mapping.technique_id, _Accumulator(mapping.technique_id))
        bucket.add(mapping, vpr=vpr, count=count)

    raw_scores = {tech: bucket.raw for tech, bucket in acc.items()}
    max_raw = max(raw_scores.values(), default=0.0)

    results: list[TechniqueScore] = []
    for tech, bucket in acc.items():
        normalized = (bucket.raw / max_raw * 100.0) if max_raw > 0 else 0.0
        results.append(
            TechniqueScore(
                technique_id=tech,
                score=round(normalized, 2),
                finding_count=len(bucket.plugin_ids),
                total_vpr=bucket.total_vpr,
                max_confidence=bucket.max_confidence,
                sources=sorted(bucket.sources),
                plugin_ids=sorted(bucket.plugin_ids),
                needs_review=bucket.max_confidence < confidence_threshold,
            )
        )

    results.sort(key=lambda s: s.score, reverse=True)
    return results


class _Accumulator:
    """Mutable per-technique aggregation helper."""

    __slots__ = ("technique_id", "raw", "total_vpr", "max_confidence", "sources", "plugin_ids")

    def __init__(self, technique_id: str):
        self.technique_id = technique_id
        self.raw = 0.0
        self.total_vpr = 0.0
        self.max_confidence = 0.0
        self.sources: set[str] = set()
        self.plugin_ids: set[str] = set()

    def add(self, mapping: TechniqueMapping, *, vpr: float, count: int) -> None:
        weight = vpr * mapping.confidence * max(count, 1)
        self.raw += weight
        # Count a finding's VPR once per technique even if it has multiple trails.
        if mapping.plugin_id not in self.plugin_ids:
            self.total_vpr += vpr
        self.max_confidence = max(self.max_confidence, mapping.confidence)
        self.sources.add(mapping.source)
        self.plugin_ids.add(mapping.plugin_id)
