"""End-to-end orchestration: pull -> map -> reconcile -> score -> export.

This module is the library entry point. It is deliberately runtime-agnostic: the
CLI, the MCP server, and any external caller all go through :func:`run` (which
talks to Security Center) or :func:`map_findings` (which works on findings you
already have, e.g. in tests or interactive Q&A).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .config import Config
from .mapping import DeterministicMapper, reconcile, score_techniques
from .mapping.semantic import SemanticMapper, SemanticMappingError
from .models import Finding, TechniqueMapping, TechniqueScore
from .navigator import build_layer, write_layer
from .report import build_summary, render_markdown


@dataclass(slots=True)
class MapResult:
    """Everything one run produces."""

    findings: list[Finding]
    mappings: list[TechniqueMapping]
    scores: list[TechniqueScore]
    layer: dict
    summary: dict
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "scores": [s.to_dict() for s in self.scores],
            "mappings": [m.to_dict() for m in self.mappings],
            "findings": [f.to_dict() for f in self.findings],
            "warnings": list(self.warnings),
        }


def load_technique_catalog(config: Config) -> dict[str, dict]:
    """Load the ATT&CK technique metadata table (names + tactics)."""
    return _load_catalog(config.data_dir)


@lru_cache(maxsize=8)
def _load_catalog(data_dir: Path) -> dict[str, dict]:
    path = data_dir / "attack_techniques.json"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def map_findings(
    config: Config,
    findings: Sequence[Finding],
    *,
    layer_name: str = "Tenable Exposure -> ATT&CK",
) -> MapResult:
    """Map an in-memory set of findings to a full :class:`MapResult`.

    The deterministic chain runs first for every finding. The semantic layer is
    only invoked for findings the deterministic chain could not map, and only
    when a Claude API key is configured — keeping the authoritative source
    primary and the LLM a documented fallback.
    """
    warnings: list[str] = []
    deterministic_mapper = DeterministicMapper(config.data_dir)
    semantic_mapper = _build_semantic_mapper(config) if config.semantic_available else None
    if config.enable_semantic and semantic_mapper is None:
        warnings.append(
            "Semantic fallback disabled (no ANTHROPIC_API_KEY); "
            "deterministic chain only."
        )

    det_mappings: list[TechniqueMapping] = []
    sem_mappings: list[TechniqueMapping] = []

    for finding in findings:
        det = deterministic_mapper.map_finding(finding)
        det_mappings.extend(det)
        if det or semantic_mapper is None:
            continue
        try:
            sem_mappings.extend(semantic_mapper.map_finding(finding))
        except SemanticMappingError as exc:
            warnings.append(f"Semantic mapping failed for {finding.plugin_id}: {exc}")

    mappings = reconcile(
        det_mappings, sem_mappings, confidence_threshold=config.confidence_threshold
    )
    findings_by_plugin = {f.plugin_id: f for f in findings}
    scores = score_techniques(
        mappings, findings_by_plugin, confidence_threshold=config.confidence_threshold
    )

    catalog = load_technique_catalog(config)
    layer = build_layer(scores, name=layer_name, technique_catalog=catalog)
    summary = build_summary(findings, mappings, scores)

    return MapResult(
        findings=list(findings),
        mappings=mappings,
        scores=scores,
        layer=layer,
        summary=summary,
        warnings=warnings,
    )


def run(
    config: Config,
    *,
    repository_id: int | str | None = None,
    query_id: int | str | None = None,
    severities: Sequence[str] | None = None,
    out_path: str | Path | None = None,
    report_path: str | Path | None = None,
) -> MapResult:
    """Pull findings from Security Center, map them, and optionally write outputs."""
    from .sc_client import SecurityCenterClient

    client = SecurityCenterClient(config)
    findings = client.fetch_findings(
        repository_id=repository_id, query_id=query_id, severities=severities
    )

    label = _layer_label(repository_id, query_id)
    result = map_findings(config, findings, layer_name=label)

    if out_path is not None:
        write_layer(result.layer, out_path)
    if report_path is not None:
        catalog = load_technique_catalog(config)
        markdown = render_markdown(result.summary, result.scores, technique_catalog=catalog)
        Path(report_path).write_text(markdown, encoding="utf-8")

    return result


def findings_for_techniques(
    mappings: Sequence[TechniqueMapping], technique_ids: Sequence[str]
) -> dict[str, list[str]]:
    """Reverse lookup: which findings map to each requested technique.

    Matching is technique-aware: requesting a base technique (``T1190``) also
    returns findings mapped to its sub-techniques (``T1190.001``).
    """
    wanted = {t.strip().upper() for t in technique_ids}
    result: dict[str, set[str]] = {t: set() for t in wanted}
    for mapping in mappings:
        tech = mapping.technique_id.upper()
        base = tech.split(".", 1)[0]
        for w in wanted:
            if tech == w or base == w:
                result[w].add(mapping.plugin_id)
    return {k: sorted(v) for k, v in result.items()}


def _build_semantic_mapper(config: Config) -> SemanticMapper:
    return SemanticMapper(api_key=config.anthropic_api_key, model=config.model)


def _layer_label(repository_id, query_id) -> str:
    if repository_id is not None:
        return f"Tenable Exposure (repo {repository_id}) -> ATT&CK"
    if query_id is not None:
        return f"Tenable Exposure (query {query_id}) -> ATT&CK"
    return "Tenable Exposure -> ATT&CK"
