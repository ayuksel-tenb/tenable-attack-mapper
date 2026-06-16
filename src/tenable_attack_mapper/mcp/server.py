"""FastMCP server exposing the core mapping functions as callable tools.

This is intentionally thin: every tool delegates to the same runtime-agnostic
functions the CLI uses (:mod:`tenable_attack_mapper.pipeline`). It adds no logic
of its own beyond connecting Security Center scope arguments to the pipeline and
caching the last run so follow-up questions ("which findings match T1190?") are
cheap.

Run it with::

    python -m tenable_attack_mapper.mcp.server

or via the plugin manifest in ``.claude-plugin/plugin.json``.
"""

from __future__ import annotations

from typing import Any

from ..config import Config, load_config
from ..pipeline import (
    MapResult,
    findings_for_techniques,
    load_technique_catalog,
    run,
)

try:
    from fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "fastmcp is required for the MCP server. Install it with:\n"
        "    pip install 'tenable-attack-mapper[mcp]'"
    ) from exc

mcp = FastMCP("tenable-attack-mapper")

# Cache the most recent run per scope so reverse-lookup tools don't re-pull
# Security Center on every follow-up question within a session.
_last_runs: dict[tuple[str, str], MapResult] = {}


def _config(no_semantic: bool) -> Config:
    config = load_config()
    if no_semantic:
        config.enable_semantic = False
    return config


def _scoped_run(
    repository_id: str | None,
    query_id: str | None,
    severities: list[str] | None,
    no_semantic: bool,
) -> MapResult:
    from ..sc_client import DEFAULT_SEVERITIES

    key = (str(repository_id), str(query_id))
    config = _config(no_semantic)
    result = run(
        config,
        repository_id=repository_id,
        query_id=query_id,
        # Default to actionable severities (exclude Info) unless caller overrides.
        severities=severities if severities is not None else list(DEFAULT_SEVERITIES),
    )
    _last_runs[key] = result
    return result


@mcp.tool()
def map_environment(
    repository_id: str | None = None,
    query_id: str | None = None,
    severities: list[str] | None = None,
    no_semantic: bool = False,
) -> dict[str, Any]:
    """Pull open findings from Security Center and map them to ATT&CK.

    Returns the coverage summary and per-technique scores (ranked by aggregated
    VPR). Scope to a single repository or saved query, or leave both unset to map
    everything. Set ``no_semantic`` to use the deterministic chain only.
    """
    result = _scoped_run(repository_id, query_id, severities, no_semantic)
    return {
        "summary": result.summary,
        "scores": [s.to_dict() for s in result.scores],
        "warnings": result.warnings,
    }


@mcp.tool()
def export_navigator_layer(
    out_path: str = "layer.json",
    repository_id: str | None = None,
    query_id: str | None = None,
    severities: list[str] | None = None,
    no_semantic: bool = False,
) -> dict[str, Any]:
    """Map the environment and write a MITRE ATT&CK Navigator layer (v4.5) to disk."""
    from ..navigator import write_layer

    result = _scoped_run(repository_id, query_id, severities, no_semantic)
    path = write_layer(result.layer, out_path)
    return {"path": str(path), "technique_count": len(result.scores)}


@mcp.tool()
def techniques_for_tactic(tactic: str) -> dict[str, Any]:
    """List the ATT&CK techniques (from the local catalog) under a given tactic.

    Useful as an entry-point question: "for initial-access, which techniques
    should I look at?" Tactic names use ATT&CK slug form, e.g. ``initial-access``,
    ``execution``, ``privilege-escalation``.
    """
    tactic = tactic.strip().lower().replace(" ", "-")
    catalog = load_technique_catalog(load_config(require_sc=False))
    techniques = [
        {"technique_id": tid, "name": meta.get("name", "")}
        for tid, meta in catalog.items()
        if tactic in [t.lower() for t in meta.get("tactics", [])]
    ]
    return {"tactic": tactic, "techniques": techniques}


@mcp.tool()
def my_findings_for_techniques(
    technique_ids: list[str],
    repository_id: str | None = None,
    query_id: str | None = None,
    no_semantic: bool = False,
) -> dict[str, Any]:
    """Which of my findings map to the given ATT&CK technique IDs?

    Reuses the last cached run for the same scope when available; otherwise pulls
    and maps the environment first. Base-technique IDs (``T1190``) also match
    their sub-techniques.
    """
    key = (str(repository_id), str(query_id))
    result = _last_runs.get(key)
    if result is None:
        result = _scoped_run(repository_id, query_id, None, no_semantic)

    matches = findings_for_techniques(result.mappings, technique_ids)
    by_plugin = {f.plugin_id: f for f in result.findings}
    enriched = {
        technique: [
            {
                "plugin_id": pid,
                "plugin_name": by_plugin[pid].plugin_name if pid in by_plugin else "",
                "vpr_score": by_plugin[pid].vpr_score if pid in by_plugin else None,
            }
            for pid in plugin_ids
        ]
        for technique, plugin_ids in matches.items()
    }
    return {"matches": enriched}


def main() -> None:  # pragma: no cover
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
