"""Coverage summary report (Markdown + machine-readable dict).

Complements the Navigator layer with a human-readable rollup: how many findings
mapped, deterministic vs semantic split, top techniques by exposure, and the
``needs-review`` queue an analyst should audit first.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .models import Finding, TechniqueMapping, TechniqueScore


def build_summary(
    findings: Sequence[Finding],
    mappings: Sequence[TechniqueMapping],
    scores: Sequence[TechniqueScore],
) -> dict:
    """Compute coverage metrics as a plain dict."""
    mapped_plugins = {m.plugin_id for m in mappings}
    deterministic = [m for m in mappings if m.source == "deterministic"]
    semantic = [m for m in mappings if m.source == "semantic"]
    needs_review = [s for s in scores if s.needs_review]
    unmapped = [f for f in findings if f.plugin_id not in mapped_plugins]

    return {
        "findings_total": len(findings),
        "findings_mapped": len(mapped_plugins),
        "findings_unmapped": len(unmapped),
        "mappings_total": len(mappings),
        "mappings_deterministic": len(deterministic),
        "mappings_semantic": len(semantic),
        "techniques_total": len(scores),
        "techniques_needs_review": len(needs_review),
        "unmapped_plugins": [f.plugin_id for f in unmapped],
    }


def render_markdown(
    summary: Mapping,
    scores: Sequence[TechniqueScore],
    *,
    technique_catalog: Mapping[str, dict] | None = None,
    top_n: int = 15,
) -> str:
    """Render a Markdown coverage report from a summary and ranked scores."""
    catalog = technique_catalog or {}
    lines: list[str] = ["# ATT&CK Coverage Summary", ""]

    lines += [
        f"- **Findings:** {summary['findings_mapped']} mapped / "
        f"{summary['findings_total']} total "
        f"({summary['findings_unmapped']} unmapped)",
        f"- **Mappings:** {summary['mappings_total']} "
        f"({summary['mappings_deterministic']} deterministic, "
        f"{summary['mappings_semantic']} semantic)",
        f"- **Techniques:** {summary['techniques_total']} "
        f"({summary['techniques_needs_review']} need review)",
        "",
        f"## Top {min(top_n, len(scores))} techniques by exposure",
        "",
        "| Rank | Technique | Name | Score | Findings | VPR | Conf | Sources | Review |",
        "|-----:|-----------|------|------:|---------:|----:|-----:|---------|:------:|",
    ]

    for i, score in enumerate(scores[:top_n], start=1):
        name = catalog.get(score.technique_id, {}).get("name", "")
        review = "⚠️" if score.needs_review else ""
        lines.append(
            f"| {i} | {score.technique_id} | {name} | {score.score:.1f} | "
            f"{score.finding_count} | {score.total_vpr:.1f} | "
            f"{score.max_confidence:.2f} | {', '.join(score.sources)} | {review} |"
        )

    review_queue = [s for s in scores if s.needs_review]
    if review_queue:
        lines += ["", "## Needs review (low-confidence mappings)", ""]
        for score in review_queue:
            name = catalog.get(score.technique_id, {}).get("name", "")
            lines.append(
                f"- `{score.technique_id}` {name} — "
                f"confidence {score.max_confidence:.2f}, "
                f"plugins: {', '.join(score.plugin_ids)}"
            )

    return "\n".join(lines) + "\n"
