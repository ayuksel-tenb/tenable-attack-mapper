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

    # Honest denominator: only CVE-bearing findings are in scope for exploitation
    # technique mapping. Compliance / scan-info findings (no CVE) are a separate,
    # legitimately-unmapped class — not a coverage failure.
    with_cve = [f for f in findings if f.cves]
    no_cve = [f for f in findings if not f.cves]
    mapped_with_cve = [f for f in with_cve if f.plugin_id in mapped_plugins]
    unmapped_with_cve = [f for f in with_cve if f.plugin_id not in mapped_plugins]
    cve_coverage = (
        round(100 * len(mapped_with_cve) / len(with_cve), 1) if with_cve else 0.0
    )

    return {
        "findings_total": len(findings),
        "findings_mapped": len(mapped_plugins),
        "findings_unmapped": len(unmapped),
        "findings_with_cve": len(with_cve),
        "findings_no_cve": len(no_cve),
        "findings_with_cve_mapped": len(mapped_with_cve),
        "cve_coverage_pct": cve_coverage,
        "mappings_total": len(mappings),
        "mappings_deterministic": len(deterministic),
        "mappings_semantic": len(semantic),
        "techniques_total": len(scores),
        "techniques_needs_review": len(needs_review),
        "unmapped_plugins": [f.plugin_id for f in unmapped],
        "unmapped_with_cve_plugins": [f.plugin_id for f in unmapped_with_cve],
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
        f"- **Findings:** {summary['findings_total']} total — "
        f"{summary.get('findings_with_cve', 0)} CVE-bearing (in scope), "
        f"{summary.get('findings_no_cve', 0)} compliance/scan-info (out of scope)",
        f"- **Exploitation coverage:** "
        f"{summary.get('findings_with_cve_mapped', 0)}/"
        f"{summary.get('findings_with_cve', 0)} CVE-bearing findings mapped "
        f"({summary.get('cve_coverage_pct', 0)}%)",
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
