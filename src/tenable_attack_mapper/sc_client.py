"""Tenable Security Center (Tenable.sc) access layer.

Thin wrapper over pyTenable's :class:`TenableSC`. Pulls open vulnerability
findings — plugin id/name, description, CVEs and VPR — optionally scoped to a
repository or an asset query, and returns them as :class:`Finding` objects.

Reference (from the pyTenable docs)::

    from tenable.sc import TenableSC
    sc = TenableSC(url='https://SC_URL', access_key='AKEY', secret_key='SKEY')
    for vuln in sc.analysis.vulns():
        print('{ip}:{pluginID}:{pluginName}'.format(**vuln))
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .config import Config
from .models import Finding

# Default severity scope: the actionable vulnerabilities. "Info" findings (scan
# info, port scans, asset inventory) are excluded by default — they aren't
# exploitation-relevant and would inflate the universe. Matches Security Center's
# default Vulnerability Summary view.
DEFAULT_SEVERITIES = ("Critical", "High", "Medium", "Low")

# Fields requested from the analysis endpoint. Keep this minimal — we only need
# what feeds the mapping pipeline.
_VULN_FIELDS = (
    "pluginID",
    "pluginName",
    "severity",
    "vprScore",
    "cve",
    "description",
)


class SecurityCenterClient:
    """Connects to Tenable.sc and yields open findings."""

    def __init__(self, config: Config):
        self._config = config
        self._sc = None  # lazily connected

    def connect(self):
        """Open the underlying pyTenable session (idempotent)."""
        if self._sc is not None:
            return self._sc

        from tenable.sc import TenableSC  # imported lazily so unit tests stay light

        self._sc = TenableSC(
            url=self._config.sc_url,
            access_key=self._config.sc_access_key,
            secret_key=self._config.sc_secret_key,
            vendor="ayuksel-tenb",
            product="tenable-attack-mapper",
        )
        return self._sc

    def iter_findings(
        self,
        *,
        repository_id: int | str | None = None,
        query_id: int | str | None = None,
        severities: Iterable[str] | None = None,
    ) -> Iterator[Finding]:
        """Stream open findings, optionally filtered.

        :param repository_id: restrict to a single Security Center repository.
        :param query_id: use a saved Security Center analysis query instead.
        :param severities: severity names to keep (e.g. ``("High", "Critical")``).
            ``None`` keeps everything the query returns.
        """
        sc = self.connect()
        filters = []
        if repository_id is not None:
            filters.append(("repositoryIDs", "=", str(repository_id)))

        kwargs: dict = {"tool": "vulndetails", "fields": list(_VULN_FIELDS)}
        if query_id is not None:
            kwargs["query_id"] = int(query_id)
        if filters:
            kwargs["filters"] = filters

        wanted = {s.lower() for s in severities} if severities else None

        for raw in sc.analysis.vulns(**kwargs):
            finding = _finding_from_raw(raw)
            if wanted is not None and finding.severity.lower() not in wanted:
                continue
            yield finding

    def fetch_findings(self, **kwargs) -> list[Finding]:
        """Eager variant of :meth:`iter_findings`, de-duplicated by plugin id.

        Security Center returns one row per (host, plugin); we collapse to one
        :class:`Finding` per plugin and accumulate the host count so the
        reconcile step can weight by prevalence.
        """
        merged: dict[str, Finding] = {}
        for finding in self.iter_findings(**kwargs):
            existing = merged.get(finding.plugin_id)
            if existing is None:
                merged[finding.plugin_id] = finding
            else:
                existing.count += finding.count
                if finding.vpr_score is not None:
                    existing.vpr_score = max(
                        existing.vpr_score or 0.0, finding.vpr_score
                    )
        return list(merged.values())


def _finding_from_raw(raw: dict) -> Finding:
    """Normalize one Security Center analysis row into a :class:`Finding`."""
    cve_field = (raw.get("cve") or "").strip()
    cves = [c.strip() for c in cve_field.split(",") if c.strip()] if cve_field else []

    vpr_raw = raw.get("vprScore")
    try:
        vpr = float(vpr_raw) if vpr_raw not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        vpr = None

    return Finding(
        plugin_id=str(raw.get("pluginID", "")).strip(),
        plugin_name=(raw.get("pluginName") or "").strip(),
        severity=_severity_name(raw.get("severity")),
        vpr_score=vpr,
        cves=cves,
        description=(raw.get("description") or "").strip(),
        count=1,
    )


def _severity_name(severity) -> str:
    """Security Center returns severity as a dict ``{"name": "High", ...}``."""
    if isinstance(severity, dict):
        return str(severity.get("name", "")).strip()
    return str(severity or "").strip()
