"""Semantic ATT&CK mapping via the Anthropic API.

This is the documented, auditable *fallback* for findings where the deterministic
chain is incomplete (no CVE, or a gap in the CWE/CAPEC/ATT&CK tables). Claude
reads the plugin name and description and proposes candidate ATT&CK technique
IDs. Every proposed mapping is forced to carry a ``confidence`` float and a
``reason_code`` via a structured-output schema, so a human can audit each link
just like a deterministic one — the difference is provenance, not rigor.

The deterministic layer is always primary; reconciliation drops a semantic
mapping whenever a deterministic mapping exists for the same finding+technique.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..models import Finding, TechniqueMapping

# Structured-output schema. Numerical bounds on confidence are validated
# client-side (the API strips unsupported JSON-schema constraints).
_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "MITRE ATT&CK enterprise technique ID, e.g. T1190 or T1059.007.",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "How confident this technique applies, 0.0-1.0.",
                    },
                    "reason_code": {
                        "type": "string",
                        "description": "Short machine code for the rationale, e.g. plugin-name-keyword, description-behavior, cve-context.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "One sentence of human-readable justification.",
                    },
                },
                "required": ["technique_id", "confidence", "reason_code", "rationale"],
            },
        }
    },
    "required": ["mappings"],
}

_SYSTEM = (
    "You are a threat-informed vulnerability analyst. Map a single Tenable "
    "vulnerability finding to the MITRE ATT&CK (enterprise) techniques an "
    "adversary would use to exploit it. Only propose techniques you can justify "
    "from the plugin name, description, or CVE context. Prefer specific "
    "sub-techniques when warranted. Never invent technique IDs; if unsure, return "
    "fewer mappings with lower confidence. Every mapping must include an honest "
    "confidence in [0,1] and a concise reason_code."
)

# Technique-ID format guard so we never emit obviously malformed IDs.
_TECH_PREFIX = "T"


class SemanticMapper:
    """Wraps an Anthropic client to propose ATT&CK techniques per finding."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        effort: str = "low",
        max_techniques: int = 5,
        cache_path: str | Path | None = None,
    ):
        from anthropic import Anthropic

        self._client = Anthropic(api_key=api_key)
        self._model = model
        self._effort = effort
        self._max_techniques = max_techniques
        # Persistent per-plugin cache so re-runs (and incremental scans) don't
        # re-pay for plugins already mapped. Keyed by plugin id.
        self._cache_path = Path(cache_path) if cache_path else None
        self._cache: dict[str, list[dict]] = _load_cache(self._cache_path)
        self._lock = threading.Lock()

    def map_finding(self, finding: Finding) -> list[TechniqueMapping]:
        """Propose semantic mappings for one finding (possibly empty).

        Thread-safe and cached: safe to call concurrently across findings.
        """
        with self._lock:
            cached = self._cache.get(finding.plugin_id)
        if cached is not None:
            return [_mapping_from_cache(finding.plugin_id, item) for item in cached]

        prompt = self._build_prompt(finding)

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=2000,
                thinking={"type": "adaptive"},
                output_config={
                    "effort": self._effort,
                    "format": {"type": "json_schema", "schema": _OUTPUT_SCHEMA},
                },
                system=_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # pragma: no cover - network/runtime guard
            raise SemanticMappingError(str(exc)) from exc

        data = _extract_json(response)
        mappings = self._to_mappings(finding, data)
        with self._lock:
            self._cache[finding.plugin_id] = [m.to_dict() for m in mappings]
        return mappings

    def save_cache(self) -> None:
        """Persist the per-plugin semantic cache."""
        if not self._cache_path:
            return
        with self._lock:
            snapshot = dict(self._cache)
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open("w", encoding="utf-8") as fh:
                json.dump(snapshot, fh)
        except OSError:  # pragma: no cover - best effort
            pass

    def _build_prompt(self, finding: Finding) -> str:
        cves = ", ".join(finding.cves) if finding.cves else "none"
        desc = finding.description[:4000] if finding.description else "(no description)"
        return (
            f"Plugin ID: {finding.plugin_id}\n"
            f"Plugin name: {finding.plugin_name}\n"
            f"CVEs: {cves}\n"
            f"Severity: {finding.severity or 'unknown'}\n\n"
            f"Description:\n{desc}\n\n"
            f"Return up to {self._max_techniques} ATT&CK techniques."
        )

    def _to_mappings(self, finding: Finding, data: dict) -> list[TechniqueMapping]:
        out: dict[str, TechniqueMapping] = {}
        for item in data.get("mappings", [])[: self._max_techniques]:
            technique = str(item.get("technique_id", "")).strip().upper()
            if not technique.startswith(_TECH_PREFIX) or len(technique) < 4:
                continue  # skip malformed IDs
            confidence = _clamp(item.get("confidence", 0.0))
            reason_code = str(item.get("reason_code") or "semantic").strip()
            rationale = str(item.get("rationale") or "").strip()
            if technique in out:
                continue
            out[technique] = TechniqueMapping(
                plugin_id=finding.plugin_id,
                technique_id=technique,
                source="semantic",
                confidence=confidence,
                reason_code=f"semantic:{reason_code}",
                evidence=rationale,
            )
        return list(out.values())


class SemanticMappingError(RuntimeError):
    """Raised when the semantic layer fails for a finding."""


def _load_cache(path: Path | None) -> dict[str, list[dict]]:
    if not path or not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return {k: v for k, v in data.items() if isinstance(v, list)}
    except (OSError, json.JSONDecodeError):
        return {}


def _mapping_from_cache(plugin_id: str, item: dict) -> TechniqueMapping:
    return TechniqueMapping(
        plugin_id=plugin_id,
        technique_id=item["technique_id"],
        source="semantic",
        confidence=float(item.get("confidence", 0.0)),
        reason_code=item.get("reason_code", "semantic"),
        evidence=item.get("evidence", ""),
        needs_review=item.get("needs_review", False),
    )


def _extract_json(response) -> dict:
    """Pull the structured JSON object out of a Messages API response."""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            try:
                return json.loads(block.text)
            except (json.JSONDecodeError, AttributeError):
                continue
    return {"mappings": []}


def _clamp(value, low: float = 0.0, high: float = 1.0) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return 0.0
