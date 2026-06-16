"""Semantic ATT&CK mapping via a hosted LLM API.

The documented, auditable fallback for findings the deterministic chain can't
reach (no CVE, or a gap in the CWE/CAPEC/ATT&CK tables). The model reads the
plugin name + description and proposes ATT&CK techniques, each with a
``confidence`` and ``reason_code`` so a human can audit each link. One call per
finding, run concurrently; results are cached per plugin id so re-runs are free.

Two providers (``TASC_SEMANTIC_BACKEND``):
- ``anthropic`` (default) — the Anthropic API (``ANTHROPIC_API_KEY``).
- ``gemini`` — the Google Gemini API (``GEMINI_API_KEY``).

The deterministic layer is always primary; reconciliation drops a semantic
mapping whenever a deterministic mapping exists for the same finding+technique.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

from ..models import Finding, TechniqueMapping

# Structured-output JSON schema (Anthropic). Numerical bounds validated client-side.
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
                    "technique_id": {"type": "string"},
                    "confidence": {"type": "number"},
                    "reason_code": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["technique_id", "confidence", "reason_code", "rationale"],
            },
        }
    },
    "required": ["mappings"],
}

_SYSTEM = (
    "You are a threat-informed vulnerability analyst. Map each Tenable "
    "vulnerability finding to the MITRE ATT&CK (enterprise) techniques an "
    "adversary would use to exploit it. Only propose techniques you can justify "
    "from the plugin name, description, or CVE context. Prefer specific "
    "sub-techniques when warranted. Never invent technique IDs; if unsure, return "
    "fewer mappings with lower confidence."
)

# JSON shape appended to the per-finding prompt (used by the Gemini backend).
_JSON_SHAPE = (
    '\n\nReturn a JSON object: {"mappings": [{"technique_id": "T....", '
    '"confidence": 0.0-1.0, "reason_code": "short", "rationale": "one sentence"}]}. '
    "Use only real MITRE ATT&CK enterprise technique IDs."
)

# Technique-ID format guard so we never emit obviously malformed IDs.
_TECH_PREFIX = "T"


class _ApiMapper:
    """Shared per-finding cache + concurrent map_many for hosted-API providers."""

    provider = "API"

    def _init_cache(self, cache_path, max_techniques):
        self._max = max_techniques
        self._cache_path = Path(cache_path) if cache_path else None
        self._cache: dict[str, list[dict]] = _load_cache(self._cache_path)
        self._lock = threading.Lock()

    def _cached(self, plugin_id):
        with self._lock:
            return self._cache.get(plugin_id)

    def _store(self, plugin_id, mappings):
        with self._lock:
            self._cache[plugin_id] = [m.to_dict() for m in mappings]

    def map_many(self, findings, *, workers: int = 8):
        """Map many findings concurrently. Returns ``(mappings, errors)``."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        out: list[TechniqueMapping] = []
        errors: list[str] = []
        if not findings:
            return out, errors
        print(
            f"semantic: mapping {len(findings)} finding(s) via {self.provider}, "
            f"{workers} parallel…",
            file=sys.stderr,
            flush=True,
        )
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(findings)))) as pool:
            futures = {pool.submit(self.map_finding, f): f for f in findings}
            for future in as_completed(futures):
                done += 1
                finding = futures[future]
                try:
                    out.extend(future.result())
                except SemanticMappingError as exc:
                    errors.append(f"{finding.plugin_id}: {exc}")
                if done % 50 == 0 or done == len(findings):
                    print(f"semantic: {done}/{len(findings)} done", file=sys.stderr, flush=True)
        return out, errors

    def save_cache(self) -> None:
        _persist_cache(self._cache_path, self._cache, self._lock)


class SemanticMapper(_ApiMapper):
    """Anthropic API backend: one structured-output call per finding."""

    provider = "Anthropic API"

    def __init__(self, *, api_key: str, model: str, effort: str = "low",
                 max_techniques: int = 5, cache_path: str | Path | None = None):
        from anthropic import Anthropic

        self._client = Anthropic(api_key=api_key)
        self._model = model
        self._effort = effort
        self._init_cache(cache_path, max_techniques)

    def map_finding(self, finding: Finding) -> list[TechniqueMapping]:
        cached = self._cached(finding.plugin_id)
        if cached is not None:
            return [_mapping_from_cache(finding.plugin_id, item) for item in cached]
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=2000,
                system=_SYSTEM,
                messages=[{"role": "user", "content": _finding_prompt(finding, self._max)}],
                **self._model_params(),
            )
        except Exception as exc:  # pragma: no cover - network/runtime guard
            raise SemanticMappingError(str(exc)) from exc
        data = _extract_json(response)
        mappings = _items_to_mappings(finding.plugin_id, data.get("mappings", []), self._max)
        self._store(finding.plugin_id, mappings)
        return mappings

    def _model_params(self) -> dict:
        """Adaptive thinking + effort only for models that support them (Haiku 4.5
        and Sonnet 4.5 reject both, so they get structured-output format only)."""
        fmt = {"format": {"type": "json_schema", "schema": _OUTPUT_SCHEMA}}
        model = self._model.lower()
        if "haiku" in model or "sonnet-4-5" in model:
            return {"output_config": fmt}
        return {"thinking": {"type": "adaptive"}, "output_config": {"effort": self._effort, **fmt}}


class GeminiSemanticMapper(_ApiMapper):
    """Google Gemini API backend: one JSON call per finding."""

    provider = "Gemini API"

    def __init__(self, *, api_key: str, model: str,
                 max_techniques: int = 5, cache_path: str | Path | None = None):
        from google import genai

        self._genai = genai
        self._client = genai.Client(api_key=api_key)
        self._model = model
        self._init_cache(cache_path, max_techniques)

    def map_finding(self, finding: Finding) -> list[TechniqueMapping]:
        cached = self._cached(finding.plugin_id)
        if cached is not None:
            return [_mapping_from_cache(finding.plugin_id, item) for item in cached]
        from google.genai import types

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=_finding_prompt(finding, self._max) + _JSON_SHAPE,
                config=types.GenerateContentConfig(
                    system_instruction=_SYSTEM,
                    response_mime_type="application/json",
                ),
            )
        except Exception as exc:  # pragma: no cover - network/runtime guard
            raise SemanticMappingError(str(exc)) from exc
        try:
            data = json.loads(response.text or "{}")
        except json.JSONDecodeError:
            data = {}
        mappings = _items_to_mappings(finding.plugin_id, data.get("mappings", []), self._max)
        self._store(finding.plugin_id, mappings)
        return mappings


def build_semantic_mapper(config, cache_path) -> _ApiMapper:
    """Build the semantic mapper for the configured provider."""
    if config.semantic_backend == "gemini":
        return GeminiSemanticMapper(
            api_key=config.gemini_api_key, model=config.gemini_model, cache_path=cache_path
        )
    return SemanticMapper(
        api_key=config.anthropic_api_key, model=config.model, cache_path=cache_path
    )


class SemanticMappingError(RuntimeError):
    """Raised when the semantic layer fails for a finding."""


# --- shared helpers -------------------------------------------------------

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


def _items_to_mappings(plugin_id, items, max_techniques) -> list[TechniqueMapping]:
    out: dict[str, TechniqueMapping] = {}
    for item in (items or [])[:max_techniques]:
        technique = str(item.get("technique_id", "")).strip().upper()
        if not technique.startswith(_TECH_PREFIX) or len(technique) < 4 or technique in out:
            continue
        reason_code = str(item.get("reason_code") or "semantic").strip()
        out[technique] = TechniqueMapping(
            plugin_id=plugin_id,
            technique_id=technique,
            source="semantic",
            confidence=_clamp(item.get("confidence", 0.0)),
            reason_code=f"semantic:{reason_code}",
            evidence=str(item.get("rationale") or "").strip(),
        )
    return list(out.values())


def _persist_cache(path: Path | None, cache: dict, lock: threading.Lock) -> None:
    if not path:
        return
    with lock:
        snapshot = dict(cache)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
    except OSError:  # pragma: no cover - best effort
        pass


def _finding_prompt(finding: Finding, max_techniques: int) -> str:
    cves = ", ".join(finding.cves) if finding.cves else "none"
    desc = finding.description[:4000] if finding.description else "(no description)"
    return (
        f"Plugin ID: {finding.plugin_id}\nPlugin name: {finding.plugin_name}\n"
        f"CVEs: {cves}\nSeverity: {finding.severity or 'unknown'}\n\n"
        f"Description:\n{desc}\n\nReturn up to {max_techniques} ATT&CK techniques."
    )


def _extract_json(response) -> dict:
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
