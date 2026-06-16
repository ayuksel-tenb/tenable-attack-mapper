"""Semantic ATT&CK mapping via the local ``claude`` CLI.

The documented, auditable fallback for findings the deterministic chain can't
reach (no CVE, or a gap in the CWE/CAPEC/ATT&CK tables). Inference runs through
``claude -p``, so it's billed to your **Claude Code subscription** — no API key,
no per-token cost. Findings are batched (one CLI call per batch) to amortize
process startup, and results are cached per plugin id. Every proposed mapping
carries a ``confidence`` and a ``reason_code`` so a human can audit each link.

The deterministic layer is always primary; reconciliation drops a semantic
mapping whenever a deterministic mapping exists for the same finding+technique.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..models import Finding, TechniqueMapping

_SYSTEM = (
    "You are a threat-informed vulnerability analyst. Map each Tenable "
    "vulnerability finding to the MITRE ATT&CK (enterprise) techniques an "
    "adversary would use to exploit it. Only propose techniques you can justify "
    "from the plugin name, description, or CVE context. Prefer specific "
    "sub-techniques when warranted. Never invent technique IDs; if unsure, return "
    "fewer mappings with lower confidence."
)

# Technique-ID format guard so we never emit obviously malformed IDs.
_TECH_PREFIX = "T"


class ClaudeCliSemanticMapper:
    """Semantic mapping via the local ``claude`` CLI (Claude Code subscription).

    Findings are batched (one ``claude -p`` call per batch) and cached per plugin
    id, so re-runs and incremental scans don't re-pay for plugins already mapped.
    """

    def __init__(
        self,
        *,
        model: str = "claude-haiku-4-5",
        cache_path: str | Path | None = None,
        batch_size: int = 25,
        max_techniques: int = 5,
    ):
        self._model = model
        self._cache_path = Path(cache_path) if cache_path else None
        self._cache: dict[str, list[dict]] = _load_cache(self._cache_path)
        self._lock = threading.Lock()
        self._batch_size = batch_size
        self._max = max_techniques

    def map_many(self, findings, *, workers: int = 4):
        """Map many findings, batched and concurrent.

        Returns ``(mappings, errors)`` where errors are human-readable strings.
        """
        out: list[TechniqueMapping] = []
        errors: list[str] = []
        pending = []
        for f in findings:
            with self._lock:
                cached = self._cache.get(f.plugin_id)
            if cached is not None:
                out.extend(_mapping_from_cache(f.plugin_id, item) for item in cached)
            else:
                pending.append(f)

        if not pending:
            return out, errors

        from concurrent.futures import ThreadPoolExecutor, as_completed

        batches = [
            pending[i : i + self._batch_size]
            for i in range(0, len(pending), self._batch_size)
        ]
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(batches)))) as pool:
            futures = {pool.submit(self._map_batch, b): b for b in batches}
            for future in as_completed(futures):
                try:
                    out.extend(future.result())
                except Exception as exc:  # noqa: BLE001 - record and continue
                    errors.append(f"claude batch: {exc}")
        return out, errors

    def _map_batch(self, batch) -> list[TechniqueMapping]:
        text = self._run_claude(_claude_prompt(batch, self._max))
        data = _extract_json_array(text)
        by_id = {f.plugin_id: f for f in batch}
        result: list[TechniqueMapping] = []
        for item in data:
            pid = str(item.get("plugin_id", "")).strip()
            if pid not in by_id:
                continue
            mappings = _items_to_mappings(pid, item.get("mappings", []), self._max)
            result.extend(mappings)
            with self._lock:
                self._cache[pid] = [m.to_dict() for m in mappings]
        return result

    def _run_claude(self, prompt: str) -> str:
        import os
        import subprocess

        claude_bin = os.getenv("TASC_CLAUDE_BIN", "claude")
        try:
            proc = subprocess.run(
                [claude_bin, "-p", "--model", self._model],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=240,
            )
        except Exception as exc:  # noqa: BLE001
            raise SemanticMappingError(f"claude CLI failed: {exc}") from exc
        if proc.returncode != 0:
            raise SemanticMappingError(
                f"claude CLI exit {proc.returncode}: {proc.stderr[:200]}"
            )
        return proc.stdout

    def save_cache(self) -> None:
        _persist_cache(self._cache_path, self._cache, self._lock)


def build_semantic_mapper(config, cache_path) -> ClaudeCliSemanticMapper:
    """Build the semantic mapper (claude CLI backend)."""
    return ClaudeCliSemanticMapper(model=config.claude_cli_model, cache_path=cache_path)


class SemanticMappingError(RuntimeError):
    """Raised when the semantic layer fails for a batch."""


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
    """Build de-duplicated TechniqueMappings from raw model output items."""
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


def _claude_prompt(batch, max_techniques: int) -> str:
    """Build a batched prompt for the `claude` CLI."""
    items = [
        {
            "plugin_id": f.plugin_id,
            "name": f.plugin_name,
            "cves": f.cves[:5],
            "desc": (f.description or "")[:600],
        }
        for f in batch
    ]
    return (
        _SYSTEM
        + "\n\nReturn ONLY a JSON array (no prose, no markdown fences). For each "
        'finding return {"plugin_id": <id>, "mappings": [{"technique_id": "T....", '
        '"confidence": 0.0-1.0, "reason_code": "short", "rationale": "one sentence"}]}. '
        "Use only real MITRE ATT&CK enterprise technique IDs. Up to "
        f"{max_techniques} techniques per finding.\n\nFindings:\n"
        + json.dumps(items)
    )


def _extract_json_array(text: str):
    import re

    match = re.search(r"\[.*\]", text or "", re.S)
    if not match:
        return []
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return []


def _clamp(value, low: float = 0.0, high: float = 1.0) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return 0.0
