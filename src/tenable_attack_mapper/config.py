"""Runtime configuration, loaded from environment variables (and an optional .env).

Secrets are never hard-coded: the Security Center URL and API keys, plus the
Anthropic API key, all come from the environment. Call :func:`load_config` once
and pass the result down into the client and mapping layers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # python-dotenv is a hard dependency, but stay importable without it.
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs) -> bool:
        return False


# The default semantic model. Overridable via ANTHROPIC_MODEL. We default to the
# most capable Claude model; override to a cheaper tier for large finding sets.
DEFAULT_MODEL = "claude-opus-4-8"

# Mappings scored below this confidence are flagged "needs-review" rather than
# being silently trusted.
DEFAULT_CONFIDENCE_THRESHOLD = 0.5


def _data_dir() -> Path:
    """Locate the reference-table directory across install layouts.

    Order: explicit override, package-bundled copy (wheel install), then the
    repo-root ``data/`` directory (editable / source checkout).
    """
    override = os.getenv("TASC_DATA_DIR")
    if override:
        return Path(override).expanduser()

    bundled = Path(__file__).resolve().parent / "data"
    if bundled.is_dir():
        return bundled

    return Path(__file__).resolve().parents[2] / "data"


@dataclass(slots=True)
class Config:
    """Resolved configuration for one mapping run."""

    sc_url: str
    sc_access_key: str
    sc_secret_key: str
    sc_verify_ssl: bool = False

    anthropic_api_key: str | None = None
    model: str = DEFAULT_MODEL
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD

    # Disable the semantic (LLM) fallback entirely — deterministic chain only.
    enable_semantic: bool = True

    data_dir: Path = field(default_factory=_data_dir)

    @property
    def semantic_available(self) -> bool:
        """The semantic layer needs both the feature flag and an API key."""
        return self.enable_semantic and bool(self.anthropic_api_key)


def load_config(*, require_sc: bool = True) -> Config:
    """Build a :class:`Config` from the environment.

    :param require_sc: when True, raise if the Security Center credentials are
        missing. Set False for offline/unit use that only touches the mappers.
    """
    load_dotenv()

    sc_url = os.getenv("TASC_SC_URL", "").strip()
    access_key = os.getenv("TASC_SC_ACCESS_KEY", "").strip()
    secret_key = os.getenv("TASC_SC_SECRET_KEY", "").strip()

    if require_sc and not (sc_url and access_key and secret_key):
        raise RuntimeError(
            "Missing Security Center credentials. Set TASC_SC_URL, "
            "TASC_SC_ACCESS_KEY and TASC_SC_SECRET_KEY (see .env.example)."
        )

    threshold = float(
        os.getenv("TASC_CONFIDENCE_THRESHOLD", str(DEFAULT_CONFIDENCE_THRESHOLD))
    )
    enable_semantic = _as_bool(os.getenv("TASC_ENABLE_SEMANTIC"), default=True)
    verify_ssl = _as_bool(os.getenv("TASC_SC_VERIFY_SSL"), default=False)

    return Config(
        sc_url=sc_url,
        sc_access_key=access_key,
        sc_secret_key=secret_key,
        sc_verify_ssl=verify_ssl,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
        model=os.getenv("ANTHROPIC_MODEL", DEFAULT_MODEL),
        confidence_threshold=threshold,
        enable_semantic=enable_semantic,
    )


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
