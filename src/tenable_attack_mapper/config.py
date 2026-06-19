"""Runtime configuration, loaded from environment variables (and an optional .env).

Secrets are never hard-coded: the Security Center URL and API keys all come from
the environment. Call :func:`load_config` once and pass the result down into the
client and mapping layers.
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


# Semantic mapping runs through the local `claude` CLI. haiku = fast.
DEFAULT_CLAUDE_MODEL = "claude-haiku-4-5"

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

    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD

    # Disable the semantic layer entirely — deterministic chain only.
    enable_semantic: bool = True
    # Model for the `claude` CLI (semantic mapping runs on your Claude Code
    # subscription via `claude -p`).
    claude_cli_model: str = DEFAULT_CLAUDE_MODEL
    # Number of concurrent `claude -p` calls (batched).
    semantic_workers: int = 20
    # By default the semantic layer maps only CVE-bearing findings (the in-scope
    # exploitation universe). Set True to also map no-CVE compliance/scan-info.
    semantic_include_no_cve: bool = False

    data_dir: Path = field(default_factory=_data_dir)

    @property
    def semantic_available(self) -> bool:
        return self.enable_semantic


def load_config(*, require_sc: bool = True) -> Config:
    """Build a :class:`Config` from the environment.

    :param require_sc: when True, raise if the Security Center credentials are
        missing. Set False for offline/unit use that only touches the mappers.

    Loads ``.env`` from the current directory and from the project root next to the
    source — so when Claude Code launches the MCP server from another working
    directory, an editable install still reads the repo's ``.env`` (no need to
    repeat the keys as ``--env`` flags). Real environment variables always win.
    """
    load_dotenv()  # .env in the current working directory, if any
    repo_env = Path(__file__).resolve().parents[2] / ".env"
    if repo_env.is_file():
        load_dotenv(repo_env, override=False)

    # Primary env var names are TSC_* (Tenable Security Center); the older
    # TASC_SC_* names are still accepted as a fallback.
    sc_url = _env("TSC_URL", "TASC_SC_URL")
    access_key = _env("TSC_ACCESS_KEY", "TASC_SC_ACCESS_KEY")
    secret_key = _env("TSC_SECRET_KEY", "TASC_SC_SECRET_KEY")

    if require_sc and not (sc_url and access_key and secret_key):
        raise RuntimeError(
            "Missing Security Center credentials. Set TSC_URL, TSC_ACCESS_KEY and "
            "TSC_SECRET_KEY (see .env.example, or copy .env_test to .env)."
        )

    threshold = float(
        os.getenv("TASC_CONFIDENCE_THRESHOLD", str(DEFAULT_CONFIDENCE_THRESHOLD))
    )
    enable_semantic = _as_bool(os.getenv("TASC_ENABLE_SEMANTIC"), default=True)
    verify_ssl = _as_bool(_env("TSC_VERIFY_SSL", "TASC_SC_VERIFY_SSL") or None, default=False)

    return Config(
        sc_url=sc_url,
        sc_access_key=access_key,
        sc_secret_key=secret_key,
        sc_verify_ssl=verify_ssl,
        confidence_threshold=threshold,
        enable_semantic=enable_semantic,
        claude_cli_model=os.getenv("TASC_CLAUDE_MODEL", DEFAULT_CLAUDE_MODEL),
        semantic_workers=int(os.getenv("TASC_SEMANTIC_WORKERS", "20")),
        semantic_include_no_cve=_as_bool(
            os.getenv("TASC_SEMANTIC_NO_CVE"), default=False
        ),
    )


def _env(*names: str) -> str:
    """First non-empty value among the given env var names (primary first)."""
    for name in names:
        val = os.getenv(name, "").strip()
        if val:
            return val
    return ""


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
