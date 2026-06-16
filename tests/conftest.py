"""Shared fixtures. All tests run fully offline — no Security Center, no Claude."""

from __future__ import annotations

from pathlib import Path

import pytest

from tenable_attack_mapper.config import Config
from tenable_attack_mapper.models import Finding

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def config() -> Config:
    return Config(
        sc_url="https://localhost:8443/",
        sc_access_key="x",
        sc_secret_key="y",
        enable_semantic=False,  # deterministic-only in tests
        confidence_threshold=0.5,
        data_dir=DATA_DIR,
    )


@pytest.fixture
def findings() -> list[Finding]:
    return [
        Finding(
            plugin_id="100001",
            plugin_name="Apache Log4j RCE (Log4Shell)",
            severity="Critical",
            vpr_score=10.0,
            cves=["CVE-2021-44228"],
            description="Remote code execution via JNDI lookup.",
            count=12,
        ),
        Finding(
            plugin_id="100002",
            plugin_name="Citrix ADC Path Traversal",
            severity="High",
            vpr_score=8.5,
            cves=["CVE-2019-19781"],
            description="Directory traversal allowing remote code execution.",
            count=3,
        ),
        Finding(
            plugin_id="100003",
            plugin_name="Generic banner grab with no CVE",
            severity="Low",
            vpr_score=None,
            cves=[],
            description="Informational service banner.",
            count=1,
        ),
    ]
