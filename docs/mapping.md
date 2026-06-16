# How the mapping works

```
Security Center findings (Critical/High/Medium/Low; Info excluded by default)
        │
        ▼
┌─────────────────────────────────────────────┐   ┌──────────────────────────────┐
│ Deterministic backbone (primary, auditable) │   │ Semantic fallback (Claude)    │
│  CVE ─► CWE ─► CAPEC ─► ATT&CK   conf 0.95   │   │ plugin name + description →   │
│  CVE ─► CWE ───────────► ATT&CK  conf 0.80   │   │ technique + confidence +      │
│  (full evidence trail per mapping)           │   │ reason_code (validated IDs)   │
└──────────────────────┬──────────────────────┘   └───────────────┬──────────────┘
                       └──────────────┬───────────────────────────┘
                                      ▼
                reconcile + de-dup + validate vs ATT&CK catalog
                  (deterministic wins; flag conf < threshold)
                                      ▼
                  score by VPR × confidence × finding count
                                      ▼
                Navigator layer (v4.5)  +  coverage report
```

Every mapping — deterministic or semantic — carries a **confidence** and a
**reason_code**, and every technique ID is validated against the authoritative
MITRE ATT&CK catalog (hallucinated IDs are dropped).

## Deterministic backbone

Two paths run per resolved CWE:

| Path | Chain | Confidence | Reason code |
|------|-------|:---------:|-------------|
| CAPEC taxonomy | `CVE → CWE → CAPEC → ATT&CK` | 0.95 | `chain:cve-cwe-capec-attack` |
| CWE bridge | `CVE → CWE → ATT&CK` (direct) | 0.80 | `chain:cve-cwe-attack` |

`CVE → CWE` resolves from the bundled seed, a persistent cache
(`data/.nvd_cache.json`), and — for misses when `TASC_USE_NVD=true` — a live NVD
lookup (set `NVD_API_KEY` for higher limits). The CWE→ATT&CK bridge
(`data/cwe_attack.json`, CWE Top 25+) is the dense, high-coverage path since every
CVE carries a CWE.

## Semantic fallback

For findings the backbone can't reach, Claude reads the plugin name + description
and proposes ATT&CK techniques. A structured-output schema forces a confidence and
reason_code onto every mapping, so semantic links are as auditable as deterministic
ones. Disabled unless `ANTHROPIC_API_KEY` is set. Runs concurrently
(`TASC_SEMANTIC_WORKERS`), caches per plugin (`data/.semantic_cache.json`), and
maps only CVE-bearing findings by default (`TASC_SEMANTIC_NO_CVE=true` to include
compliance/scan-info).

## Coverage & honesty

- **CVE-bearing findings** are the in-scope universe; `cve_coverage_pct` is measured
  against them.
- **Compliance / scan-info findings** (no CVE) are reported separately as
  out-of-scope — not mapping them is correct.
- To raise coverage: set `ANTHROPIC_API_KEY` (semantic covers the long tail), warm
  the CVE→CWE cache with `TASC_USE_NVD=true`, or drop fuller MITRE/NVD exports into
  `data/` (same format, no code change).
