# Reference tables

The deterministic mapper walks an authoritative chain:

```
CVE  ->  CWE  ->  CAPEC  ->  ATT&CK technique
```

Each hop is backed by one JSON table in this directory:

| File | Hop | Source of truth |
|------|-----|-----------------|
| `cve_cwe.json` | CVE → CWE | NVD (the offline copy here is a seed/fallback; a live NVD lookup is preferred when reachable) |
| `cwe_capec.json` | CWE → CAPEC | MITRE CAPEC "Related Weaknesses" |
| `capec_attack.json` | CAPEC → ATT&CK | MITRE CAPEC "Taxonomy Mappings" → ATT&CK |
| `attack_techniques.json` | technique metadata | MITRE ATT&CK (enterprise) — names + tactics for reports |

These shipped tables are deliberately small seed sets covering common, high-signal
CVEs so the tool runs offline out of the box. Replace or extend them with full
exports from NVD / MITRE for production coverage — the format is stable, so a
larger drop-in file needs no code changes.

To point the tool at a different directory, set `TASC_DATA_DIR`.
