# Tenable ATT&CK Mapper

Map your **Tenable Security Center** vulnerability findings to **MITRE ATT&CK**
techniques and export a **VPR-scored ATT&CK Navigator layer** — so you can see
exactly which adversary techniques your exposure enables, ranked by risk, and
overlay them against your detection coverage to find exploitable-but-undetected
gaps.

It works two ways:

- **Headless** — a CLI / MCP server you run yourself.
- **Conversational** — a Claude Code agent you can just *ask*: "Which techniques
  should I watch for initial access?" → "Which of my findings match those?"

---

## What it does

- Pulls open findings from Security Center (plugin name, description, CVE, VPR).
- Maps each finding to ATT&CK techniques using a **deterministic chain**
  (CVE → CWE → CAPEC → ATT&CK) as the primary, authoritative evidence.
- Falls back to a **semantic** (Claude) mapping only where that chain is
  incomplete — and attaches a `confidence` and `reason_code` to **every** mapping
  so you can audit each link.
- Scores techniques by aggregated VPR and finding count, flagging low-confidence
  mappings as `needs-review` instead of silently trusting them.
- Exports a ready-to-import **ATT&CK Navigator layer (v4.5)** plus a Markdown
  coverage summary. The layer JSON *is* the UI — no web app to host.

---

## Use it in 3 steps

Even if you've never touched the code, this is all you need.

### 1. Install

```bash
# from a clone of this repo
pip install .

# with the conversational MCP server too
pip install ".[mcp]"
```

> Needs Python 3.12+. Prefer isolation? `pipx install .` or `uvx --from . tenable-attack-mapper --help`.

### 2. Configure

Copy the example env file and fill in your Security Center URL + API keys:

```bash
cp .env.example .env
```

```ini
TASC_SC_URL=https://localhost:8443/
TASC_SC_ACCESS_KEY=your-access-key
TASC_SC_SECRET_KEY=your-secret-key
# Optional — enables the semantic fallback for findings with no CVE chain:
ANTHROPIC_API_KEY=sk-ant-...
```

Generate the access/secret keys in Security Center under **User → API Keys**.
Secrets only ever live in `.env` (git-ignored) — they are never hard-coded.

### 3. Use

```bash
# Map repository 1 and write an importable Navigator layer
tenable-attack-mapper run --repo 1 --out layer.json --report coverage.md
```

Then open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):
**Open Existing Layer → Upload from local → pick `layer.json`**. Each mapped
technique is colored by its VPR-weighted exposure score.

![Example exposure preview](docs/img/sample-exposure-preview.png)

> Full walkthrough — opening, self-hosting for sensitive data, reading the
> matrix, and overlaying against detection coverage — in
> **[docs/navigator.md](docs/navigator.md)**.

Other handy commands:

```bash
# Deterministic chain only (no Claude)
tenable-attack-mapper run --repo 1 --out layer.json --no-semantic

# Which of my findings map to specific techniques?
tenable-attack-mapper techniques T1190 T1059 --repo 1
```

---

## Conversational mode (Claude Code agent)

This repo is also a Claude Code plugin. The `attack-mapper` agent (see
`agents/attack-mapper.md`) talks to the MCP server in `mcp/server.py`, wired
together by `.claude-plugin/plugin.json`. Once installed you can ask:

> "For initial access, which ATT&CK techniques should I look at — and which of my
> findings match them?"

The agent calls `techniques_for_tactic`, then `my_findings_for_techniques`, and
summarizes by VPR.

---

## How the mapping works

```
Security Center findings
        │
        ▼
┌─────────────────────────────────────────────┐   ┌──────────────────────────────┐
│ Deterministic backbone (primary, auditable) │   │ Semantic fallback (Claude)    │
│  CVE ─► CWE ─► CAPEC ─► ATT&CK   conf 0.95   │   │ plugin name + description →   │
│  CVE ─► CWE ───────────► ATT&CK  conf 0.80   │   │ candidate techniques +        │
│  (full evidence trail on every mapping)      │   │ confidence + reason_code      │
└──────────────────────┬──────────────────────┘   └───────────────┬──────────────┘
                       └──────────────┬───────────────────────────┘
                                      ▼
                          reconcile + de-duplicate
                  (deterministic wins; flag conf < threshold)
                                      ▼
                     score by VPR × confidence × finding count
                                      ▼
                Navigator layer (v4.5)  +  coverage report
```

The deterministic backbone is authoritative; the semantic layer is a documented,
auditable fallback — never a silent guess. Every mapping, from either source,
carries a **confidence** and a **reason_code** so an analyst can audit each link.

### 1. Pull findings

`sc_client.py` (pyTenable) pulls open findings — plugin id/name, description, CVE,
VPR — and de-duplicates to one record per plugin, accumulating host counts.

### 2. Deterministic backbone (`mapping/deterministic.py`)

The primary, evidence-backed source. Two paths run per resolved CWE:

| Path | Chain | Confidence | Reason code |
|------|-------|:---------:|-------------|
| **A — CAPEC taxonomy** | `CVE → CWE → CAPEC → ATT&CK` | 0.95 | `chain:cve-cwe-capec-attack` |
| **B — CWE bridge** | `CVE → CWE → ATT&CK` (direct) | 0.80 | `chain:cve-cwe-attack` |

- **CVE → CWE** comes from, in order: the bundled `data/cve_cwe.json` seed, a
  persistent on-disk cache (`data/.nvd_cache.json`), and — for genuine misses when
  `TASC_USE_NVD=true` — a live NVD lookup (set `NVD_API_KEY` for higher rate
  limits). Resolved CVEs are cached, so warming is a one-time cost.
- **CWE → CAPEC → ATT&CK** uses MITRE’s CAPEC “Related Weaknesses” and
  “Taxonomy Mappings” tables (`cwe_capec.json`, `capec_attack.json`). Authoritative
  but sparse — many CWEs have no CAPEC that carries an ATT&CK mapping.
- **CWE → ATT&CK bridge** (`cwe_attack.json`) is the *dense* complement: a curated
  class-level mapping of the CWE Top 25 + common weakness classes to the technique
  an adversary uses to exploit that class. Since every CVE has a CWE, this is the
  high-coverage deterministic path. It scores a notch lower (0.80) because it is a
  weakness-class generalization, not a per-pattern taxonomy link.

Every mapping records its full trail in `evidence`, e.g.
`CVE-2021-44228 → CWE-917 → CAPEC-242 → T1190`.

### 3. Semantic fallback (`mapping/semantic.py`)

For findings the deterministic backbone can’t reach (no CVE chain, or a gap in the
tables), Claude reads the plugin name + description and proposes candidate ATT&CK
techniques. A structured-output schema **forces** a `confidence` float and a
`reason_code` onto every proposed mapping, so semantic links are as auditable as
deterministic ones — the difference is provenance, not rigor. Disabled unless
`ANTHROPIC_API_KEY` is set; run with `--no-semantic` to force backbone-only.

### 4. Reconcile (`mapping/reconcile.py`)

Both layers are merged and de-duplicated per (finding, technique). **Deterministic
wins** on conflict; an agreeing semantic mapping is folded into the evidence. Any
mapping below the confidence threshold (`TASC_CONFIDENCE_THRESHOLD`, default 0.5)
is flagged `needs-review` rather than silently trusted.

### 5. Score (`mapping/reconcile.py`)

Each technique’s exposure score aggregates its findings, weighted by
`effective_VPR × confidence × host_count`, then normalized so the highest-exposure
technique is 100. That score drives the Navigator cell intensity.

### Coverage & honesty

Not every finding *should* map. The tool reports an **honest denominator**:

- **CVE-bearing findings** are the in-scope universe for exploitation-technique
  mapping; `cve_coverage_pct` is measured against these.
- **Compliance / scan-info findings** (no CVE — CIS checks, banners, scan info) are
  reported separately as out-of-scope. Not mapping them is correct, not a gap.

**To raise CVE-bearing coverage** (the deterministic backbone is gated by how many
CVEs you’ve resolved to CWEs):

1. **Warm the CVE → CWE cache** — run once with `TASC_USE_NVD=true` (and ideally
   `NVD_API_KEY`); resolved CVEs persist to `data/.nvd_cache.json`, so subsequent
   runs are instant and offline. The CWE bridge then maps most CVE-bearing findings.
2. **Enable the semantic layer** (`ANTHROPIC_API_KEY`) to cover the long tail —
   findings with no clean CWE chain still get a confidence-scored technique.
3. **Extend the tables** — drop fuller NVD / MITRE exports into `data/` (same
   format, no code change).

### Extending the reference data

All hops are plain JSON in `data/` (`cve_cwe`, `cwe_capec`, `capec_attack`,
`cwe_attack`, `attack_techniques`). The shipped tables are high-signal seeds;
replace them with full MITRE/NVD exports for production breadth — the format is
stable, so larger files are drop-in.

---

## Project layout

```
src/tenable_attack_mapper/
  sc_client.py        # pyTenable → open findings
  mapping/
    deterministic.py  # CVE→CWE→CAPEC→ATT&CK + direct CWE→ATT&CK bridge
    semantic.py       # Claude fallback (confidence + reason_code per mapping)
    reconcile.py      # merge, de-dup, score, flag needs-review
  navigator.py        # ATT&CK Navigator layer v4.5
  report.py           # coverage summary
  pipeline.py         # orchestration (the library entry point)
  cli.py              # `tenable-attack-mapper run ...`
  mcp/server.py       # FastMCP tools (same core functions)
data/                 # CVE/CWE/CAPEC/ATT&CK reference tables
agents/attack-mapper.md
.claude-plugin/plugin.json
examples/sample-layer.json
```

The core (`src/`) has no dependency on Claude Code — it runs standalone or under
any runtime.

---

## License

MIT — see [LICENSE](LICENSE).
