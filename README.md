# Tenable ATT&CK Mapper

Map your **Tenable Security Center** findings to **MITRE ATT&CK** and open a
**VPR-scored ATT&CK matrix** in your browser — click any technique to see the
exact vulnerabilities behind it, each linking straight to its detail page on your
own Security Center.

- **Deterministic backbone** (CVE → CWE → CAPEC/ATT&CK) for authoritative,
  auditable mappings, plus a **semantic (Claude)** fallback for the long tail.
- Every mapping carries a **confidence** and a **reason code** you can audit.
- Works **headless** (CLI), as an **MCP server** (Claude Code & OpenCode), or
  end-to-end via the **`show-matrix`** skill.

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/ayuksel-tenb/tenable-attack-mapper
cd tenable-attack-mapper
uv run tenable-attack-mapper --help      # uv pulls deps on first run
```

> No `uv`? `pip install -e .` then `tenable-attack-mapper --help`. Python 3.12+.

### 2. Configure

```bash
cp .env_test .env        # local test SC is pre-filled
```

Then open `.env` and set your Anthropic key (`ANTHROPIC_API_KEY=sk-ant-...`).
That's the only value you need to add — the test Security Center is already set.

### 3. Use

Open the matrix end-to-end (clones the viewer, maps, brings it up, opens the
browser) — just ask in Claude Code:

> **"Open the attack matrix."**

or do it directly:

```bash
git clone https://github.com/ayuksel-tenb/attack-navigator
uv run tenable-attack-mapper run --out attack-navigator/layers/layer.json
cd attack-navigator && docker compose up -d viewer
open http://localhost:8080            # macOS · Linux: xdg-open · Windows: start
```

Each technique is colored by VPR exposure; click one to see its vulnerabilities,
each with an ⓘ rationale and an **Open in SC** deep link.

---

## Use it as an MCP server

One published, `uvx`-runnable stdio server works in **both** runtimes — nothing
runtime-specific to write.

**Claude Code** — `claude mcp add`:

```bash
claude mcp add --env TSC_URL=https://securitycenter.local \
  --env TSC_ACCESS_KEY=... --env TSC_SECRET_KEY=... --env ANTHROPIC_API_KEY=... \
  --transport stdio tenable-attack-mapper -- uvx tenable-attack-mapper-mcp
```

or `.mcp.json`:

```json
{
  "mcpServers": {
    "tenable-attack-mapper": {
      "command": "uvx",
      "args": ["tenable-attack-mapper-mcp"],
      "env": {
        "TSC_URL": "https://securitycenter.local",
        "TSC_ACCESS_KEY": "...",
        "TSC_SECRET_KEY": "...",
        "ANTHROPIC_API_KEY": "..."
      }
    }
  }
}
```

**OpenCode** — `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "tenable-attack-mapper": {
      "type": "local",
      "command": ["uvx", "tenable-attack-mapper-mcp"],
      "enabled": true,
      "environment": {
        "TSC_URL": "https://securitycenter.local",
        "TSC_ACCESS_KEY": "...",
        "TSC_SECRET_KEY": "...",
        "ANTHROPIC_API_KEY": "..."
      }
    }
  }
}
```

Tools exposed: `map_environment`, `export_navigator_layer`, `techniques_for_tactic`,
`my_findings_for_techniques`.

### Example chat prompts

```
Open the attack matrix.
Which ATT&CK tactics and techniques should I watch for initial access?
Which of my findings map to T1190 and T1059?
Export a Navigator layer for repository 7 to layer.json.
Map my Critical and High findings and show the top techniques by VPR.
```

---

## CLI reference

```bash
tenable-attack-mapper run --out layer.json --report coverage.md   # pull, map, export
tenable-attack-mapper run --repo 7 --out layer.json               # one repository
tenable-attack-mapper run --no-semantic                           # deterministic only
tenable-attack-mapper run --include-info                          # include Info severity
tenable-attack-mapper techniques T1190 T1059                      # which findings map here?
```

Default severity scope is Critical/High/Medium/Low (Info excluded). See
[docs/mapping.md](docs/mapping.md) for how mappings work and how to raise coverage,
[docs/navigator.md](docs/navigator.md) for the viewer, and the on-prem matrix at
[ayuksel-tenb/attack-navigator](https://github.com/ayuksel-tenb/attack-navigator).

## License

MIT — see [LICENSE](LICENSE).
