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
pip install -e .                         # Python 3.12+
tenable-attack-mapper --help
```

> Prefer `uv`? Install it once — `curl -LsSf https://astral.sh/uv/install.sh | sh`
> (then open a new terminal) — and `uv run tenable-attack-mapper --help` works with
> no manual install. `uv` is also what the MCP config below uses (`uvx`), so install
> it if you want the MCP server.

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

One `uvx`-runnable stdio server works in **both** runtimes — nothing
runtime-specific to write. `uvx` installs and runs it from Git (no PyPI publish
needed); the first launch resolves the package, then it's cached.

> Registering a server does **not** pull any data. Claude Code only starts the
> server (and `uvx` installs it on first run — confirm with `/mcp`). The first
> real **sync happens when you prompt** and Claude calls a tool, e.g.
> *"map my environment and show the top techniques."* There is no background sync.

**Claude Code** — `claude mcp add`:

```bash
claude mcp add --env TSC_URL=https://securitycenter.local \
  --env TSC_ACCESS_KEY=... --env TSC_SECRET_KEY=... --env ANTHROPIC_API_KEY=... \
  --transport stdio tenable-attack-mapper -- \
  uvx --from git+https://github.com/ayuksel-tenb/tenable-attack-mapper tenable-attack-mapper-mcp
```

or `.mcp.json`:

```json
{
  "mcpServers": {
    "tenable-attack-mapper": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/ayuksel-tenb/tenable-attack-mapper", "tenable-attack-mapper-mcp"],
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
      "command": ["uvx", "--from", "git+https://github.com/ayuksel-tenb/tenable-attack-mapper", "tenable-attack-mapper-mcp"],
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

Once published to PyPI, the `--from git+...` part drops to just `uvx tenable-attack-mapper-mcp`.

Tools exposed: `map_environment`, `export_navigator_layer`, `techniques_for_tactic`,
`my_findings_for_techniques` — Claude calls these when you ask; they're not run on
their own.

### Example chat prompts

Start with a prompt that **maps your environment** — this is the first sync (pull
from Security Center + map to ATT&CK). The follow-up prompts then work off that
mapped result:

```
# 1. First — triggers the sync (pull findings + map to ATT&CK):
Map my environment and show the top techniques by VPR.

# 2. Then ask follow-ups about the mapped result:
Which ATT&CK tactics and techniques should I watch for initial access?
Which of my findings map to T1190 and T1059?
Export a Navigator layer for repository 7 to layer.json.
Open the attack matrix.
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
