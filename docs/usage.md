# Usage details

Extra ways to run the tool, beyond the [README](../README.md) Quickstart.

## CLI (no Claude needed)

| Command | What it does |
|---|---|
| `tenable-attack-mapper run --out layer.json --report coverage.md` | Pull, map, export. |
| `tenable-attack-mapper run --repo 7 --out layer.json` | Scope to one repository. |
| `tenable-attack-mapper run --detailed` | Full per-finding pull (CVE + description, deterministic chain) — accurate but much slower on multi-host SCs. Default is the fast per-plugin summary, mapping on the plugin name. |
| `tenable-attack-mapper run --no-semantic` | Deterministic chain only. |
| `tenable-attack-mapper run --include-info` | Include Info-severity findings. |
| `tenable-attack-mapper techniques T1190 T1059` | Which findings map to these techniques? |

Default severity scope is Critical/High/Medium/Low (Info excluded).

## MCP tools exposed

Claude calls these when you ask — they don't run on their own:

- `map_environment` — pull open findings and map them to ATT&CK (the sync).
- `export_navigator_layer` — write a Navigator layer JSON to a path.
- `techniques_for_tactic` — list techniques under a tactic.
- `my_findings_for_techniques` — which findings map to given technique IDs.

> Registering the server does **not** pull data. The first sync happens when you
> prompt and Claude calls `map_environment`.

## OpenCode

Same server, in `opencode.json`:

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

(Needs `uv` installed. Once published to PyPI, the `--from git+...` part drops to
just `uvx tenable-attack-mapper-mcp`.)

## Open the matrix directly (without Claude)

```bash
git clone https://github.com/ayuksel-tenb/attack-navigator
tenable-attack-mapper run --out attack-navigator/layers/layer.json
cd attack-navigator && docker compose up -d viewer
open http://localhost:8080
```

Open `http://localhost:8080` with `open` on macOS, `xdg-open` on Linux, or `start`
on Windows.
