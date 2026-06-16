# Tenable ATT&CK Mapper

Map your **Tenable Security Center** findings to **MITRE ATT&CK** and open a
**VPR-scored ATT&CK matrix** in your browser — click any technique to see the
vulnerabilities behind it, each linking to its detail page on your Security Center.

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/ayuksel-tenb/tenable-attack-mapper
cd tenable-attack-mapper
python3 -m venv .venv && source .venv/bin/activate    # Python 3.12+ · Windows: .venv\Scripts\activate
pip install -e .
```

A virtual environment keeps deps isolated and avoids clashes with a base/conda
Python. Re-activate it (`source .venv/bin/activate`) in any new terminal.

### 2. Configure

```bash
cp .env_test .env
```

Done — nothing to add. The test Security Center is pre-filled, and semantic mapping
runs on your **Claude Code subscription** via the local `claude` CLI — no API key,
no per-token cost.

### 3. Connect it to Claude Code

Run this from the repo folder (step 1 already installed the server into `.venv`):

```bash
claude mcp add --env TSC_URL=https://localhost:8443/ \
  --env TSC_ACCESS_KEY=YOUR_KEY --env TSC_SECRET_KEY=YOUR_SECRET \
  --transport stdio tenable-attack-mapper -- "$(pwd)/.venv/bin/tenable-attack-mapper-mcp"
```

Use the same SC values as your `.env`. Then `/mcp` should show it **connected**.

### 4. Use

Open Claude Code **in this folder** and ask — in order:

```
Map my environment and show the top techniques by VPR.
```
> The first prompt is the sync: it pulls findings from Security Center and maps
> them to ATT&CK. Then follow up:

```
Open the attack matrix.
Which of my findings map to T1190 and T1059?
```

`Open the attack matrix` brings up a local viewer and opens it in your browser —
techniques colored by VPR exposure; click one to see its vulnerabilities, each with
an ⓘ rationale and an **Open in SC** deep link.

---

**More:** [how mapping works](docs/mapping.md) · [CLI, OpenCode & tools](docs/usage.md) ·
[the viewer](https://github.com/ayuksel-tenb/attack-navigator) · MIT licensed.
