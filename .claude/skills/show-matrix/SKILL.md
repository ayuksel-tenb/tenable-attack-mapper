---
name: show-matrix
description: >-
  Clone the attack-navigator viewer, map this Security Center's open findings to
  MITRE ATT&CK, bring the viewer up, and open the VPR-scored ATT&CK matrix in the
  browser. Use when the user asks to show / open / visualize the ATT&CK matrix or
  their exposure, e.g. "open the attack matrix", "show me the ATT&CK matrix".
---

# Show the ATT&CK matrix

End-to-end: from a clone of **tenable-attack-mapper** with a configured `.env`,
produce a VPR-scored ATT&CK matrix in the browser, mapping live Security Center
findings. The mapping core stays here; this skill does the visible side-effecting
steps (clone, compose, open browser) with Bash. Run everything from the
tenable-attack-mapper repo root.

## Steps

1. **Check config.** Ensure `.env` exists with the Security Center URL/keys
   (`TSC_URL` / `TSC_ACCESS_KEY` / `TSC_SECRET_KEY`). Semantic mapping uses the local
   `claude` CLI (no API key needed). If `.env` is missing, tell the user to
   `cp .env.example .env` and fill it in, then retry. Do not invent credentials.

2. **Clone the viewer if missing:**
   ```bash
   [ -d attack-navigator ] || git clone https://github.com/ayuksel-tenb/attack-navigator
   ```

3. **Point the viewer's "Open in SC" links at the same Security Center.** Copy the
   `TSC_URL` from `.env` into `attack-navigator/.env` as `SC_URL`:
   ```bash
   SC_URL=$(grep -E '^TSC_URL=' .env | cut -d= -f2-)
   printf 'SC_URL=%s\n' "$SC_URL" > attack-navigator/.env
   ```

4. **Map findings → layer.** This connects to the SC in `.env`, pulls open
   findings, maps them to ATT&CK (deterministic + semantic), and writes the layer
   the viewer reads:
   ```bash
   uv run tenable-attack-mapper run --out attack-navigator/layers/layer.json --report coverage.md
   ```
   - **Do NOT pipe through `tail`/`head`** — that hides the progress the tool prints
     to stderr (`Pulled N findings`, `semantic: batch i/N done`). Let it stream.
   - On a **cold cache** this takes a few minutes (maps ~thousands of findings via
     the LLM API) — expected, **do not cancel**; relay the progress as it streams.
     Re-runs are instant (cache).
   - If slow/rate-limited, lower concurrency: `TASC_SEMANTIC_WORKERS=4 uv run …`.
   - (No `uv`? `pip install -e . && tenable-attack-mapper run …`.)

5. **Bring up the viewer** (custom ATT&CK matrix UI). If port 8080 is taken, set
   `VIEWER_PORT` to a free port (e.g. 8090) and use it everywhere below:
   ```bash
   cd attack-navigator && docker compose up -d viewer && cd ..
   ```

6. **Wait for it** to respond:
   ```bash
   for i in $(seq 1 30); do curl -fsS -o /dev/null "http://localhost:${VIEWER_PORT:-8080}/" && break; sleep 1; done
   ```

7. **Open the browser** (pick by OS):
   - macOS: `open "http://localhost:${VIEWER_PORT:-8080}/"`
   - Linux: `xdg-open "http://localhost:${VIEWER_PORT:-8080}/"`
   - Windows: `start "" "http://localhost:${VIEWER_PORT:-8080}/"`

8. **Tell the user it's ready** — report the coverage summary (from `coverage.md`)
   and: the matrix is at `http://localhost:8080`, colored by VPR exposure; click a
   technique to see the vulnerabilities behind it (each with an ⓘ rationale and an
   "Open in SC" deep link).

## Notes

- `git clone` and `docker compose` are strong, side-effecting actions — run them as
  visible steps, never silently.
- The matrix auto-loads `attack-navigator/layers/layer.json`; re-running step 4 and
  refreshing the browser updates it.
