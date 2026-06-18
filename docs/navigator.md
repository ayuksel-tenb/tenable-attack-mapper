# Viewing your layer in the MITRE ATT&CK Navigator

`tenable-attack-mapper` produces a Navigator **layer** file (`layer.json`). The
layer *is* the UI — you open it in the MITRE ATT&CK Navigator, where each mapped
technique is colored by its VPR-weighted exposure score (0–100). This guide walks
you from a freshly generated `layer.json` to a colored matrix on screen.

Here is what the example layer (`examples/sample-layer.json`) looks like as a
ranked exposure preview — in the Navigator these same techniques appear as
colored cells on the ATT&CK matrix:

![Example exposure preview](img/sample-exposure-preview.png)

---

## 1. Generate the layer

```bash
tenable-attack-mapper run --repo 1 --out layer.json --report coverage.md
```

You now have `layer.json` in your working directory.

## 2. Open the Navigator

You have three options:

- **Hosted (no install):** open the public instance —
  **<https://mitre-attack.github.io/attack-navigator/>**
- **Self-hosted (air-gapped / sensitive data):** run the official Navigator
  locally so the layer never leaves your machine:

  ```bash
  docker run -p 4200:4200 mitre/attack-navigator
  ```

  Then browse to `http://localhost:4200`.

- **On-prem viewer with finding drill-down (recommended for sensitive data):**
  the separate **[attack-navigator](https://github.com/ayuksel-tenb/attack-navigator)**
  project is a `docker compose up` companion that stands up a local UI where you
  click a technique to see its vulnerabilities and click a finding to open its
  detail page on **your own Security Center**. Your data stays on-prem. It also
  bundles the official Navigator for standard-format viewing.

  > For sensitive exposure data, prefer either self-hosted option — the layer is
  > only ever loaded into a browser app you control.

## 3. Upload (open) the layer file

On the Navigator start screen:

1. Click **“Open Existing Layer.”**
2. Choose **“Upload from local”** (a file picker appears) — *not* “Load from URL.”
3. Select your `layer.json`.

The matrix opens with your techniques highlighted.

```
ATT&CK Navigator start screen
┌────────────────────────────────────────────┐
│  + Create New Layer                          │
│  ▸ Open Existing Layer                       │
│       • Load from URL                         │
│       • Upload from local   ◀── pick this     │
│  ▸ Create Layer from other layers            │
└────────────────────────────────────────────┘
```

## 4. Read the matrix — and drill into the vulnerabilities

This is the point of the tool: a colored technique is only useful if you can see
*which findings* drive it. Each technique carries that list.

- **Cell color** = exposure score. The gradient runs pale → deep red
  (`#fff5f0` → `#67000d`), peaking at the highest-exposure technique (score 100).
  Every scored cell also has an explicit color, so it stays colored even if the
  gradient doesn’t fully restore.
- **Grey cells** = `needs-review` mappings (low confidence) — audit these first.
- **Hover a technique → the tooltip lists its vulnerabilities.** After the
  aggregate rows (finding count, total VPR, confidence, sources) and a divider,
  you get one row per contributing finding:
  `plugin 100001 → Apache Log4j RCE (Log4Shell) — CVE-2021-44228 — VPR 10.0 — ×12 hosts`.
  (Capped at 40 per technique; a “+N more” row tells you if there are others.)
- **Right-click a technique → its links.** The first link opens the ATT&CK
  technique page; the rest open each finding’s **Tenable plugin page**
  (`tenable.com/plugins/nessus/<id>`) so you can click straight through from a
  technique to the underlying vulnerability.

> So the flow is: spot a hot (dark) technique → hover to read the exact
> vulnerabilities behind it → right-click to open those plugins in Tenable.

## 5. (Optional) Overlay against your detection coverage

This is where it gets useful for purple-teaming: compare *exposure* (this layer)
against *detection coverage* (a layer you already maintain) to find
exploitable-but-undetected techniques.

1. In the Navigator, use **“Create Layer from other layers.”**
2. Reference your two layers as `a` (exposure) and `b` (detection coverage).
3. Set the **score expression** to `a - b`.
4. Techniques that stay hot (high `a`, low `b`) are your exposed, undetected gaps.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| “Invalid layer file” | You picked a non-layer JSON. Make sure it’s the `--out` file, not the coverage report. |
| Cells have a score on hover but aren’t **colored** | The layer now bakes an explicit `color` into every scored technique, so this is fixed regardless of gradient restore. If you still see it, your Navigator failed to fully load the layer — re-upload, or use a current Navigator (see below). |
| “Outdated Layer / version mismatch” or “upgrade to ATT&CK v19?” prompt | The layer omits the `attack` field so the Navigator assumes its own current version (no upgrade prompt). A residual *layer-format* version warning means your **Navigator app is older than 4.9.0** — use the current hosted Navigator, or pull a recent self-hosted image: `docker pull mitre/attack-navigator:latest`. The layer still loads either way; the warning is non-fatal. |
| Matrix opens but nothing is colored | No findings mapped (e.g. all findings were compliance checks with no CVE, or the seed reference tables didn’t cover your CVEs). Check `coverage.md` — extend `data/*.json` with fuller NVD/CAPEC exports for more coverage. |
| Techniques look under-mapped | The bundled reference tables are small seed sets. Replace `data/cve_cwe.json`, `data/cwe_capec.json`, `data/capec_attack.json` with full MITRE/NVD exports — the format is unchanged, so it’s a drop-in. |
| Sub-technique not shown | Sub-techniques (e.g. `T1059.007`) only render when their parent row is expanded; the layer sets `showSubtechniques` for mapped sub-techniques. |

---

## Layer format

The output conforms to the **ATT&CK Navigator layer format v4.5** (`enterprise-attack`
domain). Each technique entry carries:

```jsonc
{
  "techniqueID": "T1190",
  "score": 100.0,                 // VPR-weighted exposure, 0–100
  "color": "",                    // grey when needs_review
  "comment": "Exploit Public-Facing Application\n3 finding(s), total VPR 28.8, confidence 0.95",
  "metadata": [
    { "name": "findings", "value": "3" },
    { "name": "total_vpr", "value": "28.8" },
    { "name": "max_confidence", "value": "0.95" },
    { "name": "sources", "value": "deterministic" },
    { "name": "needs_review", "value": "false" }
  ]
}
```

Because it’s standard Navigator JSON, it also works with anything that consumes
layers (the Navigator CLI, layer-diffing scripts, your own dashboards).
