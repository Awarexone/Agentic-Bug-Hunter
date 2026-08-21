---
description: Screenshot a list of live hosts for fast visual triage and reusable PoC evidence. Builds a self-contained HTML gallery. Usage: /screenshot -l urls.txt -o shots/ | /screenshot -u https://admin.target.com -o shots/
---

# /screenshot

Reading 400 URLs in a text file is slow. A screenshot gallery surfaces login
panels, default installs, stack-trace error pages, and forgotten dev/staging
boxes in seconds — and the same captures become report evidence, so you never
scramble for a PoC screenshot later.

## Usage

```
/screenshot -l recon/target.com/live/urls.txt -o shots/
/screenshot -u https://admin.target.com -o shots/
/screenshot -l urls.txt -o shots/ --tool aquatone --json
```

Run directly:

```bash
tools/visual_triage.py -l recon/target.com/live/urls.txt -o shots/
```

## Tooling

Uses whichever screenshotter is installed, in order:

1. **eyewitness** — richest per-host report
2. **aquatone** — fast, clusters similar pages together
3. **httpx `-screenshot`** — already a core dependency, so this always works

All three are registered in `tools/external_arsenal.sh`. Output always includes
a self-contained `gallery.html` (no external assets) you can open locally or
attach to a report.

## Output

```
shots/
├── gallery.html          # open this — thumbnail grid, each labeled with its URL
└── <tool output>         # individual full-size PNGs
```

## Chain

`/recon` → live URLs → `/screenshot` → eyeball the grid → send anything odd
(admin panel, debug page, default cred screen) straight to `/hunt`. Reuse the
captured PNGs as the evidence attachment in `/report`.
