---
description: Confirm DOM XSS in a real headless browser — injects canary payloads into params + URL fragment and only reports when the browser actually executes them. Usage: /domxss "<url>" [--params q,name] [--shot out.png]
---

# /domxss

Reflected-XSS scanners see a payload echoed back in HTML but can't tell whether
it *ran* — CSP, framework auto-escaping, or a sink that never reaches
`eval`/`innerHTML` all silently kill it. This drives headless Chromium, fires a
uniquely-tagged payload through each parameter and the URL fragment, and only
reports a finding when the browser executes the canary. That's the difference
between "reflected, maybe" and a report-ready `[CONFIRMED]` DOM XSS.

## Usage

```
/domxss "https://app.target.com/search?q=test"
/domxss "https://app.target.com/#name=x&redirect=y" --params name,redirect
/domxss "https://app.target.com/?q=1" --shot shots/domxss.png --json
```

Run directly:

```bash
tools/dom_xss_harness.py "https://app.target.com/search?q=test"
```

## Requires

Playwright (a new dependency, registered in `tools/external_arsenal.sh`):

```bash
pip install playwright && playwright install chromium
```

If it isn't installed the command prints this hint and exits cleanly — the rest
of the toolkit is unaffected.

## How it decides

| Verdict | Meaning |
|---|---|
| `[CONFIRMED]` | the payload's unique canary **executed** in-browser — fired via `alert`/`prompt`/`confirm`, a hooked `window.__cbbx` sink, or the console. JS ran. |
| `[POSSIBLE]` | the canary is reflected into the DOM but did **not** execute (likely CSP/escaping). Worth a manual look, not a finding on its own. |

Injection points: every `?query` parameter **and** every `#fragment` key
(fragment-based DOM XSS never reaches the server, so server-side scanners miss
it entirely). Add more with `--params`.

## Why this matters

DOM XSS, client-side prototype pollution, and PostMessage bugs need a real DOM —
this is the harness that lets the agent *confirm* them instead of guessing.
A `[CONFIRMED]` hit passes `/validate` on its own because execution is proven;
`--shot` captures the screenshot for `/report`.

## Chain

`/recon` → JS/param discovery → `/domxss "<url>" --params <candidates>` →
`[CONFIRMED]` → `/report` with the screenshot. Pairs with `/sast` (find the sink
in source) → `/domxss` (prove it fires).
