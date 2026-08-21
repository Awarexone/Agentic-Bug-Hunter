---
description: Run Semgrep security rulesets over fetched JS/source and map results into the toolkit's severity + confidence model. Usage: /sast <path> [--config p/xss,p/jwt] [--json]
---

# /sast

Recon downloads JS bundles and (sometimes) leaked source, but nothing runs a
real static analyzer over it — the skills' grep patterns get eyeballed by hand.
This drives **Semgrep** across that source and normalizes every hit into this
toolkit's states so findings drop straight into the validation gate.

## Usage

```
/sast recon/target.com/js/                 # default security packs
/sast app/ --config p/xss,p/jwt
/sast app.js --json
```

Run directly:

```bash
tools/sast_scan.py recon/target.com/js/
```

## Rulesets

Default packs (Semgrep Registry): `p/security-audit`, `p/secrets`, `p/xss`,
`p/sql-injection`, `p/command-injection`. Override with `--config`. Registered
in `tools/external_arsenal.sh` as `semgrep|sast`; if Semgrep isn't installed the
command prints the install hint and exits cleanly.

## Severity mapping

| Semgrep | Toolkit | Notes |
|---|---|---|
| `ERROR` | HIGH | |
| `WARNING` | MEDIUM | bumped to HIGH for sql-injection / rce / ssrf / secret / xxe / path-traversal rules |
| `INFO` | INFORMATIONAL | not a vulnerability on its own |

## Confidence — read this

Every SAST hit is tagged **`POSSIBLE`**, never `CONFIRMED`. Static analysis is a
*lead*, not proof: a flagged sink still needs a live request that demonstrates
impact before it goes in a report. `/validate` enforces this — no runtime PoC,
no submission. Use `/sast` to point `/hunt` at the right lines fast, not to file
findings directly.

## Chain

`/recon` → JS/source pulled → `/sast` → ranked sink list → `/hunt` the HIGH
sinks → `/validate` with a real PoC → `/report`.
