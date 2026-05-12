---
description: Hunt leaked credentials in a filesystem path, git history, JS bundles from a recon run, or an entire GitHub org. Wraps trufflehog (verifies live keys against issuer APIs), noseyparker (fast on huge histories), and gitleaks (default rule pack). Falls back to a regex grep if no scanner is installed. Usage: /secrets-hunt --filesystem <dir> | --git <repo> | --js-bundle <recon-dir> | --github-org <org>
---

# /secrets-hunt

Find leaked API keys, tokens, and credentials — verified when possible.

## Usage

```
/secrets-hunt --filesystem /path/to/project
/secrets-hunt --git https://github.com/target/repo
/secrets-hunt --js-bundle recon/target.com
/secrets-hunt --github-org acme-corp           # needs GITHUB_TOKEN env
```

## Scanners (best installed wins; the script runs whichever it finds)

| Scanner | Strength |
|---|---|
| `trufflehog` | Verifies live keys against the issuer API (AWS/Slack/Stripe/GH/...) |
| `noseyparker` | Fast on massive git histories with low false-positive rate |
| `gitleaks` | Opinionated rule pack — solid default for repos |

If none are installed the script still runs a regex fallback over the target so
something useful comes out — but you should install at least `trufflehog`
(`brew install trufflehog`) for the verified-only output.

## Why this is high-impact

- Leaked AWS / GCP / Slack / Twilio / OpenAI tokens are typically rated **High
  to Critical** ($1k–$10k+) on H1.
- Verified-only mode kills the noisy false positives that get reports closed.
- JS-bundle mode is the easiest win — companies regularly ship tokens in
  bundled frontend JavaScript.

## Verifying the find

When a hit comes back, verify the key works the right way before submitting:

- `streaak/keyhacks` shows the canonical curl-one-liner per provider.
- Submit only verified, in-scope keys.
- Don't pivot off the key (no further actions on the cloud account beyond
  proving it works) — most programs treat that as out-of-scope.

## Output

`findings/secrets/<timestamp>/` containing:
- `trufflehog.jsonl` — verified hits (high-confidence)
- `noseyparker.jsonl` — match groups across the history
- `gitleaks.json` — opinionated default-rule hits
- `regex_hits.txt` — regex fallback (manual triage required)
