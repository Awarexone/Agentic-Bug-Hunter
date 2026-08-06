# Tools

Python and shell scanner pipeline (~50 tools). Every tool checks whether its
external dependency is installed — missing tools are skipped, never hard-error.

Full catalogue below. Quick start:

```bash
python3 tools/hunt.py --target target.com          # recon → leads → scan → report
python3 tools/lead_board.py ingest target.com      # after any /recon
python3 tools/lead_board.py next target.com        # highest-value untouched lead
bash tools/external_arsenal.sh                     # what's installed vs missing
```

---

## Core Pipeline

| Tool | Purpose |
|:---|:---|
| `hunt.py` | Master orchestrator — recon, lead-board ingest, EOL check, vuln scan, optional CVE/zero-day |
| `recon_engine.sh` | Subdomain enum · live host probing · URL crawl · nuclei · CI/CD phase |
| `vuln_scanner.sh` | XSS · SQLi · SSTI · SSRF · MFA · SAML probe pipeline |
| `validate.py` | 4-gate finding validator with identity checks and curl PoC requirement |
| `scope_checker.py` | Deterministic scope safety check before any request |
| `lead_board.py` | Persistent recon→skill lead ledger (`ingest` / `show` / `next` / `touch` / `add`) |

## Recon & Discovery

| Tool | Purpose |
|:---|:---|
| `scope_aggregator.sh` | Multi-platform scope pull (bbscope + bounty-targets-data) |
| `recon_adapter.py` | Normalize recon output across nested/flat layouts |
| `param_discovery.sh` | Hidden HTTP parameters via Arjun · x8 |
| `cloud_recon.sh` | S3Scanner · cloud_enum · CloudFail for public bucket exposure |
| `takeover_scanner.sh` | Subdomain takeover via dnsReaper · subjack |
| `cve_scan.sh` | Focused nuclei CVE sweep (high/critical) + optional log4j-scan |
| `bypass_403.sh` | Header · method · encoding tricks against 403/401 (soft-block aware) |
| `secrets_hunter.sh` | trufflehog · noseyparker · gitleaks across FS/git/JS/GitHub org |
| `cicd_scanner.sh` | GitHub Actions workflow scanner (sisakulint + remote scan) |
| `graphql_audit.sh` | 7-phase GraphQL audit: introspection, batching, IDOR, injection, alias bomb |
| `eol_check.py` | End-of-life / lifecycle intel from endoflife.date for fingerprint pairs |
| `external_arsenal.sh` | Installed-tool registry (~50 external binaries); `_have <tool>` gate |
| `target_selector.py` | Rank public HackerOne programs and pick top targets |

## WAF / Bypass / Mutation

| Tool | Purpose |
|:---|:---|
| `waf_encoder.py` | Multi-layer encoded payload variants (`--class sqli\|xss\|generic`) |
| `waf_response_analyzer.py` | Score WAF block vs soft-challenge vs real app response |
| `multipart_mutator.py` | Parser-confusion multipart upload variants |
| `sneaky_bits.py` | Invisible Unicode prompt-injection encode/decode (U+2062/U+2064) |

## Fuzzing & Deep Probes

| Tool | Purpose |
|:---|:---|
| `zero_day_fuzzer.py` | Smart fuzzing + edge-case / logic-flaw probes (manual verify required) |
| `hai_payload_builder.py` | VAPT payload library + LLM injection generator |
| `hai_probe.py` | Fingerprint HackerOne AI Copilot / Hai API surface |
| `hai_browser_recon.js` | Browser-side Hai recon helper |

## IDOR / Auth / Race (H1-style dual-session)

| Tool | Purpose |
|:---|:---|
| `h1_idor_scanner.py` | Cross-user GraphQL IDOR — Account B token vs Account A IDs |
| `h1_mutation_idor.py` | Privileged mutation IDOR battery |
| `h1_oauth_tester.py` | OAuth state CSRF, redirect_uri, 2FA, pre-ATO, host-header reset |
| `h1_race.py` | Race conditions (double-spend, 2FA rate limits, parallel actions) |
| `h1_run.sh` | Convenience wrapper for the H1 dual-session suite |
| `zendesk_idor_test.py` | Zendesk org-boundary IDOR / BAC tester |

## Web3

| Tool | Purpose |
|:---|:---|
| `token_scanner.py` | Automated token red-flag scanner (EVM + Solana / Anchor) |

## Intelligence & Planning

| Tool | Purpose |
|:---|:---|
| `intel_engine.py` | CVE + disclosure intel with hunt-memory context |
| `learn.py` | On-demand target learning from disclosed reports / NVD / GHSA |
| `mindmap.py` | Mermaid mind map + prioritized hunting checklist from tech stack |
| `dashboard.py` | Live ANSI TUI for recon/hunt phase progress |
| `banner.py` / `banner.sh` | Shared CLI banner (gradient BUGHUNTER logo) |

## Memory & Session

| Tool | Purpose |
|:---|:---|
| `memory_gc.py` | Inspect and rotate hunt-memory JSONL files (10 MB cap, 3 backups) |
| `auth_session.py` | Auth header management across all tools (`--cookie` / `--bearer` / `--auth-file`) |
| `credential_store.py` | Encrypted / `.env`-backed credential store for hunt sessions |
| `_auth_helper.sh` | Bash helper that injects `BBHUNT_AUTH_*` into curl/httpx children |

## Credential Attack (requires `--with-credential-attack`)

| Tool | Purpose |
|:---|:---|
| `wordlist_engine.sh` | Company-specific password wordlist (cewler + hashcat rules) |
| `osint_employees.sh` | Employee names + emails (theHarvester + username-anarchy) |
| `breach_checker.py` | HIBP k-anonymity ranking by real-world breach count |
| `spray_orchestrator.sh` | Password spray with typed-host confirm + lockout warn + audit log |
| `_spray_http_form.py` | HTTP form spray worker (spawned by orchestrator) |
| `_spray_oauth.py` | OAuth password-grant spray worker |

## Output Format

Scanner confidence states prepended to every finding:

- `[CONFIRMED]` — PoC-verified, real impact demonstrated
- `[POSSIBLE]` — strong signal, needs manual verification
- `[INFORMATIONAL]` — version/banner/config data, not a vulnerability

## Post-recon ritual (never skip)

```bash
python3 tools/lead_board.py ingest target.com
python3 tools/lead_board.py show target.com
python3 tools/lead_board.py next target.com
# then route: GraphQL → hunt-graphql /skills/graphql-audit, etc.
```

`hunt.py` runs `lead_board ingest` + EOL check automatically after recon unless
`--skip-leads` is set.
