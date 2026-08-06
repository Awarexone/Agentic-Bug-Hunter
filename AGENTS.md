# Bug Bounty Agent Toolkit — Plugin Guide

This repo is an agent-portable bug bounty plugin for professional hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi. It supports Claude Code, OpenCode, Pi Agent, Codex-style Agent Skills, and shared `.agents/skills` harnesses.

## What's Here

### Skills (13 domains — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.)

<!-- GENERATED:skills:START (see docs/manifest.json — run scripts/gen_docs.py) -->
| Skill | Domain |
|---|---|
| `bug-bounty` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `bb-methodology` | Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline |
| `web2-recon` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `web2-vuln-classes` | 24 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `security-arsenal` | Payloads, bypass tables, gf patterns, always-rejected list |
| `web3-audit` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `meme-coin-audit` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `report-writing` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `triage-validation` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |
| `credential-attack` | Password spray methodology — when/why, 4-stage pipeline, mode selection, lockout tactics, legal guardrails |
| `mobile-pentest` | Android/iOS app pentest — runtime-first proxy workflow, APK/IPA decompile, deeplink/WebView bridge injection, SSL pinning bypass |
| `cicd-security` | CI/CD pipeline hunting — GitHub Actions injection, secret exfil, self-hosted runner poisoning, OIDC abuse, supply chain attacks |
| `graphql-audit` | GraphQL hunting — introspection, field suggestions, batching DoS, IDOR via aliasing, injection, auth bypass, depth bombs |
<!-- GENERATED:skills:END -->

### Commands (27 slash commands)

> **Note:** All commands are prefixed to avoid conflicts with Codex's built-in commands.
> `/resume` is a reserved Codex command — use `/pickup` to continue a previous hunt.

<!-- GENERATED:commands:START (see docs/manifest.json — run scripts/gen_docs.py) -->
| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/scope-aggregate` | `/scope-aggregate <program>` — pull every in-scope asset across H1/Bugcrowd/Intigriti/YWH/Immunefi |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/pickup` | `/pickup target.com` — pick up previous hunt (was /resume) |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/token-scan` | `/token-scan <contract>` — meme coin/token rug pull scanner |
| `/memory-gc` | `/memory-gc [--rotate|--purge-backups]` — inspect/rotate hunt-memory JSONL files (10MB cap, 3 backups) |
| `/secrets-hunt` | `/secrets-hunt --js-bundle <recon-dir>` — leaked-credential scan (trufflehog/noseyparker/gitleaks) |
| `/takeover` | `/takeover --recon <recon-dir>` — subdomain takeover candidates (dnsReaper/subjack) |
| `/cloud-recon` | `/cloud-recon --keyword <name>` — public S3/Azure/GCP + CloudFlare-bypass origin IPs |
| `/param-discover` | `/param-discover <url>` — find hidden HTTP parameters (Arjun/x8) |
| `/bypass-403` | `/bypass-403 <url>` — try header/method/encoding tricks against a 403/401 |
| `/arsenal` | `/arsenal [tool]` — list installed external tools or get an install hint |
| `/scan-cves` | `/scan-cves <host>` — focused nuclei CVE sweep (high/critical) + optional log4j-scan |
| `/wordlist-gen` | `/wordlist-gen <target>` — company-specific password wordlist (cewler + hashcat); requires --with-credential-attack |
| `/osint-employees` | `/osint-employees <target>` — employee names + emails (theHarvester + username-anarchy, opt-in LinkedIn); requires --with-credential-attack |
| `/breach-check` | `/breach-check <wordlist>` — HIBP k-anonymity rank wordlist by real-world breach count |
| `/spray` | `/spray <url> --mode http-form|oauth|o365|okta --users <f> --passes <f>` — password spray with hard guards |
<!-- GENERATED:commands:END -->

### Agents (13 specialized agents)

<!-- GENERATED:agents:START (see docs/manifest.json — run scripts/gen_docs.py) -->
- `recon-agent` — Subdomain enum + live host discovery
- `js-intelligence` — Mines JS bundles/source maps for hidden endpoints, feature flags, debug routes, leaked config, auth flows
- `vulnerability-intelligence` — Builds the memory-driven intelligence briefing (tech→vuln affinity, known chains, don't-retry list) before ranking; writes learned failed-patterns/chains back after a hunt
- `hypothesis-engine` — Synthesizes recon + JS intel + memory + the attack graph into ranked, evidence-backed vulnerability hypotheses before any testing starts
- `report-writer` — Generates H1/Bugcrowd/Immunefi reports; validates exploitability/impact/evidence first and checks report-outcome acceptance history
- `validation-engine` — Technical proof gate before validator: reproducibility, proven impact, authorization boundary crossed, clean PoC, duplicate/noise against hunt memory
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — Smart contract bug class analysis
- `chain-builder` — Builds A→B→C exploit chains, memory-first (chains.jsonl + lead-board graph before the static table), saves every chain it confirms
- `autopilot` — Autonomous hunt loop (scope→recon→rank→hunt→validate→report), decision-engine-driven priority scoring, experiment-tracked stop/pivot decisions
- `recon-ranker` — Scored, confidence-rated attack surface ranking from recon output + hypotheses + the intelligence briefing + lead-board chains, plus Expected Value per Hour per candidate
- `token-auditor` — Fast meme coin/token rug pull and security analysis
- `credential-hunter` — Orchestrates wordlist-gen + osint-employees + breach-check; HARD STOPS at spray for human go/no-go
- `research-director` — Turns the lead board + browser intelligence into an executable, time-boxed research plan with EV/hour ordering, mandatory falsifiers, dependency-aware scheduling, and an explicit SKIPPED negative-space section
<!-- GENERATED:agents:END -->

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

<!-- GENERATED:tools:START (see docs/manifest.json — run scripts/gen_docs.py) -->
- `tools/hunt.py` — Master hunt orchestrator — chains target selection, recon, scanning, and reporting
- `tools/recon_engine.sh` — Subdomain + URL discovery pipeline (subfinder/amass/crt.sh/wayback/httpx/nmap/gau), optional nuclei phase
- `tools/vuln_scanner.sh` — XSS/SQLi/SSTI/MFA/SAML probe pipeline with verified PoC generation
- `tools/validate.py` — Interactive 4-gate finding validator + CVSS 4.0 scorer + report skeleton; headless via --non-interactive
- `tools/validation_core.py` — Pure, headless 4-gate validation logic + CVSS 4.0 calculator (dict in/out, zero I/O) — the single implementation validate.py wraps
- `tools/learn.py` — Fetches recent bug intelligence for a tech stack from GitHub Advisories, NVD CVE API, and HackerOne Hacktivity
- `tools/intel_engine.py` — On-demand intel fetch for a target — wraps learn.py + HackerOne MCP + hunt memory context
- `tools/scope_checker.py` — Deterministic scope safety checker — anchored allowlist/blocklist matching before any outbound request
- `tools/scope_aggregator.sh` — Multi-platform in-scope asset pull (bbscope + bounty-targets-data dump)
- `tools/secrets_hunter.sh` — trufflehog/noseyparker/gitleaks wrapper for filesystem/git/JS-bundle/GitHub-org secret scanning
- `tools/takeover_scanner.sh` — dnsReaper/subjack subdomain-takeover scanner with built-in fingerprint-grep fallback
- `tools/cloud_recon.sh` — S3Scanner + cloud_enum + CloudFail wrapper for public bucket discovery and CloudFlare-bypass origin IPs
- `tools/param_discovery.sh` — Arjun/x8 hidden-parameter discovery
- `tools/bypass_403.sh` — byp4xx wrapper + built-in 403/401 bypass matrix (header/method/encoding tricks)
- `tools/cve_scan.sh` — Focused nuclei CVE-tag sweep + optional log4j-scan
- `tools/external_arsenal.sh` — Installed-tool registry (~50 tools); other scripts source this for _have <tool>
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/token_scanner.py` — Deterministic token red-flag scanner for meme coin rug vectors (EVM Solidity + Solana Rust/Anchor)
- `tools/wordlist_engine.sh` — Company-specific password wordlist generator (cewler crawl + hashcat mutation rules)
- `tools/osint_employees.sh` — Employee names + email patterns for spray prep (theHarvester + username-anarchy, opt-in CrossLinked)
- `tools/breach_checker.py` — HIBP k-anonymity wordlist enrichment; ranks passwords by real-world breach count (no API key)
- `tools/spray_orchestrator.sh` — Password spray with typed-hostname guard + lockout warning + audit log; modes http-form/oauth/o365/okta
- `tools/graphql_audit.sh` — 7-phase GraphQL audit: introspection, graphw00f fingerprint, clairvoyance field discovery, batching DoS, alias bomb, gqlmap injection, graphql-cop checklist
- `tools/lead_board.py` — Persistent per-target lead ledger that routes every recon observation to the right hunt-* skill and tracks status so no lead is forgotten; auto chain/hypothesis detection
- `tools/banner.py` — Shared CLI banner (ASCII logo + gradient) imported by every tool's --help/startup output
- `tools/banner.sh` — Shell-sourced equivalent of banner.py for the .sh tools
- `tools/h1_idor_scanner.py` — HackerOne-specific IDOR scanner — probes GraphQL/REST endpoints with two attacker session tokens
- `tools/h1_mutation_idor.py` — HackerOne mutation-IDOR tester — cross-account report mutation probes (title/status/bounty/assignee changes)
- `tools/h1_oauth_tester.py` — HackerOne OAuth/CORS/redirect/token-reuse probe suite
- `tools/h1_race.py` — HackerOne race-condition tester — parallel-threaded GraphQL/REST requests
- `tools/h1_run.sh` — Hand-edit-and-run orchestrator wiring tokens into h1_idor_scanner/h1_oauth_tester/h1_race
- `tools/hai_browser_recon.js` — DevTools console snippet that intercepts Hai's (HackerOne AI) GraphQL requests to map its API surface
- `tools/hai_payload_builder.py` — Generates LLM/agentic-AI attack payloads (prompt injection, exfil channels, ASCII smuggling) by category
- `tools/hai_probe.py` — Probes HackerOne's Hai AI assistant via api.hackerone.com for IDOR/prompt-injection/fingerprinting
- `tools/memory_gc.py` — CLI for memory/rotation.py — inspect/rotate/purge hunt-memory JSONL files
- `tools/mindmap.py` — Generates a pre-hunt reconnaissance checklist/mind-map Markdown file for a target
- `tools/multipart_mutator.py` — Builds and optionally sends mutated multipart/form-data upload requests (file-upload bypass fuzzing)
- `tools/sneaky_bits.py` — Invisible Unicode steganography encode/decode (variation selectors) for prompt-injection PoCs
- `tools/target_selector.py` — Fetches HackerOne + bounty-targets-data program listings and selects/saves top targets to hunt
- `tools/waf_encoder.py` — WAF-bypass payload encoder — URL/unicode-escape/HTML-entity/SQL-comment-injection transforms
- `tools/waf_response_analyzer.py` — Classifies WAF-block vs application responses; diffs and calibrates baselines for bypass confirmation
- `tools/zero_day_fuzzer.py` — curl-based HTTP fuzzing probes against a target or a recon-dir's URL list
- `tools/zendesk_idor_test.py` — Zendesk-specific IDOR/broken-access-control tester — cross-org API data access probes
- `tools/auth_session.py` — Auth-session layer — loads credentials once (env vars, .env, or flags) and plumbs them through a hunt
- `tools/credential_store.py` — Secure credential store — loads auth credentials from a gitignored .env file, never persisted elsewhere
- `tools/dashboard.py` — Live ANSI TUI dashboard for /recon and /hunt phase progress
- `tools/recon_adapter.py` — Canonical recon output normalizer — reads either recon_engine.sh's nested or a flat directory format
- `tools/browser_recon.py` — Browser intelligence layer — Playwright-optional source-map recovery + hidden-endpoint discovery for SPA targets; cookies/storage/auth-header values are never stored, only a one-way value_fingerprint (sha256[:16]) for cross-host credential-sharing detection
- `tools/director.py` — Research Director — turns lead-board + browser-intelligence + attack-graph leads into an executable, falsifiable, time-boxed plan via priority_score()/expected_value_per_hour(); writes recon/<target>/hunt-plan.md + a hunt-plan.json sidecar for cross-process replan
- `tools/fingerprint.py` — Target Intelligence (Phase 3) — consolidates Phase 1 browser/*.json + recon_engine.sh's httpx tech-detect output into recon/<target>/fingerprint.json (framework/version/confidence, infra CDN/WAF, api_style, CVEs from tech_attack_matrix.json); syncs tech_stack into memory_dir/targets/<target>.json for director.py's load_tech_stack()
- `tools/tech_attack_matrix.json` — Static per-framework/version-range vulnerability weight + CVE table (extends mindmap.py's TECH_CHECKS); read by fingerprint.py and optionally passed to priority_score() as a cold-start technology_match floor
<!-- GENERATED:tools:END -->

### Hunt Memory (in `memory/`)

<!-- GENERATED:memory:START (see docs/manifest.json — run scripts/gen_docs.py) -->
- `memory/pattern_db.py` — Cross-target pattern learning — successful techniques indexed by vuln class + tech stack (JSONL)
- `memory/vuln_intelligence.py` — CANONICAL decision engine — priority_score(), expected_value_per_hour(), duplicate_or_noise_check(), hypothesis_calibration(), tech→vuln affinity, self-learning acceptance-rate blending
- `memory/experiment_memory.py` — Granular per-payload-attempt log beneath patterns/failed_patterns — payload_category_affinity(), should_stop() (5-min-rule), suggest_pivot()
- `memory/audit_log.py` — Append-only outbound-request audit log, rate limiter, and circuit breaker for autopilot sessions
- `memory/rotation.py` — Size-based JSONL rotation (10MB cap, keep 3 backups), auto-fired on every append
- `memory/schemas.py` — Schema validation for all hunt-memory JSONL entry types (schema_version for migrations)
- `memory/finding_state.py` — Finding lifecycle state machine — SUSPECTED→TESTING→VALIDATED→CONFIRMED→REPORT_READY (+REJECTED), append-only transition log
- `memory/finding_score.py` — Ranks raw scanner-output lines using vuln_intelligence.priority_score() as the single scoring formula — not yet wired to brain.py
- `memory/attack_graph.py` — Typed capability graph (Asset/Endpoint/Credential/Capability/Boundary/Impact nodes) built from lead-board leads + browser intelligence, including cross-host bridging via matching cookie/storage/header value_fingerprint across two hosts; bounded N-leg DFS path search with provenance and contradiction-aware edge confidence; path_score() reuses vuln_intelligence's impact/time tables; top_paths() wired into director.py's build_plan() alongside board/browser-intel leads
<!-- GENERATED:memory:END -->

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification, AI-security skill repos
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables distilled from HowToHunt + HolyTips + AllAboutBugBounty + KingOfBugBountyTips

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

## Start Here

```bash
Codex
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

Install for another harness:

```bash
./install.sh --agent opencode          # ~/.config/opencode/skills + commands + agents
./install.sh --agent pi                # ~/.pi/agent/skills + prompt templates
./install.sh --agent codex             # ~/.codex/skills + commands
./install.sh --agent agents            # ~/.agents/skills shared by OpenCode/Pi
./install.sh --agent all               # every supported global target
./install.sh --agent opencode --project # local .opencode/ install
./install.sh --agent pi --project       # local .pi/ install
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
