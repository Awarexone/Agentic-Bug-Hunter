# Changelog

## v3.1.0 — Hunting Methodology Skill (Mar 2026)

### Added — New Skill Domain
- `skills/bb-methodology/SKILL.md`: **Hunting mindset + 5-phase non-linear workflow** — the "HOW to think" layer that was missing from the toolkit
  - **Part 1: Mindset** — Define/Select/Execute discipline, 4 thinking domains (critical, multi-perspective, tactical, strategic), developer psychology reverse-engineering, Amateur vs Pro 7-phase comparison, Feature-based vs Vuln-based route selection, anti-patterns
  - **Part 2: Workflow** — 5-phase non-linear flow (Recon → Map → Find → Prove → Report) with decision trees per phase, input-type → vuln-class routing, Error vs Blind detection cascade, escalation decision trees per vuln class
  - **Part 3: Navigation & Timing** — "I'm stuck because..." quick reference table, 20-minute rotation clock, tool routing by phase with rationale, session start/end checklists

### Changed
- `CLAUDE.md`: Skills count 7 → 8, added `bb-methodology` to skill table
- `README.md`: Updated skill domain count to 8
- `SKILL.md`: Added cross-reference to `bb-methodology` after CRITICAL RULES section

## v2.1.0 — 20 Vuln Classes + Payload Expansion (Mar 2026)

### Config
- Recon commands now read the Chaos API key from the `$CHAOS_API_KEY` environment variable for cleaner setup across different environments.

### Added — New Vuln Classes
- `web2-vuln-classes`: **MFA/2FA Bypass** (class 19) — 7 bypass patterns: rate limit, OTP reuse, response manipulation, workflow skip, race, backup codes, device trust escalation
- `web2-vuln-classes`: **SAML/SSO Attacks** (class 20) — XML signature wrapping (XSW), comment injection, signature stripping, XXE in assertion, NameID manipulation + SAMLRaider workflow

### Added — security-arsenal Payloads
- **NoSQL injection**: MongoDB `$ne`/`$gt`/`$regex`/`$where` operators, URL-encoded GET parameter injection
- **Command injection**: Basic probes, blind OOB (curl/nslookup), space/keyword bypass techniques, Windows payloads, filename injection context
- **SSTI detection**: Universal probe for all 6 engines (Jinja2, Twig, Freemarker, ERB, Spring, EJS) + RCE payloads for each
- **HTTP smuggling payloads**: CL.TE, TE.CL, TE.TE obfuscation variants, H2.CL
- **WebSocket testing**: IDOR/auth bypass messages, CSWSH PoC, Origin validation test, injection via messages
- **MFA bypass payloads**: OTP brute force (ffuf), race async script, response manipulation, device trust cookie test
- **SAML attack payloads**: XSW XML templates, comment injection, signature stripping workflow, XXE payload, SAMLRaider CLI

### Added — web2-recon Skill
- **Setup section**: `$CHAOS_API_KEY` export instructions, subfinder config.yaml with 5 API sources, nuclei-templates update command
- **crt.sh** passive subdomain source (no API key needed) added as Step 0
- **Port scanning**: naabu command for non-standard ports (8080/8443/3000/9200/6379/etc.)
- **Secret scanning**: trufflehog + SecretFinder JS bundle scan, grep patterns
- **GitHub dorking**: `gh search code` commands, GitDorker integration for org-wide secret search

### Added — report-writing Skill
- **Intigriti template**: Full format with platform-specific notes (video PoC preference, safe harbor stance)
- **CVSS 4.0 quick reference**: Key differences from CVSS 3.1, score examples for common findings, calculator link

### Added — rules/hunting.md
- **Rule 18**: Mobile = different attack surface (APK decompile workflow, key targets)
- **Rule 19**: CI/CD is attack surface (GitHub Actions expression injection, dangerous workflow patterns)
- **Rule 20**: SAML/SSO = highest auth bug density (test checklist)

### Updated
- README: CHAOS_API_KEY setup section with free key instructions and optional subfinder API keys
- README: Updated vuln class count from 18 → 20, updated skill descriptions
- `web2-vuln-classes` description updated to reflect 20 classes and new additions

---

## v2.0.0 — ECC-Style Plugin Architecture (Mar 2026)

Major restructure into a full Claude Code plugin with multi-component architecture.

### Added
- `skills/` directory with 7 focused skill domains (split from monolithic SKILL.md)
  - `skills/bug-bounty/` — master workflow (unchanged from v1)
  - `skills/web2-recon/` — recon pipeline, subdomain enum, 5-minute rule
  - `skills/web2-vuln-classes/` — 18 bug classes with bypass tables
  - `skills/security-arsenal/` — payloads, bypass tables, never-submit list
  - `skills/web3-audit/` — 10 smart contract bug classes, Foundry template
  - `skills/report-writing/` — H1/Bugcrowd/Intigriti/Immunefi templates
  - `skills/triage-validation/` — 7-Question Gate, 4 gates, always-rejected list
- `commands/` directory with 8 slash commands
  - `/recon` — full recon pipeline
  - `/hunt` — start hunting a target
  - `/validate` — 4-gate finding validation
  - `/report` — submission-ready report generator
  - `/chain` — A→B→C exploit chain builder
  - `/scope` — asset scope verification
  - `/triage` — quick 7-Question Gate
  - `/web3-audit` — smart contract audit
- `agents/` directory with 5 specialized agents
  - `recon-agent` — runs recon pipeline, uses claude-haiku-4-5 for speed
  - `report-writer` — generates reports, uses claude-opus-4-6 for quality
  - `validator` — validates findings, uses claude-sonnet-4-6
  - `web3-auditor` — audits contracts, uses claude-sonnet-4-6
  - `chain-builder` — builds exploit chains, uses claude-sonnet-4-6
- `hooks/hooks.json` — session start/stop hooks with hunt reminders
- `rules/hunting.md` — 17 critical hunting rules (always active)
- `rules/reporting.md` — 12 report quality rules (always active)
- `CLAUDE.md` — plugin overview and quick-start guide
- `install.sh` — one-command skill installation

### Content Added to Skills
- SSRF IP bypass table: 11 techniques (decimal, octal, hex, IPv6, redirect chain, DNS rebinding)
- Open redirect bypass table: 11 techniques for OAuth chaining
- File upload bypass table: 10 techniques + magic bytes reference
- Agentic AI ASI01-ASI10 table: OWASP 2026 agentic AI security framework
- Pre-dive kill signals for web3: TVL formula, audit check, line-count heuristic
- Conditionally valid with chain table: 12 entries
- Report escalation language for payout downgrade defense

---

## v1.0.0 — Initial Release (Early 2026)

- Monolithic SKILL.md (1,200+ lines) covering full web2+web3 workflow
- Python tools: `hunt.py`, `learn.py`, `validate.py`, `report_generator.py`, `mindmap.py`
- Vulnerability scanners: `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`
- AI/LLM testing: `hai_probe.py`, `hai_payload_builder.py`, `hai_browser_recon.js`
- Shell tools: `recon_engine.sh`, `vuln_scanner.sh`
- Utilities: `sneaky_bits.py`, `target_selector.py`, `zero_day_fuzzer.py`, `cve_hunter.py`
- Web3 skill chain: 10 files in `web3/` directory
- Wordlists: 5 wordlists in `wordlists/` directory
- Docs: `docs/payloads.md`, `docs/advanced-techniques.md`, `docs/smart-contract-audit.md`
