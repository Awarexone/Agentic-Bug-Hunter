# Optimization Roadmap

Living document for skill / tooling improvements. Survives across sessions — any fresh session should read this + [SKILLS_ARCHITECTURE.md](SKILLS_ARCHITECTURE.md) to pick up where we left off.

**How to use:**
- Each item has: status, goal, current state, scope hints, open questions, success criteria
- Items in **Active** are next-up candidates; **Backlog** is "noted but not detailed"; **Done** is shipped
- A fresh session should not start coding an Active item until the *Open questions* are answered
- Add new items to **Backlog** with just the title and a one-line hook; expand into the Active template only when you're ready to work on it

---

## Status legend

- `📋 PLANNING` — captured, not yet detailed enough to execute
- `🎯 READY` — open questions answered, can be picked up
- `🚧 IN PROGRESS` — actively being worked on
- `✅ DONE` — shipped (commit hash recorded)
- `❄️ FROZEN` — paused, not currently a priority

---

## Active items

### 1. Recon result persistence + diff

**Status:** 📋 PLANNING

**Goal:** Each `/recon target.com` run feeds a structured record into hunt memory so the user can: (a) see a diff between runs ("3 new subdomains since last week"), (b) query historical recon from `/intel` or `/pickup`, (c) trigger alerts on new attack surface.

**Current state:**
- [tools/recon_engine.sh](tools/recon_engine.sh) writes raw results to `recon/$TARGET/` (file-based, per-target directory)
- [memory/audit_log.py](memory/audit_log.py), [memory/pattern_db.py](memory/pattern_db.py), [memory/schemas.py](memory/schemas.py) — robust JSONL memory infrastructure already exists
- [commands/remember.md](commands/remember.md) writes `journal.jsonl` + `patterns.jsonl` but is **finding-focused, not recon-focused**
- **Gap:** recon output is on disk but not indexed in memory; no cross-run diff; no "what's new since last recon" alert

**Scope hints (files likely touched):**
- New: `memory/recon_log.py` (or extend audit_log.py) — append recon snapshot to JSONL
- New: `tools/recon_diff.py` — compare two recon snapshots, output new/removed assets
- Modify: `tools/recon_engine.sh` — emit a structured JSON summary at end of run, call recon_log writer
- Modify: [commands/recon.md](commands/recon.md) — add post-run "X new subdomains since YYYY-MM-DD" line
- Modify: [commands/intel.md](commands/intel.md) — surface new assets in intel output
- Schema extension: [memory/schemas.py](memory/schemas.py) — add ReconSnapshot schema

**Open questions:**
1. **Granularity:** snapshot per asset type (subdomains, live hosts, URLs, JS files) or one big blob per run?
2. **Diff trigger:** automatic on every `/recon` run, or opt-in via `/recon --diff`?
3. **Retention:** keep all snapshots forever, or rotate (the existing rotation.py caps at 10MB / 3 backups)?
4. **Alert UX:** silent log entry, or interrupt with "🚨 5 new subdomains found"?

**Success criteria:**
- Run `/recon target.com` twice with a faked subdomain added between runs → second run announces the new subdomain
- `/intel target.com` shows "last recon: 2 days ago, +3 new assets"
- Memory file under 10MB after 30 daily recon runs (rotation kicks in)

**Notes:**
- Heavy reuse opportunity: existing `pattern_db.py` and `audit_log.py` give us schema validation, rotation, and append-safety for free
- Aligns with user's broader "knowledge update pipeline" idea (Direction C from SKILLS_ARCHITECTURE.md §7)

---

### 2. WAF bypass skill expansion

**Status:** 📋 PLANNING

**Goal:** Make WAF bypass a first-class capability. A hunter facing Cloudflare / Akamai / AWS WAF / Imperva / F5 should get tier-1 guidance from `security-arsenal` immediately, with payload mutations, encoding tricks, fragmentation, origin-IP discovery, and rate-limit evasion — covering 80% of real-world WAF encounters in 2024-2025.

**Current state:**
- [skills/security-arsenal/SKILL.md:165](skills/security-arsenal/SKILL.md) has a `### WAF Bypass` section — appears thin (single section in an 838-line file)
- Only 8 total mentions of "WAF" across all 9 skills (5 in bb-methodology, 2 in bug-bounty, 1 in security-arsenal)
- **Gap:** for a domain where most targets sit behind some WAF, this is severely under-covered. Likely the highest-leverage single-skill deep dive (Direction B from SKILLS_ARCHITECTURE.md §7)

**Scope hints (files likely touched):**
- Heavy: [skills/security-arsenal/SKILL.md](skills/security-arsenal/SKILL.md) — expand WAF section to ~150-300 lines covering:
  - WAF fingerprinting (wafw00f, headers, error pages, CSP)
  - Per-vendor bypass tables (Cloudflare / Akamai / AWS WAF / Imperva / F5 / Sucuri)
  - Encoding chains (URL → unicode → HTML entity → base64 → mixed case → null bytes)
  - HTTP-level evasion (verb tampering, version downgrade, parameter pollution, chunked encoding, request smuggling angles)
  - Origin IP discovery (Censys, Shodan, historical DNS, SSL cert fingerprint, mail headers, dev/staging subdomains)
  - Rate-limit bypass (X-Forwarded-For, X-Real-IP, distributed sources, slow-rate)
- Light: cross-link from [skills/web2-vuln-classes/SKILL.md](skills/web2-vuln-classes/SKILL.md) IDOR / SSRF / SQLi / XSS sections to the new WAF section
- Maybe new: `docs/payloads.md` already exists (39KB) — possibly inline a "WAF Bypass Cookbook" section there for long-form examples
- Update: [skills/security-arsenal/SKILL.md](skills/security-arsenal/SKILL.md) frontmatter `description:` — add WAF bypass triggers in trigger word list

**Open questions:**
1. **Format:** one big WAF section in security-arsenal, or split into `skills/security-arsenal/SKILL.md` (overview + payloads) + `docs/waf-bypass.md` (long-form cookbook)?
2. **Vendor coverage depth:** equal weight to all 5 major WAFs, or 80/20 (Cloudflare + Akamai = most encounters)?
3. **Tooling integration:** add `tools/waf_fingerprint.sh` (wrap wafw00f + custom checks)? Or skill-only?
4. **Source material:** which 2024-2025 disclosed bypasses to cite? (HackTricks, PortSwigger research, public PoCs)

**Success criteria:**
- WAF section grows from ~1 page to comprehensive reference with per-vendor bypass table
- Hunter facing "all my payloads return 403" can find a recipe to try in <30 seconds
- 5 disclosed Cloudflare/Akamai bypass examples (2024-2025) cited with payload and outcome
- `security-arsenal` description triggers correctly on prompts like "blocked by Cloudflare", "WAF rejecting payloads", "how to find origin IP"

**Notes:**
- This is the user's flagship deep-dive candidate — improvement here directly translates to more bugs found on real targets
- Builds on existing `security-arsenal` so no new skill-domain creation needed (preserves architecture)

---

### 3. CVE intel — additional sources and richer matching

**Status:** 📋 PLANNING

**Goal:** Strengthen `/intel` output by pulling from more CVE sources beyond NVD + GitHub Advisories, attaching exploit URLs / PoC references, and improving version-fingerprint → CVE matching.

**Current state:**
- [tools/learn.py](tools/learn.py) — already wraps NVD (`fetch_nvd_cves`) + GitHub Security Advisories (`fetch_github_advisories`)
- [tools/intel_engine.py](tools/intel_engine.py) — combines learn.py + HackerOne MCP + hunt memory
- [commands/intel.md](commands/intel.md) — `/intel target.com` command, displays prioritized intel
- HackerOne MCP at [mcp/hackerone-mcp/](mcp/hackerone-mcp/) provides Hacktivity feed
- **Gap:** No exploit-db / Vulners / CVE Search; no PoC URL extraction; version-fingerprint matching is basic (likely string-match)

**Scope hints (files likely touched):**
- Modify: [tools/learn.py](tools/learn.py) — add fetchers for exploit-db, Vulners, CVE Search, possibly Trickest CVE GitHub repo
- Modify: [tools/intel_engine.py](tools/intel_engine.py) — call new fetchers, merge dedup'd CVE list, attach exploit URLs to entries
- Possibly new: MCP wrapper for a CVE source (parallel to hackerone-mcp pattern)
- Modify: [commands/intel.md](commands/intel.md) output format — show "Exploit available: <url>" inline
- Schema: extend CVE entry struct in `intel_engine.py` to include `exploit_urls`, `poc_references`, `actively_exploited` flag (CISA KEV)

**Open questions:**
1. **Sources to add:** which subset of {exploit-db, Vulners, CVE Search, CISA KEV, Trickest CVE, Nuclei templates}? (Free APIs preferred — Vulners has tiered access)
2. **Auth strategy:** which sources need API keys? Where do keys live? (existing pattern: `.env` + Chaos API key precedent)
3. **Fingerprinting depth:** keep current string-match, or add proper version-range comparison (semver/CPE)? Latter is significantly more work
4. **CISA KEV flag:** include "actively exploited in the wild" badge? Adds urgency to intel output but requires fetching kevcatalog
5. **Caching:** current cache strategy? (avoid hammering NVD per `/intel` call)

**Success criteria:**
- `/intel target.com` returns CVEs from at least 3 sources (NVD + GHSA + 1 new)
- High-priority CVEs show exploit URL when available (≥40% coverage on common stacks)
- CISA KEV badge on actively-exploited CVEs
- No degradation in existing `/intel` runtime (caching keeps it sub-5-second for cached targets)

**Notes:**
- Lower visibility than item 2 (WAF bypass) but mechanically straightforward — well-defined APIs, clear success metric
- Heavy reuse: existing `intel_engine.py` orchestration is the right place to plug new fetchers in

---

## Backlog (titles only — expand when ready to work on)

*(empty — add new items here as they come up)*

---

## Done

- **2026-05-05** — `docs/SKILLS_ARCHITECTURE.md` created (commit `213f546`). Plugin's responsibility matrix + drift inventory. Source of truth for "what each skill is for."

---

## How to add a new item

Copy this template into `## Active items` (or `## Backlog` for quick capture):

```markdown
### N. <short title>

**Status:** 📋 PLANNING

**Goal:** <one-paragraph success-state description>

**Current state:**
- <file:line refs to existing infrastructure>
- **Gap:** <what's missing>

**Scope hints (files likely touched):**
- <bullet list of paths>

**Open questions:**
1. <each question must be answered before status flips to 🎯 READY>

**Success criteria:**
- <observable, testable>

**Notes:**
- <design tensions, alternatives considered, related items>
```
