# WAF Bypass Upgrade — Change Summary
Date: 2026-05-12

## Background
AI was stopping at 403 Forbidden responses during bug bounty hunts. This upgrade
adds a systematic bypass pipeline so 403 becomes a checkpoint, not a dead end.

## Agent Architecture Used
- Main Orchestrator (Sonnet 4.6)
- Coordinator (Opus) — planned work breakdown
- Implementation Agent A (Opus) — tools
- Implementation Agent B (Opus) — skills
- Implementation Agent C (Opus) — commands + rules
- Validator (Sonnet) — verified all changes
- Recorder (this file)

## Research Sources
1. Internal gap analysis of existing project (30+ WAF bypass techniques documented, none automated)
2. waf-bypass/ directory: DEVCORE 2024 "牆の調查" (Mico) + React2Shell Vercel CTF (maple3142/Ginoah)
3. External: WAFFLED (ACSAC 2025), HackTricks, PayloadsAllTheThings, Awesome-WAF, PortSwigger

## Key Decisions
1. Coordinator decided to split into 3 parallel agents (Tools/Skills/Commands+Rules) — no file conflicts
2. bypass_403.sh enhanced rather than replaced (preserve byp4xx wrapper for power users)
3. waf_encoder.py and multipart_mutator.py created as standalone Python tools (no 3rd-party deps)
4. 403 kill signal in rules/hunting.md softened: try bypass first, then kill after 5 min
5. Skills references are text-only (not runtime calls) — agents can write references before tools exist

## Files Changed

### New Files
| File | Lines | Purpose |
|---|---|---|
| `tools/waf_encoder.py` | 229 | Multi-layer payload encoder (10 encoding techniques) |
| `tools/multipart_mutator.py` | 271 | Multipart parser confusion (10 DEVCORE 2024 techniques) |

### Enhanced Files
| File | Before | After | Key Changes |
|---|---|---|---|
| `tools/bypass_403.sh` | 99 | 182 | +WAF fingerprint, +19 probes, +vendor-specific bypass |
| `commands/bypass-403.md` | 42 | 75 | +WAF fingerprint section, +encoding tool docs, +multipart tool docs |
| `skills/security-arsenal/SKILL.md` | 838 | 980 | +WAF BYPASS REFERENCE chapter (7 sub-sections) |
| `skills/bb-methodology/SKILL.md` | 359 | ~362 | 403 handling logic updated in 3 places |
| `skills/web2-vuln-classes/SKILL.md` | 851 | ~863 | WAF bypass tips added to 4 vuln classes |
| `rules/hunting.md` | 205 | 206 | Rule 5: 403 → bypass first → kill after 5 min |
| `commands/hunt.md` | 274 | 316 | Phase 1.5 WAF Fingerprint + 403 Response Protocol |
| `commands/recon.md` | 148 | 149 | Phase 2.5 wafw00f fingerprint |

## Validation Results
- bash -n syntax check: PASS
- Python AST parse: PASS
- waf_encoder.py smoke test: 31 sqli variants generated
- multipart_mutator.py smoke test: 10 .raw files generated
- Cross-file consistency (tool names, flag syntax, spelling): PASS
- 3 WARNING-level issues found and fixed (description text, decision tree numbers, duplicate function call)
- 0 FAIL-level issues

## 403 Response Flow (After Upgrade)

```
403 received
  |
/bypass-403 <url>  (tools/bypass_403.sh)
  |-- WAF fingerprint (cf-ray/x-amzn/incap_ses/TS-cookie)
  |-- 38 probe matrix (17 IP headers + 15 paths + 6 methods)
  +-- Vendor-specific bypass (Cloudflare/AWS/Imperva/F5)
       |
       v still 403
tools/waf_encoder.py "<payload>" --class sqli|xss
  +-- 30+ encoded variants
       |
       v still 403 (upload endpoint)
tools/multipart_mutator.py --file shell --field f --send
  +-- 10 DEVCORE parser-confusion variants
       |
       v still 403 (Cloudflare)
Origin IP hunt (crt.sh + Shodan + SecurityTrails)
  +-- Direct connect bypassing WAF
       |
       v 5 min total elapsed
Kill target, move to next surface
```

---

## v2 — Soft Block Detection (2026-05-12)

**Problem discovered:** Original bypass logic used HTTP status code as the only oracle.
WAFs return 200 OK with block pages ("soft blocks"), making status-only checks unreliable.

**Root cause:** HTTP-status oracle is a broken oracle against adversarial WAFs.
Correct oracle = differential response analysis (distance from block baseline).

**Changes:**

### `tools/bypass_403.sh` (P0 bash patch)
- Added `_sample_block_baseline()` — samples WAF block response with known-bad XSS payload
- Added `_is_real_bypass()` — 3-check verdict: status whitelist + body signature regex + length diff vs BB
- Added `_extract_log_ids()` — extracts CF-Ray/Support-ID/Incident-ID/ModSec-Rule-ID from body
- Added `_classify_with_analyzer()` — delegates to Python analyzer when available, bash fallback otherwise
- **Expanded status whitelist to include 401, 500, 502, 503** (backend-reached signals)
- Probe loop now captures body to tmpfile, uses verdict system (bypassed/needs_review/blocked)
- Vendor-specific case blocks also updated to use body-aware verdict
- New output file: `bypass_uncertain.txt` for needs_review cases

### `tools/waf_response_analyzer.py` (P1 new file)
- Full baseline calibration (BB from known-bad probes + NB from /robots.txt etc.)
- WAFSignatureDB: 12 vendor regex sets (Cloudflare/AWS/Imperva/Akamai/F5/ModSec/Sucuri/FortiWeb/Barracuda/Wallarm/360/Wordfence)
- ResponseClassifier: weighted score engine (block_score → verdict)
- LogIDExtractor: 7 ID types extracted + generic pattern
- CLI: --calibrate / --classify / --diff

### Skill / Command / Rule updates
- `security-arsenal`: Added "Soft Block Detection" section with verdict table, 401/500 explanation, log ID value
- `bb-methodology`: Updated 403 handling to mention soft blocks + 200 OK ambiguity
- `commands/bypass-403.md`: Added Verdict System section

### Key design decisions
1. Block baseline via known-bad XSS probe (not synthetic) — real WAF response
2. 3-verdict not binary: `needs_review` prevents both false-positive and false-negative
3. Python analyzer is optional — bash fallback ensures tool works without Python
4. 401/500 as bypass signals — critical insight missed in v1
5. Log ID extraction for report quality improvement

