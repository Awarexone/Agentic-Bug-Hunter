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
