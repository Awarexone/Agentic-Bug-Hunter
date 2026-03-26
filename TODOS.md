# TODOS

Items deferred from the MCP-First Bionic Hunter design review (2026-03-24).

---

## TODO-1: Secure credential handling for hunt sessions

**What:** Auth credentials (API keys, cookies, Bearer tokens) passed to `/hunt` or `/autopilot` via Bash env vars or direct input persist in the Claude Code conversation transcript. Anyone with access to `~/.claude/projects/` can read them.

**Why:** This is a security gap — bug bounty hunters handle target auth tokens that grant access to real production accounts. Leaking these via conversation history is a liability.

**Pros:** Eliminates a class of credential exposure. Builds trust with security-conscious users.

**Cons:** Adds complexity to credential flow. May require Claude Code platform features (secure input) that don't exist yet.

**Context:** The design stores auth cookies "as Python variables within the autopilot agent's execution context — never written to hunt-memory files." But Claude Code's conversation transcript captures all Bash inputs/outputs. Mitigation options: (a) read credentials from a `.env` file that's `.gitignore`d, (b) use `read -s` for interactive input so the value doesn't echo, (c) document the risk and recommend short-lived tokens.

**Depends on:** Nothing — can be addressed independently. Should be resolved before Phase 3 (autopilot) ships.

**Source:** Outside voice (eng review, 2026-03-24)

---

## TODO-2: Safe HTTP method policy for autopilot --yolo mode

**What:** `/autopilot --yolo` could send PUT/DELETE/PATCH to production endpoints. Even if the target is in-scope, destructive HTTP methods on production data create legal liability and could harm the target.

**Why:** Bug bounty programs authorize *testing*, not *modification*. A DELETE that removes real user data is a program violation regardless of scope.

**Pros:** Prevents accidental data destruction. Reduces legal risk for hunters. Aligns with responsible disclosure norms.

**Cons:** May limit testing depth for some vuln classes (e.g., IDOR on DELETE requires actually sending DELETE).

**Context:** Mitigation: add a `safe_methods_only` flag (default: true in --yolo, false in --paranoid). When enabled, autopilot only sends GET/HEAD/OPTIONS automatically. PUT/DELETE/PATCH require explicit human approval via AskUserQuestion, even in --yolo mode. The flag is per-target-profile configurable.

**Depends on:** Phase 3 (autopilot) implementation.

**Source:** Outside voice (eng review, 2026-03-24)

---

## TODO-3: Circuit breaker for autopilot loop

**What:** If autopilot hits repeated errors (403 WAF blocks, rate limit 429s, connection timeouts), it has no mechanism to pause, back off, or stop. It will keep burning requests and potentially trigger IP bans.

**Why:** Runaway loops waste time, trigger WAF bans (which affect the hunter's IP for ALL targets), and generate noise in audit logs.

**Pros:** Prevents IP bans. Saves time on dead-end targets. Keeps audit logs clean.

**Cons:** Adds state tracking to the autopilot agent. False positives (legitimate 403s on auth-required endpoints) could cause premature stops.

**Context:** Implement a simple circuit breaker: if 5 consecutive requests to the same host return 403/429/timeout, pause and ask the human "Getting blocked — continue, back off 5 min, or skip this host?" In --yolo mode, auto-back-off for 60 seconds then retry once. If still blocked, skip the host and move to next P1 target.

**Depends on:** Phase 3 (autopilot) implementation.

**Source:** Outside voice (eng review, 2026-03-24)

---

## TODO-4: Fix hunt.py BASE_DIR path resolution

**What:** `hunt.py` line 1 uses `BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))` which goes 2 levels up. But `hunt.py` is at repo root, so `BASE_DIR` points to the parent of the repo — all derived paths (TOOLS_DIR, RECON_DIR, FINDINGS_DIR) resolve to wrong locations.

**Why:** This is a latent bug — any code path that uses these directories will fail silently or write to unexpected locations.

**Pros:** Fix is trivial (change to single `os.path.dirname`). Prevents future confusion when memory/ module imports hunt.py paths.

**Cons:** None — pure bug fix.

**Context:** The fix is `BASE_DIR = os.path.dirname(os.path.abspath(__file__))`. Verify downstream paths (TOOLS_DIR, RECON_DIR, FINDINGS_DIR) still make sense after the fix. This should be fixed before Phase 1 since the memory module may reference these paths.

**Depends on:** Nothing — standalone fix.

**Source:** Outside voice (eng review, 2026-03-24)

---

## TODO-5: Define canonical recon output format + legacy adapter

**What:** `recon_engine.sh` writes recon output in a nested directory format (`recon/{target}/subdomains.txt`, `recon/{target}/live-hosts.txt`, etc.). The `recon-agent.md` expects flat files. Two conflicting formats with no adapter.

**Why:** When the memory system and recon-ranker read recon output, they need one canonical format. If both formats coexist without an adapter, tools will silently miss data or break.

**Pros:** Single source of truth for recon output. Cleaner integration with recon-ranker and memory.

**Cons:** Requires either updating recon_engine.sh or writing an adapter layer. Existing users may have recon output in the old format.

**Context:** Recommended approach: define the canonical format in `skills/web2-recon/SKILL.md` (the nested directory format from recon_engine.sh is more organized). Add a `recon_adapter.py` that reads either format and normalizes to canonical. The recon-ranker and memory system import from the adapter, never directly from files.

**Depends on:** Should be resolved during Phase 1 (before recon-ranker agent is built).

**Source:** Outside voice (eng review, 2026-03-24)
