# TODOS

Items deferred from the MCP-First Bionic Hunter design review (2026-03-24).

---

## ~~TODO-1: Secure credential handling for hunt sessions~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `tools/credential_store.py` — loads credentials from `.env` file (already in `.gitignore`). Values never appear in `repr()`/`str()`, masked output via `get_masked()`, auth header builder via `as_headers()`. 15 tests in `tests/test_credential_store.py`.

**What:** Auth credentials (API keys, cookies, Bearer tokens) passed to `/hunt` or `/autopilot` via Bash env vars or direct input persist in the Claude Code conversation transcript. Anyone with access to `~/.claude/projects/` can read them.

**Why:** This is a security gap — bug bounty hunters handle target auth tokens that grant access to real production accounts. Leaking these via conversation history is a liability.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-2: Safe HTTP method policy for autopilot --yolo mode~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `SafeMethodPolicy` class in `memory/audit_log.py`. Default safe methods: GET/HEAD/OPTIONS. PUT/DELETE/PATCH/POST return `require_approval`. Configurable via `safe_methods` set, disableable via `enabled=False`. 12 tests in `tests/test_safe_method_policy.py`. Integrated into `AutopilotGuard`.
## ~~TODO-2: Safe HTTP method policy for autopilot --yolo mode~~ ✅ RESOLVED

**Resolved in:** `agents/autopilot.md` Safety Rails section
> PUT/DELETE/PATCH require human approval in --yolo mode (safe_methods_only enforced).

---

## TODO-2: Safe HTTP method policy for autopilot --yolo mode

**What:** `/autopilot --yolo` could send PUT/DELETE/PATCH to production endpoints. Even if the target is in-scope, destructive HTTP methods on production data create legal liability and could harm the target.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-3: Circuit breaker for autopilot loop~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `AutopilotGuard` class in `memory/audit_log.py` — integrates existing `CircuitBreaker` + `RateLimiter` + new `SafeMethodPolicy` into a single `check_request()` call. Returns structured decisions: `allow`, `block` (circuit tripped), or `require_approval` (unsafe method). Extracts host from URL automatically. 24 tests in `tests/test_autopilot_guard.py`.
## ~~TODO-3: Circuit breaker for autopilot loop~~ ✅ RESOLVED

**Resolved in:** `agents/autopilot.md` Circuit Breaker section
> 5 consecutive 403/429/timeout → paranoid/normal modes ask human; yolo auto-backs off 60s then skips host.

---

## TODO-3: Circuit breaker for autopilot loop

**What:** If autopilot hits repeated errors (403 WAF blocks, rate limit 429s, connection timeouts), it has no mechanism to pause, back off, or stop. It will keep burning requests and potentially trigger IP bans.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-4: Fix hunt.py BASE_DIR path resolution~~ ✅ RESOLVED (2026-04-16)

**Resolution:** `hunt.py` was moved from repo root to `tools/` — `TOOLS_DIR` and `BASE_DIR` now resolve correctly via single `os.path.dirname` chain. Verified: `BASE_DIR` matches repo root exactly.
## ~~TODO-4: Fix hunt.py BASE_DIR path resolution~~ ✅ RESOLVED

**Resolved in:** `tools/hunt.py` lines 25-26
> `hunt.py` lives in `tools/`, so `TOOLS_DIR = dirname(abspath(__file__))` and `BASE_DIR = dirname(TOOLS_DIR)` correctly resolves to the repo root. The TODO description assumed the file was at repo root — it is not.

---

## TODO-4: Fix hunt.py BASE_DIR path resolution

**What:** `hunt.py` line 1 uses `BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))` which goes 2 levels up. But `hunt.py` is at repo root, so `BASE_DIR` points to the parent of the repo — all derived paths (TOOLS_DIR, RECON_DIR, FINDINGS_DIR) resolve to wrong locations.

**Why:** This is a latent bug — any code path that uses these directories will fail silently or write to unexpected locations.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-6: Auto-memory at hunt session end~~ ✅ RESOLVED (2026-04-16)

**Resolution:** Added `make_session_summary_entry()` to `memory/schemas.py` and `log_session_summary()` to `memory/hunt_journal.py`. Both `agents/autopilot.md` and `commands/hunt.md` now instruct the agent to call `log_session_summary()` at session end. Entries are tagged `auto_logged` + `session_summary` and are non-fatal on failure. 11 new tests in `tests/test_hunt_journal.py`.

**What:** `/remember` is currently the only write path into hunt memory. Hunters forget to run it. The memory → hunt feedback loop never spins up in practice. At the end of every `/hunt` and `/autopilot` session, automatically write a journal entry with target, endpoints tested, vuln classes tried, and results. Hunter can still run `/remember` for rich notes (payout, technique, tags).

**Why:** The "memory-informed hunt" promise only works if memory gets populated. Manual `/remember` has ~10% usage rate in practice. Auto-logging makes the flywheel start on day 1.

**Implementation:** Add session summary auto-log to the end of `agents/autopilot.md` and `commands/hunt.md`. Write a minimal journal entry via `HuntJournal.append()`. Fields: target, action=hunt, endpoints_tested list, vuln_classes_tried list, result=session_summary.

**Source:** /autoplan review (2026-04-16)

---

## ~~TODO-7: Memory GC / rotation policy~~ ✅ RESOLVED (2026-04-30)

**Resolution:** Added `memory/rotation.py` — size-based JSONL rotator (10 MB cap, 3 backups) under `fcntl.LOCK_EX`. Wired into `AuditLog.log()` and `PatternDB.save()` so writes auto-rotate transparently. Added `tools/memory_gc.py` + `commands/memory-gc.md` for manual reporting / rotation / backup purge. 22 tests in `tests/test_rotation.py`.

**What:** `journal.jsonl`, `patterns.jsonl`, and `audit.jsonl` grow indefinitely with no rotation or size limit. A `/memory gc` command or automatic rotation at 10MB should be added.

**Why:** On active hunters, audit.jsonl can reach 100MB+ in months. Also, audit.jsonl contains full URL history — worth a size cap and optional purge.

**Source:** /autoplan review (2026-04-16)

---

## TODO-8: Missing test coverage (partially resolved)

**What:** 4 test gaps identified in /autoplan eng review:
1. ✅ Concurrent-write stress test for `AuditLog` (2 cases in `test_rotation.py::TestConcurrentWrites`, 2026-04-30) — `HuntJournal` removed in 97d4efb so no longer applicable
2. ⏳ End-to-end hunt loop integration test (recon → rank → hunt → validate → report as a sequence)
3. ✅ Disk-full OSError propagation test (`test_rotation.py::TestDiskFullPropagation`, 2026-04-30)
4. ⏳ `PatternDB.save()` performance test at 10,000 entries

**Why:** Unit coverage is strong (2,766 lines / 15 files). These 4 gaps cover failure modes that could bite users in production.

**Source:** /autoplan review (2026-04-16)

---

## ~~TODO-5: Define canonical recon output format + legacy adapter~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `tools/recon_adapter.py` — `ReconAdapter` class reads from nested directory format (canonical), with fallback paths for flat-file compat. `normalize()` creates all missing stubs brain.py expects (priority/, api_specs/, urls/graphql.txt, resolved.txt). Builds prioritized_hosts.json and attack_surface.md from live data. 31 tests in `tests/test_recon_adapter.py`.
## ~~TODO-5: Define canonical recon output format + legacy adapter~~ ✅ RESOLVED

**Resolved in:** `tools/recon_adapter.py`
> `load_recon()` auto-detects nested vs flat format and returns a unified `ReconData` object. `normalize_to_nested()` migrates legacy data. All consumers (recon-ranker, memory) should import from `recon_adapter`, never read files directly.

---

## TODO-5: Define canonical recon output format + legacy adapter

**What:** `recon_engine.sh` writes recon output in a nested directory format (`recon/{target}/subdomains.txt`, `recon/{target}/live-hosts.txt`, etc.). The `recon-agent.md` expects flat files. Two conflicting formats with no adapter.

**Source:** Outside voice (eng review, 2026-03-24)
