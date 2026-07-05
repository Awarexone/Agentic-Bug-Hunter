# Rules

Always-active hunting and reporting rules. Loaded every session — no exceptions.

## Files

| File | Covers |
|:---|:---|
| `hunting.md` | 17 critical hunt rules — scope, safety, 5-minute rule, depth limits |
| `reporting.md` | Report quality rules — impact-first writing, CVSS, never-submit list |

## Core Rules (short version)

1. Read full scope first — only test what the program allows
2. Real bugs only — "Can an attacker do this RIGHT NOW?"
3. Kill weak findings fast — N/A hurts your validity ratio
4. Never go out of scope — one wrong request can get you banned
5. 5-minute rule — no progress after 5 min? move on
6. Validate before report — run `/validate` first
7. Impact first — test the bugs with the worst consequences first
