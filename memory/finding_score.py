"""
Finding-score wrapper — ranks raw scanner-output lines using
memory.vuln_intelligence.priority_score() as the single scoring formula.

Problem this solves: brain.py's `_finding_score()` re-derives "how much does
this vuln class matter" from its own hand-rolled static table (rce=100,
sqli=85, ...) instead of asking the canonical decision engine, which already
knows about tech-stack affinity, historical success rate, chain probability,
and failed-pattern hard-kills. That's the exact kind of second, independently
-drifting formula priority_score() was built to prevent.

Design note (read before "fixing" the line_signal table below): priority_score()
answers a category-level question — "how much should we prioritize the
`idor` vuln class on this target" — it has no visibility into individual
scanner-output line text, so every line sharing a category gets an identical
result from it. That's correct, not a bug. But brain.py's original function
also needed to tell a confirmed `uid=root` command-injection proof apart from
a bare, unconfirmed same-category hit — a real signal that has nothing to do
with vuln-class economics. `_line_signal()` below is that signal. It is NOT a
priority or EV score (it is never labeled "priority" or "score", only
"line_signal"), and it is structurally incapable of outranking priority_score()
across categories: rank_findings() sorts on (priority_score, line_signal) in
that order, so line_signal only ever breaks ties *within* an
already-priority_score()-decided bucket.

Pure library + thin CLI: no input(), no prompts, JSON in/out — callable by
Claude Code agents that only have bash (via the CLI) and by brain.py/agent.py
(via direct import), same convention as memory/vuln_intelligence.py's own CLI.
"""

import argparse
import json
from pathlib import Path

from memory.vuln_intelligence import priority_score

# Mirrors agent.py's `_VULN_SCAN_SUBDIRS` (agent.py:487-493) — the mapping
# from vuln_scanner.sh's raw output-subdirectory names to the canonical
# vuln_class strings priority_score()/VULN_IMPACT_POTENTIAL already use.
# Reused here rather than re-invented so brain.py's finding-triage path and
# agent.py's experiment-logging path agree on what each category means.
# Extended with three categories agent.py's table doesn't need but brain.py's
# finding-collection does: rce, sqlmap (sqlmap output IS sqli evidence, so it
# folds into the same affinity bucket instead of fragmenting the data), cms.
SCANNER_CATEGORY_ALIASES: dict[str, str] = {
    "upload": "file-upload", "xss": "xss", "sqli": "sqli", "takeover": "misconfig",
    "misconfig": "misconfig", "exposure": "info-disclosure", "ssrf": "ssrf",
    "cves": "misconfig", "redirects": "open-redirect", "idor": "idor",
    "auth_bypass": "auth-bypass", "lfi": "lfi", "ssti": "ssti", "graphql": "graphql",
    "cors": "cors", "jwt": "auth-bypass", "smuggling": "misconfig", "cloud": "misconfig",
    "rce": "rce", "sqlmap": "sqli", "cms": "misconfig",
}


def normalize_vuln_class(category: str) -> str:
    """Map a raw scanner-output category name to the canonical vuln_class
    priority_score()/VULN_IMPACT_POTENTIAL use. Unknown categories pass
    through lowercased so priority_score()'s own DEFAULT_IMPACT_POTENTIAL
    handles them rather than this module guessing at a value."""
    return SCANNER_CATEGORY_ALIASES.get(category.lower(), category.lower())


# See module docstring: a bounded, line-text tiebreaker, not a priority/EV
# formula. Ported from brain.py's original _finding_score() keyword-bonus
# table (values unchanged) since that half of the old logic was genuinely
# about line-level evidence strength, not vuln-class prioritization.
_LINE_SIGNAL_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("rce", 40), ("injectable", 35), ("unauth", 30), ("idor", 28),
    ("sqli", 28), ("ssrf", 26), ("takeover", 20), ("default creds", 18),
    ("exposed", 18), ("critical", 15), ("[high]", 10), ("cve-", 25),
    ("uid=", 25), ("meterpreter session", 40),
)
_HTTP_URL_BONUS = 8


def _line_signal(line: str) -> int:
    """Bounded [0, sum(all keyword bonuses) + 8] text-tiebreaker score."""
    lower = (line or "").lower()
    signal = sum(bonus for token, bonus in _LINE_SIGNAL_KEYWORDS if token in lower)
    if "http://" in lower or "https://" in lower:
        signal += _HTTP_URL_BONUS
    return signal


def score_finding(
    category: str,
    line: str,
    tech_stack: list[str],
    target: str,
    patterns: list[dict] | None = None,
    failed_patterns: list[dict] | None = None,
    chains: list[dict] | None = None,
    chain_detected: bool = False,
    report_outcomes: list[dict] | None = None,
) -> dict:
    """Score one (category, line) finding candidate. `priority` is the
    unmodified return of memory.vuln_intelligence.priority_score() — the one
    formula. `line_signal` is the bounded text-tiebreaker (see module
    docstring); it is deliberately not part of `priority`."""
    vuln_class = normalize_vuln_class(category)
    priority = priority_score(
        vuln_class=vuln_class,
        tech_stack=tech_stack,
        target=target,
        patterns=patterns,
        failed_patterns=failed_patterns,
        chains=chains,
        chain_detected=chain_detected,
        report_outcomes=report_outcomes,
    )
    line_signal = _line_signal(line)
    return {
        "category": category,
        "vuln_class": vuln_class,
        "line": line,
        "priority": priority,
        "line_signal": line_signal,
        "sort_key": [priority["score"], line_signal],
    }


def rank_findings(
    candidates: list[dict],
    tech_stack: list[str],
    target: str,
    patterns: list[dict] | None = None,
    failed_patterns: list[dict] | None = None,
    chains: list[dict] | None = None,
    chain_detected: bool = False,
    report_outcomes: list[dict] | None = None,
    top_n: int = 25,
) -> list[dict]:
    """Score and rank a batch of {"category": ..., "line": ...} candidates,
    highest priority_score() first, line_signal as tiebreaker, capped at
    top_n — the same "top 25" contract brain.py's _collect_candidate_findings()
    uses today.

    priority_score() is memoized per distinct vuln_class within this call
    (it depends only on vuln_class/tech_stack/target/memory, never on the
    individual line), so a batch of N lines across K categories costs K
    calls into the canonical formula, not N.
    """
    priority_cache: dict[str, dict] = {}
    scored: list[dict] = []

    for candidate in candidates:
        category = candidate["category"]
        line = candidate["line"]
        vuln_class = normalize_vuln_class(category)

        if vuln_class not in priority_cache:
            priority_cache[vuln_class] = priority_score(
                vuln_class=vuln_class,
                tech_stack=tech_stack,
                target=target,
                patterns=patterns,
                failed_patterns=failed_patterns,
                chains=chains,
                chain_detected=chain_detected,
                report_outcomes=report_outcomes,
            )
        priority = priority_cache[vuln_class]
        line_signal = _line_signal(line)
        scored.append({
            "category": category,
            "vuln_class": vuln_class,
            "line": line,
            "priority": priority,
            "line_signal": line_signal,
            "sort_key": [priority["score"], line_signal],
        })

    scored.sort(key=lambda item: (item["sort_key"][0], item["sort_key"][1]), reverse=True)
    return scored[:top_n]


# ─── CLI — for agents that only have bash/read/glob/grep tools ──────────────

def _memory_lists(memory_dir: str) -> dict:
    from memory.pattern_db import PatternDB
    from memory.vuln_intelligence import ChainDB, FailedPatternDB, ReportOutcomeDB

    base = Path(memory_dir)
    return {
        "patterns": PatternDB(base / "patterns.jsonl").read_all(),
        "failed_patterns": FailedPatternDB(base / "failed_patterns.jsonl").read_all(),
        "chains": ChainDB(base / "chains.jsonl").read_all(),
        "report_outcomes": ReportOutcomeDB(base / "report_outcomes.jsonl").read_all(),
    }


def _tech_list(raw: str) -> list[str]:
    return [t.strip() for t in raw.split(",") if t.strip()]


def _cmd_score(args: argparse.Namespace) -> int:
    mem = _memory_lists(args.memory_dir)
    result = score_finding(
        category=args.category,
        line=args.line,
        tech_stack=_tech_list(args.tech),
        target=args.target,
        patterns=mem["patterns"],
        failed_patterns=mem["failed_patterns"],
        chains=mem["chains"],
        chain_detected=args.chain_detected,
        report_outcomes=mem["report_outcomes"],
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_rank(args: argparse.Namespace) -> int:
    mem = _memory_lists(args.memory_dir)
    with open(args.input) as f:
        candidates = json.load(f)
    result = rank_findings(
        candidates=candidates,
        tech_stack=_tech_list(args.tech),
        target=args.target,
        patterns=mem["patterns"],
        failed_patterns=mem["failed_patterns"],
        chains=mem["chains"],
        chain_detected=args.chain_detected,
        report_outcomes=mem["report_outcomes"],
        top_n=args.top,
    )
    print(json.dumps(result, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rank raw scanner-output findings via memory.vuln_intelligence.priority_score()"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_score = sub.add_parser("score", help="Score one (category, line) finding candidate")
    p_score.add_argument("--category", required=True)
    p_score.add_argument("--line", required=True)
    p_score.add_argument("--tech", default="", help="Comma-separated tech stack")
    p_score.add_argument("--target", required=True)
    p_score.add_argument("--memory-dir", default="hunt-memory")
    p_score.add_argument("--chain-detected", action="store_true")
    p_score.set_defaults(func=_cmd_score)

    p_rank = sub.add_parser("rank", help="Rank a batch of findings from a JSON file")
    p_rank.add_argument("--input", required=True, help='JSON file: list of {"category": ..., "line": ...}')
    p_rank.add_argument("--tech", default="")
    p_rank.add_argument("--target", required=True)
    p_rank.add_argument("--memory-dir", default="hunt-memory")
    p_rank.add_argument("--chain-detected", action="store_true")
    p_rank.add_argument("--top", type=int, default=25)
    p_rank.set_defaults(func=_cmd_rank)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
