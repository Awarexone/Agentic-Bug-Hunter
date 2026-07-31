"""
Experiment memory — the granular "what did I actually try" log beneath
patterns.jsonl / failed_patterns.jsonl.

Those two files (see vuln_intelligence.py) record the *outcome* of a
target+vuln_class+technique combination once a hunt session ends. Neither
can answer "how many payload categories have I already burned on this one
endpoint in the last 5 minutes" — that requires a per-attempt log, which is
what this module provides:

  * ExperimentDB               — append-only log of every payload/technique
                                  attempt (hunt-memory/experiments.jsonl),
                                  win or lose. Not deduplicated on a narrow
                                  key (same reasoning as ReportOutcomeDB in
                                  vuln_intelligence.py): the same endpoint
                                  legitimately gets re-tested over time, and
                                  each attempt is its own data point.
  * payload_category_affinity  — "GraphQL + Node + missing authorization
                                  checks produced findings before" as a live
                                  aggregation over experiments.jsonl, the
                                  same derived-not-duplicated pattern
                                  tech_vuln_affinity() uses one level up.
  * should_stop                — grounds rules/hunting.md's 5-minute rule
                                  and 20-minute rotation rule in an actual
                                  count instead of a vibe: elapsed time,
                                  payload categories exhausted, any success
                                  yet.
  * suggest_pivot              — given a candidate queue already scored by
                                  priority_score() (memory/vuln_intelligence.py)
                                  and the set of endpoints should_stop()
                                  flagged as exhausted, returns what to test
                                  next. Doesn't re-rank — recon-ranker/
                                  priority_score already did that.

Deliberately self-contained (own JSONL save/read, not importing
vuln_intelligence.py's private _JsonlDB) — same isolation reasoning that
module's own docstring gives for not sharing a base class with PatternDB:
nothing here can regress another module's storage if this one changes.

Agents that only have bash/read/glob/grep reach this through the CLI at the
bottom: `python3 -m memory.experiment_memory <cmd>`.
"""

import argparse
import fcntl
import json
import os
import sys
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import (
    SchemaError,
    make_experiment_entry,
    validate_experiment_entry,
)
from memory.vuln_intelligence import normalize_endpoint


def _tech_overlap(query: list[str], candidate: list[str]) -> bool:
    return bool({t.lower() for t in query} & {t.lower() for t in (candidate or [])})


def _tech_overlap_count(query: list[str], candidate: list[str]) -> int:
    return len({t.lower() for t in query} & {t.lower() for t in (candidate or [])})


class ExperimentDB:
    """Append-only log of every payload/technique attempt against an endpoint."""

    # Dedup only exact repeats (same second, same everything) — an accidental
    # double-log, not a legitimate re-test. See module docstring.
    dedup_fields = ("target", "endpoint", "payload_category", "technique", "ts")

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups
        self._dedup_keys: set[tuple[str, ...]] | None = None

    def _dedup_key(self, entry: dict) -> tuple[str, ...]:
        return tuple(str(entry.get(f, "")) for f in self.dedup_fields)

    def _load_dedup_keys(self) -> set[tuple[str, ...]]:
        keys: set[tuple[str, ...]] = set()
        if not self.path.exists():
            return keys
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                keys.add(self._dedup_key(entry))
        return keys

    def save(self, entry: dict) -> bool:
        """Validate and append ``entry``. Returns False only for an exact repeat."""
        validated = validate_experiment_entry(entry)

        if self._dedup_keys is None:
            self._dedup_keys = self._load_dedup_keys()

        key = self._dedup_key(validated)
        if key in self._dedup_keys:
            return False

        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

        self._dedup_keys.add(key)
        return True

    def read_all(self, *, validate: bool = True) -> list[dict]:
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"WARNING: experiments line {lineno} corrupted (skipping): {e}", file=sys.stderr)
                    continue

                if validate:
                    try:
                        validate_experiment_entry(entry)
                    except SchemaError as e:
                        print(f"WARNING: experiments line {lineno} failed validation (skipping): {e}", file=sys.stderr)
                        continue

                entries.append(entry)
        return entries

    def for_endpoint(self, target: str, endpoint: str) -> list[dict]:
        """All experiments for one target+endpoint, matched by normalized shape."""
        shape = normalize_endpoint(endpoint)
        return [
            e for e in self.read_all()
            if e.get("target") == target
            and (e.get("endpoint") == endpoint or normalize_endpoint(e.get("endpoint", "")) == shape)
        ]


def payload_category_affinity(
    tech_stack: list[str],
    experiments: list[dict],
    vuln_class: str | None = None,
    top: int | None = None,
) -> list[dict]:
    """Rank payload categories for a tech stack (+ optional vuln class) by track record.

    This is the "GraphQL + Node + missing authorization checks produced
    findings before -> increase priority" learning: a payload_category with
    wins on a tech stack sharing 2+ technologies with the current target
    ranks above one with only a single shared technology or none at all.
    """
    tech_stack = tech_stack or []
    stats: dict[tuple[str, str], dict] = {}

    for e in experiments:
        entry_vuln_class = e.get("vuln_class", "unknown")
        if vuln_class is not None and entry_vuln_class != vuln_class:
            continue
        if not _tech_overlap(tech_stack, e.get("tech_stack", [])):
            continue

        cat = e.get("payload_category", "unknown")
        # Keyed by (vuln_class, payload_category) — the same category name
        # under different vuln classes (e.g. "missing_authz_check" for both
        # idor and auth-bypass) must not be merged into one bucket.
        key = (entry_vuln_class, cat)
        s = stats.setdefault(key, {
            "payload_category": cat,
            "vuln_class": entry_vuln_class,
            "successes": 0,
            "failures": 0,
            "inconclusive": 0,
            "tech_overlap_strength": 0,
        })
        result = e.get("result")
        if result == "success":
            s["successes"] += 1
        elif result == "fail":
            s["failures"] += 1
        else:
            s["inconclusive"] += 1
        s["tech_overlap_strength"] = max(
            s["tech_overlap_strength"], _tech_overlap_count(tech_stack, e.get("tech_stack", []))
        )

    results = []
    for s in stats.values():
        sample = s["successes"] + s["failures"]
        net_score = s["successes"] * 2 - s["failures"]
        # A 2-tech overlap (e.g. graphql AND node both matched) is a much
        # more specific signal than a 1-tech overlap — weight it directly.
        confidence = min(100, 15 + 12 * sample + 5 * s["tech_overlap_strength"])
        results.append({**s, "net_score": net_score, "confidence": confidence, "sample_size": sample})

    results.sort(key=lambda r: (r["net_score"], r["tech_overlap_strength"]), reverse=True)
    return results[:top] if top else results


def should_stop(
    experiments_for_endpoint: list[dict],
    elapsed_minutes: float,
    minute_limit: float = 5,
    category_limit: int = 3,
) -> dict:
    """Should the hunter abandon the current endpoint right now?

    Grounds rules/hunting.md Rule 5 (5-minute rule) and Rule 14 (20-minute
    rotation) in an actual count: elapsed time, distinct payload categories
    already burned with zero successes, and whether any success has landed
    at all (a live signal always overrides the clock).
    """
    successes = sum(1 for e in experiments_for_endpoint if e.get("result") == "success")
    categories_tried = sorted({e.get("payload_category") for e in experiments_for_endpoint if e.get("payload_category")})

    if successes > 0:
        return {
            "stop": False,
            "reason": f"{successes} successful experiment(s) — active signal, keep going",
            "elapsed_minutes": elapsed_minutes,
            "categories_tried": categories_tried,
        }

    if elapsed_minutes >= minute_limit:
        return {
            "stop": True,
            "reason": f"{elapsed_minutes} min elapsed with 0 successes (5-minute rule, rules/hunting.md)",
            "elapsed_minutes": elapsed_minutes,
            "categories_tried": categories_tried,
        }

    if len(categories_tried) >= category_limit:
        return {
            "stop": True,
            "reason": f"{len(categories_tried)} payload categories exhausted with 0 successes",
            "elapsed_minutes": elapsed_minutes,
            "categories_tried": categories_tried,
        }

    return {
        "stop": False,
        "reason": "still within time/category budget",
        "elapsed_minutes": elapsed_minutes,
        "categories_tried": categories_tried,
    }


def suggest_pivot(candidates: list[dict], exhausted_endpoints: set[str] | list[str]) -> dict | None:
    """Which candidate to test next, given some endpoints are already exhausted.

    ``candidates`` is the P1/P2 queue recon-ranker/priority_score already
    scored (each dict needs an "endpoint" and a "score", optionally
    "hard_kill"). This doesn't recompute priority — it just applies the
    mid-hunt exhaustion filter that recon-ranker can't know about, since
    should_stop() only becomes true after time has actually been spent.
    """
    exhausted = set(exhausted_endpoints)
    remaining = [
        c for c in candidates
        if c.get("endpoint") not in exhausted and not c.get("hard_kill")
    ]
    if not remaining:
        return None
    remaining.sort(key=lambda c: c.get("score", 0), reverse=True)
    return remaining[0]


def evaluate_experiment(
    target: str,
    technique: str,
    vuln_class: str | None = None,
    tech_stack: list[str] | None = None,
    endpoint: str | None = None,
    experiments: list[dict] | None = None,
    failed_patterns: list[dict] | None = None,
    elapsed_minutes: float = 0.0,
    minute_limit: float = 5,
    category_limit: int = 3,
    ev_per_hour: float | None = None,
    ev_label: str | None = None,
) -> dict:
    """Continue / pivot / stop on ``technique`` right now, and why.

    Answers the three questions a hunter actually asks mid-experiment:
      1. Has this exact technique already failed here? (failed_patterns.jsonl —
         the same hard-kill signal priority_score() in vuln_intelligence.py uses)
      2. Has it worked on similar tech before? (experiments.jsonl, technique +
         vuln_class + tech-stack overlap — a narrower slice than
         payload_category_affinity()'s payload_category grouping above)
      3. Is the EV still worth the time? (caller-supplied ev_per_hour/ev_label
         from vuln_intelligence.expected_value_per_hour() — this function does
         not recompute EV itself; priority_score()/expected_value_per_hour()
         stay the single source of truth for that formula)

    Pure function over pre-loaded lists, same convention as should_stop() and
    suggest_pivot() above — the ``evaluate`` CLI subcommand does the loading.
    """
    tech_stack = tech_stack or []
    experiments = experiments or []
    failed_patterns = failed_patterns or []

    # Q1: exact repeat of a technique already known to be dead here.
    failed_entry = next(
        (f for f in failed_patterns if f.get("target") == target and f.get("technique") == technique),
        None,
    )
    if failed_entry:
        reason = f"'{technique}' already failed on {target}"
        if failed_entry.get("reason"):
            reason += f": {failed_entry['reason']}"
        return {
            "decision": "stop",
            "reason": reason,
            "confidence": 95,
            "recommended_next_step": "Do not re-attempt this technique here — pivot to a different technique or vuln class.",
        }

    # Q2: track record of this exact technique on similar tech, independent of this target.
    matching = [
        e for e in experiments
        if e.get("technique") == technique
        and (vuln_class is None or e.get("vuln_class") == vuln_class)
        and _tech_overlap(tech_stack, e.get("tech_stack", []))
    ]
    successes = sum(1 for e in matching if e.get("result") == "success")
    failures = sum(1 for e in matching if e.get("result") == "fail")
    sample = successes + failures

    # Q3 (time/category budget): should_stop() on the endpoint being tested
    # right now, when the caller tells us which one that is.
    budget = None
    if endpoint is not None:
        endpoint_experiments = [
            e for e in experiments
            if e.get("target") == target
            and (
                e.get("endpoint") == endpoint
                or normalize_endpoint(e.get("endpoint", "")) == normalize_endpoint(endpoint)
            )
        ]
        budget = should_stop(endpoint_experiments, elapsed_minutes, minute_limit, category_limit)

    # A live success right now beats every other signal — same "active signal
    # overrides the clock" rule should_stop() itself uses.
    if successes > 0 and (budget is None or not budget["stop"]):
        return {
            "decision": "continue",
            "reason": f"{successes} success(es) with '{technique}' on this tech stack — active signal overrides budget/EV checks.",
            "confidence": min(100, 60 + 10 * successes),
            "recommended_next_step": f"Keep testing '{technique}' — push toward a confirmable PoC on {endpoint or target}.",
        }

    if ev_label == "Kill":
        return {
            "decision": "stop",
            "reason": f"expected_value_per_hour() rates this candidate 'Kill' (ev_per_hour={ev_per_hour}) — not worth further time regardless of technique history.",
            "confidence": 85,
            "recommended_next_step": "Abandon this candidate entirely — move to the next-highest-EV candidate in the queue.",
        }

    if budget and budget["stop"]:
        no_wins_yet = sample > 0 and successes == 0
        decision = "stop" if (no_wins_yet and failures >= 3) else "pivot"
        reason = budget["reason"]
        if sample:
            reason += f"; '{technique}' has {successes}W/{failures}L on similar tech stacks"
        return {
            "decision": decision,
            "reason": reason,
            "confidence": min(100, 40 + 10 * sample),
            "recommended_next_step": (
                f"Kill '{technique}' on this target — log it via save-failed so it isn't retried."
                if decision == "stop"
                else "Time/category budget is exhausted here — move to the next candidate in the queue (suggest_pivot())."
            ),
        }

    if sample == 0:
        return {
            "decision": "continue",
            "reason": f"No prior data for '{technique}' on this tech stack yet, and no time/category budget exhausted — still worth a first real attempt.",
            "confidence": 20,
            "recommended_next_step": f"Run '{technique}' against {endpoint or target} and record the result via 'record'.",
        }

    # By construction, successes == 0 down here: any success would already
    # have triggered the active-signal "continue" return above, unless the
    # current endpoint's own budget was exhausted — and that case is handled
    # by the budget branch above too. So what's left is purely a failure
    # count on similar tech stacks, with the current endpoint's own budget
    # (if any) not yet exhausted.
    if failures >= 2:
        decision = "pivot"
        step = f"'{technique}' has failed {failures} time(s) on similar tech stacks with 0 successes — try a different technique before spending more budget here."
    else:
        decision = "continue"
        step = f"Only {failures} prior failure(s) on similar tech stacks — still early, worth one more attempt with '{technique}'."
    return {
        "decision": decision,
        "reason": f"'{technique}' has {successes}W/{failures}L on similar tech stacks, budget not yet exhausted.",
        "confidence": min(100, 30 + 10 * sample),
        "recommended_next_step": step,
    }


# ─── CLI — for agents that only have bash/read/glob/grep tools ──────────────

def _experiments_path(memory_dir: str) -> Path:
    return Path(memory_dir) / "experiments.jsonl"


def _cmd_record(args: argparse.Namespace) -> int:
    entry = make_experiment_entry(
        target=args.target,
        endpoint=args.endpoint,
        vuln_class=args.vuln_class,
        payload_category=args.payload_category,
        result=args.result,
        technique=args.technique,
        tech_stack=[t.strip() for t in args.tech_stack.split(",") if t.strip()] if args.tech_stack else None,
        time_spent_minutes=args.time_spent,
        notes=args.notes,
    )
    saved = ExperimentDB(_experiments_path(args.memory_dir)).save(entry)
    print(json.dumps({"saved": saved, "entry": entry}, indent=2))
    return 0


def _cmd_payload_stats(args: argparse.Namespace) -> int:
    db = ExperimentDB(_experiments_path(args.memory_dir))
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()]
    result = payload_category_affinity(tech_stack, db.read_all(), vuln_class=args.vuln_class, top=args.top)
    print(json.dumps({"tech_stack": tech_stack, "vuln_class": args.vuln_class, "payload_categories": result}, indent=2))
    return 0


def _cmd_should_stop(args: argparse.Namespace) -> int:
    db = ExperimentDB(_experiments_path(args.memory_dir))
    experiments = db.for_endpoint(args.target, args.endpoint)
    result = should_stop(experiments, args.elapsed_minutes, args.minute_limit, args.category_limit)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    from memory.pattern_db import PatternDB
    from memory.vuln_intelligence import (
        ChainDB,
        FailedPatternDB,
        ReportOutcomeDB,
        expected_value_per_hour,
    )

    memory_dir = Path(args.memory_dir)
    tech_stack = [t.strip() for t in args.tech_stack.split(",") if t.strip()] if args.tech_stack else []

    experiments = ExperimentDB(_experiments_path(args.memory_dir)).read_all()
    failed_patterns = FailedPatternDB(memory_dir / "failed_patterns.jsonl").read_all()

    ev_per_hour = ev_label = None
    if args.vuln_class:
        patterns = PatternDB(memory_dir / "patterns.jsonl").read_all()
        chains = ChainDB(memory_dir / "chains.jsonl").read_all()
        outcomes = ReportOutcomeDB(memory_dir / "report_outcomes.jsonl").read_all()
        ev_result = expected_value_per_hour(
            vuln_class=args.vuln_class,
            tech_stack=tech_stack,
            target=args.target,
            technique=args.technique,
            patterns=patterns,
            failed_patterns=failed_patterns,
            chains=chains,
            report_outcomes=outcomes,
            estimated_minutes=args.minutes,
        )
        ev_per_hour, ev_label = ev_result["ev_per_hour"], ev_result["ev_label"]

    result = evaluate_experiment(
        target=args.target,
        technique=args.technique,
        vuln_class=args.vuln_class,
        tech_stack=tech_stack,
        endpoint=args.endpoint,
        experiments=experiments,
        failed_patterns=failed_patterns,
        elapsed_minutes=args.elapsed_minutes,
        minute_limit=args.minute_limit,
        category_limit=args.category_limit,
        ev_per_hour=ev_per_hour,
        ev_label=ev_label,
    )
    print(json.dumps(result, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Experiment memory — payload-attempt log + stop/pivot decisions")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("record", help="Log a single payload-category attempt against an endpoint")
    p.add_argument("--target", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--payload-category", required=True)
    p.add_argument("--result", required=True, choices=sorted({"success", "fail", "inconclusive"}))
    p.add_argument("--technique", default=None)
    p.add_argument("--tech-stack", default=None, help="Comma-separated")
    p.add_argument("--time-spent", type=float, default=None, help="Minutes")
    p.add_argument("--notes", default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_record)

    p = sub.add_parser("payload-stats", help="Rank payload categories for a tech stack by track record")
    p.add_argument("--tech", required=True, help="Comma-separated tech stack")
    p.add_argument("--vuln-class", default=None)
    p.add_argument("--top", type=int, default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_payload_stats)

    p = sub.add_parser("should-stop", help="Should the hunter abandon the current endpoint right now?")
    p.add_argument("--target", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--elapsed-minutes", type=float, required=True)
    p.add_argument("--minute-limit", type=float, default=5)
    p.add_argument("--category-limit", type=int, default=3)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_should_stop)

    p = sub.add_parser("evaluate", help="continue/pivot/stop decision on a technique, with reason/confidence/next-step")
    p.add_argument("--target", required=True)
    p.add_argument("--technique", required=True)
    p.add_argument("--vuln-class", default=None, help="Also computes ev_per_hour/ev_label via expected_value_per_hour() when set")
    p.add_argument("--tech-stack", default=None, help="Comma-separated")
    p.add_argument("--endpoint", default=None, help="Enables the time/category budget check (should_stop) for this endpoint")
    p.add_argument("--elapsed-minutes", type=float, default=0.0)
    p.add_argument("--minute-limit", type=float, default=5)
    p.add_argument("--category-limit", type=int, default=3)
    p.add_argument("--minutes", type=float, default=None, help="Override the static per-vuln-class EV time estimate")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_evaluate)

    args = ap.parse_args()
    try:
        return args.func(args)
    except SchemaError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
