"""
Finding lifecycle engine — SUSPECTED -> TESTING -> VALIDATED -> CONFIRMED ->
REPORT_READY (plus REJECTED, reachable from any non-terminal state), backed
by an append-only hunt-memory/finding_states.jsonl transition log, the same
JSONL + schema-validation + flock pattern every other file in this package
uses (patterns.jsonl, chains.jsonl, hypotheses.jsonl, experiments.jsonl,
...). Not a new memory system — one more entry type in the existing one.

Right now nothing in the pipeline enforces that a finding actually earned
its way to CONFIRMED or REPORT_READY — a hunter (or an autonomous loop) can
just declare a finding confirmed. This module makes that a checked
transition instead of a label:

  * can_transition(current, next, evidence)  — is current -> next even a
                                                legal jump, and does the
                                                evidence support it? Returns
                                                {allowed, reason} instead of
                                                raising, for callers that
                                                want to report why.
  * transition(current, next, evidence)      — same check, raises
                                                FindingStateError instead.
  * FindingStateDB                           — the persisted transition
                                                history, current_state()
                                                lookup, and advance() (the
                                                validate+persist combo) keyed
                                                by (target, vuln_class,
                                                endpoint shape).

Integrates directly with the existing validation-engine agent
(agents/validation-engine.md), which already outputs a STRONG/WEAK/REJECT
verdict and a "Reproducible?" check per finding — that verdict and
reproducibility flag are exactly the ``evidence`` dict this module expects.
Two rules enforced regardless of what order a caller tries to advance a
finding through:

  * "Weak evidence cannot become CONFIRMED" — a transition to CONFIRMED
    requires evidence["verdict"] == "STRONG". A WEAK/REJECT verdict, or no
    verdict recorded at all, blocks it.
  * "Missing reproduction blocks REPORT_READY" — a transition to
    REPORT_READY requires evidence["reproducible"] is True.

Self-learning (FindingStateDB.advance()'s auto_learn, default on): landing
on REJECTED or CONFIRMED automatically writes to failed_patterns.jsonl /
patterns.jsonl (the same two files vuln_intelligence.py's
tech_vuln_affinity()/priority_score() already read), so a hunter never has
to run a separate `/remember` step to make a rejection or confirmation
count toward future ranking.

Agents that only have bash/read/glob/grep (no python execution) reach this
through the CLI at the bottom: `python3 -m memory.finding_state <cmd>`.
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
    make_finding_state_entry,
    validate_finding_state_entry,
)
from memory.vuln_intelligence import normalize_endpoint

FINDING_STATES = ("SUSPECTED", "TESTING", "VALIDATED", "CONFIRMED", "REPORT_READY", "REJECTED")

# Legal forward transitions. REJECTED is reachable from every non-terminal
# state (a finding can be killed at any point in its life), but nothing is
# reachable FROM REJECTED or REPORT_READY — both are terminal.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "SUSPECTED":    {"TESTING", "REJECTED"},
    "TESTING":      {"VALIDATED", "REJECTED"},
    "VALIDATED":    {"CONFIRMED", "REJECTED"},
    "CONFIRMED":    {"REPORT_READY", "REJECTED"},
    "REPORT_READY": set(),
    "REJECTED":     set(),
}


class FindingStateError(Exception):
    """Raised when a transition is illegal — wrong order, or blocked by weak/missing evidence."""


def can_transition(current_state: str, next_state: str, evidence: dict | None = None) -> dict:
    """Is ``current_state`` -> ``next_state`` legal right now?

    Returns ``{"allowed": bool, "reason": str}`` rather than raising, for
    callers (agents, the CLI below) that want to report why instead of
    catching an exception. ``evidence`` is read but never mutated; pass
    validation-engine's verdict/reproducibility straight through, e.g.
    ``{"verdict": "STRONG", "reproducible": True}``.
    """
    evidence = evidence or {}

    if current_state not in FINDING_STATES:
        return {"allowed": False, "reason": f"{current_state!r} is not a known state {FINDING_STATES}"}
    if next_state not in FINDING_STATES:
        return {"allowed": False, "reason": f"{next_state!r} is not a known state {FINDING_STATES}"}

    if next_state not in ALLOWED_TRANSITIONS[current_state]:
        allowed = sorted(ALLOWED_TRANSITIONS[current_state])
        return {
            "allowed": False,
            "reason": (
                f"{current_state} -> {next_state} is not a legal transition "
                f"(allowed from {current_state}: {allowed or 'none, terminal state'})"
            ),
        }

    # Weak-finding auto-rejection — independent of ordering, gated on the
    # evidence itself. A missing verdict is treated the same as a non-STRONG
    # one: CONFIRMED requires *positive* proof, not merely "not proven weak."
    if next_state == "CONFIRMED" and evidence.get("verdict") != "STRONG":
        return {
            "allowed": False,
            "reason": (
                f"validation-engine verdict is {evidence.get('verdict')!r}, not STRONG — "
                "weak evidence cannot become CONFIRMED"
            ),
        }

    if next_state == "REPORT_READY" and not evidence.get("reproducible", False):
        return {
            "allowed": False,
            "reason": "no reproducible evidence recorded — missing reproduction blocks REPORT_READY",
        }

    return {"allowed": True, "reason": "legal transition"}


def transition(current_state: str, next_state: str, evidence: dict | None = None) -> None:
    """Same check as can_transition(), raising FindingStateError instead of
    returning a dict — for callers that want a hard stop, not a report."""
    result = can_transition(current_state, next_state, evidence)
    if not result["allowed"]:
        raise FindingStateError(result["reason"])


class FindingStateDB:
    """Append-only transition history: hunt-memory/finding_states.jsonl.

    One line per transition event, not one line per finding — the full
    history of how a finding moved through the lifecycle stays auditable,
    same "append-only event log" convention as journal.jsonl/
    experiments.jsonl use. Not deduplicated on a narrow key (same reasoning
    as ExperimentDB/HypothesisDB): a finding can legitimately be re-tested
    across sessions, and REJECTED -> re-SUSPECTED isn't a thing this module
    forbids at the persistence layer even though ALLOWED_TRANSITIONS treats
    REJECTED as terminal for a single lifecycle run — a fresh advance()
    call with no prior REJECTED-then-SUSPECTED history simply starts a new
    one.
    """

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

    def save(self, entry: dict) -> bool:
        """Validate and append ``entry``. Always returns True on success —
        this log is intentionally not deduplicated, see class docstring."""
        validated = validate_finding_state_entry(entry)

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
                    print(f"WARNING: finding_states line {lineno} corrupted (skipping): {e}", file=sys.stderr)
                    continue

                if validate:
                    try:
                        validate_finding_state_entry(entry)
                    except SchemaError as e:
                        print(f"WARNING: finding_states line {lineno} failed validation (skipping): {e}", file=sys.stderr)
                        continue

                entries.append(entry)
        return entries

    def history(self, target: str, vuln_class: str, endpoint: str) -> list[dict]:
        """All transition events for one target+vuln_class+endpoint (matched
        by normalized shape), oldest first."""
        shape = normalize_endpoint(endpoint)
        events = [
            e for e in self.read_all()
            if e.get("target") == target
            and e.get("vuln_class") == vuln_class
            and (e.get("endpoint") == endpoint or normalize_endpoint(e.get("endpoint", "")) == shape)
        ]
        events.sort(key=lambda e: e.get("ts", ""))
        return events

    def current_state(self, target: str, vuln_class: str, endpoint: str) -> str | None:
        """The most recent state for this finding, or None if it has no
        history yet (nothing has ever been logged for it)."""
        hist = self.history(target, vuln_class, endpoint)
        return hist[-1]["state"] if hist else None

    def advance(
        self,
        target: str,
        vuln_class: str,
        endpoint: str,
        next_state: str,
        evidence: dict | None = None,
        notes: str | None = None,
        technique: str | None = None,
        tech_stack: list[str] | None = None,
        reason: str | None = None,
        payout: int | float | None = None,
        auto_learn: bool = True,
    ) -> dict:
        """Validate + persist one transition. Raises FindingStateError if
        illegal; returns the saved entry if legal.

        A finding with no prior history must be registered as SUSPECTED
        first — there's no implicit starting state, so the very first call
        for a given (target, vuln_class, endpoint) has to be
        ``advance(..., "SUSPECTED")``.

        Phase 7 self-learning: landing on REJECTED or CONFIRMED auto-saves
        to failed_patterns.jsonl / patterns.jsonl (via _auto_learn() below)
        so the next hunt already knows this technique died here, or that it
        paid off, with no manual `/remember` step required. Pass
        ``technique``/``tech_stack`` (required by both schemas) and
        optionally ``reason`` (REJECTED) / ``payout`` (CONFIRMED) to enable
        it, or ``auto_learn=False`` to skip it for this call.
        """
        current = self.current_state(target, vuln_class, endpoint)
        evidence = evidence or {}

        if current is None:
            if next_state != "SUSPECTED":
                raise FindingStateError(
                    f"no existing history for this finding — first transition must register it "
                    f"as SUSPECTED, not {next_state!r}"
                )
        else:
            result = can_transition(current, next_state, evidence)
            if not result["allowed"]:
                raise FindingStateError(result["reason"])

        entry = make_finding_state_entry(
            target=target,
            vuln_class=vuln_class,
            endpoint=endpoint,
            state=next_state,
            previous_state=current,
            verdict=evidence.get("verdict"),
            reproducible=evidence.get("reproducible"),
            notes=notes,
        )
        self.save(entry)

        result_entry = dict(entry)
        if auto_learn:
            auto_learned = self._auto_learn(
                target=target, vuln_class=vuln_class, endpoint=endpoint, state=next_state,
                technique=technique, tech_stack=tech_stack, reason=reason, payout=payout,
            )
            if auto_learned is not None:
                result_entry["auto_learned"] = auto_learned
        return result_entry

    def _auto_learn(
        self,
        target: str,
        vuln_class: str,
        endpoint: str,
        state: str,
        technique: str | None,
        tech_stack: list[str] | None,
        reason: str | None,
        payout: int | float | None,
    ) -> dict | None:
        """Phase 7 self-learning: no manual `/remember` dependency.

        On REJECTED, auto-save a failed-pattern entry (technique, vuln
        class, technology, reason) so the next hunt skips this exact dead
        end without being told by hand. On CONFIRMED, auto-save a
        successful pattern entry (technique, tech stack, endpoint,
        payout) — the tech-vuln affinity and endpoint-shape learning in
        vuln_intelligence.py is a live aggregation over these two files, so
        this is what actually feeds it.

        Best-effort and silent about *not* writing: pattern_entry/
        failed_pattern_entry both require technique+tech_stack, so if the
        caller didn't supply them, nothing is saved rather than guessed at
        — an auto-learned entry with a made-up technique would be worse
        than no entry at all.
        """
        if state not in ("REJECTED", "CONFIRMED"):
            return None
        if not technique or not tech_stack:
            return None

        from memory.pattern_db import PatternDB
        from memory.schemas import make_failed_pattern_entry, make_pattern_entry
        from memory.vuln_intelligence import FailedPatternDB

        memory_dir = self.path.parent

        if state == "REJECTED":
            fp_entry = make_failed_pattern_entry(
                target=target, vuln_class=vuln_class, technique=technique,
                tech_stack=tech_stack, endpoint=endpoint, reason=reason,
            )
            saved = FailedPatternDB(memory_dir / "failed_patterns.jsonl").save(fp_entry)
            return {"file": "failed_patterns.jsonl", "saved": saved}

        p_entry = make_pattern_entry(
            target=target, vuln_class=vuln_class, technique=technique,
            tech_stack=tech_stack, endpoint=endpoint, payout=payout,
        )
        saved = PatternDB(memory_dir / "patterns.jsonl").save(p_entry)
        return {"file": "patterns.jsonl", "saved": saved}


# ─── CLI — for agents that only have bash/read/glob/grep tools ──────────────

def _finding_states_path(memory_dir: str) -> Path:
    return Path(memory_dir) / "finding_states.jsonl"


def _cmd_current(args: argparse.Namespace) -> int:
    db = FindingStateDB(_finding_states_path(args.memory_dir))
    state = db.current_state(args.target, args.vuln_class, args.endpoint)
    print(json.dumps({"current_state": state}, indent=2))
    return 0


def _cmd_history(args: argparse.Namespace) -> int:
    db = FindingStateDB(_finding_states_path(args.memory_dir))
    print(json.dumps(db.history(args.target, args.vuln_class, args.endpoint), indent=2))
    return 0


def _cmd_can_transition(args: argparse.Namespace) -> int:
    evidence = {}
    if args.verdict is not None:
        evidence["verdict"] = args.verdict
    if args.reproducible:
        evidence["reproducible"] = True
    result = can_transition(args.current_state, args.next_state, evidence)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_advance(args: argparse.Namespace) -> int:
    evidence = {}
    if args.verdict is not None:
        evidence["verdict"] = args.verdict
    if args.reproducible:
        evidence["reproducible"] = True

    db = FindingStateDB(_finding_states_path(args.memory_dir))
    try:
        entry = db.advance(
            target=args.target,
            vuln_class=args.vuln_class,
            endpoint=args.endpoint,
            next_state=args.state,
            evidence=evidence,
            notes=args.notes,
            technique=args.technique,
            tech_stack=[t.strip() for t in args.tech_stack.split(",") if t.strip()] if args.tech_stack else None,
            reason=args.reason,
            payout=args.payout,
            auto_learn=not args.no_auto_learn,
        )
    except FindingStateError as e:
        print(json.dumps({"advanced": False, "reason": str(e)}, indent=2))
        return 2
    print(json.dumps({"advanced": True, "entry": entry}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Finding lifecycle engine — SUSPECTED/TESTING/VALIDATED/CONFIRMED/REPORT_READY/REJECTED"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("current", help="Current lifecycle state for a finding")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_current)

    p = sub.add_parser("history", help="Full transition history for a finding")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_history)

    p = sub.add_parser("can-transition", help="Is current-state -> next-state legal right now, and why/why not")
    p.add_argument("--current-state", required=True, choices=FINDING_STATES)
    p.add_argument("--next-state", required=True, choices=FINDING_STATES)
    p.add_argument("--verdict", default=None, choices=("STRONG", "WEAK", "REJECT"), help="validation-engine's verdict")
    p.add_argument("--reproducible", action="store_true", help="Reproducible evidence is on hand")
    p.set_defaults(func=_cmd_can_transition)

    p = sub.add_parser("advance", help="Validate + persist a transition for a specific finding")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--state", required=True, choices=FINDING_STATES, help="The state to advance to")
    p.add_argument("--verdict", default=None, choices=("STRONG", "WEAK", "REJECT"), help="validation-engine's verdict")
    p.add_argument("--reproducible", action="store_true", help="Reproducible evidence is on hand")
    p.add_argument("--notes", default=None)
    p.add_argument("--technique", default=None, help="Enables self-learning auto-save on REJECTED/CONFIRMED (needs --tech-stack too)")
    p.add_argument("--tech-stack", default=None, help="Comma-separated, required alongside --technique for auto-save")
    p.add_argument("--reason", default=None, help="Why it failed -- used by the auto-saved failed_patterns.jsonl entry on REJECTED")
    p.add_argument("--payout", type=float, default=None, help="Used by the auto-saved patterns.jsonl entry on CONFIRMED")
    p.add_argument("--no-auto-learn", action="store_true", help="Skip the automatic failed_patterns.jsonl/patterns.jsonl write on REJECTED/CONFIRMED")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_advance)

    args = ap.parse_args()
    try:
        return args.func(args)
    except SchemaError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
