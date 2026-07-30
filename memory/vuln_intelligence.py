"""
Vulnerability intelligence layer — the memory-driven half of ranking.

Builds on the same JSONL + schema-validation + flock design as pattern_db.py,
but adds three things patterns.jsonl alone can't give you:

  * FailedPatternDB   — techniques that were tried and did NOT pan out
                         (hunt-memory/failed_patterns.jsonl). Lets recon-ranker
                         and autopilot skip a dead end instead of re-suggesting it.
  * ChainDB           — confirmed multi-signal exploit chains
                         (hunt-memory/chains.jsonl), so a chain shape that paid
                         off on one target can be recognized on the next.
  * tech_vuln_affinity / endpoint_shape_stats — pure query functions that turn
    patterns.jsonl + failed_patterns.jsonl (+ optionally journal.jsonl) into a
    tech-stack -> vuln-class affinity ranking and an endpoint-shape hit rate,
    without a separate cache file. The intelligence is derived, not duplicated.

Agents that only have bash/read/glob/grep (no python execution) reach this
through the CLI at the bottom: `python3 -m memory.vuln_intelligence <cmd>`.
"""

import argparse
import fcntl
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import (
    SchemaError,
    make_chain_entry,
    make_failed_pattern_entry,
    validate_chain_entry,
    validate_failed_pattern_entry,
)

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_endpoint(url_or_path: str) -> str:
    """Collapse an endpoint to its path *shape* for cross-target matching.

    ``/api/v2/users/482/orders`` and ``/api/v2/users/9107/orders`` both
    normalize to ``/api/v2/users/{id}/orders`` so a hit on one target's
    endpoint shape is a signal for the same shape on another target.
    """
    if not url_or_path or not url_or_path.strip():
        return ""

    path = urlparse(url_or_path).path
    if not path:
        path = url_or_path.split("?", 1)[0]

    segments = path.split("/")
    shaped = []
    for seg in segments:
        if seg == "":
            shaped.append(seg)
        elif _NUMERIC_RE.match(seg):
            shaped.append("{id}")
        elif _UUID_RE.match(seg):
            shaped.append("{uuid}")
        elif _HEX_TOKEN_RE.match(seg):
            shaped.append("{token}")
        else:
            shaped.append(seg)
    return "/".join(shaped)


def _tech_overlap(query: list[str], candidate: list[str]) -> bool:
    return bool({t.lower() for t in query} & {t.lower() for t in (candidate or [])})


class _JsonlDB:
    """Shared save/read machinery for the two DBs below.

    Deliberately not a shared base class with PatternDB (in pattern_db.py) —
    keeping this self-contained means nothing here can regress the existing
    pattern storage.
    """

    dedup_fields: tuple[str, ...] = ()

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

    def _validate(self, entry: dict) -> dict:
        raise NotImplementedError

    def _dedup_key(self, entry: dict) -> tuple[str, ...]:
        return tuple(entry.get(f, "") for f in self.dedup_fields)

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
        """Validate and append ``entry``. Returns False if it's a duplicate."""
        validated = self._validate(entry)

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
                    print(f"WARNING: {self.path.name} line {lineno} corrupted (skipping): {e}", file=sys.stderr)
                    continue

                if validate:
                    try:
                        self._validate(entry)
                    except SchemaError as e:
                        print(f"WARNING: {self.path.name} line {lineno} failed validation (skipping): {e}", file=sys.stderr)
                        continue

                entries.append(entry)
        return entries


class FailedPatternDB(_JsonlDB):
    """Techniques that were tried and rejected/killed — the 'don't retry' list."""

    dedup_fields = ("target", "vuln_class", "technique")

    def _validate(self, entry: dict) -> dict:
        return validate_failed_pattern_entry(entry)

    def has_failed(self, target: str, technique: str) -> dict | None:
        """Return the failed-pattern entry if this exact target+technique was already tried."""
        for entry in self.read_all():
            if entry.get("target") == target and entry.get("technique") == technique:
                return entry
        return None


class ChainDB(_JsonlDB):
    """Confirmed multi-signal exploit chains, keyed by (target, chain_name)."""

    dedup_fields = ("target", "chain_name")

    def _validate(self, entry: dict) -> dict:
        return validate_chain_entry(entry)

    def match(self, tech_stack: list[str] | None = None) -> list[dict]:
        """Chains observed on any target whose tech stack overlaps this one."""
        chains = self.read_all()
        if tech_stack is not None:
            chains = [c for c in chains if _tech_overlap(tech_stack, c.get("tech_stack", []))]
        chains.sort(key=lambda c: (c.get("payout", 0), c.get("ts", "")), reverse=True)
        return chains


def tech_vuln_affinity(
    tech_stack: list[str],
    patterns: list[dict],
    failed_patterns: list[dict],
    top: int | None = None,
) -> list[dict]:
    """Rank vuln classes for a tech stack from historical wins/losses.

    This is the persisted "technology -> vulnerability mapping": it doesn't
    live in its own file, it's a live aggregation over patterns.jsonl (wins)
    and failed_patterns.jsonl (losses), so it stays consistent with whatever
    those two files actually contain instead of drifting out of sync.
    """
    tech_stack = tech_stack or []
    stats: dict[str, dict] = {}

    for p in patterns:
        if not _tech_overlap(tech_stack, p.get("tech_stack", [])):
            continue
        vc = p.get("vuln_class", "unknown")
        s = stats.setdefault(vc, {"vuln_class": vc, "wins": 0, "losses": 0, "payout_total": 0.0, "targets": set()})
        s["wins"] += 1
        s["payout_total"] += p.get("payout", 0) or 0
        s["targets"].add(p.get("target", ""))

    for f in failed_patterns:
        if not _tech_overlap(tech_stack, f.get("tech_stack", [])):
            continue
        vc = f.get("vuln_class", "unknown")
        s = stats.setdefault(vc, {"vuln_class": vc, "wins": 0, "losses": 0, "payout_total": 0.0, "targets": set()})
        s["losses"] += 1
        s["targets"].add(f.get("target", ""))

    results = []
    for vc, s in stats.items():
        wins, losses = s["wins"], s["losses"]
        sample_size = wins + losses
        net_score = wins * 2 - losses
        # Confidence grows with sample size and levels off; a single win/loss
        # is a weak signal, 5+ observations is a strong one.
        confidence = min(100, 15 + 12 * sample_size + (10 if wins > losses else 0))
        results.append({
            "vuln_class": vc,
            "wins": wins,
            "losses": losses,
            "net_score": net_score,
            "confidence": confidence,
            "avg_payout": round(s["payout_total"] / wins, 2) if wins else 0,
            "cross_target": len(s["targets"]) > 1,
        })

    results.sort(key=lambda r: (r["net_score"], r["wins"]), reverse=True)
    return results[:top] if top else results


def _read_jsonl_best_effort(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def endpoint_shape_stats(
    url: str,
    patterns: list[dict],
    failed_patterns: list[dict],
    journal_entries: list[dict] | None = None,
) -> dict:
    """Historical hit rate for the *shape* of ``url`` across all targets seen so far."""
    shape = normalize_endpoint(url)
    wins = losses = 0
    by_vuln_class: dict[str, dict] = {}

    def bump(vuln_class: str, is_win: bool) -> None:
        d = by_vuln_class.setdefault(vuln_class, {"wins": 0, "losses": 0})
        d["wins" if is_win else "losses"] += 1

    for p in patterns:
        ep = p.get("endpoint")
        if ep and normalize_endpoint(ep) == shape:
            wins += 1
            bump(p.get("vuln_class", "unknown"), True)

    for fp in failed_patterns:
        ep = fp.get("endpoint")
        if ep and normalize_endpoint(ep) == shape:
            losses += 1
            bump(fp.get("vuln_class", "unknown"), False)

    for j in journal_entries or []:
        ep = j.get("endpoint")
        if not ep or normalize_endpoint(ep) != shape:
            continue
        result = j.get("result")
        if result in ("confirmed", "partial"):
            wins += 1
            bump(j.get("vuln_class", "unknown"), True)
        elif result == "rejected":
            losses += 1
            bump(j.get("vuln_class", "unknown"), False)

    sample_size = wins + losses
    return {
        "shape": shape,
        "wins": wins,
        "losses": losses,
        "confidence": min(100, 15 + 12 * sample_size) if sample_size else 0,
        "by_vuln_class": by_vuln_class,
    }


# ─── CLI — for agents that only have bash/read/glob/grep tools ──────────────

def _memory_paths(memory_dir: str) -> dict[str, Path]:
    base = Path(memory_dir)
    return {
        "patterns": base / "patterns.jsonl",
        "failed_patterns": base / "failed_patterns.jsonl",
        "chains": base / "chains.jsonl",
        "journal": base / "journal.jsonl",
    }


def _cmd_affinity(args: argparse.Namespace) -> int:
    from memory.pattern_db import PatternDB

    paths = _memory_paths(args.memory_dir)
    patterns = PatternDB(paths["patterns"]).read_all()
    failed = FailedPatternDB(paths["failed_patterns"]).read_all()
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()]
    result = tech_vuln_affinity(tech_stack, patterns, failed, top=args.top)
    print(json.dumps({"tech_stack": tech_stack, "affinity": result}, indent=2))
    return 0


def _cmd_endpoint_stats(args: argparse.Namespace) -> int:
    from memory.pattern_db import PatternDB

    paths = _memory_paths(args.memory_dir)
    patterns = PatternDB(paths["patterns"]).read_all()
    failed = FailedPatternDB(paths["failed_patterns"]).read_all()
    journal = _read_jsonl_best_effort(paths["journal"])
    result = endpoint_shape_stats(args.url, patterns, failed, journal)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_failed_check(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    entry = FailedPatternDB(paths["failed_patterns"]).has_failed(args.target, args.technique)
    print(json.dumps({"already_failed": entry is not None, "entry": entry}, indent=2))
    return 0


def _cmd_chains(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else None
    result = ChainDB(paths["chains"]).match(tech_stack)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_save_failed(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    entry = make_failed_pattern_entry(
        target=args.target,
        vuln_class=args.vuln_class,
        technique=args.technique,
        tech_stack=[t.strip() for t in args.tech_stack.split(",") if t.strip()],
        endpoint=args.endpoint,
        reason=args.reason,
    )
    saved = FailedPatternDB(paths["failed_patterns"]).save(entry)
    print(json.dumps({"saved": saved, "entry": entry}, indent=2))
    return 0


def _cmd_save_chain(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    entry = make_chain_entry(
        target=args.target,
        chain_name=args.chain_name,
        steps=[s.strip() for s in args.steps.split("|") if s.strip()],
        tech_stack=[t.strip() for t in args.tech_stack.split(",") if t.strip()] if args.tech_stack else None,
        endpoint=args.endpoint,
        payout=args.payout,
        severity=args.severity,
    )
    saved = ChainDB(paths["chains"]).save(entry)
    print(json.dumps({"saved": saved, "entry": entry}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Vulnerability intelligence layer — query/update hunt memory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("affinity", help="Rank vuln classes for a tech stack from historical wins/losses")
    p.add_argument("--tech", required=True, help="Comma-separated tech stack")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.add_argument("--top", type=int, default=None)
    p.set_defaults(func=_cmd_affinity)

    p = sub.add_parser("endpoint-stats", help="Historical hit rate for an endpoint's shape")
    p.add_argument("--url", required=True)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_endpoint_stats)

    p = sub.add_parser("failed-check", help="Has this technique already failed on this target?")
    p.add_argument("--target", required=True)
    p.add_argument("--technique", required=True)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_failed_check)

    p = sub.add_parser("chains", help="Known chains matching a tech stack (omit --tech for all)")
    p.add_argument("--tech", default="")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_chains)

    p = sub.add_parser("save-failed", help="Record a technique that did not pan out")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--technique", required=True)
    p.add_argument("--tech-stack", required=True, help="Comma-separated")
    p.add_argument("--endpoint", default=None)
    p.add_argument("--reason", default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_save_failed)

    p = sub.add_parser("save-chain", help="Record a confirmed multi-signal exploit chain")
    p.add_argument("--target", required=True)
    p.add_argument("--chain-name", required=True)
    p.add_argument("--steps", required=True, help="Pipe-separated, e.g. 'step one|step two|step three'")
    p.add_argument("--tech-stack", default=None, help="Comma-separated")
    p.add_argument("--endpoint", default=None)
    p.add_argument("--payout", type=float, default=None)
    p.add_argument("--severity", default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_save_chain)

    args = ap.parse_args()
    try:
        return args.func(args)
    except SchemaError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
