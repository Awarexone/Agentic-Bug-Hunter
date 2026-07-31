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
                         chain_priority()/ChainDB.rank() score chains by
                         impact/probability/effort (high/high/low ranks
                         first) instead of only raw payout.
  * ReportOutcomeDB   — what submitted reports actually turned into
                         (hunt-memory/report_outcomes.jsonl): accepted, N/A'd,
                         duplicate. Lets report-writer learn which vuln
                         classes/wording convert to paid reports.
  * tech_vuln_affinity / endpoint_shape_stats — pure query functions that turn
    patterns.jsonl + failed_patterns.jsonl (+ optionally journal.jsonl) into a
    tech-stack -> vuln-class affinity ranking and an endpoint-shape hit rate,
    without a separate cache file. The intelligence is derived, not duplicated.
  * priority_score    — the autopilot decision-engine formula (impact +
                         historical success + tech match + chain probability -
                         failure penalty), one canonical implementation shared
                         by recon-ranker and autopilot instead of two
                         independently-drifting scoring formulas.
  * expected_value_per_hour — wraps priority_score with real payout
                         probability (report_outcomes.jsonl) and an
                         estimated-testing-time cost, so recon-ranker can
                         answer "which P1 pays off fastest," not just
                         "which P1 scores highest."
  * duplicate_or_noise_check — has this target+vuln_class+endpoint already
                         been found (journal.jsonl), reported
                         (report_outcomes.jsonl), or already died here
                         (failed_patterns.jsonl)? The memory-backed half of
                         validation-engine's duplicate/noise filter.
  * HypothesisDB / hypothesis_calibration — logs every hypothesis
                         hypothesis-engine generates with its stated
                         confidence (hunt-memory/hypotheses.jsonl), then
                         checks that confidence against what journal.jsonl /
                         report_outcomes.jsonl say actually happened. Closes
                         the reasoning-quality feedback loop: a vuln class
                         whose 80-100%-confidence hypotheses only convert
                         40% of the time should get less trust next time,
                         not the same blind confidence forever.

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
    make_hypothesis_entry,
    make_report_outcome_entry,
    validate_chain_entry,
    validate_failed_pattern_entry,
    validate_hypothesis_entry,
    validate_report_outcome_entry,
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


# Static impact/effort priors for chain_priority() below, used only when a
# chain entry doesn't carry a numeric probability or a recognized impact/
# effort label yet -- same "static prior, real data overrides it" role as
# VULN_IMPACT_POTENTIAL/TESTING_TIME_ESTIMATES play for priority_score().
CHAIN_IMPACT_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25}
DEFAULT_CHAIN_IMPACT_SCORE = 50
# Inverted on purpose: low effort should score HIGH (it's cheap to pull off).
CHAIN_EFFORT_SCORE = {"low": 100, "medium": 60, "high": 20}
DEFAULT_CHAIN_EFFORT_SCORE = 60


def chain_priority(chain: dict) -> dict:
    """Impact/Probability/Effort composite score for one chain entry.

    High impact + high probability + low effort should rank first — the
    same "worth doing right now" question priority_score() answers for a
    single vuln_class, applied to a whole multi-step attack chain instead.
    Example the scoring is meant to surface: exposed endpoint + weak
    authorization + sensitive object = potential IDOR chain, high impact,
    high probability, low effort -> ranks above a chain that pays more on
    paper but needs a much harder-to-pull-off precondition.

    Chains missing impact/probability/effort (older entries, or ones that
    only ever carried payout/severity) get neutral mid-range scores rather
    than being excluded — this only ranks, it never filters.
    """
    impact_label = (chain.get("impact") or "").strip().lower()
    impact_score = CHAIN_IMPACT_SCORE.get(impact_label, DEFAULT_CHAIN_IMPACT_SCORE)

    probability = chain.get("probability")
    probability_score = probability if isinstance(probability, (int, float)) and not isinstance(probability, bool) else 50

    effort_label = (chain.get("effort") or "").strip().lower()
    effort_score = CHAIN_EFFORT_SCORE.get(effort_label, DEFAULT_CHAIN_EFFORT_SCORE)

    composite = round((impact_score + probability_score + effort_score) / 3, 1)

    return {
        "composite_score": composite,
        "impact_score": impact_score,
        "probability_score": probability_score,
        "effort_score": effort_score,
        "has_scoring_data": bool(chain.get("impact") or chain.get("effort") or probability is not None),
    }


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

    def rank(self, tech_stack: list[str] | None = None) -> list[dict]:
        """match() results ordered by chain_priority() instead of raw payout —
        high impact, high probability, low effort first. Chains that don't
        carry impact/probability/effort yet still rank (via chain_priority()'s
        neutral defaults), just below ones with real scoring data attached."""
        chains = self.match(tech_stack)
        scored = [{**c, "chain_priority": chain_priority(c)} for c in chains]
        scored.sort(
            key=lambda c: (c["chain_priority"]["composite_score"], c.get("payout", 0)),
            reverse=True,
        )
        return scored


class ReportOutcomeDB(_JsonlDB):
    """What happened to submitted reports — feeds report-writer's acceptance-pattern learning.

    Not deduplicated on a narrow key like the other two DBs: the same
    vuln_class can (and should) accumulate many outcome data points over
    time on the same target as different reports come back triaged.
    """

    dedup_fields = ("target", "vuln_class", "outcome", "ts")

    def _validate(self, entry: dict) -> dict:
        return validate_report_outcome_entry(entry)

    def acceptance_rate(self, vuln_class: str | None = None) -> dict:
        """Fraction of outcomes that were accepted/triaged (paid) vs closed as noise.

        Groups by vuln_class so report-writer can see "idor reports get
        accepted 90% of the time, xss reports get closed informative 60% of
        the time" and weight its wording/evidence bar accordingly.
        """
        entries = self.read_all()
        if vuln_class is not None:
            entries = [e for e in entries if e.get("vuln_class") == vuln_class]

        by_class: dict[str, dict] = {}
        good = {"accepted", "triaged", "resolved"}
        for e in entries:
            vc = e.get("vuln_class", "unknown")
            d = by_class.setdefault(vc, {"vuln_class": vc, "accepted": 0, "closed_no_action": 0, "payout_total": 0.0})
            if e.get("outcome") in good:
                d["accepted"] += 1
                d["payout_total"] += e.get("payout", 0) or 0
            else:
                d["closed_no_action"] += 1

        results = []
        for vc, d in by_class.items():
            total = d["accepted"] + d["closed_no_action"]
            results.append({
                "vuln_class": vc,
                "accepted": d["accepted"],
                "closed_no_action": d["closed_no_action"],
                "acceptance_rate": round(100 * d["accepted"] / total) if total else None,
                "avg_payout": round(d["payout_total"] / d["accepted"], 2) if d["accepted"] else 0,
                "sample_size": total,
            })
        results.sort(key=lambda r: (r["acceptance_rate"] or 0, r["sample_size"]), reverse=True)
        return {"by_vuln_class": results}


class HypothesisDB(_JsonlDB):
    """Every hypothesis hypothesis-engine generated, with its stated confidence.

    Not deduplicated on a narrow key (same reasoning as ReportOutcomeDB): the
    same target+vuln_class+endpoint can legitimately be re-hypothesized as
    new signals accumulate, and each generation is its own calibration data
    point. This is the *prediction* half of the calibration loop —
    hypothesis_calibration() below joins it against journal.jsonl /
    report_outcomes.jsonl (the *actual* half) by target+vuln_class+endpoint
    shape, the same join key duplicate_or_noise_check() uses.
    """

    dedup_fields = ("target", "vuln_class", "endpoint", "confidence", "ts")

    def _validate(self, entry: dict) -> dict:
        return validate_hypothesis_entry(entry)


def hypothesis_calibration(
    hypotheses: list[dict],
    journal_entries: list[dict] | None = None,
    report_outcomes: list[dict] | None = None,
) -> dict:
    """Does hypothesis-engine's stated confidence match what actually happens?

    Buckets hypotheses by confidence decile-ish range, and for each bucket
    resolves whether the hypothesis panned out: a matching report_outcomes
    entry (accepted/triaged/resolved) counts as a hit; failing that, a
    matching journal entry (confirmed/partial) counts as a hit; a hypothesis
    with neither is unresolved (not yet tested), not a miss — don't punish
    the confidence score for something never actually tried.

    `calibration_gap` = stated confidence average minus actual hit rate.
    Positive = overconfident (says 90%, converts at 60%). Negative =
    underconfident. hypothesis-engine should read this and adjust, not
    just report raw signal counts as if every bucket is equally trustworthy.
    """
    journal_entries = journal_entries or []
    report_outcomes = report_outcomes or []

    def _resolved(h: dict) -> tuple[bool, bool]:
        """Returns (hit, resolved)."""
        target = h.get("target")
        vuln_class = h.get("vuln_class")
        shape = normalize_endpoint(h.get("endpoint", ""))

        matching_outcomes = [
            o for o in report_outcomes
            if o.get("target") == target and o.get("vuln_class") == vuln_class
        ]
        if matching_outcomes:
            good = {"accepted", "triaged", "resolved"}
            return any(o.get("outcome") in good for o in matching_outcomes), True

        matching_journal = [
            j for j in journal_entries
            if j.get("target") == target and j.get("vuln_class") == vuln_class
            and normalize_endpoint(j.get("endpoint", "")) == shape
        ]
        if matching_journal:
            good_results = {"confirmed", "partial"}
            return any(j.get("result") in good_results for j in matching_journal), True

        return False, False

    bucket_edges = [(0, 20), (20, 40), (40, 60), (60, 80), (80, 101)]

    def _bucket_for(confidence: float) -> tuple[int, int]:
        for lo, hi in bucket_edges:
            if lo <= confidence < hi:
                return (lo, hi)
        return bucket_edges[-1]

    buckets: dict[tuple[int, int], dict] = {}
    for h in hypotheses:
        confidence = h.get("confidence", 0)
        b = _bucket_for(confidence)
        d = buckets.setdefault(b, {"count": 0, "resolved": 0, "hits": 0, "confidence_sum": 0.0})
        d["count"] += 1
        d["confidence_sum"] += confidence
        hit, resolved = _resolved(h)
        if resolved:
            d["resolved"] += 1
            if hit:
                d["hits"] += 1

    results = []
    for (lo, hi), d in sorted(buckets.items()):
        stated_avg = round(d["confidence_sum"] / d["count"], 1) if d["count"] else 0.0
        actual_rate = round(100 * d["hits"] / d["resolved"]) if d["resolved"] else None
        results.append({
            "confidence_bucket": f"{lo}-{hi}",
            "stated_confidence_avg": stated_avg,
            "hypotheses_count": d["count"],
            "resolved_count": d["resolved"],
            "unresolved_count": d["count"] - d["resolved"],
            "actual_hit_rate": actual_rate,
            "calibration_gap": (round(stated_avg - actual_rate, 1) if actual_rate is not None else None),
        })

    return {"buckets": results}


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


# Static impact prior per vuln class, used only when no memory data exists
# yet to derive it from — same role as mindmap.py's static priors for
# tech_vuln_affinity. Override with impact_override once real report-outcome
# payout data exists for a vuln class.
VULN_IMPACT_POTENTIAL = {
    "rce": 100, "sqli": 95, "auth-bypass": 90, "ato": 90, "ssrf": 85,
    "ssti": 85, "saml": 85, "idor": 80, "file-upload": 80, "xxe": 80,
    "oauth": 80, "graphql": 75, "race-condition": 65, "cors": 60,
    "xss": 55, "misconfig": 40, "open-redirect": 35, "info-disclosure": 30,
}
DEFAULT_IMPACT_POTENTIAL = 50

# How much real report_outcomes.jsonl data it takes before it's trusted to
# nudge the static impact prior at all, and how far it's ever allowed to pull
# it (bounded — a handful of noisy outcomes shouldn't overwrite a reasonable
# starting point, only lean on it).
MIN_SAMPLES_FOR_IMPACT_RECALIBRATION = 5
MAX_IMPACT_RECALIBRATION_WEIGHT = 0.5


def _recalibrated_impact(vuln_class: str, static_prior: float, report_outcomes: list[dict]) -> dict:
    """Blend the static VULN_IMPACT_POTENTIAL prior toward this vuln_class's
    observed acceptance rate once report_outcomes.jsonl has enough samples,
    instead of trusting a hand-written constant forever — the self-learning
    half of the decision engine. A vuln class whose accepted/triaged rate is
    consistently below its assumed impact should get less trust over time;
    one that consistently converts should get more, capped so real data can
    pull the prior at most halfway even with a huge sample.
    """
    matching = [o for o in report_outcomes if o.get("vuln_class") == vuln_class]
    sample_size = len(matching)
    if sample_size < MIN_SAMPLES_FOR_IMPACT_RECALIBRATION:
        return {"impact": static_prior, "recalibrated": False, "sample_size": sample_size}

    good = {"accepted", "triaged", "resolved"}
    accepted = sum(1 for o in matching if o.get("outcome") in good)
    observed_acceptance_rate = 100 * accepted / sample_size

    weight = min(MAX_IMPACT_RECALIBRATION_WEIGHT, sample_size * 0.05)
    blended = round(static_prior * (1 - weight) + observed_acceptance_rate * weight, 1)

    return {
        "impact": blended,
        "recalibrated": True,
        "sample_size": sample_size,
        "observed_acceptance_rate": round(observed_acceptance_rate),
        "blend_weight": round(weight, 2),
        "static_prior": static_prior,
    }


def priority_score(
    vuln_class: str,
    tech_stack: list[str],
    target: str,
    technique: str | None = None,
    patterns: list[dict] | None = None,
    failed_patterns: list[dict] | None = None,
    chains: list[dict] | None = None,
    chain_detected: bool = False,
    impact_override: float | None = None,
    report_outcomes: list[dict] | None = None,
) -> dict:
    """The autopilot decision-engine formula:

        Priority = impact_potential + historical_success_probability
                 + technology_match + attack_chain_probability
                 - failure_penalty

    Every positive component is scaled 0-100, so the base score is their
    average; failure_penalty (100 when this exact target+technique already
    failed) then pulls it down — a real hit drives the score to 0, a hard
    kill signal matching recon-ranker's failed-pattern rule.

    This is the single source of truth for "which endpoint/vuln-class goes
    first" — both recon-ranker and autopilot call this (via the CLI) instead
    of each re-deriving their own formula.
    """
    patterns = patterns or []
    failed_patterns = failed_patterns or []
    chains = chains or []
    report_outcomes = report_outcomes or []

    static_impact = VULN_IMPACT_POTENTIAL.get(vuln_class.lower(), DEFAULT_IMPACT_POTENTIAL)
    if impact_override is not None:
        impact = impact_override
        impact_recalibration = {"impact": impact, "recalibrated": False, "sample_size": 0}
    elif report_outcomes:
        impact_recalibration = _recalibrated_impact(vuln_class, static_impact, report_outcomes)
        impact = impact_recalibration["impact"]
    else:
        impact = static_impact
        impact_recalibration = {"impact": impact, "recalibrated": False, "sample_size": 0}

    affinity_list = tech_vuln_affinity(tech_stack, patterns, failed_patterns)
    affinity = next((a for a in affinity_list if a["vuln_class"] == vuln_class), None)

    if affinity and (affinity["wins"] + affinity["losses"]) > 0:
        sample = affinity["wins"] + affinity["losses"]
        historical_success = round(100 * affinity["wins"] / sample)
        technology_match = affinity["confidence"]
    else:
        # No data either way: neutral on success probability, floor on tech
        # match confidence — mirrors recon-ranker's "heuristic-only" convention.
        historical_success = 50
        technology_match = 20

    matching_chains = [c for c in chains if _tech_overlap(tech_stack, c.get("tech_stack", []))]
    if chain_detected:
        attack_chain_probability = 90
    elif matching_chains:
        attack_chain_probability = 60
    else:
        attack_chain_probability = 0

    failed_entry = None
    if technique:
        failed_entry = next(
            (f for f in failed_patterns if f.get("target") == target and f.get("technique") == technique),
            None,
        )
    failure_penalty = 100 if failed_entry else 0

    base = (impact + historical_success + technology_match + attack_chain_probability) / 4
    score = max(0, min(100, round(base - failure_penalty)))

    return {
        "vuln_class": vuln_class,
        "score": score,
        "hard_kill": failure_penalty >= 100,
        "components": {
            "impact_potential": impact,
            "historical_success_probability": historical_success,
            "technology_match": technology_match,
            "attack_chain_probability": attack_chain_probability,
            "failure_penalty": failure_penalty,
        },
        "failed_pattern_reason": failed_entry.get("reason") if failed_entry else None,
        "matching_chains": [c["chain_name"] for c in matching_chains],
        "impact_recalibration": impact_recalibration,
    }


# Rough per-vuln-class testing time, used only when the caller doesn't
# supply --minutes. Same role as VULN_IMPACT_POTENTIAL above: a static
# prior, overridden the moment real data (or a caller's own estimate) exists.
TESTING_TIME_ESTIMATES = {
    "rce": 40, "sqli": 30, "auth-bypass": 30, "ato": 35, "ssrf": 25,
    "ssti": 30, "saml": 35, "idor": 20, "file-upload": 25, "xxe": 25,
    "oauth": 30, "graphql": 25, "race-condition": 20, "cors": 15,
    "xss": 15, "misconfig": 15, "open-redirect": 10, "info-disclosure": 10,
}
DEFAULT_TESTING_TIME_MINUTES = 20


def expected_value_per_hour(
    vuln_class: str,
    tech_stack: list[str],
    target: str,
    technique: str | None = None,
    patterns: list[dict] | None = None,
    failed_patterns: list[dict] | None = None,
    chains: list[dict] | None = None,
    chain_detected: bool = False,
    impact_override: float | None = None,
    report_outcomes: list[dict] | None = None,
    estimated_minutes: float | None = None,
) -> dict:
    """Expected-value-per-hour: which candidate pays off *fastest*, not just highest.

    Wraps priority_score() — the single source of truth for the 0-100
    score — and adds the two axes that formula alone doesn't have: real
    conversion probability (from report_outcomes.jsonl when there's data,
    the same historical_success_probability heuristic otherwise) and time
    cost. Two P1s with the same score can have very different EV/hr once
    one takes 45 minutes to test and the other takes 15.
    """
    report_outcomes = report_outcomes or []
    score_result = priority_score(
        vuln_class, tech_stack, target, technique,
        patterns, failed_patterns, chains, chain_detected, impact_override,
        report_outcomes=report_outcomes,
    )

    outcomes_for_class = [o for o in report_outcomes if o.get("vuln_class") == vuln_class]
    if outcomes_for_class:
        good = {"accepted", "triaged", "resolved"}
        accepted = sum(1 for o in outcomes_for_class if o.get("outcome") in good)
        payout_probability = round(100 * accepted / len(outcomes_for_class))
        payout_probability_source = "report_outcomes.jsonl"
    else:
        # No conversion data yet: fall back to the score's own
        # historical_success_probability component — same "heuristic-only"
        # convention priority_score itself uses when memory is empty.
        payout_probability = score_result["components"]["historical_success_probability"]
        payout_probability_source = "heuristic (no report-outcome data)"

    minutes = (
        estimated_minutes if estimated_minutes is not None
        else TESTING_TIME_ESTIMATES.get(vuln_class.lower(), DEFAULT_TESTING_TIME_MINUTES)
    )
    if minutes <= 0:
        raise ValueError("estimated_minutes must be positive")

    hard_kill = score_result["hard_kill"]
    ev_per_hour = 0 if hard_kill else round(score_result["score"] * (payout_probability / 100) * (60 / minutes), 1)

    if hard_kill:
        ev_label = "Kill"
    elif ev_per_hour >= 60:
        ev_label = "High"
    elif ev_per_hour >= 25:
        ev_label = "Medium"
    else:
        ev_label = "Low"

    return {
        "vuln_class": vuln_class,
        "score": score_result["score"],
        "hard_kill": hard_kill,
        "estimated_minutes": minutes,
        "payout_probability": payout_probability,
        "payout_probability_source": payout_probability_source,
        "ev_per_hour": ev_per_hour,
        "ev_label": ev_label,
        "priority_components": score_result["components"],
        "impact_recalibration": score_result["impact_recalibration"],
    }


def format_decision(
    result: dict,
    endpoint: str,
    next_experiment: str,
    affinity: dict | None = None,
) -> str:
    """Render a priority_score()/expected_value_per_hour() result as the
    standard decision-explanation block every agent presents before testing
    something:

        Decision: / Reason: / Evidence: / Confidence: / Expected Impact: /
        Estimated Effort: / Previous Similar Results: / Next Experiment:

    Pure presentation layer — every value here is read from a dict
    priority_score()/expected_value_per_hour() already computed, or from an
    optional tech_vuln_affinity() entry passed in as `affinity`. This
    function derives no new signal of its own.

    Accepts either shape: the richer expected_value_per_hour() dict
    (detected via the 'ev_per_hour' key) or a bare priority_score() dict.
    """
    vuln_class = result.get("vuln_class", "unknown")
    components = result.get("priority_components") or result.get("components") or {}
    hard_kill = result.get("hard_kill", False)
    is_ev_shape = "ev_per_hour" in result

    decision = f"KILL — {vuln_class}" if hard_kill else f"Test {vuln_class}"

    reasons = []
    if components.get("attack_chain_probability", 0) >= 60:
        reasons.append("chain/hypothesis correlation detected on this tech stack")
    if components.get("historical_success_probability", 0) >= 60:
        reasons.append(f"{components['historical_success_probability']}% historical success on this stack")
    if components.get("technology_match", 0) >= 50:
        reasons.append("strong tech-stack match in memory")
    if not reasons:
        reasons.append("heuristic-only — no strong memory signal yet, treat confidence accordingly")
    reason = ". ".join(reasons) + "."

    evidence_lines = []
    if result.get("matching_chains"):
        evidence_lines.append(f"- Matching chains: {', '.join(result['matching_chains'])}")
    if result.get("failed_pattern_reason"):
        evidence_lines.append(f"- Failed-pattern note: {result['failed_pattern_reason']}")
    recal = result.get("impact_recalibration")
    if recal and recal.get("recalibrated"):
        evidence_lines.append(
            f"- Impact recalibrated {recal['static_prior']}->{recal['impact']} "
            f"from {recal['sample_size']} real report outcomes"
        )
    if not evidence_lines:
        evidence_lines.append("- No chain/failed-pattern/recalibration evidence yet — heuristic only")
    evidence = "\n".join(evidence_lines)

    confidence = components.get("technology_match", 20)

    if is_ev_shape:
        expected_impact = f"{result['ev_label']} (EV/hr {result['ev_per_hour']}, payout probability {result['payout_probability']}%)"
        minutes = result.get("estimated_minutes")
        if minutes is None:
            estimated_effort = "not estimated"
        elif minutes < 15:
            estimated_effort = f"Low (~{minutes} min)"
        elif minutes <= 30:
            estimated_effort = f"Medium (~{minutes} min)"
        else:
            estimated_effort = f"High (~{minutes} min)"
    else:
        expected_impact = f"score {result.get('score', 0)}/100"
        estimated_effort = "not estimated (pass an expected_value_per_hour() result for a time estimate)"

    if affinity:
        wins, losses = affinity.get("wins", 0), affinity.get("losses", 0)
        if wins or losses:
            # cross_target only tells us whether multiple distinct targets
            # contributed, not whether any of them is the current query target —
            # tech_vuln_affinity() doesn't expose that, so keep the wording
            # honest about what's actually known.
            scope = "across multiple targets sharing this tech stack" if affinity.get("cross_target") else "on a target sharing this tech stack"
            payout_note = f", avg payout ${affinity['avg_payout']}" if affinity.get("avg_payout") else ""
            previous_results = f"{wins} win(s) / {losses} loss(es) {scope}{payout_note}"
        else:
            previous_results = "no prior attempts recorded for this vuln class on this stack"
    else:
        previous_results = "not checked (pass a tech_vuln_affinity() entry for real history)"

    return (
        f"Decision:\n{decision}\n\n"
        f"Reason:\n{reason}\n\n"
        f"Evidence:\n{evidence}\n\n"
        f"Confidence:\n{confidence}%\n\n"
        f"Expected Impact:\n{expected_impact}\n\n"
        f"Estimated Effort:\n{estimated_effort}\n\n"
        f"Previous Similar Results:\n{previous_results}\n\n"
        f"Next Experiment:\n{next_experiment} on {endpoint}"
    )


def duplicate_or_noise_check(
    target: str,
    vuln_class: str,
    endpoint: str,
    journal_entries: list[dict] | None = None,
    report_outcomes: list[dict] | None = None,
    failed_patterns: list[dict] | None = None,
) -> dict:
    """Has this exact finding already been logged, reported, or already died here?

    The memory-backed half of validation-engine's "is it duplicate/noise"
    check — cheap and instant against data already on disk, run before the
    more expensive external Hacktivity/GitHub search that stays part of
    validator's Gate 2. Matches by exact endpoint OR normalized shape, so
    `/api/users/12/orders` and `/api/users/9107/orders` count as the same
    surface for this check.
    """
    journal_entries = journal_entries or []
    report_outcomes = report_outcomes or []
    failed_patterns = failed_patterns or []
    shape = normalize_endpoint(endpoint) if endpoint else None

    def _same_endpoint(candidate: str | None) -> bool:
        if not candidate:
            return False
        return candidate == endpoint or (shape is not None and normalize_endpoint(candidate) == shape)

    already_found = [
        j for j in journal_entries
        if j.get("target") == target and j.get("vuln_class") == vuln_class
        and j.get("result") in ("confirmed", "partial")
        and _same_endpoint(j.get("endpoint"))
    ]
    already_reported = [
        o for o in report_outcomes
        if o.get("target") == target and o.get("vuln_class") == vuln_class
    ]
    already_failed = [
        f for f in failed_patterns
        if f.get("target") == target and f.get("vuln_class") == vuln_class
        and _same_endpoint(f.get("endpoint"))
    ]

    is_duplicate = bool(already_found) or bool(already_reported)
    is_noise = bool(already_failed) and not is_duplicate

    return {
        "is_duplicate": is_duplicate,
        "is_noise": is_noise,
        "clean": not is_duplicate and not is_noise,
        "matching_journal_entries": len(already_found),
        "matching_report_outcomes": [o.get("outcome") for o in already_reported],
        "matching_failed_patterns": len(already_failed),
    }


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
        "report_outcomes": base / "report_outcomes.jsonl",
        "hypotheses": base / "hypotheses.jsonl",
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
    db = ChainDB(paths["chains"])
    result = db.rank(tech_stack) if args.rank else db.match(tech_stack)
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
        impact=args.impact,
        probability=args.probability,
        effort=args.effort,
    )
    saved = ChainDB(paths["chains"]).save(entry)
    print(json.dumps({"saved": saved, "entry": entry}, indent=2))
    return 0


def _cmd_priority(args: argparse.Namespace) -> int:
    from memory.pattern_db import PatternDB

    paths = _memory_paths(args.memory_dir)
    patterns = PatternDB(paths["patterns"]).read_all()
    failed = FailedPatternDB(paths["failed_patterns"]).read_all()
    chains = ChainDB(paths["chains"]).read_all()
    outcomes = ReportOutcomeDB(paths["report_outcomes"]).read_all()
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()]
    result = priority_score(
        vuln_class=args.vuln_class,
        tech_stack=tech_stack,
        target=args.target,
        technique=args.technique,
        patterns=patterns,
        failed_patterns=failed,
        chains=chains,
        chain_detected=args.chain_detected,
        impact_override=args.impact_override,
        report_outcomes=outcomes,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_decision(args: argparse.Namespace) -> int:
    from memory.pattern_db import PatternDB

    paths = _memory_paths(args.memory_dir)
    patterns = PatternDB(paths["patterns"]).read_all()
    failed = FailedPatternDB(paths["failed_patterns"]).read_all()
    chains = ChainDB(paths["chains"]).read_all()
    outcomes = ReportOutcomeDB(paths["report_outcomes"]).read_all()
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()]

    result = expected_value_per_hour(
        vuln_class=args.vuln_class,
        tech_stack=tech_stack,
        target=args.target,
        technique=args.technique,
        patterns=patterns,
        failed_patterns=failed,
        chains=chains,
        chain_detected=args.chain_detected,
        impact_override=args.impact_override,
        report_outcomes=outcomes,
        estimated_minutes=args.minutes,
    )
    affinity_list = tech_vuln_affinity(tech_stack, patterns, failed)
    affinity = next((a for a in affinity_list if a["vuln_class"] == args.vuln_class), None)

    print(format_decision(result, args.endpoint, args.next_experiment, affinity=affinity))
    return 0


def _cmd_save_outcome(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    entry = make_report_outcome_entry(
        target=args.target,
        vuln_class=args.vuln_class,
        outcome=args.outcome,
        technique=args.technique,
        platform=args.platform,
        severity=args.severity,
        payout=args.payout,
        report_id=args.report_id,
        notes=args.notes,
    )
    saved = ReportOutcomeDB(paths["report_outcomes"]).save(entry)
    print(json.dumps({"saved": saved, "entry": entry}, indent=2))
    return 0


def _cmd_outcomes(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    result = ReportOutcomeDB(paths["report_outcomes"]).acceptance_rate(args.vuln_class or None)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_ev(args: argparse.Namespace) -> int:
    from memory.pattern_db import PatternDB

    paths = _memory_paths(args.memory_dir)
    patterns = PatternDB(paths["patterns"]).read_all()
    failed = FailedPatternDB(paths["failed_patterns"]).read_all()
    chains = ChainDB(paths["chains"]).read_all()
    outcomes = ReportOutcomeDB(paths["report_outcomes"]).read_all()
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()]
    result = expected_value_per_hour(
        vuln_class=args.vuln_class,
        tech_stack=tech_stack,
        target=args.target,
        technique=args.technique,
        patterns=patterns,
        failed_patterns=failed,
        chains=chains,
        chain_detected=args.chain_detected,
        impact_override=args.impact_override,
        report_outcomes=outcomes,
        estimated_minutes=args.minutes,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_duplicate_check(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    journal = _read_jsonl_best_effort(paths["journal"])
    outcomes = ReportOutcomeDB(paths["report_outcomes"]).read_all()
    failed = FailedPatternDB(paths["failed_patterns"]).read_all()
    result = duplicate_or_noise_check(
        target=args.target,
        vuln_class=args.vuln_class,
        endpoint=args.endpoint,
        journal_entries=journal,
        report_outcomes=outcomes,
        failed_patterns=failed,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_save_hypothesis(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    entry = make_hypothesis_entry(
        target=args.target,
        vuln_class=args.vuln_class,
        endpoint=args.endpoint,
        confidence=args.confidence,
        hypothesis_name=args.hypothesis_name,
        tech_stack=[t.strip() for t in args.tech_stack.split(",") if t.strip()] if args.tech_stack else None,
        signals=[s.strip() for s in args.signals.split("|") if s.strip()] if args.signals else None,
        source=args.source,
        attack_chain=[s.strip() for s in args.attack_chain.split("|") if s.strip()] if args.attack_chain else None,
        impact=args.impact,
        probability=args.probability,
        effort=args.effort,
    )
    saved = HypothesisDB(paths["hypotheses"]).save(entry)
    print(json.dumps({"saved": saved, "entry": entry}, indent=2))
    return 0


def _cmd_calibration(args: argparse.Namespace) -> int:
    paths = _memory_paths(args.memory_dir)
    hypotheses = HypothesisDB(paths["hypotheses"]).read_all()
    if args.vuln_class:
        hypotheses = [h for h in hypotheses if h.get("vuln_class") == args.vuln_class]
    journal = _read_jsonl_best_effort(paths["journal"])
    outcomes = ReportOutcomeDB(paths["report_outcomes"]).read_all()
    result = hypothesis_calibration(hypotheses, journal_entries=journal, report_outcomes=outcomes)
    print(json.dumps(result, indent=2))
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
    p.add_argument("--rank", action="store_true", help="Order by impact/probability/effort composite score instead of raw payout")
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
    p.add_argument("--impact", default=None, help="e.g. critical/high/medium/low")
    p.add_argument("--probability", type=float, default=None, help="0-100, how likely this chain holds up end-to-end")
    p.add_argument("--effort", default=None, help="e.g. low/medium/high")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_save_chain)

    p = sub.add_parser("priority", help="Decision-engine score: impact + success + tech match + chain - failure penalty")
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--tech", required=True, help="Comma-separated tech stack")
    p.add_argument("--target", required=True)
    p.add_argument("--technique", default=None, help="Checked against failed_patterns.jsonl for a hard kill")
    p.add_argument("--chain-detected", action="store_true", help="This candidate is part of a lead-board chain")
    p.add_argument("--impact-override", type=float, default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_priority)

    p = sub.add_parser("decision", help="Human-readable Decision/Reason/Evidence/... block for a candidate")
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--tech", required=True, help="Comma-separated tech stack")
    p.add_argument("--target", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--next-experiment", required=True)
    p.add_argument("--technique", default=None)
    p.add_argument("--chain-detected", action="store_true")
    p.add_argument("--impact-override", type=float, default=None)
    p.add_argument("--minutes", type=float, default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_decision)

    p = sub.add_parser("save-outcome", help="Record what a submitted report turned into (accepted/N-A/duplicate/...)")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--outcome", required=True, choices=sorted(
        {"accepted", "triaged", "duplicate", "informative", "not_applicable", "resolved"}
    ))
    p.add_argument("--technique", default=None)
    p.add_argument("--platform", default=None, help="hackerone / bugcrowd / intigriti / immunefi")
    p.add_argument("--severity", default=None)
    p.add_argument("--payout", type=float, default=None)
    p.add_argument("--report-id", default=None)
    p.add_argument("--notes", default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_save_outcome)

    p = sub.add_parser("outcomes", help="Acceptance rate by vuln class, from report_outcomes.jsonl")
    p.add_argument("--vuln-class", default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_outcomes)

    p = sub.add_parser("ev", help="Expected value per hour: priority_score + payout probability + time cost")
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--tech", required=True, help="Comma-separated tech stack")
    p.add_argument("--target", required=True)
    p.add_argument("--technique", default=None)
    p.add_argument("--chain-detected", action="store_true")
    p.add_argument("--impact-override", type=float, default=None)
    p.add_argument("--minutes", type=float, default=None, help="Override the static per-vuln-class time estimate")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_ev)

    p = sub.add_parser("duplicate-check", help="Is this finding already in journal/report_outcomes/failed_patterns?")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_duplicate_check)

    p = sub.add_parser("save-hypothesis", help="Log a generated hypothesis with its stated confidence")
    p.add_argument("--target", required=True)
    p.add_argument("--vuln-class", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--confidence", type=float, required=True, help="0-100")
    p.add_argument("--hypothesis-name", default=None)
    p.add_argument("--tech-stack", default=None, help="Comma-separated")
    p.add_argument("--signals", default=None, help="Pipe-separated, e.g. 'signal one|signal two'")
    p.add_argument("--source", default=None, help="e.g. hypothesis-engine, lead-board-chain, lead-board-hypothesis")
    p.add_argument("--attack-chain", default=None, help="Pipe-separated ordered steps, e.g. 'JS secret|API access|auth bypass'")
    p.add_argument("--impact", default=None, help="e.g. critical/high/medium/low")
    p.add_argument("--probability", type=float, default=None, help="0-100")
    p.add_argument("--effort", default=None, help="e.g. low/medium/high")
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_save_hypothesis)

    p = sub.add_parser("calibration", help="Does stated hypothesis confidence match actual outcomes?")
    p.add_argument("--vuln-class", default=None)
    p.add_argument("--memory-dir", default="hunt-memory")
    p.set_defaults(func=_cmd_calibration)

    args = ap.parse_args()
    try:
        return args.func(args)
    except SchemaError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
