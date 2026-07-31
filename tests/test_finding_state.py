"""Tests for memory/finding_state.py — the finding lifecycle engine."""

import pytest

from memory.finding_state import (
    FINDING_STATES,
    FindingStateDB,
    FindingStateError,
    can_transition,
    transition,
)


class TestCanTransition:

    def test_legal_forward_step(self):
        result = can_transition("SUSPECTED", "TESTING")
        assert result["allowed"] is True

    def test_skip_ahead_rejected(self):
        result = can_transition("SUSPECTED", "CONFIRMED")
        assert result["allowed"] is False
        assert "not a legal transition" in result["reason"]

    def test_backward_step_rejected(self):
        result = can_transition("VALIDATED", "TESTING")
        assert result["allowed"] is False

    def test_any_non_terminal_state_can_reject(self):
        for state in ("SUSPECTED", "TESTING", "VALIDATED", "CONFIRMED"):
            result = can_transition(state, "REJECTED")
            assert result["allowed"] is True, f"{state} -> REJECTED should be legal"

    def test_rejected_is_terminal(self):
        result = can_transition("REJECTED", "SUSPECTED")
        assert result["allowed"] is False

    def test_report_ready_is_terminal(self):
        result = can_transition("REPORT_READY", "CONFIRMED")
        assert result["allowed"] is False

    def test_unknown_current_state_rejected(self):
        result = can_transition("NOT_A_STATE", "TESTING")
        assert result["allowed"] is False
        assert "not a known state" in result["reason"]

    def test_unknown_next_state_rejected(self):
        result = can_transition("SUSPECTED", "NOT_A_STATE")
        assert result["allowed"] is False
        assert "not a known state" in result["reason"]

    def test_confirmed_without_verdict_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED")
        assert result["allowed"] is False
        assert "weak evidence cannot become CONFIRMED" in result["reason"]

    def test_confirmed_with_weak_verdict_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED", {"verdict": "WEAK"})
        assert result["allowed"] is False

    def test_confirmed_with_reject_verdict_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED", {"verdict": "REJECT"})
        assert result["allowed"] is False

    def test_confirmed_with_strong_verdict_allowed(self):
        result = can_transition("VALIDATED", "CONFIRMED", {"verdict": "STRONG"})
        assert result["allowed"] is True

    def test_report_ready_without_reproducible_blocked(self):
        result = can_transition("CONFIRMED", "REPORT_READY")
        assert result["allowed"] is False
        assert "missing reproduction blocks REPORT_READY" in result["reason"]

    def test_report_ready_with_reproducible_false_blocked(self):
        result = can_transition("CONFIRMED", "REPORT_READY", {"reproducible": False})
        assert result["allowed"] is False

    def test_report_ready_with_reproducible_true_allowed(self):
        result = can_transition("CONFIRMED", "REPORT_READY", {"reproducible": True})
        assert result["allowed"] is True

    def test_all_states_covered_by_transition_table(self):
        # Sanity check that FINDING_STATES and the transition rules agree.
        from memory.finding_state import ALLOWED_TRANSITIONS
        assert set(ALLOWED_TRANSITIONS.keys()) == set(FINDING_STATES)


class TestTransition:

    def test_legal_transition_does_not_raise(self):
        transition("SUSPECTED", "TESTING")  # should not raise

    def test_illegal_transition_raises(self):
        with pytest.raises(FindingStateError, match="not a legal transition"):
            transition("SUSPECTED", "CONFIRMED")

    def test_weak_evidence_raises_on_confirm(self):
        with pytest.raises(FindingStateError, match="weak evidence cannot become CONFIRMED"):
            transition("VALIDATED", "CONFIRMED", {"verdict": "WEAK"})

    def test_missing_reproduction_raises_on_report_ready(self):
        with pytest.raises(FindingStateError, match="missing reproduction blocks REPORT_READY"):
            transition("CONFIRMED", "REPORT_READY")


class TestFindingStateDB:

    def test_save_and_read(self, finding_states_path, sample_finding_state_entry):
        db = FindingStateDB(finding_states_path)
        assert db.save(sample_finding_state_entry) is True
        assert finding_states_path.exists()
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["state"] == "TESTING"

    def test_read_all_on_missing_file(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        assert db.read_all() == []

    def test_current_state_none_when_no_history(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        assert db.current_state("a.com", "idor", "/api/x") is None

    def test_advance_first_call_must_be_suspected(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        with pytest.raises(FindingStateError, match="must register it as SUSPECTED"):
            db.advance("a.com", "idor", "/api/x", "TESTING")

    def test_advance_registers_suspected(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        entry = db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        assert entry["state"] == "SUSPECTED"
        assert db.current_state("a.com", "idor", "/api/x") == "SUSPECTED"

    def test_full_lifecycle_advances_in_order(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        db.advance("a.com", "idor", "/api/x", "CONFIRMED", evidence={"verdict": "STRONG"})
        db.advance("a.com", "idor", "/api/x", "REPORT_READY", evidence={"reproducible": True})
        assert db.current_state("a.com", "idor", "/api/x") == "REPORT_READY"

    def test_skip_ahead_via_advance_raises_and_does_not_persist(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        with pytest.raises(FindingStateError):
            db.advance("a.com", "idor", "/api/x", "CONFIRMED")
        # Still SUSPECTED -- the illegal attempt must not have been persisted.
        assert db.current_state("a.com", "idor", "/api/x") == "SUSPECTED"
        assert len(db.history("a.com", "idor", "/api/x")) == 1

    def test_confirm_without_strong_verdict_raises_and_does_not_persist(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        with pytest.raises(FindingStateError, match="weak evidence cannot become CONFIRMED"):
            db.advance("a.com", "idor", "/api/x", "CONFIRMED", evidence={"verdict": "WEAK"})
        assert db.current_state("a.com", "idor", "/api/x") == "VALIDATED"

    def test_report_ready_without_reproduction_raises_and_does_not_persist(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        db.advance("a.com", "idor", "/api/x", "CONFIRMED", evidence={"verdict": "STRONG"})
        with pytest.raises(FindingStateError, match="missing reproduction blocks REPORT_READY"):
            db.advance("a.com", "idor", "/api/x", "REPORT_READY")
        assert db.current_state("a.com", "idor", "/api/x") == "CONFIRMED"

    def test_history_ordered_oldest_first(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        hist = db.history("a.com", "idor", "/api/x")
        assert [e["state"] for e in hist] == ["SUSPECTED", "TESTING"]

    def test_history_matches_normalized_endpoint_shape(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/users/482/orders", "SUSPECTED")
        hist = db.history("a.com", "idor", "/api/users/9107/orders")
        assert len(hist) == 1

    def test_history_excludes_other_targets(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        assert db.history("other.com", "idor", "/api/x") == []

    def test_history_excludes_other_vuln_classes(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        assert db.history("a.com", "xss", "/api/x") == []

    def test_independent_findings_tracked_separately(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "xss", "/api/y", "SUSPECTED")
        assert db.current_state("a.com", "idor", "/api/x") == "TESTING"
        assert db.current_state("a.com", "xss", "/api/y") == "SUSPECTED"

    def test_rejected_reachable_from_any_non_terminal_state(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        entry = db.advance("a.com", "idor", "/api/x", "REJECTED")
        assert entry["state"] == "REJECTED"
        assert db.current_state("a.com", "idor", "/api/x") == "REJECTED"
