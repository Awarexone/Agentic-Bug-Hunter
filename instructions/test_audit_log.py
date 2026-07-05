"""Tests for memory/audit_log.py — audit log, rate limiter, circuit breaker."""

import json
import time
import pytest

from memory.audit_log import AuditLog, RateLimiter, CircuitBreaker
from memory.schemas import SchemaError, CURRENT_SCHEMA_VERSION, make_audit_entry


class TestAuditLogWrite:

    def test_log_creates_file(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        entry = make_audit_entry(
            url="https://api.target.com/v2/users/1",
            method="GET",
            scope_check="pass",
            response_status=200,
            session_id="test-001",
        )
        log.log(entry)
        assert path.exists()

    def test_log_writes_valid_jsonl(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        entry = make_audit_entry(
            url="https://api.target.com/v2/users/1",
            method="GET",
            scope_check="pass",
        )
        log.log(entry)
        with open(path) as f:
            parsed = json.loads(f.readline())
        assert parsed["url"] == "https://api.target.com/v2/users/1"
        assert parsed["method"] == "GET"

    def test_log_request_convenience(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        log.log_request(
            url="https://api.target.com/test",
            method="POST",
            scope_check="pass",
            response_status=201,
            session_id="sess-1",
        )
        entries = log.read_all()
        assert len(entries) == 1
        assert entries[0]["response_status"] == 201

    def test_log_scope_fail(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        log.log_request(
            url="https://evil.com/hack",
            method="GET",
            scope_check="fail",
            error="out of scope",
        )
        entries = log.read_all()
        assert entries[0]["scope_check"] == "fail"
        assert entries[0]["error"] == "out of scope"

    def test_log_rejects_invalid_method(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        with pytest.raises(SchemaError, match="'method' must be one of"):
            log.log_request(
                url="https://target.com",
                method="DESTROY",
                scope_check="pass",
            )


class TestAuditLogRead:

    def test_read_empty(self, tmp_hunt_dir):
        log = AuditLog(tmp_hunt_dir / "audit.jsonl")
        assert log.read_all() == []

    def test_read_skips_corrupted(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        log.log_request(url="https://a.com", method="GET", scope_check="pass")
        with open(path, "a") as f:
            f.write("not json\n")
        log.log_request(url="https://b.com", method="GET", scope_check="pass")
        entries = log.read_all()
        assert len(entries) == 2

    def test_count_by_session(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)
        log.log_request(url="https://a.com", method="GET", scope_check="pass", session_id="s1")
        log.log_request(url="https://b.com", method="GET", scope_check="pass", session_id="s1")
        log.log_request(url="https://c.com", method="GET", scope_check="fail", session_id="s1")
        log.log_request(url="https://d.com", method="GET", scope_check="pass", session_id="s2")

        counts = log.count_by_session("s1")
        assert counts["total"] == 3
        assert counts["pass"] == 2
        assert counts["fail"] == 1


class TestAuditSchema:

    def test_valid_full_entry(self):
        entry = make_audit_entry(
            url="https://target.com/api",
            method="GET",
            scope_check="pass",
            response_status=200,
            finding_id="f-001",
            session_id="autopilot-001",
        )
        assert entry["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_valid_minimal_entry(self):
        entry = make_audit_entry(
            url="https://target.com",
            method="HEAD",
            scope_check="skip",
        )
        assert "response_status" not in entry

    def test_invalid_scope_check(self):
        with pytest.raises(SchemaError, match="'scope_check' must be one of"):
            make_audit_entry(url="https://t.com", method="GET", scope_check="maybe")

    def test_invalid_response_status_type(self):
        with pytest.raises(SchemaError, match="'response_status' must be an integer"):
            from memory.schemas import validate_audit_entry
            validate_audit_entry({
                "ts": "2026-03-24T21:00:00Z",
                "url": "https://t.com",
                "method": "GET",
                "scope_check": "pass",
                "response_status": "200",
                "schema_version": CURRENT_SCHEMA_VERSION,
            })


class TestRateLimiter:

    def test_first_request_no_wait(self):
        rl = RateLimiter(test_rps=10.0)
        waited = rl.wait("target.com")
        assert waited == 0.0

    def test_enforces_interval(self):
        rl = RateLimiter(test_rps=10.0)  # 0.1s interval
        rl.wait("target.com")
        start = time.monotonic()
        rl.wait("target.com")
        elapsed = time.monotonic() - start
        assert elapsed >= 0.05  # should wait ~0.1s, allow margin

    def test_different_hosts_independent(self):
        rl = RateLimiter(test_rps=2.0)  # 0.5s interval
        rl.wait("host-a.com")
        waited = rl.wait("host-b.com")  # different host, no wait
        assert waited == 0.0

    def test_recon_faster_than_test(self):
        rl = RateLimiter(recon_rps=100.0, test_rps=1.0)
        assert rl.recon_interval < rl.test_interval


class TestCircuitBreaker:

    def test_not_tripped_initially(self):
        cb = CircuitBreaker(threshold=3)
        assert cb.is_tripped("target.com") is False

    def test_trips_after_threshold(self):
        cb = CircuitBreaker(threshold=3)
        cb.record_failure("target.com")
        cb.record_failure("target.com")
        tripped = cb.record_failure("target.com")
        assert tripped is True
        assert cb.is_tripped("target.com") is True

    def test_success_resets(self):
        cb = CircuitBreaker(threshold=3)
        cb.record_failure("target.com")
        cb.record_failure("target.com")
        cb.record_success("target.com")
        tripped = cb.record_failure("target.com")
        assert tripped is False  # only 1 failure after reset

    def test_different_hosts_independent(self):
        cb = CircuitBreaker(threshold=2)
        cb.record_failure("host-a.com")
        cb.record_failure("host-a.com")
        assert cb.is_tripped("host-a.com") is True
        assert cb.is_tripped("host-b.com") is False

    def test_cooldown_resets(self):
        cb = CircuitBreaker(threshold=2, cooldown=0.1)
        cb.record_failure("target.com")
        cb.record_failure("target.com")
        assert cb.is_tripped("target.com") is True
        time.sleep(0.15)
        assert cb.is_tripped("target.com") is False  # cooldown expired

    def test_get_status(self):
        cb = CircuitBreaker(threshold=5)
        cb.record_failure("target.com")
        cb.record_failure("target.com")
        status = cb.get_status("target.com")
        assert status["failures"] == 2
        assert status["tripped"] is False
        assert status["threshold"] == 5
