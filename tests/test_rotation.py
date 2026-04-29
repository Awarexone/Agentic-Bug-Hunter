"""Tests for memory/rotation.py — size-cap rotation, backup retention, concurrency."""

import json
import multiprocessing as mp
import os
from pathlib import Path

import pytest

from memory.audit_log import AuditLog
from memory.pattern_db import PatternDB
from memory.rotation import (
    DEFAULT_KEEP,
    list_backups,
    needs_rotation,
    purge_backups,
    rotate,
    rotate_if_needed,
    total_bytes,
)
from memory.schemas import CURRENT_SCHEMA_VERSION, make_audit_entry


def _write_bytes(path: Path, n: int) -> None:
    """Write ``n`` bytes (a single line of 'a's + newline) to path."""
    path.write_bytes(b"a" * (n - 1) + b"\n")


class TestNeedsRotation:

    def test_missing_file(self, tmp_path):
        assert needs_rotation(tmp_path / "missing.jsonl", 100) is False

    def test_under_cap(self, tmp_path):
        p = tmp_path / "f.jsonl"
        _write_bytes(p, 50)
        assert needs_rotation(p, 100) is False

    def test_at_cap(self, tmp_path):
        p = tmp_path / "f.jsonl"
        _write_bytes(p, 100)
        assert needs_rotation(p, 100) is True

    def test_over_cap(self, tmp_path):
        p = tmp_path / "f.jsonl"
        _write_bytes(p, 200)
        assert needs_rotation(p, 100) is True


class TestRotate:

    def test_no_op_when_missing(self, tmp_path):
        p = tmp_path / "missing.jsonl"
        assert rotate(p, keep=3) == 0

    def test_creates_first_backup(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text("v1\n")
        rotate(p, keep=3)
        assert not p.exists()
        assert (tmp_path / "f.jsonl.1").read_text() == "v1\n"

    def test_shifts_existing_backups(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text("v3\n")
        (tmp_path / "f.jsonl.1").write_text("v2\n")
        (tmp_path / "f.jsonl.2").write_text("v1\n")
        rotate(p, keep=3)
        assert (tmp_path / "f.jsonl.1").read_text() == "v3\n"
        assert (tmp_path / "f.jsonl.2").read_text() == "v2\n"
        assert (tmp_path / "f.jsonl.3").read_text() == "v1\n"

    def test_drops_oldest_beyond_keep(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text("v4\n")
        (tmp_path / "f.jsonl.1").write_text("v3\n")
        (tmp_path / "f.jsonl.2").write_text("v2\n")
        (tmp_path / "f.jsonl.3").write_text("v1\n")  # will be dropped
        rotate(p, keep=3)
        assert (tmp_path / "f.jsonl.1").read_text() == "v4\n"
        assert (tmp_path / "f.jsonl.2").read_text() == "v3\n"
        assert (tmp_path / "f.jsonl.3").read_text() == "v2\n"
        # v1 is gone
        assert len(list(tmp_path.glob("f.jsonl*"))) == 3

    def test_custom_keep(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text("live\n")
        rotate(p, keep=1)
        assert (tmp_path / "f.jsonl.1").exists()
        # Rotate again with keep=1 — .1 should be replaced (oldest dropped)
        p.write_text("live2\n")
        rotate(p, keep=1)
        assert (tmp_path / "f.jsonl.1").read_text() == "live2\n"
        assert not (tmp_path / "f.jsonl.2").exists()


class TestRotateIfNeeded:

    def test_no_rotation_when_under_cap(self, tmp_path):
        p = tmp_path / "f.jsonl"
        _write_bytes(p, 50)
        assert rotate_if_needed(p, max_bytes=100) is False
        assert p.exists()

    def test_rotates_when_over_cap(self, tmp_path):
        p = tmp_path / "f.jsonl"
        _write_bytes(p, 150)
        assert rotate_if_needed(p, max_bytes=100) is True
        assert not p.exists()
        assert (tmp_path / "f.jsonl.1").exists()

    def test_no_op_when_missing(self, tmp_path):
        assert rotate_if_needed(tmp_path / "missing.jsonl", max_bytes=100) is False


class TestBackupHelpers:

    def test_list_backups_empty(self, tmp_path):
        assert list_backups(tmp_path / "f.jsonl") == []

    def test_list_backups_ordered(self, tmp_path):
        p = tmp_path / "f.jsonl"
        (tmp_path / "f.jsonl.1").write_text("a")
        (tmp_path / "f.jsonl.3").write_text("c")  # gap on purpose
        bps = list_backups(p, keep=3)
        # Only existing ones, ordered .1 then .3
        assert [bp.name for bp in bps] == ["f.jsonl.1", "f.jsonl.3"]

    def test_total_bytes(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text("hello\n")
        (tmp_path / "f.jsonl.1").write_text("world\n")
        assert total_bytes(p, keep=3) == 12

    def test_purge_backups(self, tmp_path):
        p = tmp_path / "f.jsonl"
        p.write_text("live\n")
        (tmp_path / "f.jsonl.1").write_text("a")
        (tmp_path / "f.jsonl.2").write_text("b")
        removed = purge_backups(p, keep=3)
        assert removed == 2
        assert p.exists()  # live file untouched
        assert not (tmp_path / "f.jsonl.1").exists()
        assert not (tmp_path / "f.jsonl.2").exists()


class TestAuditLogAutoRotate:

    def test_auto_rotates_on_write(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        # Pre-fill the file past the cap; AuditLog.log() should rotate before writing.
        _write_bytes(path, 1500)
        log = AuditLog(path, max_bytes=1024, keep_backups=3)
        log.log_request(url="https://target.com", method="GET", scope_check="pass")
        assert (tmp_hunt_dir / "audit.jsonl.1").exists()
        assert path.stat().st_size > 0
        # The fresh live file holds only the new entry.
        with open(path) as f:
            lines = [ln for ln in f if ln.strip()]
        assert len(lines) == 1
        assert json.loads(lines[0])["url"] == "https://target.com"

    def test_no_rotation_under_cap(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path, max_bytes=10 * 1024, keep_backups=3)
        for i in range(5):
            log.log_request(url=f"https://t{i}.com", method="GET", scope_check="pass")
        assert not (tmp_hunt_dir / "audit.jsonl.1").exists()
        assert len(log.read_all()) == 5


class TestPatternDBAutoRotate:

    def test_auto_rotates_on_save(self, patterns_path, sample_pattern_entry):
        # Pre-fill past cap with a single big line.
        _write_bytes(patterns_path, 800)
        db = PatternDB(patterns_path, max_bytes=512, keep_backups=2)
        result = db.save(sample_pattern_entry)
        assert result is True
        assert patterns_path.with_suffix(".jsonl.1").exists()
        # Live file holds just the new entry.
        live = patterns_path.read_text().strip().splitlines()
        assert len(live) == 1


def _writer_proc(path_str: str, count: int, marker: str) -> None:
    """Worker that writes ``count`` audit entries to ``path``."""
    log = AuditLog(path_str, max_bytes=10 * 1024 * 1024, keep_backups=3)
    for i in range(count):
        log.log_request(
            url=f"https://t.com/{marker}/{i}",
            method="GET",
            scope_check="pass",
            session_id=marker,
        )


def _writer_proc_rotating(path_str: str, count: int, marker: str, cap: int, keep: int) -> None:
    """Worker for the rotation stress test (top-level so spawn can pickle it)."""
    log = AuditLog(path_str, max_bytes=cap, keep_backups=keep)
    for i in range(count):
        log.log_request(
            url=f"https://t.com/{marker}/{i}",
            method="GET",
            scope_check="pass",
            session_id=marker,
        )


class TestConcurrentWrites:
    """TODO-8: concurrent-write stress for HuntJournal/PatternDB-style append."""

    def test_concurrent_audit_writers_no_loss(self, tmp_hunt_dir):
        path = tmp_hunt_dir / "audit.jsonl"
        n_writers = 4
        per_writer = 50
        ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
        procs = [
            ctx.Process(target=_writer_proc, args=(str(path), per_writer, f"w{i}"))
            for i in range(n_writers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
            assert p.exitcode == 0, f"writer {p.pid} crashed: {p.exitcode}"

        # Every line must be valid JSON and we must see all writes.
        with open(path) as f:
            lines = [ln for ln in f if ln.strip()]
        assert len(lines) == n_writers * per_writer
        seen = {(json.loads(ln)["session_id"], json.loads(ln)["url"]) for ln in lines}
        assert len(seen) == n_writers * per_writer  # no duplicates, no truncation

    def test_concurrent_writes_with_rotation(self, tmp_hunt_dir):
        """Writers should not lose entries when rotation fires mid-run.

        Sized so a few rotations happen but ``keep`` is large enough that no
        backup is ever dropped — that way, summing live + backups must equal
        every entry written.
        """
        path = tmp_hunt_dir / "audit.jsonl"
        n_writers = 3
        per_writer = 60
        # Each audit entry is ~200 bytes. 180 entries ≈ 36 KB total.
        # cap=12 KB → ~3 rotations; keep=20 → never drops.
        cap = 12 * 1024
        keep = 20

        ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
        procs = [
            ctx.Process(target=_writer_proc_rotating, args=(str(path), per_writer, f"r{i}", cap, keep))
            for i in range(n_writers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
            assert p.exitcode == 0

        files = [path] + list_backups(path, keep=keep)
        total = 0
        seen = set()
        for f in files:
            with open(f) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    total += 1
                    rec = json.loads(ln)
                    seen.add((rec["session_id"], rec["url"]))
        # Sanity check: rotation actually fired
        assert len(list_backups(path, keep=keep)) >= 1
        assert total == n_writers * per_writer
        assert len(seen) == n_writers * per_writer


class TestDiskFullPropagation:
    """TODO-8: disk-full OSError surfaces to the caller (not silently swallowed)."""

    def test_audit_log_propagates_oserror(self, tmp_hunt_dir, monkeypatch):
        path = tmp_hunt_dir / "audit.jsonl"
        log = AuditLog(path)

        real_write = os.write

        def fake_write(fd, data):
            # Simulate ENOSPC by writing 0 bytes — AuditLog raises on partial write.
            return 0

        monkeypatch.setattr(os, "write", fake_write)
        with pytest.raises(OSError, match="Partial write"):
            log.log_request(url="https://t.com", method="GET", scope_check="pass")
        # Restore for the rest of the test session.
        monkeypatch.setattr(os, "write", real_write)
