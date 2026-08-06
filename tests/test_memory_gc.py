"""Tests for tools/memory_gc.py — GC report, rotation, purge logic."""

import pytest
from pathlib import Path
from unittest.mock import patch

from tools.memory_gc import (
    _human_size,
    _find_targets,
    report,
    do_rotate,
    do_purge,
    main,
    ROTATABLE,
)


class TestHumanSize:
    def test_bytes(self):
        assert _human_size(0) == "0 B"
        assert _human_size(512) == "512 B"
        assert _human_size(1023) == "1023 B"

    def test_kilobytes(self):
        assert _human_size(1024) == "1.0 KB"
        assert _human_size(2048) == "2.0 KB"
        assert _human_size(1536) == "1.5 KB"

    def test_megabytes(self):
        assert _human_size(1024 * 1024) == "1.0 MB"
        assert _human_size(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self):
        assert _human_size(1024 * 1024 * 1024) == "1.0 GB"
        assert _human_size(2 * 1024 * 1024 * 1024) == "2.0 GB"


class TestFindTargets:
    def test_empty_directory(self, tmp_path):
        targets = _find_targets(tmp_path)
        assert targets == []

    def test_nonexistent_directory(self, tmp_path):
        targets = _find_targets(tmp_path / "does_not_exist")
        assert targets == []

    def test_finds_rotatable_files(self, tmp_path):
        (tmp_path / "audit.jsonl").write_text("{}")
        (tmp_path / "patterns.jsonl").write_text("{}")
        (tmp_path / "journal.jsonl").write_text("{}")
        (tmp_path / "other.jsonl").write_text("{}")  # not rotatable

        targets = _find_targets(tmp_path)
        names = [t.name for t in targets]
        assert "audit.jsonl" in names
        assert "patterns.jsonl" in names
        assert "journal.jsonl" in names
        assert "other.jsonl" not in names

    def test_finds_nested_files(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "audit.jsonl").write_text("{}")
        targets = _find_targets(tmp_path)
        assert any(t.name == "audit.jsonl" for t in targets)

    def test_orphaned_backups_surface_live_path(self, tmp_path):
        # No live file, but a backup exists
        (tmp_path / "audit.jsonl.1").write_text("{}")
        targets = _find_targets(tmp_path)
        assert any(t.name == "audit.jsonl" for t in targets)

    def test_sorted_output(self, tmp_path):
        (tmp_path / "patterns.jsonl").write_text("{}")
        (tmp_path / "audit.jsonl").write_text("{}")
        targets = _find_targets(tmp_path)
        assert targets == sorted(targets)


class TestReport:
    def test_no_files(self, tmp_path, capsys):
        over = report(tmp_path, max_bytes=10_000_000, keep=3)
        assert over == 0
        captured = capsys.readouterr()
        assert "No rotatable files" in captured.out

    def test_files_under_cap(self, tmp_path, capsys):
        (tmp_path / "audit.jsonl").write_text("x" * 100)
        over = report(tmp_path, max_bytes=10_000_000, keep=3)
        assert over == 0
        captured = capsys.readouterr()
        assert "ok" in captured.out

    def test_files_over_cap(self, tmp_path, capsys):
        (tmp_path / "audit.jsonl").write_text("x" * 200)
        over = report(tmp_path, max_bytes=100, keep=3)
        assert over == 1
        captured = capsys.readouterr()
        assert "OVER CAP" in captured.out


class TestDoRotate:
    def test_rotates_oversize_file(self, tmp_path):
        f = tmp_path / "audit.jsonl"
        f.write_text("x" * 200)
        rotated = do_rotate(tmp_path, max_bytes=100, keep=3)
        assert rotated == 1
        # After rotation, the live file should be gone or smaller
        # (rotation moves it to .1)
        assert (tmp_path / "audit.jsonl.1").exists()

    def test_does_not_rotate_small_file(self, tmp_path):
        f = tmp_path / "audit.jsonl"
        f.write_text("x" * 10)
        rotated = do_rotate(tmp_path, max_bytes=10_000, keep=3)
        assert rotated == 0


class TestDoPurge:
    def test_purges_backups(self, tmp_path):
        (tmp_path / "audit.jsonl").write_text("{}")
        (tmp_path / "audit.jsonl.1").write_text("{}")
        (tmp_path / "audit.jsonl.2").write_text("{}")
        removed = do_purge(tmp_path, keep=3)
        assert removed == 2

    def test_nothing_to_purge(self, tmp_path):
        (tmp_path / "audit.jsonl").write_text("{}")
        removed = do_purge(tmp_path, keep=3)
        assert removed == 0


class TestMain:
    def test_report_only(self, tmp_path):
        (tmp_path / "audit.jsonl").write_text("x" * 10)
        ret = main(["--dir", str(tmp_path)])
        assert ret == 0

    def test_rotate_flag(self, tmp_path):
        (tmp_path / "audit.jsonl").write_text("x" * 200)
        ret = main(["--dir", str(tmp_path), "--max-mb", "0.0001", "--rotate"])
        assert ret == 0
        assert (tmp_path / "audit.jsonl.1").exists()

    def test_purge_flag(self, tmp_path):
        (tmp_path / "audit.jsonl").write_text("{}")
        (tmp_path / "audit.jsonl.1").write_text("{}")
        ret = main(["--dir", str(tmp_path), "--purge-backups"])
        assert ret == 0

    def test_nonexistent_dir(self, tmp_path):
        ret = main(["--dir", str(tmp_path / "nope")])
        assert ret == 0
