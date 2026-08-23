"""Tests for hunt.py's session-directory resolvers — agent.py calls these
(_activate_recon_session, _resolve_recon_dir, _resolve_findings_dir) but
they didn't exist anywhere in the codebase until this fix. See
SECURITY-REVIEW-2026-08-22.md finding #0."""
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import importlib.util
spec = importlib.util.spec_from_file_location(
    "hunt", os.path.join(REPO_ROOT, "tools", "hunt.py")
)
hunt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hunt)


class TestResolveReconDir:
    def test_returns_path_under_recon_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        result = hunt._resolve_recon_dir("target.com")
        assert result == str(tmp_path / "recon" / "target.com")

    def test_rejects_path_traversal_in_domain(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        for bad in ("../../etc", "a/../../etc", "a/b", "a\\b"):
            try:
                hunt._resolve_recon_dir(bad)
                assert False, f"expected ValueError for {bad!r}"
            except ValueError:
                pass


class TestResolveFindingsDir:
    def test_returns_path_under_findings_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
        result = hunt._resolve_findings_dir("target.com", create=False)
        assert result == str(tmp_path / "findings" / "target.com")
        assert not os.path.isdir(result)

    def test_create_true_makes_directory(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
        result = hunt._resolve_findings_dir("target.com", create=True)
        assert os.path.isdir(result)

    def test_rejects_path_traversal(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "FINDINGS_DIR", str(tmp_path / "findings"))
        try:
            hunt._resolve_findings_dir("../../etc", create=False)
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestActivateReconSession:
    def test_create_true_makes_new_session_and_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        session_id, recon_dir = hunt._activate_recon_session(
            "target.com", requested_session_id="latest", create=True
        )
        assert session_id
        assert os.path.isdir(recon_dir)
        assert recon_dir.endswith(os.path.join("target.com", "sessions", session_id))

    def test_resume_latest_returns_most_recent_session(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        first_id, _ = hunt._activate_recon_session("target.com", create=True)
        second_id, _ = hunt._activate_recon_session("target.com", create=True)
        resumed_id, resumed_dir = hunt._activate_recon_session(
            "target.com", requested_session_id="latest", create=False
        )
        assert resumed_id == second_id
        assert resumed_dir.endswith(second_id)

    def test_resume_specific_id_returns_that_session(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        first_id, first_dir = hunt._activate_recon_session("target.com", create=True)
        hunt._activate_recon_session("target.com", create=True)
        resumed_id, resumed_dir = hunt._activate_recon_session(
            "target.com", requested_session_id=first_id, create=False
        )
        assert resumed_id == first_id
        assert resumed_dir == first_dir

    def test_resume_unknown_id_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        hunt._activate_recon_session("target.com", create=True)
        try:
            hunt._activate_recon_session(
                "target.com", requested_session_id="does-not-exist", create=False
            )
            assert False, "expected ValueError"
        except ValueError:
            pass

    def test_resume_latest_no_sessions_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        try:
            hunt._activate_recon_session(
                "target.com", requested_session_id="latest", create=False
            )
            assert False, "expected ValueError"
        except ValueError:
            pass

    def test_resume_specific_id_with_create_true(self, monkeypatch, tmp_path):
        """Test the exact combination used by --resume SESSION_ID flag:
        resume an existing session with create=True (idempotent)."""
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        first_id, first_dir = hunt._activate_recon_session("target.com", create=True)
        # Resume the same session with create=True (--resume SESSION_ID behavior)
        resumed_id, resumed_dir = hunt._activate_recon_session(
            "target.com", requested_session_id=first_id, create=True
        )
        assert resumed_id == first_id
        assert resumed_dir == first_dir

    def test_multiple_sessions_have_different_paths(self, monkeypatch, tmp_path):
        """Regression test: verifies that two different sessions for the same
        domain resolve to different paths (not the shared parent). This is
        critical for --resume to work — agent.py derives agent_session.json
        from recon_dir directly, so each session must have its own file."""
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        # Create two sessions
        first_id, first_recon_dir = hunt._activate_recon_session("target.com", create=True)
        second_id, second_recon_dir = hunt._activate_recon_session("target.com", create=True)

        # Verify they have different recon_dir paths
        assert first_recon_dir != second_recon_dir
        assert first_id != second_id

        # Verify that agent.py's usage pattern results in different session files
        # (mimicking agent.py lines 1483-1489)
        first_session_file = os.path.join(first_recon_dir, "agent_session.json")
        second_session_file = os.path.join(second_recon_dir, "agent_session.json")

        # Critical: they must NOT be the same file (would break --resume)
        assert first_session_file != second_session_file
