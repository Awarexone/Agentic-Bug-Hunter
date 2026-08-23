"""engine.py's save_config() must write ~/.bughunter/config.json with
0600 permissions, since it stores provider API keys in plaintext. See
SECURITY-REVIEW-2026-08-22.md finding #12."""
import os
import stat
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import engine


class TestConfigFilePermissions:
    def test_saved_config_is_owner_only_readable(self, tmp_path, monkeypatch):
        fake_config = tmp_path / "config.json"
        monkeypatch.setattr(engine, "CONFIG", fake_config)
        engine.save_config({"ANTHROPIC_API_KEY": "sk-test"})
        mode = stat.S_IMODE(os.stat(fake_config).st_mode)
        assert mode == 0o600
