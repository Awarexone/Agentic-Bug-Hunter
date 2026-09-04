"""Regression tests for Claude Code plugin manifest."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / ".claude-plugin" / "plugin.json"


def test_plugin_manifest_exists():
    assert MANIFEST.is_file(), "missing .claude-plugin/plugin.json"


def test_plugin_manifest_has_required_fields():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(data.get("name"), str) and data["name"]
    assert isinstance(data.get("description"), str) and data["description"]


def test_plugin_manifest_component_paths_exist():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for key in ("commands", "agents", "skills"):
        rel = data.get(key)
        assert rel, f"{key} path must be declared"
        path = REPO_ROOT / rel.removeprefix("./")
        assert path.exists(), f"{key} path does not exist: {path}"

    hooks = data.get("hooks")
    assert hooks, "hooks path must be declared"
    hooks_path = REPO_ROOT / hooks.removeprefix("./")
    assert hooks_path.is_file(), f"hooks path does not exist: {hooks_path}"
