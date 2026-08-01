"""
Doc-drift regression tests.

CLAUDE.md, AGENTS.md, and OPENCODE.md each used to hand-carry their own copy
of the skills/commands/agents/tools/memory inventory, and drifted
independently (AGENTS.md was stuck at "8 agents / 9 skills / 21 commands"
while the repo had grown to 13/13/27, and omitted vuln_intelligence.py,
experiment_memory.py, finding_state.py, and lead_board.py entirely).

docs/manifest.json is now the single source of truth, and scripts/gen_docs.py
is the only thing allowed to write the generated regions of AGENTS.md /
OPENCODE.md. This test file enforces both halves of that contract:

  1. The generated regions in AGENTS.md/OPENCODE.md match what
     scripts/gen_docs.py would produce from the current manifest right now
     (catches "someone hand-edited the table and didn't touch the manifest",
     and catches "someone updated the manifest and forgot to rerun the
     generator").
  2. Every skill dir / command file / agent file / public tool file / memory
     module that exists on disk has a manifest entry, and every manifest
     entry still exists on disk (catches "added a new tool and never told
     the manifest about it" — the exact failure mode that caused the drift
     in the first place).
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

MANIFEST_PATH = os.path.join(REPO_ROOT, "docs", "manifest.json")
GEN_DOCS_PATH = os.path.join(REPO_ROOT, "scripts", "gen_docs.py")

import gen_docs  # noqa: E402


@pytest.fixture(scope="module")
def manifest():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ─── manifest.json structural sanity ───────────────────────────────────────

class TestManifestShape:
    @pytest.mark.parametrize("category", ["skills", "commands", "agents", "tools", "memory"])
    def test_category_present_and_nonempty(self, manifest, category):
        assert category in manifest
        assert isinstance(manifest[category], list)
        assert len(manifest[category]) > 0

    @pytest.mark.parametrize("category", ["skills", "commands", "agents", "tools", "memory"])
    def test_every_entry_has_required_fields(self, manifest, category):
        for entry in manifest[category]:
            assert "name" in entry and entry["name"]
            assert "path" in entry and entry["path"]
            assert "description" in entry and entry["description"]

    @pytest.mark.parametrize("category", ["skills", "commands", "agents", "tools", "memory"])
    def test_no_duplicate_names(self, manifest, category):
        names = [e["name"] for e in manifest[category]]
        assert len(names) == len(set(names)), f"duplicate name(s) in {category}"

    def test_every_manifest_path_exists_on_disk(self, manifest):
        missing = []
        for category in ("skills", "commands", "agents", "tools", "memory"):
            for entry in manifest[category]:
                p = os.path.join(REPO_ROOT, entry["path"])
                if category == "skills":
                    p = os.path.join(p, "SKILL.md")
                if not os.path.exists(p):
                    missing.append((category, entry["name"], entry["path"]))
        assert missing == [], f"manifest entries with no file on disk: {missing}"


# ─── disk -> manifest completeness (the actual anti-drift check) ──────────

def _skill_dirs():
    d = os.path.join(REPO_ROOT, "skills")
    return {name for name in os.listdir(d) if os.path.isdir(os.path.join(d, name))}


def _md_stems(dirname, exclude=("README.md",)):
    d = os.path.join(REPO_ROOT, dirname)
    return {
        f[:-3] for f in os.listdir(d)
        if f.endswith(".md") and f not in exclude
    }


def _public_tool_files():
    """tools/ minus the manifest's declared exclusion patterns.

    Excluded: __init__.py, README.md, and anything starting with "_"
    (private helper modules imported by other tools, not independent
    entrypoints — e.g. _auth_helper.sh, _spray_http_form.py).
    """
    d = os.path.join(REPO_ROOT, "tools")
    return {
        f for f in os.listdir(d)
        if f not in ("__init__.py", "README.md") and not f.startswith("_")
    }


def _memory_modules():
    d = os.path.join(REPO_ROOT, "memory")
    return {f for f in os.listdir(d) if f.endswith(".py") and f != "__init__.py"}


class TestDiskManifestCompleteness:
    def test_skills_complete(self, manifest):
        on_disk = _skill_dirs()
        in_manifest = {e["name"] for e in manifest["skills"]}
        assert on_disk - in_manifest == set(), "skill dirs missing from manifest.json"
        assert in_manifest - on_disk == set(), "manifest.json lists skills that don't exist"

    def test_commands_complete(self, manifest):
        on_disk = _md_stems("commands")
        in_manifest = {e["name"] for e in manifest["commands"]}
        assert on_disk - in_manifest == set(), "command files missing from manifest.json"
        assert in_manifest - on_disk == set(), "manifest.json lists commands that don't exist"

    def test_agents_complete(self, manifest):
        on_disk = _md_stems("agents")
        in_manifest = {e["name"] for e in manifest["agents"]}
        assert on_disk - in_manifest == set(), "agent files missing from manifest.json"
        assert in_manifest - on_disk == set(), "manifest.json lists agents that don't exist"

    def test_tools_complete(self, manifest):
        on_disk = _public_tool_files()
        in_manifest = {e["name"] for e in manifest["tools"]}
        assert on_disk - in_manifest == set(), "tool files missing from manifest.json"
        assert in_manifest - on_disk == set(), "manifest.json lists tools that don't exist"

    def test_memory_complete(self, manifest):
        on_disk = _memory_modules()
        in_manifest = {e["name"] for e in manifest["memory"]}
        assert on_disk - in_manifest == set(), "memory modules missing from manifest.json"
        assert in_manifest - on_disk == set(), "manifest.json lists memory modules that don't exist"


# ─── AGENTS.md / OPENCODE.md generated regions match the manifest ─────────

class TestGeneratedRegionsInSync:
    def test_gen_docs_check_mode_reports_clean(self):
        """The exact CI invocation: fails (exit 1) if either file would change."""
        proc = subprocess.run(
            [sys.executable, GEN_DOCS_PATH, "--check"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, (
            f"AGENTS.md/OPENCODE.md are out of sync with docs/manifest.json — "
            f"run `python3 scripts/gen_docs.py`.\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

    @pytest.mark.parametrize("filename,render_fn_name", [
        ("AGENTS.md", "render_agents_md"),
        ("OPENCODE.md", "render_opencode_md"),
    ])
    def test_generated_regions_match_manifest(self, manifest, filename, render_fn_name):
        path = os.path.join(REPO_ROOT, filename)
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()

        render_fn = getattr(gen_docs, render_fn_name)
        regions = render_fn(manifest)
        assert regions, f"{render_fn_name} produced no regions"

        for key, expected_body in regions.items():
            start = gen_docs._START_RE.format(key=key)
            end = gen_docs._END_RE.format(key=key)
            assert start in content, f"{filename} missing start marker for '{key}'"
            assert end in content, f"{filename} missing end marker for '{key}'"
            actual_body = content.split(start, 1)[1].split(end, 1)[0].strip("\n")
            assert actual_body == expected_body, (
                f"{filename}'s '{key}' region doesn't match docs/manifest.json — "
                f"run `python3 scripts/gen_docs.py`"
            )

    def test_apply_regions_raises_on_missing_marker(self):
        with pytest.raises(ValueError, match="marker pair"):
            gen_docs.apply_regions("no markers here", {"skills": "x"})

    def test_generate_is_idempotent(self, tmp_path, monkeypatch):
        """Running the generator twice produces byte-identical output."""
        # Copy the two target files into a scratch dir and point REPO_ROOT-relative
        # paths at it via monkeypatching gen_docs' module-level constants.
        import shutil
        scratch = tmp_path / "docroot"
        scratch.mkdir()
        (scratch / "docs").mkdir()
        shutil.copy(MANIFEST_PATH, scratch / "docs" / "manifest.json")
        for fn in ("AGENTS.md", "OPENCODE.md"):
            shutil.copy(os.path.join(REPO_ROOT, fn), scratch / fn)

        monkeypatch.setattr(gen_docs, "REPO_ROOT", str(scratch))
        monkeypatch.setattr(gen_docs, "MANIFEST_PATH", str(scratch / "docs" / "manifest.json"))

        gen_docs.generate(check=False)
        first_pass = {fn: (scratch / fn).read_text() for fn in ("AGENTS.md", "OPENCODE.md")}
        gen_docs.generate(check=False)
        second_pass = {fn: (scratch / fn).read_text() for fn in ("AGENTS.md", "OPENCODE.md")}
        assert first_pass == second_pass


# ─── the specific historical drift this task fixes ─────────────────────────

class TestSpecificDriftRegression:
    """Locks in the exact gap called out when this task was assigned: AGENTS.md
    was stuck at 8 agents / 9 skills / 21 commands, and omitted
    vuln_intelligence.py, experiment_memory.py, finding_state.py, and
    lead_board.py entirely."""

    def test_agent_count_is_current(self, manifest):
        assert len(manifest["agents"]) == 13

    def test_skill_count_is_current(self, manifest):
        assert len(manifest["skills"]) == 13

    def test_command_count_is_current(self, manifest):
        assert len(manifest["commands"]) == 27

    @pytest.mark.parametrize("module_name", [
        "vuln_intelligence.py", "experiment_memory.py", "finding_state.py",
    ])
    def test_previously_omitted_memory_modules_now_documented(self, manifest, module_name):
        names = {e["name"] for e in manifest["memory"]}
        assert module_name in names

    def test_previously_omitted_lead_board_now_documented(self, manifest):
        names = {e["name"] for e in manifest["tools"]}
        assert "lead_board.py" in names
