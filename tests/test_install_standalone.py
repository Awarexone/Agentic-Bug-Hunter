"""Regression tests for the standalone install/uninstall path under bash 3.2.

bash 3.2 — still the default /bin/bash on macOS — aborts under `set -u` when an
empty array is expanded as "${arr[@]}". install.sh and uninstall.sh both build a
command-prefix array that stays empty whenever the target bin directory is
writable (the common case), so `--agent standalone` failed before it installed
anything:

    ./install.sh: line 283: install_cmd[@]: unbound variable

These tests drive the real scripts end to end in a temp bin directory, so the
regression cannot come back unnoticed on a bash 4+ developer machine.
"""

import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")


def _run(script, args, bin_dir):
    env = {
        **os.environ,
        "BBHUNTER_BIN_DIR": str(bin_dir),
        "BBHUNTER_SKIP_DEPS": "1",
    }
    return subprocess.run(
        [BASH, os.path.join(REPO, script), *args],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120,
    )


def test_standalone_install_succeeds(tmp_path):
    bin_dir = tmp_path / "bin"
    proc = _run("install.sh", ["--agent", "standalone"], bin_dir)

    assert "unbound variable" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert (bin_dir / "bughunter").is_symlink()


def test_standalone_install_links_to_engine(tmp_path):
    bin_dir = tmp_path / "bin"
    _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert os.path.realpath(bin_dir / "bughunter") == \
        os.path.realpath(os.path.join(REPO, "engine.py"))


def test_standalone_install_is_idempotent(tmp_path):
    bin_dir = tmp_path / "bin"
    _run("install.sh", ["--agent", "standalone"], bin_dir)
    proc = _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert proc.returncode == 0, proc.stderr
    assert (bin_dir / "bughunter").is_symlink()


def test_standalone_uninstall_removes_the_command(tmp_path):
    bin_dir = tmp_path / "bin"
    _run("install.sh", ["--agent", "standalone"], bin_dir)
    assert (bin_dir / "bughunter").is_symlink()

    proc = _run("uninstall.sh", ["--agent", "standalone", "--yes"], bin_dir)
    assert "unbound variable" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert not (bin_dir / "bughunter").exists()


@pytest.mark.parametrize("script", ["install.sh", "uninstall.sh", "install_tools.sh"])
def test_scripts_parse_under_bash(script):
    proc = subprocess.run([BASH, "-n", os.path.join(REPO, script)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_empty_array_expansion_idiom_survives_nounset():
    """The idiom itself, pinned — this is what bash 3.2 rejects without the fix."""
    broken = subprocess.run(
        [BASH, "-c", 'set -euo pipefail; a=(); "${a[@]}" true'],
        capture_output=True, text=True,
    )
    fixed = subprocess.run(
        [BASH, "-c", 'set -euo pipefail; a=(); ${a[@]+"${a[@]}"} true'],
        capture_output=True, text=True,
    )
    # On bash 4+ both succeed; on bash 3.2 only the guarded form does.
    assert fixed.returncode == 0, fixed.stderr
    if broken.returncode != 0:
        assert "unbound variable" in broken.stderr


def test_guarded_expansion_still_passes_a_non_empty_prefix():
    proc = subprocess.run(
        [BASH, "-c", 'set -euo pipefail; a=(echo); ${a[@]+"${a[@]}"} marker'],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "marker"
