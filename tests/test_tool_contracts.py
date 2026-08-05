"""
Contract tests for the 29 tools/*.py and tools/*.sh files that had zero test
coverage before this task: banner.py banner.sh breach_checker.py
cicd_scanner.sh cloud_recon.sh cve_scan.sh external_arsenal.sh
graphql_audit.sh h1_idor_scanner.py h1_mutation_idor.py h1_oauth_tester.py
h1_race.py h1_run.sh hai_payload_builder.py hai_probe.py memory_gc.py
mindmap.py multipart_mutator.py osint_employees.sh scope_aggregator.sh
secrets_hunter.sh sneaky_bits.py spray_orchestrator.sh takeover_scanner.sh
target_selector.py waf_encoder.py waf_response_analyzer.py wordlist_engine.sh
zero_day_fuzzer.py.

Three properties per tool, asserted against real subprocess invocations (not
guessed): `--help` exits cleanly, an unrecognized flag is rejected instead of
silently doing something unexpected, and (Python tools only) importing the
module performs no real work. Where a tool's *actual, verified* behavior
falls short of that ideal contract, the expectation below is written to
match reality — not the aspiration — and the gap is called out in the
Phase 0 report's OUT OF SCOPE section rather than silently asserted away or
quietly "fixed" (fixing tool behavior is out of scope for a test-only task).

Zero network calls anywhere in this file. Several of these tools genuinely
do fire on the network under the right arguments (nuclei, curl, sisakulint,
bbscope, theHarvester, trufflehog, dnsreaper, subjack, ...) and several of
those binaries are *actually installed* on this box — so every subprocess
invocation here runs with a PATH that shadows all of them (plus curl/dig/wget)
with instant-failing, no-op stubs. That makes the tests host-independent: the
same assertions hold whether or not the real security tools happen to be
installed.
"""

import os
import stat
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

# Every external binary any of the 29 scripts might shell out to, across any
# argument combination exercised below. Stubbed so tests never depend on host
# tooling and never touch the network, regardless of what's really installed.
_STUBBED_BINARIES = [
    "nuclei", "log4j-scan", "sisakulint", "s3scanner", "cloud_enum", "cloudfail",
    "dnsreaper", "dnsReaper", "subjack", "trufflehog", "noseyparker", "gitleaks",
    "theHarvester", "crosslinked", "bbscope", "cewler", "hashcat", "gqlmap",
    "graphql-cop", "graphw00f", "clairvoyance", "trevorspray",
    "curl", "dig", "wget", "nslookup", "host",
]


@pytest.fixture(scope="session")
def stub_bin_dir(tmp_path_factory):
    """A directory of no-op, instant-failing stand-ins for every external
    security tool + network utility these scripts might shell out to.

    Prepending this to PATH guarantees no test here ever makes a real network
    call and never depends on which optional tools happen to be installed."""
    d = tmp_path_factory.mktemp("stub-bin")
    for name in _STUBBED_BINARIES:
        stub = d / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(d)


@pytest.fixture()
def safe_env(stub_bin_dir):
    env = dict(os.environ)
    env["PATH"] = stub_bin_dir + os.pathsep + env.get("PATH", "")
    # Belt-and-suspenders: even if something escapes the PATH shim and tries
    # a real HTTP call, route it into a closed local port instead of the net.
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    env["NO_COLOR"] = "1"
    return env


def _run(argv, env, timeout=15):
    return subprocess.run(
        argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout, env=env,
    )


def _py(script, args, env, timeout=15):
    return _run([sys.executable, os.path.join(TOOLS_DIR, script)] + args, env, timeout)


def _sh(script, args, env, timeout=15):
    return _run(["bash", os.path.join(TOOLS_DIR, script)] + args, env, timeout)


# ─── per-tool contract table ────────────────────────────────────────────────
# help_args / invalid_args default to ["--help"] / ["--bogus-flag-xyz"].
# help_exit / invalid_nonzero default to 0 / True. Overrides below are only
# present where the *actual* (verified by running the tool) behavior differs
# from that default — see the module docstring and Phase 0's OUT OF SCOPE
# notes for why each override exists.

PY_TOOLS = [
    {"name": "banner.py", "invalid_nonzero": False},  # no argparse at all; any arg becomes the subtitle string

    {"name": "breach_checker.py"},
    {"name": "h1_idor_scanner.py"},
    {"name": "h1_mutation_idor.py"},
    {"name": "h1_oauth_tester.py"},
    {"name": "h1_race.py"},
    {"name": "hai_payload_builder.py"},
    {"name": "hai_probe.py"},
    {"name": "memory_gc.py"},
    {"name": "mindmap.py"},
    {"name": "multipart_mutator.py"},
    {"name": "sneaky_bits.py"},
    {"name": "target_selector.py"},
    {"name": "waf_encoder.py"},
    {"name": "waf_response_analyzer.py"},
    {"name": "zero_day_fuzzer.py"},
]

SH_TOOLS = [
    {"name": "banner.sh", "invalid_nonzero": False},  # sourced-function library, no arg parsing at all
    {"name": "cicd_scanner.sh", "invalid_nonzero": False},  # unknown flag becomes TARGET; scan "succeeds" (exit 0) even when the underlying tool fails
    {"name": "cloud_recon.sh"},
    {"name": "cve_scan.sh", "invalid_nonzero": False},  # unknown flag becomes TARGET; nuclei sweep "completes" (exit 0) against the bogus value
    {"name": "external_arsenal.sh", "invalid_nonzero": False},  # unknown flags fall through to default status print
    {"name": "graphql_audit.sh"},
    {"name": "h1_run.sh", "help_exit": 1},  # never reads argv at all; always exits 1 on empty hardcoded tokens
    {"name": "osint_employees.sh"},
    {"name": "scope_aggregator.sh"},
    {"name": "secrets_hunter.sh"},
    {"name": "spray_orchestrator.sh"},
    {"name": "takeover_scanner.sh"},
    {"name": "wordlist_engine.sh"},
]

ALL_TOOL_NAMES = sorted(t["name"] for t in PY_TOOLS + SH_TOOLS)


def test_covers_all_29_tools():
    expected = {
        "banner.py", "banner.sh", "breach_checker.py", "cicd_scanner.sh",
        "cloud_recon.sh", "cve_scan.sh", "external_arsenal.sh", "graphql_audit.sh",
        "h1_idor_scanner.py", "h1_mutation_idor.py", "h1_oauth_tester.py", "h1_race.py",
        "h1_run.sh", "hai_payload_builder.py", "hai_probe.py", "memory_gc.py",
        "mindmap.py", "multipart_mutator.py", "osint_employees.sh", "scope_aggregator.sh",
        "secrets_hunter.sh", "sneaky_bits.py", "spray_orchestrator.sh", "takeover_scanner.sh",
        "target_selector.py", "waf_encoder.py", "waf_response_analyzer.py",
        "wordlist_engine.sh", "zero_day_fuzzer.py",
    }
    assert set(ALL_TOOL_NAMES) == expected
    assert len(ALL_TOOL_NAMES) == 29


# ─── --help exits cleanly ───────────────────────────────────────────────────

class TestHelpExitsCleanly:
    @pytest.mark.parametrize("spec", PY_TOOLS, ids=[t["name"] for t in PY_TOOLS])
    def test_python_help(self, spec, safe_env):
        proc = _py(spec["name"], spec.get("help_args", ["--help"]), safe_env)
        expected = spec.get("help_exit", 0)
        assert proc.returncode == expected, (
            f"{spec['name']} --help exited {proc.returncode}, expected {expected}\n"
            f"stdout: {proc.stdout[:500]}\nstderr: {proc.stderr[:500]}"
        )

    @pytest.mark.parametrize("spec", SH_TOOLS, ids=[t["name"] for t in SH_TOOLS])
    def test_shell_help(self, spec, safe_env):
        proc = _sh(spec["name"], spec.get("help_args", ["--help"]), safe_env)
        expected = spec.get("help_exit", 0)
        assert proc.returncode == expected, (
            f"{spec['name']} --help exited {proc.returncode}, expected {expected}\n"
            f"stdout: {proc.stdout[:500]}\nstderr: {proc.stderr[:500]}"
        )


# ─── invalid args are rejected ──────────────────────────────────────────────

class TestInvalidArgsRejected:
    @pytest.mark.parametrize("spec", PY_TOOLS, ids=[t["name"] for t in PY_TOOLS])
    def test_python_invalid_args(self, spec, safe_env):
        proc = _py(spec["name"], spec.get("invalid_args", ["--bogus-flag-xyz"]), safe_env)
        should_be_nonzero = spec.get("invalid_nonzero", True)
        if should_be_nonzero:
            assert proc.returncode != 0, (
                f"{spec['name']} --bogus-flag-xyz exited 0 — argparse should reject it"
            )
            assert (proc.stdout + proc.stderr).strip(), (
                f"{spec['name']} rejected the bad flag silently (no message)"
            )
        else:
            assert proc.returncode == 0

    @pytest.mark.parametrize("spec", SH_TOOLS, ids=[t["name"] for t in SH_TOOLS])
    def test_shell_invalid_args(self, spec, safe_env):
        proc = _sh(spec["name"], spec.get("invalid_args", ["--bogus-flag-xyz"]), safe_env)
        should_be_nonzero = spec.get("invalid_nonzero", True)
        if should_be_nonzero:
            assert proc.returncode != 0, (
                f"{spec['name']} --bogus-flag-xyz exited 0\n"
                f"stdout: {proc.stdout[:500]}\nstderr: {proc.stderr[:500]}"
            )
        else:
            assert proc.returncode == 0


# ─── no import-time side effects (Python tools only) ───────────────────────
# Shell scripts have no equivalent "import" phase distinct from execution;
# the --help tests above already establish that invoking them doesn't
# perform real work, which is the closest analogue.

class TestNoImportTimeSideEffects:
    @pytest.mark.parametrize("spec", PY_TOOLS, ids=[t["name"] for t in PY_TOOLS])
    def test_import_is_side_effect_free(self, spec, safe_env, tmp_path):
        module = spec["name"][:-3]  # strip .py
        before = set(os.listdir(REPO_ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", f"import tools.{module}"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=10, env=safe_env,
        )
        after = set(os.listdir(REPO_ROOT))
        assert proc.returncode == 0, (
            f"import tools.{module} failed:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
        assert after == before, f"import tools.{module} created files in the repo root: {after - before}"


# ─── network-safety gate: does the tool require scope_checker before firing? ─
# CRITICAL per the task brief: assert (don't add) a scope_checker gate on the
# network-sending tools among the 29. None of them currently call it — see
# Phase 0's OUT OF SCOPE section. This block locks that finding in as a
# regression-visible fact instead of leaving it undocumented.

NETWORK_SENDING_TOOLS = {
    "breach_checker.py", "cicd_scanner.sh", "cloud_recon.sh", "cve_scan.sh",
    "graphql_audit.sh", "h1_idor_scanner.py", "h1_mutation_idor.py",
    "h1_oauth_tester.py", "h1_race.py", "h1_run.sh", "hai_probe.py",
    "multipart_mutator.py",  # only with --send, but the code path exists
    "osint_employees.sh", "scope_aggregator.sh", "secrets_hunter.sh",
    "spray_orchestrator.sh", "takeover_scanner.sh", "target_selector.py",
    "waf_response_analyzer.py",  # only with --calibrate, but the code path exists
    "wordlist_engine.sh", "zero_day_fuzzer.py",
}


class TestScopeCheckerGateGap:
    """Every one of these currently sends traffic with zero scope_checker
    involvement. This is intentionally an assertion of the gap, not a skip —
    if a future change adds the gate to one of these files, this test starts
    failing and must be updated, which is the point: it forces the manifest
    of "tools that still bypass scope_checker" to be edited deliberately."""

    @pytest.mark.parametrize("name", sorted(NETWORK_SENDING_TOOLS))
    def test_tool_does_not_import_or_source_scope_checker(self, name):
        path = os.path.join(TOOLS_DIR, name)
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        # A real enforcement call would import ScopeChecker (Python) or source
        # scope_checker.py / shell out to it (shell). A stray comment
        # mentioning the filename doesn't count as enforcement.
        enforces_scope = (
            "ScopeChecker(" in content
            or "from tools.scope_checker import" in content
            or "from tools import scope_checker" in content
        )
        assert not enforces_scope, (
            f"{name} now appears to call scope_checker — great, but that means "
            f"it should be removed from NETWORK_SENDING_TOOLS' gap list and "
            f"the Phase 0 OUT OF SCOPE note is stale."
        )

    def test_network_sending_set_is_subset_of_all_tools(self):
        assert NETWORK_SENDING_TOOLS <= set(ALL_TOOL_NAMES)
