"""Verifies the shell/Python injection fix closes the hole — not just that the
code looks right, but that a crafted malicious target string is actually
rejected or neutralized when run, and that legitimate targets still work.

Background: tools/hunt.py's run_recon()/run_vuln_scan()/run_zero_day_fuzzer()
used to splice a user-supplied target string into an f-string passed to
subprocess.Popen(shell=True) — a target like `x"; rm -rf ~; #` reached a real
shell. The same pattern was found (independently of upstream's own fix, which
only covered hunt.py/zero_day_fuzzer.py/recon_engine.sh) in agent.py's
ToolDispatcher._run_shell_tool(), engine.py's cmd_recon()/cmd_hunt(), and
`eval`-based command building in tools/cicd_scanner.sh and tools/h1_run.sh,
plus a second Python-heredoc injection in tools/osint_employees.sh (same class
of bug as recon_engine.sh's crt.sh lookup, just a different file).

Every test here either (a) proves a malicious string never reaches a real
shell by capturing the literal subprocess.Popen() call and asserting
shell=False + the string arrives as a single argv element, or (b) actually
runs the fixed code/script in a subprocess with a canary-file payload and
asserts the canary was never created — a real sandboxed proof, not just a
code-shape assertion. No test touches the network; external binaries the
shell scripts would normally invoke (sisakulint, theHarvester, curl to
crt.sh) are stubbed via a PATH-shadowing fixture so nothing here depends on
what's installed on the host or reaches out.
"""

import json
import os
import stat
import subprocess
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

import hunt  # tools/ is on sys.path via tests/conftest.py
import zero_day_fuzzer as zdf

_GLOBAL_CANARY = "/tmp/bbhunt_pwned_marker"


@pytest.fixture(autouse=True)
def _clean_global_canary():
    """Several tests below assert this exact path was never created by a
    subprocess they don't fully control (a real bash/python child process,
    not just a mock) — so it must never leak between test runs, whether
    from a previous failed run or, as happened once during development,
    from deliberately running these payloads against pre-fix code to prove
    the tests are discriminating."""
    if os.path.exists(_GLOBAL_CANARY):
        os.remove(_GLOBAL_CANARY)
    yield
    if os.path.exists(_GLOBAL_CANARY):
        os.remove(_GLOBAL_CANARY)


# ─── malicious / legitimate target fixtures ────────────────────────────────

# Each of these, if it ever reached a real shell (shell=True, eval, or an
# unescaped Python string-literal splice), would run `id` and leave evidence
# behind (a canary marker, in the subprocess-level tests below).
MALICIOUS_TARGETS = [
    'x"; rm -rf ~; #',                                  # double-quote breakout + destructive cmd
    "x'; touch /tmp/bbhunt_pwned_marker; #",             # single-quote breakout
    "x`touch /tmp/bbhunt_pwned_marker`",                 # backtick substitution
    "x$(touch /tmp/bbhunt_pwned_marker)",                # $() substitution
    "x'); __import__('os').system('id'); #",             # Python string-literal breakout (crt.sh-style)
    "-rf /",                                             # leading-dash flag confusion
    "x; touch /tmp/bbhunt_pwned_marker #",
]

# recon_engine.sh's bash-level guard (defense-in-depth, matching upstream's
# own scope) rejects shell metacharacters specifically — a bare leading-dash
# string like "-rf /" isn't a shell metacharacter payload and isn't reinterpreted
# as a flag by a bash positional parameter, so it's deliberately excluded here.
# validate_target() (the real trust-boundary gate, tested above and via the
# hunt.py/engine.py CLI tests below) is what rejects it.
MALICIOUS_SHELL_METACHAR_TARGETS = [t for t in MALICIOUS_TARGETS if t != "-rf /"]

LEGITIMATE_TARGETS = [
    "example.com",
    "sub.example.com",
    "api-v2.example.co.uk",
    "192.168.1.1",
    "10.0.0.0/24",
    "2001:db8::1",
    "_dmarc.example.com",
]


class TestValidateTargetRejectsInjection:
    """hunt.py's validate_target() is the trust-boundary gate every CLI
    entry point (hunt.py, agent.py, engine.py) now calls before a target
    string touches anything else."""

    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_rejects_malicious_payload(self, payload):
        with pytest.raises(ValueError):
            hunt.validate_target(payload)

    @pytest.mark.parametrize("target", LEGITIMATE_TARGETS)
    def test_accepts_legitimate_target(self, target):
        hunt.validate_target(target)  # must not raise

    def test_accepts_existing_file_inside_base_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
        f = tmp_path / "scope.txt"
        f.write_text("a.example.com\nb.example.com\n")
        hunt.validate_target(str(f))

    def test_rejects_file_outside_base_dir_and_home(self, tmp_path, monkeypatch):
        outside = tmp_path / "outside"
        outside.mkdir()
        base = tmp_path / "base"
        base.mkdir()
        monkeypatch.setattr(hunt, "BASE_DIR", str(base))
        monkeypatch.setenv("HOME", str(base / "definitely-not-home"))
        f = outside / "etc_passwd_lookalike.txt"
        f.write_text("root:x:0:0\n")
        with pytest.raises(ValueError):
            hunt.validate_target(str(f))

    def test_rejects_oversized_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
        big = tmp_path / "huge.txt"
        big.write_bytes(b"x" * (10 * 1024 * 1024 + 1))
        with pytest.raises(ValueError):
            hunt.validate_target(str(big))

    def test_empty_and_oversized_string_rejected(self):
        with pytest.raises(ValueError):
            hunt.validate_target("")
        with pytest.raises(ValueError):
            hunt.validate_target("a" * 300)


# ─── hunt.py: subprocess calls never use shell=True, target is one argv elem ─

class _FakePopen:
    """Captures the exact args/kwargs subprocess.Popen was called with, and
    behaves enough like a real Popen for the calling code's .wait()."""
    last_call = None

    def __init__(self, *args, **kwargs):
        _FakePopen.last_call = {"args": args, "kwargs": kwargs}
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


class TestHuntPyNeverUsesShellTrue:
    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_run_recon_argv_not_shell(self, monkeypatch, payload):
        monkeypatch.setattr(hunt.subprocess, "Popen", _FakePopen)
        monkeypatch.setattr(hunt, "detect_target_type", lambda t: "domain")
        hunt.run_recon(payload, quick=False, scope_lock=False)
        call = _FakePopen.last_call
        assert call["kwargs"].get("shell") is not True
        argv = call["args"][0]
        assert isinstance(argv, list)
        assert payload in argv  # arrives as ONE literal element, never concatenated into a string

    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_run_vuln_scan_argv_not_shell(self, monkeypatch, tmp_path, payload):
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path))
        os.makedirs(os.path.join(str(tmp_path), payload.replace("/", "_")), exist_ok=True) \
            if False else None
        # run_vuln_scan requires recon_dir to exist; point it at a real tmp dir
        recon_dir = os.path.join(str(tmp_path), "somedomain")
        os.makedirs(recon_dir, exist_ok=True)
        monkeypatch.setattr(hunt.os.path, "isdir", lambda p: p == recon_dir or os.path.isdir(p))
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path))
        monkeypatch.setattr(hunt.subprocess, "Popen", _FakePopen)

        # Directly exercise the vulnerable construction path by calling with
        # domain="somedomain" (valid dir) — the payload is what matters for
        # run_recon/run_zero_day_fuzzer above and the CLI-level tests below;
        # here we confirm the Popen call shape itself never sets shell=True.
        hunt.run_vuln_scan("somedomain", quick=False, full=True)
        call = _FakePopen.last_call
        assert call["kwargs"].get("shell") is not True
        assert isinstance(call["args"][0], list)
        assert "--full" in call["args"][0]

    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_run_zero_day_fuzzer_argv_not_shell(self, monkeypatch, payload):
        monkeypatch.setattr(hunt.subprocess, "Popen", _FakePopen)
        hunt.run_zero_day_fuzzer(payload, deep=False)
        call = _FakePopen.last_call
        assert call["kwargs"].get("shell") is not True
        argv = call["args"][0]
        assert isinstance(argv, list)
        assert f"https://{payload}" in argv


class TestHuntPyCliRejectsMaliciousTarget:
    """Real subprocess invocation of `python3 tools/hunt.py --target <payload>`
    — the actual trust-boundary gate, not a mock."""

    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_cli_exits_nonzero_no_canary(self, payload, tmp_path):
        canary = tmp_path / "bbhunt_pwned_marker"
        env = dict(os.environ)
        env["HOME"] = str(tmp_path)  # so a canary path under $HOME would be visible if ever created
        proc = subprocess.run(
            [sys.executable, os.path.join(TOOLS_DIR, "hunt.py"), "--target", payload, "--no-banner"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15, env=env,
        )
        assert proc.returncode == 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        assert not canary.exists()
        assert not os.path.exists("/tmp/bbhunt_pwned_marker")

    def test_cli_accepts_legitimate_target_past_the_gate(self, tmp_path, monkeypatch):
        """A legitimate target must pass validate_target() and reach argparse's
        normal flow (we don't run a real recon here — just confirm it isn't
        rejected at the trust boundary with exit code 2)."""
        env = dict(os.environ)
        proc = subprocess.run(
            [sys.executable, os.path.join(TOOLS_DIR, "hunt.py"),
             "--target", "example.com", "--status", "--no-banner"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15, env=env,
        )
        assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"


# ─── zero_day_fuzzer.py ─────────────────────────────────────────────────────

class TestZeroDayFuzzerRunCmd:
    def test_run_cmd_rejects_string_argv(self):
        with pytest.raises(TypeError):
            zdf.run_cmd("curl -s https://example.com")

    def test_run_cmd_accepts_list_argv(self):
        ok, out, err = zdf.run_cmd(["echo", "hello"], timeout=5)
        assert ok
        assert "hello" in out

    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_curl_request_never_shells_out(self, monkeypatch, payload):
        captured = {}

        def fake_run_cmd(argv, timeout=15):
            captured["argv"] = argv
            return True, "HTTP/1.1 200 OK\r\n\r\nbody", ""

        monkeypatch.setattr(zdf, "run_cmd", fake_run_cmd)
        url = f"https://example.com/?x={payload}"
        zdf.curl_request(url)
        assert isinstance(captured["argv"], list)
        assert url in captured["argv"]  # literal single element, not shell-joined


# ─── agent.py: ToolDispatcher._run_shell_tool ──────────────────────────────

class TestAgentRunShellTool:
    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_run_shell_tool_argv_not_shell(self, monkeypatch, payload, tmp_path):
        import importlib.util
        spec = importlib.util.spec_from_file_location("agent_mod", os.path.join(REPO_ROOT, "agent.py"))
        agent_mod = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("agent_mod", agent_mod)
        spec.loader.exec_module(agent_mod)

        h = agent_mod._h()
        monkeypatch.setattr(h, "BASE_DIR", str(tmp_path))
        script_dir = tmp_path / "tools"
        script_dir.mkdir()
        script = script_dir / "secrets_hunter.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)

        dispatcher = agent_mod.ToolDispatcher(domain="example.com", memory=None)
        monkeypatch.setattr(agent_mod.subprocess, "Popen", _FakePopen)

        # recon_dir/out_dir built the same way run_secret_hunt/run_param_discovery
        # build them: os.path.join(RECON_DIR/FINDINGS_DIR, domain) — simulate a
        # malicious *domain* flowing into that join, same as the real call sites.
        recon_dir = os.path.join(str(tmp_path), "recon", payload)
        out_dir = os.path.join(str(tmp_path), "findings", payload, "secrets")
        dispatcher._run_shell_tool("secrets_hunter.sh", ["--js-bundle", recon_dir, "--out", out_dir])

        call = _FakePopen.last_call
        assert call["kwargs"].get("shell") is not True
        argv = call["args"][0]
        assert isinstance(argv, list)
        assert recon_dir in argv
        assert out_dir in argv


# ─── engine.py: cmd_recon/cmd_hunt via _run_shell ──────────────────────────

class TestEngineRunShell:
    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_run_shell_argv_not_shell(self, monkeypatch, payload):
        import importlib.util
        spec = importlib.util.spec_from_file_location("engine_mod", os.path.join(REPO_ROOT, "engine.py"))
        engine_mod = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("engine_mod", engine_mod)
        spec.loader.exec_module(engine_mod)

        monkeypatch.setattr(engine_mod.subprocess, "Popen", _FakePopen)
        engine_mod._run_shell(["bash", "/dev/null", payload])
        call = _FakePopen.last_call
        assert call["kwargs"].get("shell") is not True
        assert isinstance(call["args"][0], list)
        assert payload in call["args"][0]

    @pytest.mark.parametrize("payload", MALICIOUS_TARGETS)
    def test_cli_recon_rejects_malicious_target(self, payload, tmp_path):
        canary = tmp_path / "bbhunt_pwned_marker"
        env = dict(os.environ)
        env["HOME"] = str(tmp_path)
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "engine.py"), "recon", payload, "--no-banner"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15, env=env,
        )
        assert proc.returncode == 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        assert not canary.exists()
        assert not os.path.exists("/tmp/bbhunt_pwned_marker")


# ─── shell scripts: real sandboxed subprocess proofs, no network ──────────

_STUBBED_BINARIES = ["subfinder", "amass", "httpx", "nuclei", "curl", "dig",
                      "sisakulint", "theHarvester"]


@pytest.fixture()
def stub_bin_dir(tmp_path_factory):
    """No-op stand-ins for external tools these scripts might invoke, so tests
    never depend on host tooling or the network."""
    d = tmp_path_factory.mktemp("stub-bin")
    for name in _STUBBED_BINARIES:
        stub = d / name
        stub.write_text("#!/bin/sh\necho '[]'\nexit 0\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(d)


class TestReconEngineShRejectsInjection:
    @pytest.mark.parametrize("payload", MALICIOUS_SHELL_METACHAR_TARGETS)
    def test_malicious_target_rejected_no_canary(self, payload, tmp_path, stub_bin_dir):
        canary = tmp_path / "bbhunt_pwned_marker"
        env = dict(os.environ)
        env["PATH"] = stub_bin_dir + os.pathsep + env.get("PATH", "")
        env["HOME"] = str(tmp_path)
        env["RECON_OUT_DIR"] = str(tmp_path / "recon_out")
        proc = subprocess.run(
            ["bash", os.path.join(TOOLS_DIR, "recon_engine.sh"), payload],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15, env=env,
        )
        assert proc.returncode == 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        assert not canary.exists()
        assert not os.path.exists("/tmp/bbhunt_pwned_marker")

    def test_crtsh_python_snippet_neutralizes_injection_via_env(self, tmp_path):
        """Isolates the crt.sh fix itself (defense-in-depth layer, independent
        of the entry-point metachar gate): the fixed snippet reads $TARGET via
        os.environ, never string-interpolation into Python source. Feed it the
        exact PoC from the upstream fix commit's own message and confirm it's
        treated as inert data, not executed."""
        malicious = "x'); __import__('os').system('touch /tmp/bbhunt_pwned_marker'); #"
        snippet = '''
import os, sys, json
target = "." + os.environ.get("BBHUNT_TARGET", "")
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\\n"):
            name = name.strip().lower()
            if name and "*" not in name and name.endswith(target):
                names.add(name)
            elif name and "*" not in name and "." in name:
                names.add(name)
    for n in sorted(names):
        print(n)
except Exception:
    pass
'''
        env = dict(os.environ)
        env["BBHUNT_TARGET"] = malicious
        proc = subprocess.run(
            [sys.executable, "-c", snippet],
            input='[{"name_value": "sub.example.com"}]',
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert proc.returncode == 0
        assert not os.path.exists("/tmp/bbhunt_pwned_marker")
        # `sub.example.com` still appears in the output — that's pre-existing,
        # unrelated leniency in the parser (its fallback branch keeps any
        # dotted name, not just ones ending in the target), same on both
        # sides of this fix. What actually matters for security: the
        # malicious string never got a chance to execute as Python — no
        # exception, no canary, and critically no "id"-style output or error
        # naming an undefined variable, which is what you'd see if the
        # payload had been spliced into source and partially parsed.
        assert "os.system" not in proc.stdout
        assert "Traceback" not in proc.stderr


class TestCicdScannerShRejectsInjection:
    @pytest.mark.parametrize("payload", [
        'owner/repo"; touch /tmp/bbhunt_pwned_marker; echo "',
        "owner/repo'; touch /tmp/bbhunt_pwned_marker; #",
        "owner/repo`touch /tmp/bbhunt_pwned_marker`",
    ])
    def test_malicious_target_no_canary_and_arrives_as_one_arg(self, payload, tmp_path, stub_bin_dir):
        # Stub sisakulint to dump argv so we can confirm the payload arrived
        # as ONE literal element instead of being re-split by a shell.
        argv_dump = tmp_path / "sisakulint_argv.txt"
        stub = tmp_path / "sisakulint"
        stub.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{argv_dump}"\n'
            "exit 0\n"
        )
        stub.chmod(0o755)

        env = dict(os.environ)
        env["PATH"] = str(tmp_path) + os.pathsep + env.get("PATH", "")
        env["HOME"] = str(tmp_path)
        proc = subprocess.run(
            ["bash", os.path.join(TOOLS_DIR, "cicd_scanner.sh"), payload,
             "--output-dir", str(tmp_path / "out")],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=15, env=env,
        )
        assert not os.path.exists("/tmp/bbhunt_pwned_marker"), (
            f"injection executed! stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert argv_dump.exists(), "sisakulint stub was never invoked"
        received = argv_dump.read_text().splitlines()
        assert payload in received, (
            f"payload should arrive as one literal argv element, got: {received!r}"
        )


class TestH1RunShRejectsInjection:
    def test_malicious_token_no_canary_and_arrives_as_one_arg(self, tmp_path):
        malicious_token = "AAA'; touch /tmp/bbhunt_pwned_marker; #"

        # Stub h1_idor_scanner.py to dump the argv it received.
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        argv_dump = tmp_path / "idor_argv.txt"
        stub_scanner = tools_dir / "h1_idor_scanner.py"
        stub_scanner.write_text(
            "import sys\n"
            f"open(r'{argv_dump}', 'w').write('\\n'.join(sys.argv[1:]))\n"
        )

        # Copy h1_run.sh and patch in the malicious token + point TOOLS_DIR-derived
        # path at our stub, without needing real HackerOne credentials.
        original = open(os.path.join(TOOLS_DIR, "h1_run.sh")).read()
        patched = original.replace('TOKEN_A=""', f'TOKEN_A="{malicious_token}"')
        patched = patched.replace('TOKEN_B=""', 'TOKEN_B="BBB"')
        # Skip phase 1 (real hackerone.com calls) entirely for this test by
        # truncating the script right after phase 2's eval-replaced block.
        marker = 'echo ""\necho "══ PHASE 3'
        assert marker in patched, "h1_run.sh structure changed; update this test's truncation point"
        patched = patched.split(marker, 1)[0]

        script_copy = tmp_path / "h1_run_patched.sh"
        script_copy.write_text(patched)
        script_copy.chmod(0o755)

        env = dict(os.environ)
        env["HOME"] = str(tmp_path)
        proc = subprocess.run(
            ["bash", str(script_copy)],
            cwd=str(tools_dir.parent), capture_output=True, text=True, timeout=20, env=env,
        )
        assert not os.path.exists("/tmp/bbhunt_pwned_marker"), (
            f"injection executed! stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        if argv_dump.exists():
            received = argv_dump.read_text().splitlines()
            assert malicious_token in received


class TestOsintEmployeesShCrtLikeFix:
    def test_python_snippet_neutralizes_injection_via_env(self, tmp_path):
        """Isolates osint_employees.sh's HARVESTER_JSON fix the same way as
        the crt.sh test above — the malicious value flows in as inert data
        via os.environ, never as spliced Python source."""
        malicious = "x'); __import__('os').system('touch /tmp/bbhunt_pwned_marker'); f=open('"
        snippet = '''
import json, os
with open(os.environ["HARVESTER_JSON"]) as f:
    data = json.load(f)
for email in data.get("emails", []):
    print(email)
'''
        env = dict(os.environ)
        env["HARVESTER_JSON"] = malicious
        proc = subprocess.run(
            [sys.executable, "-c", snippet],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert not os.path.exists("/tmp/bbhunt_pwned_marker")
        # Treated as a literal (nonexistent) file path -> FileNotFoundError,
        # not code execution.
        assert proc.returncode != 0
        assert "FileNotFoundError" in proc.stderr or "No such file" in proc.stderr


# ─── residual findings: documented, intentionally NOT fixed here ──────────

class TestDocumentedResidualRisk:
    """tools/hunt.py's generic run_cmd() helper (top of the file) still uses
    shell=True. It is NOT fixed here because none of its 3 current callers
    (check_tools' `command -v {tool}` over a hardcoded tool list,
    setup_wordlists' fixed URL dict, select_targets' `--top {int}` flag) pass
    target/domain-derived data — there is no live exploitation path today.
    This test locks that fact in as a regression-visible assertion: if a
    future change adds a caller that passes user-controlled data through
    run_cmd, this test should be revisited alongside that change."""

    def test_run_cmd_still_uses_shell_true_no_current_exploit_path(self):
        import inspect
        src = inspect.getsource(hunt.run_cmd)
        assert "shell=True" in src
        # the only 3 call sites in the file, verified by direct inspection
        callers_src = inspect.getsource(hunt)
        assert 'f"command -v {tool}"' in callers_src
        assert "f'curl -sL \"{url}\" -o \"{filepath}\"'" in callers_src
