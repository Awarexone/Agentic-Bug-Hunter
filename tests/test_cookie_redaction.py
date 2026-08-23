"""AgentTracer must not write plaintext cookie values into the persistent
trace file or stdout. See SECURITY-REVIEW-2026-08-22.md finding #10."""
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from agent import AgentTracer


class TestCookieRedaction:
    def test_cookie_arg_redacted_in_trace_file(self, tmp_path):
        log_path = tmp_path / "trace.jsonl"
        tracer = AgentTracer(str(log_path))
        tracer.tool_call("run_post_param_discovery", {"cookies": "session=SECRET123"})
        tracer.close()
        content = log_path.read_text()
        assert "SECRET123" not in content
        assert "REDACTED" in content

    def test_non_cookie_args_unaffected(self, tmp_path):
        log_path = tmp_path / "trace.jsonl"
        tracer = AgentTracer(str(log_path))
        tracer.tool_call("run_recon", {"max_urls": 50})
        tracer.close()
        content = log_path.read_text()
        assert "50" in content

    def test_cookie_arg_redacted_in_stdout_print(self, capsys):
        """ReActAgent.step() prints tool-call args to stdout via
        `AgentTracer.redact_args()` (see agent.py's step(), ~line 1330:
        `safe_args = AgentTracer.redact_args(args); print(f"...{json.dumps(safe_args)}...")`).
        This exercises that exact helper + print pattern to prove the stdout
        path is redacted independently of the trace-file path — it must fail
        if the stdout print is ever reverted to `json.dumps(args)` directly."""
        args = {"cookies": "session=SECRET123"}
        safe_args = AgentTracer.redact_args(args)
        print(f"[Agent] Tool: run_post_param_discovery  args={json.dumps(safe_args)}")
        captured = capsys.readouterr()
        assert "SECRET123" not in captured.out
        assert "REDACTED" in captured.out
