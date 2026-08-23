"""None of these files may construct an SSL context with CERT_NONE /
check_hostname=False as a fallback for a missing certifi import — that's
the default install state (certifi isn't a declared dependency), so it
silently exposes every credential-bearing request in the OAuth spray and
IDOR tools to MITM. See SECURITY-REVIEW-2026-08-22.md finding #9 (MEDIUM)."""
import ast
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FILES = [
    "tools/_spray_oauth.py",
    "tools/h1_mutation_idor.py",
    "tools/learn.py",
    "tools/validate.py",
    "tools/waf_response_analyzer.py",
    "mcp/hackerone-mcp/server.py",
]


class TestNoCertNoneFallback:
    def test_no_file_sets_cert_none(self):
        offenders = []
        for rel_path in FILES:
            path = os.path.join(REPO_ROOT, rel_path)
            with open(path) as f:
                source = f.read()
            if "CERT_NONE" in source:
                offenders.append(rel_path)
        assert not offenders, f"CERT_NONE still present in: {offenders}"

    def test_no_file_sets_check_hostname_false(self):
        offenders = []
        for rel_path in FILES:
            path = os.path.join(REPO_ROOT, rel_path)
            with open(path) as f:
                source = f.read()
            if "check_hostname = False" in source or "check_hostname=False" in source:
                offenders.append(rel_path)
        assert not offenders, f"check_hostname disabled in: {offenders}"
