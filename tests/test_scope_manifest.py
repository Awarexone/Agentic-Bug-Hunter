from pathlib import Path

from tools.scope_checker import ScopeManifest


def write_scope(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def checker(tmp_path: Path):
    path = write_scope(
        tmp_path,
        """
program_name: Practice
platform_url: https://example.test
safe_harbor_notes: safe
asset_types: [web, api]
hosts_allow: [example.test, "*.example.test"]
hosts_deny: [admin.example.test]
paths_deny: ["^/private", "/forbidden$"]
ip_cidr_allow: [10.0.0.0/24]
ip_cidr_deny: [10.0.0.13/32]
third_party_exclusions:
  - name: stripe
    cidr: [198.51.100.0/24]
methods_allow: [GET, HEAD, OPTIONS, POST]
max_rate_per_sec: 1
""",
    )
    resolver = lambda host: {
        "example.test": [],
        "api.example.test": [],
        "stripe.example.test": ["198.51.100.4"],
    }.get(host, [])
    return ScopeManifest.from_file(path).checker(resolver=resolver)


def test_host_allow_and_deny(tmp_path):
    sc = checker(tmp_path)
    assert sc.check("https://api.example.test/", resolve=False)[0] is True
    ok, reason = sc.check("https://admin.example.test/", resolve=False)
    assert ok is False
    assert reason == "host-out-of-scope:admin.example.test"


def test_path_deny(tmp_path):
    ok, reason = checker(tmp_path).check("https://example.test/private/report", resolve=False)
    assert ok is False
    assert reason == "path-denied:^/private"


def test_cidr_allow_and_deny(tmp_path):
    sc = checker(tmp_path)
    assert sc.check("https://10.0.0.12/", resolve=False)[0] is True
    ok, reason = sc.check("https://10.0.0.13/", resolve=False)
    assert ok is False
    assert reason == "ip-out-of-scope:10.0.0.13"


def test_third_party_exclusion(tmp_path):
    ok, reason = checker(tmp_path).check("https://stripe.example.test/")
    assert ok is False
    assert reason == "third-party-excluded:stripe:198.51.100.4"


def test_method_and_active_approval(tmp_path):
    sc = checker(tmp_path)
    ok, reason = sc.check("https://example.test/", method="POST", resolve=False)
    assert ok is False
    assert reason == "active-method-requires-approval:POST"
    assert sc.check("https://example.test/", method="POST", approve_active=True, resolve=False)[0] is True


def test_rate_limit(tmp_path):
    ok, reason = checker(tmp_path).check("https://example.test/", rate_limit=2, resolve=False)
    assert ok is False
    assert reason == "rate-exceeds-scope:2>1"
