"""Tests for tools/lead_board.py — recon->skill routing + persistent lead ledger.

Covers the contract that matters: every recon signal maps to the right hunt-*
skill, re-ingesting never wipes a lead's status, and the privileged-path router
does not false-positive on keywords that appear inside a query value.
"""

import pytest

import lead_board as lb  # tools/ is on sys.path via tests/conftest.py


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point the ledger at a tmp dir so tests never touch real memory/leads/."""
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


def _make_recon(tmp_path, urls):
    rd = tmp_path / "recon"
    (rd / "urls").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("\n".join(urls) + "\n")
    return str(rd)


def test_routing_maps_signals_to_skills(isolated):
    rd = _make_recon(isolated, [
        "https://t.example/api/v2/users?id=1001",       # -> hunt-idor
        "https://t.example/graphql",                     # -> hunt-graphql
        "https://t.example/fetch?url=https://internal",  # -> hunt-ssrf
        "https://t.example/static/app.js.map",           # -> hunt-source-leak
        "https://t.example/saml2/acs",                   # -> hunt-saml
        "https://t.example/api/chat",                    # -> hunt-llm-ai
    ])
    skills = {l["skill"] for l in lb.ingest("t.example", rd)}
    for expected in ("hunt-idor", "hunt-graphql", "hunt-ssrf",
                     "hunt-source-leak", "hunt-saml", "hunt-llm-ai"):
        assert expected in skills, f"{expected} not routed; got {sorted(skills)}"


def test_reingest_preserves_status_and_dedups(isolated):
    rd = _make_recon(isolated, ["https://t.example/graphql"])
    leads = lb.ingest("t.example", rd)
    n = len(leads)
    gid = next(l["id"] for l in leads if l["skill"] == "hunt-graphql")

    lb.touch("t.example", gid, "investigating", "introspection open")

    leads2 = lb.ingest("t.example", rd)               # same recon, re-run
    assert len(leads2) == n                            # dedup: no growth
    g = next(l for l in leads2 if l["id"] == gid)
    assert g["status"] == "investigating"              # progress preserved
    assert g["note"] == "introspection open"


def test_privileged_path_not_triggered_by_query_value(isolated):
    # 'dashboard' lives in the query string, not the path -> no auth-bypass lead.
    rd = _make_recon(isolated, ["https://t.example/login?next=/dashboard"])
    skills = {l["skill"] for l in lb.ingest("t.example", rd)}
    assert "hunt-auth-bypass" not in skills
    assert "hunt-open-redirect" in skills              # the real signal here


def test_touch_unknown_lead_is_safe(isolated):
    rd = _make_recon(isolated, ["https://t.example/graphql"])
    lb.ingest("t.example", rd)
    lb.touch("t.example", "lb-doesnotexist", "killed", None)  # must not raise
    leads = lb.load_ledger("t.example")
    assert all(l["status"] != "killed" for l in leads)
