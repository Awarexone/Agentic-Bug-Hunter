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


class TestChainDetection:
    """Correlation: two independently-routed leads on the same target/host
    should synthesize a composite high-priority chain lead."""

    def test_secret_plus_api_same_host_detected(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads = lb.ingest("t.example", rd)
        chains = [l for l in leads if l.get("source") == "chain"]
        assert chains, "expected a secret+API chain lead"
        assert chains[0]["priority"] == "high"
        assert chains[0]["chain_name"] == "secret_plus_api"
        assert len(chains[0]["chain_of"]) == 2

    def test_no_chain_without_both_legs(self, isolated):
        rd = _make_recon(isolated, ["https://api.t.example/api/v2/users?id=1001"])
        leads = lb.ingest("t.example", rd)
        assert not [l for l in leads if l.get("source") == "chain"]

    def test_cross_host_chain_is_med_not_high(self, isolated):
        rd = _make_recon(isolated, [
            "https://admin.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads = lb.ingest("t.example", rd)
        chains = [l for l in leads if l.get("source") == "chain"]
        assert chains
        assert all(c["priority"] == "med" for c in chains)

    def test_reingest_does_not_duplicate_chains(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads1 = lb.ingest("t.example", rd)
        n_chains_1 = len([l for l in leads1 if l.get("source") == "chain"])
        leads2 = lb.ingest("t.example", rd)
        n_chains_2 = len([l for l in leads2 if l.get("source") == "chain"])
        assert n_chains_1 == n_chains_2
        assert n_chains_1 > 0

    def test_chain_leads_appear_in_show_output(self, isolated, capsys):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        lb.ingest("t.example", rd)
        lb.show("t.example", None)
        out = capsys.readouterr().out
        assert "CHAINS DETECTED" in out

    def test_dot_tar_in_hostname_does_not_false_positive_source_leak(self, isolated):
        # api.target.com contains the substring ".tar" (api.**tar**get.com) —
        # regression guard for the unanchored \.tar false positive.
        rd = _make_recon(isolated, ["https://api.target.com/api/v2/users?id=1001"])
        leads = lb.ingest("target.com", rd)
        assert "hunt-source-leak" not in {l["skill"] for l in leads}

    def test_api_dot_hostname_does_not_false_positive_rest_api_surface(self, isolated):
        # api.t.example contains "//api." right after the scheme -- regression
        # guard for the unanchored /api\b false positive matching the host
        # instead of a real /api path.
        rd = _make_recon(isolated, ["https://api.t.example/.env"])
        leads = lb.ingest("t.example", rd)
        env_leads = [l for l in leads if l["evidence"] == "https://api.t.example/.env"]
        assert "hunt-api-misconfig" not in {l["skill"] for l in env_leads}

    def test_real_api_path_still_matches_rest_api_surface(self, isolated):
        rd = _make_recon(isolated, ["https://t.example/api/v2/orders"])
        leads = lb.ingest("t.example", rd)
        assert "hunt-api-misconfig" in {l["skill"] for l in leads}


class TestHypothesisEngine:
    """3-way correlations (Phase 3 attack graph): secret + API + weak auth,
    all on the same host, should rise to a named vulnerability hypothesis
    with an explicit impact — not just an elevated chain lead."""

    def test_three_way_same_host_produces_hypothesis(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        leads = lb.ingest("t.example", rd)
        hyps = [l for l in leads if l.get("source") == "hypothesis"]
        assert hyps, "expected an account-takeover hypothesis"
        assert hyps[0]["chain_name"] == "account_takeover_via_leaked_secret"
        assert hyps[0]["impact"] == "critical"
        assert len(hyps[0]["chain_of"]) == 3

    def test_cross_host_does_not_produce_hypothesis(self, isolated):
        rd = _make_recon(isolated, [
            "https://admin.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://other.t.example/login?next=/dashboard",
        ])
        leads = lb.ingest("t.example", rd)
        assert not [l for l in leads if l.get("source") == "hypothesis"]

    def test_missing_leg_produces_no_hypothesis(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        leads = lb.ingest("t.example", rd)
        assert not [l for l in leads if l.get("source") == "hypothesis"]

    def test_same_url_cannot_fill_two_legs(self, isolated):
        # A single URL matching multiple skills in one leg's skill set is one
        # real artifact, not grounds for a duplicate hypothesis.
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",  # matches idor AND api-misconfig
            "https://api.t.example/login?next=/dashboard",
        ])
        leads = lb.ingest("t.example", rd)
        hyps = [l for l in leads if l.get("source") == "hypothesis"]
        # exactly one hypothesis, not one per (idor-lead, api-misconfig-lead) pairing
        assert len(hyps) == 1

    def test_reingest_does_not_duplicate_hypotheses(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        leads1 = lb.ingest("t.example", rd)
        n1 = len([l for l in leads1 if l.get("source") == "hypothesis"])
        leads2 = lb.ingest("t.example", rd)
        n2 = len([l for l in leads2 if l.get("source") == "hypothesis"])
        assert n1 == n2 > 0

    def test_hypothesis_leads_appear_in_show_output(self, isolated, capsys):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        lb.ingest("t.example", rd)
        lb.show("t.example", None)
        out = capsys.readouterr().out
        assert "VULNERABILITY HYPOTHESES" in out
        assert "Account Takeover" in out


class TestAttackGraph:

    def test_graph_has_asset_and_endpoint_nodes(self, isolated):
        rd = _make_recon(isolated, ["https://t.example/graphql"])
        lb.ingest("t.example", rd)
        g = lb.build_graph("t.example")
        types = {n["type"] for n in g["nodes"]}
        assert "asset" in types
        assert "endpoint" in types

    def test_graph_links_hypothesis_to_impact(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        lb.ingest("t.example", rd)
        g = lb.build_graph("t.example")
        hyp_nodes = [n for n in g["nodes"] if n["type"] == "vulnerability_hypothesis"]
        impact_nodes = [n for n in g["nodes"] if n["type"] == "impact"]
        assert hyp_nodes and impact_nodes
        hyp_id = hyp_nodes[0]["id"]
        assert any(e["from"] == hyp_id and e["to"] == impact_nodes[0]["id"] for e in g["edges"])

    def test_graph_json_serializable(self, isolated):
        rd = _make_recon(isolated, ["https://t.example/graphql"])
        lb.ingest("t.example", rd)
        g = lb.build_graph("t.example")
        import json
        json.dumps(g)  # must not raise

    def test_print_graph_handles_no_hypotheses(self, isolated, capsys):
        rd = _make_recon(isolated, ["https://t.example/graphql"])
        lb.ingest("t.example", rd)
        lb.print_graph("t.example")
        out = capsys.readouterr().out
        assert "ATTACK SURFACE GRAPH" in out
        assert "no correlated hypotheses" in out
