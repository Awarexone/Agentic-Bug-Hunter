"""Tests for memory/attack_graph.py — Phase 4 batch 1 (Attack Graph v2).

Covers the batch-1-relevant subset: rules/chain_rules.yaml loads and
validates (malformed YAML fails loudly, never silently skipped/defaulted),
a regression proof that the YAML transcription reproduces
tools/lead_board.py's hardcoded CHAIN_RULES/HYPOTHESIS_RECIPES output on
identical fixture leads, N-leg path discovery (including a 4-leg fixture
that genuinely requires depth 4), cycle protection (a cyclic graph must not
hang), the combinatorial cap holding on a large synthetic lead set, and
path_score()'s monotonicity in confidence and impact.

tools/lead_board.py's CHAIN_RULES / HYPOTHESIS_RECIPES / detect_chains() /
detect_hypotheses() are read-only reference here — never modified, never
monkeypatched. tests/test_lead_board.py is the proof they still behave
exactly as before; this file never touches it.
"""

import json
import time
from pathlib import Path

import pytest
import yaml

from memory import attack_graph as ag
from tools import lead_board as lb


# ─────────────────────────────────────────────────────────────────────────
# Item 1: rules/chain_rules.yaml — load/validate, malformed-YAML failure
# ─────────────────────────────────────────────────────────────────────────

class TestLoadChainRules:

    def test_default_file_loads(self):
        rules = ag.load_chain_rules()
        assert len(rules) == 6
        ids = {r.id for r in rules}
        assert ids == {
            "secret_plus_api", "idor_plus_account_surface", "cors_plus_sensitive",
            "upload_plus_processing", "account_takeover_via_leaked_secret",
            "account_takeover_via_cors_and_idor",
        }

    def test_chain_shaped_rules_have_one_step(self):
        rules = {r.id: r for r in ag.load_chain_rules()}
        for chain_id in ("secret_plus_api", "idor_plus_account_surface",
                          "cors_plus_sensitive", "upload_plus_processing"):
            assert len(rules[chain_id].steps) == 1

    def test_hypothesis_shaped_rules_terminate_on_impact(self):
        rules = {r.id: r for r in ag.load_chain_rules()}
        for hyp_id in ("account_takeover_via_leaked_secret", "account_takeover_via_cors_and_idor"):
            rule = rules[hyp_id]
            assert len(rule.steps) == 3
            assert rule.steps[-1].to_type == "Impact"
            assert rule.impact == "critical"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(tmp_path / "nope.yaml"))

    def test_bad_yaml_syntax_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("- id: x\n  steps: [unbalanced")
        with pytest.raises(yaml.YAMLError):
            ag.load_chain_rules(str(p))

    def test_top_level_must_be_a_list(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("id: x\ndescription: y\n")
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(p))

    def test_missing_id_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "- description: d\n"
            "  steps:\n"
            "    - from_type: Endpoint\n"
            "      from_value: a\n"
            "      edge_type: reveals\n"
            "      to_type: Endpoint\n"
            "      to_value: b\n"
            "      confidence: 0.5\n"
        )
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(p))

    def test_invalid_edge_type_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "- id: x\n"
            "  description: d\n"
            "  steps:\n"
            "    - from_type: Endpoint\n"
            "      from_value: a\n"
            "      edge_type: not_a_real_edge_type\n"
            "      to_type: Endpoint\n"
            "      to_value: b\n"
            "      confidence: 0.5\n"
        )
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(p))

    def test_invalid_node_type_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "- id: x\n"
            "  description: d\n"
            "  steps:\n"
            "    - from_type: NotARealType\n"
            "      from_value: a\n"
            "      edge_type: reveals\n"
            "      to_type: Endpoint\n"
            "      to_value: b\n"
            "      confidence: 0.5\n"
        )
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(p))

    def test_confidence_out_of_range_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            "- id: x\n"
            "  description: d\n"
            "  steps:\n"
            "    - from_type: Endpoint\n"
            "      from_value: a\n"
            "      edge_type: reveals\n"
            "      to_type: Endpoint\n"
            "      to_value: b\n"
            "      confidence: 1.5\n"
        )
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(p))

    def test_empty_steps_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("- id: x\n  description: d\n  steps: []\n")
        with pytest.raises(ag.RuleLoadError):
            ag.load_chain_rules(str(p))

    def test_valid_minimal_rule_loads(self, tmp_path):
        p = tmp_path / "good.yaml"
        p.write_text(
            "- id: x\n"
            "  description: d\n"
            "  steps:\n"
            "    - from_type: Endpoint\n"
            "      from_value: [a, b]\n"
            "      edge_type: reveals\n"
            "      to_type: Endpoint\n"
            "      to_value: c\n"
            "      confidence: 0.5\n"
        )
        rules = ag.load_chain_rules(str(p))
        assert len(rules) == 1
        assert rules[0].steps[0].from_values == ("a", "b")
        assert rules[0].steps[0].to_values == ("c",)
        assert rules[0].enabled is True
        assert rules[0].min_confidence == 0.5

    def test_disabled_rule_flag_respected(self, tmp_path):
        p = tmp_path / "good.yaml"
        p.write_text(
            "- id: x\n"
            "  description: d\n"
            "  enabled: false\n"
            "  steps:\n"
            "    - from_type: Endpoint\n"
            "      from_value: a\n"
            "      edge_type: reveals\n"
            "      to_type: Endpoint\n"
            "      to_value: b\n"
            "      confidence: 0.5\n"
        )
        rules = ag.load_chain_rules(str(p))
        assert rules[0].enabled is False


# ─────────────────────────────────────────────────────────────────────────
# Regression: chain_rules.yaml (via the new detectors) reproduces
# lead_board.py's hardcoded CHAIN_RULES/HYPOTHESIS_RECIPES output.
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(lb, "LEADS_DIR", str(tmp_path / "leads"))
    return tmp_path


def _make_recon(tmp_path, urls, subdir="recon"):
    rd = tmp_path / subdir
    (rd / "urls").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text("\n".join(urls) + "\n")
    return str(rd)


def _chain_key_set(chains):
    return {(c["chain_name"], tuple(sorted(c["chain_of"]))) for c in chains}


def _hyp_key_set(hyps):
    return {(h["chain_name"], tuple(sorted(h["chain_of"])), h["impact"]) for h in hyps}


class TestRegressionAgainstLeadBoard:
    """Same fixture leads fed to the OLD hardcoded-table path
    (lead_board.detect_chains/detect_hypotheses, driven by CHAIN_RULES/
    HYPOTHESIS_RECIPES) and the NEW yaml-driven path
    (attack_graph.detect_chains_from_rules/detect_hypotheses_from_rules,
    driven by rules/chain_rules.yaml) must detect the identical set of
    correlations: same rule fired, same leg leads paired, same host-based
    priority tier, same declared impact. Fields that are allowed to differ
    (synthetic id, "skill" inheritance details, timestamps) are excluded
    from the comparison on purpose — this proves structural/semantic
    equivalence, not byte-identical dict equality between two independent
    implementations.
    """

    def test_three_way_same_host_hypothesis_and_chains_match(self, isolated):
        rd = _make_recon(isolated, [
            "https://api.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://api.t.example/login?next=/dashboard",
        ])
        all_leads = lb.ingest("t.example", rd)
        raw_leads = [l for l in all_leads if l.get("source") not in ("chain", "hypothesis")]

        old_chains = [l for l in all_leads if l.get("source") == "chain"]
        old_hyps = [l for l in all_leads if l.get("source") == "hypothesis"]
        assert old_chains and old_hyps, "fixture must actually trigger both old detectors"

        new_chains = ag.detect_chains_from_rules("t.example", raw_leads)
        new_hyps = ag.detect_hypotheses_from_rules("t.example", raw_leads)

        assert _chain_key_set(old_chains) == _chain_key_set(new_chains)
        assert _hyp_key_set(old_hyps) == _hyp_key_set(new_hyps)
        # host-based priority tier must also match per matching pair
        old_priority = {tuple(sorted(c["chain_of"])): c["priority"] for c in old_chains}
        new_priority = {tuple(sorted(c["chain_of"])): c["priority"] for c in new_chains}
        assert old_priority == new_priority

    def test_cross_host_produces_no_hypothesis_in_either_path(self, isolated):
        rd = _make_recon(isolated, [
            "https://admin.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
            "https://other.t.example/login?next=/dashboard",
        ])
        all_leads = lb.ingest("t.example", rd)
        raw_leads = [l for l in all_leads if l.get("source") not in ("chain", "hypothesis")]

        old_hyps = [l for l in all_leads if l.get("source") == "hypothesis"]
        new_hyps = ag.detect_hypotheses_from_rules("t.example", raw_leads)
        assert not old_hyps
        assert not new_hyps

    def test_cross_host_chain_is_med_in_both_paths(self, isolated):
        rd = _make_recon(isolated, [
            "https://admin.t.example/.env",
            "https://api.t.example/api/v2/users?id=1001",
        ])
        all_leads = lb.ingest("t.example", rd)
        raw_leads = [l for l in all_leads if l.get("source") not in ("chain", "hypothesis")]

        old_chains = [l for l in all_leads if l.get("source") == "chain"]
        new_chains = ag.detect_chains_from_rules("t.example", raw_leads)
        assert old_chains and all(c["priority"] == "med" for c in old_chains)
        assert new_chains and all(c["priority"] == "med" for c in new_chains)

    def test_no_legs_present_produces_nothing_in_either_path(self, isolated):
        rd = _make_recon(isolated, ["https://api.t.example/api/v2/users?id=1001"])
        all_leads = lb.ingest("t.example", rd)
        raw_leads = [l for l in all_leads if l.get("source") not in ("chain", "hypothesis")]

        assert not [l for l in all_leads if l.get("source") == "chain"]
        assert not ag.detect_chains_from_rules("t.example", raw_leads)

    def test_second_hypothesis_recipe_cors_and_idor(self, isolated):
        # account_takeover_via_cors_and_idor: hunt-cors + hunt-idor + (hunt-ato|hunt-auth-bypass)
        rd = _make_recon(isolated, [
            "https://cors.t.example/jsonp?callback=x",                     # -> hunt-cors
            "https://cors.t.example/api/v2/users?id=1001",                 # -> hunt-idor
            "https://cors.t.example/login?next=/dashboard",                # -> hunt-auth-bypass? / hunt-open-redirect
        ])
        all_leads = lb.ingest("t.example", rd)
        raw_leads = [l for l in all_leads if l.get("source") not in ("chain", "hypothesis")]
        old_hyps = [l for l in all_leads if l.get("source") == "hypothesis"]
        new_hyps = ag.detect_hypotheses_from_rules("t.example", raw_leads)
        assert _hyp_key_set(old_hyps) == _hyp_key_set(new_hyps)


# ─────────────────────────────────────────────────────────────────────────
# Item 2: typed capability graph — provenance + contradiction
# ─────────────────────────────────────────────────────────────────────────

def _lead(id_, skill, evidence, priority="high"):
    return {"id": id_, "skill": skill, "evidence": evidence, "priority": priority, "source": "url"}


class TestBuildCapabilityGraph:

    def test_every_node_and_edge_has_origin(self):
        leads = [
            _lead("lb-1", "hunt-source-leak", "https://t.example/.env"),
            _lead("lb-2", "hunt-api-misconfig", "https://t.example/api/v2/orders"),
        ]
        g = ag.build_capability_graph("t.example", recon_dir="/nonexistent/recon/dir", leads=leads)
        assert g.nodes
        for node in g.nodes.values():
            assert node.origin_source
        for edge in g.edges:
            assert edge.origin_source

    def test_source_leak_lead_becomes_credential_node(self):
        leads = [_lead("lb-1", "hunt-source-leak", "https://t.example/.env")]
        g = ag.build_capability_graph("t.example", recon_dir="/nonexistent", leads=leads)
        node = g.nodes["lead:lb-1"]
        assert node.type == "Credential"
        assert node.origin_lead_id == "lb-1"

    def test_non_secret_lead_becomes_endpoint_node(self):
        leads = [_lead("lb-1", "hunt-idor", "https://t.example/api/v2/users?id=1")]
        g = ag.build_capability_graph("t.example", recon_dir="/nonexistent", leads=leads)
        node = g.nodes["lead:lb-1"]
        assert node.type == "Endpoint"

    def test_grants_edge_confidence_reduced_by_contradicting_status(self, tmp_path):
        # account_takeover_via_leaked_secret's middle step (leg2 -> leg3) is
        # the only `grants`-typed step among the transcribed rules:
        # hunt-source-leak -(reveals)-> {api-misconfig,graphql,idor}
        #   -(grants)-> {auth-bypass,ato,oauth} -(impacts)-> Impact
        rd = tmp_path / "recon" / "t.example"
        browser_dir = rd / "browser"
        browser_dir.mkdir(parents=True)
        import json
        (browser_dir / "api-calls.json").write_text(json.dumps({
            "target": "t.example",
            "calls": [{"url": "https://t.example/login?next=/dashboard", "response_status": 403}],
        }))
        leads = [
            _lead("lb-1", "hunt-source-leak", "https://t.example/.env"),
            _lead("lb-2", "hunt-idor", "https://t.example/api/v2/users?id=1"),
            _lead("lb-3", "hunt-auth-bypass", "https://t.example/login?next=/dashboard"),
        ]
        g = ag.build_capability_graph("t.example", recon_dir=str(rd), leads=leads)
        grants_edges = [e for e in g.edges if e.edge_type == "grants" and e.rule_id]
        assert grants_edges, "expected at least one rule-driven grants edge"
        contradicted = [e for e in grants_edges if e.contradiction]
        assert contradicted, "expected the observed 403 to contradict a grants edge"
        for e in contradicted:
            assert e.confidence < 0.75  # below the rule's base confidence

    def test_no_contradiction_when_status_is_success(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        browser_dir = rd / "browser"
        browser_dir.mkdir(parents=True)
        import json
        (browser_dir / "api-calls.json").write_text(json.dumps({
            "target": "t.example",
            "calls": [{"url": "https://t.example/login?next=/dashboard", "response_status": 200}],
        }))
        leads = [
            _lead("lb-1", "hunt-source-leak", "https://t.example/.env"),
            _lead("lb-2", "hunt-idor", "https://t.example/api/v2/users?id=1"),
            _lead("lb-3", "hunt-auth-bypass", "https://t.example/login?next=/dashboard"),
        ]
        g = ag.build_capability_graph("t.example", recon_dir=str(rd), leads=leads)
        contradicted = [e for e in g.edges if e.contradiction]
        assert not contradicted

    def test_auth_model_role_constants_become_capability_nodes(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        browser_dir = rd / "browser"
        browser_dir.mkdir(parents=True)
        import json
        (browser_dir / "auth-model.json").write_text(json.dumps({
            "target": "t.example", "role_permission_constants": ["ROLE_ADMIN"],
            "candidate_privileged_client_routes": ["/admin/settings"],
            "auth_lifecycle_endpoints": [],
        }))
        g = ag.build_capability_graph("t.example", recon_dir=str(rd), leads=[])
        cap_nodes = [n for n in g.nodes.values() if n.type == "Capability"]
        boundary_nodes = [n for n in g.nodes.values() if n.type == "Boundary"]
        assert any(n.label == "ROLE_ADMIN" for n in cap_nodes)
        assert any(n.label == "/admin/settings" for n in boundary_nodes)
        assert cap_nodes[0].origin_source == "browser/auth-model.json"

    def test_malformed_browser_json_does_not_raise(self, tmp_path):
        rd = tmp_path / "recon" / "t.example"
        browser_dir = rd / "browser"
        browser_dir.mkdir(parents=True)
        (browser_dir / "auth-model.json").write_text("{not json")
        g = ag.build_capability_graph("t.example", recon_dir=str(rd), leads=[])
        assert "asset:t.example" in g.nodes

    def test_tech_attack_matrix_only_modifies_confidence_never_adds_nodes(self):
        leads = [_lead("lb-1", "hunt-sqli", "https://t.example/search?q=1")]
        g_before = ag.build_capability_graph("t.example", recon_dir="/nonexistent", leads=leads)
        n_nodes_before = len(g_before.nodes)
        matrix = {"php": {"version_ranges": [{"range": "*", "vulns": [
            {"class": "sqli", "weight": 90, "cve": None, "citation": None},
        ]}]}}
        g_after = ag.build_capability_graph("t.example", recon_dir="/nonexistent", leads=leads,
                                             tech_stack=["php"], tech_attack_matrix=matrix)
        assert len(g_after.nodes) == n_nodes_before  # no new nodes from tech modifiers
        edge_before = next(e for e in g_before.edges if e.to_id == "lead:lb-1")
        edge_after = next(e for e in g_after.edges if e.to_id == "lead:lb-1")
        assert edge_after.confidence > edge_before.confidence


# ─────────────────────────────────────────────────────────────────────────
# Item 3: N-leg path search — depth, cycle protection, combinatorial cap
# ─────────────────────────────────────────────────────────────────────────

def _node(id_, type_, label, vuln_class=None):
    return ag.Node(id_, type_, label, origin_lead_id=None, origin_source="test", confidence_source="test",
                   vuln_class=vuln_class)


def _edge(from_id, to_id, edge_type, confidence):
    return ag.Edge(from_id, to_id, edge_type, confidence, origin_lead_id=None, origin_source="test")


class TestFindPaths:

    def test_four_leg_path_requires_depth_four(self):
        g = ag.Graph()
        g.add_node(_node("c1", "Credential", "leaked key"))
        g.add_node(_node("cap1", "Capability", "admin scope"))
        g.add_node(_node("ep1", "Endpoint", "/api/admin"))
        g.add_node(_node("b1", "Boundary", "client-only check"))
        g.add_node(_node("imp1", "Impact", "RCE", vuln_class="rce"))
        g.add_edge(_edge("c1", "cap1", "grants", 0.9))
        g.add_edge(_edge("cap1", "ep1", "reveals", 0.8))
        g.add_edge(_edge("ep1", "b1", "crosses", 0.7))
        g.add_edge(_edge("b1", "imp1", "impacts", 0.6))

        paths_depth_5 = ag.find_paths(g, max_depth=5)
        four_leg = [p for p in paths_depth_5 if p.node_ids[0] == "c1"]
        assert four_leg and len(four_leg[0].edges) == 4

        paths_depth_3 = ag.find_paths(g, max_depth=3)
        assert not [p for p in paths_depth_3 if p.node_ids[0] == "c1"]

    def test_no_credential_or_capability_start_yields_no_paths(self):
        g = ag.Graph()
        g.add_node(_node("ep1", "Endpoint", "e"))
        g.add_node(_node("imp1", "Impact", "i"))
        g.add_edge(_edge("ep1", "imp1", "impacts", 0.5))
        assert ag.find_paths(g) == []

    def test_cycle_does_not_hang_and_terminates(self):
        g = ag.Graph()
        g.add_node(_node("cap1", "Capability", "cap"))
        g.add_node(_node("ep1", "Endpoint", "ep1"))
        g.add_node(_node("ep2", "Endpoint", "ep2"))
        g.add_node(_node("imp1", "Impact", "imp"))
        g.add_edge(_edge("cap1", "ep1", "reveals", 0.5))
        g.add_edge(_edge("ep1", "ep2", "reveals", 0.5))
        g.add_edge(_edge("ep2", "ep1", "reveals", 0.5))  # cycle back to ep1
        g.add_edge(_edge("ep2", "imp1", "impacts", 0.5))

        start = time.time()
        paths = ag.find_paths(g, max_depth=5)
        elapsed = time.time() - start
        assert elapsed < 2.0  # must terminate quickly, not hang
        assert len(paths) == 1
        assert len(paths[0].edges) == 3  # cap1->ep1->ep2->imp1, cycle never re-walked

    def test_pure_self_loop_cycle_never_reached_twice(self):
        g = ag.Graph()
        g.add_node(_node("cap1", "Capability", "cap"))
        g.add_edge(_edge("cap1", "cap1", "reveals", 0.5))  # self-loop
        start = time.time()
        paths = ag.find_paths(g, max_depth=5)
        elapsed = time.time() - start
        assert elapsed < 2.0
        assert paths == []  # never reaches an Impact node

    def test_combinatorial_cap_holds_on_large_lead_set(self):
        g = ag.Graph()
        g.add_node(_node("asset:t.example", "Asset", "t.example"))
        leads = []
        for i in range(50):
            lid = f"sl-{i}"
            leads.append(_lead(lid, "hunt-source-leak", f"https://t.example/.env{i}"))
            g.add_node(_node(f"lead:{lid}", "Credential", leads[-1]["evidence"]))
        for i in range(50):
            lid = f"am-{i}"
            leads.append(_lead(lid, "hunt-api-misconfig", f"https://t.example/api/{i}"))
            g.add_node(_node(f"lead:{lid}", "Endpoint", leads[-1]["evidence"]))

        start = time.time()
        added = ag.apply_chain_rules(g, leads)
        elapsed = time.time() - start
        assert elapsed < 5.0
        # bounded by MAX_LEG_CANDIDATES^2 per matching rule, not 50*50=2500
        assert added <= ag.MAX_LEG_CANDIDATES * ag.MAX_LEG_CANDIDATES


# ─────────────────────────────────────────────────────────────────────────
# Item 4: path scoring
# ─────────────────────────────────────────────────────────────────────────

class TestPathScore:

    def test_monotonic_in_confidence(self):
        low = ag.path_score(0.3, 50, 20)
        high = ag.path_score(0.8, 50, 20)
        assert high > low

    def test_monotonic_in_impact(self):
        low = ag.path_score(0.5, 30, 20)
        high = ag.path_score(0.5, 90, 20)
        assert high > low

    def test_inverse_in_expected_minutes(self):
        fast = ag.path_score(0.5, 50, 10)
        slow = ag.path_score(0.5, 50, 40)
        assert fast > slow

    def test_zero_or_negative_minutes_raises(self):
        with pytest.raises(ValueError):
            ag.path_score(0.5, 50, 0)

    def test_reuses_vuln_intelligence_tables_not_a_second_copy(self):
        from memory.vuln_intelligence import VULN_IMPACT_POTENTIAL, TESTING_TIME_ESTIMATES
        assert ag.VULN_IMPACT_POTENTIAL is VULN_IMPACT_POTENTIAL
        assert ag.TESTING_TIME_ESTIMATES is TESTING_TIME_ESTIMATES

    def test_top_paths_emits_one_candidate_per_impact_node(self):
        g = ag.Graph()
        g.add_node(_node("c1", "Credential", "leaked key"))
        g.add_node(_node("cap1", "Capability", "admin scope"))
        g.add_node(_node("ep1", "Endpoint", "/api/admin"))
        g.add_node(_node("imp1", "Impact", "RCE", vuln_class="rce"))
        # two distinct paths from two distinct starts to the SAME impact node
        g.add_edge(_edge("c1", "cap1", "grants", 0.9))
        g.add_edge(_edge("cap1", "ep1", "reveals", 0.8))
        g.add_edge(_edge("ep1", "imp1", "impacts", 0.6))
        g.add_edge(_edge("cap1", "imp1", "impacts", 0.2))  # weaker direct shortcut

        candidates = ag.top_paths("t.example", g)
        assert len(candidates) == 1  # one Impact node -> one candidate
        assert candidates[0]["source"] == "attack-graph"
        assert candidates[0]["skill"] == "hunt-rce"
        assert candidates[0]["status"] == "new"

    def test_top_paths_lead_board_shaped(self):
        g = ag.Graph()
        g.add_node(_node("c1", "Credential", "leaked key"))
        g.add_node(_node("imp1", "Impact", "RCE", vuln_class="rce"))
        g.add_edge(_edge("c1", "imp1", "impacts", 0.5))
        candidates = ag.top_paths("t.example", g)
        required_fields = {"id", "target", "skill", "priority", "signal", "why", "evidence",
                            "source", "status", "chain_of", "created", "last_seen", "seen_count"}
        assert required_fields.issubset(candidates[0].keys())

    def test_top_paths_includes_path_legs_for_explainability(self):
        """path_legs (batch 2 addition) must let a caller identify the
        weakest leg, its origin, and any contradiction WITHOUT re-walking
        the graph — tools/director.py's explain() source=="attack-graph"
        case (batch 2) reads this field directly."""
        g = ag.Graph()
        g.add_node(_node("c1", "Credential", "leaked key"))
        g.add_node(_node("cap1", "Capability", "admin scope"))
        g.add_node(_node("imp1", "Impact", "RCE", vuln_class="rce"))
        g.add_edge(_edge("c1", "cap1", "grants", 0.9))
        g.add_edge(_edge("cap1", "imp1", "impacts", 0.3))
        candidates = ag.top_paths("t.example", g)
        legs = candidates[0]["path_legs"]
        assert len(legs) == 2
        assert {"from", "to", "edge_type", "confidence", "origin_source", "rule_id", "contradiction"} \
            <= set(legs[0].keys())
        weakest = min(legs, key=lambda leg: leg["confidence"])
        assert weakest["confidence"] == 0.3
        assert "expected_minutes" in candidates[0]
        assert "impact_weight" in candidates[0]


# ─────────────────────────────────────────────────────────────────────────
# Item 5 (batch 2): cross-host chains via a shared value_fingerprint
# ─────────────────────────────────────────────────────────────────────────

def _write_auth_model(recon_dir, cookies=None, local_storage=None, session_storage=None):
    browser_dir = Path(recon_dir) / "browser"
    browser_dir.mkdir(parents=True, exist_ok=True)
    (browser_dir / "auth-model.json").write_text(json.dumps({
        "target": "t.example",
        "cookies": cookies or [],
        "local_storage": local_storage or [],
        "session_storage": session_storage or [],
        "role_permission_constants": [],
        "auth_lifecycle_endpoints": [],
        "candidate_privileged_client_routes": [],
    }))


def _write_api_calls(recon_dir, calls=None):
    browser_dir = Path(recon_dir) / "browser"
    browser_dir.mkdir(parents=True, exist_ok=True)
    (browser_dir / "api-calls.json").write_text(json.dumps({
        "target": "t.example",
        "calls": calls or [],
    }))


SHARED_FP = "deadbeefcafebabe"  # 16 hex chars, same shape as sha256(...)[:16]


class TestCrossHostFingerprintLinking:
    """find_cross_host_credential_links() — the raw fingerprint-matching
    layer, independent of graph construction."""

    def test_shared_fingerprint_across_two_hosts_links(self, tmp_path):
        rd_a = tmp_path / "a"
        rd_b = tmp_path / "b"
        _write_auth_model(rd_a, cookies=[
            {"name": "session_id", "value_fingerprint": SHARED_FP, "looks_auth_related": True},
        ])
        _write_auth_model(rd_b, cookies=[
            {"name": "session_id", "value_fingerprint": SHARED_FP, "looks_auth_related": True},
        ])
        links = ag.find_cross_host_credential_links({
            "a.t.example": str(rd_a), "b.t.example": str(rd_b),
        })
        assert len(links) == 1
        assert links[0]["fingerprint"] == SHARED_FP
        hosts = {h["host"] for h in links[0]["hosts"]}
        assert hosts == {"a.t.example", "b.t.example"}

    def test_same_domain_family_no_shared_fingerprint_does_not_link(self, tmp_path):
        """api.foo.example and www.foo.example share only a domain suffix
        -- no matching secret value was ever observed on both -- so this
        must NOT be treated as linked. This is the explicit negative case
        the batch 2 spec requires."""
        rd_api = tmp_path / "api"
        rd_www = tmp_path / "www"
        _write_auth_model(rd_api, cookies=[
            {"name": "session_id", "value_fingerprint": "aaaaaaaaaaaaaaaa"},
        ])
        _write_auth_model(rd_www, cookies=[
            {"name": "session_id", "value_fingerprint": "bbbbbbbbbbbbbbbb"},
        ])
        links = ag.find_cross_host_credential_links({
            "api.foo.example": str(rd_api), "www.foo.example": str(rd_www),
        })
        assert links == []

    def test_fingerprint_on_only_one_host_does_not_link(self, tmp_path):
        rd_a = tmp_path / "a"
        rd_b = tmp_path / "b"
        _write_auth_model(rd_a, cookies=[{"name": "s", "value_fingerprint": SHARED_FP}])
        _write_auth_model(rd_b, cookies=[])  # host b never observed this fingerprint at all
        links = ag.find_cross_host_credential_links({
            "a.t.example": str(rd_a), "b.t.example": str(rd_b),
        })
        assert links == []

    def test_header_fingerprint_from_api_calls_json_links(self, tmp_path):
        rd_a = tmp_path / "a"
        rd_b = tmp_path / "b"
        _write_api_calls(rd_a, calls=[
            {"url": "https://a.t.example/api/x",
             "request_headers_auth_fingerprint": {"authorization": SHARED_FP}},
        ])
        _write_api_calls(rd_b, calls=[
            {"url": "https://b.t.example/api/y",
             "request_headers_auth_fingerprint": {"authorization": SHARED_FP}},
        ])
        links = ag.find_cross_host_credential_links({
            "a.t.example": str(rd_a), "b.t.example": str(rd_b),
        })
        assert len(links) == 1
        kinds = {h["kind"] for h in links[0]["hosts"]}
        assert kinds == {"header"}

    def test_missing_recon_dir_is_best_effort_not_a_crash(self, tmp_path):
        links = ag.find_cross_host_credential_links({
            "a.t.example": str(tmp_path / "nonexistent-a"),
            "b.t.example": str(tmp_path / "nonexistent-b"),
        })
        assert links == []


class TestAddCrossHostEdges:
    """add_cross_host_edges() — graph-level bridging, provenance, and the
    reused CONTRADICTORY EVIDENCE check applied per-host."""

    def _graph_with_host_b_endpoint(self):
        g = ag.Graph()
        g.add_node(_node("asset:t.example", "Asset", "t.example"))
        g.add_node(_node("lead:host-b-1", "Endpoint", "https://b.t.example/api/admin",
                          vuln_class="auth-bypass"))
        g.add_node(_node("impact:test", "Impact", "Admin Panel Takeover"))
        g.add_edge(_edge("lead:host-b-1", "impact:test", "impacts", 0.7))
        return g

    def test_positive_cross_host_path_reachable_only_via_shared_fingerprint(self, tmp_path):
        rd_a = tmp_path / "a"
        rd_b = tmp_path / "b"
        _write_auth_model(rd_a, cookies=[{"name": "sid", "value_fingerprint": SHARED_FP}])
        _write_auth_model(rd_b, cookies=[{"name": "sid", "value_fingerprint": SHARED_FP}])

        g = self._graph_with_host_b_endpoint()
        added = ag.add_cross_host_edges(g, {"a.t.example": str(rd_a), "b.t.example": str(rd_b)})
        assert added > 0

        xhost_node_id = f"credential:xhost:{SHARED_FP}"
        assert xhost_node_id in g.nodes
        xhost_node = g.nodes[xhost_node_id]
        assert xhost_node.type == "Credential"
        # PROVENANCE: origin references both hosts + the artifact + the fingerprint
        assert "a.t.example" in xhost_node.origin_source
        assert "b.t.example" in xhost_node.origin_source
        assert SHARED_FP in xhost_node.id
        assert SHARED_FP in xhost_node.confidence_source

        grants = [e for e in g.edges if e.from_id == xhost_node_id and e.to_id == "lead:host-b-1"]
        assert grants and grants[0].edge_type == "grants"

        # a full Credential -> Endpoint -> Impact path now exists, crossing hosts
        paths = ag.find_paths(g)
        crossing = [p for p in paths if p.node_ids[0] == xhost_node_id]
        assert crossing, "expected a path starting at the shared cross-host credential node"
        assert crossing[0].node_ids[-1] == "impact:test"

    def test_negative_no_shared_fingerprint_produces_no_cross_host_path(self, tmp_path):
        """api.foo.example and www.foo.example sharing only a domain suffix
        (no matching value_fingerprint) must NOT chain — explicit negative
        test at the graph level, matching TestCrossHostFingerprintLinking's
        link-level negative test."""
        rd_api = tmp_path / "api"
        rd_www = tmp_path / "www"
        _write_auth_model(rd_api, cookies=[{"name": "sid", "value_fingerprint": "aaaaaaaaaaaaaaaa"}])
        _write_auth_model(rd_www, cookies=[{"name": "sid", "value_fingerprint": "bbbbbbbbbbbbbbbb"}])

        g = ag.Graph()
        g.add_node(_node("asset:t.example", "Asset", "t.example"))
        g.add_node(_node("lead:host-www-1", "Endpoint", "https://www.foo.example/api/admin"))
        g.add_node(_node("impact:test", "Impact", "Admin Panel Takeover"))
        g.add_edge(_edge("lead:host-www-1", "impact:test", "impacts", 0.7))
        n_nodes_before = len(g.nodes)
        n_edges_before = len(g.edges)

        added = ag.add_cross_host_edges(g, {
            "api.foo.example": str(rd_api), "www.foo.example": str(rd_www),
        })
        assert added == 0
        assert len(g.nodes) == n_nodes_before
        assert len(g.edges) == n_edges_before
        assert not [n for n in g.nodes.values() if n.id.startswith("credential:xhost:")]
        # and no path can possibly start at a cross-host node since none exists
        assert not [p for p in ag.find_paths(g) if p.node_ids[0].startswith("credential:xhost:")]

    def test_contradiction_check_applies_per_host_to_grants_edge(self, tmp_path):
        rd_a = tmp_path / "a"
        rd_b = tmp_path / "b"
        _write_auth_model(rd_a, cookies=[{"name": "sid", "value_fingerprint": SHARED_FP}])
        _write_auth_model(rd_b, cookies=[{"name": "sid", "value_fingerprint": SHARED_FP}])
        # host b's own browser recon observed a 403 on the exact endpoint the
        # cross-host grants edge would otherwise claim access to.
        _write_api_calls(rd_b, calls=[
            {"url": "https://b.t.example/api/admin", "response_status": 403},
        ])

        g = self._graph_with_host_b_endpoint()
        ag.add_cross_host_edges(g, {"a.t.example": str(rd_a), "b.t.example": str(rd_b)})

        xhost_node_id = f"credential:xhost:{SHARED_FP}"
        grants = [e for e in g.edges if e.from_id == xhost_node_id and e.to_id == "lead:host-b-1"]
        assert grants
        assert grants[0].contradiction is not None
        assert grants[0].confidence < ag.CROSS_HOST_GRANT_BASE_CONFIDENCE

    def test_no_asset_node_is_best_effort_zero(self):
        g = ag.Graph()
        g.add_node(_node("lead:x", "Endpoint", "https://b.t.example/x"))
        added = ag.add_cross_host_edges(g, {"a.t.example": "/nonexistent", "b.t.example": "/nonexistent2"})
        assert added == 0

    def test_build_capability_graph_wires_cross_host_when_provided(self, tmp_path):
        """Least-invasive integration point: build_capability_graph()'s new
        optional cross_host_recon_dirs param produces the same bridging as
        calling add_cross_host_edges() directly, and omitting it (batch 1
        callers, every existing test) leaves behavior unchanged."""
        rd_a = tmp_path / "a"
        rd_b = tmp_path / "b"
        _write_auth_model(rd_a, cookies=[{"name": "sid", "value_fingerprint": SHARED_FP}])
        _write_auth_model(rd_b, cookies=[{"name": "sid", "value_fingerprint": SHARED_FP}])
        leads = [_lead("lb-1", "hunt-idor", "https://b.t.example/api/users?id=1")]

        g_no_cross_host = ag.build_capability_graph("t.example", recon_dir=str(rd_b), leads=leads)
        assert not [n for n in g_no_cross_host.nodes.values() if n.id.startswith("credential:xhost:")]

        g_with_cross_host = ag.build_capability_graph(
            "t.example", recon_dir=str(rd_b), leads=leads,
            cross_host_recon_dirs={"a.t.example": str(rd_a), "b.t.example": str(rd_b)},
        )
        assert any(n.id.startswith("credential:xhost:") for n in g_with_cross_host.nodes.values())
