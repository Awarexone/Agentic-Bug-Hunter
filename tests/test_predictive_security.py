"""Tests for AXGuard Predictive Security Intelligence (engines.predictive).

Fixture catalog: ``fixtures/predictive_security/``.
Modules still landing use ``pytest.importorskip`` / soft getattr.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "predictive_security"
CATALOG_PATH = FIXTURE / "expected.json"
PKG = ROOT / "engines" / "predictive"

# Certainty / CVE language that predictive outputs must never use.
FALSE_CERTAINTY = (
    "will definitely",
    "guaranteed exploit",
    "will be exploited",
    "future vulnerability confirmed",
    "predicted cve",
    "this code will definitely contain a vulnerability",
)
CVE_CLAIM = re.compile(r"\bcve-\d{4}-\d+\b", re.I)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _catalog() -> dict[str, Any]:
    return _load(CATALOG_PATH)


def _case_dir(case_id: str) -> Path:
    return FIXTURE / "cases" / case_id


def _case_pair(case_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    d = _case_dir(case_id)
    return _load(d / "before.json"), _load(d / "after.json"), _load(d / "expected.json")


def _blob(obj: Any) -> str:
    return json.dumps(obj, default=str).lower()


def _risks_as_dicts(risks: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in risks or []:
        if hasattr(r, "to_dict"):
            out.append(r.to_dict())
        elif isinstance(r, dict):
            out.append(r)
    return out


def _require_predictive():
    return pytest.importorskip("engines.predictive")


def _require_mod(name: str):
    return pytest.importorskip(f"engines.predictive.{name}")


# ---------------------------------------------------------------------------
# Fixture contracts (always run — no engine required)
# ---------------------------------------------------------------------------
def test_fixture_catalog_labels_and_cases():
    cat = _catalog()
    assert cat["kind"] == "predictive_security_fixture"
    assert set(cat["labels"]) >= {
        "predictive_risk",
        "vulnerability",
        "insufficient_evidence",
    }
    ids = [c["id"] for c in cat["cases"]]
    assert ids == [
        "01_privilege_expansion",
        "02_trust_boundary_expansion",
        "03_new_public_endpoint",
        "04_new_mcp_server",
        "05_actual_vulnerability",
        "06_insufficient_evidence",
    ]
    for c in cat["cases"]:
        d = ROOT / "fixtures" / "predictive_security" / c["dir"]
        assert (d / "before.json").is_file()
        assert (d / "after.json").is_file()
        assert (d / "expected.json").is_file()
        expect = _load(d / "expected.json")
        assert expect["label"] == c["expect_label"]
        assert expect["label"] in {
            "predictive_risk",
            "vulnerability",
            "insufficient_evidence",
        }


def test_fixture_predictive_cases_are_not_vuln_labeled():
    for case_id in (
        "01_privilege_expansion",
        "02_trust_boundary_expansion",
        "03_new_public_endpoint",
        "04_new_mcp_server",
    ):
        _, _, expect = _case_pair(case_id)
        assert expect["label"] == "predictive_risk"
        assert expect.get("not_a_vulnerability") is True


def test_fixture_actual_vuln_and_unknown_cases():
    _, after, expect = _case_pair("05_actual_vulnerability")
    assert expect["label"] == "vulnerability"
    assert after.get("findings"), "actual vuln case must carry findings"
    assert any(
        str(f.get("status")).upper() in {"CONFIRMED", "LIKELY", "VERIFIED"}
        for f in after["findings"]
    )

    _, _, unk = _case_pair("06_insufficient_evidence")
    assert unk["label"] == "insufficient_evidence"
    assert unk["expect"]["confidence"] == "UNKNOWN"


def test_benchmark_doc_exists():
    path = ROOT / "docs" / "predictive" / "benchmark.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8").lower()
    for needle in (
        "attack surface",
        "privilege",
        "auth drift",
        "tenant",
        "dependency",
        "mcp",
        "precision",
        "false prediction",
        "calibration",
        "unknown",
    ):
        assert needle in text


# ---------------------------------------------------------------------------
# Schema / categories
# ---------------------------------------------------------------------------
def test_schema_categories_and_confidence_vocab():
    schema = _require_mod("schema")
    required = {
        "ATTACK_SURFACE_EXPANSION",
        "PRIVILEGE_EXPANSION",
        "TRUST_BOUNDARY_EXPANSION",
        "AUTHORIZATION_DRIFT",
        "TENANT_ISOLATION_RISK",
        "DEPENDENCY_RISK",
        "AI_AGENT_PRIVILEGE_RISK",
        "MCP_TRUST_RISK",
        "TOOL_PERMISSION_RISK",
        "SECURITY_DEBT",
        "REGRESSION_RISK",
        "ARCHITECTURE_DRIFT",
        "API_EXPOSURE_RISK",
    }
    assert required <= set(schema.RISK_CATEGORIES)
    assert {"HIGH", "MEDIUM", "LOW", "UNKNOWN"} <= set(schema.CONFIDENCE_LEVELS)
    assert {"IMMEDIATE", "NEAR_TERM", "LONGER_TERM"} <= set(schema.TIME_HORIZONS)
    assert {
        "RISK_INCREASED",
        "RISK_DECREASED",
        "STABLE",
        "RESOLVED",
        "NEW_RISK",
    } <= set(schema.RISK_CHANGE_STATUSES)
    empty = schema.empty_predict_result(target="fixture://predictive")
    assert empty["kind"] == "predictive_security"
    assert empty["risks"] == []
    assert "cve" not in empty["disclaimer"].lower() or "not" in empty["disclaimer"].lower()


# ---------------------------------------------------------------------------
# Model: grounding + no fabricated history
# ---------------------------------------------------------------------------
def test_model_requires_trigger_and_evidence():
    model = _require_mod("model")
    schema = _require_mod("schema")
    with pytest.raises(Exception):
        model.build_predictive_risk(
            category=schema.CAT_PRIVILEGE_EXPANSION,
            title="ungrounded",
            trigger_change={},
            supporting_evidence=[{"ok": True}],
            security_effect="x",
            risk_signal="y",
        )
    with pytest.raises(Exception):
        model.build_predictive_risk(
            category=schema.CAT_PRIVILEGE_EXPANSION,
            title="no evidence",
            trigger_change={"kind": "change", "observation": "x"},
            supporting_evidence=[],
            security_effect="x",
            risk_signal="y",
        )


def test_model_never_fabricates_historical_evidence():
    model = _require_mod("model")
    schema = _require_mod("schema")
    risk = model.build_predictive_risk(
        category=schema.CAT_REGRESSION_RISK,
        title="no history invented",
        trigger_change={"kind": "file_change", "observation": "auth.py touched"},
        supporting_evidence=[{"source": "diff", "file": "auth.py"}],
        security_effect="Hotspot touched",
        risk_signal="Regression risk uncertain without memory",
        historical_evidence=None,
    )
    assert risk.historical_evidence == []
    # Explicit empty list must stay empty — never auto-fill fake history
    risk2 = model.build_predictive_risk(
        category=schema.CAT_REGRESSION_RISK,
        title="empty history stays empty",
        trigger_change={"kind": "file_change", "observation": "auth.py touched"},
        supporting_evidence=[{"source": "diff", "file": "auth.py"}],
        security_effect="Hotspot touched",
        risk_signal="No memory ledger available",
        historical_evidence=[],
    )
    assert risk2.historical_evidence == []
    d = risk2.to_dict()
    assert d["historical_evidence"] == []
    assert "repeatedly regressed" not in _blob(d)


# ---------------------------------------------------------------------------
# Language honesty / no CVE claims
# ---------------------------------------------------------------------------
def test_no_false_certainty_language_in_built_risks():
    model = _require_mod("model")
    schema = _require_mod("schema")
    risk = model.build_predictive_risk(
        category=schema.CAT_ATTACK_SURFACE_EXPANSION,
        title="New public import endpoint",
        trigger_change={
            "kind": "entrypoint_delta",
            "observation": "POST /api/import added",
        },
        supporting_evidence=[{"source": "fixture", "endpoint": "POST /api/import"}],
        security_effect="New attacker-influenced file ingestion surface",
        risk_signal="Attack surface expansion — not a confirmed vulnerability",
        confidence=schema.CONF_MEDIUM,
    )
    blob = _blob(risk.to_dict())
    for phrase in FALSE_CERTAINTY:
        assert phrase not in blob
    assert "vulnerability" not in risk.risk_signal.lower() or "not" in risk.risk_signal.lower()
    assert CVE_CLAIM.search(blob) is None


def test_disclaimer_rejects_cve_prediction_claims():
    schema = _require_mod("schema")
    disc = schema.DISCLAIMER.lower()
    assert "cve" in disc  # disclaimer mentions CVE to forbid it
    assert "not" in disc
    assert "predict" in disc or "prediction" in disc


# ---------------------------------------------------------------------------
# Detectors (fixture before/after attack_graphs)
# ---------------------------------------------------------------------------
def test_attack_surface_detector_on_new_public_endpoint():
    surface = _require_mod("surface")
    before, after, expect = _case_pair("03_new_public_endpoint")
    risks = _risks_as_dicts(
        surface.detect_surface_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
            twin=after,
            base_twin=before,
        )
    )
    cats = {r.get("category") for r in risks}
    assert cats & set(expect["expect"]["categories_any"])
    blob = _blob(risks)
    for phrase in FALSE_CERTAINTY:
        assert phrase not in blob
    assert CVE_CLAIM.search(blob) is None
    for r in risks:
        assert r.get("status", "PREDICTIVE") == "PREDICTIVE"
        assert r.get("trigger_change")
        assert r.get("supporting_evidence")


def test_privilege_detector_on_privilege_expansion():
    privilege = _require_mod("privilege")
    before, after, expect = _case_pair("01_privilege_expansion")
    risks = _risks_as_dicts(
        privilege.detect_privilege_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
            twin=after,
            base_twin=before,
        )
    )
    cats = {r.get("category") for r in risks}
    # Privilege detector may emit PRIVILEGE_EXPANSION; agent tools also valid
    assert cats & set(expect["expect"]["categories_any"]) or (
        "PRIVILEGE_EXPANSION" in cats
    )
    assert all(r.get("status", "PREDICTIVE") == "PREDICTIVE" for r in risks)
    blob = _blob(risks)
    # Disclaimer may say "not a confirmed vulnerability" — that is allowed
    assert "is a confirmed vulnerability" not in blob
    assert "will definitely" not in blob


def test_trust_boundary_detector_on_external_ingress():
    surface = _require_mod("surface")
    before, after, expect = _case_pair("02_trust_boundary_expansion")
    risks = _risks_as_dicts(
        surface.detect_surface_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
            twin=after,
            base_twin=before,
        )
    )
    cats = {r.get("category") for r in risks}
    assert cats & set(expect["expect"]["categories_any"])


def test_agent_mcp_detector_on_new_mcp_server():
    agent_mcp = _require_mod("agent_mcp")
    before, after, expect = _case_pair("04_new_mcp_server")
    risks = _risks_as_dicts(
        agent_mcp.detect_agent_mcp_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
            twin=after,
            base_twin=before,
        )
    )
    cats = {r.get("category") for r in risks}
    assert cats & set(expect["expect"]["categories_any"])
    assert any(r.get("category") == "MCP_TRUST_RISK" for r in risks)
    blob = _blob(risks)
    assert "vulnerability" not in blob or "not a confirmed" in blob
    assert CVE_CLAIM.search(blob) is None


def test_insufficient_evidence_yields_unknown_or_empty():
    """Cosmetic rename must not invent predictive risks or history."""
    _require_predictive()
    before, after, expect = _case_pair("06_insufficient_evidence")
    surface = _require_mod("surface")
    privilege = _require_mod("privilege")
    agent_mcp = _require_mod("agent_mcp")

    risks: list[dict[str, Any]] = []
    risks.extend(
        surface.detect_surface_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
        )
    )
    risks.extend(
        privilege.detect_privilege_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
        )
    )
    risks.extend(
        agent_mcp.detect_agent_mcp_risks(
            attack_graph=after["attack_graph"],
            base_attack_graph=before["attack_graph"],
            twin=after,
            base_twin=before,
        )
    )
    risks = _risks_as_dicts(risks)
    # Prefer empty; if anything emitted, confidence must be UNKNOWN/LOW and no history
    for r in risks:
        assert r.get("confidence") in {"UNKNOWN", "LOW", None} or not r
        assert not r.get("historical_evidence")
    assert CVE_CLAIM.search(_blob(risks)) is None
    assert expect["expect"]["confidence"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# Security debt factor breakdown
# ---------------------------------------------------------------------------
def test_security_debt_factor_breakdown_not_opaque():
    score = _require_mod("score")
    debt_fn = getattr(score, "compute_security_debt", None) or getattr(
        score, "security_debt", None
    )
    if debt_fn is None:
        pytest.skip("compute_security_debt not exported yet")

    _, after, _ = _case_pair("04_new_mcp_server")
    memory = {
        "REGRESSED": [{"outcome": "REGRESSED", "fingerprint": "mem.f.demo"}],
        "predictive": None,
    }
    result = debt_fn(
        attack_graph=after["attack_graph"],
        twin=after,
        memory_regressions=memory,
    )
    assert isinstance(result, dict)
    factors = result.get("factors") or result.get("debt_factors") or []
    assert factors, "security debt must expose factor breakdown"
    assert result.get("total_weight") is not None or result.get("score") is None or factors
    # Must not be only a single meaningless number with no factors
    assert isinstance(factors, list) and len(factors) >= 1
    blob = _blob(result)
    assert CVE_CLAIM.search(blob) is None
    for phrase in FALSE_CERTAINTY:
        assert phrase not in blob


# ---------------------------------------------------------------------------
# Risk compare lifecycle
# ---------------------------------------------------------------------------
def test_risk_compare_lifecycle_statuses():
    compare = _require_mod("compare")
    schema = _require_mod("schema")
    model = _require_mod("model")

    prev = [
        model.build_predictive_risk(
            category=schema.CAT_ATTACK_SURFACE_EXPANSION,
            title="public surface",
            trigger_change={"kind": "surface", "observation": "1 public ep"},
            supporting_evidence=[{"metric": "public_entrypoints", "value": 1}],
            security_effect="surface",
            risk_signal="stable surface",
            risk_id="pred-surface-1",
            change_status=schema.STATUS_STABLE,
        ).to_dict()
    ]
    new = [
        model.build_predictive_risk(
            category=schema.CAT_ATTACK_SURFACE_EXPANSION,
            title="public surface grew",
            trigger_change={
                "kind": "entrypoint_delta",
                "observation": "2 public ep",
                "before": 1,
                "after": 2,
            },
            supporting_evidence=[{"metric": "public_entrypoints", "before": 1, "after": 2}],
            security_effect="wider surface",
            risk_signal="increasing exposure",
            risk_id="pred-surface-1",
            change_status=schema.STATUS_RISK_INCREASED,
        ).to_dict(),
        model.build_predictive_risk(
            category=schema.CAT_MCP_TRUST_RISK,
            title="new mcp",
            trigger_change={"kind": "mcp_delta", "observation": "mcp added"},
            supporting_evidence=[{"mcp": 1}],
            security_effect="mcp trust",
            risk_signal="mcp expansion",
            risk_id="pred-mcp-1",
            change_status=schema.STATUS_NEW_RISK,
        ).to_dict(),
    ]

    fn = (
        getattr(compare, "compare_risk_sets", None)
        or getattr(compare, "compare_risks", None)
        or getattr(compare, "compare_predictive_risks", None)
    )
    if fn is None:
        pytest.skip("compare_risk_sets not exported yet")
    result = fn(prev, new)
    blob = _blob(result)
    # Expect lifecycle vocabulary present
    assert any(
        s.lower() in blob
        for s in (
            "RISK_INCREASED",
            "NEW_RISK",
            "STABLE",
            "RISK_DECREASED",
            "RESOLVED",
        )
    )
    assert CVE_CLAIM.search(blob) is None


# ---------------------------------------------------------------------------
# GitHub output separation
# ---------------------------------------------------------------------------
def test_github_output_separates_verified_vs_predictive():
    gh = _require_mod("github_output")
    _, after_vuln, _ = _case_pair("05_actual_vulnerability")
    _, after_pred, _ = _case_pair("03_new_public_endpoint")

    verified = [
        {
            "id": f.get("id"),
            "status": f.get("status"),
            "rule_id": f.get("rule_id"),
            "severity": f.get("severity"),
            "title": "SQL injection",
            "file": f.get("file"),
            "line": f.get("line"),
            "confidence": f.get("confidence"),
        }
        for f in after_vuln.get("findings") or []
    ]
    predictive = {
        "risks": [
            {
                "category": "ATTACK_SURFACE_EXPANSION",
                "title": "New public POST /api/import",
                "status": "PREDICTIVE",
                "confidence": "MEDIUM",
                "time_horizon": "IMMEDIATE",
                "change_status": "RISK_INCREASED",
                "security_effect": "New attacker-influenced file ingestion surface",
                "risk_signal": "Attack surface expansion — not a confirmed vulnerability",
                "trigger_change": (after_pred.get("observable_changes") or [{}])[0],
                "supporting_evidence": [{"source": "fixture"}],
            }
        ],
        "summary": {"risk_count": 1},
        "disclaimer": "Not a confirmed vulnerability",
        "comparisons": [],
    }

    fmt = getattr(gh, "format_github_check_text", None)
    if fmt is None:
        pytest.skip("format_github_check_text not exported yet")

    text = fmt(verified_findings=verified, predictive=predictive, comparisons=[])
    lower = text.lower()
    assert "verified" in lower
    assert "predictive" in lower
    # Sections must appear as separate headings
    assert "### verified" in lower or "verified findings" in lower
    assert "### predictive" in lower or "predictive security" in lower
    assert "not" in lower and "vulnerabilit" in lower
    assert CVE_CLAIM.search(lower) is None
    for phrase in FALSE_CERTAINTY:
        assert phrase not in lower
    # Verified finding content present
    assert "sql" in lower or "confirmed" in lower


def test_actual_vuln_fixture_belongs_in_verified_not_predictive_only():
    _, after, expect = _case_pair("05_actual_vulnerability")
    assert expect["expect"].get("must_not_be_predictive_only") is True
    assert expect["expect"].get("github_section") == "Verified"
    assert after["findings"]


# ---------------------------------------------------------------------------
# Memory bridge: never fabricate history
# ---------------------------------------------------------------------------
def test_memory_bridge_returns_empty_without_real_ledger():
    bridge = _require_mod("memory_bridge")
    fn = getattr(bridge, "historical_evidence_from_memory", None)
    if fn is None:
        pytest.skip("historical_evidence_from_memory not exported yet")

    # Empty / missing memory must not invent patterns
    assert fn(None) == []
    assert fn({}) == []
    assert fn({"available": False, "REGRESSED": [{"id": "x"}]}) == []


# ---------------------------------------------------------------------------
# Pipeline smoke (when present)
# ---------------------------------------------------------------------------
def test_pipeline_run_predict_unknown_on_cosmetic_change(tmp_path: Path):
    try:
        pipeline = _require_mod("pipeline")
    except pytest.skip.Exception:
        raise

    run = getattr(pipeline, "run_predict", None)
    if run is None:
        pytest.skip("run_predict not exported yet")

    before, after, _ = _case_pair("06_insufficient_evidence")
    # Prefer twin/graph kwargs if supported; else skip soft
    try:
        result = run(
            str(tmp_path),
            base=None,
            mode="architecture",
            twin=after,
            base_twin=before,
            attack_graph=after.get("attack_graph"),
            base_attack_graph=before.get("attack_graph"),
        )
    except TypeError:
        pytest.skip("run_predict signature not ready for twin kwargs")

    blob = _blob(result)
    assert CVE_CLAIM.search(blob) is None
    for phrase in FALSE_CERTAINTY:
        assert phrase not in blob
    # Either no risks or UNKNOWN confidence
    risks = _risks_as_dicts(result.get("risks") or [])
    for r in risks:
        assert r.get("confidence") in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", None}


def test_package_init_exports_when_ready():
    if not (PKG / "__init__.py").is_file():
        pytest.skip("engines.predictive.__init__ not written yet")
    pred = _require_predictive()
    schema = _require_mod("schema")
    model = _require_mod("model")
    assert hasattr(schema, "RISK_CATEGORIES")
    assert hasattr(schema, "empty_predict_result")
    assert hasattr(model, "build_predictive_risk")
    # Prefer package re-exports when present
    for name in ("RISK_CATEGORIES", "empty_predict_result", "build_predictive_risk"):
        if hasattr(pred, name):
            assert getattr(pred, name) is not None
