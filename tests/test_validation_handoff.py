"""End-to-end checks for scanner-confidence -> validation handoff."""

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATE_PATH = REPO_ROOT / "tools" / "validate.py"


def _load_validate():
    import importlib.util

    spec = importlib.util.spec_from_file_location("validate_handoff", VALIDATE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


validate = _load_validate()


def test_validation_json_marks_validated_finding(tmp_path):
    info = {
        "target": "target-program",
        "vuln_type": "IDOR",
        "endpoint": "/api/users/456",
        "impact": "victim PII read",
        "curl_poc": "curl -s https://target/api/users/456 -H 'Cookie: sess=ATTACKER'",
        "scanner_confidence": "confirmed",
        "scanner_summary": {"counts": {"confirmed": {"sqli": 1}}},
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "cvss_params": {"AV": "N"},
        "gate1_pass": True,
        "gate2_pass": True,
        "gate3_pass": True,
        "gate4_pass": True,
        "validation_status": "validated_finding",
    }
    gate_notes = {
        "gate1": {"rejection_reason": None},
        "gate2": {"rejection_reason": None},
        "gate3": {"rejection_reason": None},
        "gate4": {"rejection_reason": None},
    }

    path = validate.write_validation_json(str(tmp_path), info, gate_notes)
    payload = json.loads(Path(path).read_text())

    assert payload["status"] == "validated_finding"
    assert payload["scanner_confidence"] == "confirmed"
    assert payload["scanner_summary"]["counts"]["confirmed"]["sqli"] == 1
    assert payload["finding"]["curl_poc"]
    assert payload["rejection_reasons"] == []


def test_validation_json_marks_scanner_hit_with_reasons(tmp_path):
    info = {
        "target": "target-program",
        "vuln_type": "Open redirect",
        "endpoint": "/redirect",
        "impact": "redirect only",
        "curl_poc": "",
        "scanner_confidence": "possible",
        "cvss_score": 0.0,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        "cvss_params": {"AV": "N"},
        "gate1_pass": False,
        "gate2_pass": True,
        "gate3_pass": False,
        "gate4_pass": True,
        "validation_status": "scanner_hit",
    }
    gate_notes = {
        "gate1": {"rejection_reason": "not_reproducible"},
        "gate2": {"rejection_reason": None},
        "gate3": {"rejection_reason": "no_reproducible_impact"},
        "gate4": {"rejection_reason": None},
    }

    path = validate.write_validation_json(str(tmp_path), info, gate_notes)
    payload = json.loads(Path(path).read_text())

    assert payload["status"] == "scanner_hit"
    assert payload["scanner_confidence"] == "possible"
    assert payload["rejection_reasons"] == [
        "not_reproducible",
        "no_reproducible_impact",
    ]
    assert payload["curl_poc"] == ""


def test_report_skeleton_includes_validation_state():
    skeleton = validate.generate_report_skeleton({
        "target": "target-program",
        "vuln_type": "IDOR",
        "endpoint": "/api/users/456",
        "impact": "victim PII read",
        "scanner_confidence": "confirmed",
        "validation_status": "validated_finding",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "cvss_params": {"AV": "N"},
    })

    assert "Scanner Confidence:" in skeleton
    assert "Validation Status:" in skeleton
    assert "confirmed" in skeleton
    assert "validated_finding" in skeleton


def test_validate_cli_can_load_scanner_summary(tmp_path, monkeypatch):
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "target": "target-program",
                "counts": {
                    "confirmed": {"sqli": 1, "rce": 0, "ssti": 0, "saml_sig_strip": 0},
                    "possible": {"sqli_delay": 2, "xss_dalfox": 3, "mfa_rate_limit": 0, "upload_file_only": 0, "mfa_workflow_skip": 0},
                    "informational": {"upload_paths": 4, "saml_endpoints": 1, "saml_metadata": 0, "cms_detected": 0, "mfa_response_manip": 0},
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = validate.load_json_file(str(summary_path))
    assert loaded["counts"]["confirmed"]["sqli"] == 1
