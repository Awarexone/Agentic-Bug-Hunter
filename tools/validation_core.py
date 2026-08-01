"""
validation_core.py — pure validation-gate logic + CVSS 4.0 scoring.

Extracted from tools/validate.py so the 4 validation gates (Is it real? / Is
it in scope? / Is it exploitable? / Is it a dup?) and the CVSS 4.0 calculator
can run headless: no input(), no prompts, no network, dict in -> dict out.

This is what makes the autonomous path (agent.py / autopilot) able to run a
real validation gate instead of having none at all — tools/validate.py stays
the interactive human wrapper around these same functions, so there is
exactly one implementation of each gate's pass/fail logic.

Pure library + thin CLI convention, same as memory/vuln_intelligence.py and
memory/finding_score.py — this module has no CLI of its own; tools/validate.py
exposes it via `--json --non-interactive --input finding.json`.
"""

from __future__ import annotations


class ValidationInputError(ValueError):
    """Raised when a gate/CVSS input dict is missing a field or has the wrong type."""


# ─── shared helpers ────────────────────────────────────────────────────────

# Auth-related vuln types that require session identity checks before Gate 1 can pass.
_AUTH_KEYWORDS = {
    "idor", "ato", "auth", "session", "login", "privilege", "account",
    "bypass", "takeover", "permission", "access control", "broken auth",
    "bac", "broken access", "insecure direct",
}


def is_auth_related(vuln_type: str) -> bool:
    vt = (vuln_type or "").lower()
    return any(k in vt for k in _AUTH_KEYWORDS)


def _require_dict(data) -> dict:
    if not isinstance(data, dict):
        raise ValidationInputError(f"input must be a JSON object, got {type(data).__name__}")
    return data


def _require_bool(data: dict, key: str) -> bool:
    if key not in data:
        raise ValidationInputError(f"missing required field: {key}")
    val = data[key]
    if not isinstance(val, bool):
        raise ValidationInputError(f"field '{key}' must be a boolean, got {type(val).__name__}")
    return val


def _optional_str(data: dict, key: str, default: str = "") -> str:
    val = data.get(key, default)
    if val is None:
        return default
    if not isinstance(val, str):
        raise ValidationInputError(f"field '{key}' must be a string, got {type(val).__name__}")
    return val


def _optional_list(data: dict, key: str, default: list | None = None) -> list:
    val = data.get(key, default if default is not None else [])
    if not isinstance(val, list):
        raise ValidationInputError(f"field '{key}' must be a list, got {type(val).__name__}")
    return val


# ─── Gate 1 — Is It Real? ──────────────────────────────────────────────────

def gate1_is_real(data: dict) -> dict:
    """Evaluate Gate 1 (reproducibility + identity check for auth-related bugs).

    Required keys (all bool): repro_3_3, works_without_proxy, no_special_state,
    not_documented_behavior.

    Optional: vuln_type (str) — when it matches an auth-related keyword
    (idor, ato, auth, takeover, ...), three additional bool keys become
    required: cross_account_tested, fresh_session_tested, anon_vs_auth_delta.

    Returns {"passed": bool, "notes": {...}} — notes shape matches the
    interactive gate's return value exactly (identity keys are entirely
    absent from notes when the vuln type isn't auth-related).
    """
    data = _require_dict(data)
    vuln_type = _optional_str(data, "vuln_type")

    repro3   = _require_bool(data, "repro_3_3")
    no_burp  = _require_bool(data, "works_without_proxy")
    no_state = _require_bool(data, "no_special_state")
    rtfm     = _require_bool(data, "not_documented_behavior")

    identity_ok = True
    identity_notes: dict = {}
    if is_auth_related(vuln_type):
        cross_account = _require_bool(data, "cross_account_tested")
        fresh_session = _require_bool(data, "fresh_session_tested")
        anon_delta    = _require_bool(data, "anon_vs_auth_delta")
        identity_ok   = cross_account and fresh_session and anon_delta
        identity_notes = {
            "cross_account_tested": cross_account,
            "fresh_session_tested": fresh_session,
            "anon_vs_auth_delta":   anon_delta,
            "identity_required":    True,
        }

    passed = repro3 and no_burp and no_state and rtfm and identity_ok

    rejection_reason = None
    if not passed:
        rejection_reason = (
            "identity_not_proven"
            if (repro3 and no_burp and no_state and rtfm and not identity_ok)
            else "not_reproducible"
        )

    notes = {
        "repro_3_3":               repro3,
        "works_without_proxy":     no_burp,
        "no_special_state":        no_state,
        "not_documented_behavior": rtfm,
        **identity_notes,
        "rejection_reason":        rejection_reason,
    }
    return {"passed": passed, "notes": notes}


# ─── Gate 2 — Is It In Scope? ──────────────────────────────────────────────

def gate2_in_scope(data: dict) -> dict:
    """Evaluate Gate 2 (scope). Required bool keys: asset_in_scope, not_excluded, version_ok."""
    data = _require_dict(data)
    asset_in_scope = _require_bool(data, "asset_in_scope")
    not_excluded   = _require_bool(data, "not_excluded")
    version_ok     = _require_bool(data, "version_ok")

    passed = asset_in_scope and not_excluded and version_ok
    notes = {
        "asset_in_scope":   asset_in_scope,
        "not_excluded":     not_excluded,
        "version_ok":       version_ok,
        "rejection_reason": "out_of_scope" if not passed else None,
    }
    return {"passed": passed, "notes": notes}


# ─── Gate 3 — Is It Exploitable? ───────────────────────────────────────────

def gate3_exploitable(data: dict) -> dict:
    """Evaluate Gate 3 (concrete impact + working PoC).

    Required bool keys: concrete_impact, no_unrealistic_preconditions.
    Optional str keys: curl_poc, impact_description. A blank curl_poc (or the
    literal "skip") auto-fails the gate — no proof, no submit.
    """
    data = _require_dict(data)
    concrete_impact = _require_bool(data, "concrete_impact")
    no_unrealistic  = _require_bool(data, "no_unrealistic_preconditions")
    curl_poc        = _optional_str(data, "curl_poc").strip()
    impact_desc     = _optional_str(data, "impact_description")

    curl_valid = bool(curl_poc) and curl_poc.lower() != "skip"

    passed = concrete_impact and no_unrealistic and curl_valid

    rejection_reason = None
    if not passed:
        if not curl_valid:
            rejection_reason = "no_reproducible_impact"
        elif not concrete_impact:
            rejection_reason = "no_concrete_impact"
        elif not no_unrealistic:
            rejection_reason = "unrealistic_privileges"
        else:
            rejection_reason = "no_reproducible_impact"

    notes = {
        "concrete_impact":              concrete_impact,
        "no_unrealistic_preconditions": no_unrealistic,
        "curl_poc":                     curl_poc if curl_valid else "",
        "has_proof":                    curl_valid,
        "impact_description":           impact_desc,
        "rejection_reason":             rejection_reason,
    }
    return {"passed": passed, "notes": notes}


# ─── Gate 4 — Is It a Dup? ─────────────────────────────────────────────────

def gate4_not_dup(data: dict) -> dict:
    """Evaluate Gate 4 (duplicate/disclosure check).

    Required bool keys: not_in_h1_disclosed, not_in_github_issues, checked_git_history.
    Optional: h1_similar_reports (list of report titles the caller already
    looked up — this function does not perform any network lookups itself).
    """
    data = _require_dict(data)
    not_disclosed   = _require_bool(data, "not_in_h1_disclosed")
    not_in_issues   = _require_bool(data, "not_in_github_issues")
    checked_history = _require_bool(data, "checked_git_history")
    h1_similar      = _optional_list(data, "h1_similar_reports")

    passed = not_disclosed and not_in_issues and checked_history
    notes = {
        "not_in_h1_disclosed":  not_disclosed,
        "not_in_github_issues": not_in_issues,
        "checked_git_history":  checked_history,
        "h1_similar_reports":   h1_similar,
        "rejection_reason":     "duplicate_or_already_disclosed" if not passed else None,
    }
    return {"passed": passed, "notes": notes}


# ─── CVSS 4.0 scoring ─────────────────────────────────────────────────────
# Implements the CVSS 4.0 macro-vector approach from FIRST.org.
# For authoritative scores verify at: https://www.first.org/cvss/calculator/4.0

def _eq1(av: str, pr: str, ui: str) -> int:
    """EQ1: Attack Vector / Privileges Required / User Interaction (0=highest severity)."""
    if av == "N" and (pr == "N" or ui == "N"):
        return 0
    if av == "N" or pr == "N" or ui == "N":
        return 1
    return 2


def _eq2(ac: str, at: str) -> int:
    """EQ2: Attack Complexity / Attack Requirements."""
    return 0 if (ac == "L" and at == "N") else 1


def _eq3(vc: str, vi: str, va: str) -> int:
    """EQ3: Vulnerable System CIA impact."""
    if vc == "H" and vi == "H":
        return 0
    if vc == "H" or vi == "H" or va == "H":
        return 1
    return 2


def _eq4(sc: str, si: str, sa: str) -> int:
    """EQ4: Subsequent System impact (Safety > High > Low/None)."""
    if si == "S" or sa == "S":
        return 0
    if sc == "H" or si == "H" or sa == "H":
        return 1
    return 2


# CVSS 4.0 base score lookup by macro vector (eq1, eq2, eq3, eq4).
# EQ5=0 (E=Active, default for base metrics).
# EQ6 is derived from EQ3 with default CR=IR=AR=High.
# Values approximate FIRST.org CVSS 4.0 specification.
# Verify exact scores at: https://www.first.org/cvss/calculator/4.0
#
# eq1: 0=Network+(no-auth or no-UI), 1=partial advantage, 2=local/physical/high-priv+UI
# eq2: 0=Low-complexity+no-prereqs, 1=otherwise
# eq3: 0=VC+VI both High, 1=partial High, 2=no High CIA on vulnerable system
# eq4: 0=Safety impact, 1=High subsequent-system impact, 2=no subsequent impact
_CVSS40_TABLE: dict[tuple[int, int, int, int], float] = {
    # eq1=0 (widest attack reach: network + no-auth OR no-UI)
    (0, 0, 0, 0): 10.0, (0, 0, 0, 1): 10.0, (0, 0, 0, 2): 9.3,
    (0, 0, 1, 0): 9.5,  (0, 0, 1, 1): 9.1,  (0, 0, 1, 2): 7.1,
    (0, 0, 2, 0): 7.9,  (0, 0, 2, 1): 6.9,  (0, 0, 2, 2): 4.8,
    (0, 1, 0, 0): 9.5,  (0, 1, 0, 1): 9.1,  (0, 1, 0, 2): 8.0,
    (0, 1, 1, 0): 8.9,  (0, 1, 1, 1): 8.5,  (0, 1, 1, 2): 6.5,
    (0, 1, 2, 0): 7.0,  (0, 1, 2, 1): 5.5,  (0, 1, 2, 2): 4.0,
    # eq1=1 (some network/auth/UI advantage)
    (1, 0, 0, 0): 9.3,  (1, 0, 0, 1): 9.0,  (1, 0, 0, 2): 7.8,
    (1, 0, 1, 0): 8.8,  (1, 0, 1, 1): 8.5,  (1, 0, 1, 2): 6.5,
    (1, 0, 2, 0): 7.0,  (1, 0, 2, 1): 6.0,  (1, 0, 2, 2): 4.5,
    (1, 1, 0, 0): 9.0,  (1, 1, 0, 1): 8.5,  (1, 1, 0, 2): 7.5,
    (1, 1, 1, 0): 8.5,  (1, 1, 1, 1): 7.5,  (1, 1, 1, 2): 5.9,
    (1, 1, 2, 0): 6.0,  (1, 1, 2, 1): 5.5,  (1, 1, 2, 2): 3.5,
    # eq1=2 (local/physical or high-privileges + active UI required)
    (2, 0, 0, 0): 9.0,  (2, 0, 0, 1): 8.5,  (2, 0, 0, 2): 7.5,
    (2, 0, 1, 0): 8.0,  (2, 0, 1, 1): 7.5,  (2, 0, 1, 2): 6.5,
    (2, 0, 2, 0): 6.0,  (2, 0, 2, 1): 5.5,  (2, 0, 2, 2): 4.0,
    (2, 1, 0, 0): 8.5,  (2, 1, 0, 1): 8.0,  (2, 1, 0, 2): 7.0,
    (2, 1, 1, 0): 7.5,  (2, 1, 1, 1): 7.0,  (2, 1, 1, 2): 5.5,
    (2, 1, 2, 0): 5.5,  (2, 1, 2, 1): 5.0,  (2, 1, 2, 2): 3.5,
}

# Allowed CVSS 4.0 metric values, used by validate_cvss_params() to reject
# malformed vectors cleanly instead of silently falling back to a default score.
_CVSS_ALLOWED: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"},
    "VI": {"H", "L", "N"},
    "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"},
    "SI": {"S", "H", "L", "N"},
    "SA": {"S", "H", "L", "N"},
}

# Order matters for the assembled vector string.
_CVSS_FIELD_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def calculate_cvss40(av, ac, at, pr, ui, vc, vi, va, sc, si, sa) -> tuple[float, str]:
    """Calculate CVSS 4.0 base score (approximate) and return (score, vector_string).

    Unvalidated — callers that accept untrusted input should call
    validate_cvss_params() first. Values outside the known macro-vector table
    fall back to 5.0 (MEDIUM), matching the FIRST.org reference calculator's
    treatment of underspecified vectors.
    """
    e1 = _eq1(av, pr, ui)
    e2 = _eq2(ac, at)
    e3 = _eq3(vc, vi, va)
    e4 = _eq4(sc, si, sa)
    score = _CVSS40_TABLE.get((e1, e2, e3, e4), 5.0)
    vector = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
        f"/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
    )
    return score, vector


def severity_from_score(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"


def validate_cvss_params(params: dict) -> dict:
    """Validate a CVSS 4.0 param dict, return it normalized (uppercased values).

    Raises ValidationInputError naming the first missing/invalid field —
    unlike calculate_cvss40(), this never silently accepts garbage.
    """
    params = _require_dict(params)
    normalized: dict = {}
    for key in _CVSS_FIELD_ORDER:
        if key not in params:
            raise ValidationInputError(f"missing CVSS field: {key}")
        val = params[key]
        if not isinstance(val, str):
            raise ValidationInputError(f"CVSS field '{key}' must be a string, got {type(val).__name__}")
        val = val.strip().upper()
        allowed = _CVSS_ALLOWED[key]
        if val not in allowed:
            raise ValidationInputError(
                f"CVSS field '{key}' has invalid value '{val}' — allowed: {sorted(allowed)}"
            )
        normalized[key] = val
    return normalized


def score_cvss(params: dict) -> dict:
    """Validate + compute a CVSS 4.0 score from a params dict. Pure, no I/O.

    Returns {"score": float, "vector": str, "severity": str, "params": dict}.
    """
    p = validate_cvss_params(params)
    score, vector = calculate_cvss40(
        p["AV"], p["AC"], p["AT"], p["PR"], p["UI"],
        p["VC"], p["VI"], p["VA"], p["SC"], p["SI"], p["SA"],
    )
    return {
        "score": score,
        "vector": vector,
        "severity": severity_from_score(score),
        "params": p,
    }


# ─── Combined headless evaluation ──────────────────────────────────────────

def evaluate_finding(finding: dict) -> dict:
    """Run all 4 gates (+ CVSS, if provided) against one finding dict. Pure, no I/O.

    Expected shape:
        {
          "vuln_type": "IDOR",                 # optional, drives gate1's identity check
          "gate1": {"repro_3_3": true, "works_without_proxy": true,
                     "no_special_state": true, "not_documented_behavior": true,
                     # + cross_account_tested / fresh_session_tested / anon_vs_auth_delta
                     # if vuln_type is auth-related
                     },
          "gate2": {"asset_in_scope": true, "not_excluded": true, "version_ok": true},
          "gate3": {"concrete_impact": true, "no_unrealistic_preconditions": true,
                     "curl_poc": "curl -s https://...", "impact_description": "..."},
          "gate4": {"not_in_h1_disclosed": true, "not_in_github_issues": true,
                     "checked_git_history": true, "h1_similar_reports": []},
          "cvss": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                    "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}
        }

    "cvss" is optional — omit it to skip CVSS scoring. Any missing/malformed
    field anywhere in the payload raises ValidationInputError with the exact
    field name, so callers get a clean rejection instead of a KeyError/TypeError.

    Returns {"gate1_is_real": {...}, "gate2_in_scope": {...},
             "gate3_exploitable": {...}, "gate4_not_dup": {...},
             "cvss": {...} (if requested), "overall_pass": bool}.
    """
    finding = _require_dict(finding)
    vuln_type = _optional_str(finding, "vuln_type")

    gate1_input = dict(_optional_dict(finding, "gate1"))
    gate1_input.setdefault("vuln_type", vuln_type)
    g1 = gate1_is_real(gate1_input)

    g2 = gate2_in_scope(_optional_dict(finding, "gate2"))
    g3 = gate3_exploitable(_optional_dict(finding, "gate3"))
    g4 = gate4_not_dup(_optional_dict(finding, "gate4"))

    result = {
        "gate1_is_real":     g1,
        "gate2_in_scope":    g2,
        "gate3_exploitable": g3,
        "gate4_not_dup":     g4,
    }

    if "cvss" in finding and finding["cvss"] is not None:
        result["cvss"] = score_cvss(finding["cvss"])

    result["overall_pass"] = all(
        result[k]["passed"] for k in ("gate1_is_real", "gate2_in_scope", "gate3_exploitable", "gate4_not_dup")
    )
    return result


def _optional_dict(finding: dict, key: str) -> dict:
    val = finding.get(key, {})
    if not isinstance(val, dict):
        raise ValidationInputError(f"field '{key}' must be a JSON object, got {type(val).__name__}")
    return val
