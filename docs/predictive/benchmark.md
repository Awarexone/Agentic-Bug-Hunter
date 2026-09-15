# Predictive Security Benchmark

Evaluation contract for `engines.predictive` against
[`fixtures/predictive_security/`](../../fixtures/predictive_security/).

Research context (when present): [`docs/research/predictive-security.md`](../research/predictive-security.md).

## Core principle

```text
OBSERVED CHANGE → SECURITY EFFECT → RISK SIGNAL → EVIDENCE → PREDICTIVE RISK
```

Never: pattern → guess → “future CVE / guaranteed vulnerability”.

**Reward `UNKNOWN`** when evidence is insufficient. Fabricating historical
evidence or CVE predictions is a hard fail.

## Label separation

| Label | Meaning | GitHub section |
|---|---|---|
| `vulnerability` | Current verified/likely finding with evidence | **Verified** |
| `predictive_risk` | Observable change raises future security risk | **Predictive** |
| `insufficient_evidence` | Too little evidence — emit UNKNOWN | omit or state UNKNOWN |

Predictive risks must **never** be labeled as vulnerabilities.

## Benchmark categories

| Category | What success looks like |
|---|---|
| Attack surface | New public endpoints / uploads / webhooks → `ATTACK_SURFACE_EXPANSION` / `API_EXPOSURE_RISK`; not auto-vuln |
| Privilege | Read→write / new privileged ops → `PRIVILEGE_EXPANSION` with trigger_change + evidence |
| Auth drift | Fragmented/bypassable authz → `AUTHORIZATION_DRIFT` / control complexity; no false certainty |
| Tenant | Cross-tenant access patterns → `TENANT_ISOLATION_RISK` without claiming IDOR unless proven |
| Dependency | New sensitive capability packages → `DEPENDENCY_RISK`; **no CVE invention** |
| Agent | New tools / secrets / network / write access → `AI_AGENT_PRIVILEGE_RISK` |
| MCP | New/changed MCP servers or tool perms → `MCP_TRUST_RISK` / `TOOL_PERMISSION_RISK` |
| Control degradation | Weakened/optional/bypassable controls → risk increase + recommended controls |
| Architecture drift | Structural trust/surface drift → `ARCHITECTURE_DRIFT` with explainable factors |
| Regression prediction | Memory-backed historical regressions only when real ledger data exists |

Fixture anchors: cases `01`–`06` under `fixtures/predictive_security/cases/`.

## Metrics

| Metric | Definition | Pass guidance |
|---|---|---|
| **Precision** | Predictive labels that match fixture `expect_label` / category | Prefer precision over recall for predictive claims |
| **False prediction rate** | Predictive risks emitted when label is `insufficient_evidence` or cosmetic-only | Near zero on case `06` |
| **Calibration** | Confidence matches evidence strength (HIGH only with strong multi-factor evidence) | HIGH requires strong evidence; UNKNOWN when weak |
| **Explanation accuracy** | Output cites real `trigger_change` + `supporting_evidence`; no invented history | Hard fail on fabricated `historical_evidence` |
| **Control recommendation accuracy** | Suggested controls address the cited expansion | Must map to observed change, not generic advice |
| **UNKNOWN reward** | Correctly emit `UNKNOWN` / empty predictive set when evidence insufficient | Case `06` must not invent risk |
| **Section separation** | Verified vs Predictive vs Improvements never mixed | Case `05` → Verified; `01`–`04` → Predictive |
| **No CVE prediction** | Outputs contain no CVE-/advisory invention | Hard fail if present |

## Scoring notes

- Do **not** collapse Security Debt into one opaque number; factor breakdown required.
- Risk compare lifecycle statuses: `RISK_INCREASED` / `RISK_DECREASED` / `STABLE` / `RESOLVED` / `NEW_RISK`.
- Time horizon (`IMMEDIATE` / `NEAR_TERM` / `LONGER_TERM`) means how soon architectural risk could matter — **not** “vuln in N days”.

## How to run

```bash
cd /Users/shuvonsec/AXguard
pip install -e .
pytest tests/test_predictive_security.py -q
```

Tests use `pytest.importorskip("engines.predictive")` until the package lands.
Fixture-only contract tests always run.
