# Predictive Security fixtures

Synthetic before→after cases for `engines.predictive`.

These distinguish **PREDICTIVE RISK** (architectural / surface / privilege conditions that raise future risk) from **ACTUAL VULNERABILITY** (proven finding with evidence).

| Case | Transition | Expected label |
|---|---|---|
| `01_privilege_expansion` | Agent DB read → write | `predictive_risk` (`PRIVILEGE_EXPANSION`) |
| `02_trust_boundary_expansion` | Internal service → untrusted inbound | `predictive_risk` (`TRUST_BOUNDARY_EXPANSION`) |
| `03_new_public_endpoint` | Secure app → new public `POST /api/import` | `predictive_risk` (`ATTACK_SURFACE_EXPANSION` / `API_EXPOSURE_RISK`) |
| `04_new_mcp_server` | Agent without MCP → new external MCP | `predictive_risk` (`MCP_TRUST_RISK` / `AI_AGENT_PRIVILEGE_RISK`) |
| `05_actual_vulnerability` | Secure query → tainted SQL concat | `vulnerability` (not merely predictive) |
| `06_insufficient_evidence` | Cosmetic rename only | `insufficient_evidence` → confidence `UNKNOWN` |

Each case has `before.json`, `after.json` (minimal Security Twin–shaped snapshots) and `expected.json`.

Top-level [`expected.json`](expected.json) is the catalog contract asserted by `tests/test_predictive_security.py`.

Benchmark categories and metrics: [`docs/predictive/benchmark.md`](../../docs/predictive/benchmark.md).

Do not deploy these fixtures. Never treat predictive labels as verified vulns.
