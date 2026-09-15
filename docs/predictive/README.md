# AXGuard Predictive Security

Predictive security answers a different question than vulnerability detection.

| Vulnerability detection | Predictive security |
|---|---|
| “Is this PR vulnerable **now**?” | “Did this change create conditions where future security problems are **more likely**?” |

AXGuard predicts **security risk expansion** — attack-surface growth, privilege expansion, trust-boundary drift, control degradation, and related architectural signals — not exact future CVEs or guaranteed bugs.

## Core principle

Prediction must rest on **observable changes**.

```text
OBSERVED CHANGE
  → SECURITY EFFECT
  → RISK SIGNAL
  → HISTORICAL / STRUCTURAL EVIDENCE
  → PREDICTIVE RISK
```

Never:

```text
PATTERN → RANDOM GUESS → “FUTURE VULNERABILITY”
```

Every predictive risk should cite a **trigger change** and **supporting evidence**. Prefer **UNKNOWN** over inventing history or impact.

## What is *not* a predictive risk

- A verified exploit or confirmed finding (that belongs under **Verified Security Issues**)
- Speculative “this might become a CVE someday”
- An opaque score with no factor breakdown
- Fabricated repository history or invented prior regressions

## Risk categories

Supported category labels (schema / detectors):

| Category | Typical trigger |
|---|---|
| `ATTACK_SURFACE_EXPANSION` | New public endpoints, uploads, webhooks, tools |
| `PRIVILEGE_EXPANSION` | Read → write, new privileged operations |
| `TRUST_BOUNDARY_EXPANSION` | New external trust, shared layers, MCP/agent trust |
| `AUTHORIZATION_DRIFT` | Fragmented / duplicated / bypassable authZ |
| `TENANT_ISOLATION_RISK` | Cross-tenant access paths or shared caches |
| `SENSITIVE_DATA_FLOW` | Broader reach to PII / secrets / customer data |
| `EXTERNAL_INTEGRATION_RISK` | New outbound integrations or network edges |
| `DEPENDENCY_RISK` | New packages with security-sensitive capabilities |
| `CLOUD_PRIVILEGE_RISK` | Broader cloud / IAM style privilege |
| `SECRET_MANAGEMENT_RISK` | Wider secret access or weaker handling |
| `AI_AGENT_PRIVILEGE_RISK` | Agent tools, writes, network, code execution |
| `MCP_TRUST_RISK` | New MCP servers, tools, or trust changes |
| `TOOL_PERMISSION_RISK` | Tool permission widening or lost approval gates |
| `SECURITY_CONTROL_COMPLEXITY` | Controls weaker, optional, or fragmented |
| `SECURITY_DEBT` | Accumulated debt factors (explainable, not one magic number) |
| `REGRESSION_RISK` | Area with real prior security regressions |
| `ARCHITECTURE_DRIFT` | Structural drift away from safer patterns |
| `API_EXPOSURE_RISK` | Broader or riskier API exposure |
| `NETWORK_EXPOSURE_RISK` | New or wider network exposure |

Example (surface, not a vuln):

> PR adds `POST /api/import` → “New attacker-controlled file ingestion surface.”  
> Do **not** call it vulnerable unless verification proves a finding.

## Confidence

| Level | Meaning |
|---|---|
| `HIGH` | Strong observable evidence (e.g. privileged tool + sensitive access + no approval gate) |
| `MEDIUM` | Clear risk signal with some uncertainty or missing controls |
| `LOW` | Weak or narrow signal |
| `UNKNOWN` | Insufficient evidence; do not invent certainty |

`HIGH` requires strong evidence. Small refactors are usually `LOW` or `UNKNOWN`.

## Time horizon

| Value | Meaning |
|---|---|
| `IMMEDIATE` | Architectural risk can matter as soon as the change lands |
| `NEAR_TERM` | Risk becomes material as the architecture is reused or extended |
| `LONGER_TERM` | Risk compounds over ongoing growth / debt |

Time horizon is **not** “a vulnerability will appear in N days.” It is how soon the **architectural risk** could matter.

## Separation from vulnerabilities

Keep these lanes separate in every UI (CLI, HTML, GitHub Check, PR comment):

| Lane | Content |
|---|---|
| **Verified Security Issues** | Confirmed / verified findings |
| **Predictive Security Risks** | Evidence-backed risk expansion (not exploits) |
| **Security Improvements** | Recommended controls / architecture advice |

Never mix a predictive risk into a verified finding list. Never label a predictive signal as a vulnerability.

Risk-change statuses (before → after): `RISK_INCREASED`, `RISK_DECREASED`, `RISK_STABLE`, `RISK_RESOLVED`, `NEW_RISK`.

## CLI

Conceptual CLI (follows existing `axguard` patterns):

```bash
axguard predict .
axguard predict . --pr
axguard predict . --architecture
axguard predict . --agent
axguard predict . --mcp
axguard predict . --what-if
```

| Flag / mode | Intent |
|---|---|
| (default) | Predictive risk analysis for the workspace / change set |
| `--pr` | PR / diff-oriented predictive review |
| `--architecture` | Architecture drift and control-complexity focus |
| `--agent` | AI agent privilege / tool expansion |
| `--mcp` | MCP trust and tool-permission expansion |
| `--what-if` | Counterfactual prediction via Security Twin |

Artifacts, when written by the CLI, land under `.findings/axguard/predictive/` (alongside twin / memory / investigation). Exact flags and artifact names follow the Implementation Engineer package — do not invent extra config keys here.

Related diagnostics (already shipped):

```bash
axguard paths . --predictive          # attack-surface / drift signals on the graph
axguard paths . --what-if SCENARIO    # hypothetical paths (status PREDICTIVE)
axguard twin what-if . --scenario …
axguard memory regressions
```

## GitHub Check sections

The GitHub Check / PR summary should keep three distinct sections:

```text
Verified Security Issues
Predictive Security Risks
Security Improvements
```

Optional **AXGuard Predictive Security** factor panel (explain every factor; no opaque score):

```text
AXGuard Predictive Security

Attack Surface:              +2
Privilege:                   +1
Trust Boundaries:            +1
Sensitive Data Exposure:      0
Security Controls:           -1
Historical Regression Risk:  +1

Overall: MEDIUM
```

Only surface **high-value** predictive risks on PRs — do not spam developers with low-signal noise. Tone and examples: [pr-ux.md](pr-ux.md). Broader bot voice rules: [docs/github/pr-ux.md](../github/pr-ux.md).

## What-if prediction

Integrate with the Security Twin / counterfactual engine.

Example:

> What if this new agent gets access to the production database?

Report:

- New attack paths (count + structure)
- Blast radius
- Affected assets
- Controls required

Preferred framing:

> Current system is safe under current permissions.  
> Granting this permission would create N new attack paths.

Counterfactual / what-if output is always **predictive / simulated**, never a verified vulnerability.

## Security architecture advice

For high-confidence predictive risks, recommend concrete controls tied to the observed risk — for example: centralize authorization, reduce agent privileges, add tool approval, isolate tenants, restrict outbound network, isolate MCP servers, reduce secret exposure, add security tests or invariant checks.

Recommendations must follow from the actual risk signal, not a generic checklist.

## DO NOTs

- Do **not** predict specific future CVEs
- Do **not** claim “this code will definitely contain a vulnerability”
- Do **not** write “this PR will introduce a vulnerability”
- Do **not** fabricate historical regression patterns
- Do **not** mix predictive risks with verified findings
- Do **not** reduce security debt to a meaningless single number without factors
- Do **not** invent config keys incompatible with existing `.axguard.yml` / GitHub bot docs
- Prefer: “No vulnerability was verified, but security risk increased because…”

## See also

- Research notes: [`docs/research/predictive-security.md`](../research/predictive-security.md)
- PR / Check tone: [`docs/predictive/pr-ux.md`](pr-ux.md)
- Security Twin: [`docs/twin/README.md`](../twin/README.md)
- Security Memory: [`docs/memory/README.md`](../memory/README.md)
- Attack graph predictive helpers: [`docs/attack-graph.md`](../attack-graph.md)
- GitHub bot PR UX: [`docs/github/pr-ux.md`](../github/pr-ux.md)
