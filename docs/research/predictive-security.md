# Research: AXGuard Predictive Security Intelligence

**Status:** Internal research ahead of `engines/predictive/`  
**Date:** 2026-09  
**Stance:** Skeptical of marketing “prediction.” Prefer observable change → security effect → risk signal. Prefer UNKNOWN over invented futures. Never label architecture risk as a vulnerability.

---

## 1. Problem statement

Traditional AppSec answers:

> Is this line / dependency / PR **vulnerable right now**?

AXGuard already answers that path with hunters, Evidence, Judge, Attack Graph, Investigation, Security Twin, and Security Memory.

The remaining gap is **security foresight without false certainty**:

> Did this change create conditions where future security problems are **more likely** or **more impactful**?

That is **predictive software security** — risk expansion and architecture drift — not CVE forecasting.

| Detection asks | Prediction asks |
|---|---|
| Is there a confirmed weakness with evidence? | Did attack surface / privilege / trust / controls move in a dangerous direction? |
| Can we name a CWE / finding today? | What blast radius would grow if a later bug or agent abuse appears here? |
| Pass / fail the Verified check | Separate Predictive signal; do not block merge as if verified |

**Positioning (defensible):**

> AXGuard Predictive Security reports evidence-backed **risk expansion** from observable diffs and structural history — never “this PR will introduce CVE-…,” never fabricated regressions, never architecture risk re-labeled as a vulnerability.

---

## 2. Predictive security vs vulnerability detection

### 2.1 Two products, one PR surface

| Layer | Output language | Gate role |
|---|---|---|
| **Vulnerability detection** | CONFIRMED / LIKELY findings, with Evidence + Judge | Verified Security Issues |
| **Predictive security** | PREDICTIVE risk signals (`status: PREDICTIVE`) | Predictive Security Risks |
| **Hardening advice** | Optional controls / tests when confidence is high | Security Improvements |

Industry already separates *presence* from *prioritization*, but rarely separates *verified issue* from *structural foresight* in the same PR UX:

- **Reachability SCA** (Endor Labs, Semgrep Supply Chain, Snyk) asks whether a *known CVE* is callable — still detection + triage, not architecture prediction.  
  - https://docs.endorlabs.com/scan/sca/reachability-analysis  
  - https://www.endorlabs.com/use-case/sca-with-reachability  
  - https://docs.semgrep.dev/faq/comparisons/endor-labs  
  - https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/risk-score  
- **EPSS** (FIRST) predicts *exploitation likelihood of a published CVE in the wild*, not whether a PR will create one.  
  - https://www.first.org/epss/  
- **GitHub code scanning merge protection** blocks on *alerts from required tools*, not on speculative future bugs.  
  - https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-merge-protection  
  - https://github.blog/changelog/2024-04-30-code-scanning-now-allows-configuring-rulesets-to-prevent-pull-requests-from-being-merged-beta/  
- **Microsoft Security Exposure Management / MDASH** emphasizes confidence hierarchies for *detected* weaknesses (UNLIKELY → PROVEN), which is closer to AXGuard’s honesty contract than to CVE prophecy.  
  - https://learn.microsoft.com/en-us/security-exposure-management/ai-code-security-overview  
- **GitHub + Defender code-to-cloud** adds *runtime exposure context* to existing alerts — prioritization of detected issues, not invention of future CVEs.  
  - https://github.blog/changelog/2025-11-18-unified-code-to-cloud-artifact-risk-visibility-with-microsoft-defender-for-cloud-now-in-public-preview/

**AXGuard rule:** Predictive output must never be merged into Verified findings. Reuse the Phase 6 honesty contract already in `engines/attack_graph/predictive.py` and `whatif.py` (`status: PREDICTIVE`, trend/surface language only).

### 2.2 What “prediction” is allowed to mean here

Allowed:

- Attack surface expansion (new public entry, upload, webhook, MCP server, agent tool)
- Privilege / trust / tenant / data-sensitivity expansion
- Control degradation or complexity increase
- Explainable change-risk scores with factor breakdown
- Historical **repository-local** regression patterns from Security Memory (when recorded)

Disallowed:

- Naming future CVE IDs or inventing exploitation timelines (“will be vulnerable in 30 days”)
- Treating EPSS/CVSS-style CVE scores as architecture foresight for first-party design changes
- Pattern match → “future vulnerability” without an observed change and security effect

---

## 3. Landscape: security debt, architecture, ASM, change-risk, churn

### 3.1 Security debt

Industry usage varies; AXGuard should treat debt as a **factor vector**, not a single opaque grade.

- **Veracode State of Software Security 2025** defines security debt operationally as flaws remaining unfixed for over a year; reports ~74% of orgs with some debt and debt in ~42% of actively tested apps. Useful as *industry context*, not as AXGuard’s scoring formula.  
  - https://www.veracode.com/wp-content/uploads/2025/02/State-of-Software-Security-2025.pdf  
- **OWASP Top 10:2025 A06 Insecure Design** frames missing/ineffective *control design* and business-logic architecture flaws — distinct from implementation bugs.  
  - https://owasp.org/Top10/2025/A06_2025-Insecure_Design/  
- **OWASP Secure by Design Framework** and **ASVS V15** emphasize design-phase controls, trust boundaries, and isolation around dangerous / risky components.  
  - https://owasp.org/www-project-secure-by-design-framework/  
  - https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md  
- **NIST SP 800-218 SSDF** and **CISA Secure by Design** push root-cause prevention and secure defaults across the SDLC — alignment for “recommend controls,” not for claiming undetected CVEs.  
  - https://csrc.nist.gov/pubs/sp/800/218/final  
  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf  
  - https://www.cisa.gov/sites/default/files/2023-06/principles_approaches_for_security-by-design-default_508c.pdf  

**AXGuard Security Debt inputs (product brief):** unresolved findings, repeated FP patterns, duplicated controls, missing tests, complex authorization, growing attack surface, unknown assumptions, stale dependencies, privileged agents, security regressions — **show contributing factors**; do not collapse to one meaningless number.

### 3.2 Architectural risk & secure architecture drift

Architecture drift is a **delta** between intended trust model and observed structure across revisions:

- New bypass routes; authz split across layers; middleware removed; direct DB access; optional validation; approval gates removed; shared caches crossing tenants; agent/MCP trust expansion.

OWASP Insecure Design + SbD make clear: these are **design/architecture conditions**, not automatic “vulnerabilities.” Predictive language:

> “Authorization complexity increased” / “Cross-tenant security risk increased”

— not —

> “IDOR confirmed” (unless Evidence + Judge say so).

### 3.3 Attack surface management (ASM)

Cloud/exposure products (Microsoft Exposure Management, code-to-cloud runtime tags) operationalize **inventory + exposure + path combination**. AXGuard’s local pre-ship analogue is:

- Application model + Attack Graph entrypoints  
- Diff of entrypoints / tools / externals (`engines/attack_graph/diff.py`, `predictive.surface_report`)  
- Twin blast radius under current vs counterfactual permissions  

ASM for AXGuard = **measured surface metrics + direction of change**, not internet-wide asset discovery.

### 3.4 Change-risk & code churn ↔ vulnerability correlation

Empirical literature supports **prioritization signals**, not certainty:

| Work | Claim (careful reading) | Use for AXGuard |
|---|---|---|
| Shin, Meneely, Williams, Osborne — *IEEE TSE* (complexity, churn, developer activity) | Vulnerable files often show higher churn/complexity; combined models can concentrate inspection effort (high recall at reduced file set; **low precision on single metrics**) | Churn / change size → **MEDIUM/LOW** predictive factors or UNKNOWN if alone | 
| Nagappan & Ball — relative code churn / static-analysis density as early defect indicators | Churn and static findings correlate with fault-prone components | Change-risk factor; never sole proof of a vuln |

Canonical references:

- https://doi.org/10.1109/tse.2010.81  
- https://techrep.csc.ncsu.edu/2009/TR-2009-10.pdf  
- https://doi.org/10.1109/icse.2005.1553604  

**Calibration rule:** Correlation literature justifies *attention*, not *Verified* labels. A large churny PR without surface/privilege/trust deltas → LOW or UNKNOWN predictive risk.

### 3.5 Vendor “prediction” that is *not* AXGuard’s job

| Signal | What it predicts | AXGuard stance |
|---|---|---|
| FIRST EPSS | P(CVE exploited in wild ≈30d) | Optional dependency triage only; **not** architecture prediction |
| Snyk Risk Score | Impact × likelihood for *known* issues | Complementary prioritization; do not invent CVEs |
| Endor / Semgrep reachability | Whether vulnerable functions are callable | Detection triage |
| Google SAIF risk self-assessment | AI system risk categories (prompt injection, insecure components, …) | Inform **AI_AGENT_*** / **MCP_*** category design |  
  - https://saif.google/ · https://saif.google/risk-self-assessment  
| NIST AI RMF / AI 600-1 | AI risk management | Frame agent/MCP predictive categories |  
  - https://www.nist.gov/itl/ai-risk-management-framework  

---

## 4. Privilege expansion, AI agents, MCP, architecture drift

### 4.1 Privilege expansion (general)

Observable before/after capability:

```text
Agent → read-only DB   →   Agent → write DB
Service → scoped IAM   →   Service → admin role
Tool → no network      →   Tool → unrestricted egress
```

Prediction: privilege expanded; then Twin/Attack Graph assess reachable sensitive assets, controls, blast radius. **Do not** auto-promote to Verified vulnerability.

### 4.2 AI agent / MCP security (2025–2026 evidence)

Credible research shows **trust and privilege expansion** are first-class risk surfaces:

| Source | Relevance to predictive categories |
|---|---|
| Trail of Bits — MCP “line jumping” / tool-description injection before tool invoke | New MCP server or tool-description change → `MCP_TRUST_RISK`, `TOOL_PERMISSION_RISK`; TOFU / re-approval as recommended controls |  
  - https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/  
  - https://blog.trailofbits.com/2025/04/23/how-mcp-servers-can-steal-your-conversation-history/  
  - https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/  
  - https://blog.trailofbits.com/2025/04/30/insecure-credential-storage-plagues-mcp/  
  - https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/  
| Unit 42 — MCP sampling attack vectors (resource theft, conversation hijacking, covert tool invocation) | Sampling / bidirectional trust → `AI_AGENT_PRIVILEGE_RISK`, `MCP_TRUST_RISK` |  
  - https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/  
| OWASP Agentic Top 10 / GenAI Agentic Security Initiative | Taxonomy for agent privilege, tool abuse, identity |  
  - https://genai.owasp.org/initiatives/agentic-security-initiative/  
  - https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/  
| Academic MCP toolchain / taint analyses (e.g. parasitic toolchain, VIPER-MCP) | Support treating multi-tool ambient authority as structural risk |  
  - https://arxiv.org/html/2509.06572v5  

**Predictive detections (product brief):** new tool; write/network/fs/secrets/customer-data/code-exec; new MCP server; untrusted content; approval gate removed → predict privilege expansion, tool-abuse impact, prompt-injection impact expansion, exfil / confused-deputy / trust-boundary expansion — still **PREDICTIVE** unless Investigation verifies a concrete issue.

### 4.3 Secure architecture drift

Compose Twin regression + Memory + Attack Graph diff:

- `RISK_INCREASED` / `RISK_DECREASED` / `RISK_STABLE` / `RISK_RESOLVED` / `NEW_RISK`  
- Overall direction already sketched in `engines/attack_graph/predictive.predictive_report` (`increasing` / `decreasing` / `stable`)

---

## 5. CORE PRINCIPLE — evidence-backed prediction vs speculation

```text
OBSERVED CHANGE
  → SECURITY EFFECT
  → RISK SIGNAL
  → HISTORICAL / STRUCTURAL EVIDENCE
  → PREDICTIVE RISK
```

Never:

```text
PATTERN → RANDOM GUESS → "FUTURE VULNERABILITY"
```

### 5.1 Evidence requirements

| Confidence | Requires |
|---|---|
| **HIGH** | Clear capability delta (e.g. privileged tool + sensitive asset + missing approval) with Twin/graph support |
| **MEDIUM** | Measurable surface/privilege/trust change with partial control context |
| **LOW** | Weak or noisy signals (churn alone, style-only refactors) |
| **UNKNOWN** | Insufficient evidence — **preferred over speculation**; rewarded in benchmarks |

### 5.2 Language contract (no false certainty)

Forbidden:

- “This PR will introduce a vulnerability.”
- “This will be exploited within N days.”
- “CVE-YYYY-… will appear here.”

Preferred:

- “This PR increases the conditions under which this class of issue could become impactful.”
- “No vulnerability was verified, but security risk increased because …”
- “MCP trust boundary expanded; affected agents/resources: …”

Align with existing disclaimer in `engines/attack_graph/predictive.py`: trend/surface observation, **not** confirmed finding.

### 5.3 Historical evidence honesty

Security Memory may say:

> “This area has repeatedly regressed in previous changes”

**only** when Memory holds actual recorded regressions for that fingerprint. **Never fabricate** repository history or incidents. No external telemetry requirement.

---

## 6. Proposed AXGuard `PredictiveRisk` model

### 6.1 Fields (product brief)

| Field | Role |
|---|---|
| `risk_id` | Stable id for the predictive signal |
| `category` | One of §6.2 |
| `affected_asset` | Asset / data class impacted |
| `affected_component` | Module, agent, MCP server, package, endpoint |
| `trigger_change` | Observable PR/diff/twin delta that fired the signal |
| `supporting_evidence` | Structural evidence from current analysis (graph, twin, identity, dataflow) |
| `historical_evidence` | Memory-backed only; empty → do not invent |
| `attack_surface_change` | Δ entrypoints / tools / integrations / exposure |
| `privilege_change` | Δ capabilities (read→write, scoped→admin, …) |
| `trust_change` | Δ trust boundaries / MCP / external servers |
| `data_sensitivity` | Sensitivity of newly reachable data |
| `complexity_change` | Authz/control complexity delta |
| `control_change` | Weakened / fragmented / optional / bypassable controls |
| `confidence` | `HIGH` \| `MEDIUM` \| `LOW` \| `UNKNOWN` |
| `severity` | Predictive severity of *risk expansion* (not Verified finding severity) |
| `time_horizon` | `IMMEDIATE` \| `NEAR_TERM` \| `LONGER_TERM` — when architectural risk could matter; **not** a CVE ETA |
| `recommended_action` | Concrete control advice tied to the risk |
| `unknowns` | Explicit gaps (required for honesty + benchmarks) |

Every emitted object should also carry:

- `status: "PREDICTIVE"`  
- `disclaimer` (non-finding)  
- optional `regression_state`: `RISK_INCREASED` | `RISK_DECREASED` | `RISK_STABLE` | `RISK_RESOLVED` | `NEW_RISK`

### 6.2 Categories (product brief)

```text
ATTACK_SURFACE_EXPANSION
PRIVILEGE_EXPANSION
TRUST_BOUNDARY_EXPANSION
AUTHORIZATION_DRIFT
TENANT_ISOLATION_RISK
SENSITIVE_DATA_FLOW
EXTERNAL_INTEGRATION_RISK
DEPENDENCY_RISK
CLOUD_PRIVILEGE_RISK
SECRET_MANAGEMENT_RISK
AI_AGENT_PRIVILEGE_RISK
MCP_TRUST_RISK
TOOL_PERMISSION_RISK
SECURITY_CONTROL_COMPLEXITY
SECURITY_DEBT
REGRESSION_RISK
ARCHITECTURE_DRIFT
API_EXPOSURE_RISK
NETWORK_EXPOSURE_RISK
```

### 6.3 Category sketches (detection → language)

| Category | Detect (examples) | Predictive language |
|---|---|---|
| `ATTACK_SURFACE_EXPANSION` | New public endpoint, API method, webhook, upload, integration, network path, tool, MCP, agent, privileged op | “New attacker-controlled … surface” — **not** “vulnerable endpoint” |
| `PRIVILEGE_EXPANSION` | Capability widening (identity, IAM, agent tools) | “Privilege expanded from X to Y” |
| `AUTHORIZATION_DRIFT` | Split/dupe authz, bypass routes, middleware removed, fragmented ownership checks | “Authorization complexity increased” |
| `TENANT_ISOLATION_RISK` | Cross-tenant access paths, shared caches, multi-tenant workers, missing tenant propagation | “Cross-tenant security risk increased” — not “IDOR confirmed” |
| `DEPENDENCY_RISK` | New package with network/fs/exec/credential capability; trust/concentration | “New dependency introduces a security-sensitive capability” — **no CVE IDs invented** |
| `AI_AGENT_PRIVILEGE_RISK` / `MCP_TRUST_RISK` / `TOOL_PERMISSION_RISK` | Tool/MCP/approval/secrets/data deltas | “Agent/MCP trust or privilege expanded” |
| `SECURITY_CONTROL_COMPLEXITY` / debt / drift | Weaker, optional, fragmented, bypassable controls; debt factors | “Control degradation / debt factors: …” |

### 6.4 Explainable change-risk score

Factorized, auditable contributions (product brief):

- Attack surface change  
- Privilege change  
- Trust boundary change  
- Data sensitivity  
- Control degradation  
- Historical regressions (Memory only)  
- Complexity  
- Dependency change  
- Unknowns (increase uncertainty, not fake severity)  
- Existing attack paths (from Attack Graph)

Emit factor breakdown for GitHub Check / HTML — **no opaque single number without explanation**.

Example PR check sketch:

```text
AXGuard Predictive Security
  Attack Surface:            +2
  Privilege:                 +1
  Trust Boundaries:          +1
  Sensitive Data Exposure:    0
  Security Controls:         -1
  Historical Regression Risk:+1
  Overall:                 MEDIUM
  (each factor explained)
```

---

## 7. Integration with AXGuard engines

```text
PR / revision diff
  → Data Flow + Identity/Authz + Dependency + AI/MCP models
  → Attack Graph (paths, barriers, surface)
  → Security Twin (what-if, blast, control value)
  → Security Memory (real history only)
  → Investigation (optional deepen HIGH candidates)
  → Evidence (attach only real artifacts)
  → Judge (Verified findings ONLY — not predictive promotion)
  → PredictiveRisk model + scoring
  → GitHub Check / HTML / CLI (`axguard predict …`)
```

| Engine | Predictive role |
|---|---|
| **Security Twin** | Counterfactuals: “safe under current perms; granting write opens N simulated paths”; quarantine hypotheticals as SIMULATED/PREDICTIVE |
| **Security Memory** | Historical regression / debt factors; never invent; invalidate when evidence hash drifts |
| **Attack Graph** | Surface metrics, path deltas, weakened controls; reuse `diff` + `predictive` modules |
| **Investigation** | Spend budget only on HIGH predictive candidates that might become Verified; stop on UNKNOWN |
| **Evidence** | Bind `supporting_evidence` to content-addressed artifacts; no speculative evidence objects |
| **Judge** | Owns Verified / FP decisions; **must not** convert PREDICTIVE → CONFIRMED without new proof |
| **GitHub bot** | Separate Check sections; high-value predictive comments only (no spam) |

**What-if example (product brief):**

> Current system is safe under current permissions. Granting this agent production DB write would create 4 new (simulated) attack paths. Recommended: table-scoped tool + approval for writes.

---

## 8. GitHub Check separation

Never mix Verified and Predictive in one undifferentiated list.

| Section | Contents |
|---|---|
| **Verified Security Issues** | Evidence-backed findings after Judge |
| **Predictive Security Risks** | `PredictiveRisk` objects; disclaimers; factor score |
| **Security Improvements** | Architecture advice for high-confidence predictive risks (centralize authz, reduce agent privileges, tool approval, tenant isolation, egress restrict, MCP isolate, secret reduction, tests/invariants) |

PR comment pattern (high-value only):

```markdown
### AXGuard Predictive Security Risk

**Medium: Agent privilege expansion**

This PR gives the support agent write access to the customer database.

No current exploit was verified.

However, the Security Twin shows that this expands the agent's potential
impact from read-only customer data to database modification.

Recommended control: Restrict the tool to required tables/actions and
require approval for writes.

This is NOT a confirmed vulnerability.
```

Policy note: Predictive Check should default to **informational / non-blocking** unless the org explicitly policies otherwise. Verified issues remain the merge gate (aligned with GitHub code-scanning alert thresholds).

---

## 9. Benchmark design (reward UNKNOWN)

### 9.1 Categories

1. Attack surface prediction  
2. Privilege prediction  
3. Authorization drift  
4. Tenant risk  
5. Dependency risk  
6. Agent risk  
7. MCP risk  
8. Security-control degradation  
9. Architecture drift  
10. Regression prediction  

### 9.2 Synthetic case pattern

```text
Secure architecture
  → privilege / trust / public endpoint / MCP expansion
  → PREDICTIVE RISK label

Separate track:
  → Vulnerability introduced
  → ACTUAL VULNERABILITY (Verified) label
```

Training/eval must **distinguish** `PREDICTIVE RISK` from `ACTUAL VULNERABILITY`. Mislabeling architecture risk as vulnerability = hard fail.

### 9.3 Metrics

| Metric | Definition |
|---|---|
| Prediction precision | Fraction of PREDICTIVE emits that match gold risk categories/effects |
| False prediction rate | Speculative or overconfident emits without observed change |
| Risk calibration | HIGH/MEDIUM/LOW match gold confidence bands |
| Explanation accuracy | Trigger change + factors match gold rationale |
| Control recommendation accuracy | Advice matches gold mitigations |
| **UNKNOWN reward** | Credit for UNKNOWN when evidence insufficient; **penalize** forced HIGH/MEDIUM without evidence |

Gold sets should include “insufficient evidence” fixtures where the only correct answer is UNKNOWN.

---

## 10. Explicit DO NOTs

1. **No CVE prediction** — do not invent future CVE IDs or claim EPSS-style timelines for first-party design changes.  
2. **No fabricated history** — Memory/historical_evidence only from real AXGuard artifacts.  
3. **No false certainty** — no “will be vulnerable”; prefer condition/risk language.  
4. **Never label architecture risk as vulnerability** — PREDICTIVE ≠ Verified finding.  
5. **No fabricated incidents** or external telemetry requirements.  
6. **No production attacks** / exploitation as part of prediction.  
7. **Do not spam** developers with low-value predictive noise.  
8. **Do not let Judge auto-promote** predictive signals without new Evidence.

---

## 11. Suggested UX / CLI / HTML (product brief — implementation later)

**CLI (conceptual):**

```text
axguard predict
axguard predict --pr
axguard predict --architecture
axguard predict --agent
axguard predict --mcp
axguard predict --what-if
```

**HTML sections:** New Risks · Risk Changes · Attack Surface · Privilege · Trust Boundaries · AI/Agent Risk · MCP Risk · Security Debt · Historical Regression · Recommended Controls · What-If Analysis.

---

## 12. Quality bar (success criterion)

AXGuard should be able to tell a developer:

> Your PR is not currently vulnerable.  
> But you expanded this agent’s privileges from reading customer data to modifying it.  
> That creates a materially larger blast radius.  
> Here is the control we recommend before this architecture grows further.

Not fear. Not guessing. **Security foresight backed by evidence.**

---

## 13. Key sources (Sept 2026 context)

**Standards / frameworks**

- OWASP Top 10:2025 A06 Insecure Design — https://owasp.org/Top10/2025/A06_2025-Insecure_Design/  
- OWASP Secure by Design Framework — https://owasp.org/www-project-secure-by-design-framework/  
- OWASP ASVS V15 — https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md  
- OWASP Agentic / GenAI — https://genai.owasp.org/initiatives/agentic-security-initiative/ · https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/  
- NIST SP 800-218 SSDF — https://csrc.nist.gov/pubs/sp/800/218/final · https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf  
- NIST AI RMF — https://www.nist.gov/itl/ai-risk-management-framework  
- CISA Secure by Design — https://www.cisa.gov/sites/default/files/2023-06/principles_approaches_for_security-by-design-default_508c.pdf  
- Google SAIF — https://saif.google/ · https://saif.google/risk-self-assessment  

**Platform / vendors**

- GitHub code scanning merge protection — https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-merge-protection  
- GitHub + Defender code-to-cloud risk — https://github.blog/changelog/2025-11-18-unified-code-to-cloud-artifact-risk-visibility-with-microsoft-defender-for-cloud-now-in-public-preview/  
- Microsoft Exposure Management / MDASH — https://learn.microsoft.com/en-us/security-exposure-management/ai-code-security-overview  
- Endor Labs reachability — https://docs.endorlabs.com/scan/sca/reachability-analysis · https://www.endorlabs.com/use-case/sca-with-reachability  
- Semgrep vs Endor (reachability states) — https://docs.semgrep.dev/faq/comparisons/endor-labs  
- Snyk Risk Score — https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/risk-score  
- FIRST EPSS — https://www.first.org/epss/  
- Veracode SoSS 2025 (security debt stats) — https://www.veracode.com/wp-content/uploads/2025/02/State-of-Software-Security-2025.pdf  

**Research labs**

- Trail of Bits MCP series (2025) — https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ (and linked follow-ons)  
- Unit 42 MCP sampling — https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/  

**Academic / change-risk**

- Shin et al., complexity/churn/developer activity ↔ vulnerabilities — https://doi.org/10.1109/tse.2010.81  
- Nagappan & Ball, static analysis / churn as early defect indicators — https://doi.org/10.1109/icse.2005.1553604  

**Internal AXGuard primitives to reuse**

- `engines/attack_graph/predictive.py`, `diff.py`, `whatif.py`  
- Security Twin (`docs/research/security-twin.md`, `engines/twin/`)  
- Security Memory (`docs/research/security-memory.md`, `engines/memory/`)  
- Investigation / Evidence / Judge pipelines  

---

## 14. Implementation implications (research → build)

1. New `PredictiveRisk` schema + explainable scorer (compose, don’t fork Twin/Memory/Graph).  
2. Wire PR diff → category detectors → Twin what-if for HIGH agent/MCP/privilege cases.  
3. GitHub Check: three sections; predictive default non-blocking.  
4. Benchmarks with UNKNOWN-reward and PREDICTIVE vs VULNERABILITY separation.  
5. Keep Phase 6 language: increasing/decreasing risk and emerging surface — never silent promotion to findings.
