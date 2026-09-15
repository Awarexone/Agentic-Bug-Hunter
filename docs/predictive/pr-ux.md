# Predictive Security — PR UX

Tone contract for **Predictive Security Risks** on pull requests. This is a companion to [docs/github/pr-ux.md](../github/pr-ux.md). Predictive copy must never use fear, hype, or guessing.

Goal: security foresight backed by evidence — not panic, not speculation.

---

## Separation (required)

Always keep three lanes. Never merge them into one undifferentiated list.

| Section | Contains | Does not contain |
|---|---|---|
| **Verified Security Issues** | Confirmed / verified findings | Predictive signals, advice-only notes |
| **Predictive Security Risks** | Evidence-backed risk expansion | Exploits, “will be vulnerable”, CVE forecasts |
| **Security Improvements** | Recommended controls for high-value risks | Fake urgency, marketing |

If there are no high-value predictive risks, omit the Predictive section rather than padding it.

---

## Voice

- Calm, precise, engineering-first
- Cite the **observable change** before the risk claim
- Say what was **not** verified when relevant (“No current exploit was verified.”)
- Prefer “risk increased / conditions expanded” over future-tense vulnerability claims
- No exclamation marks as urgency theater; no emoji-led panic

### Prefer

```text
No vulnerability was verified, but the security risk increased because…
This PR increases the conditions under which this class of issue could become impactful.
```

### Never

```text
This PR will introduce a vulnerability.
This code will definitely contain a vulnerability.
Potential vulnerability!!!
We predict CVE-YYYY-NNNN.
```

---

## Example Predictive PR comment

High-value only. Update the single AXGuard summary comment; do not spam a second thread for predictions.

```markdown
<!-- AXGUARD-SECURITY-REVIEW -->

## AXGuard Security Review

**Conclusion:** PASS_WITH_NOTES

### Verified Security Issues

None verified on this PR.

### Predictive Security Risks

**Medium — Agent privilege expansion** (`PRIVILEGE_EXPANSION` · confidence `MEDIUM` · horizon `NEAR_TERM`)

This PR gives the support agent write access to the customer database.

No current exploit was verified.

The Security Twin shows this expands the agent’s potential impact from read-only customer data to database modification (blast radius increases; new write paths under the agent identity).

**Trigger change:** agent tool permission `db.read` → `db.write`  
**Supporting evidence:** tool definition + twin privilege edge + sensitive asset tags on customer tables

### Security Improvements

- Restrict the tool to required tables/actions
- Require approval for writes
- Add an invariant / regression check so write scope cannot widen silently

This is **not** a confirmed vulnerability.

---
AXGuard by Awarexone / Open-source security tooling for the AI era.
```

---

## Optional Check factor panel

When the Predictive Check section is shown, explain factors — do not ship an unexplained overall alone:

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

Each non-zero factor should map to at least one predictive risk or an explicit “no change” note for zeros that readers might question.

---

## What-if wording on PRs

Counterfactuals are predictive / simulated:

```text
Current permissions: no verified exploit path from this agent to production DB writes.
What-if (grant production DB write): Twin reports N new attack paths; blast radius includes <assets>.
Required controls before granting: …
```

Never present what-if paths as verified issues.

---

## When to stay silent

Do not post predictive noise for:

- Pure refactors with no privilege / surface / trust change
- `LOW` / `UNKNOWN` signals without clear developer action
- Duplicate restatements of the same root architectural change

Silence is better than fear.

---

## Forbidden (predictive-specific)

- Mixing predictive risks into **Verified Security Issues**
- Claiming CVE prediction or timed “will be vulnerable in N days”
- Fabricating historical regressions (only Security Memory with real history)
- Opaque scores without factor explanation
- Marketing, star-begging, or upsell inside predictive sections

See also: [docs/predictive/README.md](README.md) · [docs/research/predictive-security.md](../research/predictive-security.md)
