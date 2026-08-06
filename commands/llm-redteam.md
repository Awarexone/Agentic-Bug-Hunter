---
description: LLM red-team corpus runner — fires categorized prompt-injection / jailbreak / system-prompt-leak / data-exfil / indirect-injection / guardrail-bypass payloads at a chat endpoint and canary-detects which land. Usage: /llm-redteam --url <chat-endpoint> --field message [--category jailbreak]
---

# /llm-redteam

Automated LLM/agentic red-teaming. Instead of hand-firing one prompt-injection
at a time, this runs a categorized corpus against a chat endpoint and uses a
**canary token** to reliably detect which payloads succeeded.

## Usage

```
# simple endpoint that takes {"message": "..."}
/llm-redteam --url https://t/api/chat --field message

# only one category
/llm-redteam --url https://t/api/chat --field message --category jailbreak

# OpenAI-style body + nested response path
/llm-redteam --url https://t/api/chat \
  --template '{"messages":[{"role":"user","content":"{{PAYLOAD}}"}]}' \
  --response-path choices.0.message.content
```

Run directly:

```bash
tools/llm_redteam.py --url https://t/api/chat --field message --json
tools/llm_redteam.py --list-categories
```

## Categories (OWASP LLM Top 10 / ASI)

| Category | Tests | OWASP |
|---|---|---|
| `prompt-injection` | direct instruction override | LLM01 |
| `jailbreak` | DAN / developer-mode persona escape | LLM01 |
| `system-prompt-leak` | extract the hidden system prompt | LLM07 |
| `data-exfil` | markdown-image beacon to attacker host | LLM02/LLM06 |
| `indirect-injection` | payload framed as a retrieved document | LLM01 (indirect) |
| `guardrail-bypass` | base64 / split-instruction filter evasion | LLM01 |

## How detection works

Most payloads instruct the model to emit a unique token (`RT_PWNED_xxxx`). If
that token appears in the response, the injection landed — far more reliable
than keyword matching. System-prompt-leak uses a multi-signal heuristic;
`data-exfil` confirms when the canary URL is reflected in the output.

`--header "Authorization: Bearer ..."` (repeatable) for authed chatbots.

## Turn a hit into a report

A bare prompt-injection is **Informational** until chained. Escalate:
injection → **chatbot IDOR** (read another user's data), **data exfil** (the
markdown-beacon hit proves a working channel), or **RCE** if the agent has a
code/tool execution capability. See `skills/web2-vuln-classes` §11 and
`skills/bug-bounty` Agentic AI (ASI01–ASI10).
