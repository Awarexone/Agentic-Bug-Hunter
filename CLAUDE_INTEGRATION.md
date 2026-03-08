# Claude Integration Guide

How to use Claude AI as your bug bounty co-pilot with this toolkit.

## Option 1 — Claude Code (Recommended)

[Claude Code](https://claude.ai/claude-code) is Anthropic's official CLI. It can read files, run commands, and use all tools in this repo automatically.

```bash
npm install -g @anthropic-ai/claude-code
cd claude-bug-bounty
claude
```

Then just talk to it:
> "Run recon on target.com and tell me what to hunt"
> "I found a potential IDOR — validate it"
> "Write a Bugcrowd report for this XSS"

## Option 2 — Claude API

```python
import anthropic

client = anthropic.Anthropic(api_key="YOUR_API_KEY")

# Read your recon output
with open("recon/target.com/urls.txt") as f:
    urls = f.read()

message = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=4096,
    messages=[{
        "role": "user",
        "content": f"""You are a senior bug bounty hunter.

Here are crawled URLs from target.com:
{urls}

Identify the top 10 endpoints most likely to have IDOR vulnerabilities.
For each, explain why and what to test."""
    }]
)

print(message.content[0].text)
```

## Option 3 — Wrap hunt.py with Claude

```python
import subprocess
import anthropic

client = anthropic.Anthropic()

# Run recon
result = subprocess.run(
    ["python3", "hunt.py", "--target", "example.com", "--recon-only"],
    capture_output=True, text=True
)

# Ask Claude what to hunt
response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=2048,
    messages=[{
        "role": "user",
        "content": f"Recon output:\n{result.stdout}\n\nWhat vulnerabilities should I hunt and in what order?"
    }]
)

print(response.content[0].text)
```

## Recommended Claude Prompts

### Pre-Hunt Research
```
Target: [company.com]
Tech stack: [React, GraphQL, AWS, JWT]
Bug bounty program: [HackerOne/Bugcrowd]

Generate a prioritized hunting checklist focusing on:
1. High-payout vulnerability classes for this tech stack
2. Common misconfigurations in this stack
3. 5 specific test cases I should manually check
```

### IDOR Hunting
```
Here are API endpoints from [target]:
[paste endpoints]

Which endpoints are highest risk for IDOR?
What object IDs should I try to swap?
What HTTP methods should I test?
```

### Finding Validation (4-Gate Check)
```
Finding: [describe vuln]
Request: [HTTP request]
Response: [HTTP response]

Run me through the 4 validation gates:
1. Is this actually a vulnerability (not by design)?
2. Is it in scope?
3. Is it a duplicate of known issues?
4. What's the realistic business impact?

Then give me a CVSS 3.1 score with justification.
```

### Report Writing
```
Write a HackerOne bug report for this finding:

Title: [one-line summary]
Vulnerability: [vuln type]
Target: [URL/endpoint]
Steps to reproduce:
1. [step]
2. [step]

Impact: [what attacker can do]

Use a professional tone. Include: summary, steps to reproduce,
supporting material section, impact assessment, suggested fix.
```
