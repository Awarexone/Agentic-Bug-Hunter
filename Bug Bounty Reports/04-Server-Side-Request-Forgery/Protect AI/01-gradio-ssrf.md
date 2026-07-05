# Title: Server-Side Request Forgery in gradio-app/gradio save_url_to_cache

- **Platform**: Protect AI (huntr)
- **Program**: gradio-app/gradio (Open Source Bug Bounty)
- **Severity**: High
- **Date**: 2024-09-10
- **Researcher**: huntr community member
- **Bounty**: Not disclosed

## Summary
A Server-Side Request Forgery (SSRF) vulnerability was discovered in gradio-app/gradio, a popular Python library for building machine learning demos. The `save_url_to_cache` function failed to properly validate the URL path parameter, allowing an attacker to make unauthorized HTTP requests to internal services.

## Technical Details
The `save_url_to_cache` function in gradio accepts a URL as input and fetches the resource to cache it locally. The function did not properly validate or sanitize the URL parameter, allowing an attacker to specify internal IP addresses (e.g., 127.0.0.1, 10.0.0.0/8, 169.254.169.254) or file:// protocol URLs. This enabled the server to make requests to internal services that should not be accessible from the outside.

## Steps to Reproduce
1. Deploy a gradio application with the file upload/cache feature enabled
2. Send a request with a URL pointing to an internal service
3. Observe that the server fetches the internal resource

## Proof of Concept
```python
# Malicious request to save_url_to_cache
import requests

url = "http://169.254.169.254/latest/meta-data/"  # AWS metadata
# or
url = "http://127.0.0.1:8080/admin"

response = requests.post("https://gradio-app.com/upload", json={"url": url})
print(response.text)
```

## Impact
- Access to internal cloud metadata services (AWS, GCP, Azure)
- Port scanning of internal network
- Access to internal APIs and admin interfaces
- Potential credential exposure from internal services
- Data exfiltration from internal systems

## Remediation
- Implement URL validation with an allowlist of permitted domains/schemes
- Block requests to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Block metadata IPs like 169.254.169.254
- Disable file:// and other non-HTTP protocols
- Use a DNS-based blocklist for internal hostnames

## References
- https://sightline.protectai.com/vulnerabilities/e74b6a9b-9ddb-496a-8dfa-d374311209eb
- https://protectai.com/threat-research/september-vulnerability-report
