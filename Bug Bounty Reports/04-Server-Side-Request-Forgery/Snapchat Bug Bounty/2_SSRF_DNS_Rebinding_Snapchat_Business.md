# Title: SSRF via DNS Rebinding on Snapchat Business Platform Leads to Cloud Metadata Exfiltration

- **Platform**: Snapchat Bug Bounty
- **Program**: Snapchat (HackerOne)
- **Severity**: Critical
- **Date**: 2019 (publicly disclosed)
- **Researcher**: nahamsec, daeken, ziot
- **Bounty**: $12,500 (combined across multiple findings)
- **Report**: https://hackerone.com/reports/530974

## Summary

Researchers discovered a Server-Side Request Forgery (SSRF) vulnerability in Snapchat's Business platform (business.snapchat.com). The "Import" feature in the Creative Library fetched and executed JavaScript from user-supplied URLs. By combining this with a DNS rebinding attack, the researchers were able to bypass validation and access Google Cloud's metadata service (169.254.169.254), extracting SSH keys, service account tokens, and internal credentials.

## Technical Details

The vulnerability was located in the Creative Library feature at `https://business.snapchat.com/`. The "Import" function allowed users to import images for ad creatives by providing a URL. The service would fetch the URL using Puppeteer/Chrome, and crucially, would execute JavaScript from the fetched page.

The researchers used a multi-stage DNS rebinding attack:

1. **Initial Setup**: Registered a domain and configured its nameserver to point to a server they controlled
2. **First Resolution**: The domain initially resolved to the attacker's server IP, passing Snapchat's URL validation checks
3. **DNS Rebinding**: After validation passed, the DNS record was changed to point to `169.254.169.254` (Google Cloud's metadata service IP)
4. **Execution**: Snapchat's Chrome instance executed JavaScript from what it believed was the attacker's server, but was now the metadata service
5. **Exfiltration**: The JavaScript extracted metadata including SSH keys and service account credentials

The TTL on the DNS record was set to 0, ensuring the second resolution would not be cached.

## Steps to Reproduce

1. Register a domain (e.g., `attacker.com`) and point it to your server
2. Set up a nameserver with a custom DNS response that can switch between IPs
3. Initially point to your server's IP (e.g., `1.2.3.4`) with TTL=0
4. Access Snapchat Business → Creative Library → New Creative → Replace → Import
5. Submit your domain URL to the import feature
6. Snapchat validates the URL resolves to `1.2.3.4` (external IP — passes validation)
7. Immediately switch DNS to resolve to `169.254.169.254`
8. Snapchat's Chrome fetches the URL again (TTL=0 forces re-resolution)
9. Chrome now receives content from the metadata service
10. JavaScript from the metadata response executes in Snapchat's infrastructure

## Proof of Concept

The attack used the `httprebind` tool (created by daeken) to automate the DNS rebinding process:

```bash
sudo python httprebind.py attacker.com server_ip gcloud
```

The attackers set up a page that, when fetched by Snapchat's Chrome:

1. First load: served benign JavaScript from the attacker's server
2. After DNS rebind: made requests to the metadata endpoint `http://169.254.169.254/computeMetadata/v1/`
3. Used the `X-Google-Metadata-Request: True` header to bypass metadata service protection
4. Exfiltrated `/computeMetadata/v1/instance/service-accounts/default/token` and SSH keys

## Impact

- Extraction of SSH keys for production and development instances
- Service account tokens with cloud API access
- Internal network and infrastructure information
- Development environment credentials with access to internal systems
- Potential pivot from cloud metadata to full infrastructure compromise

## Remediation

- Switch from DNS-based URL validation to IP-based validation (resolve once, validate the IP, then connect directly to that IP)
- Implement iptables rules to block outbound traffic to metadata service IP ranges (169.254.169.0/24)
- Use a dedicated egress proxy (e.g., Smokescreen by Stripe) that enforces IP restrictions at the connection layer
- Disable JavaScript execution in headless Chrome when fetching external resources
- Enable IMDSv2 on cloud instances (requires session token for metadata access)

## References

- https://hackerone.com/reports/530974
- https://infosecwriteups.com/the-12-500-dns-trick-that-hacked-snapchats-cloud-servers-0cb299ec1d37
- https://github.com/daeken/httprebind
- https://cybernoz.com/spotlight-on-the-server-side-hackerone/
