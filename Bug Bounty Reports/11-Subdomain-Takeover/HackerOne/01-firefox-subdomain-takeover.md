# Title: Subdomain takeover on a subdomain under firefox.com

- **Platform**: HackerOne
- **Program**: Mozilla
- **Severity**: High
- **Date**: 2025-07-03
- **Researcher**: RedTeam Security
- **Bounty**: N/A

## Summary
A subdomain takeover vulnerability was discovered on a subdomain under firefox.com. The subdomain was configured with a CNAME record pointing to a cloud service that had been decommissioned, allowing an attacker to claim the subdomain and serve arbitrary content.

## Technical Details
The subdomain was a CNAME pointing to an external cloud platform service. When the target cloud resource was deactivated or deleted, the DNS record remained active. The CNAME resolved to a domain that was available for registration on the third-party platform. By registering the resource on the same platform and configuring the appropriate CNAME mapping, an attacker could fully control the subdomain's content.

## Steps to Reproduce
1. Identify dangling DNS records using subdomain enumeration tools (Sublist3r, Amass, etc.)
2. Verify the CNAME target is unclaimed by checking if the resource can be registered
3. Register the resource on the target platform (e.g., cloud service, Heroku, GitHub Pages)
4. Configure the platform to serve content on the claimed subdomain
5. Confirm control by accessing the subdomain in a browser

## Proof of Concept
```
$ dig CNAME vulnerable-subdomain.firefox.com

vulnerable-subdomain.firefox.com. 300 IN CNAME decommissioned-service.herokuapp.com.

$ curl -I https://decommissioned-service.herokuapp.com
HTTP/1.1 404 Not Found

# Registered the Heroku app name and deployed a PoC page
$ heroku create decommissioned-service
$ echo "<h1>PoC - Subdomain Takeover</h1>" > index.html
$ git push heroku main
$ curl https://vulnerable-subdomain.firefox.com
<h1>PoC - Subdomain Takeover</h1>
```

## Impact
An attacker could host phishing pages, steal cookies, distribute malware, or perform SEO hijacking on a trusted Mozilla subdomain. Since the subdomain resides under firefox.com, browsers trust it, making social engineering attacks highly effective.

## Remediation
Mozilla deleted the dangling DNS record and implemented a process to audit DNS entries when decommissioning cloud resources. They also added automated monitoring for orphaned DNS records.

## References
- https://hackerone.com/reports/2899858
