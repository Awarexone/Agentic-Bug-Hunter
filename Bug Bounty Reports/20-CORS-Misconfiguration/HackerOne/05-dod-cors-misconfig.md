# Title: CORS Misconfiguration in U.S. Department of Defense Login Page

- **Platform**: HackerOne
- **Program**: U.S. Dept Of Defense VDP
- **Severity**: Medium
- **Date**: November 11, 2022
- **Researcher**: deepvvm
- **Bounty**: N/A

## Summary
A CORS misconfiguration was found on a U.S. Department of Defense application's login page at `/accounts/login/`. The server reflected arbitrary origins in the `Access-Control-Allow-Origin` header with `Access-Control-Allow-Credentials: true`, potentially allowing attackers to exfiltrate sensitive authentication-related data.

## Technical Details
The DoD application's login endpoint responded with permissive CORS headers. When sending a request with `Origin: evil.com`, the server returned `Access-Control-Allow-Origin: evil.com` with credentials enabled. This misconfiguration allowed attacker-controlled domains to make cross-origin requests to the login page.

## Steps to Reproduce
1. Navigate to the DoD login page
2. Intercept the POST request to `/accounts/login/`
3. Change the `Origin` header to `evil.com`
4. Observe the permissive CORS response

## Proof of Concept
```
Request:
POST /accounts/login/ HTTP/1.1
Host: ██████
Origin: evil.com
Cookie: csrftoken=JvozZTiwMukzgt7inOPsCLhG2hVTT98qt7mybOSNtumWh0D3w9xIJS4cOePatlet
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0

Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: evil.com
Access-Control-Allow-Credentials: true
```

## Impact
Potential exfiltration of sensitive data from a U.S. government system. An attacker could craft a malicious page that, when visited by an authenticated user, would send cross-origin requests to the DoD application and exfiltrate the response to the attacker's server.

## Remediation
Remove the permissive CORS policy from the login endpoint. Government applications should have explicit origin whitelists. Never set `Access-Control-Allow-Credentials: true` with a dynamically reflected origin.

## References
- https://hackerone.com/reports/1771149
