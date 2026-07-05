# Title: Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: Medium (CVSS 5.0)
- **Date**: October 4, 2018
- **Researcher**: japz
- **Bounty**: $10,000 ($2,500 + $7,500 for related finding)

## Summary
A critical authentication bypass vulnerability allowed hackers to bypass the two-factor authentication (2FA) requirement enforced by certain programs and also bypass the reporter blacklist through the embedded submission form.

## Technical Details
HackerOne allows program owners to require that reporters have 2FA enabled before submitting reports. The embedded submission form (used by programs to receive reports from external pages) did not properly validate the 2FA requirement or blacklist restrictions. By directly interacting with the API endpoints used by the embedded form, an attacker could submit reports without having 2FA enabled and even if their account was blacklisted by the program.

During the investigation, HackerOne also discovered that the vulnerability allowed an attacker to gain access to other users' attachments who were writing reports at the same time (CVSS 7.1), for which the researcher received an additional $7,500.

## Steps to Reproduce
1. Identify a program that enforces 2FA requirement for reporters
2. Note that the embedded submission form bypasses the 2FA check
3. Craft API requests that mimic the embedded form submission
4. Submit a report without having 2FA enabled
5. The report is accepted despite the 2FA requirement
6. Also test with a blacklisted account - the submission is also accepted

## Proof of Concept
The embedded submission form endpoint did not properly validate the same restrictions enforced on the main HackerOne platform. By sending specially crafted requests, a user without 2FA could submit reports to programs requiring 2FA.

```
POST /api/embedded/submissions HTTP/1.1
Host: hackerone.com
...
```

## Impact
- Bypass of security controls put in place by program owners
- Blacklisted reporters could continue submitting to programs
- Users without 2FA could submit to programs requiring 2FA
- The related attachment access vulnerability could leak confidential bug report information

## Remediation
HackerOne fixed the embedded submission form to properly validate all program-level security requirements including 2FA enforcement and blacklist checks. The attachment access issue was also patched.

## References
- https://hackerone.com/reports/418767
- https://medium.com/japzdivino/bypass-hackerone-2fa-requirement-and-reporter-blacklist-46d7959f1ee5
