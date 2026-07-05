# Title: Information Disclosure in /skills call

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: High
- **Date**: December 6, 2016
- **Researcher**: deepankerchawla
- **Bounty**: $10,000

## Summary
A critical information disclosure vulnerability in HackerOne's new "Skills" feature allowed hackers to view the report titles that other hackers had submitted as proof of their skills, potentially leaking confidential bug report information.

## Technical Details
HackerOne launched a new "Skills" feature that allowed hackers to apply for skill sets and receive tailored invitations for private programs. Hackers submitted reports as proof of their skills. However, due to an incorrectly written database query, the proof (including report titles) was exposed to all other hackers that applied for the same skill set.

The vulnerability was in the `/settings/skills` API endpoint. When a user viewed their skills page, the response included the titles of reports submitted by all other hackers for the same skill set, not just their own.

Notably, only report titles of fixed vulnerability reports could have been exposed, and only those submitted as proof. HackerOne awarded a $10,000 bounty because report titles could contain sensitive information about the vulnerability and the affected program.

## Steps to Reproduce
1. Apply for a skill set on HackerOne
2. Submit a report as proof of skill
3. View the `/settings/skills` page
4. Observe that the API response includes report titles from other hackers who applied for the same skill set
5. These titles could reveal vulnerability details and program names

## Proof of Concept
```
GET /settings/skills HTTP/1.1
Host: hackerone.com
Cookie: <session>

Response includes:
{
  "skills": [
    {
      "name": "SQL Injection",
      "proofs": [
        {"report_title": "SQL injection on *.example.com leading to data leak"},
        {"report_title": "Blind SQLi in login parameter at company.com"}
      ]
    }
  ]
}
```

## Impact
Hackers could see the titles of vulnerability reports submitted by other researchers. These titles could contain:
- The affected program or company name
- Details about the vulnerability type
- Potentially sensitive information about unpatched issues
- This could lead to duplicate submissions or premature disclosure

## Remediation
HackerOne fixed the issue within hours by correcting the database query to only return the current user's report submissions, not all submissions for the skill set. The Skills feature was temporarily disabled during the rollout.

## References
- https://hackerone.com/reports/188719
