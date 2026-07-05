# Title: IDOR on HackerOne Embedded Submission Form — $2,500 Bounty

- **Platform**: HackerOne
- **Program**: HackerOne Bug Bounty Program
- **Severity**: Medium
- **Date**: 2024-04-30
- **Researcher**: Japz Divino
- **Bounty**: $2,500

## Summary
An insecure direct object reference vulnerability was discovered in HackerOne's embedded submission form. By manipulating UUIDs found through Wayback Machine archives, the researcher could access sensitive information from private programs, including intro text, response efficiency percentages, and structured scopes.

## Technical Details
HackerOne allows programs to create embedded submission forms that can be placed on external websites. Each form has a unique UUID. These forms reveal program information when accessed, including:
- Program intro text and description
- Response efficiency metrics
- Structured scope details (what's in/out of scope)

The researcher used the Wayback Machine (`waybackurls`) to find old, disabled, or inactive embedded submission form UUIDs. Even when the program disabled the form, the UUID endpoint would still return sensitive program information if accessed directly. This meant that information from private programs was accessible without authentication.

The key insight was that even after a program deleted or disabled their embedded submission form, the API endpoint for that UUID would still return program details. This violated the expectation that disabling the form would prevent access.

## Steps to Reproduce
1. Run waybackurls on hackerone.com: `echo 'https://hackerone.com/' | waybackurls > urls.txt`
2. Filter for embedded submission URLs: `grep embedded_submissions urls.txt`
3. Find UUIDs of private programs' forms (including disabled/deleted ones)
4. Access: `https://hackerone.com/embedded_submissions/<uuid>`
5. View the program's sensitive information in the response

## Proof of Concept
Using waybackurls to discover UUIDs:
```bash
echo 'https://hackerone.com/' | waybackurls | grep -i "embedded_submissions" > results.txt
cat results.txt | grep -oP '[a-f0-9-]{36}' > uuids.txt
```

Each UUID could be accessed at:
```
https://hackerone.com/embedded_submissions/<uuid>
```

Even inactive/disabled forms returned program details.

## Impact
- Access to private program sensitive information
- Disclosure of response efficiency percentages (business metrics)
- Viewing structured scope details of private programs
- Ability to discover program participation without authorization
- Information gathering that could aid in targeting private programs

## Remediation
HackerOne fixed the vulnerability by ensuring that disabled or deleted embedded submission forms no longer return program details. The API now properly checks the form status before returning sensitive information. The platform standards were also clarified regarding UUID predictability.

## References
- https://blog.bugbountyhunter.xyz/idor-on-hackerone-embedded-submission-form-9e59c6f044b3
