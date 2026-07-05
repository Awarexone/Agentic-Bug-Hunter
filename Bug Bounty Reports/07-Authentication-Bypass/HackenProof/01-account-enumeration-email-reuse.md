# Title: Account Enumeration via Email Address Reuse

- **Platform**: HackenProof
- **Program**: HackenProof (self-hosted)
- **Severity**: Medium
- **Date**: 2023-03-15
- **Researcher**: abduuuu
- **Bounty**: $0 (Verified but informational)

## Summary
A broken authentication vulnerability was discovered on the HackenProof platform itself that allowed users to create multiple accounts using a single email address by manipulating the signup request. This enabled account enumeration and potential impersonation.

## Technical Details
The vulnerability existed in the user registration flow. When a user signs up, the email address was used as a unique identifier. However, by intercepting the HTTP request during registration and appending a trailing space character to the email address, the backend failed to properly trim/normalize the input. This allowed multiple accounts to be registered with what appeared to be the same email address, bypassing the uniqueness constraint.

## Steps to Reproduce
1. Navigate to the HackenProof signup page
2. Fill in registration details with a valid email address
3. Complete the registration and email verification process
4. Attempt to sign up again with the same email address but use Burp Suite to intercept the request
5. Add a trailing space character to the email parameter value
6. The system accepts the registration and sends a new verification email
7. A second account is created for what is logically the same email address

## Proof of Concept
```
POST /signup HTTP/1.1
Host: hackenproof.com
Content-Type: application/json

{"email":"user@example.com ", "password":"Password123!"}
```

## Impact
- Account enumeration: An attacker could identify which email addresses are registered
- Multiple accounts per email: Bypasses the one-account-per-user restriction
- Potential impersonation: Could lead to confusion in account recovery or support scenarios
- Violation of user identity integrity

## Remediation
- Trim whitespace from all input fields before validation
- Normalize email addresses before checking uniqueness
- Implement consistent input sanitization across all registration entry points
- Add server-side validation to strip leading/trailing whitespace

## References
- https://hackenproof.com/reports/HAC-814
