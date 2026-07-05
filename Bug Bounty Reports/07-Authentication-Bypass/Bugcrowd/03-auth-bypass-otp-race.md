# Title: Authentication Bypass via OTP Race Condition

- **Platform**: Bugcrowd
- **Program**: Indian Fintech Platform
- **Severity**: Critical
- **Date**: 2024
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
An authentication bypass was discovered in a fintech platform's OTP-based login system. The OTP validation endpoint had a race condition that allowed an attacker to bypass the one-time password check and authenticate as any user.

## Technical Details
The application used email-based OTP for login. When a user requested an OTP, the server generated a 6-digit code and sent it via email. The validation endpoint `/api/auth/verify-otp` accepted the OTP and user identifier. 

A race condition existed because the OTP was validated in a non-atomic manner: the server first checked if the OTP was correct, then marked it as used. By sending multiple concurrent requests with the same incorrect OTP immediately after requesting a legitimate one, one of the requests would pass through during the time window between validation and invalidation.

## Steps to Reproduce
1. Request an OTP for the victim's email address
2. Intercept the request and note the session token
3. Send 50-100 concurrent requests to the OTP validation endpoint with arbitrary OTP values
4. Due to the race condition, one request may be accepted before the OTP is marked as used
5. If successful, the response contains an authentication token for the victim's account

## Proof of Concept
```bash
# Using curl in a bash loop
for i in {1..100}; do
  curl -s "https://target.com/api/auth/verify-otp" \
    -d "email=victim@example.com&otp=000000&session=TOKEN" &
done
wait
```

## Impact
- Complete account takeover without knowing the victim's OTP
- Access to financial data, transactions, and personal information
- Ability to perform unauthorized transactions

## Remediation
The platform implemented atomic OTP validation using database-level locking and added rate limiting to the verification endpoint.

## References
- https://bugcrowd.com/otp-race-condition-authentication-bypass
