# Title: Bypassing HackerOne 2FA Due to Race Condition

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: Critical
- **Date**: 2024
- **Researcher**: Akash Hamal
- **Bounty**: N/A

## Summary
A race condition vulnerability in HackerOne's two-factor authentication (2FA) reset process allowed an attacker to bypass 2FA on any HackerOne account. By sending multiple simultaneous reset confirmation requests, the 2FA could be disabled without proper authentication.

## Technical Details
HackerOne's 2FA reset flow involves entering email+password, clicking "Reset two-factor authentication," receiving a confirmation email, and waiting 24 hours for the reset to process. Alert emails are sent during this period to notify the user. However, the race condition allowed an attacker to exploit the timing of the reset confirmation, bypassing the intended security controls.

## Steps to Reproduce
1. Go to HackerOne login page and enter target's email and password
2. Click "Reset two-factor authentication" link
3. Click OK on the confirmation prompt
4. Intercept the reset confirmation request
5. Send multiple simultaneous requests
6. The 2FA reset is processed without proper verification

## Proof of Concept
```
POST /users/reset_two_factor_auth HTTP/1.1
Host: hackerone.com
Cookie: <session>

// Send parallel requests simultaneously
// Race condition causes 2FA to be disabled
```

## Impact
Complete account takeover. An attacker who knows a target's email and password but is blocked by 2FA can disable it without access to the 2FA device or backup codes. This compromises all accounts with known credentials but 2FA protection.

## Remediation
Implement idempotency controls on the 2FA reset endpoint. Use database-level transactions to ensure the reset can only be processed once. Require re-authentication or confirmation via the registered 2FA method before allowing reset.

## References
- https://hackerone.com/reports/2598548
- https://akashhamal0x01.medium.com/bypassing-hackerone-2fa-due-to-race-condition-8afe2dbff7c9
