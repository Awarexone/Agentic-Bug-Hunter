# Title: Authentication Bypass via Forgot Password Token Predictability

- **Platform**: Google VRP
- **Program**: Google Cloud Console
- **Severity**: High
- **Date**: 2021
- **Researcher**: N/A
- **Bounty**: N/A

## Summary
A vulnerability was discovered in the forgot password flow where the password reset token was generated using predictable values (timestamp-based), allowing an attacker to enumerate and predict reset tokens for any user and gain unauthorized access.

## Technical Details
The password reset flow for a Google Cloud feature worked as follows:
1. User requests a password reset for their email
2. Server generates a 32-character hex token using `md5(timestamp + user_id)`
3. Token is sent via email in a link: `https://console.cloud.google.com/reset?token=TOKEN`
4. User clicks the link and can set a new password

Since the token was generated using a predictable timestamp and the user ID could be enumerated, an attacker could:
1. Request a password reset for themselves to capture the token generation pattern
2. Use the pattern to predict tokens for other users
3. Access the password reset page and set a new password

## Steps to Reproduce
1. Create two test accounts on the platform
2. Request password reset for account A; note the timestamp
3. Receive the reset email and capture the token
4. Compare the token with `md5(timestamp + user_id)` to confirm the pattern
5. Request password reset for target user (account B)
6. Predict the token based on the timestamp pattern
7. Access the reset URL with the predicted token
8. Set a new password and log in

## Proof of Concept
```python
import hashlib, time

# Predict reset token
base_time = int(time.time())
for offset in range(-5, 5):
    token_input = str(base_time + offset) + "target_user_id"
    predicted_token = hashlib.md5(token_input.encode()).hexdigest()
    print(f"Trying {predicted_token}")
```

## Impact
- Complete account takeover via predictable password reset tokens
- Access to Google Cloud resources and data
- Potential privilege escalation within the organization

## Remediation
Google fixed the issue by implementing cryptographically secure random tokens (using `secrets.token_urlsafe()`) and adding rate limiting to the password reset flow.

## References
- https://bughunters.google.com/ (Google VRP - Password Reset category)
