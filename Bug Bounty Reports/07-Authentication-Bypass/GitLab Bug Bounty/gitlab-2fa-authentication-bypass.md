# Title: Bypassing Password Authentication of Users That Have 2FA Enabled

- **Platform**: GitLab Bug Bounty
- **Program**: GitLab
- **Severity**: Critical
- **Date**: 2016-04-04
- **Researcher**: jobert
- **Bounty**: N/A (acknowledged)

## Summary

A critical authentication bypass vulnerability allowed an attacker to sign in to any GitLab account that had Two-Factor Authentication (2FA) enabled, without knowing the account's password. The attacker only needed to know the victim's username.

## Technical Details

When a user with 2FA enabled attempted to log in, GitLab's authentication flow set the user's ID in `session[:otp_user_id]` after the first stage (username/password). The 2FA token entry page then used this session value to identify which account to log in to upon successful OTP verification.

The flaw was that the 2FA verification request included a `user[login]` parameter that was not properly validated. By manipulating this parameter during the 2FA step, an attacker could substitute a different username, effectively telling the server to complete authentication for a different account.

## Steps to Reproduce

1. Attacker (Jane) has a valid GitLab account with 2FA enabled
2. Attacker navigates to the sign-in page and enters her own username and password
3. The server sets Jane's user ID in `session[:otp_user_id]`
4. Attacker is prompted for the 2FA OTP code
5. Using Burp Suite or similar proxy, intercept the 2FA token submission request
6. Add an extra form parameter `user[login]` with the victim's username (John)
7. Submit Jane's valid 2FA code

The server processes the request, sees `user[login]=john`, and completes the authentication for John's account instead of Jane's.

## Proof of Concept

```http
POST /users/sign_in HTTP/1.1
Host: gitlab.target.com
...

Content-Disposition: form-data; name="user[otp_attempt]"
212421
Content-Disposition: form-data; name="user[login]"
john
```

## Impact

- Complete account takeover of any GitLab user with 2FA enabled
- Access to private repositories, projects, and sensitive data
- Ability to perform actions as the victim user
- No password required - only knowledge of the username

## Remediation

GitLab resolved this within 2 days of the report. The fix was released in GitLab version 8.6.5. The commit `00da609cfd8bf1105fe433dfc92ab263d6205eaf` addressed the issue by ensuring the `user[login]` parameter could not override the authenticated session during OTP verification.

## References
- https://hackerone.com/reports/128085
- https://gitlab.com/gitlab-org/gitlab-ce/commit/00da609cfd8bf1105fe433dfc92ab263d6205eaf
