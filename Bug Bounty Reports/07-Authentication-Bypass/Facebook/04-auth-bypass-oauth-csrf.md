# Title: Facebook OAuth Login CSRF Leads to Account Takeover

- **Platform**: Facebook Bug Bounty
- **Program**: Third-party Application using Facebook Login
- **Severity**: High
- **Date**: 2023
- **Researcher**: N/A
- **Bounty**: $5,000

## Summary
A vulnerability in Facebook's OAuth implementation for a third-party application allowed an attacker to bypass authentication and take over user accounts by exploiting a CSRF flaw in the OAuth login flow.

## Technical Details
The vulnerable application used Facebook Login for authentication. The OAuth flow worked as follows:
1. User clicks "Login with Facebook"
2. User is redirected to Facebook's OAuth dialog
3. After authorization, Facebook redirects back with a `code` parameter
4. The application exchanges the code for an access token
5. The access token is used to create/login the user

The vulnerability was that the `state` parameter (which prevents CSRF in OAuth) was not validated by the application. An attacker could:
1. Initiate their own Facebook Login flow and obtain a valid authorization code
2. Craft a login URL for the victim that uses the attacker's authorization code
3. When the victim clicks the URL and completes Facebook login, the application links the attacker's Facebook account to the victim's session

## Steps to Reproduce
1. Create a Facebook app and note the App ID
2. Initiate the Facebook Login flow on the vulnerable application
3. Intercept the redirect back from Facebook and capture the `code` parameter
4. Note that the application does not validate the `state` parameter
5. Craft a URL: `https://target.com/auth/facebook/callback?code=ATTACKER_CODE&state=ANYTHING`
6. Send this URL to the victim
7. When the victim visits, their account is linked to the attacker's Facebook profile

## Impact
- Account takeover of any user who clicks the crafted link
- Attacker gains access to all victim data and functionality

## Remediation
The third-party application implemented proper `state` parameter validation in the OAuth flow.

## References
- https://www.facebook.com/whitehat/bugs/ (Facebook Bug Bounty program)
