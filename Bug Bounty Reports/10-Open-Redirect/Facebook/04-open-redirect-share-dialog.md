# Title: Facebook Open Redirect via Share Dialog

- **Platform**: Facebook Bug Bounty
- **Program**: Facebook Share Dialog
- **Severity**: Medium
- **Date**: 2022
- **Researcher**: N/A
- **Bounty**: $3,000

## Summary
An open redirect vulnerability was found in Facebook's Share Dialog feature. The `redirect_uri` parameter in the share flow did not properly validate the destination URL, allowing attackers to redirect users to arbitrary domains.

## Technical Details
The Facebook Share Dialog allows users to share content from third-party apps. The dialog accepted a `redirect_uri` parameter that would redirect the user after the sharing action was completed. The validation logic checked if the redirect URI was a subdomain of Facebook's allowed domains, but used a flawed prefix match.

The validation checked if the redirect URI *started with* `https://www.facebook.com/` or `https://m.facebook.com/`. An attacker could bypass this by registering a domain like `https://www.facebook.com.evil.com/` — since this starts with `www.facebook.com` followed by a dot, the string starts with the allowed prefix.

## Steps to Reproduce
1. Create a Facebook App
2. Initiate the Share Dialog with a crafted redirect_uri
3. Set `redirect_uri=https://www.facebook.com.evil.com/phishing-page`
4. Send the share dialog link to a victim
5. When the victim completes the sharing action, they are redirected to the phishing page

## Proof of Concept
```
https://www.facebook.com/dialog/share?
app_id=APP_ID&
display=popup&
href=https://target.com&
redirect_uri=https://www.facebook.com.evil.com/phishing-page
```

## Impact
- Phishing attacks using Facebook's trusted domain
- Bypass of URL reputation filters
- Credential theft from users who trust Facebook redirects

## Remediation
Facebook fixed the validation to use exact domain matching rather than prefix matching, ensuring the redirect URI is a legitimate Facebook domain.

## References
- https://www.facebook.com/whitehat/ (Facebook Bug Bounty - Open Redirect)
