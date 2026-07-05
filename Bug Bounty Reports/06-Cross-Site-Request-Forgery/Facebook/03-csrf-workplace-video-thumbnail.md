# Title: Facebook Workplace CSRF - Disclose thumbnail of any video

- **Platform**: Facebook Bug Bounty
- **Program**: Facebook Workplace
- **Severity**: Medium
- **Date**: 2019
- **Researcher**: Sarmad Hassan (jubabaghdad)
- **Bounty**: $3,000

## Summary
A CSRF vulnerability in Facebook Workplace allowed attackers to disclose the thumbnail of any video in a Workplace group by crafting a malicious request that bypassed CSRF protections.

## Technical Details
Facebook Workplace's video sharing feature had a CSRF vulnerability that allowed attackers to perform actions on behalf of authenticated users. The video thumbnail generation endpoint lacked proper CSRF protection, enabling an attacker to force a victim to disclose or interact with videos they shouldn't have access to.

The vulnerability existed in the graph API endpoint that handled video thumbnail operations. By crafting a malicious page with an auto-submitting form, an attacker could trick a Workplace user into triggering actions on videos in their Workplace groups.

## Steps to Reproduce
1. Create a Workplace group and upload a video as admin
2. Identify the video ID and the thumbnail endpoint
3. Note that the endpoint accepts GET requests without CSRF token validation
4. Craft a URL that triggers the thumbnail disclosure for the video
5. Create a CSRF PoC page hosting this URL
6. Send the PoC to the victim
7. When the victim visits, the request executes with their authentication

## Proof of Concept
```html
<img src="https://graph.facebook.com/video/VIDEO_ID/thumbnail" 
     style="display:none" />
```

## Impact
Unauthorized disclosure of video thumbnails from Workplace groups, potentially leaking sensitive visual information about workplace communications.

## Remediation
Facebook fixed the issue by adding proper CSRF protection to the video thumbnail endpoints, including CSRF token validation for all video-related operations.

## References
- https://bugreader.com/jubabaghdad@disclose-thumbnail-of-any-video-in-facebook-workplace-87
