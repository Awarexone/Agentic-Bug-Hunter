# Title: Business Logic Flaw - Non-Premium User Can Change/Update Retailers for Cashback

- **Platform**: HackerOne
- **Program**: Curve
- **Severity**: Medium
- **Date**: August 13, 2019
- **Researcher**: praseudo7
- **Bounty**: N/A

## Summary
A business logic flaw in the Curve Android application allowed non-premium users to change/update their selected retailers for cashback rewards. Non-premium users are limited to 3 retailers, but a logic flaw allowed them to swap retailers freely, effectively giving access to all available cashback offers.

## Technical Details
Curve's "Earn curve cash" feature allows users to select retailers for cashback. Premium users can select 6+ retailers while non-premium users are limited to 3. The API endpoint for updating retailers lacked proper validation of the user's subscription tier, allowing non-premium users to call the update endpoint.

## Steps to Reproduce
1. Login as a non-premium user
2. Navigate to "Earn curve cash" and select 3 retailers, confirm selection
3. Go back to the feature and capture the request/response
4. Notice the GET request to merchants endpoint
5. Modify the request to update retailers with new selections
6. Non-premium restrictions are bypassed

## Proof of Concept
```
GET /v1/rewards/users/programs/e329e463-7f5d-4358-9109-4f97c9f86abd/merchants HTTP/1.1
Host: api.curve.com
Curve-UserAgent: Android;Genymotion;Custom Phone
Authorization: Bearer <non_premium_token>

Response includes ability to update merchant selection despite non-premium status
```

## Impact
Financial loss to the platform as non-paying users can access premium features. Unauthorized benefit from cashback programs designed for premium subscribers only.

## Remediation
Implement server-side validation of user subscription tier on the merchants update endpoint. The API should verify premium status before allowing retailer changes beyond the initial selection.

## References
- https://hackerone.com/reports/672487
