# Title: Second Order IDOR — Access Other Users' Children's Meal Plans

- **Platform**: Intigriti
- **Program**: Private Program (Diet/Nutrition Platform)
- **Severity**: High
- **Date**: 2025-02-10
- **Researcher**: MR YOGii (Yogesh Kumar)
- **Bounty**: Undisclosed

## Summary
A second-order insecure direct object reference vulnerability was discovered in a nutrition/diet platform on Intigriti. By manipulating the `selectChildVal` parameter during account switching, the researcher could access and modify meal plans belonging to other users' children.

## Technical Details
The application allowed parents to create diet plans for themselves and their children. The feature used an account-switching mechanism where a parent could switch between their own profile and their children's profiles.

The researcher noticed that the request to switch between child accounts contained a parameter called `selectChildVal`. When switching between their own children, the response simply returned `true`. The researcher tested whether this parameter could be manipulated to access other users' children.

By intercepting the request and changing `selectChildVal` to another parent's child ID (discovered through information disclosure elsewhere in the application), the application returned the diet plan for that victim's child. The server never verified that the child ID belonged to the authenticated user.

This was a "second-order" IDOR because the child selection was stored server-side and used for subsequent requests, rather than being sent with every request. The initial switch request set the context, and all subsequent operations would operate on that selected child.

## Steps to Reproduce
1. Log into the platform as a parent with two child accounts
2. Click to switch between child accounts and intercept the request
3. Observe the `selectChildVal` parameter with the child ID
4. Change the `selectChildVal` to another user's child ID (obtained via info disclosure or enumeration)
5. Forward the modified request
6. The application now operates on the victim's child profile
7. Create, view, or modify meal plans for the victim's child

## Proof of Concept
```
POST /switch-child HTTP/1.1
Host: nutrition-platform.com
Cookie: session=valid_session
Content-Type: application/x-www-form-urlencoded

selectChildVal=victim_child_id_42
```

Response: `true`

Subsequent requests to view or modify meal plans now operate on the victim's child account.

## Impact
- Unauthorized access to other users' children's meal plans
- Modification of diet plans (potentially dangerous health implications)
- Privacy violation of family health data
- Viewing sensitive nutritional and health information
- The vulnerability affected the core functionality of the application

## Remediation
The program fixed the vulnerability by implementing proper authorization checks on the child account switching mechanism. The server now validates that the authenticated user is actually the parent or guardian of the specified child before allowing access.

## References
- https://medium.com/@mr_yogii/how-i-found-second-order-idor-and-earned-a-reward-e3d779b8a90b
