# Title: Race Condition to Premium Feature Bypass in Add User Function

- **Platform**: Zerocopter
- **Program**: Private Zerocopter Program (Dutch Online Services Company)
- **Severity**: High
- **Date**: September 2020 (reported), October 2020 (bounty awarded)
- **Researcher**: Lütfü Mert Ceylan
- **Bounty**: €€€ (monetary reward)

## Summary

A race condition vulnerability was discovered in a private bug bounty program managed through Zerocopter. The target was a Dutch online services company. The "Add User" function, which was restricted to premium (€500/year) accounts allowing only one user in the free tier, was vulnerable to a race condition attack. By sending concurrent requests using Turbo Intruder, the researcher could bypass the user limit and add an unlimited number of users to a test group with a free account.

## Technical Details

The researcher had previously identified that the application had no rate limiting on API endpoints. This laid the foundation for a race condition exploit. The "Add User" function was designed to enforce a limit: free accounts could add only 1 user to a group, while premium accounts (worth ~€500/year) could add unlimited users.

The race condition existed because the server performed a read-check-update sequence without proper locking:

1. Read current user count from database
2. Check if count exceeds the limit
3. Increment count and add the user

By sending multiple concurrent requests, several threads could pass the check (step 2) before any of them completed the increment (step 3), allowing the limit to be exceeded.

## Steps to Reproduce

1. Sign up for a free account on the target platform
2. Log in and navigate to the "Add User" function for a test group
3. Configure Burp Suite with Turbo Intruder extension
4. Capture the "Add User" request
5. Send the Python Turbo Intruder script with multiple concurrent threads
6. Observe that the user counter goes negative (e.g., -22), indicating the race condition was successful
7. Verify that more users were added than the free tier limit allows

## Proof of Concept

The researcher used the following Turbo Intruder script template:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for i in range(50):
        engine.queue(target.req, i)
        # Small delay to ensure concurrent window
        time.sleep(0.01)

def handleResponse(req, interesting):
    if 'success' in req.response or '200' in req.response:
        table.add(req)
```

After execution, the user limit counter showed `-22`, confirming that 23 users were added (1 original + 22 extra) to a free account that should have been limited to 1 user. The counter went negative because the subtraction logic assumed only 1 user existed but the race condition caused the count to overflow.

## Impact

- Free users could access premium features worth €500/year
- Unlimited user creation in test groups
- Financial loss for the platform (premium subscription bypass)
- Potential for larger-scale abuse by adding thousands of users
- Indication of deeper systemic race condition issues across other functions

## Remediation

- Implement database-level locking (e.g., SELECT ... FOR UPDATE or optimistic locking)
- Use atomic operations for increment/decrement of user counts
- Enforce rate limiting on all API endpoints
- Move business logic to server-side transactions with proper isolation levels
- Conduct thorough race condition testing across all limit-enforcement functions

## References

- https://lutfumertceylan.com.tr/posts/race-condition-limit-bypass/
