# Title: $10,800 Business Impact Bug: Race Condition + Broken Access Control

- **Platform**: Medium
- **Program**: Private Program
- **Severity**: Critical
- **Date**: 2025
- **Researcher**: Abhishek Gupta
- **Bounty**: $10,800

## Summary
A combination of race condition and broken access control led to a business-impact vulnerability worth $10,800. The vulnerability allowed unauthorized access to premium features and data manipulation through concurrent request exploitation.

## Technical Details
The researcher found a private program through Google dorking. The product had a race condition in a feature that processed financial transactions. By sending concurrent requests, the validation that checked account balances and limits was bypassed. The broken access control component allowed the race condition to be exploited across different user roles and account tiers.

## Steps to Reproduce
1. Identify target through Google dorking
2. Map out the application's transaction flow
3. Find the endpoint that processes financial transactions
4. Intercept the transaction confirmation request
5. Use race condition tool (Turbo Intruder) to send parallel requests
6. Observe that multiple transactions succeed despite balance limits

## Proof of Concept
```
POST /api/v1/transactions/create HTTP/1.1
Host: target.com
Authorization: Bearer <token>
Content-Type: application/json

{
  "amount": 1000,
  "currency": "USD",
  "recipient": "attacker_account"
}

// Send 10 requests simultaneously
// All succeed despite balance of only 1000
// 10,000 deducted from source
```

## Impact
Direct financial loss through unauthorized transactions. Business logic bypass allowed exploitation of pricing tiers and feature restrictions. Combined with broken access control, attackers could access admin-level functionality.

## Remediation
Implement proper database-level locking for financial transactions. Use idempotency keys to prevent duplicate transaction processing. Fix access control by implementing server-side authorization checks for all operations.

## References
- https://infosecwriteups.com/how-i-found-a-10-800-business-impact-bug-race-condition-broken-access-control-de40c9897e91
