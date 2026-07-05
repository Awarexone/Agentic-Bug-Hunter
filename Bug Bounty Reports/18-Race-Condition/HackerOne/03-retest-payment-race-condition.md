# Title: $2,500 Bounty: Race Condition in Retest Payments

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: High
- **Date**: 2018
- **Researcher**: cablej
- **Bounty**: $2,500

## Summary
A race condition vulnerability in HackerOne's retest confirmation feature allowed a researcher to get paid multiple times for a single retest. By sending multiple simultaneous requests to confirm a retest, the system processed each request independently and issued payments for all of them.

## Technical Details
When a researcher confirms a retest on HackerOne, the system processes a payment action. The payment logic checked if the retest was already paid before processing, but this check was not atomic. By sending multiple confirm requests at exactly the same time, each request passed the payment check before any of them completed, resulting in multiple payments for the same retest.

## Steps to Reproduce
1. Complete a retest on a HackerOne report
2. Intercept the retest confirmation request
3. Send 5+ identical requests simultaneously
4. Each request processes the payment independently
5. Multiple payments appear in the account

## Proof of Concept
```
POST /reports/<id>/retest/confirm HTTP/1.1
Host: hackerone.com
Cookie: <researcher_session>
Content-Type: application/json

{"retest_id": 12345}

// Send 5 identical requests in parallel
// All return 200 OK
// Account credited 5x for one retest
```

## Impact
Direct financial loss to HackerOne through duplicate bounty payments. The vulnerability could be exploited to receive multiple payouts for a single security assessment, potentially costing thousands in unauthorized bounties.

## Remediation
Implement idempotency keys for retest confirmation requests. Use database-level transactions with row-level locking to ensure each retest can only be confirmed and paid once. Add idempotency tokens that expire after use.

## References
- https://hackerone.com/reports/429026
- https://osintteam.blog/2-500-bounty-how-a-simple-race-condition-let-me-get-paid-multiple-times-by-hackerone-cc7bbb0551f1
