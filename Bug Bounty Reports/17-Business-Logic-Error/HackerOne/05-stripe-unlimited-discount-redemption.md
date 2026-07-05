# Title: Business Logic Vulnerability: Unlimited Fee Discount Redemption

- **Platform**: HackerOne
- **Program**: Stripe
- **Severity**: High
- **Date**: 2019
- **Researcher**: ian
- **Bounty**: $5,000

## Summary
A business logic vulnerability in Stripe's fee discount system allowed a discount to be redeemed multiple times via a race condition. Using parallel requests, the researcher accepted a $20,000 fee discount 30 times, resulting in $600,000 of fee-free transactions.

## Technical Details
Stripe offered a fee discount of $20,000 on transactions. The discount was applied via a "Accept Discount" endpoint. The researcher used Turbo Intruder (Burp Suite extension) to send 30 rapid parallel requests to the acceptance endpoint. Without proper locking or idempotency controls, each request independently accepted the full discount amount.

## Steps to Reproduce
1. Receive a fee discount offer from Stripe Support in the dashboard
2. Intercept the "Accept Discount" request
3. Use Turbo Intruder to send 30 simultaneous requests
4. Each request accepts the full $20,000 discount
5. Total: $600,000 in fee-free transactions

## Proof of Concept
```
Using Turbo Intruder:
POST /api/discounts/accept HTTP/1.1
Host: dashboard.stripe.com
Cookie: <session>
Content-Type: application/json

{"discount_id": "dsc_XXXXX"}

// Send 30 parallel requests
// All 30 return 200 OK, each granting $20,000 fee-free processing
```

## Impact
Massive financial loss to Stripe — approximately 3% per transaction means $600 lost per $20,000 discount abuse, multiplied by 30 = $18,000 potential loss per attack scenario.

## Remediation
Stripe initially added a check but the researcher showed a race condition remained. After a second fix implementing proper database-level locking and idempotency tokens, the vulnerability was fully resolved.

## References
- https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption
