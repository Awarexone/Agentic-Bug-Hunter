# Title: Bypassing Business Logic via Race Condition: $500 Bounty

- **Platform**: Medium
- **Program**: Examlife
- **Severity**: High
- **Date**: March 1, 2025
- **Researcher**: Abhi Sharma
- **Bounty**: $500

## Summary
A race condition vulnerability in Examlife's member creation system allowed attackers to bypass duplicate account restrictions. Multiple insurance profiles could be created using the same email and employee ID, leading to data inconsistencies.

## Technical Details
Examlife is an employee benefits and insurance platform. It restricts users from registering one email under multiple employee IDs to prevent duplicate profiles. However, this validation was enforced only at the application level, not at the database level. By sending simultaneous registration requests, the validation check passed for all requests before any profile was created, allowing duplicate entries.

## Steps to Reproduce
1. Navigate to the member creation/registration page
2. Fill in the form with email: victim@example.com and Employee ID: EMP001
3. Intercept the registration POST request
4. Use Turbo Intruder or a Python script to send multiple identical requests
5. All requests succeed, creating multiple profiles with the same email

## Proof of Concept
```
POST /api/v1/members/create HTTP/1.1
Host: examlife.com
Content-Type: application/json
Cookie: <session>

{
  "email": "victim@example.com",
  "employee_id": "EMP001",
  "name": "Victim User",
  "plan": "standard"
}

// Send 5 parallel requests
// All return 200 OK with different profile IDs
// Same email now has 5 insurance profiles
```

## Impact
Data inconsistencies in insurance records, administrative errors, incorrect insurance coverage, and potential for insurance fraud. Duplicate profiles could lead to billing errors and regulatory compliance issues.

## Remediation
Implement database-level unique constraints on (email, employee_id) combination. Use transactions with row-level locking to prevent concurrent duplicate inserts. Add application-level checks within atomic transactions.

## References
- https://medium.com/h7w/bypassing-business-logic-via-race-condition-a-500-bounty-bug-273396b17ec4
