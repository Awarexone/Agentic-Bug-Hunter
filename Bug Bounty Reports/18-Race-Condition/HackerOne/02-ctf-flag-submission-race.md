# Title: Race Condition in Flag Submission

- **Platform**: HackerOne
- **Program**: HackerOne CTF
- **Severity**: Low
- **Date**: December 4, 2018
- **Researcher**: dropper
- **Bounty**: N/A

## Summary
A race condition vulnerability in the Hacker101 CTF flag submission system allowed an authenticated user to submit the same flag multiple times, gaining extra points and increasing their chances of getting invitations to private bug bounty programs.

## Technical Details
The flag submission endpoint lacked proper idempotency controls. Once a flag was validated as correct, the system credited points to the user. By sending multiple simultaneous submission requests, the same flag could be credited multiple times before the system marked it as "used."

## Steps to Reproduce
1. Login with a valid user account
2. Solve a CTF challenge and obtain a flag (e.g., Trivial challenge worth 1 point)
3. Go to the submission page and intercept the POST request
4. Send the same POST request multiple times simultaneously
5. Observe points being credited multiple times for the same flag

## Proof of Concept
```
Using "Race The Web" tool:
POST /ctf/flag/submit HTTP/1.1
Host: ctf.hacker101.com
Cookie: <session>

flag=FLAG{trivial_challenge_flag}

// Send 10 parallel requests
// All 10 return success, granting 10 points for one flag
```

## Impact
Unauthorized point accumulation in the CTF leaderboard. This could lead to unfair advantages in CTF competitions and potentially influence program invitation decisions based on inflated scores.

## Remediation
Implement database-level unique constraint on flag submissions per user. Use atomic transactions with proper locking to ensure each flag can only be submitted once regardless of request timing. Add idempotency keys to submission requests.

## References
- https://hackerone.com/reports/454949
- https://github.com/insp3ctre/race-the-web
