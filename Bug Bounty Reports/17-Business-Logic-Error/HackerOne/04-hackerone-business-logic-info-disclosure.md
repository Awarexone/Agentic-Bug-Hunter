# Title: Business Logic Errors Leads to Information Disclosure via Error Messages

- **Platform**: HackerOne
- **Program**: HackerOne
- **Severity**: Medium (CVSS 5.0)
- **Date**: November 28, 2017
- **Researcher**: cjlegacion
- **Bounty**: None (Duplicate)

## Summary
A business logic error in HackerOne's authorization layer caused input validation to run before authorization checks. Error messages returned information about reports (such as bounty balance) before verifying the requesting user had permission to view that report data. This allowed unauthorized information disclosure.

## Technical Details
HackerOne used a library that consolidated authorization, input validation, and business logic. However, input validation was sometimes bloated with business logic and executed before authorization. The validation would check report state, balance, etc., and return error messages that leaked information about the report — all before the authorization layer confirmed the user had access.

## Steps to Reproduce
1. As an unauthorized user, attempt to award a bounty on a report
2. Observe that the error message reveals information about the report balance
3. This information should only be visible to authorized participants

## Proof of Concept
```
Wrong pattern (vulnerable):
class AwardBountyClass
  def validate
    # check report_id is integer
    # return error when balance is too low  <-- INFO LEAK
  end
  def authorized?
    # check permissions  <-- happens AFTER validate
  end
end

Correct pattern:
class AwardBountyClass
  def authorized?
    # check permissions  <-- happens FIRST
  end
  def execute
    # return error when balance is too low  <-- INFO LEAK prevented
  end
end
```

## Impact
Information disclosure — unauthorized users could learn details about private reports, including bounty status, balance information, and report progress. This violates the confidentiality of the bug bounty process.

## Remediation
Authorization checks must always execute before input validation that could leak sensitive information. Business logic validations that reveal report details should be moved to the execution phase after authorization.

## References
- https://hackerone.com/reports/293593
