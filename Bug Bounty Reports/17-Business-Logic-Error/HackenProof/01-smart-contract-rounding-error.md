# Title: Business Logic Flaw in Smart Contract Withdrawal Logic

- **Platform**: HackenProof
- **Program**: AlphaSec Web & Smart Contracts
- **Severity**: High
- **Date**: 2024-11-08
- **Researcher**: IamSalted
- **Bounty**: $5,000

## Summary
A business logic vulnerability was discovered in a DeFi smart contract's withdrawal function where rounding errors in division operations could be exploited to drain more funds than entitled. The contract failed to properly handle precision loss during reward calculation, allowing an attacker to withdraw funds repeatedly before state updates were finalized.

## Technical Details
The vulnerability was found in the reward distribution mechanism of a staking contract. The `claimRewards()` function calculated user rewards based on a division operation that suffered from precision loss. The Solidity contract used integer division, which truncates toward zero. By calling the function with specific input values that maximized the rounding error, an attacker could claim more rewards than actually accrued. The contract also failed to implement a reentrancy guard, allowing the attacker to call the function multiple times before the state was updated.

## Steps to Reproduce
1. Stake a minimal amount of tokens to become eligible for rewards
2. Wait for a rewards period to accumulate
3. Craft a transaction that exploits the rounding error in the division calculation
4. Call `claimRewards()` with the crafted parameters
5. Before the transaction completes, call `claimRewards()` again (reentrancy)
6. Observe that the reward balance is not properly updated

## Proof of Concept
```
// Vulnerable calculation
function claimRewards() external {
    uint256 reward = (userStake[msg.sender] * totalRewards) / totalStaked;
    // Rounding error causes reward to be slightly higher than actual
    // No reentrancy guard allows multiple claims
    rewardToken.transfer(msg.sender, reward);
    userLastClaim[msg.sender] = block.timestamp;
}
```

## Impact
- Loss of funds from the reward pool
- Economic manipulation of the staking protocol
- Drainage of reward tokens allocated for all users
- Potential collapse of the tokenomics model

## Remediation
- Use a multiplication-before-division pattern to minimize precision loss
- Implement ReentrancyGuard from OpenZeppelin
- Update state before making external calls (checks-effects-interactions pattern)
- Add input validation for minimum stake amounts
- Use a higher-precision math library like PRBMath

## References
- https://hackenproof.com/programs/alphasec-web-and-smart-contracts
