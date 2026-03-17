---
description: Smart contract security audit — runs through 10 bug class checklist (accounting desync, access control, incomplete path, off-by-one, oracle errors, ERC4626, reentrancy, flash loan, signature replay, proxy/upgrade). Applies pre-dive kill signals first. Generates Foundry PoC template for confirmed findings. Usage: /web3-audit <contract.sol>
---

# /web3-audit

Smart contract security audit using the 10-bug-class methodology.

## Usage

```
/web3-audit VulnerableContract.sol
/web3-audit https://github.com/protocol/contracts
/web3-audit [paste contract code]
```

## Step 0: Pre-Dive Kill Signals

ALWAYS check these BEFORE reading any code:

```
1. TVL < $500K → max payout too low for effort → SKIP
2. 2+ top-tier audits (Halborn, ToB, Cyfrin, OZ) on simple protocol → SKIP
3. Protocol < 500 lines, single A→B→C flow → minimal attack surface → SKIP
4. max_payout = min(10% × TVL, program_cap) → if < $10K → SKIP

Formula: Is [TVL * 10%] > [hours I'll spend * hourly rate]? If not, skip.
```

Only proceed if score >= 6/10:
- TVL > $10M: +2
- Immunefi Critical >= $50K: +2
- No top-tier audit on current version: +2
- < 30 days since deploy: +1
- Protocol you've hunted before: +1
- Upgradeable proxies present: +1

## Step 1: Accounting State Desynchronization (28% of Criticals)

```bash
# Find accounting variables
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward" contracts/

# Find ALL early returns in critical functions
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"
```

Check: For each early return in claim/redeem/withdraw functions:
- Which state variables are updated in the normal path?
- Are ALL of them also updated in the early return path?
- If A updated but B isn't → potential desync bug

## Step 2: Access Control (19% of Criticals)

```bash
# Sibling function families — do ALL have same modifier set?
grep -rn "function vote\|function poke\|function reset\|function update\|function claim\|function harvest" contracts/ -A2

# Ownership check: existence vs ownership
grep -rn "_requireOwned\|ownerOf\|_isApprovedOrOwner" contracts/ -B5

# Silent modifiers (if without revert)
grep -rn "modifier\b" contracts/ -A8 | grep -B3 "if (" | grep -v "require\|revert"

# Uninitialized proxy
grep -rn "function initialize\b" contracts/ -A3
grep -rn "_disableInitializers()" contracts/
```

Check: Does EVERY sibling function in a family have the SAME modifiers?

## Step 3: Incomplete Code Path (17% of Criticals)

The function family comparison test:
```
1. List all state changes in function A (deposit/place/create)
2. List all state changes in function B (withdraw/update/cancel)
3. For each state change in A: does B have the corresponding reverse?
4. For each token transfer in A: does B have the corresponding refund?
```

```bash
grep -rn "safeApprove\b" contracts/    # safeApprove without zero-reset?
grep -rn "delete\b" contracts/ -B5     # delete before operation completes?
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

## Step 4: Off-By-One (22% of Highs)

Mental test: For EVERY `if (A > B)`: "What happens when A == B?" Is that correct?

```bash
# Boundary comparisons
grep -rn "Period\|Epoch\|Deadline\|period\|epoch\|deadline" contracts/ -A3 | grep "[<>][^=]"

# Loop breaks
grep -rn "\bbreak\b" contracts/ -B10

# Array bounds
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```

## Step 5: Oracle / Price Manipulation

```bash
# Missing staleness check
grep -rn "latestRoundData" contracts/ -A5 | grep -v "updatedAt\|timestamp"

# Pyth confidence interval
grep -rn "getPriceUnsafe\|getPrice\b" contracts/ -A8 | grep -v "conf\|confidence"

# TWAP windows
grep -rn "secondsAgo\|TWAP\|cardinality" contracts/ -A5
```

Check:
- Is staleness checked? (`require(block.timestamp - updatedAt <= MAX_AGE)`)
- Is Pyth confidence interval checked? (`require(conf * 10 <= price)`)
- Is TWAP window > 1800 seconds (30 min)?

## Step 6: ERC4626 Vaults

```bash
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
grep -rn "function transfer\|function transferFrom" contracts/ -A15
```

Check:
- Does `mint()` call the same validation as `deposit()`?
- Does `transfer()` move lock records along with shares?
- Is there a `_decimalsOffset()` virtual shares defense against first-depositor attack?

## Step 7: Reentrancy

```bash
# Effects after interactions
grep -rn "\.call{value\|safeTransfer\|transfer(" contracts/ -B10 | grep -v "require\|revert"

# Missing nonReentrant
grep -rn "function withdraw\|function redeem\|function claim" contracts/ -A2 | grep -v "nonReentrant"
```

Check: Does every function that transfers ETH or ERC20 follow CEI order?
(Checks → Effects → Interactions)

## Step 8: Flash Loan Oracle Manipulation

```bash
grep -rn "getReserves\|getAmountsOut\|slot0\b" contracts/ -A5
```

Check: Any spot price reading from Uniswap reserves/slot0? → flash loan manipulatable.

## Step 9: Signature Replay

```bash
grep -rn "ecrecover\|ECDSA\.recover" contracts/ -B20
grep -rn "nonce\|_nonces\|nonces\[" contracts/
```

Check: Does signed hash include: nonce + chainId + contract address?

## Step 10: Proxy / Upgrade

```bash
grep -rn "function initialize\b\|_disableInitializers\|initializer" contracts/
grep -rn "delegatecall\b" contracts/ -B3
grep -rn "0x360894\|_IMPLEMENTATION_SLOT\|EIP1967" contracts/
```

Check:
- `_disableInitializers()` in implementation constructor?
- Implementation can't be initialized directly by attacker?
- Storage layout compatible between versions?

## Confirming a Finding

Apply the 7-Question Gate:
```
1. Can I demonstrate this with a Foundry test?
2. What is the financial impact (quantify in $)?
3. Is this in the Immunefi scope?
4. Is it a known issue or acknowledged behavior?
5. Does my Foundry PoC actually run? (forge test -vvvv)
```

## Foundry PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
        target = VulnerableContract(TARGET_ADDRESS);
        deal(address(token), attacker, INITIAL_BALANCE);
    }

    function test_exploit() public {
        uint256 before = token.balanceOf(attacker);
        vm.startPrank(attacker);
        // Execute exploit
        vm.stopPrank();
        assertGt(token.balanceOf(attacker), before, "Exploit failed");
    }
}
```

Run: `forge test --match-test test_exploit -vvvv`
