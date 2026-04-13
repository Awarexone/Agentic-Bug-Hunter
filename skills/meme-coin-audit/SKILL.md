---
name: meme-coin-audit
description: Meme coin and token security audit — rug pull detection (honeypot, hidden mint, fee manipulation, LP lock bypass), Solana SPL token analysis (freeze authority, mint authority, metadata mutability), Token-2022 extension risks (transfer hooks, permanent delegate), DEX liquidity pool attacks (sandwich amplification, LP drain, bonding curve exploits), pump.fun/Raydium/Jupiter integration risks, token_scanner.py automation, and real exploit examples from 2024-2025. Use for any token audit, rug pull assessment, meme coin security review, or pre-investment due diligence.
---

# MEME COIN & TOKEN SECURITY AUDIT

Fast-kill rug pull detection and deep token security analysis for EVM and Solana meme coins.

---

## PRE-DIVE KILL SIGNALS

Check these BEFORE reading a single line of code. If any are true, skip the audit — the token is likely a rug or not worth the time.

### Hard Kills (Skip Immediately)
- **Contract not verified** on Etherscan/Solscan → Cannot audit source = cannot trust
- **Deployer wallet** has history of rug pulls (check Etherscan deployer page)
- **Token age < 1 hour** AND no known team → Too early, wait for more data
- **Mint authority retained** (Solana) AND no cap → Infinite mint = certain rug
- **Freeze authority retained** (Solana) on meme coin → Honeypot confirmed
- **Transfer hook present** (Token-2022) with mutable hook program → Honeypot vector
- **Permanent delegate** extension (Token-2022) → Can steal all holder tokens

### Soft Kills (Proceed with Extreme Caution)
- Top holder > 20% of supply (excluding DEX pools)
- LP not burned or locked in verified contract
- Contract is upgradeable / proxy with retained admin
- Less than $5K liquidity in the pool
- No social presence / anonymous deployer with no history

---

## THE ONE RULE

> **"Check ALL authorities and owner functions. The retained authority IS the rug vector."**
>
> Every rug pull requires a privileged operation: mint, blacklist, fee change, LP removal, or authority abuse. If you find the privilege, you found the bug.

---

## BUG CLASSES (8 TOKEN-SPECIFIC)

### 1. HIDDEN MINT / UNLIMITED SUPPLY
> 35% of meme coin rugs. Deployer mints tokens post-launch, dumps on LP.

**Quick grep (EVM):**
```bash
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib\|node_modules"
```

**Quick grep (Solana):**
```bash
grep -rn "MintTo\|mint_to\|mint_authority" src/ --include="*.rs" | grep -v "test\|target"
```

**Kill if:** MAX_SUPPLY enforced in every mint path, or mint function removed entirely.

### 2. HONEYPOT / TRANSFER RESTRICTION
> 25% of meme coin scams. Buy works, sell blocked.

**Quick grep:**
```bash
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|approve.*override\|tradingEnabled" src/ --include="*.sol"
```

**Solana equivalent:**
```bash
grep -rn "freeze_authority\|transfer_hook\|TransferHook\|permanent_delegate" src/ --include="*.rs"
```

**Kill if:** No blacklist mapping, no transfer hooks, no freeze authority.

### 3. FEE MANIPULATION
> 20% of rugs. Sell fee set to 99% after initial buys.

**Quick grep:**
```bash
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="
```

**Kill if:** Fee setter has `require(fee <= MAX_FEE)` with MAX_FEE <= 10%.

### 4. LIQUIDITY POOL DRAIN
> LP removal, migration, or manipulation to crash price.

**Quick grep:**
```bash
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
```

**Kill if:** LP tokens burned to dead address, no migration function, no pair setter.

### 5. BONDING CURVE MANIPULATION
> Exploits in pump.fun-style bonding curves.

**Quick grep:**
```bash
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
```

**Kill if:** Curve parameters immutable, graduation permissionless.

### 6. AUTHORITY RETENTION (SOLANA)
> Retained mint/freeze/update authorities on Solana tokens.

**Quick grep:**
```bash
grep -rn "mint_authority\|freeze_authority\|update_authority\|close_authority" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"  # Good sign: revocation
```

**Kill if:** All authorities = None, verified on-chain.

### 7. FAKE RENOUNCE / HIDDEN OWNERSHIP
> Ownership appears renounced but backdoor control retained.

**Quick grep:**
```bash
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
```

**Kill if:** renounceOwnership NOT overridden, no second admin role, no selfdestruct.

### 8. SANDWICH AMPLIFICATION BY DESIGN
> Contract makes holders maximally sandwichable.

**Quick grep:**
```bash
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"
grep -rn "swapThreshold\|_rebase\|mandatoryPool" src/ --include="*.sol"
```

**Kill if:** Auto-swap has proper slippage, no rebase mechanics.

---

## AUTOMATED SCANNER

Run the token scanner tool for fast red flag detection:

```bash
# EVM token
python3 tools/token_scanner.py contracts/Token.sol

# Solana program
python3 tools/token_scanner.py programs/token/ --chain solana --recursive

# Full directory scan with report
python3 tools/token_scanner.py src/ --recursive --output findings/token-report.md
```

The scanner checks all 8 bug classes via regex patterns. It catches:
- Direct mint/balance manipulation
- Blacklist and transfer restriction patterns
- Unbounded fee setters
- LP migration and emergency withdraw functions
- Fake renounce overrides
- Zero slippage auto-swaps
- All Solana authority patterns
- Token-2022 dangerous extensions

**Scanner does NOT check:**
- On-chain state (use Etherscan/Solscan for authority verification)
- Holder distribution (use DEXTools/Birdeye)
- LP lock status (use Unicrypt/PinkLock/Solscan)
- Deployer wallet history (manual check)

---

## FOUNDRY POC TEMPLATE (TOKEN EXPLOITS)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenExploitTest is Test {
    Token token;
    address owner = makeAddr("owner");
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    // Uniswap V2 router (mainnet fork)
    address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function setUp() public {
        vm.createSelectFork("mainnet");
        // Deploy token as owner
        vm.startPrank(owner);
        token = new Token();
        // Add liquidity...
        vm.stopPrank();
    }

    function test_hiddenMint_rug() public {
        // Step 1: Victim buys tokens
        vm.startPrank(victim);
        // ... buy tokens on Uniswap
        vm.stopPrank();

        // Step 2: Owner mints and dumps
        vm.startPrank(owner);
        uint256 supplyBefore = token.totalSupply();
        token.mint(owner, 1_000_000_000e18);
        assertGt(token.totalSupply(), supplyBefore, "Supply should increase");
        // ... sell minted tokens
        vm.stopPrank();

        // Step 3: Victim's tokens are now worthless
        // Assert token price crashed
    }

    function test_honeypot_blacklist() public {
        // Step 1: Victim buys
        vm.startPrank(victim);
        // ... buy tokens
        vm.stopPrank();

        // Step 2: Owner blacklists victim
        vm.startPrank(owner);
        token.blacklist(victim);
        vm.stopPrank();

        // Step 3: Victim cannot sell
        vm.startPrank(victim);
        vm.expectRevert("Blacklisted");
        token.transfer(address(1), 100e18);
        vm.stopPrank();
    }

    function test_fee_manipulation_rug() public {
        // Step 1: Verify initial fee is low
        assertEq(token.sellFee(), 3); // 3%

        // Step 2: Owner sets fee to 99%
        vm.prank(owner);
        token.setFees(3, 99); // Buy 3%, Sell 99%

        // Step 3: Victim sells — loses 99% to fees
        vm.startPrank(victim);
        uint256 balanceBefore = address(victim).balance;
        // ... sell tokens
        // Assert: received almost nothing
        vm.stopPrank();
    }
}
```

---

## SOLANA QUICK CHECKS (NO SOURCE CODE NEEDED)

When you don't have source code, check on-chain:

```
1. MINT AUTHORITY → solana account <MINT> --output json | check mint_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: can mint infinite tokens

2. FREEZE AUTHORITY → same as above, check freeze_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: honeypot

3. LP STATUS → Check Raydium/Orca pool
   - LP burned? (tokens sent to 1111...1111)
   - LP locked? (in verified locker with no backdoor)
   - LP held by deployer? → CRITICAL: instant rug

4. TOP HOLDERS → Birdeye/Solscan holders tab
   - Top 10 < 30% of supply (excluding pools)
   - Creator wallets (check first transactions)

5. PROGRAM UPGRADEABILITY
   - Is the program upgradeable? → can change any logic
   - Upgrade authority should be None for immutable programs

6. TOKEN-2022 EXTENSIONS
   - Any transfer hook? → potential honeypot
   - Permanent delegate? → CRITICAL
```

---

## FULL REFERENCE FILES

For deep dives into specific areas:
- `web3/10-meme-coin-bugs.md` — All 8 bug classes with full code examples and variants
- `web3/11-solana-token-audit.md` — Solana-specific: SPL authorities, Token-2022, pump.fun, Raydium, Jupiter
- `web3/12-dex-lp-attacks.md` — DEX & LP manipulation patterns (sandwich, pool sniping, CL position attacks)
