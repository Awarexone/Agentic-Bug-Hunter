---
name: dex-lp-attacks
description: DEX and liquidity pool attack patterns for meme coin markets. Covers sandwich attacks, LP manipulation (add/remove liquidity timing), bonding curve exploits, pool creation sniping, fake pool injection, concentrated liquidity position manipulation, and cross-DEX arbitrage exploits. Includes Uniswap V2/V3, PancakeSwap, Raydium, Orca, Meteora, and pump.fun patterns with grep commands and real exploit examples.
---

# DEX & LP ATTACKS — Liquidity Pool Manipulation

Attack patterns targeting the DEX layer of meme coin markets. These are bugs in how tokens interact with DEX infrastructure — not external MEV (which is a market issue, not a bug bounty target).

Focus: **contract-level bugs** that enable or amplify LP manipulation, pool sniping, and liquidity drain.

---

## 1. POOL CREATION SNIPING

> The first block after a pool is created is the most profitable — and most dangerous — moment.

### What It Is

When a new liquidity pool is created (Uniswap `createPair` + `addLiquidity`, Raydium `initialize`), the creation transaction is visible in the mempool. Snipers:
1. Monitor mempool for pool creation transactions
2. Bundle a buy transaction in the same block (or next block)
3. Get tokens at the initial price before any other buyers
4. Sell after organic buys drive the price up

This is a **bug bounty target** when the token contract itself creates conditions that amplify sniping damage.

### Contract-Level Bugs That Enable Sniping

**Bug 1: No Anti-Snipe on First Blocks**
```solidity
// VULNERABLE: no protection in first blocks after launch
// Anyone who buys in block 0 gets best price
function _transfer(address from, address to, uint256 amount) internal override {
    // No launch block check
    super._transfer(from, to, amount);
}

// CORRECT: anti-snipe for first N blocks
uint256 public launchBlock;
uint256 public constant SNIPE_BLOCKS = 3;

function _transfer(address from, address to, uint256 amount) internal override {
    if (block.number <= launchBlock + SNIPE_BLOCKS) {
        require(amount <= maxTxAmount / 10, "Anti-snipe: reduced max during launch");
        // OR: apply higher tax during launch blocks
    }
    super._transfer(from, to, amount);
}
```

**Bug 2: Public addLiquidity Without Pairing**
```solidity
// VULNERABLE: addLiquidity and enableTrading are separate transactions
// Gap between them = snipe window
function addLiquidity() external onlyOwner {
    router.addLiquidityETH{value: address(this).balance}(
        address(this), balanceOf(address(this)), 0, 0, owner(), block.timestamp
    );
    // Trading not enabled yet, but pair exists and has reserves
}

function enableTrading() external onlyOwner {
    tradingEnabled = true;
    launchBlock = block.number;
    // Between addLiquidity and enableTrading → snipe window
}

// CORRECT: atomic launch
function launch() external onlyOwner {
    router.addLiquidityETH{value: address(this).balance}(...);
    tradingEnabled = true;
    launchBlock = block.number;
    // Single transaction — no gap
}
```

### Grep Patterns
```bash
# Launch mechanics
grep -rn "enableTrading\|openTrading\|setTrading\|tradingEnabled\|tradingActive" src/ --include="*.sol"
grep -rn "launchBlock\|launch_block\|startBlock" src/ --include="*.sol"
grep -rn "addLiquidity\|addLiquidityETH" src/ --include="*.sol"

# Anti-snipe protections
grep -rn "SNIPE\|antiSnipe\|antiBot\|launchBlock.*block.number" src/ --include="*.sol"

# Separate launch steps (vulnerable pattern)
grep -rn "function.*[Ll]iquidity\|function.*[Tt]rading\|function.*[Ll]aunch" src/ --include="*.sol"

# Solana: Raydium pool initialization
grep -rn "initialize.*pool\|create_pool\|InitializePool" src/ --include="*.rs"
grep -rn "open_trading\|enable_trading\|start_trading" src/ --include="*.rs"
```

---

## 2. LIQUIDITY REMOVAL ATTACKS

> LP tokens = ownership of pool liquidity. Whoever controls LP tokens controls the exit.

### What It Is

After adding liquidity, the creator receives LP tokens. If these aren't locked or burned, the creator can remove liquidity at any time — instantly crashing the token price to near-zero.

### Contract-Level Bugs

**Bug 1: Auto-LP to Owner Wallet**
```solidity
// VULNERABLE: auto-liquidity from tax goes to owner
function swapAndLiquify(uint256 tokens) private {
    uint256 half = tokens / 2;
    uint256 otherHalf = tokens - half;

    swapTokensForEth(half);
    uint256 newBalance = address(this).balance;

    router.addLiquidityETH{value: newBalance}(
        address(this),
        otherHalf,
        0,
        0,
        owner(), // LP tokens go to OWNER, not contract or dead address
        block.timestamp
    );
}

// CORRECT: LP tokens to dead address (auto-burn)
router.addLiquidityETH{value: newBalance}(
    address(this), otherHalf, 0, 0,
    address(0xdead), // LP tokens burned
    block.timestamp
);
```

**Bug 2: LP Lock with Backdoor**
```solidity
// VULNERABLE: lock contract has emergency withdraw
contract LPLocker {
    uint256 public unlockTime;
    address public owner;

    function lock(address token, uint256 duration) external {
        IERC20(token).transferFrom(msg.sender, address(this),
            IERC20(token).balanceOf(msg.sender));
        unlockTime = block.timestamp + duration;
    }

    function withdraw(address token) external {
        require(block.timestamp >= unlockTime, "Still locked");
        IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
    }

    // BACKDOOR: extend can also be used to set unlockTime to past
    function extend(uint256 newUnlockTime) external {
        require(msg.sender == owner);
        unlockTime = newUnlockTime; // Can set to 0 = instant unlock
    }
}
```

### Grep Patterns
```bash
# LP token destination
grep -rn "addLiquidityETH\|addLiquidity" -A5 src/ --include="*.sol" | grep "owner\|msg.sender\|_owner"

# LP lock contracts
grep -rn "unlockTime\|lockDuration\|lockPeriod\|lock.*LP\|lockLiquidity" src/ --include="*.sol"
grep -rn "emergencyWithdraw\|forceWithdraw\|extend.*unlock" src/ --include="*.sol"

# Dead address patterns (safe LP destination)
grep -rn "0xdead\|address(0)\|DEAD_ADDRESS\|BURN_ADDRESS" src/ --include="*.sol"

# Solana LP handling
grep -rn "burn.*lp\|lp.*burn\|burn_lp_tokens" src/ --include="*.rs"
grep -rn "remove_liquidity\|withdraw_liquidity\|close_position" src/ --include="*.rs"
```

---

## 3. SANDWICH ATTACK AMPLIFICATION

> When the token contract itself makes sandwiching easier or more profitable.

### What It Is

Standard sandwich: attacker frontrun-buys before a large trade, backrun-sells after. This is external MEV and not a bug bounty target.

**Bug bounty target:** when the token contract amplifies sandwich profitability through:
- Zero slippage in auto-swaps
- Tax mechanics that create predictable price impact
- Large auto-swap thresholds
- Rebasing on every swap

### Contract-Level Bugs

**Bug 1: Zero Slippage Auto-Swap**
```solidity
// VULNERABLE: accumulated tax tokens swapped with 0 slippage
function _transfer(address from, address to, uint256 amount) internal {
    uint256 contractBalance = balanceOf(address(this));
    if (contractBalance >= swapThreshold && to == uniswapPair) {
        swapTokensForETH(contractBalance); // Swaps ALL accumulated tokens
    }
    // ...
}

function swapTokensForETH(uint256 amount) private {
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        amount,
        0, // ZERO minimum output — sandwich guaranteed
        path,
        address(this),
        block.timestamp
    );
}
```

**Bug 2: Predictable Swap Threshold**
```solidity
// VULNERABLE: threshold is public and swaps exact amount
uint256 public swapThreshold = 1000000e18;

// Sandwich strategy:
// 1. Monitor contractTokenBalance approaching swapThreshold
// 2. Trigger a small buy that pushes balance over threshold
// 3. Contract auto-swaps 1M tokens → massive sell pressure
// 4. Attacker bought the dip in step 2, sells after swap completes
```

**Bug 3: Pair Sync After Direct Transfer**
```solidity
// VULNERABLE: direct transfer to pair + sync = price manipulation
function distributeRewards() external onlyOwner {
    _transfer(address(this), pair, rewardAmount);
    IUniswapV2Pair(pair).sync(); // Forces pair to re-read reserves
    // Price change is atomic — no slippage protection
    // Attacker can sandwich this transaction
}
```

### Grep Patterns
```bash
# Auto-swap with zero slippage
grep -rn "swapExactTokensForETH\|swapExactTokensForTokens" -B2 -A10 src/ --include="*.sol" | grep -E "0,|amountOutMin.*0"

# Swap threshold
grep -rn "swapThreshold\|swapTokensAtAmount\|numTokensSellToAddToLiquidity\|minTokensBeforeSwap" src/ --include="*.sol"
grep -rn "setSwapThreshold\|updateSwapTokensAt\|setNumTokens" src/ --include="*.sol"

# Pair sync calls
grep -rn "\.sync()\|IUniswapV2Pair.*sync\|pair\.sync" src/ --include="*.sol"

# Direct transfers to pair
grep -rn "transfer.*pair\|_transfer.*uniswapPair\|_transfer.*pancakePair" src/ --include="*.sol"
```

---

## 4. CONCENTRATED LIQUIDITY POSITION ATTACKS

> Uniswap V3 / Orca Whirlpools / Meteora DLMM — concentrated liquidity enables sophisticated rug patterns.

### What It Is

Concentrated liquidity lets LPs provide liquidity in specific price ranges. Meme coin creators exploit this:
- Open position in narrow range around launch price
- Organic buys push price above range → position is 100% ETH/SOL
- Creator removes position → has all the ETH/SOL, holders have worthless tokens
- Looks like a natural price movement, but was engineered

### Attack Pattern

```
1. Creator launches token, adds CL position at range [0.0001 - 0.001]
2. Buys push price to 0.002 (above range)
3. Creator's position is now 100% ETH (all tokens sold into buys)
4. Creator removes liquidity → gets ETH
5. No liquidity left in that range → price crashes
6. Different from V2 because ALL the creator's tokens were sold
   automatically as price crossed through their range
```

### Grep Patterns
```bash
# Uniswap V3 position management
grep -rn "INonfungiblePositionManager\|NonfungiblePositionManager" src/ --include="*.sol"
grep -rn "mint.*position\|increaseLiquidity\|decreaseLiquidity\|collect" src/ --include="*.sol"
grep -rn "tickLower\|tickUpper\|tick_lower\|tick_upper" src/ --include="*.sol"

# Orca Whirlpool positions
grep -rn "open_position\|close_position\|increase_liquidity\|decrease_liquidity" src/ --include="*.rs"
grep -rn "tick_lower_index\|tick_upper_index\|Whirlpool" src/ --include="*.rs"

# Meteora DLMM
grep -rn "add_liquidity.*bin\|remove_liquidity.*bin\|active_bin" src/ --include="*.rs"
grep -rn "LbPair\|lb_pair\|DLMM\|meteora" src/ --include="*.rs"

# Narrow range detection (V3 / whirlpool)
# Check: tickUpper - tickLower < 200 (very narrow range = rug signal)
```

---

## 5. POOL MIGRATION EXPLOITS

> Token contract can create a new pool and migrate liquidity — leaving the old pool empty.

### What It Is

Some token contracts have a `migrate()` or `setNewPair()` function. This lets the owner:
1. Create a new LP pair (with a different token or different DEX)
2. Remove liquidity from the old pair
3. Add to the new pair (or just keep the ETH)
4. Old pair has zero liquidity → anyone holding tokens in old pair is rugged

### Contract-Level Bugs

```solidity
// VULNERABLE: pair can be changed, breaking old holders
address public uniswapPair;

function setPair(address _newPair) external onlyOwner {
    uniswapPair = _newPair;
    // Tax logic now applies to new pair
    // Old pair still exists but no longer recognized by contract
    // Old pair holders can't sell (tax logic broken)
}

// VULNERABLE: full migration
function migrate(address _newRouter) external onlyOwner {
    // Remove all liquidity from current pair
    uint256 lpBalance = IERC20(uniswapPair).balanceOf(address(this));
    IUniswapV2Router02(router).removeLiquidityETH(
        address(this), lpBalance, 0, 0, address(this), block.timestamp
    );
    // Add to new pair
    IUniswapV2Router02(_newRouter).addLiquidityETH{value: address(this).balance}(
        address(this), balanceOf(address(this)), 0, 0, owner(), block.timestamp
    );
    router = _newRouter;
}
```

### Grep Patterns
```bash
# Pair change functions
grep -rn "setPair\|setNewPair\|updatePair\|changePair\|_pair\s*=" src/ --include="*.sol"
grep -rn "setRouter\|updateRouter\|changeRouter\|_router\s*=" src/ --include="*.sol"

# Migration functions
grep -rn "function migrate\|function migration\|migrateLP\|migrateLiquidity" src/ --include="*.sol"

# Remove + re-add liquidity pattern
grep -rn "removeLiquidity\|removeLiquidityETH" src/ --include="*.sol"

# Solana equivalent
grep -rn "migrate_pool\|close_pool\|transfer_pool_authority" src/ --include="*.rs"
```

---

## 6. FLASH LOAN ATTACKS ON MEME COIN POOLS

> Using flash loans to manipulate thin meme coin liquidity pools.

### What It Is

Meme coins typically have thin liquidity ($10K-$100K). Flash loans can temporarily distort pool reserves:
1. Flash borrow large amount of paired asset (ETH/SOL)
2. Swap into meme coin pool → crash price
3. Buy at depressed price (or trigger liquidations in leveraged positions)
4. Swap back → restore price
5. Repay flash loan

**Bug bounty target** when a protocol reads the meme coin price from the pool (as oracle) and can be exploited.

### Contract-Level Bugs

```solidity
// VULNERABLE: reads price from spot reserves (manipulable)
function getTokenPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
    // This price can be manipulated within a single transaction via flash loan
}

// CORRECT: use TWAP or external oracle
function getTokenPrice() public view returns (uint256) {
    // Uniswap V2 TWAP
    uint256 price0Cumulative = IUniswapV2Pair(pair).price0CumulativeLast();
    // ... calculate time-weighted average
}
```

### Grep Patterns
```bash
# Spot price reads (vulnerable to flash loan)
grep -rn "getReserves()\|reserve0\|reserve1" src/ --include="*.sol"
grep -rn "price.*reserve\|token.*price.*pair\|getTokenPrice\|getPrice" src/ --include="*.sol"

# Flash loan receivers
grep -rn "flashLoan\|flash_loan\|FlashLoan\|onFlashLoan\|executeOperation" src/ --include="*.sol"

# TWAP usage (safer)
grep -rn "TWAP\|twap\|priceCumulative\|price0Cumulative\|observe" src/ --include="*.sol"
```

---

## 7. CROSS-DEX PRICE DISCREPANCY

> Same token on multiple DEXs with different prices = arbitrage target. Bug when the contract facilitates this.

### What It Is

A meme coin trades on multiple DEXs (e.g., Uniswap + SushiSwap, or Raydium + Orca). If the token contract:
- Has different tax rates for different DEX pairs
- Routes internal swaps through only one DEX
- Creates price discrepancy through rebasing mechanics

...it creates arbitrage opportunities that drain value from holders.

### Grep Patterns
```bash
# Multiple pair tracking
grep -rn "pair1\|pair2\|pairs\[\|_pairs\|automatedMarketMakerPairs" src/ --include="*.sol"
grep -rn "setAutomatedMarketMakerPair\|addPair\|removePair" src/ --include="*.sol"

# Per-pair tax rates
grep -rn "pairFee\|_pairTax\|feeForPair\|taxByPair" src/ --include="*.sol"

# Multiple DEX routers
grep -rn "router1\|router2\|_routers\|secondaryRouter" src/ --include="*.sol"
```

---

## ATTACK SURFACE BY DEX

| DEX | Chain | Key Attack Vector | Grep Target |
|---|---|---|---|
| Uniswap V2 | ETH | LP removal, pair.sync() | `IUniswapV2Pair\|sync()` |
| Uniswap V3 | ETH | CL position manipulation | `NonfungiblePositionManager\|tickLower` |
| PancakeSwap | BSC | Same as Uni V2 + masterchef | `IPancakeRouter\|PancakeFactory` |
| Raydium CPMM | SOL | LP burn check, pool init snipe | `raydium_amm\|create_pool` |
| Raydium CLMM | SOL | CL position range attacks | `raydium_clmm\|open_position` |
| Orca Whirlpools | SOL | Narrow tick range rug | `Whirlpool\|tick_lower_index` |
| Meteora DLMM | SOL | Bin liquidity manipulation | `LbPair\|active_bin` |
| pump.fun | SOL | Graduation snipe, bundled buys | `bonding_curve\|graduate` |
| Jupiter | SOL | Routing via fake pools | `jupiter\|route_plan` |

---

## QUICK AUDIT FLOW FOR MEME COIN DEX INTERACTION

```
1. IDENTIFY which DEX(es) the token interacts with
   → grep for router/pair/pool addresses

2. CHECK LP token destination
   → Are LP tokens burned, locked, or held by owner?

3. CHECK for migration functions
   → Can the pair/router be changed?

4. CHECK auto-swap mechanics
   → Zero slippage? Predictable threshold?

5. CHECK for direct pair manipulation
   → sync() calls? Direct transfers to pair?

6. CHECK concentrated liquidity range
   → Narrow range = engineered rug potential

7. VERIFY price oracle
   → Spot reserves (bad) vs TWAP (better) vs Chainlink (best)
```

---

-> BACK TO: [10-meme-coin-bugs.md](10-meme-coin-bugs.md) — Meme coin vulnerability taxonomy
