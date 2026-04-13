---
name: meme-coin-bugs
description: Complete reference for meme coin and token vulnerability classes — 8 bug classes covering hidden mint, honeypot transfer restrictions, fee manipulation, LP lock bypasses, bonding curve exploits, authority retention, fake renounce, and sandwich/MEV. Covers EVM (Solidity) and Solana (Rust/Anchor) with real exploit examples from 2024-2025. Use when auditing any token contract, checking for rug pull vectors, or analyzing honeypot mechanisms.
---

# BUG CLASSES — Meme Coin & Token Vulnerabilities

8 bug classes extracted from 400+ rug pulls, 200+ honeypot reports, and real Immunefi/Code4rena findings.
These are **different from DeFi protocol bugs** — meme coin vulns target token mechanics, not protocol logic.

---

## 1. HIDDEN MINT / UNLIMITED SUPPLY
> 35% of meme coin rugs. The deployer retains the ability to mint tokens post-launch, inflating supply and dumping on buyers.
> Real rugs: SQUID token ($3.4M, Oct 2021), Meerkat Finance ($31M), AnubisDAO ($60M)

### What It Is

The token contract contains a mint function callable by the owner (or any privileged address) without a hard cap. After launch and initial buys drive the price up, the deployer mints millions of tokens and sells them into the liquidity pool, crashing the price to zero.

More sophisticated variants hide the mint behind delegatecall, proxy upgrades, or obscure function selectors that don't appear in the verified source.

### Root Cause Patterns

**Variant 1: Direct Owner Mint**
```solidity
// VULNERABLE: owner can mint infinite tokens
function mint(address to, uint256 amount) external onlyOwner {
    _mint(to, amount);
}

// CORRECT: hard cap enforced
function mint(address to, uint256 amount) external onlyOwner {
    require(totalSupply() + amount <= MAX_SUPPLY, "cap exceeded");
    _mint(to, amount);
}
```

**Variant 2: Hidden Function Selector**
```solidity
// VULNERABLE: function name looks benign but mints tokens
function _updateRewards(address account, uint256 amount) internal {
    // Looks like a reward update, actually mints
    _balances[account] += amount;
    _totalSupply += amount;
}

// Called via: function processReflections() external onlyOwner
//   which internally calls _updateRewards(owner, 1000000e18);
```

**Variant 3: Delegatecall Mint**
```solidity
// VULNERABLE: external contract can mint via delegatecall
function execute(address target, bytes calldata data) external onlyOwner {
    (bool success,) = target.delegatecall(data);
    require(success);
}
// Owner deploys a separate contract with mint logic,
// calls execute() pointing to it
```

**Variant 4: Proxy Upgrade to Add Mint**
```solidity
// VULNERABLE: upgradeable proxy — initial impl has no mint
// After launch, owner upgrades implementation to add mint()
function upgradeTo(address newImplementation) external onlyOwner {
    _setImplementation(newImplementation);
}
```

### Grep Patterns
```bash
# Direct mint detection
grep -rn "function mint\|function _mint\|\.mint(" src/ --include="*.sol" | grep -v "test\|mock\|node_modules\|lib/"

# Uncapped mint (mint without MAX_SUPPLY or cap check)
grep -rn "_mint(" src/ --include="*.sol" | grep -v "require\|MAX_SUPPLY\|maxSupply\|cap\|test"

# Hidden balance manipulation
grep -rn "_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|_transfer\|_mint"
grep -rn "_totalSupply +=" src/ --include="*.sol" | grep -v "_mint\|test"

# Delegatecall (can proxy any function including mint)
grep -rn "delegatecall\|DELEGATECALL" src/ --include="*.sol"

# Proxy upgrade (can swap entire implementation)
grep -rn "upgradeTo\|_setImplementation\|_upgradeTo" src/ --include="*.sol"
```

### Kill Signals
- `MAX_SUPPLY` constant defined AND enforced in every mint path
- Mint function removed entirely (total supply set in constructor)
- Ownership renounced AND no proxy/delegatecall
- OpenZeppelin `ERC20Capped` used with immutable cap

### Real Paid Examples
| Token/Protocol | Loss | Bug |
|---|---|---|
| SQUID Token | $3.4M | Owner mint + anti-sell mechanism combined |
| Meerkat Finance | $31M | Proxy upgrade added mint after TVL grew |
| Paid Network (PAID) | $27M | Infinite mint via compromised owner key |
| Cover Protocol | $4M | Mint function in staking contract with no cap |

---

## 2. HONEYPOT / TRANSFER RESTRICTION
> 25% of meme coin scams. Tokens that let you buy but block sells through transfer restrictions, blacklists, or max transaction limits set to zero.
> Real: Squid Game Token, hundreds of daily honeypots on BSC/ETH

### What It Is

The contract appears normal — users can buy on Uniswap/Raydium. But a hidden mechanism prevents selling:
- Blacklist mapping that blocks all non-owner transfers
- `maxTxAmount` setter that owner sets to 0 after buys come in
- Transfer function that reverts for non-whitelisted addresses
- Approve function that silently fails for the DEX router

### Root Cause Patterns

**Variant 1: Blacklist on Sell**
```solidity
// VULNERABLE: owner can block any address from selling
mapping(address => bool) private _isBlacklisted;

function _transfer(address from, address to, uint256 amount) internal override {
    require(!_isBlacklisted[from], "Blacklisted");
    super._transfer(from, to, amount);
}

function blacklist(address account) external onlyOwner {
    _isBlacklisted[account] = true;
}
```

**Variant 2: Max Transaction to Zero**
```solidity
// VULNERABLE: owner can set max tx to 0, blocking all transfers
uint256 public maxTxAmount = 1000000e18;

function setMaxTxAmount(uint256 amount) external onlyOwner {
    maxTxAmount = amount; // No minimum! Can be set to 0
}

function _transfer(address from, address to, uint256 amount) internal override {
    require(amount <= maxTxAmount, "Exceeds max tx");
    super._transfer(from, to, amount);
}
```

**Variant 3: Sell-Only Cooldown**
```solidity
// VULNERABLE: cooldown only applies to sells, not buys
mapping(address => uint256) private _lastSell;

function _transfer(address from, address to, uint256 amount) internal override {
    if (to == uniswapPair) { // This is a sell
        require(block.timestamp >= _lastSell[from] + 86400, "Cooldown");
        _lastSell[from] = block.timestamp;
    }
    super._transfer(from, to, amount);
}
// Owner can set cooldown to type(uint256).max, blocking sells forever
```

**Variant 4: Approve Override**
```solidity
// VULNERABLE: approve silently does nothing for non-owner
function approve(address spender, uint256 amount) public override returns (bool) {
    if (msg.sender == owner()) {
        _approve(msg.sender, spender, amount);
        return true;
    }
    // Silently returns true without actually approving
    return true;
}
```

### Grep Patterns
```bash
# Blacklist mechanisms
grep -rn "blacklist\|isBlacklisted\|_isBlocked\|_blocked\|isBot\|_bots" src/ --include="*.sol"

# Max transaction limits with setters
grep -rn "maxTxAmount\|_maxWalletSize\|maxTransactionAmount\|maxWallet" src/ --include="*.sol"
grep -rn "setMaxTx\|setMaxWallet\|updateMaxTx" src/ --include="*.sol"

# Cooldown mechanisms
grep -rn "cooldown\|_lastSell\|_lastTx\|tradeCooldown" src/ --include="*.sol"

# Transfer restriction flags
grep -rn "tradingEnabled\|tradingActive\|canTrade\|_tradingOpen" src/ --include="*.sol"
grep -rn "enableTrading\|openTrading\|setTrading" src/ --include="*.sol"

# Approve overrides (should almost never be overridden)
grep -rn "function approve.*override" src/ --include="*.sol"
```

### Kill Signals
- No blacklist mapping or function anywhere in contract
- `maxTxAmount` has enforced minimum (e.g., 0.1% of supply)
- No `onlyOwner` functions that modify transfer behavior
- Contract is a clean OpenZeppelin ERC20 with no overrides

### Real Paid Examples
| Token/Protocol | Mechanism | Bug |
|---|---|---|
| Squid Game Token | Blacklist + anti-sell | Could buy but never sell |
| Numerous BSC tokens | maxTxAmount to 0 | Daily occurrence on BSC |
| Various honeypots | approve override | Router can't get approval to swap |

---

## 3. FEE MANIPULATION
> 20% of meme coin scams. Owner can change buy/sell fees dynamically — launch at 0%, wait for volume, set sell fee to 99%.
> Real: SafeMoon clones, tax token ecosystem

### What It Is

The contract has configurable buy/sell fees. At launch, fees are 0-5% to attract buyers. Once sufficient liquidity and holders exist, the owner sets the sell fee to 50-99%, effectively trapping all holders. The fee goes to the owner's wallet or a "marketing" address they control.

### Root Cause Patterns

**Variant 1: Unbounded Fee Setter**
```solidity
// VULNERABLE: no upper bound on fees
uint256 public buyFee = 3;
uint256 public sellFee = 3;

function setFees(uint256 _buyFee, uint256 _sellFee) external onlyOwner {
    buyFee = _buyFee;
    sellFee = _sellFee;
    // No require(sellFee <= MAX_FEE)!
}

// CORRECT: bounded fees
function setFees(uint256 _buyFee, uint256 _sellFee) external onlyOwner {
    require(_buyFee <= 10 && _sellFee <= 10, "Fee too high"); // Max 10%
    buyFee = _buyFee;
    sellFee = _sellFee;
}
```

**Variant 2: Hidden Fee Recipient Change**
```solidity
// VULNERABLE: marketing wallet can be changed to any address
address public marketingWallet;

function setMarketingWallet(address _wallet) external onlyOwner {
    marketingWallet = _wallet;
}

// In _transfer: fees go to marketingWallet
// Owner changes to fresh wallet, sets fee to 50%, drains via swaps
```

**Variant 3: Fee Bypass for Owner**
```solidity
// VULNERABLE: owner excluded from fees, can sell tax-free
mapping(address => bool) private _isExcludedFromFee;

constructor() {
    _isExcludedFromFee[owner()] = true;
    _isExcludedFromFee[address(this)] = true;
}

function _transfer(address from, address to, uint256 amount) internal {
    uint256 fee = _isExcludedFromFee[from] ? 0 : (amount * sellFee / 100);
    // Owner sells at 0% fee while everyone else pays 99%
}
```

**Variant 4: Dynamic Fee Based on Block**
```solidity
// VULNERABLE: fee changes based on block number (sniper tax that never expires)
function _getFee() internal view returns (uint256) {
    if (block.number <= launchBlock + 3) return 99; // "anti-sniper"
    return sellFee; // But sellFee can be set to 99 too
}
```

### Grep Patterns
```bash
# Fee variables and setters
grep -rn "_taxFee\|_sellFee\|_buyFee\|_liquidityFee\|_marketingFee" src/ --include="*.sol"
grep -rn "setFee\|updateFee\|setTax\|updateTax\|setBuyFee\|setSellFee" src/ --include="*.sol"

# Fee bounds check (look for absence of require/max check)
grep -rn "function set.*Fee\|function set.*Tax" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<=\|<"

# Fee exclusion
grep -rn "_isExcludedFromFee\|isExcludedFromFee\|excludeFromFee" src/ --include="*.sol"

# Marketing/dev wallet changes
grep -rn "setMarketingWallet\|setDevWallet\|setTaxWallet\|setFeeReceiver" src/ --include="*.sol"

# Block-based fees
grep -rn "launchBlock\|block.number.*fee\|block.number.*tax" src/ --include="*.sol"
```

### Kill Signals
- Fee setters have `require(fee <= MAX_FEE)` with MAX_FEE <= 10%
- Fees are immutable (set in constructor, no setter)
- Timelock on fee changes (>= 24 hours)
- No fee exclusion for owner/deployer

### Real Paid Examples
| Token/Protocol | Fee Range | Bug |
|---|---|---|
| SafeMoon clones (100s) | 0% → 99% | Unbounded fee setter, standard rug pattern |
| Various "reflection" tokens | Dynamic | Fee calculation manipulated via reflection mechanics |
| Anti-sniper tokens | 99% block-based | Anti-sniper fee never turned off by design |

---

## 4. LIQUIDITY POOL DRAIN / LP LOCK BYPASS
> 15% of meme coin rugs. Even with "locked" LP, deployers find ways to drain liquidity — fake lock contracts, backdoor timelocks, or LP token migration.
> Real: numerous "LP locked" rugs on BSC, Unicrypt/PinkLock bypass attempts

### What It Is

After token launch, liquidity is added to a DEX (Uniswap/PancakeSwap). The LP tokens represent ownership of that liquidity. Legitimate projects lock LP tokens in a timelock contract. Rug vectors:
- Fake lock contract that the deployer controls
- Timelock with an owner-callable `emergencyWithdraw()`
- Migrating LP tokens to a new pair (draining the old one)
- Removing liquidity by minting enough tokens to imbalance the pool

### Root Cause Patterns

**Variant 1: Fake Lock Contract**
```solidity
// VULNERABLE: "lock" contract with owner override
contract FakeLock {
    mapping(address => uint256) public unlockTime;

    function lock(address token, uint256 duration) external {
        unlockTime[token] = block.timestamp + duration;
        // ... transfers token to this contract
    }

    // BACKDOOR: owner can withdraw anytime
    function emergencyWithdraw(address token) external onlyOwner {
        IERC20(token).transfer(owner(), IERC20(token).balanceOf(address(this)));
    }
}
```

**Variant 2: LP Migration**
```solidity
// VULNERABLE: can migrate liquidity to new pair
function migrateLP(address newPair) external onlyOwner {
    uint256 lpBalance = IUniswapV2Pair(pair).balanceOf(address(this));
    IUniswapV2Pair(pair).transfer(newPair, lpBalance);
    pair = newPair; // Old pair is now empty
}
```

**Variant 3: Pool Drain via Mint**
```solidity
// VULNERABLE: mint tokens, swap into pool, drain ETH side
// Step 1: mint(owner, 1000000000e18)
// Step 2: swap tokens for ETH on Uniswap
// Step 3: Pool ETH is drained, token price = 0
// This is why hidden mint + LP drain are often combined
```

**Variant 4: Sync Manipulation**
```solidity
// VULNERABLE: direct pair.sync() after balance manipulation
function skim() external onlyOwner {
    // Transfer tokens directly to pair (bypassing swap)
    _transfer(address(this), pair, balanceOf(address(this)));
    // Force pair to re-sync reserves
    IUniswapV2Pair(pair).sync();
    // Price is now manipulated
}
```

### Grep Patterns
```bash
# LP token handling
grep -rn "IUniswapV2Pair\|IUniswapV2Router\|IPancakeRouter\|addLiquidity\|removeLiquidity" src/ --include="*.sol"

# LP migration functions
grep -rn "migrate\|migrateLP\|setNewPair\|updatePair" src/ --include="*.sol"

# Emergency withdraw (in lock contracts)
grep -rn "emergencyWithdraw\|forceWithdraw\|rescueTokens\|recoverTokens" src/ --include="*.sol"

# Pair sync manipulation
grep -rn "\.sync()\|pair\.sync\|IUniswapV2Pair.*sync" src/ --include="*.sol"

# Direct pair transfers (bypassing router)
grep -rn "_transfer.*pair\|transfer.*uniswapPair\|transfer.*pancakePair" src/ --include="*.sol"
```

### Kill Signals
- LP locked in verified, audited timelock (Unicrypt, Team Finance, PinkLock)
- No `emergencyWithdraw` or owner override in lock contract
- No migration functions in token contract
- Ownership renounced AND no proxy

### Real Paid Examples
| Token/Protocol | Method | Bug |
|---|---|---|
| Various BSC tokens | Fake lock contract | emergencyWithdraw bypasses timelock |
| TurtleDEX | LP migration | Migrated LP to deployer-controlled pair |
| Compounder Finance | Direct removal | Removed $10.8M LP after "lock" expired early |

---

## 5. BONDING CURVE MANIPULATION
> Growing attack vector since pump.fun (2024). Exploits in bonding curve math, graduation mechanics, and migration to DEX.
> Real: pump.fun graduation exploits, Bonding curve MEV

### What It Is

Bonding curves price tokens mathematically — early buyers pay less, price rises with supply. Platforms like pump.fun, friend.tech, and similar use bonding curves for token launches. Attack vectors:
- Manipulating curve parameters to frontrun graduation
- Sniping the migration from bonding curve to DEX
- Virtual reserve manipulation to distort pricing
- Graduation threshold gaming (buying right before migration for guaranteed arbitrage)

### Root Cause Patterns

**Variant 1: Graduation Frontrun (pump.fun style)**
```
// Attack flow:
// 1. Monitor bonding curve — token at 95% of graduation threshold
// 2. Buy remaining 5% to trigger graduation (migration to Raydium)
// 3. During migration, the price resets to DEX market price
// 4. Sell immediately on Raydium at migration price
// Profit = difference between curve price and DEX opening price
```

**Variant 2: Virtual Reserve Inflation**
```solidity
// VULNERABLE: owner can change virtual reserves
uint256 public virtualTokenReserves;
uint256 public virtualSolReserves;

function setVirtualReserves(uint256 tokenRes, uint256 solRes) external onlyOwner {
    virtualTokenReserves = tokenRes;
    virtualSolReserves = solRes;
}
// Changing reserves distorts the price curve
// Owner inflates sol reserves → price appears lower → attracts buyers
// Then deflates → price spikes → owner sells
```

**Variant 3: Curve Parameter Swap**
```solidity
// VULNERABLE: curve formula can be changed post-launch
uint256 public curveExponent = 2; // quadratic by default

function setCurveParams(uint256 _exp) external onlyOwner {
    curveExponent = _exp; // Change from quadratic to linear or exponential
}

function getPrice(uint256 supply) public view returns (uint256) {
    return basePrice * (supply ** curveExponent) / PRECISION;
}
```

### Grep Patterns
```bash
# Bonding curve mechanics
grep -rn "bondingCurve\|bonding_curve\|curvePrice\|getPrice.*supply" src/ --include="*.sol"

# Virtual reserves
grep -rn "virtualReserve\|virtual_reserve\|virtualToken\|virtualSol" src/ --include="*.sol"
grep -rn "virtualReserve\|virtual_reserve\|virtual_token\|virtual_sol" src/ --include="*.rs"

# Graduation/migration
grep -rn "graduate\|migration\|migrateToPool\|createPool\|addInitialLiquidity" src/ --include="*.sol"
grep -rn "graduate\|migrate_to_pool\|create_pool\|add_initial_liquidity" src/ --include="*.rs"

# Curve parameter setters
grep -rn "setCurve\|setExponent\|updateCurve\|setSlope\|setBasePrice" src/ --include="*.sol"
```

### Kill Signals
- Curve parameters are immutable (set in constructor/initializer only)
- Virtual reserves cannot be modified after creation
- Graduation is permissionless (anyone can trigger, not just owner)
- Migration uses verified DEX factory (Raydium, Uniswap)

---

## 6. METADATA & AUTHORITY RETENTION (SOLANA-FOCUSED)
> Critical for Solana meme coins. Retained authorities (mint, freeze, update) are the #1 rug vector on Solana.
> Real: numerous Solana meme coin rugs via retained mint authority

### What It Is

SPL tokens on Solana have explicit authority fields:
- **Mint Authority** — can mint new tokens (inflate supply)
- **Freeze Authority** — can freeze any account (honeypot)
- **Update Authority** — can change token metadata (name, symbol, image)
- **Close Authority** (Token-2022) — can close token accounts

Legitimate tokens set these to `None` after launch. Rug tokens retain them.

### Root Cause Patterns

**Retained Mint Authority (Rust/Anchor)**
```rust
// VULNERABLE: mint authority not revoked
pub fn initialize_mint(ctx: Context<InitMint>) -> Result<()> {
    let mint = &ctx.accounts.mint;
    token::initialize_mint(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),
        9, // decimals
        ctx.accounts.authority.key, // mint authority = deployer
        Some(ctx.accounts.authority.key), // freeze authority = deployer
    )?;
    // Never calls set_authority to revoke!
    Ok(())
}

// CORRECT: revoke authorities after initial mint
pub fn revoke_authorities(ctx: Context<RevokeAuth>) -> Result<()> {
    token::set_authority(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),
        token::spl_token::instruction::AuthorityType::MintTokens,
        None, // Revoke mint authority
    )?;
    token::set_authority(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),
        token::spl_token::instruction::AuthorityType::FreezeAccount,
        None, // Revoke freeze authority
    )?;
    Ok(())
}
```

**Token-2022 Transfer Hook as Honeypot**
```rust
// VULNERABLE: transfer hook can block transfers
// Token-2022 extension: TransferHook
// The hook program is called on every transfer
// If hook reverts → transfer blocked → honeypot

pub fn transfer_hook(ctx: Context<TransferHook>) -> Result<()> {
    // Owner can update this logic to block sells
    if ctx.accounts.destination.key == &BLOCKED_POOL {
        return Err(ErrorCode::TransferBlocked.into());
    }
    Ok(())
}
```

### Grep Patterns
```bash
# Solana authority checks
grep -rn "mint_authority\|MintAuthority" src/ --include="*.rs"
grep -rn "freeze_authority\|FreezeAuthority" src/ --include="*.rs"
grep -rn "update_authority\|UpdateAuthority" src/ --include="*.rs"
grep -rn "close_authority\|CloseAuthority" src/ --include="*.rs"

# Authority revocation (good sign)
grep -rn "set_authority.*None\|AuthorityType::MintTokens" src/ --include="*.rs"

# Token-2022 extensions (potential risk vectors)
grep -rn "transfer_hook\|TransferHook\|TransferHookExtension" src/ --include="*.rs"
grep -rn "permanent_delegate\|PermanentDelegate" src/ --include="*.rs"
grep -rn "confidential_transfer\|ConfidentialTransfer" src/ --include="*.rs"
grep -rn "non_transferable\|NonTransferable" src/ --include="*.rs"

# Metadata mutability
grep -rn "is_mutable.*true\|isMutable.*true" src/ --include="*.rs"
grep -rn "update_metadata\|UpdateMetadata" src/ --include="*.rs"
```

### Kill Signals
- All authorities set to `None` (verified on-chain via Solscan/Solana Explorer)
- No Token-2022 transfer hook extension
- Metadata `is_mutable = false`
- Program is not upgradeable (no upgrade authority)

---

## 7. FAKE RENOUNCE / HIDDEN OWNERSHIP
> Deployer appears to renounce ownership but retains backdoor control. Trust theater — the most deceptive rug pattern.
> Real: sophisticated rugs that pass basic "ownership renounced" checks

### What It Is

The deployer calls `renounceOwnership()` and ownership shows as `address(0)`. Scanners report "ownership renounced = safe." But the deployer retains control through:
- Overridden `renounceOwnership()` that doesn't actually renounce
- Pre-approved allowances that persist after renounce
- Constructor-set addresses with special privileges
- CREATE2 redeployment to predictable address

### Root Cause Patterns

**Variant 1: Fake Renounce Override**
```solidity
// VULNERABLE: renounceOwnership does nothing
function renounceOwnership() public override onlyOwner {
    // Emits event but doesn't clear owner
    emit OwnershipTransferred(owner(), address(0));
    // owner() still returns the deployer!
    // Missing: _transferOwnership(address(0));
}
```

**Variant 2: Shadow Admin via Constructor**
```solidity
// VULNERABLE: constructor sets a second admin that survives renounce
address private _shadowAdmin;

constructor() {
    _shadowAdmin = msg.sender;
}

modifier onlyAdmin() {
    require(msg.sender == owner() || msg.sender == _shadowAdmin);
    _;
}

// Owner can renounce, but _shadowAdmin still has control
function setFees(uint256 fee) external onlyAdmin { ... }
```

**Variant 3: Pre-Approved Allowance**
```solidity
// VULNERABLE: constructor approves deployer for max tokens
constructor() {
    _approve(address(this), msg.sender, type(uint256).max);
    // After renounce, deployer can still transferFrom the contract's tokens
}
```

**Variant 4: CREATE2 Redeploy**
```solidity
// VULNERABLE: contract deployed via CREATE2
// Deployer can selfdestruct and redeploy to same address with new code
// Old approvals and state are gone, but address relationships persist
// Particularly dangerous in proxy patterns
```

### Grep Patterns
```bash
# Renounce override (should NOT override without calling super)
grep -rn "function renounceOwnership.*override" src/ --include="*.sol"
grep -rn "renounceOwnership" -A5 src/ --include="*.sol" | grep -v "_transferOwnership\|super\."

# Hidden admin patterns
grep -rn "_admin\|_shadowAdmin\|_secondOwner\|_backupOwner\|_manager" src/ --include="*.sol"
grep -rn "modifier.*admin\|modifier.*manager\|modifier.*operator" src/ --include="*.sol"

# Constructor approvals
grep -rn "constructor" -A10 src/ --include="*.sol" | grep "_approve\|allowance\|type(uint256).max"

# CREATE2 deployment
grep -rn "CREATE2\|create2\|selfdestruct\|SELFDESTRUCT" src/ --include="*.sol"

# Multiple privilege roles
grep -rn "onlyOwner\|onlyAdmin\|onlyOperator\|onlyManager" src/ --include="*.sol" | sort | uniq -c | sort -rn
```

### Kill Signals
- `renounceOwnership()` is NOT overridden (uses OpenZeppelin default)
- No second admin/operator/manager role in contract
- No constructor approvals for deployer
- No CREATE2 or selfdestruct
- Verified on-chain: `owner()` returns `address(0)`

---

## 8. SANDWICH & MEV EXPLOITATION BY DESIGN
> Token contracts designed to maximize MEV extraction against their own holders. Not a market issue — the contract is built to enable it.
> Real: tokens with no slippage protection, forced routing through attacker pools

### What It Is

Some token contracts are intentionally designed to make their holders maximally vulnerable to sandwich attacks and MEV. Unlike external sandwich bots (which are a market issue), these bugs are in the token contract itself:
- No minimum output / slippage protection in swap functions
- Forced routing through specific pools the deployer controls
- Rebasing on swap that creates guaranteed arbitrage
- Tax mechanics that create predictable price impact

### Root Cause Patterns

**Variant 1: No Slippage Protection in Auto-Swap**
```solidity
// VULNERABLE: auto-swap with 0 minimum output
function swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();

    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0, // amountOutMin = 0! Accepts ANY output, guaranteed sandwich profit
        path,
        address(this),
        block.timestamp
    );
}
```

**Variant 2: Forced Routing**
```solidity
// VULNERABLE: contract forces swaps through specific pool
address public mandatoryPool; // Owner can change this

function _transfer(address from, address to, uint256 amount) internal {
    if (to == uniswapPair && amount > swapThreshold) {
        // Force route through mandatoryPool first
        _swapVia(mandatoryPool, amount);
    }
}
// Owner sets mandatoryPool to a pool they control with thin liquidity
// → guaranteed massive slippage = guaranteed MEV profit
```

**Variant 3: Rebasing on Swap**
```solidity
// VULNERABLE: balance changes on every swap create arbitrage
function _transfer(address from, address to, uint256 amount) internal {
    if (to == uniswapPair || from == uniswapPair) {
        _rebase(); // Changes totalSupply on every swap
        // Creates price discrepancy between real and expected price
        // Bots can calculate exact rebase impact → sandwich
    }
}
```

### Grep Patterns
```bash
# Auto-swap with zero slippage
grep -rn "amountOutMin.*0\|swapExact.*,\s*0\s*," src/ --include="*.sol"
grep -rn "swapExactTokensForETH\|swapExactTokensForTokens" -A5 src/ --include="*.sol" | grep "0,"

# Forced routing
grep -rn "mandatoryPool\|forcedRoute\|requiredPool\|routeVia" src/ --include="*.sol"

# Swap-triggered rebasing
grep -rn "_rebase\|rebase()\|_reflect\|reflect()" src/ --include="*.sol"
grep -rn "function _transfer" -A20 src/ --include="*.sol" | grep "rebase\|reflect\|sync"

# Swap threshold manipulation
grep -rn "swapThreshold\|numTokensSellToAddToLiquidity\|swapTokensAtAmount" src/ --include="*.sol"
grep -rn "setSwapThreshold\|setSwapAmount\|updateSwapTokens" src/ --include="*.sol"
```

### Kill Signals
- `amountOutMin` calculated with proper slippage (not hardcoded 0)
- No auto-swap in transfer function
- No rebasing mechanics
- Standard Uniswap/PancakeSwap integration without custom routing

---

## QUICK REFERENCE

| Class | Chain | Key Grep | Severity |
|---|---|---|---|
| 1. Hidden Mint | EVM | `function mint\|_mint(` without cap | CRITICAL |
| 2. Honeypot | EVM | `blacklist\|maxTxAmount\|approve.*override` | CRITICAL |
| 3. Fee Manipulation | EVM | `setFee\|setSellFee` without bound | HIGH-CRITICAL |
| 4. LP Drain | EVM | `emergencyWithdraw\|migrateLP\|\.sync()` | CRITICAL |
| 5. Bonding Curve | EVM/SOL | `virtualReserve\|setCurve\|graduate` | HIGH |
| 6. Authority Retention | SOL | `mint_authority\|freeze_authority` | CRITICAL |
| 7. Fake Renounce | EVM | `renounceOwnership.*override\|_shadowAdmin` | CRITICAL |
| 8. Sandwich by Design | EVM | `amountOutMin.*0\|_rebase\|mandatoryPool` | HIGH |

---

-> NEXT: [11-solana-token-audit.md](11-solana-token-audit.md) — Deep dive into Solana-specific token vulnerabilities
