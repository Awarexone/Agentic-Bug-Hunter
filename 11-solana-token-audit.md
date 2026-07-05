---
name: solana-token-audit
description: Solana SPL token and program security audit reference. Covers mint authority retention, freeze authority abuse, metadata mutability, Token-2022 extension risks (transfer hooks, confidential transfers, transfer fees, permanent delegate), pump.fun bonding curve analysis, Raydium LP pool attacks, Jupiter aggregator routing exploits, and PDA authority patterns. Use when auditing any Solana token, meme coin, or DeFi program.
---

# SOLANA TOKEN SECURITY — SPL Token & Program Vulnerabilities

Solana meme coins are architecturally different from EVM tokens. Instead of a single contract, you audit:
- **SPL Token mint** (authority fields)
- **Token-2022 extensions** (transfer hooks, permanent delegates, etc.)
- **Program instructions** (Anchor/native — the logic that interacts with the token)
- **Metadata** (Metaplex — name, symbol, image, mutability)
- **DEX integration** (Raydium, Orca, Meteora, Jupiter routing)

This file covers Solana-specific attack vectors that don't exist on EVM.

---

## 1. SPL TOKEN AUTHORITY CHECKLIST

Every SPL token has four authority fields. Each retained authority = a rug vector.

### Authority Matrix

| Authority | What It Does | Rug Vector | How to Check |
|---|---|---|---|
| **Mint Authority** | Can mint new tokens | Infinite mint → dump on LP | `spl-token display <mint>` → mint_authority |
| **Freeze Authority** | Can freeze any token account | Freeze buyer accounts → honeypot | `spl-token display <mint>` → freeze_authority |
| **Update Authority** | Can change metadata | Change name/symbol/image to scam | Metaplex metadata account → update_authority |
| **Close Authority** (Token-2022) | Can close token accounts | Destroy user token accounts | Token-2022 extension data |

### Checking On-Chain
```bash
# Check mint authority and freeze authority
solana account <MINT_ADDRESS> --output json | jq '.data'
# Or use spl-token CLI:
spl-token display <MINT_ADDRESS>

# Check metadata (Metaplex)
# Look for update_authority and is_mutable fields
# Use Solscan → Token → Metadata tab

# Programmatic check (Anchor/Rust)
let mint_info = Mint::unpack(&mint_account.data.borrow())?;
assert!(mint_info.mint_authority.is_none(), "Mint authority not revoked!");
assert!(mint_info.freeze_authority.is_none(), "Freeze authority not revoked!");
```

### Grep Patterns (Source Code Audit)
```bash
# Mint authority retention
grep -rn "mint_authority" src/ --include="*.rs"
grep -rn "MintTo\|mint_to\|token::mint_to" src/ --include="*.rs"

# Freeze authority
grep -rn "freeze_authority\|FreezeAccount\|freeze_account" src/ --include="*.rs"
grep -rn "ThawAccount\|thaw_account" src/ --include="*.rs"

# Authority changes (should go to None for safety)
grep -rn "set_authority\|SetAuthority\|AuthorityType" src/ --include="*.rs"
grep -rn "set_authority" -A5 src/ --include="*.rs" | grep "None"

# Check if authorities are EVER revoked
grep -rn "AuthorityType::MintTokens" src/ --include="*.rs"
grep -rn "AuthorityType::FreezeAccount" src/ --include="*.rs"
```

### Red Flags
- `mint_authority = Some(deployer_pubkey)` after token launch
- `freeze_authority = Some(any_pubkey)` on a meme coin (legitimate use is rare)
- No `set_authority(..., None)` call anywhere in the codebase
- Authority transferred to a PDA controlled by an upgradeable program

---

## 2. TOKEN-2022 EXTENSION RISKS

Token-2022 (SPL Token 2022) adds extensions that create NEW rug vectors not possible with legacy SPL tokens.

### Extension Risk Matrix

| Extension | Risk Level | Rug Vector |
|---|---|---|
| **Transfer Hook** | CRITICAL | Hook program can block transfers → honeypot |
| **Permanent Delegate** | CRITICAL | Delegate can transfer/burn ANY holder's tokens |
| **Transfer Fee** | HIGH | Fee can be set to 100% on sells |
| **Non-Transferable** | HIGH | Can be toggled to lock all tokens |
| **Confidential Transfer** | MEDIUM | Hides amounts, harder to audit |
| **Default Account State** | MEDIUM | New accounts created frozen by default |
| **Interest-Bearing** | LOW | Interest rate manipulation |
| **Metadata** | LOW | On-chain metadata can be changed |

### Transfer Hook Deep Dive (Most Dangerous)

```rust
// VULNERABLE: Transfer hook that blocks sells to DEX pools
use spl_transfer_hook_interface::instruction::ExecuteInstruction;

pub fn transfer_hook(ctx: Context<TransferHook>) -> Result<()> {
    let destination = ctx.accounts.destination_account.key();

    // Check if destination is a DEX pool
    // If owner has added the pool to blocked list → honeypot
    let blocked = &ctx.accounts.blocked_list;
    if blocked.addresses.contains(&destination) {
        return Err(ErrorCode::TransferBlocked.into());
    }

    Ok(())
}

// The blocked_list account can be updated by the program authority
// After buyers are in → add the Raydium pool to blocked list → sells blocked
```

### Permanent Delegate Deep Dive

```rust
// CRITICAL: Permanent delegate can steal ALL tokens
// Token-2022 extension: PermanentDelegate
// The delegate can transfer tokens FROM any account WITHOUT approval

// If mint has permanent_delegate set:
// - Delegate calls transfer_checked() from ANY holder's account
// - No approve() needed
// - Holders cannot prevent it
// This is BY DESIGN in the extension — the rug IS the feature

// Check: does the mint have PermanentDelegate extension?
let mint_data = ctx.accounts.mint.to_account_info();
let extension = get_extension::<PermanentDelegate>(&mint_data)?;
// If extension.delegate != Pubkey::default() → CRITICAL RED FLAG
```

### Grep Patterns
```bash
# Transfer hook (most dangerous extension)
grep -rn "transfer_hook\|TransferHook\|spl_transfer_hook" src/ --include="*.rs"
grep -rn "execute_transfer_hook\|ExecuteInstruction" src/ --include="*.rs"

# Permanent delegate
grep -rn "permanent_delegate\|PermanentDelegate" src/ --include="*.rs"
grep -rn "get_extension.*PermanentDelegate" src/ --include="*.rs"

# Transfer fee
grep -rn "transfer_fee\|TransferFee\|TransferFeeConfig" src/ --include="*.rs"
grep -rn "set_transfer_fee\|SetTransferFee" src/ --include="*.rs"

# Non-transferable
grep -rn "non_transferable\|NonTransferable\|NonTransferableExtension" src/ --include="*.rs"

# Default account state (frozen by default = honeypot setup)
grep -rn "default_account_state\|DefaultAccountState\|AccountState::Frozen" src/ --include="*.rs"

# All Token-2022 extensions
grep -rn "spl_token_2022\|token_2022\|Token2022" src/ --include="*.rs"
```

### Kill Signals (Safe)
- No transfer hook extension on the mint
- No permanent delegate extension
- Transfer fee is 0 or reasonable (< 5%) and immutable
- Default account state is Initialized (not Frozen)

---

## 3. PUMP.FUN BONDING CURVE ANALYSIS

pump.fun is the dominant Solana meme coin launchpad. Understanding its bonding curve = understanding 90% of Solana meme coin launches.

### How pump.fun Works

```
1. Creator deploys token via pump.fun program
2. Token trades on a bonding curve (constant product: x * y = k)
3. Virtual reserves: 1.073B tokens + 30 SOL initial
4. Users buy/sell against the curve
5. At ~$69K market cap → "graduation" → migrates to Raydium
6. Migration: creates Raydium pool with accumulated SOL + remaining tokens
```

### Attack Vectors

**Vector 1: Graduation Sniping**
```
// The graduation transaction is visible in the mempool
// Attackers watch for tokens approaching the $69K threshold
// Buy right before graduation → token migrates to Raydium
// Sell immediately on Raydium at higher liquidity
// Risk: front-running the migration transaction itself

// Detection: watch for large buys when curve is 80%+ filled
```

**Vector 2: Bundled Launch Buys**
```
// Creator launches token AND buys with multiple wallets in same block
// Creator owns 20-50% of supply at launch price
// Wait for organic buys → dump on buyers
// Detection: check first few transactions after creation
//   - Multiple buys from related wallets in block 0
//   - Total creator allocation > 10%
```

**Vector 3: Creator Fee Extraction (pump.fun Advanced)**
```
// pump.fun takes 1% fee on trades
// Some clone platforms modify the fee structure:
// - Creator gets X% of every trade
// - Fee goes to creator wallet, not platform
// - Creator generates volume via wash trading to extract fees
```

### Grep Patterns (for pump.fun clones / similar programs)
```bash
# Bonding curve implementation
grep -rn "bonding_curve\|BondingCurve\|curve_amount" src/ --include="*.rs"
grep -rn "virtual_token_reserves\|virtual_sol_reserves" src/ --include="*.rs"

# Graduation / migration
grep -rn "graduate\|graduation\|migrate_to_raydium\|create_raydium_pool" src/ --include="*.rs"
grep -rn "migration_threshold\|graduation_threshold\|GRADUATION" src/ --include="*.rs"

# Fee extraction
grep -rn "creator_fee\|platform_fee\|trade_fee\|fee_basis_points" src/ --include="*.rs"
grep -rn "fee_recipient\|fee_destination\|collect_fee" src/ --include="*.rs"

# Initial buy bundling (look for multi-buy in initialization)
grep -rn "initialize.*buy\|create.*swap\|launch.*purchase" src/ --include="*.rs"
```

### Checking a pump.fun Token (No Source Code Needed)
```bash
# 1. Check first transactions (bundled buys?)
# Use Solscan → Token → Transactions → sort by oldest
# Look for: multiple buys from different wallets in same slot

# 2. Check creator holdings
# Use Birdeye/Solscan → Token → Holders tab
# Red flag: creator + related wallets > 10% of supply

# 3. Check if graduated
# Graduated = has Raydium pool
# Not graduated = still on bonding curve (lower liquidity, higher risk)

# 4. Check mint authority
solana account <MINT_ADDRESS> --output json
# mint_authority should be null after graduation
```

---

## 4. RAYDIUM LP POOL VULNERABILITIES

Raydium is the primary DEX for Solana meme coins post-graduation.

### Attack Vectors

**Vector 1: LP Burn vs Lock**
```
// Raydium CPMM: LP tokens minted to creator on pool creation
// SAFE: LP tokens burned (sent to 1111...1111 address)
// RISKY: LP tokens "locked" in a program that has withdraw functions
// WORST: LP tokens held by creator wallet (can remove anytime)

// Check: who holds the LP tokens?
// Burned = safe (irreversible)
// Program-held = check program for withdraw instructions
// Wallet-held = CRITICAL (instant rug possible)
```

**Vector 2: Pool Creation with Skewed Ratio**
```
// Creator adds liquidity with extreme token/SOL ratio
// Example: 1B tokens + 0.1 SOL
// Price per token is essentially 0
// After buys push price up, creator removes liquidity
// Gets back the SOL buyers added + their proportional tokens

// Detection: check initial pool ratio
// Normal: matches bonding curve graduation ratio
// Suspicious: wildly different from expected market cap
```

**Vector 3: Concentrated Liquidity Position Manipulation (Orca Whirlpools)**
```
// Orca uses concentrated liquidity (like Uniswap V3)
// Creator opens position in very narrow range
// When price moves out of range → all liquidity is single-sided
// Creator owns 100% of one side → removes liquidity
// Effectively a sophisticated rug using CL mechanics
```

### Grep Patterns
```bash
# Raydium pool interactions
grep -rn "raydium\|RaydiumSwap\|raydium_amm\|raydium_cp" src/ --include="*.rs"
grep -rn "create_pool\|initialize_pool\|add_liquidity\|remove_liquidity" src/ --include="*.rs"

# LP token handling
grep -rn "lp_mint\|lp_token\|pool_lp\|burn_lp\|LP_BURN" src/ --include="*.rs"

# Orca whirlpool
grep -rn "whirlpool\|Whirlpool\|open_position\|close_position\|tick_range" src/ --include="*.rs"

# Meteora DLMM
grep -rn "meteora\|dlmm\|DLMM\|dynamic_amm" src/ --include="*.rs"
```

---

## 5. JUPITER ROUTING EXPLOITS

Jupiter is Solana's dominant aggregator. Meme coin attacks can exploit Jupiter's routing.

### Attack Vectors

**Fake Pool Injection**
```
// Attacker creates a fake pool on an obscure DEX
// Pool has favorable price (lower than real pools)
// Jupiter routes trades through the fake pool
// Attacker sandwich attacks via the fake pool

// Detection: check which pools Jupiter routes through
// Red flag: routes through pools with < $1K liquidity
// Red flag: routes through pools on unverified DEX programs
```

**Price Oracle Manipulation via Jupiter**
```
// Some protocols use Jupiter quotes as price oracle
// Attacker manipulates a small pool → distorts Jupiter quote
// Protocol reads stale/manipulated price → exploit

// Grep: look for on-chain Jupiter quote usage
grep -rn "jupiter\|Jupiter\|jup_ag\|quote_response" src/ --include="*.rs"
grep -rn "get_quote\|swap_exact\|route_plan" src/ --include="*.rs"
```

---

## 6. PDA AUTHORITY PATTERNS

Program Derived Addresses (PDAs) are Solana's way of giving programs authority over accounts. Hidden authority via PDA = hidden control.

### Attack Vector: Authority Transferred to Upgradeable Program PDA

```rust
// VULNERABLE: mint authority transferred to PDA
// PDA is derived from an UPGRADEABLE program
// Step 1: Transfer mint authority to PDA
// Step 2: Program currently has no mint instruction
// Step 3: Upgrade program to add mint instruction
// Step 4: Mint via PDA → rug

pub fn transfer_authority_to_pda(ctx: Context<TransferAuth>) -> Result<()> {
    let (pda, _bump) = Pubkey::find_program_address(
        &[b"mint_auth", ctx.accounts.mint.key().as_ref()],
        ctx.program_id,
    );

    token::set_authority(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),
        AuthorityType::MintTokens,
        Some(pda), // Authority → PDA (looks safe!)
    )?;
    // But if the program is upgradeable → PDA authority = deployer authority
    Ok(())
}
```

### Grep Patterns
```bash
# PDA derivation (check what PDAs control)
grep -rn "find_program_address\|Pubkey::find_program_address" src/ --include="*.rs"
grep -rn "seeds.*=\|bump.*=\|#\[account.*seeds" src/ --include="*.rs"

# Program upgrade authority
grep -rn "upgrade_authority\|UpgradeAuthority\|programdata_address" src/ --include="*.rs"

# CPI (cross-program invocation — programs calling other programs)
grep -rn "invoke_signed\|CpiContext::new_with_signer" src/ --include="*.rs"
```

### Red Flags
- Mint authority = PDA from an upgradeable program
- Program has BPF upgrade authority set (not revoked)
- PDA seeds are predictable and derivable by deployer

### Kill Signals (Safe)
- Mint authority = None (revoked entirely)
- If PDA: program is NOT upgradeable (upgrade authority = None)
- Program deployed with `--final` flag (immutable)

---

## 7. ANCHOR PROGRAM VULNERABILITIES (Token-Specific)

Most Solana token programs use the Anchor framework. Common Anchor bugs in token contexts:

### Missing Signer Checks
```rust
// VULNERABLE: no signer check on authority
#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    pub authority: AccountInfo<'info>, // NOT Signer<'info>!
    // Anyone can pass any pubkey as authority
}

// CORRECT:
pub authority: Signer<'info>, // Requires signature
```

### Missing Owner Checks
```rust
// VULNERABLE: account owner not validated
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    // No constraint checking config.authority == signer
}

// CORRECT:
#[account(mut, has_one = authority)]
pub config: Account<'info, Config>,
pub authority: Signer<'info>,
```

### Unchecked Arithmetic
```rust
// VULNERABLE: overflow in token amount calculation
pub fn calculate_output(input: u64, reserve_in: u64, reserve_out: u64) -> u64 {
    let numerator = input * reserve_out; // Can overflow!
    let denominator = reserve_in + input;
    numerator / denominator
}

// CORRECT: use checked math
pub fn calculate_output(input: u64, reserve_in: u64, reserve_out: u64) -> Result<u64> {
    let numerator = input.checked_mul(reserve_out).ok_or(ErrorCode::Overflow)?;
    let denominator = reserve_in.checked_add(input).ok_or(ErrorCode::Overflow)?;
    numerator.checked_div(denominator).ok_or(ErrorCode::DivisionByZero)
}
```

### Grep Patterns
```bash
# Missing signer checks
grep -rn "AccountInfo<'info>" src/ --include="*.rs" | grep -v "Signer\|/// \|//\|CHECK:"

# Missing owner/has_one constraints
grep -rn "#\[account(mut)\]" src/ --include="*.rs" | grep -v "has_one\|constraint\|seeds"

# Unchecked arithmetic
grep -rn "\* \|+ \|- \|/ " src/ --include="*.rs" | grep -v "checked_\|saturating_\|test\|//\|///\|assert"

# Missing account validation
grep -rn "/// CHECK:" src/ --include="*.rs"
# Every unchecked AccountInfo should have a CHECK: comment explaining why
```

---

## SOLANA AUDIT CHECKLIST

Quick-fire checklist for any Solana meme coin:

```
[ ] Mint authority = None?
[ ] Freeze authority = None?
[ ] Update authority = None (or is_mutable = false)?
[ ] No Token-2022 transfer hook?
[ ] No Token-2022 permanent delegate?
[ ] Transfer fee = 0 or reasonable?
[ ] Program is NOT upgradeable?
[ ] LP tokens burned (not just locked)?
[ ] No bundled creator buys at launch?
[ ] Creator + related wallets < 10% of supply?
[ ] Top 10 holders < 30% of supply (excluding DEX pools)?
[ ] Pool has > $10K liquidity?
[ ] Token has been trading > 24 hours?
```

---

-> NEXT: [12-dex-lp-attacks.md](12-dex-lp-attacks.md) — DEX & LP manipulation attack patterns
