---
description: Meme coin and token security scan — checks for rug pull vectors (hidden mint, honeypot, fee manipulation, LP lock bypass, authority retention, bonding curve exploits, fake renounce, sandwich amplification). Runs automated token_scanner.py + manual 8-class audit. Usage: /token-scan <contract_path_or_dir> [--chain solana]
---

# /token-scan

Fast rug pull detection for meme coins and token contracts. Covers EVM (Solidity) and Solana (Rust/Anchor).

## Usage

```
/token-scan contracts/Token.sol                          # Single EVM contract
/token-scan src/ --recursive                             # Scan entire directory
/token-scan programs/token/ --chain solana --recursive   # Solana program
/token-scan contracts/Token.sol --output findings/report.md  # Save report
```

## Step 0: Quick Kill Signals

Before scanning code, check:

```
[ ] Contract is verified (source code available)?
[ ] Deployer has no rug history?
[ ] Token has been trading > 1 hour?
[ ] Liquidity > $5K?
[ ] Not a proxy with retained admin?
```

If ANY answer is NO → flag and proceed with extreme caution.

## Step 1: Run Automated Scanner

```bash
# EVM
python3 tools/token_scanner.py <contract_path>

# Solana
python3 tools/token_scanner.py <program_dir> --chain solana --recursive

# JSON output for piping
python3 tools/token_scanner.py <path> --json
```

The scanner checks all 8 bug classes via regex and returns a risk score + verdict.

## Step 2: Hidden Mint Check

```bash
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib"
grep -rn "delegatecall" src/ --include="*.sol"
# Solana:
grep -rn "MintTo\|mint_to\|mint_authority" src/ --include="*.rs"
```

Look for: mint without MAX_SUPPLY cap, direct balance manipulation, delegatecall to unknown targets.

## Step 3: Honeypot Check

```bash
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|approve.*override" src/ --include="*.sol"
# Solana:
grep -rn "freeze_authority\|transfer_hook\|permanent_delegate" src/ --include="*.rs"
```

Look for: blacklist mappings, max tx setters without minimum bound, approve overrides that don't call super.

## Step 4: Fee Manipulation Check

```bash
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX"
```

Look for: fee setters without upper bound, fee exclusion for owner.

## Step 5: LP Drain Check

```bash
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
grep -rn "addLiquidityETH" -A5 src/ --include="*.sol" | grep "owner\|msg.sender"
```

Look for: LP migration functions, emergency withdraw, auto-LP to owner wallet.

## Step 6: Bonding Curve Check

```bash
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
```

Look for: mutable curve parameters, manipulable graduation threshold.

## Step 7: Authority Check (Solana)

```bash
grep -rn "mint_authority\|freeze_authority\|update_authority\|close_authority" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"
grep -rn "upgrade_authority" src/ --include="*.rs"
```

Look for: retained authorities that should be None, upgradeable programs.

## Step 8: Fake Renounce Check

```bash
grep -rn "renounceOwnership.*override" src/ --include="*.sol"
grep -rn "_shadowAdmin\|_backupOwner" src/ --include="*.sol"
```

Look for: overridden renounce without actual transfer, secondary admin roles.

## Step 9: Sandwich Amplification Check

```bash
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"
grep -rn "swapThreshold\|_rebase\|reflect()" src/ --include="*.sol"
```

Look for: auto-swap with amountOutMin=0, rebase on every transfer.

## Output

The scanner produces:
- **Risk score** (0-100) based on finding severity
- **Verdict** (CLEAN / LOW RISK / MEDIUM RISK / HIGH RISK / CRITICAL RISK)
- **Individual findings** with file:line, code snippet, and recommendation
- **Exit code** 1 if CRITICAL/HIGH findings (for CI integration)

## What to Do Next

- If CRITICAL findings → **DO NOT INTERACT**. Report if on Immunefi/Code4rena.
- If HIGH findings → Manual deep review. May be intentional design. Check deployer history.
- If MEDIUM findings → Flag for awareness. Likely not rug but worth monitoring.
- If CLEAN → Token passes automated checks. Still verify on-chain state manually.

## 5-Minute Rule

If you've been scanning for 5 minutes and found no red flags across all 8 classes + automated scan → the token is likely clean. Move on. Don't hunt for phantom bugs.
