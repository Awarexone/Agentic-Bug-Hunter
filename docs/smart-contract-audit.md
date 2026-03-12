# Smart Contract Audit — Web3 Bug Bounty Hunting

Complete workflow: Target Selection → Code Review → PoC → Immunefi Report.

For authorized bug bounty hunting on Immunefi, Code4rena, Sherlock, Cantina, and CodeHawks.

---

## TARGET EVALUATION SCORECARD (Score ≥ 6/10 to Proceed)

| Criterion | Points | How to Check |
|-----------|--------|-------------|
| Max bounty ≥ $50K | +2 | Immunefi program page |
| TVL > $1M | +2 | DeFiLlama |
| Program launched < 30 days ago | +2 | Immunefi "new" filter |
| Custom math (AMM/vault/lending) | +1 | Read scope contracts |
| Recent code changes (git log) | +1 | `git log --oneline -20` |
| Prior audits available to read | +1 | Program page / GitHub |
| In-scope includes SC + web/app | +1 | Program scope section |
| Few prior reports | +1 | Check program stats |
| Protocol type you know well | +1 | Your specialization |
| Source code is public/readable | +1 | GitHub / Etherscan |

**Score < 4:** Skip
**Score 6-8:** Good target — spend 1-2 days
**Score 9-10:** Excellent — spend up to 1 week

---

## HARD KILL SIGNALS (Check These First — 10 min)

```
HARD KILL 1: TVL < $500K
  → Even a Critical pays max 10% TVL = $50K
  → Expected payout math: P(critical) * min(10%*TVL, cap) < effort cost

HARD KILL 2: 2+ top-tier audits (Trail of Bits, Halborn, Cyfrin, OpenZeppelin)
  → These firms catch 70-80% of classic bugs
  → EXCEPTION: audits > 1 year old + major code changes = still huntable

HARD KILL 3: Protocol is "simple" (< 500 lines, single function flow)
  → A→B→C with no composability = minimal attack surface

HARD KILL 4: Max payout below threshold
  → Formula: max_realistic_payout = min(10% * TVL, program_cap)
  → If max_realistic_payout < $10K, skip unless brand new
```

---

## ATTACK SURFACE MINDMAP BY PROTOCOL TYPE

```
DEX / AMM
├── Oracle manipulation (flash loan → move price → profit)
├── Rounding in pool math (1-wei edge cases × flash swap)
├── Sandwich / frontrun (missing slippage protection)
├── Fee accounting (fee-on-transfer tokens break invariants)
└── LP share inflation (first depositor / donation attack)

LENDING / BORROWING
├── Collateral valuation (oracle dependency → overborrow)
├── Liquidation logic (bad debt creation, self-liquidation)
├── Interest accrual (rounding favors borrower/lender?)
├── Flash loan → inflate collateral → borrow → repay
└── ERC4626 vault share manipulation

BRIDGE / CROSS-CHAIN
├── Message replay (missing nonce/nullifier)
├── Validator/guardian set manipulation
├── Uninitialized proxy after upgrade
├── Cross-chain signature replay (no chainId)
└── Destination execution reentrancy

VAULT / YIELD
├── Share price manipulation (donation attack)
├── ERC4626 first depositor inflation
├── Reward accounting (timing, snapshot, distribution)
└── Withdrawal queue manipulation

STABLECOIN
├── Collateral depeg cascading liquidations
├── Oracle dependence (stale price → undercollateralized)
└── Liquidation engine rounding

GOVERNANCE / DAO
├── Flash loan voting (borrow → vote → repay in 1 tx)
├── Quorum manipulation
├── Timelock bypass
└── Token snapshot timing attack

ZK ROLLUP / CIRCUIT
├── Unsound proof constraints
├── Unconstrained witness variables
├── Missing range checks in circuit
└── Exodus mode bypassing verification
```

---

## AUDIT METHODOLOGY (10-Step Process)

### Step 1: Read Documentation
- Whitepaper, README, NatSpec comments, design docs
- Gap between intent and implementation = bugs

### Step 2: Scope and Line Count
```bash
git clone <target-repo>
cloc src/ --include-lang=Solidity
```

### Step 3: Local Setup
```bash
forge build          # must compile
forge test           # run existing tests — note coverage gaps
forge coverage       # find untested code paths
```

### Step 4: Static Analysis
```bash
# Slither — 93 detectors, fast
slither . --exclude-low --filter-paths "test|lib|node_modules"
slither . --detect reentrancy-eth,unprotected-upgrade,arbitrary-send-eth

# Aderyn — Rust-based, Foundry-native
aderyn . --output report.md

# Mythril — symbolic execution (slower, deeper)
myth analyze src/Contract.sol --max-depth 6
```

### Step 5: Architecture Visualization
- Map contract relationships, value flows, external integrations
- Identify privileged roles (owner, multisig, governance)
- Note oracle dependencies (Chainlink, Uniswap TWAP, spot price)

### Step 6: Grep Surface Map
```bash
# Run GREP PATTERNS section below — 15 min
# Map: external calls, access control, oracle usage, unchecked math
# Rank red flags by fund proximity
```

### Step 7: Checklist Review
- Search Solodit (solodit.cyfrin.io) for findings on similar protocol types
- Use transmissions11/solcurity checklist
- Use Cyfrin/audit-checklist

### Step 8: Line-by-Line Manual Review
- First pass: read everything, DON'T investigate leads yet
- Second pass: investigate suspicious areas
- Focus on external/public functions, state changes, math, access control

### Step 9: Invariant Testing
```solidity
function invariant_totalAssetsMatchBalance() public {
    assertEq(vault.totalAssets(), token.balanceOf(address(vault)));
}
function invariant_noUserCanWithdrawMoreThanDeposited() public {
    // ...
}
```
```bash
forge test --match-test invariant_ -vvv
echidna test/EchidnaTest.sol --contract EchidnaTest
```

---

## BUG CLASSES — OWASP Smart Contract Top 10

### SC01: Access Control ($953M lost in 2024 — #1 priority)
- Every `external`/`public` function: who can call this? Is there a modifier?
- `initialize()` on proxy implementations: is it protected?
- `selfdestruct`, `delegatecall`, `upgrade`, `mint`, `withdraw`, `setOwner` without auth
```bash
slither . --detect missing-protection,unprotected-upgrade
```
**Real example:** Wormhole $10M — uninitialized UUPS proxy implementation

### SC02: Business Logic / Incorrect Calculations
- Division before multiplication (precision loss)
- Off-by-one in loops, boundary conditions
- Double-claiming rewards
- ERC4626 inflation attack (first depositor)

### SC03: Price Oracle Manipulation
- `getReserves()`, `slot0()` — AMM spot price reads (manipulable via flash loan)
- Chainlink without stale price check: `updatedAt + MAX_STALENESS`
- TWAP window too short (<30 min)
**Real example:** Mango Markets $117M — inflated own token price via oracle

### SC04: Flash Loan Attacks
- Any function that reads price AND acts on it in same block
- Governance without snapshot delay
```
83.3% of eligible exploits in 2024 used flash loans
```

### SC05: Lack of Input Validation
- Zero-address checks missing
- Array length mismatch (two arrays, no length check)
- No `minAmountOut` on swaps (sandwich attack vector)
- Signature without chainId or nonce (replay)
- `delegatecall` with user-controlled target/calldata

### SC06: Unchecked External Calls
- `.call{value:}` without `require(success, ...)`
- `ERC20.transfer()` on tokens that don't revert (old USDT) — need `safeTransfer`

### SC07: Arithmetic Errors
- Solidity <0.8.0: every arithmetic suspect
- Solidity 0.8.0+: `unchecked {}` blocks — manually verify safety

### SC08: Reentrancy ($35.7M lost in 2024)
**Variants:**
1. **Classic**: external call before state update
2. **Cross-function**: A calls B which calls A's sibling function
3. **Read-only**: view function returns stale value during external call (Curve $70M)
```bash
slither . --detect reentrancy-eth,reentrancy-no-eth
```

### SC10: Proxy & Upgradeability
- Uninitialized implementation: call `initialize()` on impl directly
- Storage collision: new impl adds variables before existing ones
- UUPS without `_authorizeUpgrade()` access control
```bash
slither . --detect uninitialized-local,unprotected-upgrade
```

---

## NEW IN 2024-2025: High-Value Bug Classes

### 1. ERC4626 Near-Empty Vault Manipulation
```bash
grep -rn "totalAssets\|convertToShares\|convertToAssets" src/
grep -rn "deposit\|mint\|withdraw\|redeem" src/ | grep -v "virtual\|dead"
```
**Checklist:**
- [ ] Uses OpenZeppelin's `_decimalsOffset()` virtual shares defense?
- [ ] Minimum deposit enforced?
- [ ] Can exchange rate be manipulated via direct token donation?
- [ ] Does `mint()` call `_deposit()` with same receipt checks as `deposit()`?

### 2. EIP-2612 Permit Frontrun DoS
```bash
grep -rn "permit\|IERC20Permit\|ERC20Permit" src/
grep -rn "permitAndDeposit\|permitAndStake\|permitAndBorrow" src/
```

### 3. Signature Replay Across Chains
```bash
grep -rn "ecrecover\|ECDSA\.recover" src/
grep -rn "chainId\|block\.chainid\|DOMAIN_SEPARATOR" src/
# If ecrecover present but chainId NOT present = red flag
```

### 4. ZK Proof Verifier Bypass
```bash
grep -rn "verifyProof\|verify(" src/
grep -rn "return true" src/ | grep -i "verify\|proof"
```
- [ ] Does the verifier actually revert on invalid proof?
- [ ] Is there a code path where `verifyProof()` returns true without calling verifier?

### 5. Incorrect Access Control Modifier (if vs require)
```bash
grep -A5 "modifier only" src/**/*.sol
# Look for: `if (condition) { _; }` — missing else revert
# Correct:  `require(condition, "..."); _;`
```

### 6. Donation Attack
```bash
grep -rn "balanceOf(address(this))" src/
grep -rn "totalAssets\|totalSupply" src/ | grep -v "virtual"
```

### 7. Deploy Script / Initializer Bugs
```bash
grep -rn "initialize\|__init\|constructor" script/ deploy/
grep -rn "reinitializer\|_disableInitializers" src/
```

---

## GREP QUICK-HITS (Run These First on Any New Codebase)

```bash
# ACCESS CONTROL red flags
grep -rn "tx\.origin" src/                          # never use for auth
grep -rn "msg\.sender == owner" src/                # is owner a single EOA?
grep -rn "onlyOwner\|onlyAdmin\|onlyRole" src/ | wc -l  # count privileged funcs

# REENTRANCY red flags
grep -rn "\.call{value\|\.call(" src/               # any external call
grep -rn "\.transfer(\|\.send(" src/                # ETH sends
grep -rn "nonReentrant\|ReentrancyGuard" src/       # where guards exist

# ORACLE red flags
grep -rn "slot0\b" src/                             # Uniswap V3 spot price — manipulable
grep -rn "getReserves()" src/                       # Uniswap V2 spot price — manipulable
grep -rn "latestRoundData\|latestAnswer" src/       # Chainlink — check staleness
grep -rn "updatedAt" src/                           # Is staleness checked?

# UNCHECKED MATH
grep -rn "unchecked {" src/                         # manually verify each
grep -rn "/ \|/=" src/ | grep -v "//\|test"        # division — precision loss risk

# INPUT VALIDATION
grep -rn "address(0)\|== address(0)" src/           # zero-address checks
grep -rn "require.*length\|\.length ==" src/         # array length checks
grep -rn "delegatecall" src/                        # user-controlled?

# SIGNATURE / REPLAY
grep -rn "ecrecover\|ECDSA\.recover" src/
grep -rn "chainId\|block\.chainid" src/
grep -rn "nonces\[" src/                            # nonce-based replay protection

# ERC4626
grep -rn "totalAssets\|convertToShares\|previewDeposit" src/
grep -rn "balanceOf(address(this))" src/            # raw balance read = donation attack risk

# UPGRADEABLE PROXY
grep -rn "_authorizeUpgrade\|upgradeTo\|upgradeToAndCall" src/
grep -rn "initialize(" src/ | grep -v "//\|test"

# ZK VERIFIER
grep -rn "verifyProof\|verify(" src/
grep -rn "return true" src/ | grep -i "verify\|proof"

# SOLANA / RUST
grep -rn "remaining_accounts" src/ --include="*.rs"
grep -rn "invoke\|invoke_signed" src/ --include="*.rs"
grep -rn "as u64\|as u128\|as u32" src/ --include="*.rs"  # silent truncation
```

---

## AUDIT CHECKLIST

### Access Control
- [ ] Every `external`/`public` function — who can call? Is there a modifier?
- [ ] `initialize()` protected by `initializer` modifier?
- [ ] Any `selfdestruct`, `upgrade`, `mint`, `withdraw`, `setOwner` without auth?
- [ ] Modifier uses `require` not `if` (silent bypass bug)?

### Math & Logic
- [ ] Division before multiplication?
- [ ] `unchecked {}` blocks manually verified?
- [ ] ERC4626 first depositor: virtual shares or dead shares defense?

### Reentrancy
- [ ] State updated BEFORE external calls? (CEI pattern)
- [ ] Missing `ReentrancyGuard`?
- [ ] Read-only reentrancy (view function reads stale state during callback)?

### Oracle & Price
- [ ] Single oracle dependency?
- [ ] Missing staleness check?
- [ ] Flash-loan manipulable spot price?
- [ ] TWAP window <30 min?

### Token Handling
- [ ] Fee-on-transfer tokens: balance before/after tracking?
- [ ] Rebasing tokens (stETH): snapshot accounting broken?
- [ ] `transfer()` return value checked?

### Proxy & Upgrades
- [ ] Storage slot collisions between proxy and implementation?
- [ ] Uninitialized implementation callable directly?
- [ ] UUPS: `_authorizeUpgrade()` has access control?

### Governance
- [ ] Flash-loan voting possible?
- [ ] Missing timelock between proposal pass and execution?

---

## FOUNDRY PoC WRITING

### Quick Start
```bash
forge init --template immunefi-team/forge-poc-templates --branch flash-loan my-poc
cd my-poc
echo "MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" > .env
```

### Standard PoC Structure
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitTest is Test {
    address constant TARGET = 0xVULNERABLE;
    address constant TOKEN = 0xTOKEN;

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), 18000000);
        vm.label(TARGET, "VulnerableProtocol");
        vm.deal(address(this), 1 ether);
    }

    function testExploit() public {
        console.log("=== BEFORE ===");
        console.log("Attacker balance:", IERC20(TOKEN).balanceOf(address(this)));
        console.log("Protocol balance:", IERC20(TOKEN).balanceOf(TARGET));

        // --- EXPLOIT LOGIC ---

        console.log("=== AFTER ===");
        console.log("Attacker balance:", IERC20(TOKEN).balanceOf(address(this)));
        assertGt(IERC20(TOKEN).balanceOf(address(this)), 0, "Exploit failed");
    }

    receive() external payable {}
}
```

### Essential Cheatcodes
```solidity
vm.prank(address who);              // Next call from `who`
vm.deal(address who, uint256 eth);  // Give ETH
vm.warp(uint256 timestamp);         // Set block.timestamp
vm.roll(uint256 blockNum);          // Set block.number
vm.store(addr, slot, value);        // Write storage directly
vm.mockCall(addr, data, retval);    // Mock any call
vm.sign(privateKey, digest);        // Sign a hash
vm.createSelectFork(rpc, block);    // Fork mainnet at block
```

### Run
```bash
forge test --match-test testExploit -vvvv --fork-url $MAINNET_RPC_URL
```

---

## NON-EVM CHAINS

### Solana (Rust / Anchor) — Key Vuln Classes
1. **Missing owner check** — verify `.owner == program_id`
2. **Missing signer check** — use `Signer<'info>` not `AccountInfo`
3. **Type cosplay** — pass account of wrong type if discriminator not checked
4. **PDA seed canonicalization** — user-provided bump allows non-canonical PDAs
5. **Arbitrary CPI** — unverified program ID in cross-program invocations
6. **Integer overflow** — Rust RELEASE builds wrap silently! Use `.checked_add()`
7. **Sysvar spoofing** — fake Clock/Instructions accounts (Wormhole $320M root cause)

**Tools:** sec3 X-Ray (static analysis), Trident (fuzzer)

### CosmWasm (Rust) — Key Vuln Classes
1. **Unsaved storage** — `load()` without `save()` on every path
2. **Missing access control** — `execute` handlers without `info.sender` check
3. **Address validation** — must call `deps.api.addr_validate()` on user strings

### Move (Aptos / Sui) — Key Vuln Classes
1. **Wrong ability assignment** — `copy` on tokens = infinite mint, `drop` on loans = skip repayment
2. **Missing capability check** — `public` functions without capability resource gate
3. **Bitshift overflow** — `<<`/`>>` don't revert, fill with zeros silently

### Cross-Chain Bridges ($2.8B+ stolen)
1. Validator key management — multisig threshold too low?
2. Signature verification bypass — can threshold be reduced to 0?
3. Zero/default values as valid roots (Nomad $200M)
4. Message replay — can same bridge message process twice?
5. Deprecated sysvar functions (Wormhole $320M)

---

## IMMUNEFI RULES

1. **NEVER test on mainnet or public testnet** — local fork ONLY. Violation = permanent ban.
2. **NO AI-generated spray reports** — instant permanent ban
3. **5 reports per 48 hours** max rate limit
4. **PoC MUST be runnable Foundry/Hardhat code** — not steps, not pseudocode
5. **Don't contact the project directly** — only through Immunefi dashboard
6. **One bug per report** — don't submit variants of the same root cause

## IMMUNEFI SEVERITY (v2.3)

| Severity | Impact | Payout |
|----------|--------|--------|
| **Critical** | Direct theft, permanent freeze, unauthorized mint | 10% of TVL; min $10K |
| **High** | Temporary freezing >24h, theft of unclaimed yield | $5K–$100K |
| **Medium** | Block stuffing, griefing | $1K–$5K |
| **Low** | Contract fails to deliver promised returns | $200–$1K |

## IMMUNEFI REPORT FORMAT

```
Title: [Vuln Class] in [Contract::function()] leads to [Impact]

Bug Description:
  - Root cause explanation
  - Exact file, function, line number

Impact:
  - SELECT from program's "Impacts in Scope" list
  - Quantify: "$X TVL at risk" with calculation

Proof of Concept:
  - Runnable Foundry fork test
  - Pin block number, console.log before/after, assertGt proving profit
  - Paste code in PoC field (not attachment)

Remediation:
  - Concrete fix recommendation
```

## WHAT IMMUNEFI REJECTS (don't waste time)
- Bugs requiring leaked private keys or admin compromise
- Centralization risk ("owner could rug") — design choice, not a bug
- DoS where attacker spends more gas than value extracted
- Lack of liquidity impacts
- Third-party dependency bugs (Chainlink, OpenZeppelin)
- Known issues from prior audit reports

---

## PAYOUT BENCHMARKS (2024-2025)

| Bug Type | Typical Immunefi Range |
|----------|----------------------|
| Access control — direct fund theft | $50K–$15M (Critical) |
| Flash loan + oracle manipulation | $50K–$5M (Critical) |
| Reentrancy — fund theft | $50K–$3M (Critical) |
| ZK verifier bypass | $50K–$10M (Critical) |
| ERC4626 inflation attack | $10K–$500K (High/Critical) |
| Price oracle manipulation | $10K–$2M (High/Critical) |
| Signature replay | $5K–$50K (High) |
| Read-only reentrancy | $10K–$500K (High) |
| Missing staleness check | $1K–$20K (Medium) |

---

## NOTABLE REAL EXPLOITS (Study These)

| Protocol | Loss | Root Cause | Year |
|----------|------|-----------|------|
| Wormhole | $320M | Fake sysvar bypassed signature check (Solana) | 2022 |
| Ronin Bridge | $625M | 5/9 validator keys compromised | 2022 |
| Nomad Bridge | $200M | Zero hash = trusted root | 2022 |
| Beanstalk | $182M | Flash loan governance takeover | 2022 |
| Curve Finance | $70M | Read-only reentrancy (Vyper compiler) | 2023 |
| Mango Markets | $117M | Oracle manipulation via own token | 2022 |
| Cetus DEX (Sui) | $223M | Integer overflow missed check | 2025 |
| Loopscale (Solana) | $5.8M | Single-source spot price oracle | 2025 |
| ResupplyFi | $9.8M | ERC4626 near-empty vault exchange rate manipulation | 2025 |

---

## REAL PAID BOUNTY WRITEUPS — TOP PAYOUTS

| Protocol | Payout | Vulnerability | Key Insight |
|----------|--------|--------------|-------------|
| Wormhole | $10M | Uninitialized UUPS proxy | `initialize()` callable by anyone on impl |
| Aurora | $6M | DelegateCall to precompile | Balance not decremented in delegatecall context |
| Polygon MRC20 | $2.2M | Missing balance + signature check | `ecrecover` returned zero = unchecked |
| Optimism | $2M | SELFDESTRUCT duplication | Refund without removing off-chain IOU |
| Balancer | $1M | ERC4626 1-wei rounding | User-favorable rounding + flash swap = drain |
| Raydium | $505K | `remaining_accounts` validation bypass | Wrong account passed to tick array |
| Redacted Cartel | $560K | Custom ERC-20 approval bypass | `transferFrom()` without allowance check |
| VeChainThor | $50K | Self-destruct + flash loan VTHO mint | Classic trick amplified by flash loan |

---

## TOOLS REFERENCE

### Static Analysis
| Tool | Install | Use |
|------|---------|-----|
| **Slither** | `pip3 install slither-analyzer` | `slither .` — 93 detectors |
| **Aderyn** | cyfrinup | `aderyn .` — Foundry-native |
| **Mythril** | `pip3 install mythril` | `myth analyze src/X.sol` |

### Fuzzing
| Tool | Install | Use |
|------|---------|-----|
| **Foundry fuzz** | Built in | Test functions with parameters auto-fuzzed |
| **Echidna** | `brew install echidna` | Stateful fuzzing |
| **Medusa** | GitHub releases | Trail of Bits next-gen fuzzer |
| **Halmos** | `pip install halmos` | Symbolic testing |

### On-Chain Investigation
| Tool | URL | Use |
|------|-----|-----|
| **Phalcon** | blocksec.com | Transaction trace debugger |
| **Tenderly** | tenderly.co | Fork + simulate transactions |
| **Dedaub** | dedaub.com | Decompile unverified bytecode |
| **Solodit** | solodit.cyfrin.io | 50K+ searchable audit findings |

### DeFi Hack Reproduction
```bash
git clone https://github.com/SunWeb3Sec/DeFiHackLabs
cd DeFiHackLabs && git submodule update --init --recursive
forge test -vvv --contracts src/test/2025-01/SomeHack_exp.sol
# 572+ real hacks reproduced
```

---

## KEY GITHUB REPOS

- **DeFiHackLabs**: github.com/SunWeb3Sec/DeFiHackLabs — 572+ real hacks in Foundry
- **DeFiVulnLabs**: github.com/SunWeb3Sec/DeFiVulnLabs — 48 vuln types with working tests
- **forge-poc-templates**: github.com/immunefi-team/forge-poc-templates — Immunefi official PoC starter
- **building-secure-contracts**: github.com/crytic/building-secure-contracts — Trail of Bits
- **not-so-smart-contracts**: github.com/crytic/not-so-smart-contracts — real vuln patterns
- **solcurity**: github.com/transmissions11/solcurity — audit checklist
- **Awesome-web3-Security**: github.com/Anugrahsr/Awesome-web3-Security

## AUDIT CONTEST PLATFORMS

| Platform | URL | Notes |
|----------|-----|-------|
| **Immunefi** | immunefi.com/bug-bounty/ | $100M+ paid, $190B+ protected |
| **Code4rena** | code4rena.com | Competitive audits, largest findings corpus |
| **Sherlock** | sherlock.xyz | Expert triage, $250 stake per submission |
| **Cantina** | cantina.xyz | Spearbit's platform |
| **CodeHawks** | codehawks.cyfrin.io | Cyfrin, First Flights for beginners |

## COMMUNITY & STAYING CURRENT

- **Rekt News** — https://rekt.news — Post-mortems of major exploits
- **DeFiLlama Hacks** — https://defillama.com/hacks — Real-time hack tracker
- **Solodit** — https://solodit.cyfrin.io — 50K+ searchable audit findings
- **Twitter/X**: @immunefi, @samczsun, @bytes032, @0xOwenThurm, @PatrickAlphaC
