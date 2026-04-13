#!/usr/bin/env python3
"""
Token red flag scanner — deterministic contract analysis for meme coin rug vectors.

Scans Solidity and Rust/Anchor token contracts for known rug pull patterns:
hidden mint, honeypot transfer restrictions, fee manipulation,
LP lock bypasses, authority retention, fake renounce, and MEV amplification.

Uses regex pattern matching (no LLM, no API calls) for fast, reproducible results.

Usage:
    python3 tools/token_scanner.py <contract_path>
    python3 tools/token_scanner.py <contract_path> --chain solana
    python3 tools/token_scanner.py <contract_path> --json
    python3 tools/token_scanner.py src/ --recursive
    python3 tools/token_scanner.py <contract_path> --output findings/token-report.md

Known limitations:
    - Regex-based: can miss obfuscated patterns or produce false positives
    - Does not analyze bytecode (source code only)
    - Does not check on-chain state (authorities, LP locks, holder distribution)
    - Exclude known library paths manually if false positives on OpenZeppelin/SPL base
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

# ── Colors ──────────────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ── Data types ──────────────────────────────────────────────────────────────


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


RISK_COLORS = {
    RiskLevel.CRITICAL: RED,
    RiskLevel.HIGH: RED,
    RiskLevel.MEDIUM: YELLOW,
    RiskLevel.LOW: GREEN,
    RiskLevel.INFO: CYAN,
}


@dataclass
class Finding:
    """A single red flag detected in a token contract."""

    risk: RiskLevel
    category: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str


@dataclass
class ScanResult:
    """Aggregated scan results."""

    target: str
    chain: str
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        weights = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 10,
            RiskLevel.MEDIUM: 5,
            RiskLevel.LOW: 2,
            RiskLevel.INFO: 0,
        }
        return sum(weights.get(f.risk, 0) for f in self.findings)

    @property
    def verdict(self) -> str:
        score = self.risk_score
        if score >= 50:
            return "CRITICAL RISK — DO NOT INTERACT"
        if score >= 25:
            return "HIGH RISK — LIKELY RUG VECTORS PRESENT"
        if score >= 10:
            return "MEDIUM RISK — MANUAL REVIEW NEEDED"
        if score >= 5:
            return "LOW RISK — MINOR CONCERNS"
        return "CLEAN — NO RED FLAGS DETECTED"


# ── Pattern definitions ─────────────────────────────────────────────────────
#
# Each pattern: (regex, title, description, risk, recommendation)
# Patterns are applied line-by-line unless marked multiline.

_PatternTuple = tuple[str, str, str, RiskLevel, str]

EVM_PATTERNS: dict[str, list[_PatternTuple]] = {
    "hidden_mint": [
        (
            r"function\s+mint\s*\(",
            "Public mint function",
            "Contract has a mint function — check if it has a supply cap",
            RiskLevel.HIGH,
            "Verify MAX_SUPPLY is enforced in every mint path. If no cap exists, this is a CRITICAL rug vector.",
        ),
        (
            r"_mint\s*\([^)]*\)\s*;",
            "Internal _mint call",
            "Direct _mint() call found — verify it is bounded by a supply cap",
            RiskLevel.MEDIUM,
            "Trace all callers of _mint(). Each must enforce totalSupply + amount <= MAX_SUPPLY.",
        ),
        (
            r"_balances\s*\[.*\]\s*\+=",
            "Direct balance manipulation",
            "Balance increased directly without going through _mint — can inflate supply silently",
            RiskLevel.CRITICAL,
            "Balance changes MUST go through _mint/_burn. Direct manipulation bypasses supply tracking.",
        ),
        (
            r"_totalSupply\s*\+=",
            "Direct totalSupply manipulation",
            "Total supply modified directly — bypasses ERC20 mint/burn flow",
            RiskLevel.CRITICAL,
            "Total supply changes MUST go through _mint/_burn, not direct assignment.",
        ),
        (
            r"delegatecall\s*\(",
            "Delegatecall present",
            "delegatecall can execute arbitrary code including mint in the contract's context",
            RiskLevel.HIGH,
            "Verify delegatecall target is immutable and trusted. Owner-controlled delegatecall target = critical.",
        ),
    ],
    "honeypot": [
        (
            r"(?:_isBlacklisted|isBlacklisted|_blacklist|isBot|_bots|_blocked)\s*\[",
            "Blacklist mapping",
            "Contract has a blacklist that can block addresses from transferring",
            RiskLevel.CRITICAL,
            "Blacklists can be used to block all sells. Verify: can owner blacklist the DEX pair?",
        ),
        (
            r"function\s+(?:blacklist|addBot|blockAddress|setBot)\s*\(",
            "Blacklist setter function",
            "Owner can add addresses to blacklist — honeypot vector",
            RiskLevel.CRITICAL,
            "If owner can blacklist any address, they can block sells on all DEXs.",
        ),
        (
            r"maxTxAmount\s*=|_maxTxAmount|maxTransactionAmount|_maxWalletSize|maxWallet",
            "Max transaction/wallet limit",
            "Transaction or wallet size limit exists — check if setter has minimum bound",
            RiskLevel.MEDIUM,
            "Verify setMaxTx() has require(amount >= totalSupply / 1000) or similar floor.",
        ),
        (
            r"function\s+(?:setMaxTx|setMaxWallet|updateMaxTx|updateMaxWallet)\s*\(",
            "Max tx/wallet setter",
            "Owner can change max transaction limit — can be set to 0 to block all transfers",
            RiskLevel.HIGH,
            "Must have minimum bound. setMaxTx(0) = honeypot.",
        ),
        (
            r"function\s+approve.*override",
            "Approve function override",
            "approve() is overridden — can silently prevent DEX router approvals",
            RiskLevel.HIGH,
            "Verify override calls super.approve() or _approve(). Silent return = honeypot.",
        ),
        (
            r"tradingEnabled|tradingActive|canTrade|_tradingOpen",
            "Trading toggle flag",
            "Contract has a trading enabled flag — verify it cannot be toggled after enable",
            RiskLevel.MEDIUM,
            "Check: can enableTrading() be called again to disable? Should be one-way.",
        ),
        (
            r"cooldown\s*\[|_lastSell\s*\[|_lastTx\s*\[|tradeCooldown",
            "Transfer cooldown",
            "Cooldown mechanism can block sells if set to extreme values",
            RiskLevel.MEDIUM,
            "Verify cooldown is bounded (e.g., max 1 hour) and cannot be set by owner to max uint.",
        ),
    ],
    "fee_manipulation": [
        (
            r"(?:_taxFee|_sellFee|_buyFee|_liquidityFee|_marketingFee|_devFee)\s*=",
            "Tax/fee variable",
            "Contract has configurable fee — check if setter is bounded",
            RiskLevel.MEDIUM,
            "Fee setters MUST have require(fee <= MAX_FEE) with MAX_FEE <= 10%.",
        ),
        (
            r"function\s+(?:setFee|updateFee|setTax|updateTax|setBuyFee|setSellFee|setFees)\s*\(",
            "Fee setter function",
            "Owner can change buy/sell fees — can be set to 99% (rug)",
            RiskLevel.HIGH,
            "Check function body for require(fee <= MAX). Unbounded = CRITICAL.",
        ),
        (
            r"_isExcludedFromFee\s*\[|isExcludedFromFee|excludeFromFee",
            "Fee exclusion mapping",
            "Some addresses excluded from fees — owner can sell tax-free",
            RiskLevel.MEDIUM,
            "Fee exclusion for owner + 99% sell tax = classic rug pattern.",
        ),
        (
            r"(?:setMarketingWallet|setDevWallet|setTaxWallet|setFeeReceiver)\s*\(",
            "Fee recipient setter",
            "Fee destination wallet can be changed — enables hidden fee extraction",
            RiskLevel.MEDIUM,
            "Verify fee recipient change has timelock or multi-sig requirement.",
        ),
    ],
    "lp_drain": [
        (
            r"function\s+(?:migrate|migrateLP|migrateLiquidity)\s*\(",
            "LP migration function",
            "Contract can migrate liquidity to new pair — drains old pair",
            RiskLevel.CRITICAL,
            "Migration functions allow owner to move liquidity to a controlled pair = rug.",
        ),
        (
            r"(?:emergencyWithdraw|forceWithdraw|rescueTokens|recoverTokens|rescueETH)\s*\(",
            "Emergency withdraw function",
            "Contract has emergency withdrawal — can drain locked LP or contract balance",
            RiskLevel.HIGH,
            "Verify emergency withdraw cannot access LP tokens or paired asset.",
        ),
        (
            r"\.sync\s*\(\)",
            "Pair sync call",
            "Direct pair.sync() call — can manipulate pool reserves",
            RiskLevel.HIGH,
            "sync() after direct token transfer to pair = price manipulation vector.",
        ),
        (
            r"(?:setPair|setNewPair|updatePair|changePair)\s*\(",
            "Pair change function",
            "DEX pair can be changed — breaks old pair trading",
            RiskLevel.CRITICAL,
            "Pair changes break all existing liquidity. Should be immutable after launch.",
        ),
        (
            r"(?:setRouter|updateRouter|changeRouter)\s*\(",
            "Router change function",
            "DEX router can be changed — enables routing through attacker-controlled router",
            RiskLevel.HIGH,
            "Router should be immutable. Changing router = redirect all swaps.",
        ),
    ],
    "fake_renounce": [
        (
            r"function\s+renounceOwnership.*override",
            "renounceOwnership override",
            "renounceOwnership is overridden — may not actually renounce",
            RiskLevel.CRITICAL,
            "Verify override calls _transferOwnership(address(0)). Missing = fake renounce.",
        ),
        (
            r"_shadowAdmin|_secondOwner|_backupOwner|_hiddenOwner",
            "Shadow admin pattern",
            "Secondary admin address that survives ownership renounce",
            RiskLevel.CRITICAL,
            "Second admin = fake renounce. Owner looks renounced but shadow admin retains control.",
        ),
        (
            r"selfdestruct|SELFDESTRUCT",
            "selfdestruct present",
            "Contract can self-destruct — destroys all state, potentially redeployable via CREATE2",
            RiskLevel.HIGH,
            "selfdestruct + CREATE2 = contract redeployment to same address with new code.",
        ),
    ],
    "sandwich_amplification": [
        (
            r"swapExactTokensForETH.*,\s*0\s*,",
            "Zero slippage auto-swap",
            "Auto-swap with amountOutMin=0 — guaranteed sandwich profit",
            RiskLevel.HIGH,
            "Calculate minimum output with slippage tolerance. amountOutMin=0 is exploitable.",
        ),
        (
            r"swapTokensAtAmount|numTokensSellToAddToLiquidity|swapThreshold",
            "Auto-swap threshold",
            "Public swap threshold — attackers can predict and sandwich auto-swaps",
            RiskLevel.MEDIUM,
            "Consider randomizing swap threshold or making it private.",
        ),
        (
            r"_rebase\s*\(\)|rebase\s*\(\)|_reflect\s*\(\)",
            "Rebase on transfer",
            "Rebasing mechanics in transfer function create predictable price impact",
            RiskLevel.MEDIUM,
            "Rebasing tokens amplify MEV. Consider time-weighted rebasing instead.",
        ),
    ],
}

SOLANA_PATTERNS: dict[str, list[_PatternTuple]] = {
    "authority_retention": [
        (
            r"mint_authority",
            "Mint authority reference",
            "Token references mint_authority — verify it is set to None after initial mint",
            RiskLevel.HIGH,
            "Mint authority MUST be None for meme coins. Retained = infinite mint rug vector.",
        ),
        (
            r"freeze_authority",
            "Freeze authority reference",
            "Token references freeze_authority — can freeze any holder's account",
            RiskLevel.HIGH,
            "Freeze authority MUST be None for meme coins. Retained = honeypot vector.",
        ),
        (
            r"update_authority|UpdateAuthority",
            "Update authority reference",
            "Metadata update authority present — can change token name/symbol/image",
            RiskLevel.MEDIUM,
            "Update authority should be None or is_mutable=false for launched tokens.",
        ),
        (
            r"close_authority|CloseAuthority",
            "Close authority reference",
            "Token-2022 close authority — can destroy token accounts",
            RiskLevel.HIGH,
            "Close authority can destroy holder accounts. Should be None.",
        ),
        (
            r"MintTo\s*\{|mint_to\s*\(",
            "Mint instruction",
            "Program can mint new tokens — verify mint authority and supply cap",
            RiskLevel.HIGH,
            "Check: who can call this instruction? Is there a cap? Is mint authority revoked?",
        ),
    ],
    "token_2022_extensions": [
        (
            r"transfer_hook|TransferHook|spl_transfer_hook",
            "Transfer hook extension",
            "Token-2022 transfer hook — can block transfers (honeypot)",
            RiskLevel.CRITICAL,
            "Transfer hooks execute on every transfer. If owner controls hook logic = honeypot.",
        ),
        (
            r"permanent_delegate|PermanentDelegate",
            "Permanent delegate extension",
            "Token-2022 permanent delegate — can steal tokens from ANY holder",
            RiskLevel.CRITICAL,
            "Permanent delegate can transfer tokens from any account without approval. CRITICAL.",
        ),
        (
            r"TransferFee|transfer_fee|TransferFeeConfig",
            "Transfer fee extension",
            "Token-2022 transfer fee — can be set to 100%",
            RiskLevel.HIGH,
            "Verify fee is immutable or bounded. Owner-controlled fee = rug vector.",
        ),
        (
            r"DefaultAccountState|default_account_state|AccountState::Frozen",
            "Default frozen account state",
            "New token accounts created frozen by default — honeypot setup",
            RiskLevel.HIGH,
            "Frozen by default means users can't transfer without owner thawing first.",
        ),
        (
            r"NonTransferable|non_transferable",
            "Non-transferable extension",
            "Token marked non-transferable — soulbound, cannot be sold",
            RiskLevel.HIGH,
            "Non-transferable tokens cannot be traded. Legitimate for SBTs, rug for meme coins.",
        ),
    ],
    "program_safety": [
        (
            r"AccountInfo<'info>",
            "Unchecked AccountInfo",
            "Raw AccountInfo without Signer check — verify /// CHECK: comment exists",
            RiskLevel.MEDIUM,
            "Every AccountInfo should be Signer<'info> or have a CHECK comment explaining why.",
        ),
        (
            r"invoke_signed|CpiContext::new_with_signer",
            "Signed CPI invocation",
            "Program makes signed cross-program calls via PDA — verify PDA authority scope",
            RiskLevel.MEDIUM,
            "Verify PDA seeds are specific. Broad PDA authority = privilege escalation.",
        ),
        (
            r"upgrade_authority|UpgradeAuthority",
            "Program upgrade authority",
            "Program is upgradeable — can change logic after deployment",
            RiskLevel.HIGH,
            "Upgradeable programs can add any instruction including mint/freeze. Should be immutable.",
        ),
    ],
    "bonding_curve": [
        (
            r"virtual_token_reserves|virtual_sol_reserves|virtualReserve",
            "Virtual reserves",
            "Bonding curve with virtual reserves — check if owner can modify",
            RiskLevel.MEDIUM,
            "Virtual reserves should be immutable after creation. Owner-modifiable = price manipulation.",
        ),
        (
            r"graduate|graduation|migrate_to_raydium|create_raydium_pool",
            "Graduation/migration",
            "Bonding curve graduation mechanic — check migration safety",
            RiskLevel.MEDIUM,
            "Verify graduation is permissionless and migration ratio matches curve price.",
        ),
        (
            r"creator_fee|platform_fee|trade_fee",
            "Trading fees",
            "Fee extraction on curve trades — check if creator can modify",
            RiskLevel.LOW,
            "Verify fee is bounded and immutable. Creator-controlled fee = extraction risk.",
        ),
    ],
}

# Files to always exclude from scanning
EXCLUDE_DIRS = {
    "node_modules",
    "lib",
    ".git",
    "test",
    "tests",
    "mock",
    "mocks",
    "scripts",
    "hardhat",
    "forge-std",
    "openzeppelin-contracts",
    "solmate",
    "@openzeppelin",
    "@solana",
    "target",
    "artifacts",
    "cache",
}


# ── Scanner ─────────────────────────────────────────────────────────────────


class TokenScanner:
    """Deterministic token contract red flag scanner."""

    def __init__(
        self,
        target_path: str,
        chain: str = "evm",
        recursive: bool = False,
    ):
        self.target_path = Path(target_path)
        self.chain = chain.lower()
        self.recursive = recursive
        self.patterns = EVM_PATTERNS if self.chain == "evm" else SOLANA_PATTERNS
        self.file_ext = "*.sol" if self.chain == "evm" else "*.rs"
        self._files: list[Path] = []

    def _discover_files(self) -> list[Path]:
        """Find all contract files to scan."""
        if self.target_path.is_file():
            return [self.target_path]

        if not self.target_path.is_dir():
            print(f"{RED}Error: {self.target_path} is not a file or directory{RESET}")
            sys.exit(1)

        files = []
        glob_fn = self.target_path.rglob if self.recursive else self.target_path.glob
        for f in glob_fn(self.file_ext):
            # Skip excluded directories
            if any(excl in f.parts for excl in EXCLUDE_DIRS):
                continue
            files.append(f)

        if not files:
            print(f"{YELLOW}Warning: no {self.file_ext} files found in {self.target_path}{RESET}")

        return sorted(files)

    def scan(self) -> ScanResult:
        """Run all pattern checks and return findings."""
        self._files = self._discover_files()
        result = ScanResult(
            target=str(self.target_path),
            chain=self.chain,
            files_scanned=len(self._files),
        )

        for file_path in self._files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except OSError as e:
                print(f"{YELLOW}Warning: cannot read {file_path}: {e}{RESET}")
                continue

            for category, patterns in self.patterns.items():
                for regex, title, desc, risk, recommendation in patterns:
                    compiled = re.compile(regex)
                    for i, line in enumerate(lines, 1):
                        if compiled.search(line):
                            # Get surrounding context (2 lines before/after)
                            start = max(0, i - 3)
                            end = min(len(lines), i + 2)
                            snippet = "\n".join(lines[start:end])

                            result.findings.append(
                                Finding(
                                    risk=risk,
                                    category=category,
                                    title=title,
                                    description=desc,
                                    file_path=str(file_path),
                                    line_number=i,
                                    code_snippet=snippet,
                                    recommendation=recommendation,
                                )
                            )

        # Deduplicate: same title + same file + within 5 lines
        result.findings = self._deduplicate(result.findings)

        # Sort: CRITICAL first, then HIGH, etc.
        risk_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }
        result.findings.sort(key=lambda f: risk_order.get(f.risk, 99))

        return result

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same title, same file, within 5 lines)."""
        seen: list[Finding] = []
        for f in findings:
            duplicate = False
            for s in seen:
                if (
                    f.title == s.title
                    and f.file_path == s.file_path
                    and abs(f.line_number - s.line_number) <= 5
                ):
                    duplicate = True
                    break
            if not duplicate:
                seen.append(f)
        return seen


# ── Output formatters ───────────────────────────────────────────────────────


def _separator() -> str:
    return f"{DIM}{'─' * 72}{RESET}"


def format_terminal(result: ScanResult) -> str:
    """Format scan results for terminal display with colors."""
    lines = []
    lines.append("")
    lines.append(f"{BOLD}TOKEN SCAN RESULTS{RESET}")
    lines.append(_separator())
    lines.append(f"  Target:    {result.target}")
    lines.append(f"  Chain:     {result.chain.upper()}")
    lines.append(f"  Files:     {result.files_scanned}")
    lines.append(f"  Findings:  {len(result.findings)}")
    lines.append(f"  Risk Score: {result.risk_score}")

    # Verdict
    score = result.risk_score
    if score >= 25:
        color = RED
    elif score >= 10:
        color = YELLOW
    else:
        color = GREEN
    lines.append(f"  Verdict:   {color}{BOLD}{result.verdict}{RESET}")
    lines.append(_separator())

    if not result.findings:
        lines.append(f"\n  {GREEN}No red flags detected.{RESET}\n")
        return "\n".join(lines)

    # Count by risk level
    counts: dict[RiskLevel, int] = {}
    for f in result.findings:
        counts[f.risk] = counts.get(f.risk, 0) + 1

    lines.append("")
    for risk in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
        if risk in counts:
            c = RISK_COLORS[risk]
            lines.append(f"  {c}{risk.value}: {counts[risk]}{RESET}")

    lines.append("")
    lines.append(_separator())

    # Individual findings
    for i, f in enumerate(result.findings, 1):
        c = RISK_COLORS[f.risk]
        lines.append(f"\n  {c}{BOLD}[{f.risk.value}]{RESET} {BOLD}#{i}: {f.title}{RESET}")
        lines.append(f"  {DIM}Category: {f.category} | {f.file_path}:{f.line_number}{RESET}")
        lines.append(f"  {f.description}")
        lines.append(f"\n  {DIM}Code:{RESET}")
        for code_line in f.code_snippet.splitlines():
            lines.append(f"    {DIM}{code_line}{RESET}")
        lines.append(f"\n  {CYAN}Recommendation:{RESET} {f.recommendation}")
        lines.append(_separator())

    return "\n".join(lines)


def format_markdown(result: ScanResult) -> str:
    """Format scan results as Markdown report."""
    lines = []
    lines.append("# Token Scan Report")
    lines.append("")
    lines.append(f"- **Target:** `{result.target}`")
    lines.append(f"- **Chain:** {result.chain.upper()}")
    lines.append(f"- **Files scanned:** {result.files_scanned}")
    lines.append(f"- **Findings:** {len(result.findings)}")
    lines.append(f"- **Risk Score:** {result.risk_score}")
    lines.append(f"- **Verdict:** {result.verdict}")
    lines.append("")

    if not result.findings:
        lines.append("> No red flags detected.")
        return "\n".join(lines)

    lines.append("---")
    lines.append("")

    for i, f in enumerate(result.findings, 1):
        lines.append(f"## [{f.risk.value}] #{i}: {f.title}")
        lines.append("")
        lines.append(f"**Category:** {f.category}  ")
        lines.append(f"**File:** `{f.file_path}:{f.line_number}`")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        lines.append("```")
        lines.append(f"{f.code_snippet}")
        lines.append("```")
        lines.append("")
        lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    data = {
        "target": result.target,
        "chain": result.chain,
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score,
        "verdict": result.verdict,
        "findings": [
            {
                "risk": f.risk.value,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(data, indent=2)


# ── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Token red flag scanner — detect rug pull patterns in token contracts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tools/token_scanner.py contracts/Token.sol
  python3 tools/token_scanner.py programs/token/ --chain solana --recursive
  python3 tools/token_scanner.py src/ --recursive --json
  python3 tools/token_scanner.py src/ --recursive --output report.md
        """,
    )
    parser.add_argument(
        "target",
        help="Contract file or directory to scan",
    )
    parser.add_argument(
        "--chain",
        choices=["evm", "solana"],
        default="evm",
        help="Blockchain platform (default: evm)",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively scan directories",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write report to file (markdown format)",
    )

    args = parser.parse_args()

    scanner = TokenScanner(
        target_path=args.target,
        chain=args.chain,
        recursive=args.recursive,
    )

    result = scanner.scan()

    # Output
    if args.json_output:
        print(format_json(result))
    elif args.output:
        report = format_markdown(result)
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
        print(f"{GREEN}Report written to {args.output}{RESET}")
        # Also print summary to terminal
        print(format_terminal(result))
    else:
        print(format_terminal(result))

    # Exit code: 1 if critical/high findings, 0 otherwise
    has_critical = any(
        f.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) for f in result.findings
    )
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
