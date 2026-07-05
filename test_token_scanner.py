"""Tests for tools/token_scanner.py — meme coin red flag scanner."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.token_scanner import (
    Finding,
    RiskLevel,
    ScanResult,
    TokenScanner,
    format_json,
    format_markdown,
    format_terminal,
)


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test contract files."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def _write_sol(tmp_dir: Path, filename: str, content: str) -> Path:
    """Write a .sol file to the temp directory."""
    p = tmp_dir / filename
    p.write_text(content)
    return p


def _write_rs(tmp_dir: Path, filename: str, content: str) -> Path:
    """Write a .rs file to the temp directory."""
    p = tmp_dir / filename
    p.write_text(content)
    return p


# ── ScanResult tests ────────────────────────────────────────────────────────


class TestScanResult:
    def test_empty_result_is_clean(self):
        r = ScanResult(target="test", chain="evm", files_scanned=0)
        assert r.risk_score == 0
        assert "CLEAN" in r.verdict

    def test_risk_score_calculation(self):
        r = ScanResult(target="test", chain="evm", files_scanned=1)
        r.findings = [
            Finding(RiskLevel.CRITICAL, "cat", "title", "desc", "f.sol", 1, "code", "rec"),
            Finding(RiskLevel.HIGH, "cat", "title", "desc", "f.sol", 10, "code", "rec"),
        ]
        assert r.risk_score == 35  # 25 + 10

    def test_verdict_critical(self):
        r = ScanResult(target="test", chain="evm", files_scanned=1)
        r.findings = [
            Finding(RiskLevel.CRITICAL, "cat", "t", "d", "f", 1, "c", "r"),
            Finding(RiskLevel.CRITICAL, "cat", "t2", "d", "f", 10, "c", "r"),
        ]
        assert "CRITICAL" in r.verdict

    def test_verdict_high(self):
        r = ScanResult(target="test", chain="evm", files_scanned=1)
        r.findings = [
            Finding(RiskLevel.HIGH, "cat", "t", "d", "f", 1, "c", "r"),
            Finding(RiskLevel.HIGH, "cat", "t2", "d", "f", 10, "c", "r"),
            Finding(RiskLevel.HIGH, "cat", "t3", "d", "f", 20, "c", "r"),
        ]
        assert "HIGH RISK" in r.verdict

    def test_verdict_medium(self):
        r = ScanResult(target="test", chain="evm", files_scanned=1)
        r.findings = [
            Finding(RiskLevel.MEDIUM, "cat", "t", "d", "f", 1, "c", "r"),
            Finding(RiskLevel.MEDIUM, "cat", "t2", "d", "f", 10, "c", "r"),
        ]
        assert "MEDIUM" in r.verdict

    def test_verdict_low(self):
        r = ScanResult(target="test", chain="evm", files_scanned=1)
        r.findings = [
            Finding(RiskLevel.LOW, "cat", "t", "d", "f", 1, "c", "r"),
            Finding(RiskLevel.LOW, "cat", "t2", "d", "f", 10, "c", "r"),
            Finding(RiskLevel.LOW, "cat", "t3", "d", "f", 20, "c", "r"),
        ]
        # 3 LOW findings = 6 points = LOW RISK
        assert "LOW" in r.verdict


# ── Scanner — EVM patterns ──────────────────────────────────────────────────


class TestEVMPatterns:
    def test_detects_hidden_mint(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            function mint(address to, uint256 amount) external onlyOwner {
                _mint(to, amount);
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "hidden_mint" in categories

    def test_detects_direct_balance_manipulation(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            mapping(address => uint256) _balances;
            function _updateRewards(address a, uint256 amt) internal {
                _balances[a] += amt;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        titles = {f.title for f in result.findings}
        assert "Direct balance manipulation" in titles

    def test_detects_blacklist_honeypot(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            mapping(address => bool) private _isBlacklisted;
            function blacklist(address a) external onlyOwner {
                _isBlacklisted[a] = true;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "honeypot" in categories

    def test_detects_max_tx_honeypot(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            uint256 public maxTxAmount = 1000000e18;
            function setMaxTxAmount(uint256 amount) external onlyOwner {
                maxTxAmount = amount;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "honeypot" in categories

    def test_detects_fee_manipulation(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            uint256 public _sellFee = 3;
            function setSellFee(uint256 fee) external onlyOwner {
                _sellFee = fee;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "fee_manipulation" in categories

    def test_detects_lp_migration(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            function migrateLP(address newPair) external onlyOwner {
                // migrate liquidity
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "lp_drain" in categories

    def test_detects_fake_renounce(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            function renounceOwnership() public override onlyOwner {
                emit OwnershipTransferred(owner(), address(0));
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "fake_renounce" in categories

    def test_detects_zero_slippage_swap(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            function swapTokensForETH(uint256 amount) private {
                router.swapExactTokensForETHSupportingFeeOnTransferTokens(amount, 0, path, address(this), block.timestamp);
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "sandwich_amplification" in categories

    def test_detects_pair_sync(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            function skim() external onlyOwner {
                IUniswapV2Pair(pair).sync();
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "lp_drain" in categories

    def test_clean_contract_no_findings(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract CleanToken {
            string public name = "Clean";
            string public symbol = "CLN";
            uint256 public totalSupply;

            mapping(address => uint256) public balanceOf;

            constructor(uint256 supply) {
                totalSupply = supply;
                balanceOf[msg.sender] = supply;
            }

            function transfer(address to, uint256 amount) external returns (bool) {
                require(balanceOf[msg.sender] >= amount);
                balanceOf[msg.sender] -= amount;
                balanceOf[to] += amount;
                return true;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        # Should have no critical/high findings
        critical_high = [f for f in result.findings if f.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        assert len(critical_high) == 0

    def test_detects_emergency_withdraw(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            function emergencyWithdraw(address token) external onlyOwner {
                IERC20(token).transfer(owner(), IERC20(token).balanceOf(address(this)));
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "lp_drain" in categories

    def test_detects_shadow_admin(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            address private _shadowAdmin;
            constructor() {
                _shadowAdmin = msg.sender;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "fake_renounce" in categories

    def test_detects_trading_toggle(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        contract Token {
            bool public tradingEnabled;
            function enableTrading() external onlyOwner {
                tradingEnabled = true;
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "honeypot" in categories


# ── Scanner — Solana patterns ───────────────────────────────────────────────


class TestSolanaPatterns:
    def test_detects_mint_authority(self, tmp_dir):
        _write_rs(tmp_dir, "token.rs", """
        pub fn initialize_mint(ctx: Context<InitMint>) -> Result<()> {
            token::initialize_mint(
                CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),
                9,
                ctx.accounts.authority.key, // mint_authority = deployer
                Some(ctx.accounts.authority.key), // freeze_authority = deployer
            )?;
            Ok(())
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "authority_retention" in categories

    def test_detects_transfer_hook(self, tmp_dir):
        _write_rs(tmp_dir, "hook.rs", """
        use spl_transfer_hook_interface::instruction::ExecuteInstruction;

        pub fn transfer_hook(ctx: Context<TransferHook>) -> Result<()> {
            if ctx.accounts.destination.key == &BLOCKED_POOL {
                return Err(ErrorCode::TransferBlocked.into());
            }
            Ok(())
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "token_2022_extensions" in categories
        # Transfer hook should be CRITICAL
        critical = [f for f in result.findings if f.risk == RiskLevel.CRITICAL]
        assert len(critical) > 0

    def test_detects_permanent_delegate(self, tmp_dir):
        _write_rs(tmp_dir, "token.rs", """
        let extension = get_extension::<PermanentDelegate>(&mint_data)?;
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()
        titles = {f.title for f in result.findings}
        assert "Permanent delegate extension" in titles

    def test_detects_upgrade_authority(self, tmp_dir):
        _write_rs(tmp_dir, "program.rs", """
        pub fn check_upgrade(ctx: Context<CheckUpgrade>) -> Result<()> {
            let upgrade_authority = ctx.accounts.program_data.upgrade_authority;
            Ok(())
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "program_safety" in categories

    def test_detects_bonding_curve_reserves(self, tmp_dir):
        _write_rs(tmp_dir, "curve.rs", """
        pub struct BondingCurve {
            pub virtual_token_reserves: u64,
            pub virtual_sol_reserves: u64,
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "bonding_curve" in categories

    def test_detects_frozen_default_state(self, tmp_dir):
        _write_rs(tmp_dir, "token.rs", """
        let default_state = DefaultAccountState {
            state: AccountState::Frozen,
        };
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()
        categories = {f.category for f in result.findings}
        assert "token_2022_extensions" in categories


# ── Scanner — file handling ─────────────────────────────────────────────────


class TestFileHandling:
    def test_single_file_scan(self, tmp_dir):
        p = _write_sol(tmp_dir, "Token.sol", "contract Token { function mint() {} }")
        scanner = TokenScanner(str(p), chain="evm")
        result = scanner.scan()
        assert result.files_scanned == 1

    def test_directory_scan(self, tmp_dir):
        _write_sol(tmp_dir, "A.sol", "contract A { function mint() {} }")
        _write_sol(tmp_dir, "B.sol", "contract B {}")
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        assert result.files_scanned == 2

    def test_excludes_test_dirs(self, tmp_dir):
        (tmp_dir / "test").mkdir()
        _write_sol(tmp_dir / "test", "Test.sol", "contract Test { function mint() {} }")
        _write_sol(tmp_dir, "Token.sol", "contract Token {}")
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        # Only Token.sol should be scanned, not test/Test.sol
        assert result.files_scanned == 1

    def test_excludes_node_modules(self, tmp_dir):
        (tmp_dir / "node_modules").mkdir()
        _write_sol(tmp_dir / "node_modules", "OZ.sol", "function mint() {}")
        _write_sol(tmp_dir, "Token.sol", "contract Token {}")
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        assert result.files_scanned == 1

    def test_no_files_found(self, tmp_dir):
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_chain_selects_file_extension(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", "contract Token { function mint() {} }")
        _write_rs(tmp_dir, "token.rs", "pub fn init() {}")
        # EVM scanner should only find .sol
        evm_scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        evm_result = evm_scanner.scan()
        assert evm_result.files_scanned == 1
        # Solana scanner should only find .rs
        sol_scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        sol_result = sol_scanner.scan()
        assert sol_result.files_scanned == 1


# ── Deduplication ───────────────────────────────────────────────────────────


class TestDeduplication:
    def test_deduplicates_same_title_same_file_close_lines(self, tmp_dir):
        _write_sol(tmp_dir, "Token.sol", """
        _isBlacklisted[a] = true;
        _isBlacklisted[b] = true;
        _isBlacklisted[c] = true;
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        # All 3 lines match same pattern, within 5 lines — should deduplicate
        blacklist_findings = [f for f in result.findings if "Blacklist" in f.title]
        assert len(blacklist_findings) == 1

    def test_keeps_different_files(self, tmp_dir):
        _write_sol(tmp_dir, "A.sol", "_isBlacklisted[a] = true;")
        _write_sol(tmp_dir, "B.sol", "_isBlacklisted[b] = true;")
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()
        blacklist_findings = [f for f in result.findings if "Blacklist" in f.title]
        assert len(blacklist_findings) == 2


# ── Output formatters ──────────────────────────────────────────────────────


class TestOutputFormatters:
    def _make_result(self) -> ScanResult:
        r = ScanResult(target="test.sol", chain="evm", files_scanned=1)
        r.findings = [
            Finding(RiskLevel.CRITICAL, "hidden_mint", "Public mint function",
                    "Contract has mint", "test.sol", 10, "function mint() {}", "Add cap"),
            Finding(RiskLevel.HIGH, "honeypot", "Blacklist mapping",
                    "Has blacklist", "test.sol", 20, "_isBlacklisted[a]", "Remove"),
        ]
        return r

    def test_terminal_format_includes_verdict(self):
        result = self._make_result()
        output = format_terminal(result)
        assert "CRITICAL" in output
        assert "TOKEN SCAN RESULTS" in output

    def test_markdown_format_is_valid(self):
        result = self._make_result()
        output = format_markdown(result)
        assert "# Token Scan Report" in output
        assert "CRITICAL" in output
        assert "```" in output

    def test_json_format_is_valid(self):
        result = self._make_result()
        output = format_json(result)
        import json
        data = json.loads(output)
        assert data["target"] == "test.sol"
        assert data["chain"] == "evm"
        assert len(data["findings"]) == 2
        assert data["risk_score"] == 35

    def test_empty_result_formats(self):
        r = ScanResult(target="test", chain="evm", files_scanned=0)
        assert "CLEAN" in format_terminal(r)
        assert "No red flags" in format_markdown(r)
        data = format_json(r)
        import json
        assert json.loads(data)["findings"] == []


# ── Combined rug pattern detection ──────────────────────────────────────────


class TestCombinedRugPatterns:
    def test_classic_rug_token_multiple_findings(self, tmp_dir):
        """A classic rug token should trigger multiple findings across categories."""
        _write_sol(tmp_dir, "RugToken.sol", """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract RugToken {
            mapping(address => uint256) _balances;
            mapping(address => bool) private _isBlacklisted;
            uint256 public _sellFee = 3;
            uint256 public maxTxAmount = 1000000e18;
            address private _shadowAdmin;

            constructor() {
                _shadowAdmin = msg.sender;
            }

            function mint(address to, uint256 amount) external {
                _balances[to] += amount;
            }

            function blacklist(address account) external {
                _isBlacklisted[account] = true;
            }

            function setSellFee(uint256 fee) external {
                _sellFee = fee;
            }

            function setMaxTxAmount(uint256 amount) external {
                maxTxAmount = amount;
            }

            function emergencyWithdraw(address token) external {
                // drain everything
            }
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="evm", recursive=True)
        result = scanner.scan()

        categories = {f.category for f in result.findings}
        assert "hidden_mint" in categories
        assert "honeypot" in categories
        assert "fee_manipulation" in categories
        assert "lp_drain" in categories
        assert "fake_renounce" in categories

        # Risk score should be very high
        assert result.risk_score >= 50
        assert "CRITICAL" in result.verdict

    def test_solana_rug_token(self, tmp_dir):
        """A Solana rug token with retained authorities and transfer hook."""
        _write_rs(tmp_dir, "token.rs", """
        use anchor_lang::prelude::*;
        use spl_transfer_hook_interface;

        pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
            // mint_authority retained
            let mint = &ctx.accounts.mint;
            // freeze_authority retained
            let freeze = ctx.accounts.freeze_authority.key;

            // Transfer hook setup
            let hook = TransferHook::new();

            // Permanent delegate
            let delegate = PermanentDelegate::new(ctx.accounts.authority.key);

            // upgrade_authority set
            let upgrade_authority = ctx.accounts.upgrade_authority.key;

            Ok(())
        }
        """)
        scanner = TokenScanner(str(tmp_dir), chain="solana", recursive=True)
        result = scanner.scan()

        categories = {f.category for f in result.findings}
        assert "authority_retention" in categories
        assert "token_2022_extensions" in categories
        assert "program_safety" in categories
        assert result.risk_score >= 25
