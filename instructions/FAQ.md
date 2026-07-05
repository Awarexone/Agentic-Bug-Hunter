# Frequently Asked Questions

---

## Getting Started

**What is bug bounty hunting?**

Companies pay security researchers (called "hunters") to find vulnerabilities in their websites, apps, and systems before hackers do. You report what you find, they fix it, and you get paid. Payouts range from $100 to over $1,000,000 depending on the severity. Platforms like HackerOne, Bugcrowd, Intigriti, and Immunefi connect hunters with companies.

---

**What is Claude Code?**

Claude Code is a free command-line tool from Anthropic (the company behind Claude AI). It runs in your terminal and lets you use AI to write code, analyze files, and run tasks. This plugin turns it into a bug bounty hunting assistant. You can download it at [claude.ai/claude-code](https://claude.ai/claude-code).

---

**Do I need to be a professional hacker to use this?**

No. This tool is designed to help at every level:
- **Beginners** get AI guidance at each step — it explains what to test and why
- **Mid-level hunters** get time-saving automation for the repetitive parts (recon, reporting)
- **Experienced hunters** get an autonomous loop that runs while they focus on creative bugs

That said, you should understand the basics of how websites work (HTTP requests, APIs, authentication) before hunting. Bug bounty hunting on systems you don't understand can lead to accidental damage.

---

**Is this free?**

Yes. The plugin is free and open source (MIT license). You do need:
- A free [Claude Code](https://claude.ai/claude-code) account
- Some free API keys for better recon (Chaos, VirusTotal — optional but recommended)
- External tools that `install_tools.sh` installs for free (subfinder, httpx, nuclei, etc.)

---

**What operating systems does it support?**

macOS and Linux. Windows is not officially supported but may work with WSL (Windows Subsystem for Linux).

---

## Using the Tool

**Where do I find targets to hunt?**

Sign up on a bug bounty platform:
- [HackerOne](https://hackerone.com) — largest platform, many public programs
- [Bugcrowd](https://bugcrowd.com) — large selection of programs
- [Intigriti](https://intigriti.com) — popular in Europe
- [Immunefi](https://immunefi.com) — web3 / smart contract programs (highest payouts)

Start with public programs that have a broad scope. Read the program policy carefully before testing anything.

---

**What's the difference between `/hunt` and `/autopilot`?**

- **`/hunt`** is interactive — the AI suggests what to test and waits for you to approve each step. Best for new targets or when you want to stay in control.
- **`/autopilot`** runs automatically — it does recon, ranks the surface, tests, validates, and drafts reports without asking at every step. It stops at checkpoints for your review. Best for systematic coverage of known targets.

If you're new, start with `/hunt`. Once you're comfortable, try `/autopilot --paranoid` which stops after every finding.

---

**What does `/validate` actually do?**

It runs a "7-Question Gate" — a checklist that asks:

1. Can an attacker do this right now, with a real request?
2. Does the attacker need special access that most people don't have?
3. Is there actual impact (data leak, account takeover, money loss)?
4. Has this already been reported or disclosed?
5. Is the vulnerability in scope for this program?
6. Is there a clear reproduction step?
7. Is the severity accurate?

If your finding doesn't pass, the tool kills it or asks you to downgrade it. This saves you from submitting weak bugs that get rejected and hurt your reputation score.

---

**How does the memory system work?**

Every time you finish a hunt session, the tool automatically saves a summary of what you tested and found. This gets stored locally in `~/.claude/projects/[project]/hunt-memory/`.

When you start a new hunt on the same target, it tells you what's already been tested. When you hunt a new target with a similar tech stack, it suggests techniques that worked before.

You can also manually save rich notes (payout, specific technique, tags) by running `/remember` after a confirmed finding.

---

**What is Burp Suite and do I need it?**

[Burp Suite](https://portswigger.net/burp) is a popular proxy tool that intercepts your browser's traffic so you can inspect and modify HTTP requests. It's the industry standard for web security testing.

This plugin can connect to Burp via MCP (an integration protocol) so Claude can read your proxy history and replay requests through Burp. **But Burp is optional.** Every command works without it — the tool falls back to using `curl` for HTTP requests automatically.

If you're serious about bug bounty, install Burp Suite Community Edition (free). If you're just starting out, skip it for now.

---

**What platforms can I submit reports to?**

The `/report` command generates reports formatted for:
- HackerOne
- Bugcrowd
- Intigriti
- Immunefi

The report includes title, severity (CVSS 3.1), impact description, reproduction steps, and suggested fix — all written in a professional, human tone.

---

## Safety & Legal

**Is it safe to run `/autopilot`?**

With the right settings, yes. Built-in protections:

- Every URL is checked against the scope allowlist before any request is sent
- PUT/DELETE/PATCH requests require your manual approval (never sent automatically)
- A circuit breaker stops the tool if it gets too many errors on one host (prevents accidental hammering)
- Every request is logged to `hunt-memory/audit.jsonl` so you can review what happened
- Reports are **never** auto-submitted — you always approve before anything gets sent

Start with `--paranoid` mode, which stops after every single finding. Graduate to `--normal` once you're comfortable.

---

**Can I get in trouble using this?**

Yes, if you misuse it. Testing systems without permission is illegal. Stick to active bug bounty programs and always verify you're testing in-scope assets before running any command.

The tool has a built-in scope checker (`/scope <asset>`) that tells you whether something is in scope. Use it when in doubt.

---

**Does this tool store my findings or send data anywhere?**

No. Everything stays local on your machine:
- Hunt memory is stored in `~/.claude/projects/[project]/hunt-memory/`
- Audit logs stay in the same directory
- Nothing is sent to any server outside of your normal Claude Code usage

The `.gitignore` excludes `hunt-memory/` so it won't be accidentally committed to a public repo.

---

## Web3 / Crypto

**Does this work for smart contract auditing?**

Yes. Run `/web3-audit <contract.sol>` for a full 10-class smart contract security checklist. It covers reentrancy, access control, accounting desync, oracle manipulation, flash loan attacks, and more.

---

**What is `/token-scan`?**

It scans a token contract address for rug pull signals — things like mint authority still active, LP not locked, hidden transfer taxes, honeypot patterns. Works on EVM chains (Ethereum, BSC, etc.) and Solana (SPL tokens).

---

**What's the meme coin mentioned in the README?**

The community launched a meme coin to support the project. It has nothing to do with the tool's functionality. The contract address is there for community members who want to find it.

---

## Troubleshooting

**`/recon target.com` does nothing or gives an error**

Make sure you ran `./install_tools.sh` first. The recon command depends on external tools (subfinder, httpx, nuclei) that aren't installed by default. Run:

```bash
chmod +x install_tools.sh && ./install_tools.sh
```

---

**The tool tested something out of scope**

Check your scope input. Run `/scope <asset>` before running `/hunt` or `/autopilot`. If `/autopilot` sent an out-of-scope request, check `hunt-memory/audit.jsonl` for the full log and review your scope configuration.

---

**How do I update to the latest version?**

```bash
cd claude-bug-bounty
git pull origin main
chmod +x install.sh && ./install.sh   # reinstall skills + commands
```

---

**Where do I report bugs or ask for help?**

Open an issue on [GitHub](https://github.com/shuvonsec/claude-bug-bounty/issues). Include:
- What command you ran
- What you expected to happen
- What actually happened
- Your OS and Claude Code version
