# Terms & Conditions

**Claude Bug Bounty** — Last updated: April 2026

---

## 1. What This Tool Is

Claude Bug Bounty is a free, open-source plugin for Claude Code that helps security researchers find vulnerabilities in authorized bug bounty programs. It is a tool to assist human hunters — not a replacement for professional judgment.

---

## 2. You Must Have Permission

**This tool may only be used on targets you have explicit, written authorization to test.**

That means:
- The target must be listed in an active bug bounty program (HackerOne, Bugcrowd, Intigriti, Immunefi, or similar)
- The asset you are testing must be listed as **in scope** by that program
- You must follow that program's specific rules and restrictions

**Testing any system without permission is illegal** in most countries, including under the Computer Fraud and Abuse Act (USA), Computer Misuse Act (UK), and similar laws worldwide. This tool will not protect you from legal consequences if you use it on unauthorized targets.

---

## 3. What You Are Responsible For

By using this tool, you agree that:

- **You** are responsible for every HTTP request this tool sends
- **You** are responsible for reading and following the scope rules of each program you hunt
- **You** are responsible for any damage caused by misuse, even if unintentional
- **You** will not use this tool to attack, disrupt, or harm any system
- **You** will not use this tool to collect personal data from third parties
- **You** will follow responsible disclosure practices — report findings to the program before making them public

---

## 4. What We Are Not Responsible For

The authors of Claude Bug Bounty provide this software **as-is**, with no warranties of any kind.

We are not responsible for:
- Bans, legal action, or penalties resulting from misuse
- Inaccurate findings, false positives, or missed vulnerabilities
- Data loss or system damage caused during testing
- Actions taken by the AI that you did not review before execution
- Any financial losses related to the use of this software

---

## 5. Autonomous Mode Warning

The `/autopilot` command sends HTTP requests automatically. Before running it:

- Confirm the target and scope are correct
- Start with `--paranoid` mode on unfamiliar targets
- Review the audit log at `hunt-memory/audit.jsonl` after each session

**You are still responsible for every request autopilot sends.** "The AI did it" is not a legal defense.

---

## 6. No Malicious Use

You may not use this tool to:
- Attack systems outside of authorized bug bounty scope
- Conduct denial-of-service attacks (DoS/DDoS)
- Harvest, scrape, or steal personal data
- Bypass authentication to access accounts you do not own
- Facilitate unauthorized access for yourself or others
- Build offensive tools or weaponized exploits intended for use outside authorized testing

---

## 7. Open Source License

This software is released under the **MIT License**. You are free to use, copy, modify, and distribute it for any lawful purpose. See [LICENSE](LICENSE) for the full text.

---

## 8. Changes to These Terms

These terms may be updated at any time. Continued use of the tool after changes means you accept the updated terms.

---

## 9. Contact

Questions or concerns: [shuvonsec@gmail.com](mailto:shuvonsec@gmail.com)

For security disclosures about this tool itself, open a GitHub issue marked **[SECURITY]**.
