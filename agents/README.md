# Agents

Ten specialized AI agents, each built for exactly one job in the hunt pipeline.

| Agent | Job |
|:---|:---|
| `recon-agent` | Subdomain enum · live host discovery · URL crawl · fingerprint |
| `vulnerability-intelligence` | Builds the memory-driven intelligence briefing (tech→vuln affinity, known chains, don't-retry list) before ranking; writes learned failed-patterns/chains back after a hunt |
| `recon-ranker` | Scores + ranks attack surface using the intelligence briefing and lead-board chains |
| `report-writer` | Writes impact-first reports that get paid, not N/A'd |
| `validator` | Runs the 7-Question Gate and 4 pre-submission gates |
| `web3-auditor` | Smart contract audit across 10 bug classes |
| `chain-builder` | Bug A → finds bugs B and C that chain with it |
| `autopilot` | Full autonomous hunt loop with safety checkpoints |
| `token-auditor` | Meme coin / token rug pull and security scan |
| `credential-hunter` | Wordlist gen → OSINT → breach-check → hard-stop before spray |

Agents are activated automatically by the `/autopilot` command or called directly during a hunt.
