# Agents

Thirteen specialized AI agents, each built for exactly one job in the hunt pipeline.

| Agent | Job |
|:---|:---|
| `recon-agent` | Subdomain enum · live host discovery · URL crawl · fingerprint |
| `js-intelligence` | Mines JS bundles/source maps for hidden endpoints, feature flags, debug routes, leaked config, auth flows |
| `vulnerability-intelligence` | Builds the memory-driven intelligence briefing (tech→vuln affinity, known chains, don't-retry list) before ranking; writes learned failed-patterns/chains back after a hunt |
| `hypothesis-engine` | Synthesizes recon + JS intel + memory + the attack graph into ranked, evidence-backed vulnerability hypotheses before any testing starts |
| `recon-ranker` | Scores + ranks attack surface using hypotheses, the intelligence briefing, and lead-board chains; computes Expected Value per Hour (score × payout probability × time cost) for each P1/P2 |
| `validation-engine` | Technical proof gate before `validator` — reproducibility, proven impact, authorization boundary crossed, clean PoC, duplicate/noise against hunt memory |
| `report-writer` | Writes impact-first reports that get paid, not N/A'd — validates exploitability/impact/evidence first, and checks report-outcome history for acceptance-rate signal |
| `validator` | Runs the 7-Question Gate and 4 pre-submission gates |
| `web3-auditor` | Smart contract audit across 10 bug classes |
| `chain-builder` | Bug A → finds bugs B and C that chain with it |
| `autopilot` | Full autonomous hunt loop with safety checkpoints, decision-engine-driven priority scoring, experiment-tracked stop/pivot decisions |
| `token-auditor` | Meme coin / token rug pull and security scan |
| `credential-hunter` | Wordlist gen → OSINT → breach-check → hard-stop before spray |

Agents are activated automatically by the `/autopilot` command or called directly during a hunt.
