---
description: Scan an endpoint for CORS misconfiguration — arbitrary-origin reflection, null-origin trust, credential exposure, suffix/prefix regex bypass, scheme downgrade. Usage: /cors <url> [--cookie "session=..."] | /cors -l urls.txt
---

# /cors

Find CORS misconfigurations that let an attacker page read authenticated
responses cross-origin. Sends a battery of crafted `Origin` headers and inspects
the `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials` reply.

## Usage

```
/cors https://api.target.com/me
/cors https://api.target.com/me --cookie "session=abcd1234"
/cors -l recon/target.com/urls/api-endpoints.txt --json
```

Run directly:

```bash
tools/cors_scanner.py https://api.target.com/me --cookie "session=..."
```

## What it tests

| Origin sent | Detects |
|---|---|
| `https://evil.example` | arbitrary-origin reflection |
| `null` | sandboxed-iframe / data: URI trust |
| `https://api.target.com.evil.example` | weak `endsWith` (suffix) regex |
| `https://notapi.target.com` | weak `startsWith` (prefix) regex |
| `https://attacker.api.target.com` | blanket subdomain trust (chains w/ takeover) |
| `http://api.target.com` | https→http scheme downgrade |

## Severity

- **CRITICAL** — reflects attacker origin **with** `ACAC: true` (cookie-auth cross-origin read).
- **HIGH** — `null` origin trusted with credentials.
- **MEDIUM** — reflects attacker origin without credentials (exploitable when auth is a non-cookie token), or trusts http downgrade.
- **INFO** — `ACAO: *` with no credentials (usually intended public CORS).

## Why a credentialed reflection is the win

`ACAO: <attacker>` + `ACAC: true` means `fetch(url, {credentials:'include'})`
from an attacker page returns the victim's authenticated response body — full
account-data exfil. Pass `--cookie` with a live session to confirm the credentialed path.

## Chain

CORS data-read → harvest CSRF token / PII / API keys from the response →
escalate to ATO. A subdomain-trust CORS bug + a [subdomain takeover](takeover.md)
on that subdomain = a clean credentialed-read exploit.
