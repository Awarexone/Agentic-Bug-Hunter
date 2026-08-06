---
description: Test for CRLF / HTTP response-splitting and host-header injection — Set-Cookie injection, cache poisoning, reset-poisoning. Usage: /crlf <url> [--host-header] | /crlf -l urls.txt
---

# /crlf

Inject carriage-return/line-feed sequences into the path/query (and optionally
the Host/forwarding headers) and check whether an attacker-controlled header
lands in the **response** — proof of CRLF injection.

## Usage

```
/crlf "https://target.com/redirect?url=x"
/crlf https://target.com/ --host-header
/crlf -l recon/target.com/urls/params.txt --json
```

Run directly:

```bash
tools/crlf_scanner.py "https://target.com/r?u=x" --host-header
```

## What it injects

| Vector | Payloads |
|---|---|
| Encoded CRLF | `%0d%0a`, `%0a`, `%0d`, `%250d%250a` (double-encoded) |
| Header fold | `%0d%0a%20Set-Cookie:...` |
| UTF-8 bypass | `%E5%98%8A%E5%98%8D` (overlong CR/LF that defeats naive `\r\n` filters) |
| IIS unicode | `%u000d%u000a` |
| Host-header | `Host: evil`, `X-Forwarded-Host`, `Forwarded: host=`, CRLF-in-Host |

Detection canary: the payloads try to inject `Set-Cookie: crlftest=1`. If that
header appears in the response, it's confirmed.

## Impact

- **Set-Cookie injection** → session fixation.
- **Injected `Location`** → open redirect / OAuth token theft.
- **Injected body** → reflected XSS that survives CSP host allowlists.
- **Host-header injection** → password-reset poisoning (attacker host in reset link), cache poisoning.

## Note

Python's `urllib` refuses raw `\r\n` in a URL (it protects you), so the
**encoded** variants are what actually go on the wire — that's intended. The
host-header path also flags when your attacker host is reflected in a `Location`
response header (reset-poisoning signal) even without a full CRLF.
