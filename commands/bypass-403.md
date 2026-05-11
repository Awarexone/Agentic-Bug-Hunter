---
description: Probe a 403/401 endpoint with the most-paid bypass tricks (header injection, path encoding, method swap). Wraps byp4xx when installed; otherwise runs a built-in matrix of ~20 techniques. Usage: /bypass-403 <url> | /bypass-403 -l <urls-file>
---

# /bypass-403

Try to bypass an HTTP 403/401 response with header injection, path encoding,
and method tampering — the standard battery from disclosed reports.

## Usage

```
/bypass-403 https://target.com/admin
/bypass-403 -l recon/target.com/live/status_403.txt
```

## What it tries

| Class | Examples |
|---|---|
| Header injection | `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization` |
| Path encoding | `/admin/%2e/`, `/.admin`, `/admin/`, `/admin;/`, `/admin..;/` |
| Suffix tricks | `/admin.json`, `/admin#`, `/admin/.` |
| Method tampering | POST, PUT, PATCH, TRACE on a GET-only endpoint |

When `byp4xx` (`lobuhi/byp4xx`) is installed it is used directly; otherwise the
built-in fallback runs the same set with `curl`.

## When it pays

- 403 on `/admin`, `/api/internal/*`, `/debug` — admin panel exposure.
- 401 on a GET endpoint that proxies through a misconfigured nginx — bypass
  via `X-Original-URL` is common for Nginx + Spring Boot stacks.
- A bypass that lands you in a privileged endpoint typically chains into
  IDOR / RCE / data exposure — payouts depend on what's behind the door.

## Output

`findings/bypass/<timestamp>/`:
- `byp4xx.txt` — full upstream-tool output, OR
- `bypass_hits.txt` — `method|url|header|status` lines for built-in fallback hits
