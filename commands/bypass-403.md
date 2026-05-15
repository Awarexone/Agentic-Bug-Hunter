---
description: Probe a 403/401 endpoint with the most-paid bypass tricks (header injection, path encoding, method swap, WAF fingerprint, vendor-specific). Wraps byp4xx when installed; otherwise runs a built-in matrix of 38+ techniques. Usage: /bypass-403 <url> | /bypass-403 -l <urls-file>
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
| IP spoofing headers | `X-Forwarded-For: 127.0.0.1`, `True-Client-IP`, `CF-Connecting-IP`, `X-Originating-IP`, `X-ProxyUser-Ip`, `Client-IP`, `Forwarded`, `X-Remote-Addr`, `X-Remote-IP`, `Via`, `X-HTTP-Method-Override` |
| Path tricks | `/%2e/`, `/%252e/`, `/.xxx`, `/xxx/`, `/xxx;/`, `/xxx..;/`, `/xxx%20`, `/xxx%09`, `//xxx`, `/./xxx` |
| Suffix tricks | `/xxx.json`, `/xxx.html`, `/xxx.css`, `/xxx#` |
| Method tampering | POST, PUT, PATCH, TRACE on a GET-only endpoint |
| Content-Type confusion | `application/json` POST, `multipart/form-data` POST, dual Content-Type header trick |
| Vendor-specific | Cloudflare (TE + X-Forwarded-Host), AWS WAF (`/**/` comment split), Imperva (`%c0%2e` unicode), F5 (double-slash path) |
| WAF fingerprint | Auto-detect via response headers/cookies (cf-ray → Cloudflare, x-amzn → AWS, TS cookie → F5, incap_ses → Imperva) |

When `byp4xx` (`lobuhi/byp4xx`) is installed it is used directly; otherwise the
built-in fallback runs the same set with `curl`.

## WAF Fingerprinting

The script auto-detects WAF vendor from response headers and cookies, then applies vendor-specific tricks automatically. Uses `wafw00f` when installed; falls back to header/cookie signature match.

Fingerprint saved to `findings/bypass/<ts>/waf_fingerprint.txt`.

## Payload Encoding (separate tool)

For payload-level bypass (SQLi/XSS keyword blocked by WAF):

```bash
tools/waf_encoder.py "' OR 1=1--" --class sqli
tools/waf_encoder.py "<script>alert(1)</script>" --class xss
tools/waf_encoder.py "<payload>" --layers 3   # triple URL-encode
tools/waf_encoder.py "<payload>" --json       # machine-readable output
```

Generates 20-40 variants: URL encoding (1-3 layers), unicode escape, HTML entity, SQL comment injection, MySQL version comment, case mixing, operator substitution, base64 XSS wrappers, null byte insertion.

## Multipart Upload Bypass (separate tool)

For blocked file upload endpoints:

```bash
tools/multipart_mutator.py --file shell.aspx --field file
tools/multipart_mutator.py --file shell.aspx --field file \
  --url https://target/upload --send
```

Emits 10 parser-confusion variants: boundary simplification, double-boundary case confusion, charset=utf-16le encoding, null-byte boundary, Content-Disposition sub-param injection, post-terminator payload, per-part image/jpeg Content-Type, CRLF/LF mix, leading-whitespace boundary, duplicate filename parameter.

## Verdict System

`bypass_403.sh` uses a 3-verdict system instead of raw status-code matching:

| Verdict | Condition | Output file |
|---|---|---|
| `bypassed` | Status ∈ {200,201,204,301,302,401,500,502,503} AND body ≠ block baseline AND no vendor signature | `bypass_hits.txt` |
| `needs_review` | Ambiguous — status OK but body unclear (manual check needed) | `bypass_uncertain.txt` |
| `blocked` | Body matches WAF vendor signature OR length ≈ block baseline (±5%) | `bypass_blocked.txt` |

When `waf_response_analyzer.py` is available (Python 3 + file exists), a weighted score engine is used: score ≥ 60 = blocked, 30–59 = needs_review, < 30 = bypassed. Without Python, a 3-check bash fallback runs (status whitelist + body regex + length diff).

**Why 200 OK is not enough:** WAF vendors intentionally return 200 with a challenge/block page
to hide that they're blocking. The tool samples a "block baseline" (known-bad XSS payload) at
startup to learn what blocked responses look like for this target.

**401 and 500 are bypass wins:** They indicate the request reached the backend past the WAF edge.
Previously these were incorrectly discarded as failures.

**WAF Log IDs:** When a block page contains a Log/Support/Incident ID, the tool extracts it
and logs it to `findings/bypass/<ts>/waf_fingerprint.txt`. Include these IDs in bug reports —
triage can look up the exact WAF rule that fired.

For more sophisticated analysis (baseline calibration + weighted score engine + log ID extraction):
```bash
tools/waf_response_analyzer.py --calibrate https://target.com --output /tmp/baseline.json
tools/waf_response_analyzer.py --classify --status 200 --body /tmp/resp.html \
  --headers /tmp/resp.hdr --baseline /tmp/baseline.json --metrics "200|2048|0.05" --format json
```

## When it pays

- 403 on `/admin`, `/api/internal/*`, `/debug` — admin panel exposure.
- 401 on a GET endpoint that proxies through a misconfigured nginx — bypass
  via `X-Original-URL` is common for Nginx + Spring Boot stacks.
- A bypass that lands you in a privileged endpoint typically chains into
  IDOR / RCE / data exposure — payouts depend on what's behind the door.

## Output

`findings/bypass/<timestamp>/`:
- `byp4xx.txt` — full upstream-tool output, OR
- `bypass_hits.txt` — `method|url|header|status|bodylen|verdict_json` lines for bypassed probes
- `bypass_uncertain.txt` — probes that need manual review (ambiguous response)
- `bypass_blocked.txt` — probes confirmed blocked (for debug/reporting)
