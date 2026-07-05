# Methodology Cheatsheet

Distilled from `KathanP19/HowToHunt`, `HolyBugx/HolyTips`,
`daffainfo/AllAboutBugBounty`, and `KingOfBugbounty/KingOfBugBountyTips`. The
upstream repos go deeper — see `REFERENCES.md` for links. Use this as a lookup
table during the hunt.

## Per-vuln quick checks (try first, in order)

### IDOR
1. Replace numeric IDs (1 → 2, 100 → 101) with another user's ID.
2. Replace UUID with another user's UUID (especially in PUT/DELETE).
3. Try parameter pollution: `?user_id=1&user_id=2`.
4. Swap auth tokens between two test accounts; replay the same request.
5. Look for IDs in JSON bodies, GraphQL variables, WebSocket frames — not just URL.
6. Check mass-assignment angle: PATCH `/api/users/1 {"role":"admin"}`.

### XSS
1. Reflected: inject `'"<script>alert(1)</script>` in every reflected param; check encoding.
2. DOM: search the source for `innerHTML`, `eval`, `document.write`, `location.hash`, `postMessage`.
3. Stored: profile bio, comment, file metadata (EXIF), display name, support ticket.
4. Mutation XSS: nested `<svg><a><animate attributeName=href values=javascript:alert(1)>`.
5. Bypasses: try `</script><script>`, SVG, mathml, fenced fragments.

### SSRF
1. Try `http://127.0.0.1`, `http://localhost`, `http://[::]`, `http://0.0.0.0`.
2. Cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3. Bypass via redirect: `http://attacker.com/redirect?to=http://localhost`.
4. DNS rebinding via your own A record: TTL=0, alternate between attacker IP and localhost.
5. Bypass parser tricks: `http://127.0.0.1#@target.com`, decimal `http://2130706433`.
6. Use OOB tool (`interactsh-client`) — file uploads, webhook URLs, PDF generators.

### Open redirect
1. Find every `?redirect=`, `?next=`, `?return=`, `?continue=`, `?dest=`.
2. Bypass: `//evil.com`, `https:evil.com`, `https://evil.com\@target.com`.
3. Path-relative trick: `?redirect=/\\evil.com`.
4. Whitelist defeat: `?redirect=https://target.com.evil.com`.
5. Chain to OAuth code theft: `?redirect_uri=https://attacker.com`.

### SQLi
1. Append `'` and look for SQL error in response.
2. Time-based: `' AND SLEEP(5)--`, `' OR pg_sleep(5)--`.
3. Boolean: `' AND 1=1--` vs `' AND 1=2--` and diff response.
4. Stacked: `;DROP TABLE` (rarely works but disclosed often as severe even when not).
5. Use `ghauri` or `sqlmap` with `--level=5 --risk=3` for confirmed time-based.

### CSRF
1. Find any state-changing request (POST/PUT/DELETE) without an Authorization header.
2. Confirm no anti-CSRF token, no SameSite cookie attribute (None or absent).
3. Build minimal HTML PoC: `<form action=... method=post><input ...></form><script>document.forms[0].submit()</script>`.
4. JSON CSRF: try `Content-Type: text/plain` with a JSON-encoded body in the form.

### OAuth
1. `redirect_uri` validation lax → swap to attacker domain → leak code on referer.
2. `state` missing or fixed → CSRF on the OAuth callback.
3. Implicit flow: token in fragment → leaks via `Referer` to any embedded image.
4. PKCE not enforced → MITM/XSS can reuse the code.
5. Pre-account-takeover: register the victim's email at the IDP before they do.

### Race conditions
1. Money: send the same withdrawal request 50× in parallel — does balance go negative?
2. Coupons: redeem same single-use coupon 100× in parallel.
3. Account creation: same username 50× in parallel — duplicates?
4. Use `ffuf -p` or a goroutine-based fuzzer; avoid `&` background loops in bash for true parallelism.

### File upload
1. Bypass extension allowlist: `shell.php.jpg`, `shell.php%00.jpg`, `shell.PHP`, `shell.phtml`.
2. Bypass MIME check: keep allowed content-type in header, change body to PHP.
3. SVG with embedded JS for stored XSS.
4. Polyglot files: PNG header + PHP body → `image/png` MIME but executes as PHP.
5. ZIP/tar slip: filename `../../../etc/passwd` extracted into restricted dir.

### Subdomain takeover
1. Run `tools/takeover_scanner.sh --recon recon/<target>` — covers most fingerprints.
2. Manual: `dig CNAME suspect.target.com`; if it points at a service that returns a "no such app/page" page → claimable.
3. Check `EdOverflow/can-i-take-over-xyz` for the per-provider claim flow.

### MFA bypass
1. Response manipulation: change `success: false` → `true` in the OTP response.
2. Skip the OTP step: try the post-MFA URL directly with the pre-MFA cookie.
3. No rate limit: brute-force 6-digit OTP with 1M requests over a long window.
4. Replay the OTP after expiration window — many backends don't invalidate.
5. Force the backup-code flow when the program advertises only TOTP.

## High-EV recon one-liners

```bash
# Find every JS file the target loads, extract endpoints, then check 200/403
gau target.com | grep '\.js$' | xargs -I{} curl -s {} | linkfinder -d -o cli | tee endpoints.txt

# Fast subdomain enum + live + screenshot in one shot
subfinder -d target.com -all -silent | httpx -silent | aquatone -out aquatone/

# Pull every leaked secret from a GitHub org via dorks
GitDorker -tf tokens.txt -q '<org-name>' -d dorks/alldorks.txt -o dork.json

# Find hidden parameters on a 200 endpoint
arjun -u 'https://target.com/api/v2/users/123' -m GET --headers 'Authorization: Bearer ...'

# Race-condition burst with curl + xargs
seq 1 100 | xargs -P50 -I{} curl -sk -X POST 'https://target.com/api/redeem' -d 'coupon=ABC123'
```

## Always check, even when target looks dead

- `/.git/config`, `/.env`, `/server-status`, `/actuator`, `/.DS_Store`, `/swagger.json`, `/api-docs`.
- `/api/v1` vs `/api/v2` vs `/api/internal` — internal versions often skip auth.
- robots.txt + sitemap.xml — disclosed paths the dev didn't want spidered.
- HTTP/2 vs HTTP/1 host header smuggling on every CDN-fronted host.
- WebSocket endpoints — origin check often missing, and rarely tested.
