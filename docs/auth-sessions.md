# Auth-aware hunting

Most paying bugs (IDOR, BOLA, privilege escalation, auth bypass, mass-assignment,
SSRF behind a login) only exist *behind* a session. The default recon and vuln
pipeline runs anonymous, so those classes are invisible until you log in. This
doc explains how to plumb a session into the entire pipeline once and have
every downstream tool — `httpx`, `katana`, `ffuf`, `nuclei`, `dalfox`, the
SQLi / SSTI / upload PoC probes — send your auth headers automatically.

## Quick start

```bash
# Option A: CLI flags (one-off run)
python3 tools/hunt.py --target target.com \
    --cookie "session=eyJabc..." \
    --bearer "eyJhbGciOiJIUzI1NiI..."

# Option B: env vars (persists across commands in the shell)
export BBHUNT_COOKIE="session=eyJabc..."
export BBHUNT_BEARER="eyJhbGciOiJIUzI1NiI..."
python3 tools/hunt.py --target target.com

# Option C: file (recommended for multi-target hunts)
cat > .private/target.json <<'JSON'
{
  "cookie": "session=eyJabc...",
  "headers": ["X-Org-Id: 42", "X-CSRF-Token: abc"]
}
JSON
python3 tools/hunt.py --target target.com --auth-file .private/target.json
```

The `.private/` directory is gitignored. Use it.

## What gets auth'd

| Stage | Tool | Auth-aware? |
|---|---|---|
| Subdomain enum | subfinder, amass, crt.sh, wayback | No (passive) |
| Live host probing | httpx | **Yes** |
| Active crawl | katana | **Yes** |
| URL collection | gau, wayback | No (passive) |
| JS analysis | curl + regex | **Yes** |
| Config-file exposure | curl | **Yes** |
| Directory fuzzing | ffuf | **Yes** |
| nuclei templates | nuclei | **Yes** |
| SQLi PoC verifier | curl timing probes | **Yes** |
| Upload PoC | curl multipart | **Yes** |
| XSS scanner | dalfox | **Yes** |
| SSTI probes | curl | **Yes** |
| CMS detection | curl | **Yes** |
| **MFA workflow-skip test** | curl | **No, intentionally** |
| **SAML signature-stripping** | curl | **No, intentionally** |

The MFA-skip and SAML-stripping tests deliberately stay anonymous — that's the
attack they're checking for. Everything else is gated on the same session.

## CLI flags

All `tools/hunt.py` runs accept:

```
--auth-header 'Name: value'   # repeatable
--cookie 'session=...'        # shorthand for Cookie: header
--bearer 'eyJ...'             # shorthand for Authorization: Bearer ...
--api-key 'k'                 # shorthand for X-API-Key: header
--auth-file PATH              # JSON or .env file
--auth-from-env               # explicit opt-in (auto-detected if any env var set)
```

`scripts/full_hunt.sh` keeps its existing `--cookie` / `--token` flags. They
now flow through to httpx, katana, ffuf, nuclei, and dalfox.

## Env vars

```
BBHUNT_COOKIE        # one cookie string
BBHUNT_BEARER        # one bearer token
BBHUNT_API_KEY       # one API key (sent as X-API-Key)
BBHUNT_AUTH_HEADER   # newline-separated "Name: value" entries (repeatable)
```

When `tools/hunt.py` runs, it merges all inputs into a single session and
exports two derived vars to every subprocess:

```
BBHUNT_AUTH_HEADERS  # the merged, deduped header list (newline-separated)
BBHUNT_SESSION_ID    # sha256(headers)[:12] — short, stable hash
```

Bash scripts source `tools/_auth_helper.sh`, which turns these into an array
they can splat:

```bash
. tools/_auth_helper.sh
curl -sk "${BB_AUTH_ARGS[@]}" "$url"
nuclei -l "$list" "${BB_AUTH_ARGS[@]}" -o "$out"
```

Empty session = empty array = no behavior change. Anonymous hunts are still
the default and still fast.

## Audit trail

Every request that hits `memory/audit_log.py` is stamped with `session_id`
(the same 12-char hash). Raw cookie/token values are **never** logged. To
audit which requests went out under which identity:

```bash
jq -r 'select(.session_id) | "\(.session_id) \(.method) \(.url)"' \
    hunt-memory/audit.jsonl | sort -u
```

If you rotate the credential, the hash changes. That's the whole point —
you can correlate findings to a session without ever writing the secret.

## Auth file format

JSON (preferred):

```json
{
  "cookie": "session=eyJabc...",
  "bearer": "eyJhbGciOi...",
  "api_key": "ak_live_...",
  "api_key_header": "X-Token",
  "headers": [
    "X-Org-Id: 42",
    "X-Tenant: acme"
  ]
}
```

A bare JSON array of header strings also works:

```json
["Cookie: session=abc", "X-Org-Id: 42"]
```

Or a `.env`-style file:

```
BBHUNT_COOKIE=session=eyJabc
BBHUNT_BEARER=eyJhbGciOi
X-API-Key=ak_live_xxx
```

## Multiple sessions (low-priv vs high-priv)

For IDOR / privilege-escalation work, keep two files:

```
.private/user-a.json   # low-priv session
.private/user-b.json   # high-priv session
```

Run two passes:

```bash
python3 tools/hunt.py --target target.com --auth-file .private/user-a.json
python3 tools/hunt.py --target target.com --auth-file .private/user-b.json
```

Audit log entries will carry different `session_id` hashes, so you can diff
which endpoints behaved differently per identity.

## Safety

- Auth values never appear in `repr()`, `str()`, logs, or hunt-memory.
- CR/LF in any header value is rejected (would be header-injection in our own requests).
- The session_id is a hash — losing the audit log doesn't leak the credential.
- `.private/` is gitignored. So is `.env`.
- Set `--auth-from-env` only on machines you trust; env vars are visible to other
  processes running as the same user.

## Adding auth to a custom script

```python
from tools.auth_session import AuthSession

session = AuthSession.from_sources(
    file=".private/target.json",
    headers=["X-Custom: extra"],
)
print(session.describe())          # "auth: session=b181f318fb10 headers=[Authorization, Cookie, X-Custom]"

# For Python HTTP libs:
import requests
requests.get(url, headers=session.headers_dict())

# For subprocess:
import subprocess, os
env = os.environ.copy()
session.export_to_env(env)
subprocess.run(["bash", "tools/recon_engine.sh", target], env=env)
```
