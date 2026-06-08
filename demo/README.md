# Vulnerable Demo Target

A self-contained "shuvonsec.me lookalike" web app used by the
[A→Z tutorial](../TUTORIAL.md) to demonstrate the toolkit end-to-end.

> ⚠️  **Intentionally vulnerable. Run locally only.**
> The server binds to `127.0.0.1` by default. Don't expose it to the public
> internet — these bugs are real, just deliberately introduced for teaching.

## Run

```bash
python3 serve.py        # ← use this in the recording (no "demo" in command)
# or, equivalently:
python3 demo/app.py
```

Either form prints just `Serving on http://127.0.0.1:8080  (Ctrl+C to stop)`.
Pure stdlib — no `pip install`. Stop with Ctrl+C.

Environment variables:

| Variable          | Default     | Notes                                          |
|-------------------|-------------|------------------------------------------------|
| `APP_HOST`        | `127.0.0.1` | Override only inside a disposable VM/container |
| `APP_PORT`        | `8080`      | Pick another if 8080 is taken                  |
| `SHUVONSEC_QUIET` | unset       | Set to `1` to suppress the startup banner (recording-friendly) |

## Planted bugs

Six bugs, all detectable by `/recon` + `/hunt`. The same payload table appears
inside the app's startup banner.

| # | Class               | Path                                         | Payload that proves it                                                        |
|---|---------------------|----------------------------------------------|-------------------------------------------------------------------------------|
| 1 | Reflected XSS       | `/search?q=`                                 | `<script>alert(1)</script>` reflected raw into `<h2>`                         |
| 2 | Open redirect       | `/go?url=`                                   | `?url=https://evil.example` → 302 to attacker domain                          |
| 3 | SSRF                | `/fetch?url=`                                | `?url=http://127.0.0.1:8080/.env` (or `http://169.254.169.254/...` on AWS)    |
| 4 | Sensitive file      | `/.env`                                      | Returns fake `AWS_ACCESS_KEY_ID`, JWT signing key, DB password                |
| 5 | Unauthed admin      | `/admin`                                     | 200 OK — no auth check, no session, no CSRF token                             |
| 6 | Debug info leak     | `/api/debug`                                 | JSON dump of host, port, env vars, feature flags                              |

The `/robots.txt` advertises four of these on purpose, so URL-crawl-style
recon finds them quickly.

## Tearing it down

Just Ctrl+C the process. Nothing is persisted to disk.

## After the video

Delete the `demo/` directory if you don't want it shipped with your repo —
or keep it as a regression target for your own future tool work.
