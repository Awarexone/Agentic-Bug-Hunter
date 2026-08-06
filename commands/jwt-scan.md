---
description: JWT attack toolkit (offline) — alg:none forgery, RS256→HS256 algorithm confusion, weak-secret crack, static claim analysis. Usage: /jwt-scan <token> [--analyze|--alg-none|--confuse --public-key pub.pem|--crack --wordlist f]
---

# /jwt-scan

Forge and analyze JWTs offline. Implements the three highest-paid JWT bugs from
the auth skill. All crypto is pure stdlib — no network needed to mint a forgery.

## Usage

```
/jwt-scan <token> --analyze
/jwt-scan <token> --alg-none
/jwt-scan <token> --confuse --public-key pub.pem --set role=admin
/jwt-scan <token> --crack --wordlist wordlists/jwt-secrets.txt
```

Run directly:

```bash
tools/jwt_scanner.py "$TOKEN" --analyze
tools/jwt_scanner.py "$TOKEN" --crack --wordlist secrets.txt
```

## Attacks

| Flag | Attack | When it works |
|---|---|---|
| `--alg-none` | Strip signature, set `alg` to none/None/NONE/nOnE | verifier honors `alg` from the header |
| `--confuse --public-key` | RS256→HS256: re-sign with the server's **public** key as the HMAC secret | verifier calls generic `verify(token, key)` |
| `--crack --wordlist` | Brute-force the HS256 secret | weak/guessable signing secret |
| `--analyze` | Static: flags `alg=none`, missing `exp`, trust-bearing claims (`role`/`is_admin`/`scope`), `kid` (probe for traversal/SQLi) | always |

`--set key=value` (repeatable) overrides claims in `--alg-none`/`--confuse`
forgeries — e.g. `--set role=admin --set sub=1`.

## Workflow

1. `--analyze` to read the header/claims and pick an attack.
2. Mint a forgery (`--alg-none` or `--confuse`) with `--set role=admin`.
3. Replay the forged token against an authenticated endpoint — if it's
   accepted, you have **privilege escalation / auth bypass** (Critical).

Getting the public key for `--confuse`: try `/jwks.json`,
`/.well-known/jwks.json`, or extract it from the TLS cert / a verify endpoint.
