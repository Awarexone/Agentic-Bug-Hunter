#!/usr/bin/env python3
"""
Port / service scanner — exposes the NON-HTTP attack surface recon misses.

The main pipeline is HTTP-only (httpx/nuclei/katana), so open ports that don't
speak HTTP — SSH, databases, Redis, SMTP, RDP, admin panels on odd ports — are
invisible to the rest of the toolkit. This wraps ProjectDiscovery's `naabu`
(registered in external_arsenal as `naabu|probe`) with an `smap` fallback
(Shodan-backed, no packets) and turns raw `host:port` output into a surface map
that flags the interesting, often-forgotten services.

Parsing + service classification are pure and unit-tested; only `scan()` shells
out to naabu/smap.

Usage:
  tools/port_scanner.py target.com                 # top-100 ports via naabu
  tools/port_scanner.py target.com --top 1000
  tools/port_scanner.py target.com -p 22,6379,27017
  tools/port_scanner.py -l hosts.txt --json
  tools/port_scanner.py target.com --smap          # passive (Shodan) fallback
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

USER_AGENT = "agentic-bug-hunter/port_scanner"

# port -> (service, note). Anything here that is NOT 80/443 is worth a second
# look because the HTTP pipeline never touched it.
KNOWN_SERVICES: dict[int, tuple[str, str]] = {
    21: ("ftp", "anon login / creds"),
    22: ("ssh", "weak creds / exposed key auth"),
    23: ("telnet", "cleartext admin"),
    25: ("smtp", "open relay / user enum"),
    53: ("dns", "zone transfer / recursion"),
    110: ("pop3", "cleartext mail"),
    135: ("msrpc", "windows rpc"),
    139: ("netbios", "smb enum"),
    445: ("smb", "null session / eternalblue-class"),
    1433: ("mssql", "db exposed to internet"),
    1521: ("oracle", "db exposed to internet"),
    2375: ("docker", "UNAUTH docker API — instant RCE"),
    3306: ("mysql", "db exposed to internet"),
    3389: ("rdp", "bluekeep / weak creds"),
    5432: ("postgres", "db exposed to internet"),
    5900: ("vnc", "no-auth remote desktop"),
    6379: ("redis", "UNAUTH redis — RCE / data dump"),
    8009: ("ajp", "ghostcat / tomcat"),
    9200: ("elasticsearch", "UNAUTH index dump"),
    11211: ("memcached", "UNAUTH / DDoS amp"),
    27017: ("mongodb", "UNAUTH db dump"),
}

# Ports that usually just mean "there's a web app here" — recon already has these.
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


@dataclass
class PortResult:
    host: str
    port: int
    service: str = ""
    note: str = ""

    @property
    def is_web(self) -> bool:
        return self.port in WEB_PORTS

    @property
    def is_interesting(self) -> bool:
        """Open, non-web, and a service we have an attack note for."""
        return not self.is_web and self.port in KNOWN_SERVICES


def classify(host: str, port: int) -> PortResult:
    """Pure: attach the known service/note (if any) to a host:port."""
    service, note = KNOWN_SERVICES.get(port, ("", ""))
    return PortResult(host=host, port=port, service=service, note=note)


def parse_naabu(text: str) -> list[PortResult]:
    """Parse naabu's default `host:port` lines (one per line). Ignores JSON,
    blanks, and comments so it also tolerates `-json` accidentally left off."""
    out: list[PortResult] = []
    seen: set[tuple[str, int]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):  # tolerate -json lines
            try:
                obj = json.loads(line)
                host, port = obj.get("host") or obj.get("ip"), obj.get("port")
            except (ValueError, TypeError):
                continue
        else:
            host, _, port_s = line.rpartition(":")
            if not host or not port_s.isdigit():
                continue
            port = int(port_s)
        if host is None or port is None:
            continue
        key = (host, int(port))
        if key in seen:
            continue
        seen.add(key)
        out.append(classify(host, int(port)))
    return out


def summarize(results: list[PortResult]) -> dict:
    """Pure: counts + the interesting (non-web) services pulled to the top."""
    interesting = [r for r in results if r.is_interesting]
    return {
        "total_open": len(results),
        "web": sum(1 for r in results if r.is_web),
        "interesting": len(interesting),
        "hosts": len({r.host for r in results}),
        "flagged": [asdict(r) for r in interesting],
    }


def build_naabu_cmd(target: str, ports: str | None, top: int, is_list: bool) -> list[str]:
    cmd = ["naabu", "-silent"]
    cmd += ["-list", target] if is_list else ["-host", target]
    if ports:
        cmd += ["-port", ports]
    else:
        cmd += ["-top-ports", str(top)]
    return cmd


def build_smap_cmd(target: str, is_list: bool) -> list[str]:
    # smap is nmap-compatible; -oG - streams greppable output to stdout.
    return ["smap", "-iL", target] if is_list else ["smap", target]


def _binary(prefer_smap: bool) -> str | None:
    order = ["smap", "naabu"] if prefer_smap else ["naabu", "smap"]
    for b in order:
        if shutil.which(b):
            return b
    return None


def scan(target: str, ports: str | None, top: int, is_list: bool, prefer_smap: bool) -> list[PortResult]:
    binary = _binary(prefer_smap)
    if binary is None:
        raise FileNotFoundError("naabu")
    if binary == "smap":
        cmd = build_smap_cmd(target, is_list)
    else:
        cmd = build_naabu_cmd(target, ports, top, is_list)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    return parse_naabu(proc.stdout)


def _render(results: list[PortResult], as_json: bool) -> str:
    summary = summarize(results)
    if as_json:
        return json.dumps({"summary": summary, "ports": [asdict(r) for r in results]}, indent=2)
    lines = [
        f"[*] {summary['total_open']} open ports on {summary['hosts']} host(s) "
        f"— {summary['web']} web, {summary['interesting']} non-web flagged",
    ]
    for r in sorted(results, key=lambda x: (x.host, x.port)):
        tag = f"  <- {r.service}: {r.note}" if r.is_interesting else ""
        lines.append(f"    {r.host}:{r.port}{tag}")
    if summary["interesting"]:
        lines.append("")
        lines.append("[!] Non-web services the HTTP pipeline can't see — start here.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Port/service scanner (naabu, smap fallback).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("target", nargs="?", help="host, IP, or CIDR")
    src.add_argument("-l", "--list", dest="list_file", help="file of hosts, one per line")
    ap.add_argument("-p", "--port", help="explicit ports, e.g. 22,6379,27017")
    ap.add_argument("--top", type=int, default=100, help="top-N ports (default 100)")
    ap.add_argument("--smap", action="store_true", help="prefer passive smap (Shodan, no packets)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    target = args.list_file or args.target
    is_list = bool(args.list_file)
    if is_list and not Path(target).is_file():
        print(f"[-] host list not found: {target}", file=sys.stderr)
        return 2

    try:
        results = scan(target, args.port, args.top, is_list, args.smap)
    except FileNotFoundError:
        print(
            "[-] neither `naabu` nor `smap` is installed.\n"
            "    naabu: GOBIN=$HOME/go/bin go install "
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n"
            "    smap : GOBIN=$HOME/go/bin go install github.com/s0md3v/smap/cmd/smap@latest",
            file=sys.stderr,
        )
        return 127
    except subprocess.TimeoutExpired:
        print("[-] port scan timed out (30m).", file=sys.stderr)
        return 124

    print(_render(results, args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
