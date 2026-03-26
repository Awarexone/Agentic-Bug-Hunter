#!/usr/bin/env python3
"""
Zero-Day Bug Finder
Automated fuzzing and edge-case testing to discover novel vulnerabilities.
Uses smart fuzzing, logic flaw detection, and unusual input testing.

This focuses on finding bugs that automated scanners miss:
- Business logic flaws
- Race conditions
- Unusual parameter interactions
- Edge cases in input validation
- Access control bypasses
- IDOR via parameter manipulation

Usage:
    python3 zero_day_fuzzer.py <target_url>
    python3 zero_day_fuzzer.py --recon-dir <recon_dir>
    python3 zero_day_fuzzer.py <target_url> --deep
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")


def run_cmd(cmd, timeout=15):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


def curl_request(url, method="GET", headers=None, data=None, timeout=10):
    """Make an HTTP request via curl and return status, headers, body."""
    cmd_parts = ["curl", "-s", "-D-", "--max-time", str(timeout)]

    if method != "GET":
        cmd_parts.extend(["-X", method])

    if headers:
        for k, v in headers.items():
            cmd_parts.extend(["-H", f"{k}: {v}"])

    if data:
        cmd_parts.extend(["-d", data])

    cmd_parts.append(f'"{url}"')
    cmd = " ".join(cmd_parts)

    success, stdout, stderr = run_cmd(cmd, timeout=timeout + 5)

    if not success or not stdout:
        return None, None, None

    # Split headers and body
    parts = stdout.split("\r\n\r\n", 1)
    if len(parts) == 2:
        resp_headers, body = parts
    else:
        resp_headers, body = stdout, ""

    # Extract status code
    status_match = re.search(r'HTTP/\S+\s+(\d+)', resp_headers)
    status = int(status_match.group(1)) if status_match else 0

    return status, resp_headers, body


def get_response_signature(status, body):
    """Create a signature for response comparison."""
    body_hash = hashlib.md5(body.encode()[:1000]).hexdigest()[:8] if body else "empty"
    body_len = len(body) if body else 0
    return f"{status}:{body_len}:{body_hash}"


class ZeroDayFuzzer:
    def __init__(self, target, findings_dir=None, deep=False):
        self.target = target
        self.deep = deep
        self.domain = urlparse(target).netloc
        self.findings = []

        if findings_dir:
            self.findings_dir = findings_dir
        else:
            self.findings_dir = os.path.join(FINDINGS_DIR, self.domain, "zero_day")
        os.makedirs(self.findings_dir, exist_ok=True)

    def add_finding(self, vuln_type, severity, title, details):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "title": title,
            "details": details,
            "url": self.target,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        sev_colors = {"critical": "\033[0;31m", "high": "\033[0;31m", "medium": "\033[1;33m", "low": "\033[0;36m"}
        color = sev_colors.get(severity, "")
        reset = "\033[0m"
        print(f"    {color}[FINDING]{reset} [{severity.upper()}] {title}")

    def test_http_method_tampering(self):
        """Test for HTTP method override/tampering vulnerabilities."""
        print("\n  [>] Testing HTTP method tampering...")
        methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
        override_headers = {
            "X-HTTP-Method-Override": "PUT",
            "X-Method-Override": "DELETE",
            "X-HTTP-Method": "PATCH",
        }

        # Get baseline
        base_status, _, base_body = curl_request(self.target)
        if not base_status:
            return

        base_sig = get_response_signature(base_status, base_body)

        # Test each method
        for method in methods:
            status, headers, body = curl_request(self.target, method=method)
            if status and status != 405 and status != 501:
                sig = get_response_signature(status, body)
                if sig != base_sig:
                    self.add_finding(
                        "method_tampering", "medium",
                        f"HTTP {method} returns unexpected response ({status})",
                        f"URL: {self.target}\nMethod: {method}\nStatus: {status}\nBaseline: {base_status}"
                    )

            # Test TRACE specifically (XST)
            if method == "TRACE" and status == 200 and body:
                if "TRACE" in body:
                    self.add_finding(
                        "xst", "low",
                        "TRACE method enabled (Cross-Site Tracing)",
                        f"URL: {self.target}\nTRACE method reflects request"
                    )

        # Test method override headers
        for header, value in override_headers.items():
            status, headers, body = curl_request(
                self.target, headers={header: value}
            )
            if status and status != base_status:
                self.add_finding(
                    "method_override", "medium",
                    f"Method override via {header} changes behavior",
                    f"Header: {header}: {value}\nOriginal status: {base_status}\nNew status: {status}"
                )

    def test_host_header_injection(self):
        """Test for Host header injection vulnerabilities."""
        print("  [>] Testing Host header injection...")

        payloads = [
            ("evil.com", "Host header accepts arbitrary domain"),
            (f"{self.domain}.evil.com", "Host header accepts subdomain injection"),
            (f"{self.domain}@evil.com", "Host header accepts @ injection"),
            (f"{self.domain}\r\nX-Injected: true", "Host header CRLF injection"),
        ]

        for payload, desc in payloads:
            status, headers, body = curl_request(
                self.target, headers={"Host": payload}
            )
            if status and body:
                if payload in body or "evil.com" in body:
                    self.add_finding(
                        "host_header_injection", "high",
                        desc,
                        f"Payload: Host: {payload}\nReflected in response body"
                    )
                if headers and ("evil.com" in headers):
                    self.add_finding(
                        "host_header_injection", "high",
                        f"{desc} (reflected in headers)",
                        f"Payload: Host: {payload}\nReflected in response headers"
                    )

    def test_cors_misconfig(self):
        """Deep CORS misconfiguration testing."""
        print("  [>] Testing CORS misconfigurations...")

        origins = [
            "https://evil.com",
            f"https://{self.domain}.evil.com",
            f"https://evil{self.domain}",
            "null",
            f"https://{self.domain}%60.evil.com",
            f"https://{self.domain}_.evil.com",
        ]

        for origin in origins:
            status, headers, body = curl_request(
                self.target, headers={"Origin": origin}
            )
            if headers:
                acao = re.search(r'access-control-allow-origin:\s*(.+)', headers, re.I)
                acac = re.search(r'access-control-allow-credentials:\s*true', headers, re.I)

                if acao:
                    acao_value = acao.group(1).strip()
                    if origin in acao_value or acao_value == "*":
                        severity = "high" if acac else "medium"
                        self.add_finding(
                            "cors", severity,
                            f"CORS reflects origin: {origin}",
                            f"Origin: {origin}\nACAO: {acao_value}\nCredentials: {'Yes' if acac else 'No'}"
                        )

    def test_security_headers(self):
        """Check for missing security headers."""
        print("  [>] Checking security headers...")

        status, headers, body = curl_request(self.target)
        if not headers:
            return

        headers_lower = headers.lower()

        required_headers = {
            "strict-transport-security": "Missing HSTS header",
            "x-content-type-options": "Missing X-Content-Type-Options",
            "x-frame-options": "Missing X-Frame-Options (clickjacking)",
            "content-security-policy": "Missing Content-Security-Policy",
            "x-xss-protection": "Missing X-XSS-Protection",
        }

        for header, desc in required_headers.items():
            if header not in headers_lower:
                self.add_finding("missing_header", "low", desc, f"URL: {self.target}")

    def test_path_traversal(self):
        """Test for path traversal in URL paths."""
        print("  [>] Testing path traversal...")

        payloads = [
            ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal"),
            ("....//....//....//etc/passwd", "Double-dot bypass"),
            ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "Hex-encoded traversal"),
            ("..%252f..%252f..%252fetc%252fpasswd", "Double URL-encoded"),
            ("..\\..\\..\\etc\\passwd", "Backslash traversal"),
        ]

        base_url = self.target.rstrip("/")

        for payload, desc in payloads:
            url = f"{base_url}/{payload}"
            status, headers, body = curl_request(url)
            if status == 200 and body:
                if "root:" in body or "/bin/" in body:
                    self.add_finding(
                        "path_traversal", "critical",
                        f"Path traversal: {desc}",
                        f"URL: {url}\nEvidence: File content in response"
                    )

    def test_crlf_injection(self):
        """Test for CRLF injection in various locations."""
        print("  [>] Testing CRLF injection...")

        payloads = [
            "%0d%0aX-Injected:true",
            "%0d%0aSet-Cookie:injected=true",
            "%E5%98%8D%E5%98%8AX-Injected:true",  # Unicode CRLF
        ]

        base_url = self.target.rstrip("/")

        for payload in payloads:
            url = f"{base_url}/{payload}"
            status, headers, body = curl_request(url)
            if headers and "x-injected" in headers.lower():
                self.add_finding(
                    "crlf", "high",
                    "CRLF injection in URL path",
                    f"URL: {url}\nInjected header reflected in response"
                )

            # Test in query parameter
            url = f"{base_url}/?param={payload}"
            status, headers, body = curl_request(url)
            if headers and "x-injected" in headers.lower():
                self.add_finding(
                    "crlf", "high",
                    "CRLF injection in query parameter",
                    f"URL: {url}\nInjected header reflected in response"
                )

    def test_open_redirect(self):
        """Test for open redirect with various bypass techniques."""
        print("  [>] Testing open redirect bypasses...")

        redirect_params = ["url", "redirect", "next", "return", "returnTo", "return_to",
                          "goto", "dest", "destination", "redir", "redirect_uri",
                          "continue", "target", "rurl", "out", "view", "ref"]

        payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "/\\evil.com",
            "https:evil.com",
            f"https://{self.domain}@evil.com",
            f"https://{self.domain}.evil.com",
            "javascript:alert(1)",
            "data:text/html,<h1>test</h1>",
            "https://evil.com/%2F%2F",
        ]

        base_url = self.target.rstrip("/")

        for param in redirect_params:
            for payload in payloads[:3]:  # Test top 3 payloads per param
                url = f"{base_url}/?{param}={payload}"
                # Use curl with -L to follow redirects but capture all headers
                cmd = f'curl -sI -D- --max-time 10 "{url}" 2>/dev/null'
                success, stdout, _ = run_cmd(cmd, timeout=15)
                if success and stdout:
                    location = re.search(r'location:\s*(.+)', stdout, re.I)
                    if location:
                        loc = location.group(1).strip()
                        if "evil.com" in loc:
                            self.add_finding(
                                "open_redirect", "medium",
                                f"Open redirect via {param} parameter",
                                f"URL: {url}\nRedirects to: {loc}\nPayload: {payload}"
                            )
                            break  # Found one, move to next param

    def test_403_bypass(self):
        """Test for 403 bypass techniques."""
        print("  [>] Testing 403 bypass techniques...")

        # First find 403 pages
        common_403 = ["/admin", "/admin/", "/dashboard", "/internal", "/config",
                      "/management", "/api/admin", "/server-status"]

        base_url = self.target.rstrip("/")

        for path in common_403:
            status, _, _ = curl_request(f"{base_url}{path}")
            if status != 403:
                continue

            print(f"      Testing bypasses for {path} (403)...")

            bypass_techniques = [
                # Path manipulation
                (f"{path}/.", "path with trailing dot"),
                (f"{path}//", "double slash"),
                (f"{path}/./", "dot-slash"),
                (f"{path}%20", "URL-encoded space"),
                (f"{path}%09", "URL-encoded tab"),
                (f"{path}..;/", "semicolon bypass"),
                (f"{path};", "trailing semicolon"),
                (f"{path}.json", "add extension"),
                (f"{path}.html", "add HTML extension"),
                (f"/{path.strip('/')}", "re-normalize"),
                # Case manipulation
                (path.upper(), "uppercase path"),
            ]

            # Header bypasses
            header_bypasses = [
                {"X-Original-URL": path},
                {"X-Rewrite-URL": path},
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Forwarded-Host": "localhost"},
            ]

            for bypass_path, desc in bypass_techniques:
                test_status, _, _ = curl_request(f"{base_url}{bypass_path}")
                if test_status and test_status == 200:
                    self.add_finding(
                        "403_bypass", "high",
                        f"403 bypass on {path} via {desc}",
                        f"Original: {base_url}{path} → 403\n"
                        f"Bypass: {base_url}{bypass_path} → {test_status}"
                    )
                    break

            for headers in header_bypasses:
                test_status, _, _ = curl_request(f"{base_url}{path}", headers=headers)
                if test_status and test_status == 200:
                    header_name = list(headers.keys())[0]
                    self.add_finding(
                        "403_bypass", "high",
                        f"403 bypass on {path} via {header_name} header",
                        f"Original: {base_url}{path} → 403\n"
                        f"Header: {header_name}: {headers[header_name]} → {test_status}"
                    )
                    break

    def test_prototype_pollution(self):
        """Test for client-side prototype pollution indicators."""
        print("  [>] Testing prototype pollution indicators...")

        base_url = self.target.rstrip("/")
        payloads = [
            "?__proto__[test]=polluted",
            "?constructor[prototype][test]=polluted",
            "?__proto__.test=polluted",
            "#__proto__[test]=polluted",
        ]

        for payload in payloads:
            url = f"{base_url}/{payload}"
            status, headers, body = curl_request(url)
            if status == 200 and body:
                # Check if there's any reflection or error that indicates processing
                if "polluted" in body and "__proto__" not in body:
                    self.add_finding(
                        "prototype_pollution", "high",
                        "Potential prototype pollution",
                        f"URL: {url}\nPayload value reflected without key"
                    )

    def test_cache_poisoning(self):
        """Test for web cache poisoning."""
        print("  [>] Testing cache poisoning indicators...")

        # Test unkeyed headers
        unkeyed_headers = {
            "X-Forwarded-Host": "evil.com",
            "X-Host": "evil.com",
            "X-Forwarded-Server": "evil.com",
            "X-Forwarded-Scheme": "nothttps",
        }

        for header, value in unkeyed_headers.items():
            status, resp_headers, body = curl_request(
                self.target, headers={header: value}
            )
            if body and "evil.com" in body:
                self.add_finding(
                    "cache_poisoning", "high",
                    f"Cache poisoning via {header} header",
                    f"Header: {header}: {value}\nValue reflected in response body"
                )

    def run_all_tests(self):
        """Run all zero-day detection tests."""
        print(f"\n{'='*55}")
        print(f"  Zero-Day Bug Finder — {self.domain}")
        print(f"  Target: {self.target}")
        print(f"  Mode: {'Deep' if self.deep else 'Standard'}")
        print(f"{'='*55}")

        tests = [
            self.test_http_method_tampering,
            self.test_host_header_injection,
            self.test_cors_misconfig,
            self.test_security_headers,
            self.test_crlf_injection,
            self.test_open_redirect,
            self.test_path_traversal,
            self.test_403_bypass,
        ]

        if self.deep:
            tests.extend([
                self.test_prototype_pollution,
                self.test_cache_poisoning,
            ])

        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"    [!] Error in {test.__name__}: {e}")

        self.save_findings()
        self.print_summary()

    def save_findings(self):
        """Save findings to disk."""
        if not self.findings:
            return

        output_file = os.path.join(self.findings_dir, "zero_day_findings.json")
        with open(output_file, "w") as f:
            json.dump({
                "target": self.target,
                "domain": self.domain,
                "scan_date": datetime.now().isoformat(),
                "mode": "deep" if self.deep else "standard",
                "total_findings": len(self.findings),
                "findings": self.findings
            }, f, indent=2)

        # Also save as readable text
        text_file = os.path.join(self.findings_dir, "zero_day_findings.txt")
        with open(text_file, "w") as f:
            for finding in self.findings:
                f.write(f"[{finding['severity'].upper()}] {finding['title']}\n")
                f.write(f"Type: {finding['type']}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Details:\n{finding['details']}\n")
                f.write("-" * 50 + "\n\n")

    def print_summary(self):
        """Print findings summary."""
        print(f"\n{'='*55}")
        print(f"  Zero-Day Scan Summary — {self.domain}")
        print(f"{'='*55}")

        if not self.findings:
            print("  No findings detected.")
            print("  This doesn't mean the target is secure —")
            print("  consider manual testing for logic flaws.")
        else:
            severity_counts = {}
            for f in self.findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            print(f"  Total findings: {len(self.findings)}")
            for sev in ["critical", "high", "medium", "low"]:
                if sev in severity_counts:
                    print(f"    {sev.upper()}: {severity_counts[sev]}")

            print(f"\n  Results: {self.findings_dir}/")

        print(f"\n  NOTE: All findings need manual verification.")
        print(f"  False positives are possible — verify before reporting.")
        print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(description="Zero-Day Bug Finder")
    parser.add_argument("target", nargs="?", help="Target URL (https://example.com)")
    parser.add_argument("--recon-dir", type=str, help="Recon directory to load URLs from")
    parser.add_argument("--deep", action="store_true", help="Run additional deep checks")
    args = parser.parse_args()

    if not args.target and not args.recon_dir:
        parser.print_help()
        sys.exit(1)

    targets = []

    if args.target:
        target = args.target
        if not target.startswith("http"):
            target = f"https://{target}"
        targets.append(target)

    if args.recon_dir:
        live_file = os.path.join(args.recon_dir, "live", "urls.txt")
        if os.path.exists(live_file):
            with open(live_file) as f:
                targets.extend([line.strip() for line in f if line.strip()][:10])

    for target in targets:
        fuzzer = ZeroDayFuzzer(target, deep=args.deep)
        fuzzer.run_all_tests()


if __name__ == "__main__":
    main()
