#!/usr/bin/env python3
"""
HIBP k-anonymity password breach checker.

Reads a password wordlist, queries the HaveIBeenPwned /range/ API using
k-anonymity (only first 5 chars of SHA-1 are sent), enriches each password
with its breach count, then writes the ranked output.

Why rank by breach count:
  - HIGH count (>1M):  "Password123" — already in every generic spray list
  - SWEET SPOT (1-1k): proven-real passwords not yet over-used
  - ZERO count:        never seen — could be truly company-specific (or random)

Usage:
  tools/breach_checker.py <wordlist.txt>
  tools/breach_checker.py <wordlist.txt> -o ranked.txt --with-counts
  tools/breach_checker.py <wordlist.txt> --min-count 1 --max-count 1000000
  tools/breach_checker.py <wordlist.txt> --limit 5000   # test/preview
"""
from __future__ import annotations
import argparse
import hashlib
import random
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

API_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "claude-bug-bounty/breach_checker"


def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    """Return (first 5 chars, remaining 35 chars) of SHA-1, uppercase."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def query_range(prefix: str, retries: int = 3) -> dict[str, int]:
    """Query HIBP /range/{prefix}, return {suffix: count}.

    Uses Add-Padding header (HIBP-recommended privacy feature that pads the
    response with random fake entries so an observer can't infer real hits
    from response size).
    """
    req = urllib.request.Request(
        API_URL.format(prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8")
            return {
                suffix: int(count)
                for line in body.splitlines()
                if ":" in line
                for suffix, count in [line.strip().split(":", 1)]
                if int(count) > 0  # drop padded fake entries (count=0)
            }
        except urllib.error.HTTPError as e:
            if e.code == 429:  # rate limited
                time.sleep(2 ** attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)
    return {}


def check_batch(passwords: list[str], concurrent: int) -> dict[str, int]:
    """Check passwords against HIBP, return {password: count}.

    Groups by SHA-1 prefix to minimize API calls. Many passwords typically
    map to the same prefix (5-char hex = 1M buckets; for a 100k wordlist
    expect ~9% collision rate -> ~91k unique prefix queries).
    """
    prefix_groups: dict[str, list[tuple[str, str]]] = {}
    for pwd in passwords:
        prefix, suffix = sha1_prefix_suffix(pwd)
        prefix_groups.setdefault(prefix, []).append((pwd, suffix))

    results: dict[str, int] = {}
    completed = 0
    total = len(prefix_groups)
    start = time.time()

    with ThreadPoolExecutor(max_workers=concurrent) as executor:
        futures = {executor.submit(query_range, p): p for p in prefix_groups}
        for future in as_completed(futures):
            prefix = futures[future]
            completed += 1
            try:
                bucket = future.result()
                for pwd, suffix in prefix_groups[prefix]:
                    results[pwd] = bucket.get(suffix, 0)
            except Exception as e:
                # Mark unknowns as -1 so they can be filtered or reviewed
                print(
                    f"\r    [!] Prefix {prefix} failed ({type(e).__name__}): {e}",
                    file=sys.stderr,
                    flush=True,
                )
                for pwd, _ in prefix_groups[prefix]:
                    results[pwd] = -1

            if completed % 500 == 0 or completed == total:
                elapsed = time.time() - start
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total - completed) / rate if rate > 0 else 0
                print(
                    f"\r    [*] {completed:,}/{total:,} prefixes "
                    f"({rate:.0f}/s, ETA {eta:.0f}s)",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )

    print("", file=sys.stderr)
    return results


def main() -> int:
    p = argparse.ArgumentParser(
        description="HIBP k-anonymity breach checker for password wordlists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("wordlist", type=Path, help="Input wordlist (one password per line)")
    p.add_argument("-o", "--output", type=Path,
                   help="Output ranked file (default: <input>-ranked.txt)")
    p.add_argument("--min-count", type=int, default=0,
                   help="Keep passwords with breach count >= N (default: 0 = keep all)")
    p.add_argument("--max-count", type=int, default=None,
                   help="Keep passwords with breach count <= N (e.g. 1000000 drops generic)")
    p.add_argument("--concurrent", type=int, default=20,
                   help="Parallel HIBP requests (default: 20; HIBP allows ~25/sec)")
    p.add_argument("--limit", type=int, default=None,
                   help="Process only first N unique passwords (testing/preview)")
    p.add_argument("--shuffle", action="store_true",
                   help="Shuffle wordlist before --limit (avoids ASCII-sort bias on samples)")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed for --shuffle (default: non-deterministic)")
    p.add_argument("--with-counts", action="store_true",
                   help="Also write <output>-counts.tsv with breach counts")
    args = p.parse_args()

    if not args.wordlist.is_file():
        print(f"[-] Wordlist not found: {args.wordlist}", file=sys.stderr)
        return 1

    output = args.output or args.wordlist.with_name(args.wordlist.stem + "-ranked.txt")

    with args.wordlist.open() as f:
        passwords = list(dict.fromkeys(
            line.strip() for line in f if line.strip()
        ))

    if args.shuffle:
        rng = random.Random(args.seed)
        rng.shuffle(passwords)

    if args.limit:
        passwords = passwords[: args.limit]

    if not passwords:
        print("[-] Wordlist is empty", file=sys.stderr)
        return 1

    unique_prefixes = len({sha1_prefix_suffix(p)[0] for p in passwords})
    est_secs = unique_prefixes / 20  # rough estimate at 20 req/s

    print(f"[*] Wordlist: {args.wordlist}  ({len(passwords):,} unique passwords)")
    print(f"[*] Unique SHA-1 prefixes: {unique_prefixes:,}  "
          f"({len(passwords)/unique_prefixes:.1f}x grouping factor)")
    print(f"[*] Estimated time: {est_secs:.0f}s "
          f"({est_secs/60:.1f}m) at {args.concurrent} concurrent")
    print(f"[*] Querying HaveIBeenPwned (k-anonymity, no full passwords sent)...")

    start = time.time()
    results = check_batch(passwords, args.concurrent)
    elapsed = time.time() - start

    print(f"[+] Done in {elapsed:.1f}s")

    # Filter
    filtered = [(pwd, c) for pwd, c in results.items() if c >= args.min_count]
    if args.max_count is not None:
        filtered = [(pwd, c) for pwd, c in filtered if c <= args.max_count]

    # Sort: count DESC, then password ASC for stability
    filtered.sort(key=lambda x: (-x[1], x[0]))

    with output.open("w") as f:
        for pwd, _ in filtered:
            f.write(pwd + "\n")

    if args.with_counts:
        counts_out = output.with_name(output.stem + "-counts.tsv")
        with counts_out.open("w") as f:
            f.write("count\tpassword\n")
            for pwd, c in filtered:
                f.write(f"{c}\t{pwd}\n")

    # Stats
    in_breach = sum(1 for _, c in filtered if c > 0)
    sweet = sum(1 for _, c in filtered if 1 <= c <= 1000)
    generic = sum(1 for _, c in filtered if c > 1_000_000)
    unknown = sum(1 for _, c in filtered if c < 0)

    print()
    print("=" * 60)
    print("  Breach Check Summary")
    print("=" * 60)
    print(f"  Output:           {output}")
    if args.with_counts:
        print(f"  Counts TSV:       {output.with_name(output.stem + '-counts.tsv')}")
    print(f"  Total ranked:     {len(filtered):,}")
    if filtered:
        in_pct = 100 * in_breach / len(filtered)
        print(f"  In any breach:    {in_breach:,} ({in_pct:.1f}%)")
        print(f"  Sweet spot (1-1k):  {sweet:,}  "
              f"-- used by some humans, not in every spray list")
        print(f"  Generic (>1M):      {generic:,}  "
              f"-- skip these, already in every spray list")
        print(f"  Never seen (0):     {len(filtered)-in_breach-unknown:,}  "
              f"-- possibly company-specific")
        if unknown:
            print(f"  Unknown (API err):  {unknown:,}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
