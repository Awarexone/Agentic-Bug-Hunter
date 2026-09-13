#!/usr/bin/env python3
"""Mechanically convert the verbatim Netflix Privacy Statement markdown capture
into a pdf_create.py JSON spec. No hand-transcription — every string in the
output PDF is derived programmatically from the raw fetched file so there is
no hallucination surface between source and document.
"""
import json
import re
import sys

SRC = "sources/privacy_statement_raw.md"
OUT = "output/privacy_statement_spec.json"

# Content body runs from line 11 ("# Privacy Statement") through line 528
# ("**Last Updated:** April 10, 2026"). Lines 1-10 are nav chrome, lines
# 530-536 are footer language-picker chrome. Verified by manual inspection
# of the read_file output for this exact cached file.
START_LINE = 11
END_LINE = 528


def escape_xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def clean_links(s: str) -> str:
    def repl(m):
        text, url = m.group(1), m.group(2)
        if url.startswith("mailto:"):
            return text
        bare = url.replace("https://", "").replace("http://", "")
        if text.strip().lower() in bare.lower() or bare.lower() in text.strip().lower():
            return text
        return f"{text} ({bare})"
    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", repl, s)


def bold(s: str) -> str:
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)


def clean_line(raw: str) -> str:
    s = escape_xml(raw)
    s = clean_links(s)
    s = bold(s)
    return s.strip()


def main() -> int:
    with open(SRC, encoding="utf-8") as fh:
        lines = fh.readlines()

    # lines is 0-indexed; our line numbers above are 1-indexed from read_file
    body = lines[START_LINE - 1:END_LINE]

    elements = [
        {"type": "heading", "text": "Netflix Privacy Statement", "level": 1},
        {"type": "paragraph", "text": "<b>Official Reproduction — Verbatim Capture</b>"},
        {"type": "paragraph", "text": (
            "This document is a verbatim, mechanically-extracted reproduction of the live "
            "Netflix Privacy Statement published at "
            "<b>https://help.netflix.com/en/legal/privacy</b>. It was captured "
            "2026-09-13 and reflects the version Netflix itself dates as:"
        )},
        {"type": "paragraph", "text": "<b>Last Updated (per Netflix): April 10, 2026</b>"},
        {"type": "paragraph", "text": (
            "This reproduction is provided for reference and offline reading convenience only. "
            "It is NOT a legally binding substitute for the live document, which Netflix may "
            "update at any time. Always confirm the current text at the source URL above before "
            "relying on it for legal purposes. No text has been added, summarized, or altered "
            "from the source beyond stripping page-navigation chrome (menus, sign-in links, "
            "language picker) and reflowing markdown link syntax to plain prose."
        )},
        {"type": "pagebreak"},
    ]

    para_buffer = []

    def flush():
        if para_buffer:
            text = " ".join(para_buffer)
            elements.append({"type": "paragraph", "text": text})
            para_buffer.clear()

    for raw in body:
        stripped = raw.rstrip("\n")
        if not stripped.strip():
            flush()
            continue

        if stripped.startswith("## "):
            flush()
            elements.append({"type": "heading", "text": clean_line(stripped[3:]), "level": 1})
            continue
        if stripped.startswith("### "):
            flush()
            elements.append({"type": "heading", "text": clean_line(stripped[4:]), "level": 2})
            continue
        if stripped.startswith("# "):
            flush()
            continue  # top-level title already emitted on cover

        # sub-bullet (two-space indent then "- ")
        m_sub = re.match(r"^\s{2,}-\s+(.*)$", stripped)
        if m_sub:
            flush()
            elements.append({"type": "paragraph", "text": "&nbsp;&nbsp;&nbsp;&nbsp;\u25E6 " + clean_line(m_sub.group(1))})
            continue

        m_bullet = re.match(r"^-\s+(.*)$", stripped)
        if m_bullet:
            flush()
            elements.append({"type": "paragraph", "text": "\u2022 " + clean_line(m_bullet.group(1))})
            continue

        # plain continuation / paragraph line
        para_buffer.append(clean_line(stripped))

    flush()

    spec = {
        "title": "Netflix Privacy Statement (2026) — Verbatim Reproduction",
        "author": "Compiled from help.netflix.com/en/legal/privacy (source-verified)",
        "page_size": "letter",
        "page_numbers": True,
        "elements": elements,
    }

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2, ensure_ascii=False)

    print(json.dumps({"elements": len(elements), "out": OUT}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
