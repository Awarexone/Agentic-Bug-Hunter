#!/usr/bin/env python3
"""Launch the local shuvonsec.me lookalike target.

For recordings:  `python3 serve.py`  is the command; nothing in the visible
output mentions "demo". The actual implementation lives in `demo/app.py`.

⚠️  Intentionally vulnerable. Run locally only.
"""

import os
import runpy

if __name__ == "__main__":
    # Recording-friendly default: suppress the toolkit banner so the terminal
    # looks like a plain web server start-up. Set SHUVONSEC_QUIET=0 to opt back in.
    os.environ.setdefault("SHUVONSEC_QUIET", "1")
    runpy.run_module("demo.app", run_name="__main__")
