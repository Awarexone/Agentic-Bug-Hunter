#!/bin/bash
# Populate AWS / Stripe / Cloudflare CIDR exclusions in a target scope.yaml.

set -uo pipefail

usage() {
  echo "Usage: $0 <scope.yaml>" >&2
}

SCOPE_FILE="${1:-}"
[ -n "$SCOPE_FILE" ] || { usage; exit 1; }
[ -f "$SCOPE_FILE" ] || { echo "Missing scope.yaml: $SCOPE_FILE" >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL https://ip-ranges.amazonaws.com/ip-ranges.json -o "$TMP_DIR/aws.json"
curl -fsSL https://stripe.com/files/ips/ips_api.json -o "$TMP_DIR/stripe.json"
curl -fsSL https://www.cloudflare.com/ips-v4 -o "$TMP_DIR/cloudflare-v4.txt"
curl -fsSL https://www.cloudflare.com/ips-v6 -o "$TMP_DIR/cloudflare-v6.txt"

python3 - "$SCOPE_FILE" "$TMP_DIR" <<'PY'
import json
import sys
from pathlib import Path

import yaml

scope_path = Path(sys.argv[1])
tmp = Path(sys.argv[2])
data = yaml.safe_load(scope_path.read_text(encoding="utf-8")) or {}

aws = sorted({p["ip_prefix"] for p in json.loads((tmp / "aws.json").read_text())["prefixes"]})
aws += sorted({p["ipv6_prefix"] for p in json.loads((tmp / "aws.json").read_text())["ipv6_prefixes"]})
stripe_data = json.loads((tmp / "stripe.json").read_text())
stripe = sorted(set(stripe_data.get("WEBHOOKS", []) + stripe_data.get("API", [])))
cloudflare = []
for name in ("cloudflare-v4.txt", "cloudflare-v6.txt"):
    cloudflare.extend(
        line.strip()
        for line in (tmp / name).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    )

data["third_party_exclusions"] = [
    {"name": "stripe", "cidr": stripe},
    {"name": "aws", "cidr": aws},
    {"name": "cloudflare", "cidr": sorted(set(cloudflare))},
]
scope_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
print(f"updated {scope_path} with stripe/aws/cloudflare third-party CIDRs")
PY
