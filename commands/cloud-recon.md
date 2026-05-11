---
description: Sweep cloud assets for a target — public S3/Azure/GCP buckets via S3Scanner and cloud_enum, plus CloudFlare-bypassed origin IPs via CloudFail (or built-in DNS-history fallback). Use --keyword for storage discovery and --cf-bypass to find an origin IP behind CloudFlare. Usage: /cloud-recon --keyword <name> | /cloud-recon --cf-bypass <domain>
---

# /cloud-recon

Find cloud-storage misconfigurations and origin IPs that bypass CloudFlare.

## Usage

```
/cloud-recon --keyword acme
/cloud-recon --keyword acme --s3-only
/cloud-recon --cf-bypass api.target.com
```

## What it runs

| Tool | Mode | What it finds |
|---|---|---|
| `s3scanner` | `--keyword` | Public/listable S3 buckets across AWS, DigitalOcean Spaces, Wasabi, Linode |
| `cloud_enum` | `--keyword` | AWS S3, Azure blobs/files/queues, GCP storage with permutation patterns |
| `cloudfail` | `--cf-bypass` | DNS-history-based CloudFlare origin IP discovery |

When `cloudfail` is missing the script falls back to crt.sh + dig and flags any
subdomain that resolves to an IP **outside** CloudFlare's published ranges —
typical origin-IP leak symptom.

## Why this matters

- A world-readable S3 bucket holding PII or backups is usually rated **High to
  Critical** ($1k–$10k+).
- An exposed CloudFlare origin IP lets you bypass WAF rules; combined with a
  Host-header trick or a vulnerability that the WAF was masking, payouts climb
  fast.
- Both classes are easy to triage and nearly always in-scope.

## Output

`findings/cloud/<timestamp>/` with:
- `s3scanner.txt` — buckets that exist + their permission bits
- `cloud_enum.txt` — multi-cloud OSINT hits
- `cloudfail.txt` or `non_cf_ips.txt` — origin-IP candidates
