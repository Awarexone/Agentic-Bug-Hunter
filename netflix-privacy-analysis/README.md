# Netflix Privacy Analysis (2026)

Methodical analysis of Netflix's public Privacy Statement and "How to stop
certain uses of your personal information" Help Center article
(`help.netflix.com/en/node/100637`), producing two deliverables:

## Output

- **`output/Netflix_PrivacyHardening_OptOut_Guide.pdf`** — simplified,
  priority-ordered checklist for opting out of behavioral advertising,
  matched-identifier marketing, and restricting personal-data exposure,
  framed around data-minimization / least-exposure / account-hardening
  security principles. Every claim is inline-cited to a numbered source.
- **`output/Netflix_Privacy_Statement_2026_Verbatim.pdf`** — mechanically
  extracted, verbatim reproduction of the live Privacy Statement
  (Last Updated per Netflix: April 10, 2026), for offline reference.

## Verification

All factual claims were captured verbatim from Netflix's own Help Center
(`sources/*.md`, raw retrieval captures) and independently cross-checked by
a second research pass, including Wayback Machine snapshot corroboration
confirming the "Last Updated" date genuinely changed between March and May
2026 (from "April 17, 2025" to "April 10, 2026") rather than being stale or
fabricated.

## Rebuilding

```bash
cd netflix-privacy-analysis
python3 build_guide_spec.py && python3 build_privacy_spec.py
# then render both specs with the `pdf` skill's pdf_create.py
```

## Sources

- https://help.netflix.com/en/legal/privacy
- https://help.netflix.com/en/node/100637
- https://help.netflix.com/en/node/100624
- https://help.netflix.com/en/node/100625
- https://help.netflix.com/en/node/100627
- https://help.netflix.com/en/node/100628
- https://help.netflix.com/en/node/100639
- https://help.netflix.com/en/node/124925
- https://help.netflix.com/en/node/22205

This is independent reference material, not a Netflix-published document,
and not legal advice.
