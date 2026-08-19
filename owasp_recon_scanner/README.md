python -m owasp_recon --url https://your-authorized-target.example --safe-probes --output report.json --html report.html# OWASP Recon Scanner

An intentionally conservative, standard-library-only web reconnaissance scanner for systems you own or are explicitly authorized to assess. It performs safe discovery and evidence-based configuration checks; it does **not** exploit vulnerabilities, brute-force credentials, submit forms, or attempt destructive payloads.

The current OWASP Top 10 is the 2025 edition. A scanner cannot prove several categories (for example business-logic authorization, insecure design, logging quality, or supply-chain risk) from an unauthenticated HTTP crawl, so this tool reports coverage gaps as manual-review items rather than pretending to test them.

## Quick start

```text
python -m owasp_recon --url https://app.example.test --safe-probes --max-pages 50 \
  --output report.json --html report.html
```

`--safe-probes` is opt-in. It checks a small, fixed set of non-destructive paths such as `robots.txt`, `security.txt`, common API descriptions, and a few accidentally published-file indicators. The scanner stays on the target host unless additional hosts are explicitly supplied with `--allow-host`.

Useful options:

```text
--url URL                 Starting URL (required)
--allow-host HOST         Additional redirect/link host to permit (repeatable)
--max-pages N             Same-origin pages to crawl (default: 30)
--max-depth N             Link depth (default: 2)
--delay SECONDS           Minimum delay between requests (default: 0.20)
--timeout SECONDS         Per-request timeout (default: 10)
--safe-probes             Enable fixed, low-impact endpoint probes
--ignore-robots           Do not honor robots.txt while crawling
--insecure                Allow invalid TLS certificates (lab use only)
--header 'Name: value'    Add a request header (repeatable; use only with authorization)
--output PATH             JSON report path (default: report.json)
--html PATH               Optional human-readable HTML report
```

Example against a local lab:

```text
python -m owasp_recon --url http://127.0.0.1:8000 --safe-probes \
  --output report.json --html report.html
```

## What is checked

- Discovery: same-origin links, forms, scripts, robots.txt, sitemap.xml, security.txt, and OpenAPI/Swagger descriptions.
- HTTP controls: HTTPS/HSTS, CSP, frame protection, MIME sniffing, referrer and permissions policy, cache controls, CORS, server disclosure, cookie flags, mixed content, and third-party script integrity.
- Exposure indicators: directory listings, debug/error leakage, source maps, and opt-in checks for common accidentally published files.
- TLS: certificate expiry, negotiated protocol, and certificate validation status.
- OWASP 2025 mapping: findings are tagged A01–A10. Items needing authentication, source review, business context, or controlled payloads are listed as manual verification tasks.

## Safety boundary

Use this only against assets for which you have written permission. The tool makes GET requests only, does not follow cross-host redirects unless allowlisted, never submits discovered forms, and enforces request limits and delays. It is a reconnaissance and control-checking aid, not a substitute for an authorized penetration test or a complete ASVS/API assessment.
