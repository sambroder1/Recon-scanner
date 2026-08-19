from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanResult


def write_json(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.as_dict(), indent=2, sort_keys=True), encoding="utf-8")


def write_html(result: ScanResult, path: str | Path) -> None:
    summary = result.summary()
    rows = []
    for item in sorted(result.findings, key=lambda f: (f.severity, f.owasp, f.finding_id)):
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.severity.upper())}</td>"
            f"<td>{html.escape(item.owasp)}</td>"
            f"<td>{html.escape(item.title)}</td>"
            f"<td>{html.escape(item.url)}</td>"
            f"<td>{html.escape(item.evidence)}</td>"
            f"<td>{html.escape(item.remediation)}</td>"
            "</tr>"
        )
    manual = "".join(
        f"<li><strong>{html.escape(item.get('owasp', ''))}</strong> — {html.escape(item.get('title', ''))}: {html.escape(item.get('reason', ''))}</li>"
        for item in result.manual_checks
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>OWASP Recon Report</title>
<style>body{{font:14px system-ui,sans-serif;max-width:1400px;margin:2rem auto;padding:0 1rem;color:#202124}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.5rem;vertical-align:top;text-align:left}}th{{background:#f4f5f7}}code{{white-space:pre-wrap}}.high,.critical{{background:#ffe5e5}}.medium{{background:#fff4d6}}.low{{background:#eef5ff}}.info{{background:#f5f5f5}}</style></head>
<body><h1>OWASP Recon Report</h1><p><strong>Target:</strong> {html.escape(result.target)}</p>
<p><strong>Pages fetched:</strong> {summary['pages_fetched']} &nbsp; <strong>URLs discovered:</strong> {summary['urls_discovered']} &nbsp; <strong>Findings:</strong> {summary['findings']}</p>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>OWASP</th><th>Title</th><th>URL</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="6">No automated findings.</td></tr>'}</tbody></table>
<h2>Manual verification</h2><ul>{manual or '<li>None recorded.</li>'}</ul>
<h2>Errors</h2><ul>{''.join(f'<li>{html.escape(error)}</li>' for error in result.errors) or '<li>None.</li>'}</ul>
</body></html>"""
    Path(path).write_text(document, encoding="utf-8")
