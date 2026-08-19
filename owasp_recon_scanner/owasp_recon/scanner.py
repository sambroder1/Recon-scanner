from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from .checks import check_headers, check_html, check_safe_probe, check_scripts
from .discovery import extract_sitemap_urls, parse_document, parse_robots, path_is_disallowed
from .http import HttpClient, canonicalize, host_allowed, tls_observation
from .models import Finding, PageSnapshot, ScanConfig, ScanResult


SAFE_PROBE_PATHS = (
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api",
    "/actuator/health",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/config.php.bak",
    "/backup.zip",
    "/dump.sql",
)


class Scanner:
    def __init__(self, config: ScanConfig):
        target = canonicalize(config.target)
        if not target:
            raise ValueError("target must be an absolute http:// or https:// URL")
        target_host = (urlsplit(target).hostname or "").lower()
        if target_host not in {host.lower().split(":", 1)[0] for host in config.allowed_hosts}:
            raise ValueError("target host must be present in the explicit allowlist")
        config.target = target
        self.config = config
        self.client = HttpClient(config)
        now = datetime.now(timezone.utc).isoformat()
        self.result = ScanResult(target=target, started_at=now, finished_at=now)
        self._finding_keys: set[tuple[str, str]] = set()
        self._visited: set[str] = set()

    def run(self) -> ScanResult:
        root = self.config.target
        origin = self._origin(root)
        robots_disallowed: list[str] = []
        if self.config.respect_robots:
            robots_url = canonicalize("/robots.txt", origin)
            if robots_url:
                robots_page = self._fetch(robots_url, process=False)
                if robots_page:
                    sitemap_urls, robots_disallowed = parse_robots(robots_page.body, origin)
                    for sitemap_url in sitemap_urls:
                        sitemap_page = self._fetch(sitemap_url, process=False)
                        if sitemap_page:
                            for url in extract_sitemap_urls(sitemap_page.body, sitemap_url, self.config.allowed_hosts):
                                self.result.discovered_urls.append(url)

        queue: deque[tuple[str, int]] = deque([(root, 0)])
        queued = {root}
        crawl_count = 0
        while queue and crawl_count < self.config.max_pages:
            url, depth = queue.popleft()
            if url in self._visited:
                continue
            if self.config.respect_robots and url != root and path_is_disallowed(url, origin, robots_disallowed):
                continue
            page = self._fetch(url)
            if not page:
                continue
            crawl_count += 1
            if depth >= self.config.max_depth or not page.is_html:
                continue
            links, forms, scripts = parse_document(page.body, page.url, self.config.allowed_hosts)
            self.result.forms.extend({**form, "page": page.url} for form in forms)
            self.result.scripts.extend({**script, "page": page.url} for script in scripts)
            self._add_findings(check_scripts(page, scripts))
            if "openapi" in page.body.lower() or "swagger" in page.body.lower():
                if any(token in page.content_type.lower() for token in ("json", "yaml", "text/plain")) or "openapi" in page.url.lower() or "swagger" in page.url.lower():
                    self.result.api_descriptions.append(page.url)
            self.result.discovered_urls.extend(links)
            for link in links:
                if link not in queued and link not in self._visited and len(queued) < self.config.max_pages * 4:
                    queue.append((link, depth + 1))
                    queued.add(link)
        if self.config.safe_probes:
            for path in SAFE_PROBE_PATHS:
                if len(self.result.pages) >= self.config.max_pages + len(SAFE_PROBE_PATHS):
                    break
                url = canonicalize(path, origin)
                page = self._fetch(url, process=False)
                if page:
                    self._add_findings(check_safe_probe(page, path))
                    if path in {"/swagger.json", "/openapi.json", "/api-docs", "/api"} and ("openapi" in page.body.lower() or "swagger" in page.body.lower()):
                        self.result.api_descriptions.append(page.url)
        self._tls_checks()
        self._add_manual_checks()
        self.result.discovered_urls = sorted(set(self.result.discovered_urls))
        self.result.finished_at = datetime.now(timezone.utc).isoformat()
        return self.result

    def _fetch(self, url: str, process: bool = True) -> PageSnapshot | None:
        target = canonicalize(url)
        if not target or target in self._visited:
            return None
        self._visited.add(target)
        page, error = self.client.fetch(target)
        if error:
            self.result.errors.append(f"{error.url}: {error.message}")
            return None
        assert page is not None
        self.result.pages.append(page)
        if process:
            self._add_findings(check_headers(page))
            html_findings, manual = check_html(page)
            self._add_findings(html_findings)
            self.result.manual_checks.extend(manual)
        return page

    def _add_findings(self, findings: list[Finding]) -> None:
        for item in findings:
            key = (item.finding_id, item.url)
            if key not in self._finding_keys:
                self._finding_keys.add(key)
                self.result.findings.append(item)

    def _tls_checks(self) -> None:
        observation = tls_observation(self.config.target, self.config.timeout, self.config.verify_tls)
        if not observation.get("checked"):
            return
        if observation.get("error"):
            self.result.errors.append(f"TLS: {observation['error']}")
            return
        days = observation.get("cert_days_remaining")
        if isinstance(days, int) and days < 0:
            self._add_findings([Finding("TLS-EXPIRED", "TLS certificate is expired", "high", "high", "A04:2025", "Cryptographic Failures", self.config.target, f"Certificate expired {abs(days)} days ago.", "Renew the certificate and monitor expiry automatically.", ["https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"])])
        elif isinstance(days, int) and days <= 30:
            self._add_findings([Finding("TLS-EXPIRY", "TLS certificate expires soon", "medium", "high", "A04:2025", "Cryptographic Failures", self.config.target, f"Certificate has approximately {days} days remaining.", "Renew before expiry and add automated certificate monitoring.", ["https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"])])
        protocol = str(observation.get("protocol", ""))
        if protocol in {"TLSv1", "TLSv1.1"}:
            self._add_findings([Finding("TLS-LEGACY", "Legacy TLS protocol was negotiated", "high", "high", "A04:2025", "Cryptographic Failures", self.config.target, f"Negotiated protocol: {protocol}.", "Disable TLS 1.0/1.1 and require a currently supported protocol.", ["https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"])])

    def _add_manual_checks(self) -> None:
        checks = [
            ("A01:2025", "Verify authorization server-side", "Test horizontal and vertical access-control matrices with two authorized accounts; this scanner does not alter identifiers or bypass controls."),
            ("A03:2025", "Review software supply-chain controls", "Inspect SBOMs, dependency pinning, provenance, CI/CD permissions, and dependency update policy."),
            ("A05:2025", "Review injection defenses", "Use code review and an approved staging test plan to verify parameterized queries, safe interpreters, and output encoding; no injection payloads are sent by this tool."),
            ("A06:2025", "Review threat model and business logic", "Confirm abuse cases, rate limits, workflow authorization, and fail-closed behavior with product and engineering owners."),
            ("A07:2025", "Review authentication lifecycle", "Verify MFA, password policy, session rotation, logout invalidation, account recovery, and rate limiting."),
            ("A08:2025", "Review integrity and deployment controls", "Verify signed artifacts, protected build pipelines, trusted update paths, and secret scanning."),
            ("A09:2025", "Review security logging and alerting", "Confirm security events are recorded, protected from tampering, monitored, and linked to actionable alerts."),
            ("A10:2025", "Review exceptional-condition handling", "Test error paths in an authorized staging environment for generic responses, safe transactions, and no sensitive leakage."),
        ]
        self.result.manual_checks.extend({"owasp": owasp, "title": title, "reason": reason} for owasp, title, reason in checks)

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        netloc = parts.netloc
        return urlunsplit((parts.scheme, netloc, "/", "", ""))
