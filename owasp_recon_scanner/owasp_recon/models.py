from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    owasp: str
    category: str
    url: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PageSnapshot:
    url: str
    status: int
    headers: dict[str, str]
    set_cookies: list[str]
    body: str
    content_type: str
    elapsed_ms: int
    redirect_url: str | None = None

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type.lower() or "application/xhtml" in self.content_type.lower()

    def as_dict(self) -> dict[str, Any]:
        # Reports deliberately omit response bodies and cookie values because a scan can
        # encounter secrets. Findings retain short, contextual evidence instead.
        cookie_names: list[str] = []
        for raw in self.set_cookies:
            cookie_names.append(raw.split("=", 1)[0].strip()[:80])
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "set_cookie_names": cookie_names,
            "body_length": len(self.body),
            "content_type": self.content_type,
            "elapsed_ms": self.elapsed_ms,
            "redirect_url": self.redirect_url,
        }


@dataclass
class ScanConfig:
    target: str
    allowed_hosts: set[str]
    max_pages: int = 30
    max_depth: int = 2
    delay: float = 0.20
    timeout: float = 10.0
    safe_probes: bool = False
    respect_robots: bool = True
    verify_tls: bool = True
    user_agent: str = "owasp-recon-scanner/0.1 (+authorized-security-assessment)"
    request_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    pages: list[PageSnapshot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    api_descriptions: list[str] = field(default_factory=list)
    manual_checks: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "pages": [page.as_dict() for page in self.pages],
            "findings": [finding.as_dict() for finding in self.findings],
            "discovered_urls": self.discovered_urls,
            "forms": self.forms,
            "scripts": self.scripts,
            "api_descriptions": self.api_descriptions,
            "manual_checks": self.manual_checks,
            "errors": self.errors,
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "pages_fetched": len(self.pages),
            "urls_discovered": len(self.discovered_urls),
            "findings": len(self.findings),
            "severity_counts": counts,
            "manual_checks": len(self.manual_checks),
            "errors": len(self.errors),
        }
