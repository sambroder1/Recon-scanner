from __future__ import annotations

import re
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from .models import Finding, PageSnapshot


REF_TOP10 = "https://owasp.org/Top10/2025/"
REF_CHEAT = "https://cheatsheetseries.owasp.org/"


def finding(
    finding_id: str,
    title: str,
    severity: str,
    confidence: str,
    owasp: str,
    category: str,
    page: PageSnapshot | str,
    evidence: str,
    remediation: str,
    references: list[str] | None = None,
) -> Finding:
    url = page.url if isinstance(page, PageSnapshot) else page
    return Finding(finding_id, title, severity, confidence, owasp, category, url, evidence, remediation, references or [REF_TOP10])


def check_headers(page: PageSnapshot) -> list[Finding]:
    headers = page.headers
    findings: list[Finding] = []
    is_https = urlsplit(page.url).scheme == "https"
    if is_https and "strict-transport-security" not in headers:
        findings.append(finding("HDR-HSTS", "HSTS is not advertised", "medium", "high", "A04:2025", "Cryptographic Failures", page, "Strict-Transport-Security header is absent on an HTTPS response.", "Set HSTS with an appropriate max-age after confirming every subdomain is HTTPS-only.", [f"{REF_CHEAT}cheatsheets/HTTP_Headers_Cheat_Sheet.html"]))
    if page.is_html and "content-security-policy" not in headers:
        findings.append(finding("HDR-CSP", "Content Security Policy is absent", "low", "high", "A02:2025", "Security Misconfiguration", page, "No Content-Security-Policy header was observed.", "Deploy a restrictive CSP and tune it from report-only mode before enforcement.", [f"{REF_CHEAT}cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]))
    if "x-content-type-options" not in headers:
        findings.append(finding("HDR-NOSNIFF", "MIME sniffing protection is absent", "low", "high", "A02:2025", "Security Misconfiguration", page, "X-Content-Type-Options is absent.", "Send X-Content-Type-Options: nosniff for browser-served resources."))
    if page.is_html and "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append(finding("HDR-FRAME", "Clickjacking protection is absent", "low", "high", "A01:2025", "Broken Access Control", page, "Neither X-Frame-Options nor CSP frame-ancestors was observed.", "Use CSP frame-ancestors and/or X-Frame-Options according to browser compatibility needs."))
    if page.is_html and "referrer-policy" not in headers:
        findings.append(finding("HDR-REFERRER", "Referrer-Policy is absent", "low", "high", "A02:2025", "Security Misconfiguration", page, "No Referrer-Policy header was observed.", "Set a deliberate policy such as strict-origin-when-cross-origin."))
    if page.is_html and "permissions-policy" not in headers:
        findings.append(finding("HDR-PERMISSIONS", "Permissions-Policy is absent", "info", "high", "A02:2025", "Security Misconfiguration", page, "No Permissions-Policy header was observed.", "Disable browser capabilities that the application does not require."))
    if headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(finding("HDR-CORS", "Wildcard CORS is combined with credentials", "high", "high", "A01:2025", "Broken Access Control", page, "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true were observed together.", "Allow only known origins and avoid credentialed wildcard access."))
    if "server" in headers or "x-powered-by" in headers:
        values = "; ".join(part for part in [headers.get("server"), headers.get("x-powered-by")] if part)
        findings.append(finding("HDR-DISCLOSURE", "Server implementation details are disclosed", "info", "high", "A02:2025", "Security Misconfiguration", page, f"Observed response metadata: {values[:160]}", "Minimize unnecessary product and version disclosure in response headers."))
    if any(word in page.url.lower() for word in ("login", "signin", "account", "profile", "admin", "session")) and "cache-control" not in headers:
        findings.append(finding("HDR-CACHE", "Sensitive-looking endpoint lacks explicit cache controls", "medium", "medium", "A04:2025", "Cryptographic Failures", page, "URL suggests a sensitive endpoint but Cache-Control is absent.", "Set appropriate private/no-store directives for authenticated or sensitive responses."))
    findings.extend(check_cookies(page))
    return findings


def check_cookies(page: PageSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for raw in page.set_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            attrs = {key.lower(): str(morsel[key] or "") for key in morsel.keys()}
            if urlsplit(page.url).scheme == "https" and not attrs.get("secure"):
                findings.append(finding("COOKIE-SECURE", f"Cookie {name} lacks Secure", "medium", "high", "A07:2025", "Authentication Failures", page, f"Set-Cookie for {name} did not include Secure.", "Set Secure on cookies that must never traverse cleartext HTTP."))
            if not attrs.get("httponly"):
                findings.append(finding("COOKIE-HTTPONLY", f"Cookie {name} lacks HttpOnly", "low", "high", "A07:2025", "Authentication Failures", page, f"Set-Cookie for {name} did not include HttpOnly.", "Set HttpOnly on session and other server-managed cookies."))
            if not attrs.get("samesite"):
                findings.append(finding("COOKIE-SAMESITE", f"Cookie {name} lacks SameSite", "low", "high", "A07:2025", "Authentication Failures", page, f"Set-Cookie for {name} did not include SameSite.", "Set an explicit SameSite value appropriate to the application flow."))
    return findings


def check_html(page: PageSnapshot) -> tuple[list[Finding], list[dict[str, str]]]:
    if not page.is_html:
        return [], []
    body = page.body
    findings: list[Finding] = []
    manual: list[dict[str, str]] = []
    if urlsplit(page.url).scheme == "https" and re.search(r"(?:src|href)\s*=\s*[\"']http://", body, re.IGNORECASE):
        findings.append(finding("HTML-MIXED", "HTTPS page references cleartext HTTP resources", "medium", "high", "A04:2025", "Cryptographic Failures", page, "An http:// resource reference was found in an HTTPS page.", "Serve all active and passive resources over HTTPS and review third-party dependencies."))
    error_patterns = (r"traceback \(most recent call last\)", r"sql syntax.*error", r"stack trace", r"exception in thread", r"fatal error", r"unhandled exception")
    for pattern in error_patterns:
        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
            findings.append(finding("HTML-ERROR", "Detailed error information may be exposed", "medium", "medium", "A10:2025", "Mishandling of Exceptional Conditions", page, f"Response matched an error-leakage signature: {pattern}", "Return generic client errors, log details server-side, and ensure production debug mode is disabled."))
            break
    if re.search(r"<title>\s*index of\s+", body, re.IGNORECASE):
        findings.append(finding("HTML-INDEX", "Directory listing appears enabled", "medium", "high", "A02:2025", "Security Misconfiguration", page, "The response title resembles an Apache/Nginx directory index.", "Disable directory listings and ensure sensitive files are outside the web root."))
    if re.search(r"(?:src|href)\s*=\s*[\"'][^\"']+\.map(?:[\"'?#])", body, re.IGNORECASE):
        findings.append(finding("HTML-SOURCEMAP", "JavaScript source map is publicly referenced", "low", "high", "A08:2025", "Software or Data Integrity Failures", page, "A .map resource was referenced by the HTML.", "Avoid publishing source maps in production unless their disclosure is intentional."))
    if re.search(r"<input[^>]+type\s*=\s*[\"']password", body, re.IGNORECASE) and urlsplit(page.url).scheme != "https":
        findings.append(finding("FORM-CLEAR", "Password input is served over HTTP", "high", "high", "A07:2025", "Authentication Failures", page, "A password input was found on a non-HTTPS page.", "Serve authentication pages and submissions exclusively over HTTPS."))
    for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form\s*>", body, re.IGNORECASE | re.DOTALL):
        attrs, inner = form_match.groups()
        method = re.search(r"method\s*=\s*[\"']?([a-z]+)", attrs, re.IGNORECASE)
        if method and method.group(1).lower() in {"post", "put", "patch", "delete"} and not re.search(r"(?:csrf|xsrf|nonce|token)", inner, re.IGNORECASE):
            manual.append({"owasp": "A01:2025", "title": "Review state-changing form for CSRF protection", "url": page.url, "reason": "A non-GET form had no obvious CSRF token field; this is only a heuristic."})
    return findings, manual


def check_scripts(page: PageSnapshot, scripts: list[dict[str, object]]) -> list[Finding]:
    findings: list[Finding] = []
    for script in scripts:
        if script.get("third_party") and script.get("src") and not script.get("integrity"):
            findings.append(finding("SCRIPT-SRI", "Third-party script lacks Subresource Integrity", "low", "high", "A08:2025", "Software or Data Integrity Failures", page, f"External script without integrity: {str(script['src'])[:180]}", "Pin and integrity-protect third-party scripts, or serve vetted assets from your own origin."))
    return findings


def check_safe_probe(page: PageSnapshot, requested_path: str) -> list[Finding]:
    findings: list[Finding] = []
    body_lower = page.body.lower()
    if page.status != 200:
        return findings
    if requested_path == "/.git/HEAD" and body_lower.startswith("ref: refs/"):
        findings.append(finding("PROBE-GIT", "Git metadata appears publicly readable", "high", "high", "A02:2025", "Security Misconfiguration", page, "/.git/HEAD returned a Git reference.", "Remove repository metadata from the web root and rotate any exposed secrets."))
    elif requested_path == "/.env" and re.search(r"(?:app_key|api_key|secret|password|database_url)\s*=", body_lower):
        findings.append(finding("PROBE-ENV", "Environment configuration appears publicly readable", "high", "high", "A02:2025", "Security Misconfiguration", page, "/.env returned configuration-like key/value content.", "Remove environment files from the web root and rotate any exposed credentials."))
    elif requested_path in {"/server-status", "/server-info", "/phpinfo.php"}:
        findings.append(finding("PROBE-DEBUG", "Administrative or diagnostic page is publicly reachable", "high", "medium", "A02:2025", "Security Misconfiguration", page, f"{requested_path} returned HTTP 200.", "Restrict diagnostics to an administrative network or disable them in production."))
    elif requested_path in {"/swagger.json", "/openapi.json", "/api-docs", "/api"} and ("openapi" in body_lower or "swagger" in body_lower or page.content_type.lower().startswith("application/json")):
        findings.append(finding("PROBE-API-DOC", "API description is publicly reachable", "info", "high", "A02:2025", "Security Misconfiguration", page, f"{requested_path} returned an API-like document.", "Confirm that documentation exposure is intentional and that every documented operation enforces authorization."))
    elif requested_path.endswith((".bak", ".zip", ".sql")):
        findings.append(finding("PROBE-BACKUP", "Possible backup artifact is publicly reachable", "high", "medium", "A02:2025", "Security Misconfiguration", page, f"{requested_path} returned HTTP 200.", "Remove backup artifacts from the web root and use deployment-time secret scanning."))
    elif "<title>index of" in body_lower:
        findings.append(finding("PROBE-INDEX", "Directory listing is publicly reachable", "medium", "high", "A02:2025", "Security Misconfiguration", page, f"{requested_path} returned a directory index.", "Disable directory indexing and review the exposed files."))
    return findings
