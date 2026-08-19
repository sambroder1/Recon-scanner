from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, HTTPSHandler, build_opener

from .models import PageSnapshot, ScanConfig


MAX_BODY_BYTES = 1_500_000


def canonicalize(url: str, base: str | None = None) -> str:
    from urllib.parse import urljoin

    value = urljoin(base or "", url.strip())
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return ""
    host = parts.hostname.lower()
    netloc = host
    if parts.port and not ((parts.scheme.lower() == "http" and parts.port == 80) or (parts.scheme.lower() == "https" and parts.port == 443)):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def host_allowed(url: str, allowed_hosts: set[str]) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return bool(host) and host in {item.lower().split(":", 1)[0] for item in allowed_hosts}


class AllowlistedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        target = canonicalize(newurl)
        if not target or not host_allowed(target, self.allowed_hosts):
            raise PermissionError(f"redirect blocked outside allowlist: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, target)


@dataclass
class FetchError:
    url: str
    message: str


class HttpClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.last_request = 0.0
        self.opener = build_opener(
            AllowlistedRedirectHandler(config.allowed_hosts),
            HTTPSHandler(context=self._ssl_context()),
        )

    def _ssl_context(self) -> ssl.SSLContext:
        if self.config.verify_tls:
            return ssl.create_default_context()
        context = ssl._create_unverified_context()
        context.check_hostname = False
        return context

    def fetch(self, url: str) -> tuple[PageSnapshot | None, FetchError | None]:
        target = canonicalize(url)
        if not target:
            return None, FetchError(url, "unsupported or malformed URL")
        if not host_allowed(target, self.config.allowed_hosts):
            return None, FetchError(target, "host is not in the explicit allowlist")
        wait = self.config.delay - (time.monotonic() - self.last_request)
        if wait > 0:
            time.sleep(wait)
        headers = {"User-Agent": self.config.user_agent, "Accept": "text/html,application/json,application/xml,text/plain;q=0.8,*/*;q=0.1"}
        headers.update(self.config.request_headers)
        request = Request(target, headers=headers, method="GET")
        started = time.monotonic()
        self.last_request = started
        try:
            with self.opener.open(request, timeout=self.config.timeout) as response:
                raw = response.read(MAX_BODY_BYTES + 1)
                body = raw[:MAX_BODY_BYTES].decode(response.headers.get_content_charset() or "utf-8", errors="replace")
                header_map = {key.lower(): value.strip() for key, value in response.headers.items()}
                cookies = response.headers.get_all("Set-Cookie") or []
                return PageSnapshot(
                    url=canonicalize(response.geturl()) or target,
                    status=int(response.status),
                    headers=header_map,
                    set_cookies=list(cookies),
                    body=body,
                    content_type=response.headers.get("Content-Type", ""),
                    elapsed_ms=round((time.monotonic() - started) * 1000),
                    redirect_url=target if canonicalize(response.geturl()) != target else None,
                ), None
        except HTTPError as exc:
            try:
                raw = exc.read(MAX_BODY_BYTES + 1)
                body = raw[:MAX_BODY_BYTES].decode(exc.headers.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                body = ""
            headers_map = {key.lower(): value.strip() for key, value in exc.headers.items()}
            return PageSnapshot(
                url=target,
                status=int(exc.code),
                headers=headers_map,
                set_cookies=list(exc.headers.get_all("Set-Cookie") or []),
                body=body,
                content_type=exc.headers.get("Content-Type", ""),
                elapsed_ms=round((time.monotonic() - started) * 1000),
            ), None
        except (URLError, TimeoutError, socket.timeout, PermissionError, ssl.SSLError, ValueError) as exc:
            return None, FetchError(target, str(exc))


def tls_observation(url: str, timeout: float, verify: bool) -> dict[str, str | int | bool]:
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        return {"checked": False}
    port = parts.port or 443
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    context.check_hostname = verify
    result: dict[str, str | int | bool] = {"checked": True, "host": parts.hostname, "port": port}
    try:
        with socket.create_connection((parts.hostname, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=parts.hostname) as tls_sock:
                result["protocol"] = tls_sock.version() or "unknown"
                result["cipher"] = tls_sock.cipher()[0] if tls_sock.cipher() else "unknown"
                certificate = tls_sock.getpeercert()
                if certificate and certificate.get("notAfter"):
                    expiry = ssl.cert_time_to_seconds(certificate["notAfter"])
                    remaining = int((expiry - datetime.now(timezone.utc).timestamp()) / 86400)
                    result["cert_days_remaining"] = remaining
                    result["cert_valid"] = remaining >= 0
                else:
                    result["cert_valid"] = False
        result["verified"] = verify
    except Exception as exc:  # TLS diagnostics should never abort the scan.
        result["error"] = str(exc)
    return result
