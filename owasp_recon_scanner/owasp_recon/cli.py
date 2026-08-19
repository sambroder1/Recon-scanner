from __future__ import annotations

import argparse
import sys
from urllib.parse import urlsplit

from .report import write_html, write_json
from .scanner import Scanner
from .models import ScanConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized, low-impact OWASP web reconnaissance scanner")
    parser.add_argument("--url", required=True, help="absolute http:// or https:// target URL")
    parser.add_argument("--allow-host", action="append", default=[], help="additional host allowed for links/redirects; repeatable")
    parser.add_argument("--max-pages", type=int, default=30)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--delay", type=float, default=0.20, help="minimum seconds between requests")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--safe-probes", action="store_true", help="enable fixed, non-destructive exposure probes")
    parser.add_argument("--ignore-robots", action="store_true", help="do not honor robots.txt while crawling")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate verification (lab use only)")
    parser.add_argument("--header", action="append", default=[], help="request header in 'Name: value' form; repeatable")
    parser.add_argument("--output", default="report.json", help="JSON report path")
    parser.add_argument("--html", help="optional HTML report path")
    return parser


def _headers(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if ":" not in value:
            raise ValueError(f"invalid --header {value!r}; expected 'Name: value'")
        name, header_value = value.split(":", 1)
        name = name.strip()
        if not name or name.lower() in {"host", "content-length"}:
            raise ValueError("Host and Content-Length cannot be supplied as custom headers")
        result[name] = header_value.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        parts = urlsplit(args.url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("--url must be an absolute http:// or https:// URL")
        if args.max_pages < 1 or args.max_depth < 0 or args.delay < 0 or args.timeout <= 0:
            raise ValueError("max-pages, max-depth, delay, and timeout must be non-negative/positive values")
        allowed_hosts = {parts.hostname.lower(), *(host.strip().lower() for host in args.allow_host if host.strip())}
        config = ScanConfig(
            target=args.url,
            allowed_hosts=allowed_hosts,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            delay=args.delay,
            timeout=args.timeout,
            safe_probes=args.safe_probes,
            respect_robots=not args.ignore_robots,
            verify_tls=not args.insecure,
            request_headers=_headers(args.header),
        )
        result = Scanner(config).run()
        write_json(result, args.output)
        if args.html:
            write_html(result, args.html)
        summary = result.summary()
        print(f"Target: {result.target}")
        print(f"Pages fetched: {summary['pages_fetched']} | URLs discovered: {summary['urls_discovered']}")
        print(f"Findings: {summary['findings']} | Manual checks: {summary['manual_checks']} | Errors: {summary['errors']}")
        print(f"JSON report: {args.output}")
        if args.html:
            print(f"HTML report: {args.html}")
        return 0
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
