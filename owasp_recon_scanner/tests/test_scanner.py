import json
import tempfile
import unittest
from pathlib import Path

from owasp_recon.checks import check_headers, check_html, check_safe_probe
from owasp_recon.discovery import parse_document, parse_robots
from owasp_recon.http import canonicalize, host_allowed
from owasp_recon.models import PageSnapshot
from owasp_recon.report import write_json


class ScannerUnitTests(unittest.TestCase):
    def test_canonicalize_removes_fragments_and_normalizes(self):
        value = canonicalize("HTTPS://Example.TEST:443/a#fragment")
        self.assertEqual(value, "https://example.test/a")
        self.assertTrue(host_allowed(value, {"example.test"}))

    def test_document_parser_collects_links_forms_and_scripts(self):
        body = """<html><script src='https://cdn.example.test/app.js'></script>
        <a href='/next#x'>next</a><form method='post'><input name='email'></form></html>"""
        links, forms, scripts = parse_document(body, "https://app.example.test/", {"app.example.test", "cdn.example.test"})
        self.assertIn("https://app.example.test/next", links)
        self.assertEqual(forms[0]["method"], "POST")
        self.assertTrue(scripts[0]["third_party"])

    def test_security_headers_and_cors_are_reported(self):
        page = PageSnapshot(
            url="https://app.example.test/login",
            status=200,
            headers={"content-type": "text/html", "access-control-allow-origin": "*", "access-control-allow-credentials": "true", "set-cookie": ""},
            set_cookies=["sid=secret; Path=/"],
            body="<html><form method='post'><input type='password'></form></html>",
            content_type="text/html",
            elapsed_ms=1,
        )
        findings = check_headers(page)
        findings.extend(check_html(page)[0])
        ids = {item.finding_id for item in findings}
        self.assertIn("HDR-CORS", ids)
        self.assertIn("COOKIE-SECURE", ids)
        cleartext_page = PageSnapshot("http://app.example.test/login", 200, {"content-type": "text/html"}, [], "<input type='password'>", "text/html", 1)
        self.assertIn("FORM-CLEAR", {item.finding_id for item in check_html(cleartext_page)[0]})

    def test_probe_detects_git_head_without_exploitation(self):
        page = PageSnapshot("https://app.example.test/.git/HEAD", 200, {}, [], "ref: refs/heads/main\n", "text/plain", 1)
        findings = check_safe_probe(page, "/.git/HEAD")
        self.assertEqual(findings[0].finding_id, "PROBE-GIT")

    def test_robots_parser(self):
        sitemaps, disallowed = parse_robots("User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n", "https://app.example.test/")
        self.assertEqual(sitemaps, ["https://app.example.test/sitemap.xml"])
        self.assertEqual(disallowed, ["/admin"])

    def test_report_does_not_write_response_body_or_cookie_value(self):
        from owasp_recon.models import ScanResult

        result = ScanResult("https://app.example.test", "now", "now", pages=[PageSnapshot("https://app.example.test", 200, {}, ["sid=secret"], "SECRET_BODY", "text/plain", 1)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_json(result, path)
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("SECRET_BODY", path.read_text(encoding="utf-8"))
            self.assertNotIn("secret", path.read_text(encoding="utf-8"))
            self.assertEqual(report["pages"][0]["set_cookie_names"], ["sid"])


if __name__ == "__main__":
    unittest.main()
