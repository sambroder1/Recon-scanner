from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .http import canonicalize, host_allowed


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[dict[str, str | bool]] = []
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag in {"a", "area", "link", "iframe", "img", "video", "audio", "source"} and values.get("href", values.get("src", "")):
            self.links.append(values.get("href", values.get("src", "")))
        if tag == "script":
            self.scripts.append({"src": values.get("src", ""), "integrity": values.get("integrity", ""), "crossorigin": values.get("crossorigin", "")})
        if tag == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            inputs = self._form["inputs"]
            assert isinstance(inputs, list)
            inputs.append({"name": values.get("name", ""), "type": values.get("type", "text")})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


def parse_document(body: str, page_url: str, allowed_hosts: set[str]) -> tuple[list[str], list[dict[str, object]], list[dict[str, object]]]:
    parser = DocumentParser()
    try:
        parser.feed(body)
    except Exception:
        pass
    urls: list[str] = []
    for raw in parser.links:
        normalized = canonicalize(raw, page_url)
        if normalized and host_allowed(normalized, allowed_hosts):
            urls.append(normalized)
    forms: list[dict[str, object]] = []
    for form in parser.forms:
        action = canonicalize(str(form.get("action", "")), page_url) if form.get("action") else canonicalize(page_url)
        item = dict(form)
        item["action"] = action
        forms.append(item)
    scripts: list[dict[str, object]] = []
    page_host = (urlsplit(page_url).hostname or "").lower()
    for script in parser.scripts:
        src = canonicalize(str(script.get("src", "")), page_url) if script.get("src") else ""
        script_item = dict(script)
        script_item["src"] = src
        script_item["third_party"] = bool(src and (urlsplit(src).hostname or "").lower() != page_host)
        scripts.append(script_item)
        if src and host_allowed(src, allowed_hosts):
            urls.append(src)
    return sorted(set(urls)), forms, scripts


def extract_sitemap_urls(body: str, base_url: str, allowed_hosts: set[str]) -> list[str]:
    values = re.findall(r"<loc>\s*([^<]+?)\s*</loc>", body, flags=re.IGNORECASE)
    result = []
    for raw in values:
        url = canonicalize(raw, base_url)
        if url and host_allowed(url, allowed_hosts):
            result.append(url)
    return sorted(set(result))


def parse_robots(body: str, base_url: str) -> tuple[list[str], list[str]]:
    sitemaps: list[str] = []
    disallowed: list[str] = []
    active_agent = False
    for line in body.splitlines():
        value = line.split("#", 1)[0].strip()
        if not value or ":" not in value:
            continue
        key, item = [part.strip() for part in value.split(":", 1)]
        lower_key = key.lower()
        if lower_key == "user-agent":
            active_agent = item == "*"
        elif lower_key == "disallow" and active_agent and item:
            disallowed.append(item)
        elif lower_key == "sitemap" and item:
            url = canonicalize(item, base_url)
            if url:
                sitemaps.append(url)
    return sorted(set(sitemaps)), sorted(set(disallowed))


def path_is_disallowed(url: str, base_url: str, disallowed: list[str]) -> bool:
    path = urlsplit(url).path or "/"
    for rule in disallowed:
        if rule.startswith("http"):
            if url.startswith(rule):
                return True
        elif path.startswith(rule):
            return True
    return False
