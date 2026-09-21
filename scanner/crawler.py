"""Site crawler: discovers pages and HTML forms within a target's scope."""
from __future__ import annotations

import urllib.parse
from collections import deque
from dataclasses import dataclass, field

import requests
import tldextract
from bs4 import BeautifulSoup


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
    page_url: str = ""


@dataclass
class CrawlResult:
    pages: set[str] = field(default_factory=set)
    forms: list[FormInfo] = field(default_factory=list)


def _same_registered_domain(url_a: str, url_b: str) -> bool:
    a = tldextract.extract(url_a)
    b = tldextract.extract(url_b)
    return (a.domain, a.suffix) == (b.domain, b.suffix)


def _extract_forms(page_url: str, soup: BeautifulSoup) -> list[FormInfo]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "get").lower()
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": tag.get("type", "text"),
                "value": tag.get("value", ""),
            })
        forms.append(FormInfo(
            action=urllib.parse.urljoin(page_url, action),
            method=method,
            inputs=inputs,
            page_url=page_url,
        ))
    return forms


class Crawler:
    def __init__(self, start_url: str, max_pages: int = 100, timeout: int = 10,
                 session: requests.Session | None = None):
        self.start_url = start_url
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.setdefault(
            "User-Agent", "WebVulnScanner/1.0 (+authorized-security-testing)"
        )

    def crawl(self) -> CrawlResult:
        result = CrawlResult()
        queue = deque([self.start_url])
        seen = {self.start_url}

        while queue and len(result.pages) < self.max_pages:
            url = queue.popleft()
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            result.pages.add(url)
            soup = BeautifulSoup(resp.text, "html.parser")
            result.forms.extend(_extract_forms(url, soup))

            for link in soup.find_all("a", href=True):
                next_url = urllib.parse.urljoin(url, link["href"])
                next_url = next_url.split("#")[0]
                if not next_url.startswith(("http://", "https://")):
                    continue
                if not _same_registered_domain(next_url, self.start_url):
                    continue
                if next_url in seen:
                    continue
                seen.add(next_url)
                queue.append(next_url)

        return result
