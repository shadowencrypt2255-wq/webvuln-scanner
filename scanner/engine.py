"""Scan orchestration: runs the crawler then the SQLi/XSS/auth checks
concurrently across discovered pages and forms, with basic rate limiting."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from . import auth, sqli, xss
from .crawler import Crawler, CrawlResult
from .findings import Finding

logger = logging.getLogger("webvuln")


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


class _ThrottledSession(requests.Session):
    def __init__(self, limiter: RateLimiter):
        super().__init__()
        self._limiter = limiter

    def request(self, *args, **kwargs):
        self._limiter.wait()
        return super().request(*args, **kwargs)


class ScanEngine:
    def __init__(self, target_url: str, max_pages: int = 100, threads: int = 8,
                 requests_per_second: float = 10.0, timeout: int = 10,
                 skip_auth_bruteforce: bool = False):
        self.target_url = target_url
        self.max_pages = max_pages
        self.threads = threads
        self.timeout = timeout
        self.skip_auth_bruteforce = skip_auth_bruteforce
        self.limiter = RateLimiter(requests_per_second)

    def _session(self) -> requests.Session:
        return _ThrottledSession(self.limiter)

    def crawl(self) -> CrawlResult:
        crawler = Crawler(self.target_url, max_pages=self.max_pages,
                           timeout=self.timeout, session=self._session())
        logger.info("Crawling %s (max_pages=%s)...", self.target_url, self.max_pages)
        result = crawler.crawl()
        logger.info("Crawl complete: %d pages, %d forms", len(result.pages), len(result.forms))
        return result

    def scan(self, crawl_result: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        tasks = []

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            for page_url in crawl_result.pages:
                if "?" in page_url:
                    tasks.append(pool.submit(sqli.test_url_params, page_url, self._session(), self.timeout))
                    tasks.append(pool.submit(xss.test_url_params, page_url, self._session(), self.timeout))
                tasks.append(pool.submit(auth.check_session_cookies, page_url, self._session(), self.timeout))

            for form in crawl_result.forms:
                tasks.append(pool.submit(sqli.test_form, form, self._session(), self.timeout))
                tasks.append(pool.submit(xss.test_form, form, self._session(), self.timeout))
                tasks.append(pool.submit(auth.check_form_transport, form))
                if not self.skip_auth_bruteforce:
                    tasks.append(pool.submit(auth.check_weak_credentials, form, self._session(), self.timeout))

            for future in as_completed(tasks):
                try:
                    result = future.result()
                except Exception:
                    logger.exception("A check task failed")
                    continue
                if result:
                    findings.extend(result)

        return findings

    def run(self) -> tuple[CrawlResult, list[Finding]]:
        crawl_result = self.crawl()
        logger.info("Running SQLi / XSS / broken-auth checks...")
        findings = self.scan(crawl_result)
        logger.info("Scan complete: %d findings", len(findings))
        return crawl_result, findings
