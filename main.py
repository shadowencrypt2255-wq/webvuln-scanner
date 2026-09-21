#!/usr/bin/env python3
"""Web Application Vulnerability Scanner
Crawls a target site and tests for SQL injection, XSS, and broken
authentication, with optional OWASP ZAP active-scan integration.

FOR AUTHORIZED SECURITY TESTING ONLY. Only scan targets you own or have
explicit written permission to test.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import urllib.parse

from colorama import Fore, Style, init as colorama_init

from scanner.engine import ScanEngine
from scanner.findings import Finding, Severity
from scanner.report import to_html, to_json

SEVERITY_COLOR = {
    Severity.CRITICAL: Fore.MAGENTA,
    Severity.HIGH: Fore.RED,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.WHITE,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crawl a site and scan for SQL injection, XSS, and broken authentication.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", help="Target URL to scan, e.g. http://localhost:8080/")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl")
    parser.add_argument("--threads", type=int, default=8, help="Concurrent worker threads for checks")
    parser.add_argument("--rps", type=float, default=10.0, help="Max requests per second (rate limit)")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds")
    parser.add_argument("--skip-auth-bruteforce", action="store_true",
                         help="Skip weak-credential login attempts (still checks cookies/transport)")
    parser.add_argument("--use-zap", action="store_true",
                         help="Also run an OWASP ZAP spider + active scan (requires ZAP running)")
    parser.add_argument("--zap-proxy", default="http://127.0.0.1:8080", help="ZAP proxy address")
    parser.add_argument("--zap-api-key", default=os.environ.get("ZAP_API_KEY", ""),
                         help="ZAP API key (or set ZAP_API_KEY env var)")
    parser.add_argument("--output-dir", default="reports", help="Directory to write JSON/HTML reports into")
    parser.add_argument("--i-have-authorization", action="store_true",
                         help="Confirm you have explicit authorization to scan this target")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser


def require_authorization(args) -> None:
    if args.i_have_authorization:
        return
    print(Fore.YELLOW + "This tool sends attack payloads (SQLi, XSS) and login attempts to the target."
          + Style.RESET_ALL)
    print("Only use it against systems you own or are explicitly authorized to test.")
    answer = input(f"Confirm you are authorized to scan {args.url} ? [y/N] ").strip().lower()
    if answer != "y":
        print("Aborted: authorization not confirmed.")
        sys.exit(1)


def print_summary(findings: list[Finding]) -> None:
    if not findings:
        print(Fore.GREEN + "\nNo vulnerabilities detected." + Style.RESET_ALL)
        return
    print(f"\n{Style.BRIGHT}Findings ({len(findings)}):{Style.RESET_ALL}")
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"  {color}[{f.severity.value}]{Style.RESET_ALL} {f.category} - {f.url}"
              + (f" (param: {f.parameter})" if f.parameter else ""))
        print(f"      {f.description}")


def main() -> int:
    colorama_init()
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        print(Fore.RED + "Target URL must start with http:// or https://" + Style.RESET_ALL)
        return 1

    require_authorization(args)

    engine = ScanEngine(
        target_url=args.url,
        max_pages=args.max_pages,
        threads=args.threads,
        requests_per_second=args.rps,
        timeout=args.timeout,
        skip_auth_bruteforce=args.skip_auth_bruteforce,
    )
    crawl_result, findings = engine.run()

    if args.use_zap:
        from scanner.zap_client import ZapScanner, ZapUnavailableError
        try:
            zap = ZapScanner(api_key=args.zap_api_key, proxy=args.zap_proxy)
            print(Fore.CYAN + "\nRunning OWASP ZAP spider + active scan (this can take a while)..." + Style.RESET_ALL)
            findings.extend(zap.spider_and_scan(args.url))
        except ZapUnavailableError as exc:
            print(Fore.YELLOW + f"\nSkipping ZAP scan: {exc}" + Style.RESET_ALL)

    print_summary(findings)

    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "scan_report.json")
    html_path = os.path.join(args.output_dir, "scan_report.html")

    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(to_json(args.url, findings, len(crawl_result.pages), len(crawl_result.forms)))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(to_html(args.url, findings, len(crawl_result.pages), len(crawl_result.forms)))

    print(f"\nReports written to {json_path} and {html_path}")

    critical_or_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    return 2 if critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
