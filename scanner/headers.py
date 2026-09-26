"""Passive HTTP security-header analysis.

These checks are read-only: a single GET per page, no payloads. They flag
missing or weak response headers that weaken a site's security posture.
"""
from __future__ import annotations

import urllib.parse

import requests

from .findings import Finding, Severity

# header (lowercased) -> (severity, human description shown when missing)
_EXPECTED_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Missing Content-Security-Policy header; increases exposure to XSS and data injection.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing X-Content-Type-Options: nosniff; browsers may MIME-sniff responses.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Missing X-Frame-Options (or a frame-ancestors CSP); page may be clickjacked.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Missing Referrer-Policy header; referrer data may leak to third parties.",
    ),
}


def check_security_headers(url: str, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_https = urllib.parse.urlparse(url).scheme == "https"

    for header, (severity, description) in _EXPECTED_HEADERS.items():
        if header == "x-frame-options" and "frame-ancestors" in headers.get(
            "content-security-policy", ""
        ):
            continue
        if header not in headers:
            findings.append(Finding(
                category="Security Misconfiguration",
                severity=severity,
                url=url,
                description=description,
                evidence=f"response header {header!r} not present",
                extra={"header": header},
            ))

    # HSTS only meaningful over HTTPS.
    if is_https and "strict-transport-security" not in headers:
        findings.append(Finding(
            category="Security Misconfiguration",
            severity=Severity.MEDIUM,
            url=url,
            description="Missing Strict-Transport-Security header on an HTTPS endpoint; "
                        "connections may be downgraded to HTTP.",
            evidence="response header 'strict-transport-security' not present",
            extra={"header": "strict-transport-security"},
        ))

    # Version/technology disclosure.
    for disclosing in ("server", "x-powered-by", "x-aspnet-version"):
        value = headers.get(disclosing, "")
        if value and any(ch.isdigit() for ch in value):
            findings.append(Finding(
                category="Information Disclosure",
                severity=Severity.INFO,
                url=url,
                description=f"Response discloses software version via '{disclosing}' header.",
                evidence=f"{disclosing}: {value}",
                extra={"header": disclosing},
            ))

    return findings
