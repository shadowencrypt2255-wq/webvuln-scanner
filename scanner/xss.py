"""Reflected XSS checks for URL parameters and HTML forms."""
from __future__ import annotations

import urllib.parse

import requests

from .findings import Finding, Severity
from .payloads import XSS_PAYLOADS


def test_url_params(url: str, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        for payload in XSS_PAYLOADS:
            mutated = {k: v[0] for k, v in params.items()}
            mutated[param] = payload
            new_query = urllib.parse.urlencode(mutated)
            test_url = parsed._replace(query=new_query).geturl()
            try:
                resp = session.get(test_url, timeout=timeout)
            except requests.RequestException:
                continue
            if payload in resp.text:
                findings.append(Finding(
                    category="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    description="Reflected XSS: payload echoed back unescaped in the response body.",
                    evidence=f"payload={payload!r}",
                ))
                break
    return findings


def test_form(form, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    if not form.inputs:
        return findings

    for target_input in form.inputs:
        if target_input["type"] in ("submit", "button", "checkbox", "radio", "file"):
            continue
        for payload in XSS_PAYLOADS:
            data = {i["name"]: (i["value"] or "test") for i in form.inputs}
            data[target_input["name"]] = payload
            try:
                if form.method == "post":
                    resp = session.post(form.action, data=data, timeout=timeout)
                else:
                    resp = session.get(form.action, params=data, timeout=timeout)
            except requests.RequestException:
                continue
            if payload in resp.text:
                findings.append(Finding(
                    category="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    url=form.action,
                    parameter=target_input["name"],
                    description=f"Reflected XSS via form field on {form.page_url}.",
                    evidence=f"payload={payload!r}",
                ))
                break
    return findings
