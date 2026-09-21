"""Error-based and time-based blind SQL injection checks."""
from __future__ import annotations

import time
import urllib.parse

import requests

from .findings import Finding, Severity
from .payloads import SQLI_ERROR_SIGNATURES, SQLI_PAYLOADS

TIME_PAYLOAD = "' OR SLEEP(5)-- -"
TIME_THRESHOLD_SECONDS = 4.5


def _body_has_sql_error(text: str) -> str | None:
    lowered = text.lower()
    for sig in SQLI_ERROR_SIGNATURES:
        if sig in lowered:
            return sig
    return None


def test_url_params(url: str, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        for payload in SQLI_PAYLOADS:
            mutated = {k: v[0] for k, v in params.items()}
            mutated[param] = payload
            new_query = urllib.parse.urlencode(mutated)
            test_url = parsed._replace(query=new_query).geturl()
            try:
                resp = session.get(test_url, timeout=timeout)
            except requests.RequestException:
                continue
            sig = _body_has_sql_error(resp.text)
            if sig:
                findings.append(Finding(
                    category="SQL Injection",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    description="Error-based SQL injection: database error text reflected after injecting a payload into a query parameter.",
                    evidence=f"payload={payload!r} matched signature {sig!r}",
                ))
                break

        try:
            mutated = {k: v[0] for k, v in params.items()}
            mutated[param] = TIME_PAYLOAD
            new_query = urllib.parse.urlencode(mutated)
            test_url = parsed._replace(query=new_query).geturl()
            start = time.monotonic()
            session.get(test_url, timeout=timeout + 8)
            elapsed = time.monotonic() - start
            if elapsed >= TIME_THRESHOLD_SECONDS:
                findings.append(Finding(
                    category="SQL Injection",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    description="Time-based blind SQL injection: response delayed as expected after injecting a SLEEP payload.",
                    evidence=f"payload={TIME_PAYLOAD!r} response_time={elapsed:.2f}s",
                ))
        except requests.RequestException:
            pass

    return findings


def test_form(form, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    if not form.inputs:
        return findings

    for target_input in form.inputs:
        if target_input["type"] in ("submit", "button", "checkbox", "radio", "file"):
            continue
        for payload in SQLI_PAYLOADS:
            data = {i["name"]: (i["value"] or "test") for i in form.inputs}
            data[target_input["name"]] = payload
            try:
                if form.method == "post":
                    resp = session.post(form.action, data=data, timeout=timeout)
                else:
                    resp = session.get(form.action, params=data, timeout=timeout)
            except requests.RequestException:
                continue
            sig = _body_has_sql_error(resp.text)
            if sig:
                findings.append(Finding(
                    category="SQL Injection",
                    severity=Severity.HIGH,
                    url=form.action,
                    parameter=target_input["name"],
                    description=f"Error-based SQL injection via form field on {form.page_url}.",
                    evidence=f"payload={payload!r} matched signature {sig!r}",
                ))
                break
    return findings
