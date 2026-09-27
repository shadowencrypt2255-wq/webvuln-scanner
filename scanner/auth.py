"""Broken authentication checks: weak credentials, missing lockout, insecure
cookie flags, and login forms submitted over plaintext HTTP."""
from __future__ import annotations

import urllib.parse

import requests

from .findings import Finding, Severity
from .payloads import WEAK_CREDENTIALS

AUTH_FAILURE_HINTS = [
    "invalid", "incorrect", "failed", "denied", "wrong password",
    "does not match", "try again", "not found", "error",
]

USERNAME_FIELD_HINTS = ["user", "email", "login", "uname"]
PASSWORD_FIELD_HINTS = ["pass", "pwd"]


def _is_login_form(form) -> bool:
    names = [i["name"].lower() for i in form.inputs]
    has_user = any(any(h in n for h in USERNAME_FIELD_HINTS) for n in names)
    has_pass = any(i["type"] == "password" or any(h in i["name"].lower() for h in PASSWORD_FIELD_HINTS)
                   for i in form.inputs)
    return has_user and has_pass


def _field_names(form) -> tuple[str | None, str | None]:
    user_field = pass_field = None
    for i in form.inputs:
        name_lower = i["name"].lower()
        if i["type"] == "password" or any(h in name_lower for h in PASSWORD_FIELD_HINTS):
            pass_field = pass_field or i["name"]
        elif any(h in name_lower for h in USERNAME_FIELD_HINTS):
            user_field = user_field or i["name"]
    return user_field, pass_field


def check_form_transport(form) -> list[Finding]:
    findings = []
    if _is_login_form(form) and form.action.startswith("http://"):
        findings.append(Finding(
            category="Broken Authentication",
            severity=Severity.HIGH,
            url=form.action,
            description="Login form submits credentials over plaintext HTTP instead of HTTPS.",
            evidence=f"form action={form.action}",
        ))
    return findings


def check_weak_credentials(form, session: requests.Session, timeout: int = 10,
                            max_attempts: int = 10) -> list[Finding]:
    findings: list[Finding] = []
    if not _is_login_form(form):
        return findings

    user_field, pass_field = _field_names(form)
    if not user_field or not pass_field:
        return findings

    baseline_data = {i["name"]: (i["value"] or "") for i in form.inputs}

    responses_seen = []
    lockout_triggered = False

    for idx, (username, password) in enumerate(WEAK_CREDENTIALS[:max_attempts]):
        data = dict(baseline_data)
        data[user_field] = username
        data[pass_field] = password
        try:
            if form.method == "post":
                resp = session.post(form.action, data=data, timeout=timeout, allow_redirects=True)
            else:
                resp = session.get(form.action, params=data, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue

        body_lower = resp.text.lower()
        looks_like_failure = any(hint in body_lower for hint in AUTH_FAILURE_HINTS)
        responses_seen.append((resp.status_code, len(resp.text)))

        if idx >= 5 and "lock" in body_lower or "too many attempts" in body_lower:
            lockout_triggered = True

        if not looks_like_failure and resp.status_code in (200, 301, 302, 303):
            findings.append(Finding(
                category="Broken Authentication",
                severity=Severity.CRITICAL,
                url=form.action,
                parameter=user_field,
                description="Login succeeded with a common weak/default credential pair.",
                evidence=f"username={username!r} password={password!r} status={resp.status_code}",
            ))
            break

    if len(responses_seen) >= 8 and not lockout_triggered:
        findings.append(Finding(
            category="Broken Authentication",
            severity=Severity.MEDIUM,
            url=form.action,
            description="No account lockout or rate limiting detected after multiple failed login attempts, allowing credential brute-forcing.",
            evidence=f"{len(responses_seen)} consecutive failed attempts accepted without lockout",
        ))

    return findings


def check_session_cookies(url: str, session: requests.Session, timeout: int = 10) -> list[Finding]:
    findings = []
    try:
        # The response body is not needed; this call populates session.cookies.
        session.get(url, timeout=timeout)
    except requests.RequestException:
        return findings

    parsed = urllib.parse.urlparse(url)
    is_https = parsed.scheme == "https"

    for cookie in session.cookies:
        name_lower = cookie.name.lower()
        if not any(h in name_lower for h in ("sess", "auth", "token", "login", "id")):
            continue
        issues = []
        if is_https and not cookie.secure:
            issues.append("missing Secure flag")
        httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly", False)
        if not httponly:
            issues.append("missing HttpOnly flag")
        samesite = cookie._rest.get("SameSite")
        if not samesite:
            issues.append("missing SameSite attribute")
        if issues:
            findings.append(Finding(
                category="Broken Authentication",
                severity=Severity.MEDIUM,
                url=url,
                parameter=cookie.name,
                description=f"Session cookie '{cookie.name}' is missing security attributes: {', '.join(issues)}.",
                evidence=f"cookie={cookie.name}",
            ))
    return findings
