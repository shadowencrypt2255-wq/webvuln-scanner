"""Static knowledge base mapping engine finding categories to CWE, remediation,
references, and *potential* MITRE ATT&CK techniques.

MITRE techniques attached here are POTENTIAL (a vulnerability may enable a
technique) — never OBSERVED. Observed techniques come only from the detection
engine acting on real events.
"""
from __future__ import annotations

from app.models.enums import Confidence, Severity

# category -> metadata
CATALOG: dict[str, dict] = {
    "SQL Injection": {
        "cwe": "CWE-89",
        "confidence": Confidence.HIGH,
        "remediation": "Use parameterized queries / prepared statements and an ORM; "
                       "validate and canonicalize input; apply least-privilege DB accounts.",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
        "mitre": ["T1190"],
    },
    "Cross-Site Scripting (XSS)": {
        "cwe": "CWE-79",
        "confidence": Confidence.HIGH,
        "remediation": "Context-aware output encoding, a strict Content-Security-Policy, "
                       "and framework auto-escaping; never reflect raw user input.",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
        "mitre": ["T1189"],
    },
    "Broken Authentication": {
        "cwe": "CWE-287",
        "confidence": Confidence.HIGH,
        "remediation": "Enforce strong password policy and MFA, rate-limit and lock out after "
                       "failed logins, set Secure/HttpOnly/SameSite cookies, and use HTTPS only.",
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
        "mitre": ["T1110", "T1078"],
    },
    "Security Misconfiguration": {
        "cwe": "CWE-16",
        "confidence": Confidence.HIGH,
        "remediation": "Add the missing security response headers (CSP, HSTS, X-Content-Type-Options, "
                       "etc.) at the edge/proxy or application framework.",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/16.html",
        ],
        "mitre": [],
    },
    "Information Disclosure": {
        "cwe": "CWE-200",
        "confidence": Confidence.MEDIUM,
        "remediation": "Suppress version banners and verbose headers; return generic error pages.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "mitre": ["T1592"],
    },
}

_DEFAULT = {
    "cwe": "",
    "confidence": Confidence.MEDIUM,
    "remediation": "Review the finding evidence and apply vendor guidance.",
    "references": [],
    "mitre": [],
}


def metadata_for(category: str) -> dict:
    # ZAP alerts arrive as "ZAP: <name>"; fall back gracefully.
    return CATALOG.get(category, _DEFAULT)


# Deterministic engine findings warrant a floor severity; used only for sanity.
CATEGORY_MIN_SEVERITY = {
    "SQL Injection": Severity.HIGH,
    "Cross-Site Scripting (XSS)": Severity.HIGH,
}
