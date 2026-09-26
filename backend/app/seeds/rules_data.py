"""Default GLOBAL detection rules (organization_id = NULL).

These are defensive rules keyed off structured security events. They use safe,
synthetic-friendly thresholds and map to MITRE techniques.
"""
from __future__ import annotations

from app.models.enums import Severity

DEFAULT_RULES: list[dict] = [
    {
        "key": "auth.bruteforce",
        "name": "Credential brute force",
        "description": "Many failed authentication attempts from one source IP in a short window.",
        "severity": Severity.HIGH,
        "event_type": "authentication",
        "conditions": {"match": {"outcome": "failure"}},
        "threshold": 8,
        "window_seconds": 300,
        "group_by": ["source_ip"],
        "mitre_technique_ids": ["T1110"],
        "references": ["https://attack.mitre.org/techniques/T1110/"],
    },
    {
        "key": "auth.password_spray",
        "name": "Password spraying",
        "description": "One source IP failing auth against many distinct usernames.",
        "severity": Severity.HIGH,
        "event_type": "authentication",
        "conditions": {"match": {"outcome": "failure"}},
        "threshold": 10,
        "window_seconds": 600,
        "group_by": ["source_ip"],
        "mitre_technique_ids": ["T1110"],
        "references": ["https://attack.mitre.org/techniques/T1110/"],
    },
    {
        "key": "recon.port_scan",
        "name": "Port scan indicator",
        "description": "A single source touching many distinct ports/services rapidly.",
        "severity": Severity.MEDIUM,
        "event_type": "network",
        "conditions": {},
        "threshold": 15,
        "window_seconds": 120,
        "group_by": ["source_ip"],
        "mitre_technique_ids": ["T1046", "T1595"],
        "references": ["https://attack.mitre.org/techniques/T1046/"],
    },
    {
        "key": "web.sensitive_path",
        "name": "Repeated access to sensitive paths",
        "description": "Repeated requests to sensitive paths (admin, config, backups).",
        "severity": Severity.MEDIUM,
        "event_type": "web_access",
        "conditions": {"match": {"outcome": "denied"}},
        "threshold": 6,
        "window_seconds": 300,
        "group_by": ["source_ip"],
        "mitre_technique_ids": ["T1595"],
        "references": ["https://attack.mitre.org/techniques/T1595/"],
    },
    {
        "key": "web.high_request_rate",
        "name": "Abnormal request rate",
        "description": "A single source generating an unusually high request volume.",
        "severity": Severity.LOW,
        "event_type": "web_access",
        "conditions": {},
        "threshold": 100,
        "window_seconds": 60,
        "group_by": ["source_ip"],
        "mitre_technique_ids": ["T1499"],
        "references": ["https://attack.mitre.org/techniques/T1499/"],
    },
]
