"""Shared finding data structure and severity levels."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    category: str
    severity: Severity
    url: str
    description: str
    evidence: str = ""
    parameter: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": self.evidence,
            **self.extra,
        }
