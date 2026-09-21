"""Optional OWASP ZAP integration: drives a running ZAP daemon through its
API to spider and actively scan the target, then normalizes ZAP alerts into
our Finding objects. Requires ZAP running locally (default proxy :8080) with
the API key available via --zap-api-key or the ZAP_API_KEY env var."""
from __future__ import annotations

import time

from .findings import Finding, Severity

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

ZAP_RISK_TO_SEVERITY = {
    "Informational": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
}


class ZapUnavailableError(RuntimeError):
    pass


class ZapScanner:
    def __init__(self, api_key: str = "", proxy: str = "http://127.0.0.1:8080"):
        if ZAPv2 is None:
            raise ZapUnavailableError(
                "python-owasp-zap-v2.4 is not installed. Run: pip install python-owasp-zap-v2.4"
            )
        self.zap = ZAPv2(apikey=api_key, proxies={"http": proxy, "https": proxy})

    def spider_and_scan(self, target_url: str, poll_interval: float = 2.0,
                         max_wait_seconds: int = 300) -> list[Finding]:
        try:
            self.zap.urlopen(target_url)
        except Exception as exc:
            raise ZapUnavailableError(f"Could not reach ZAP proxy: {exc}") from exc

        scan_id = self.zap.spider.scan(target_url)
        waited = 0.0
        while int(self.zap.spider.status(scan_id)) < 100 and waited < max_wait_seconds:
            time.sleep(poll_interval)
            waited += poll_interval

        ascan_id = self.zap.ascan.scan(target_url)
        waited = 0.0
        while int(self.zap.ascan.status(ascan_id)) < 100 and waited < max_wait_seconds:
            time.sleep(poll_interval)
            waited += poll_interval

        findings = []
        for alert in self.zap.core.alerts(baseurl=target_url):
            severity = ZAP_RISK_TO_SEVERITY.get(alert.get("risk"), Severity.INFO)
            findings.append(Finding(
                category=f"ZAP: {alert.get('alert', 'Unknown')}",
                severity=severity,
                url=alert.get("url", target_url),
                parameter=alert.get("param", ""),
                description=alert.get("description", ""),
                evidence=alert.get("evidence", ""),
                extra={"solution": alert.get("solution", ""), "cweid": alert.get("cweid", "")},
            ))
        return findings
