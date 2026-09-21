"""Renders scan findings as JSON and a standalone HTML report."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .findings import Finding, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_COLORS = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#c2650a",
    Severity.LOW: "#1d4ed8",
    Severity.INFO: "#6b7280",
}


def to_json(target: str, findings: list[Finding], pages_crawled: int, forms_found: int) -> str:
    payload = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": pages_crawled,
        "forms_found": forms_found,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def _summary_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return counts


def to_html(target: str, findings: list[Finding], pages_crawled: int, forms_found: int) -> str:
    counts = _summary_counts(findings)
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    summary_cards = "".join(
        f'<div class="card" style="border-color:{SEVERITY_COLORS[s]}">'
        f'<div class="count" style="color:{SEVERITY_COLORS[s]}">{counts[s]}</div>'
        f'<div class="label">{s.value}</div></div>'
        for s in SEVERITY_ORDER
    )

    rows = ""
    if not ordered:
        rows = '<tr><td colspan="5" class="empty">No vulnerabilities detected.</td></tr>'
    for f in ordered:
        color = SEVERITY_COLORS[f.severity]
        rows += (
            "<tr>"
            f'<td><span class="badge" style="background:{color}">{f.severity.value}</span></td>'
            f"<td>{html.escape(f.category)}</td>"
            f'<td class="url">{html.escape(f.url)}</td>'
            f"<td>{html.escape(f.parameter)}</td>"
            f"<td>{html.escape(f.description)}<div class=\"evidence\">{html.escape(f.evidence)}</div></td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Web Vulnerability Scan Report - {html.escape(target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#0b0f14; color:#e5e7eb; margin:0; padding:32px; }}
  h1 {{ font-size: 22px; margin-bottom:4px; }}
  .meta {{ color:#9ca3af; font-size:13px; margin-bottom:24px; }}
  .summary {{ display:flex; gap:16px; margin-bottom:28px; flex-wrap:wrap; }}
  .card {{ background:#111826; border:1px solid; border-radius:8px; padding:14px 20px; min-width:90px; text-align:center; }}
  .card .count {{ font-size:26px; font-weight:700; }}
  .card .label {{ font-size:11px; letter-spacing:0.05em; color:#9ca3af; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:#111826; border-radius:8px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #1f2937; font-size:13px; vertical-align:top; }}
  th {{ background:#0f1620; color:#9ca3af; font-size:11px; text-transform:uppercase; letter-spacing:0.04em; }}
  .badge {{ color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }}
  .url {{ word-break:break-all; max-width:260px; color:#93c5fd; }}
  .evidence {{ color:#9ca3af; font-size:11px; margin-top:4px; font-family: ui-monospace, monospace; }}
  .empty {{ text-align:center; padding:24px; color:#9ca3af; }}
  .disclaimer {{ margin-top:24px; font-size:12px; color:#6b7280; }}
</style>
</head>
<body>
  <h1>Web Vulnerability Scan Report</h1>
  <div class="meta">Target: {html.escape(target)} &middot; Generated: {datetime.now(timezone.utc).isoformat()} &middot; Pages crawled: {pages_crawled} &middot; Forms found: {forms_found}</div>
  <div class="summary">{summary_cards}</div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>URL</th><th>Parameter</th><th>Details</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="disclaimer">For authorized security testing only. Only scan targets you own or have explicit written permission to test.</div>
</body>
</html>"""
