"""Report generation: aggregates real project data into executive/technical
reports rendered as JSON, CSV, or PDF. Never fabricates content."""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assets import Asset, Project
from app.models.enums import (
    FindingStatus,
    ReportFormat,
    ReportStatus,
    Severity,
)
from app.models.governance import Report
from app.models.scans import Finding
from app.services.risk_engine import risk_band

REPORTS_DIR = Path(__file__).resolve().parents[2] / "var" / "reports"


def gather_report_data(db: Session, project: Project) -> dict:
    findings = db.scalars(
        select(Finding).where(Finding.project_id == project.id)
        .order_by(Finding.risk_score.desc())
    ).all()
    assets = db.scalars(select(Asset).where(Asset.project_id == project.id)).all()

    by_sev = {s.value: 0 for s in Severity}
    open_count = 0
    for f in findings:
        by_sev[f.severity.value] += 1
        if f.status == FindingStatus.OPEN:
            open_count += 1

    avg_risk = round(sum(f.risk_score for f in findings) / len(findings), 1) if findings else 0.0

    return {
        "project": {"id": project.id, "name": project.name, "description": project.description},
        "generated_at": datetime.now(UTC).isoformat(),
        "totals": {
            "assets": len(assets),
            "findings": len(findings),
            "open_findings": open_count,
            "average_risk": avg_risk,
            "posture": risk_band(avg_risk),
        },
        "findings_by_severity": by_sev,
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity.value,
                "status": f.status.value, "category": f.category, "cwe": f.cwe,
                "asset_id": f.asset_id, "risk_score": f.risk_score,
                "parameter": f.parameter, "evidence": f.evidence,
                "remediation": f.remediation, "references": f.references,
                "description": f.description,
            }
            for f in findings
        ],
    }


def _render_json(data: dict) -> bytes:
    return json.dumps(data, indent=2).encode("utf-8")


def _render_csv(data: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "title", "severity", "status", "category", "cwe",
                     "asset_id", "risk_score", "parameter"])
    for f in data["findings"]:
        writer.writerow([f["id"], f["title"], f["severity"], f["status"], f["category"],
                         f["cwe"], f["asset_id"], f["risk_score"], f["parameter"]])
    return buf.getvalue().encode("utf-8")


def _render_pdf(data: dict, executive: bool) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="SentinelX Report")
    styles = getSampleStyleSheet()
    story = []

    kind = "Executive" if executive else "Technical"
    story.append(Paragraph(f"SentinelX {kind} Security Report", styles["Title"]))
    story.append(Paragraph(f"Project: {data['project']['name']}", styles["Heading2"]))
    story.append(Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]))
    story.append(Spacer(1, 12))

    t = data["totals"]
    story.append(Paragraph(
        f"Overall posture: <b>{t['posture']}</b> (average finding risk {t['average_risk']}/100). "
        f"{t['findings']} findings across {t['assets']} assets; {t['open_findings']} open.",
        styles["Normal"]))
    story.append(Spacer(1, 12))

    sev = data["findings_by_severity"]
    sev_table = Table(
        [["Severity", "Count"]] + [[s, sev[s]] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")],
        hAlign="LEFT",
    )
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 16))

    if executive:
        story.append(Paragraph("Top Risks", styles["Heading2"]))
        for f in data["findings"][:10]:
            story.append(Paragraph(
                f"<b>[{f['severity']}] {f['title']}</b> — risk {f['risk_score']}/100. "
                f"{f['remediation']}", styles["Normal"]))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("Findings", styles["Heading2"]))
        for f in data["findings"]:
            story.append(Paragraph(f"[{f['severity']}] {f['title']} ({f['cwe'] or 'n/a'})",
                                   styles["Heading3"]))
            story.append(Paragraph(f["description"] or "", styles["Normal"]))
            if f["evidence"]:
                story.append(Paragraph(f"Evidence: <font face='Courier'>{f['evidence'][:400]}</font>",
                                       styles["Normal"]))
            story.append(Paragraph(f"Remediation: {f['remediation']}", styles["Normal"]))
            story.append(Spacer(1, 8))

    doc.build(story)
    return buf.getvalue()


def generate_report(db: Session, report_id: int) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise ValueError("report not found")
    project = db.get(Project, report.project_id)
    try:
        data = gather_report_data(db, project)
        executive = report.report_type.value == "EXECUTIVE"
        if report.fmt == ReportFormat.JSON:
            content, ext = _render_json(data), "json"
        elif report.fmt == ReportFormat.CSV:
            content, ext = _render_csv(data), "csv"
        else:
            content, ext = _render_pdf(data, executive), "pdf"

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / f"report_{report.id}.{ext}"
        path.write_bytes(content)
        report.file_path = str(path)
        report.status = ReportStatus.READY
    except Exception as exc:  # noqa: BLE001
        report.status = ReportStatus.FAILED
        report.error = str(exc)
    db.commit()
    return report
