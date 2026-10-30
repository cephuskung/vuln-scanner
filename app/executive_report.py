"""IVMP Phase 6: Executive Report.

One-page-friendly PDF combining the platform-level view: KPI summary,
security posture by category, and the highest-priority attack paths -
the "hand this to a manager" artifact, as opposed to the per-scan PDF
in app/pdf_report.py which is technical/per-target.
"""

from io import BytesIO
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

CATEGORY_COLOR = colors.HexColor("#0d6efd")


def _score_color(score):
    if score is None:
        return colors.HexColor("#8a93a3")
    if score >= 80:
        return colors.HexColor("#16a34a")
    if score >= 60:
        return colors.HexColor("#b58900")
    if score >= 40:
        return colors.HexColor("#d97706")
    return colors.HexColor("#dc2626")


def build_executive_report(kpis, posture, critical_paths):
    """kpis: dict from database.db.get_kpis()
    posture: dict from database.db.get_latest_posture(), or None
    critical_paths: list from attack_path.path_finder.find_all_critical_paths()
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20, spaceAfter=2)
    subtitle_style = ParagraphStyle("SubtitleStyle", parent=styles["Normal"], textColor=colors.HexColor("#8a93a3"))
    body = styles["BodyText"]
    body.fontSize = 9
    body.leading = 12

    elements = []
    elements.append(Paragraph("Executive Security Summary", title_style))
    elements.append(Paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", subtitle_style))
    elements.append(Spacer(1, 18))

    # --- KPI summary ---
    elements.append(Paragraph("Environment Overview", styles["Heading2"]))
    kpi_data = [
        ["Assets", "Total Scans", "Critical Findings", "Avg Risk Score"],
        [str(kpis.get("total_assets", 0)), str(kpis.get("total_scans", 0)),
         str(kpis.get("critical_vulns", 0)), str(kpis.get("avg_risk", 0))],
    ]
    kpi_table = Table(kpi_data, colWidths=[1.5 * inch] * 4)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f9")),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e6ee")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 20))

    # --- Posture ---
    elements.append(Paragraph("Security Posture", styles["Heading2"]))
    if posture:
        categories = [
            ("Overall", posture.get("overall_score")),
            ("Network", posture.get("network_score")),
            ("Host", posture.get("host_score")),
            ("Web", posture.get("web_score")),
            ("Patch Mgmt", posture.get("patch_score")),
            ("Config", posture.get("config_score")),
        ]
        posture_data = [[c[0] for c in categories], [str(c[1]) for c in categories]]
        posture_table = Table(posture_data, colWidths=[1.1 * inch] * 6)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f9")),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, 1), 14),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e6ee")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
        for i, (_, score) in enumerate(categories):
            style_cmds.append(("TEXTCOLOR", (i, 1), (i, 1), _score_color(float(score) if score is not None else None)))
        posture_table.setStyle(TableStyle(style_cmds))
        elements.append(posture_table)
    else:
        elements.append(Paragraph("No posture snapshot available yet.", body))
    elements.append(Spacer(1, 20))

    # --- Attack paths ---
    elements.append(Paragraph("Highest-Priority Attack Paths", styles["Heading2"]))
    if critical_paths:
        for target in critical_paths[:5]:
            elements.append(Paragraph(f"<b>Target: {target['target_label']}</b> (CRITICAL asset)", body))
            best = target["paths"][0]
            route = " → ".join(best["labels"])
            elements.append(Paragraph(f"Cheapest route (weight {best['weight']}, {best['hops']} hop(s)): {route}", body))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph(
            "No attack paths to CRITICAL-criticality assets were found in the current graph. "
            "This may mean no assets are marked CRITICAL yet, or none are currently reachable "
            "from an internet-exposed, exploitable entry point.", body))

    doc.build(elements)
    buffer.seek(0)
    return buffer
