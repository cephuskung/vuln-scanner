"""Generates a downloadable PDF vulnerability report for a scan."""

from io import BytesIO
from xml.sax.saxutils import escape as _esc
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#d97706"),
    "MEDIUM": colors.HexColor("#b58900"),
    "LOW": colors.HexColor("#16a34a"),
    "Unknown": colors.HexColor("#8a93a3"),
}


def build_pdf_report(scan, vulns, counts, extra=None):
    """scan: dict with id/target/status/total_risk/scan_time
    vulns: list of dicts with port_number/service/cve_id/severity/cvss_score/description/remediation.
        Optionally also carries confidence_pct (0-100 int) and
        confidence_label (str), as attached by web/app.py's
        _attach_confidence() helper from the persisted
        vulnerability_confidence/confidence_reason columns. Both are
        display-only and safe to omit (falls back to no confidence line).
    counts: dict of severity -> count
    extra: optional scan-type specific data for Software/System scans (see
        web/app.py::_scan_extra): software list, system info, coverage,
        configuration checks, listeners and inventory counts.
    Returns BytesIO positioned at 0, ready to send_file.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], fontSize=20, spaceAfter=4
    )
    body = styles["BodyText"]
    body.fontSize = 9
    body.leading = 12

    elements = []

    elements.append(Paragraph("Vulnerability Scan Report", title_style))
    # Everything from the database is escaped before going into Paragraph
    # markup: NVD text and targets may contain '<' or '&', which would
    # otherwise break (or inject markup into) report generation.
    elements.append(Paragraph(f"Target: <b>{_esc(str(scan['target']))}</b>", styles["Normal"]))
    elements.append(Paragraph(f"Scan date: {_esc(str(scan['scan_time']))}", styles["Normal"]))
    elements.append(Paragraph(f"Status: {_esc(str(scan['status']))}", styles["Normal"]))
    elements.append(Paragraph(f"Total risk score: <b>{_esc(str(scan['total_risk']))}</b>", styles["Normal"]))
    detail = scan.get("status_detail") if hasattr(scan, "get") else None
    if detail:
        label = "Scan failed" if scan["status"] == "failed" else "Note - results may be incomplete"
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>{label}:</b> {_esc(str(detail))}", styles["Normal"]))
    elements.append(Spacer(1, 6))
    kind = scan.get("scan_type") or "manual"
    info_mode = ((scan.get("scan_info") or {}).get("mode") if hasattr(scan, "get") else None)
    if kind == "software" and info_mode == "windows-inventory":
        scope = ("Assessment scope: installed applications of the computer running the SentriX server, discovered from the "
                 "Windows registry (read-only) and assessed against NVD. Only product and version are known, so a CVE match "
                 "shows the version is in a vulnerable range, not that the software is exploitable. Portable applications and "
                 "software without an uninstall entry are not included. No result proves the computer is secure.")
    elif kind == "system-windows":
        scope = ("Assessment scope: Windows threat assessment of the computer running the SentriX server, performed by "
                 "Microsoft Defender Antivirus through its PowerShell cmdlets. SentriX has no antivirus engine of its own and "
                 "never removes, quarantines or executes files. An empty result is not proof the computer is free of malware.")
    elif kind == "software":
        scope = ("Assessment scope: software scan - the software supplied by the user was assessed against NVD. "
                 "Nothing was inspected on any machine; applicability depends on the accuracy of the vendor, "
                 "product and version entered.")
    elif kind in ("system-local", "system-remote"):
        scope = ("Assessment scope: system scan (" + ("local" if kind == "system-local" else "remote over SSH, key authentication")
                 + ") - configuration, exposure and installed software were inspected with read-only commands. Checks "
                 "marked unknown / not assessed were NOT verified; passing every check performed does not prove the "
                 "system is secure.")
    else:
        scope = ("Assessment scope: remote, unauthenticated assessment (Nmap service/version detection "
                 "correlated with NVD). No local or credentialed checks were performed.")
    elements.append(Paragraph(f"<i>{_esc(scope)}</i>", styles["Normal"]))
    elements.append(Spacer(1, 16))

    # KPI summary table
    summary_data = [["Critical", "High", "Medium", "Low"]]
    summary_data.append([
        str(counts.get("CRITICAL", 0)),
        str(counts.get("HIGH", 0)),
        str(counts.get("MEDIUM", 0)),
        str(counts.get("LOW", 0)),
    ])
    summary_table = Table(summary_data, colWidths=[1.3 * inch] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f9")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e6ee")),
        ("TEXTCOLOR", (0, 1), (0, 1), SEVERITY_COLORS["CRITICAL"]),
        ("TEXTCOLOR", (1, 1), (1, 1), SEVERITY_COLORS["HIGH"]),
        ("TEXTCOLOR", (2, 1), (2, 1), SEVERITY_COLORS["MEDIUM"]),
        ("TEXTCOLOR", (3, 1), (3, 1), SEVERITY_COLORS["LOW"]),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    if extra:
        _extra_sections(elements, scan, extra, styles)

    if kind == "system-windows":
        doc.build(elements)
        buffer.seek(0)
        return buffer
    elements.append(Paragraph("CVE findings for installed software" if kind in ("system-local", "system-remote")
                              else "Findings", styles["Heading2"]))
    elements.append(Spacer(1, 8))

    header = ["Port", "Service", "CVE", "Sev", "CVSS", "Description / Remediation"]
    table_data = [header]

    for v in vulns:
        desc = _esc(v.get("description") or "")
        remediation = _esc(v.get("remediation") or "")

        # Vulnerability confidence (IVMP confidence scoring) - display only,
        # does not affect CVSS/EPSS/contextual priority. Appended to the
        # combined cell rather than given its own column, to stay within
        # the existing table width.
        confidence_pct = v.get("confidence_pct")
        confidence_label = v.get("confidence_label")
        confidence_reason = _esc(v.get("confidence_reason") or "")
        confidence_line = ""
        if confidence_pct is not None:
            confidence_line = f"<br/><br/><b>Confidence:</b> {_esc(str(confidence_label))} ({confidence_pct}%)"
            if confidence_reason:
                confidence_line += f" — {confidence_reason}"

        # Same evidence the scan page shows, so the two stay consistent:
        # contextual priority, applicability, and what was actually matched.
        prio = v.get("contextual_priority")
        meta = []
        if prio is not None:
            meta.append(f"<b>Priority:</b> {_esc(str(v.get('priority_label') or ''))} ({prio})"
                        + (" - known exploited (CISA KEV)" if v.get("is_kev") else ""))
        if v.get("applicability_status"):
            meta.append(f"<b>Applicability:</b> {_esc(str(v['applicability_status']))}")
        ev = v.get("match_evidence") or {}
        if isinstance(ev, dict) and (ev.get("product") or ev.get("version")):
            matched = _esc(str(ev.get("product") or "-"))
            if ev.get("vendor"):
                matched += f" ({_esc(str(ev['vendor']))})"
            if ev.get("version"):
                matched += f" {_esc(str(ev['version']))}"
            meta.append(f"<b>Matched:</b> {matched}" + (" - CPE-confirmed" if ev.get("cpe_confirmed") else ""))
        meta_line = ("<br/>" + "<br/>".join(meta) + "<br/>") if meta else ""

        combined = Paragraph(
            f"{desc[:280]}{'...' if len(desc) > 280 else ''}<br/>{meta_line}<br/><b>Remediation:</b> {remediation}{confidence_line}",
            body,
        )
        table_data.append([
            _esc(str(v.get("port_number")) if v.get("port_number") is not None else "-"),
            _esc(v.get("service") or ""),
            _esc(v.get("cve_id") or "-"),
            _esc(v.get("severity") or "Unknown"),
            str(v.get("cvss_score") or "-"),
            combined,
        ])

    findings_table = Table(
        table_data,
        colWidths=[0.45 * inch, 0.8 * inch, 1.0 * inch, 0.55 * inch, 0.5 * inch, 3.2 * inch],
        repeatRows=1,
    )

    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2233")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e6ee")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 1), (-2, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    for i, v in enumerate(vulns, start=1):
        sev = v.get("severity") or "Unknown"
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["Unknown"])
        style_commands.append(("TEXTCOLOR", (3, i), (3, i), color))
        style_commands.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))

    findings_table.setStyle(TableStyle(style_commands))
    if vulns:
        elements.append(findings_table)
    elif scan["status"] == "completed":
        elements.append(Paragraph(
            "No vulnerabilities were identified by the checks that ran for this scan"
            + (" (see the note above - results may be incomplete)" if detail else "")
            + ". This is not proof that the target is secure.", styles["Normal"]))
    elif scan["status"] == "failed":
        elements.append(Paragraph("No results - the scan did not complete.", styles["Normal"]))
    else:
        elements.append(Paragraph("The scan is still in progress.", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def _small_table(rows, widths, header_bg="#f1f5f9"):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    return t


def _extra_sections(elements, scan, extra, styles):
    """Software-list / system-information / coverage / checks / inventory
    sections. Every database-sourced string is escaped before it reaches
    reportlab's Paragraph markup."""
    body = ParagraphStyle("extra-body", parent=styles["Normal"], fontSize=8, leading=10)
    P = lambda text: Paragraph(_esc(str(text if text is not None else "")), body)
    info = extra.get("info") or {}

    if extra["kind"] == "windows_inventory":
        _inventory_sections(elements, extra, styles, P, info)
        return
    if extra["kind"] == "windows_defender":
        _defender_sections(elements, extra, styles, P, info)
        return

    if extra["kind"] == "software":
        elements.append(Paragraph("Software assessed", styles["Heading2"]))
        rows = [["Software", "Version", "NVD identity", "Result", "CVEs", "Note"]]
        for s in extra["inventory"]:
            rows.append([P(((s.get("vendor") or "") + " " + s["product"]).strip()), P(s.get("version") or "unknown"),
                         P(f"{s['cpe_vendor']}:{s['cpe_product']}" if s.get("cpe_vendor") else "name only"),
                         P("assessed" if s["assessment"] == "assessed" else "NOT assessed"),
                         P(s.get("findings_count", 0)), P(s.get("note") or "")])
        elements.append(_small_table(rows, [1.3 * inch, 0.7 * inch, 1.2 * inch, 0.8 * inch, 0.4 * inch, 2.4 * inch]))
        elements.append(Spacer(1, 14))
        return

    elements.append(Paragraph("System information", styles["Heading2"]))
    facts = [
        ("Operating system", info.get("os")), ("Kernel / arch", f"{info.get('kernel')} / {info.get('arch')}"),
        ("Hostname", info.get("hostname")), ("Uptime (days)", info.get("uptime_days")),
        ("Mode", "Local" if info.get("mode") == "local" else "Remote over SSH"),
        ("Privilege", info.get("elevation")),
    ]
    if info.get("mode") == "remote":
        facts.append(("Host key", "verified" if info.get("host_key_verified") else "NOT verified"))
    counts = extra.get("inventory_counts") or {}
    facts.append(("Installed packages", f"{counts.get('total', 0)} ({counts.get('assessed', 0)} with a known NVD identity)"))
    elements.append(_small_table([[P(k), P(v)] for k, v in facts], [1.6 * inch, 4.9 * inch]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Assessment coverage", styles["Heading2"]))
    rows = [["Area", "Status", "Detail", "Needs"]]
    for c in info.get("coverage") or []:
        rows.append([P(c["name"].replace("_", " ")), P(c["status"]), P(c["detail"]), P(c.get("requires") or "")])
    elements.append(_small_table(rows, [1.4 * inch, 0.7 * inch, 3.6 * inch, 0.8 * inch]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Security configuration checks", styles["Heading2"]))
    rows = [["Result", "Check", "Priority", "Evidence / remediation"]]
    for c in extra["checks"]:
        res = c["status"].replace("_", " ") + (f" ({c['severity']})" if c["status"] == "fail" and c.get("severity") else "")
        if c["status"] == "unknown" and c.get("requires"):
            res += f" - needs {c['requires']}"
        text = c.get("evidence") or ""
        if c["status"] == "fail" and c.get("remediation"):
            text += "  Remediation: " + c["remediation"]
        prio = f"{c.get('priority_label')} ({c.get('contextual_priority')})" if c.get("priority_label") else "-"
        rows.append([P(res), P(c["title"]), P(prio), P(text)])
    elements.append(_small_table(rows, [1.0 * inch, 1.7 * inch, 0.8 * inch, 3.0 * inch]))
    elements.append(Spacer(1, 10))

    exposed = [l for l in (info.get("listeners") or []) if l.get("scope") != "loopback"]
    if exposed:
        elements.append(Paragraph("Network-exposed listening services", styles["Heading2"]))
        rows = [["Protocol", "Address", "Port", "Process"]]
        for l in exposed[:60]:
            rows.append([P(l["proto"]), P(l["address"]), P(l["port"]), P(l.get("process") or "unknown")])
        elements.append(_small_table(rows, [0.8 * inch, 2.4 * inch, 0.8 * inch, 2.5 * inch]))
        elements.append(Spacer(1, 10))

    elements.append(Paragraph("Installed software assessed against NVD", styles["Heading2"]))
    rows = [["Package", "Version", "NVD identity", "Result", "CVEs"]]
    for s in extra["inventory"]:
        rows.append([P(s["product"]), P(s["version"]), P(f"{s.get('cpe_vendor')}:{s.get('cpe_product')}"),
                     P("assessed" if s["assessment"] == "assessed" else "NOT assessed"), P(s.get("findings_count", 0))])
    if len(rows) == 1:
        rows.append([P("none"), P(""), P(""), P("No software had a known NVD identity or the inventory was unavailable"), P("")])
    elements.append(_small_table(rows, [1.5 * inch, 1.6 * inch, 1.4 * inch, 1.5 * inch, 0.5 * inch]))
    elements.append(Spacer(1, 14))


def _inventory_sections(elements, extra, styles, P, info):
    host, cnt, tiers = info.get("host") or {}, info.get("counts") or {}, info.get("tiers") or {}
    elements.append(Paragraph("Computer inspected", styles["Heading2"]))
    facts = [("Computer", host.get("computer_name")), ("Operating system", host.get("os")),
             ("Scope", "The computer running the SentriX server process"),
             ("Inventory source", f"Windows registry (read-only) - {info.get('inventory_status')}")]
    elements.append(_small_table([[P(k), P(v)] for k, v in facts], [1.6 * inch, 4.9 * inch]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("Collection details", styles["Heading2"]))
    rows = [["Registry location", "Result", "Entries", "Detail"]]
    for l in info.get("locations") or []:
        rows.append([P(l["label"]), P(str(l["status"]).replace("_", " ")), P(l.get("entries_read")), P(l.get("detail") or "")])
    elements.append(_small_table(rows, [2.2 * inch, 0.9 * inch, 0.6 * inch, 2.8 * inch]))
    for n in info.get("notes") or []:
        elements.append(Paragraph("&bull; " + _esc(n), styles["Normal"]))
    if cnt:
        elements.append(Spacer(1, 8))
        elements.append(Paragraph("Assessment summary", styles["Heading2"]))
        na = cnt.get("not_assessed") or {}
        summary = [("Applications discovered", cnt.get("discovered")),
                   ("Assessed against NVD", f"{cnt.get('assessed')} ({cnt.get('assessed_products')} distinct products)"),
                   ("With findings", f"{cnt.get('with_findings')} ({cnt.get('findings')} CVE matches)"),
                   ("Confirmed / Probable / Potential / Indeterminate",
                    " / ".join(str(tiers.get(k, 0)) for k in ("CONFIRMED", "PROBABLE", "POTENTIAL", "INDETERMINATE"))),
                   ("Unknown applicability (no version)", na.get("no_version", 0)),
                   ("NVD lookup failed", cnt.get("lookup_failed", 0)),
                   ("Not assessed (other reasons)", sum(na.values()) - na.get("no_version", 0) - na.get("nvd_unavailable", 0))]
        elements.append(_small_table([[P(k), P(v)] for k, v in summary], [3.0 * inch, 3.5 * inch]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("Installed applications", styles["Heading2"]))
    rows = [["Application", "Publisher", "Version", "Assessment", "CVEs", "Note"]]
    for s in extra["inventory"]:
        if s["assessment"] == "assessed":
            res = "assessed"
        elif s["assessment"] == "lookup_failed":
            res = "NVD lookup failed"
        elif s.get("assessment_reason") == "no_version":
            res = "unknown applicability"
        else:
            res = "NOT assessed"
        rows.append([P(s["product"]), P(s.get("vendor") or ""), P(s.get("version") or "unknown"), P(res),
                     P(s.get("findings_count", 0)), P(s.get("note") or "")])
    elements.append(_small_table(rows, [1.7 * inch, 1.1 * inch, 0.8 * inch, 0.9 * inch, 0.4 * inch, 1.6 * inch]))
    elements.append(Spacer(1, 14))


def _defender_sections(elements, extra, styles, P, info):
    host, prot, sc, det = info.get("host") or {}, info.get("protection") or {}, info.get("scan") or {}, info.get("detections") or {}
    elements.append(Paragraph("Computer inspected", styles["Heading2"]))
    action = {"status": "Protection status only", "quick": "Quick Scan", "full": "Full Scan", "custom": "Custom Scan"}.get(info.get("action"), info.get("action"))
    facts = [("Computer", host.get("computer_name")), ("Operating system", host.get("os")),
             ("Engine", "Microsoft Defender Antivirus"), ("Requested", action + (f": {info['path']}" if info.get("path") else ""))]
    elements.append(_small_table([[P(k), P(v)] for k, v in facts], [1.6 * inch, 4.9 * inch]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("Protection status", styles["Heading2"]))
    elements.append(Paragraph(_esc(f"{(prot.get('state') or 'unknown').capitalize()}. {prot.get('summary') or ''}"), styles["Normal"]))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("Scan result", styles["Heading2"]))
    outcome = sc.get("outcome")
    text = {
        "scan_finished": "Defender reports the scan finished. " + ("" if det.get("current_scan") else
                         "No detections attributable to this scan were reported; this is not proof the computer is free of malware."),
        "completion_unverified": "COMPLETION NOT ESTABLISHED: the scan command returned without error but SentriX could not confirm "
                                 "Defender finished. The absence of detections is not a clean result.",
        "scan_incomplete": "SCAN INCOMPLETE: it did not finish, so results are partial.",
        "scan_failed": "The scan did not run.",
    }.get(outcome, "No scan was performed.")
    elements.append(Paragraph(_esc(text), styles["Normal"]))
    if (sc.get("error") or {}).get("message"):
        elements.append(Paragraph(_esc(sc["error"]["message"]), styles["Normal"]))
    comp = sc.get("completion") or {}
    for line in (comp.get("evidence") or []) + (comp.get("caveats") or []):
        elements.append(Paragraph("&bull; " + _esc(line), styles["Normal"]))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Protection checks", styles["Heading2"]))
    rows = [["Result", "Check", "Evidence / remediation"]]
    for c in extra["checks"]:
        res = c["status"].replace("_", " ") + (f" ({c['severity']})" if c["status"] == "fail" and c.get("severity") else "")
        if c["status"] == "unknown" and c.get("requires"):
            res += f" - needs {c['requires']}"
        t = c.get("evidence") or ""
        if c["status"] == "fail" and c.get("remediation"):
            t += "  Remediation: " + c["remediation"]
        rows.append([P(res), P(c["title"]), P(t)])
    elements.append(_small_table(rows, [1.1 * inch, 2.0 * inch, 3.4 * inch]))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Threat detections", styles["Heading2"]))
    if det.get("available") is False:
        elements.append(Paragraph(_esc("Detection records could not be read: " + str(det.get("error"))), styles["Normal"]))
    rows = [["Attribution", "Threat", "Severity", "Affected resource", "Detected", "Status"]]
    for t in extra["threats"]:
        res = "; ".join(f"{r.get('type')}: {r.get('value')}" for r in (t.get("resources") or []))
        rows.append([P({"current_scan": "during this scan", "historical": "historical"}.get(t["attribution"], t["attribution"])),
                     P(t.get("threat_name") or f"threat id {t.get('threat_id')}"), P(t.get("defender_severity")), P(res),
                     P(t.get("initial_detection_time")), P(t["status"] + (" - UNRESOLVED" if t.get("needs_attention") else ""))])
    if len(rows) == 1:
        rows.append([P("-"), P("No detection records to show"), P(""), P(""), P(""), P("")])
    elements.append(_small_table(rows, [0.9 * inch, 1.3 * inch, 0.7 * inch, 1.9 * inch, 0.9 * inch, 0.8 * inch]))
    elements.append(Spacer(1, 6))
    for l in info.get("limitations") or []:
        elements.append(Paragraph("&bull; " + _esc(l), styles["Normal"]))
    elements.append(Spacer(1, 10))
