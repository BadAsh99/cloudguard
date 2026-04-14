"""
CloudGuard PDF Report Generator

Executive-level PDF: compliance posture summary, risk heatmap,
category breakdown, and detailed findings with remediation.
"""

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)


# Brand colors
CYAN = colors.HexColor("#00d9ff")
DARK_BG = colors.HexColor("#0d0d1a")
CARD_BG = colors.HexColor("#1a1a28")
RED = colors.HexColor("#ff4444")
ORANGE = colors.HexColor("#ffaa00")
GREEN = colors.HexColor("#44ff44")
BLUE = colors.HexColor("#4488ff")
GRAY = colors.HexColor("#888888")
WHITE = colors.HexColor("#ffffff")
BLACK = colors.HexColor("#000000")

STATUS_COLORS = {
    "vulnerable": RED,
    "partial": ORANGE,
    "resistant": GREEN,
    "review": BLUE,
}

SEVERITY_COLORS = {
    "critical": RED,
    "high": ORANGE,
    "medium": colors.HexColor("#ddaa00"),
    "low": BLUE,
    "info": GRAY,
}


def _styles():
    """Build custom paragraph styles."""
    base = getSampleStyleSheet()
    s = {}
    s["title"] = ParagraphStyle(
        "CGTitle", parent=base["Title"],
        fontSize=28, textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
    )
    s["subtitle"] = ParagraphStyle(
        "CGSub", parent=base["Normal"],
        fontSize=12, textColor=GRAY, spaceAfter=20,
    )
    s["h1"] = ParagraphStyle(
        "CGH1", parent=base["Heading1"],
        fontSize=18, textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=20, spaceAfter=10,
    )
    s["h2"] = ParagraphStyle(
        "CGH2", parent=base["Heading2"],
        fontSize=14, textColor=colors.HexColor("#333333"),
        spaceBefore=14, spaceAfter=6,
    )
    s["body"] = ParagraphStyle(
        "CGBody", parent=base["Normal"],
        fontSize=10, textColor=colors.HexColor("#333333"),
        leading=14, spaceAfter=4,
    )
    s["small"] = ParagraphStyle(
        "CGSmall", parent=base["Normal"],
        fontSize=8, textColor=GRAY, leading=11, spaceAfter=2,
    )
    s["code"] = ParagraphStyle(
        "CGCode", parent=base["Code"],
        fontSize=7.5, textColor=colors.HexColor("#333333"),
        backColor=colors.HexColor("#f0f0f5"),
        leftIndent=6, rightIndent=6,
        spaceBefore=2, spaceAfter=6,
        leading=11,
    )
    return s


def generate_pdf(scan_data: dict) -> bytes:
    """Generate executive PDF report from scan summary dict."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    st = _styles()
    story = []

    provider = (scan_data.get("provider") or "Unknown").upper()
    ts = datetime.now().strftime("%B %d, %Y at %H:%M")
    total = scan_data.get("total_findings", 0)
    compliance = scan_data.get("overall_compliance", 0)
    risk = scan_data.get("overall_risk_score", 0)
    cancelled = scan_data.get("cancelled", False)

    # ── Title page ──────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("CloudGuard", st["title"]))
    story.append(Paragraph("Cloud Security Posture Assessment", st["subtitle"]))
    story.append(HRFlowable(width="40%", thickness=2, color=CYAN, spaceAfter=20))
    story.append(Paragraph(f"<b>Provider:</b> {provider}", st["body"]))
    story.append(Paragraph(f"<b>Date:</b> {ts}", st["body"]))
    story.append(Paragraph(f"<b>Total Checks:</b> {total}", st["body"]))
    if cancelled:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            '<font color="#ff8800">Note: This scan was stopped before completion. Results are partial.</font>',
            st["body"],
        ))
    story.append(PageBreak())

    # ── Executive summary ───────────────────────────────────────
    story.append(Paragraph("Executive Summary", st["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dddddd"), spaceAfter=12))

    # Compliance / risk gauge table
    compliance_color = GREEN if compliance >= 80 else (ORANGE if compliance >= 50 else RED)
    risk_color = RED if risk >= 50 else (ORANGE if risk >= 20 else GREEN)

    gauge_data = [
        ["Compliance", "Risk Score", "Vulnerable", "Partial", "Resistant", "Review"],
        [
            Paragraph(f'<font size="18" color="{compliance_color.hexval()}">{compliance}%</font>', st["body"]),
            Paragraph(f'<font size="18" color="{risk_color.hexval()}">{risk}</font>', st["body"]),
            Paragraph(f'<font size="14" color="{RED.hexval()}">{scan_data.get("vulnerable_count", 0)}</font>', st["body"]),
            Paragraph(f'<font size="14" color="{ORANGE.hexval()}">{scan_data.get("partial_count", 0)}</font>', st["body"]),
            Paragraph(f'<font size="14" color="{GREEN.hexval()}">{scan_data.get("resistant_count", 0)}</font>', st["body"]),
            Paragraph(f'<font size="14" color="{BLUE.hexval()}">{scan_data.get("review_count", 0)}</font>', st["body"]),
        ],
    ]
    gt = Table(gauge_data, colWidths=[7.0 / 6 * inch] * 6)
    gt.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("TEXTCOLOR", (0, 0), (-1, 0), GRAY),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 1), (-1, 1), 8),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f8fc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#dddddd")),
    ]))
    story.append(gt)
    story.append(Spacer(1, 12))

    # Severity breakdown
    story.append(Paragraph("Severity Distribution", st["h2"]))
    sev_data = [
        ["Critical", "High", "Medium", "Low"],
        [
            str(scan_data.get("critical_issues", 0)),
            str(scan_data.get("high_issues", 0)),
            str(scan_data.get("medium_issues", 0)),
            str(scan_data.get("low_issues", 0)),
        ],
    ]
    st_table = Table(sev_data, colWidths=[1.4 * inch] * 4)
    st_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("TEXTCOLOR", (0, 0), (0, 0), RED),
        ("TEXTCOLOR", (1, 0), (1, 0), ORANGE),
        ("TEXTCOLOR", (2, 0), (2, 0), colors.HexColor("#ddaa00")),
        ("TEXTCOLOR", (3, 0), (3, 0), BLUE),
        ("TEXTCOLOR", (0, 1), (0, 1), RED),
        ("TEXTCOLOR", (1, 1), (1, 1), ORANGE),
        ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor("#ddaa00")),
        ("TEXTCOLOR", (3, 1), (3, 1), BLUE),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING", (0, 1), (-1, 1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f8fc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ]))
    story.append(st_table)
    story.append(Spacer(1, 16))

    # ── Category breakdown ──────────────────────────────────────
    categories = scan_data.get("categories", [])
    if categories:
        story.append(Paragraph("Category Compliance Overview", st["h2"]))
        cat_header = ["Category", "Compliance", "Vuln", "Partial", "Resist", "Review"]
        cat_rows = [cat_header]
        for cat in categories:
            pct = cat.get("compliance_percentage", 0)
            pct_color = GREEN if pct >= 80 else (ORANGE if pct >= 50 else RED)
            cat_rows.append([
                Paragraph(cat.get("category_name", ""), st["small"]),
                Paragraph(f'<font color="{pct_color.hexval()}">{pct}%</font>', st["body"]),
                str(cat.get("count_vulnerable", 0)),
                str(cat.get("count_partial", 0)),
                str(cat.get("count_resistant", 0)),
                str(cat.get("count_review", 0)),
            ])
        ct = Table(cat_rows, colWidths=[2.4 * inch, 0.9 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch])
        ct.setStyle(TableStyle([
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a2a3e")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f8fc"), WHITE]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#444466")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#eeeeee")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ct)

    story.append(PageBreak())

    # ── Detailed findings ───────────────────────────────────────
    story.append(Paragraph("Detailed Findings", st["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dddddd"), spaceAfter=12))

    for cat in categories:
        cat_name = cat.get("category_name", "Unknown")
        findings = cat.get("findings", [])
        vuln_findings = [f for f in findings if f.get("status") != "resistant"]
        if not vuln_findings:
            continue

        story.append(Paragraph(cat_name, st["h2"]))

        for f in vuln_findings:
            sev = f.get("severity_original", "info").lower()
            status = f.get("status", "review")
            sev_color = SEVERITY_COLORS.get(sev, GRAY)
            status_color = STATUS_COLORS.get(status, GRAY)

            # Finding header
            story.append(Paragraph(
                f'<font color="{sev_color.hexval()}"><b>[{sev.upper()}]</b></font> '
                f'{_esc(f.get("check_name", ""))} '
                f'<font color="{status_color.hexval()}">({status.upper()})</font>',
                st["body"],
            ))
            story.append(Paragraph(
                f'<font color="#888888">Resource:</font> {_esc(f.get("resource", ""))} '
                f'&nbsp;&nbsp;<font color="#888888">CIS:</font> {_esc(f.get("cis_control", ""))}',
                st["small"],
            ))
            story.append(Paragraph(_esc(f.get("finding", "")), st["body"]))

            # Remediation
            rem = f.get("remediation", "")
            if rem:
                story.append(Paragraph(
                    f'<font color="#888888">Remediation:</font> {_esc(rem)}',
                    st["small"],
                ))

            # CLI command
            cli = f.get("remediation_cli", "")
            if cli:
                story.append(Paragraph('<font color="#888888">CLI Fix:</font>', st["small"]))
                story.append(Paragraph(_esc_code(cli), st["code"]))

            # Terraform
            tf = f.get("remediation_tf", "")
            if tf:
                story.append(Paragraph('<font color="#888888">Terraform Fix:</font>', st["small"]))
                story.append(Paragraph(_esc_code(tf), st["code"]))

            story.append(Spacer(1, 10))

    # ── Footer ──────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=8))
    story.append(Paragraph(
        f'Generated by CloudGuard on {ts}. '
        'This report is confidential and intended for authorized recipients only.',
        st["small"],
    ))

    doc.build(story)
    return buf.getvalue()


def _esc(text: str) -> str:
    """Escape XML special characters for reportlab Paragraphs."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _esc_code(text: str) -> str:
    """Escape and preserve line breaks + indentation for code blocks."""
    escaped = _esc(text)
    escaped = escaped.replace("\n", "<br/>")
    escaped = escaped.replace("  ", "&nbsp;&nbsp;")
    return escaped
