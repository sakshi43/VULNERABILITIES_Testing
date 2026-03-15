from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.platypus import Flowable
from datetime import datetime


SEVERITY_COLORS = {
    'High':   colors.HexColor('#C0392B'),
    'Medium': colors.HexColor('#E67E22'),
    'Low':    colors.HexColor('#F1C40F'),
    'Info':   colors.HexColor('#2980B9'),
}

SEVERITY_BG = {
    'High':   colors.HexColor('#FDEDEC'),
    'Medium': colors.HexColor('#FEF9E7'),
    'Low':    colors.HexColor('#FFFDE7'),
    'Info':   colors.HexColor('#EBF5FB'),
}

DARK    = colors.HexColor('#1A1A2E')
ACCENT  = colors.HexColor('#16213E')
LIGHT   = colors.HexColor('#F4F6F9')
WHITE   = colors.white
MUTED   = colors.HexColor('#7F8C8D')


class HorizontalLine(Flowable):
    def __init__(self, width, color=MUTED, thickness=0.5):
        super().__init__()
        self.width = width
        self.color = color
        self.thickness = thickness

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)


def build_styles():
    base = getSampleStyleSheet()

    styles = {
        'report_title': ParagraphStyle(
            'report_title',
            fontName='Helvetica-Bold',
            fontSize=26,
            textColor=WHITE,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        'report_subtitle': ParagraphStyle(
            'report_subtitle',
            fontName='Helvetica',
            fontSize=11,
            textColor=colors.HexColor('#BDC3C7'),
            alignment=TA_CENTER,
            spaceAfter=2,
        ),
        'section_heading': ParagraphStyle(
            'section_heading',
            fontName='Helvetica-Bold',
            fontSize=13,
            textColor=DARK,
            spaceBefore=18,
            spaceAfter=8,
        ),
        'vuln_title': ParagraphStyle(
            'vuln_title',
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=DARK,
            spaceAfter=4,
        ),
        'vuln_body': ParagraphStyle(
            'vuln_body',
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=3,
            leading=14,
        ),
        'vuln_label': ParagraphStyle(
            'vuln_label',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=MUTED,
            spaceAfter=2,
        ),
        'meta': ParagraphStyle(
            'meta',
            fontName='Helvetica',
            fontSize=9,
            textColor=MUTED,
        ),
        'summary_num': ParagraphStyle(
            'summary_num',
            fontName='Helvetica-Bold',
            fontSize=22,
            textColor=WHITE,
            alignment=TA_CENTER,
        ),
        'summary_label': ParagraphStyle(
            'summary_label',
            fontName='Helvetica',
            fontSize=8,
            textColor=colors.HexColor('#BDC3C7'),
            alignment=TA_CENTER,
        ),
    }
    return styles


def make_header_table(url, styles):
    """Dark banner header."""
    title      = Paragraph("API Security Scan Report", styles['report_title'])
    subtitle   = Paragraph(f"Target: {url}", styles['report_subtitle'])
    date_str   = datetime.now().strftime("%B %d, %Y  %H:%M")
    date_para  = Paragraph(f"Generated: {date_str}", styles['report_subtitle'])

    inner = Table(
        [[title], [subtitle], [date_para]],
        colWidths=[6.5 * inch],
    )
    inner.setStyle(TableStyle([
        ('ALIGN',       (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING',  (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))

    outer = Table([[inner]], colWidths=[6.5 * inch])
    outer.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), DARK),
        ('ROUNDEDCORNERS', [8]),
        ('TOPPADDING',    (0, 0), (-1, -1), 20),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
        ('LEFTPADDING',   (0, 0), (-1, -1), 20),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 20),
    ]))
    return outer


def make_summary_table(vulns, styles):
    """Coloured summary boxes: High / Medium / Low / Total."""
    counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for v in vulns:
        sev = v.get('severity', 'Low')
        counts[sev] = counts.get(sev, 0) + 1

    def box(label, count, bg):
        num   = Paragraph(str(count), styles['summary_num'])
        lbl   = Paragraph(label, styles['summary_label'])
        tbl   = Table([[num], [lbl]], colWidths=[1.4 * inch])
        tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), bg),
            ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING',    (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('ROUNDEDCORNERS', [6]),
        ]))
        return tbl

    total_bg = colors.HexColor('#2C3E50')
    row = [
        box("HIGH",   counts['High'],   SEVERITY_COLORS['High']),
        box("MEDIUM", counts['Medium'], SEVERITY_COLORS['Medium']),
        box("LOW",    counts['Low'],    colors.HexColor('#27AE60')),
        box("TOTAL",  len(vulns),       total_bg),
    ]
    summary = Table([row], colWidths=[1.4 * inch] * 4, hAlign='CENTER')
    summary.setStyle(TableStyle([
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    return summary


def make_vuln_card(v, styles, page_width):
    """One card per vulnerability."""
    sev       = v.get('severity', 'Low')
    sev_color = SEVERITY_COLORS.get(sev, MUTED)
    bg_color  = SEVERITY_BG.get(sev, LIGHT)

    # Severity badge
    badge = Table(
        [[Paragraph(sev.upper(), ParagraphStyle(
            'badge',
            fontName='Helvetica-Bold',
            fontSize=8,
            textColor=WHITE,
            alignment=TA_CENTER,
        ))]],
        colWidths=[0.7 * inch],
    )
    badge.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), sev_color),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('ROUNDEDCORNERS', [4]),
    ]))

    title_row = Table(
        [[badge, Paragraph(v.get('title', ''), styles['vuln_title'])]],
        colWidths=[0.8 * inch, 5.4 * inch],
    )
    title_row.setStyle(TableStyle([
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (0, 0),   0),
        ('LEFTPADDING', (1, 0), (1, 0),   6),
        ('TOPPADDING',  (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))

    desc_label = Paragraph("DESCRIPTION", styles['vuln_label'])
    desc_text  = Paragraph(v.get('description', ''), styles['vuln_body'])
    fix_label  = Paragraph("REMEDIATION", styles['vuln_label'])
    fix_text   = Paragraph(v.get('fix', ''), styles['vuln_body'])
    ref_label  = Paragraph("REFERENCE", styles['vuln_label'])
    ref_text   = Paragraph(
        f'<link href="{v.get("reference","")}" color="#2980B9">{v.get("reference","")}</link>',
        styles['vuln_body']
    )

    inner = Table(
        [
            [title_row],
            [HorizontalLine(5.9 * inch, color=colors.HexColor('#DADFE1'), thickness=0.5)],
            [desc_label], [desc_text],
            [fix_label],  [fix_text],
            [ref_label],  [ref_text],
        ],
        colWidths=[5.9 * inch],
    )
    inner.setStyle(TableStyle([
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
    ]))

    card = Table([[inner]], colWidths=[6.3 * inch])
    card.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), bg_color),
        ('LEFTPADDING',   (0, 0), (-1, -1), 14),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
        ('TOPPADDING',    (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BOX',           (0, 0), (-1, -1), 1.2, sev_color),
        ('ROUNDEDCORNERS', [6]),
    ]))
    return KeepTogether([card, Spacer(1, 10)])


def generate_pdf(result, output_path="report.pdf"):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles  = build_styles()
    vulns   = result.get('vulnerabilities', [])
    url     = result.get('url', 'Unknown')
    story   = []

    # Header
    story.append(make_header_table(url, styles))
    story.append(Spacer(1, 20))

    # Summary
    story.append(Paragraph("Scan Summary", styles['section_heading']))
    story.append(make_summary_table(vulns, styles))
    story.append(Spacer(1, 20))

    # Findings
    story.append(Paragraph("Detailed Findings", styles['section_heading']))
    story.append(HorizontalLine(6.5 * inch, color=DARK, thickness=1))
    story.append(Spacer(1, 8))

    # Sort: High -> Medium -> Low
    order = {'High': 0, 'Medium': 1, 'Low': 2}
    sorted_vulns = sorted(vulns, key=lambda x: order.get(x.get('severity', 'Low'), 3))

    for v in sorted_vulns:
        story.append(make_vuln_card(v, styles, doc.width))

    doc.build(story)