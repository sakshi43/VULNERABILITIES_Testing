from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf(result):

    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("API Security Report", styles['Title']))
    content.append(Paragraph(f"Target: {result['url']}", styles['Normal']))

    for v in result["vulnerabilities"]:
        text = f"{v['severity']} -{v['title']} {v['issue']} (Fix: {v['fix']})"
        content.append(Paragraph(text, styles['Normal']))

    pdf = SimpleDocTemplate("report.pdf")
    pdf.build(content)