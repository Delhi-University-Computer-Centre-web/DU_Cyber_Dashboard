# utils/report_generator.py
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
import matplotlib.pyplot as plt

def generate_chart(data, chart_path):
    labels = list(data.keys())
    sizes = list(data.values())

    if not labels or not sizes:
        return None

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title("Top Threat IP Distribution")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()
    return chart_path

def generate_pdf_report(data, output_dir="reports"):
    today = datetime.now()
    year = str(today.year)
    month = today.strftime('%B')
    day = str(today.day)

    output_path = os.path.join(output_dir, year, month, day)
    os.makedirs(output_path, exist_ok=True)

    filename = os.path.join(output_path, "threat_report.pdf")
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("📄 <b>Threat Intelligence Report</b>", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"🕒 Date: {today.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Summary:</b>", styles['Heading2']))
    summary_data = [
        ['Total Logs', str(data.get('total_logs', 'N/A'))],
        ['Total Threats', str(data.get('total_threats', 'N/A'))],
        ['Unique IPs', str(data.get('unique_ips', 'N/A'))]
    ]
    table = Table(summary_data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("<b>Top Threat IPs:</b>", styles['Heading2']))
    top_threat_data = [[ip, str(count)] for ip, count in data.get('top_threats', {}).items()]
    if top_threat_data:
        table = Table([['IP Address', 'Threat Count']] + top_threat_data, colWidths=[250, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # Generate and embed threat pie chart
        chart_path = os.path.join(output_path, "threat_chart.png")
        if generate_chart(data['top_threats'], chart_path):
            elements.append(Image(chart_path, width=400, height=300))
            elements.append(Spacer(1, 20))

    elements.append(Paragraph("<b>AI Predicted Threat IPs:</b>", styles['Heading2']))
    ai_threat_data = [[ip, str(score)] for ip, score in data.get('ai_threats', {}).items()]
    if ai_threat_data:
        table = Table([['IP Address', 'AI Risk Score']] + ai_threat_data, colWidths=[250, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ]))
        elements.append(table)

    doc.build(elements)
    return filename
