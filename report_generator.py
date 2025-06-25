import os
from datetime import datetime
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from models import db, LogEntry, Threat

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

def generate_pdf_report():
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")

    # Prepare directories
    year = now.strftime("%Y")
    month = now.strftime("%B")
    day = now.strftime("%d")

    output_pdf_dir = os.path.join(REPORTS_DIR, year, month, day)
    os.makedirs(output_pdf_dir, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Fetch data
    logs = LogEntry.query.filter(db.func.date(LogEntry.timestamp) == date_str).all()
    threats = Threat.query.filter(db.func.date(Threat.timestamp) == date_str).all()

    # Render HTML
    template = env.get_template("report_template.html")
    rendered = template.render(logs=logs, threats=threats, date=now.strftime("%d-%b-%Y %H:%M:%S"))

    # Save HTML
    html_path = os.path.join(RESULTS_DIR, f"{date_str}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    # Generate PDF
    pdf_path = os.path.join(output_pdf_dir, f"{date_str}.pdf")
    HTML(string=rendered).write_pdf(pdf_path)

    print(f"[✔] PDF Report saved: {pdf_path}")
    print(f"[✔] HTML Report saved: {html_path}")
