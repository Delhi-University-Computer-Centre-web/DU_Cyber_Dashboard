import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from models import LogEntry, Threat
from flask import current_app

def generate_html_summary():
    with current_app.app_context():
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report_template.html')

        logs = LogEntry.query.all()
        threats = Threat.query.all()

        now = datetime.now()
        year = str(now.year)
        month = now.strftime('%B')
        day = now.strftime('%d')

        # Generate HTML content
        html_out = template.render(
            date=now.strftime("%Y-%m-%d %H:%M:%S"),
            logs=logs,
            threats=threats
        )

        # Save to results folder
        results_dir = os.path.join('results')
        os.makedirs(results_dir, exist_ok=True)
        output_file = os.path.join(results_dir, f'{year}-{month}-{day}.html')

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_out)

        print(f"[+] HTML summary saved: {output_file}")
