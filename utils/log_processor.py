# log_processor.py

import os
from datetime import datetime
from models import db, LogEntry, Threat
from utils.threat_detection import detect_threats
from utils.geoip import resolve_geoip

LOG_FOLDER = 'logs'

def process_all_logs():
    print("[LogProcessor] Scanning all log files...")
    for filename in os.listdir(LOG_FOLDER):
        if filename.endswith(".log") or filename.endswith(".txt"):
            filepath = os.path.join(LOG_FOLDER, filename)
            process_log_file(filepath)

def process_log_file(filepath):
    print(f"[LogProcessor] Processing {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(" ")
            if len(parts) < 4:
                continue
            ip, status_code, path, timestamp_str = parts[:4]
            try:
                status_code = int(status_code)
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            except:
                continue

            entry = LogEntry(ip=ip, status_code=status_code, path=path, timestamp=timestamp)
            db.session.add(entry)

            # Threat detection
            if detect_threats(entry):
                country, city = resolve_geoip(ip)
                threat = Threat(
                    ip=ip,
                    status=status_code,
                    path=path,
                    timestamp=timestamp,
                    country=country,
                    city=city,
                    threat_level=3,
                    reason="Auto-detected by rules"
                )
                db.session.add(threat)

    db.session.commit()
