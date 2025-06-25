# parser.py

import time
import re
import os
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app import app
from models import db, LogEntry
from alerts import send_email_alert
from config import Config
from ai_model.features import extract_features
import joblib
from pcap_capture.capture import capture_traffic

LOG_FILE = os.path.join(Config.LOG_FOLDER, "access.log")
SUSPICIOUS_IP_FILE = os.path.join(Config.LOG_FOLDER, "suspicious_ips.txt")
model = joblib.load(Config.MODEL_PATH) if os.path.exists(Config.MODEL_PATH) else None

def append_suspicious_ip(ip):
    if not os.path.exists(SUSPICIOUS_IP_FILE):
        open(SUSPICIOUS_IP_FILE, 'w').close()
    with open(SUSPICIOUS_IP_FILE, "r+") as f:
        existing = f.read().splitlines()
        if ip not in existing:
            f.write(ip + "\n")

def parse_log_line(line):
    match = re.match(r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\] "(.*?)" (\d+)', line)
    if match:
        ip = match.group(1)
        timestamp = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
        request = match.group(3)
        status = int(match.group(4))
        return ip, timestamp, request, status
    return None

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self._last_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0

    def on_modified(self, event):
        if event.src_path.endswith("access.log"):
            with open(LOG_FILE, "r", encoding='utf-8') as f:
                f.seek(self._last_size)
                new_lines = f.readlines()
                self._last_size = f.tell()

            with app.app_context():
                for line in new_lines:
                    parsed = parse_log_line(line)
                    if not parsed:
                        continue
                    ip, timestamp, request, status = parsed
                    entry = LogEntry(ip=ip, timestamp=timestamp, request=request, status=status)

                    # AI detection
                    if model:
                        features = extract_features(entry)
                        result = model.predict([features])[0]
                        if result == -1:
                            entry.threat = "AI-Anomaly"
                            append_suspicious_ip(ip)
                            capture_traffic(ip, duration=20)
                            send_email_alert(ip, entry.threat, timestamp, request)

                    db.session.add(entry)
                    db.session.commit()

if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    print(f"📡 Monitoring {LOG_FILE} for real-time logs...")
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=Config.LOG_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
