import os

SUSPICIOUS_IP_FILE = 'suspicious_ips.txt'

# ✅ Load existing suspicious IPs into a Python set
def load_suspicious_ips():
    if not os.path.exists(SUSPICIOUS_IP_FILE):
        with open(SUSPICIOUS_IP_FILE, 'w') as f:
            pass  # Create the file if it doesn't exist

    with open(SUSPICIOUS_IP_FILE, 'r') as f:
        ips = set(line.strip() for line in f if line.strip())
    return ips

# ✅ Save new suspicious IPs to file (append mode)
def save_suspicious_ip(ip):
    with open(SUSPICIOUS_IP_FILE, 'a') as f:
        f.write(ip + '\n')

# ✅ Simple AI-based threat detection logic (mock logic here)
def detect_threats(log_entry, suspicious_ips):
    threat_reasons = []
    ip = log_entry['ip']
    status = log_entry['status']
    path = log_entry['path']

    if ip in suspicious_ips:
        threat_reasons.append("Previously flagged IP")

    if status in [401, 403, 404, 500]:
        threat_reasons.append("Frequent error status")

    if '/admin' in path or '/login' in path:
        threat_reasons.append("Access to restricted path")

    if threat_reasons:
        save_suspicious_ip(ip)
        return {
            'ip': ip,
            'status': status,
            'path': path,
            'reason': ', '.join(threat_reasons),
            'threat_level': len(threat_reasons)  # Simple risk score
        }

    return None
