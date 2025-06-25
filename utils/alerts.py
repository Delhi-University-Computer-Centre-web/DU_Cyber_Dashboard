# utils/alerts.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = 'email-smtp.ap-south-1.amazonaws.com'
SMTP_PORT = 587
SMTP_USER = 'AKIA3TTNA7MSFZFPYKCQ'
SMTP_PASS = 'BOCu82P7rMnpv5NTORbAkxPmSbhU5E1UOFflFTb11eeE'

SENDER_EMAIL = 'no-reply@notification.du.ac.in'
RECIPIENT_EMAILS = ['balaraj@ducc.du.ac.in']

def send_alert_email(ip, location, threat_type, timestamp):
    subject = f"[ALERT] Suspicious IP Detected: {ip}"
    body = f"""
    🚨 High-Risk IP Detected 🚨

    IP Address: {ip}
    Location: {location}
    Threat Type: {threat_type}
    Time Detected: {timestamp}

    Immediate review is recommended.

    -- DU Cyber Cell SIEM System
    """

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECIPIENT_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        print(f"[EMAIL SENT] Alert for {ip} to {RECIPIENT_EMAILS}")

    except Exception as e:
        print(f"[EMAIL ERROR] Could not send alert email: {str(e)}")
