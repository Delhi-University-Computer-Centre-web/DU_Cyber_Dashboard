# config.py

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'very_secret_key_123'
    SQLALCHEMY_DATABASE_URI = "sqlite:///C:/Users/DUCC/Desktop/parse/app.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Log and PCAP paths
    LOG_FOLDER = os.path.join(os.getcwd(), "logs")
    PCAP_FOLDER = os.path.join(os.getcwd(), "logs", "pcaps")

    # Email alert settings (using Amazon SES or SMTP)
    ENABLE_EMAIL_ALERTS = True
    SMTP_HOST = 'email-smtp.ap-south-1.amazonaws.com'
    SMTP_PORT = 587
    SMTP_USER = 'your_smtp_user'
    SMTP_PASS = 'your_smtp_password'
    SENDER_EMAIL = 'no-reply@notification.du.ac.in'
    ADMIN_EMAILS = ['balaraj@ducc.du.ac.in']

    # Model path
    MODEL_PATH = os.path.join("ai_model", "ai_model.pkl")
