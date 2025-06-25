from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# 🧑‍💼 User model with role for login/register and RBAC
class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' or 'user'

# ☠️ Threat model to track suspicious activities
class Threat(db.Model):
    __tablename__ = 'threat'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Integer)
    path = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    country = db.Column(db.String(50))
    city = db.Column(db.String(50))
    threat_level = db.Column(db.Integer)
    reason = db.Column(db.String(255))

# 📜 LogEntry model to store all parsed logs and analysis
class LogEntry(db.Model):
    __tablename__ = 'log_entry'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    status_code = db.Column(db.Integer)
    path = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    threat = db.Column(db.String(255))  # Nullable, AI or rule-based detection
    country = db.Column(db.String(50))
    city = db.Column(db.String(50))

# 🌐 GeoIP cache table for optimization
class GeoIPCache(db.Model):
    __tablename__ = 'geoip_cache'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100), unique=True, nullable=False)
    country = db.Column(db.String(50))
    city = db.Column(db.String(50))
    last_resolved = db.Column(db.DateTime, default=datetime.utcnow)
