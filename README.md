# DU Cyber Dashboard made by Priyanshu and Pushkar

A web-based cyber security dashboard for log analysis, threat detection, reporting, and visualization. Built with Flask, SQLAlchemy, and AI/ML for advanced threat intelligence.
https://prod.liveshare.vsengsaas.visualstudio.com/join?877C4EE06687615B94790A2140861BEF0D12

## Features
- User authentication (login/register)
- Dashboard with real-time log analytics
- Threat detection (rule-based & AI/ML)
- PDF report generation (with charts)
- Upload and parse log files
- GeoIP mapping of threats
- Admin/user roles

## Project Structure
- `app.py` — Main Flask app and routes
- `model.py` — Database models (User, Threat, LogEntry, etc.)
- `forms.py` — WTForms for login/register
- `utils/` — Log parsing, threat detection, reporting, geoip, etc.
- `ai_model/` — ML model training and feature extraction
- `auth/` — Authentication blueprint
- `geo_map/` — GeoIP API for map visualization
- `uploads/` — Log upload and parsing
- `templates/` & `static/` — HTML templates and CSS
- `logs/` — Log files
- `reports/` — Generated PDF reports

## Setup Instructions

### 1. Create a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 2. Install Dependencies
```powershell
pip install flask flask-sqlalchemy flask-login matplotlib reportlab scikit-learn
```
Or use the provided `requirements.txt`:
```powershell
pip install -r requirements.txt
```

### 3. Initialize the Database
```powershell
python
>>> from app import db
>>> db.create_all()
>>> exit()
```

### 4. Run the Application
You can use the batch script for Windows:
```powershell
.\run_everything.bat
```
Or run manually:
```powershell
python app.py
```

## Usage
- Access the dashboard at [http://127.0.0.1:5000](http://127.0.0.1:5000)
- Upload log files via the Upload page
- Generate PDF threat reports from the dashboard
- View threat locations on the map

## Requirements
- Python 3.8+
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Matplotlib
- ReportLab
- scikit-learn

## Notes
- Default database: `app.db` (SQLite)
- AI model: `ai_model/ai_model.pkl` (IsolationForest)
- GeoIP: `utils/GeoLite2-City.mmdb`

---
For more details, see code comments and each module’s docstrings.
