from flask import Blueprint, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from models import db, LogEntry
from datetime import datetime

upload_bp = Blueprint('upload', __name__)

# 📁 Folder to store uploaded logs
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 🌐 Allowed extensions
ALLOWED_EXTENSIONS = {'log', 'txt', 'gz'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@upload_bp.route('/upload', methods=['GET', 'POST'])
def upload_logs():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['logfile']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            parse_log_file(filepath)
            flash('Log file uploaded and parsed successfully.')
            return redirect(url_for('upload.upload_logs'))
    return render_template('upload_logs.html')

# 📜 Simple parser function to insert logs
# You can expand this parser as needed
def parse_log_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 9:
                continue  # not a valid log line
            ip = parts[0]
            status = int(parts[8])
            path = parts[6]
            timestamp = datetime.utcnow()
            entry = LogEntry(ip=ip, status_code=status, path=path, timestamp=timestamp)
            db.session.add(entry)
    db.session.commit()
