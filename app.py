# app.py
import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from utils.log_parser import parse_logs
from utils.geoip import get_ip_location
from utils.alerts import send_alert_email
from utils.report_generator import generate_pdf_report
from forms import LoginForm, RegisterForm
from model import db, User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    log_data = parse_logs('logs')
    total_logs = log_data["total_logs"]
    total_threats = log_data["total_threats"]
    unique_ips = log_data["unique_ips"]
    top_threats = log_data["top_threats"]
    ai_threats = log_data["ai_threats"]
    geo_data = log_data["geo_data"]
    # total_logs = len(log_data)
    # total_threats = sum(1 for log in log_data if log.get('is_threat'))
    # unique_ips = len(set(log['ip'] for log in log_data))

    # top_threats = {}
    # ai_threats = {}

    # for log in log_data:
    #     ip = log['ip']
    #     if log['is_threat']:
    #         top_threats[ip] = top_threats.get(ip, 0) + 1
    #     if model.predict(log):
    #         ai_threats[ip] = ai_threats.get(ip, 0) + 1
    #         if ai_threats[ip] > 5:
    #             send_alert_email(ip, log)

    # geo_data = [get_ip_location(ip) for ip in top_threats]

    # data_summary = {
    #     'total_logs': total_logs,
    #     'total_threats': total_threats,
    #     'unique_ips': unique_ips,
    #     'top_threats': top_threats,
    #     'ai_threats': ai_threats
    # }
    return render_template('dashboard.html',
                           total_logs=total_logs,
                           total_threats=total_threats,
                           unique_ips=unique_ips,
                           top_threats=top_threats,
                           ai_threats=ai_threats,
                           geo_data=geo_data,
                           log_data=log_data)

@app.route('/view_result')
@login_required
def view_result():
    return render_template('results.html')

@app.route('/generate_report')
@login_required
def generate_report():
    log_data = parse_logs('logs')
    total_logs = len(log_data)
    total_threats = sum(1 for log in log_data if log.get('is_threat'))
    unique_ips = len(set(log['ip'] for log in log_data))

    top_threats = {}
    ai_threats = {}
    for log in log_data:
        ip = log['ip']
        if log['is_threat']:
            top_threats[ip] = top_threats.get(ip, 0) + 1
        if model.predict(log):
            ai_threats[ip] = ai_threats.get(ip, 0) + 1

    data = {
        'total_logs': total_logs,
        'total_threats': total_threats,
        'unique_ips': unique_ips,
        'top_threats': top_threats,
        'ai_threats': ai_threats
    }
    filename = generate_pdf_report(data)
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
