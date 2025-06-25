@echo off
title DU Cyber Threat Monitor - Windows Launcher

REM === Setup environment (optional if venv is used) ===
REM call venv\Scripts\activate

echo [1/4] Ensuring logs and DB exist...
if not exist logs mkdir logs
if not exist logs\pcaps mkdir logs\pcaps
if not exist logs\access.log type nul > logs\access.log
if not exist logs\suspicious_ips.txt type nul > logs\suspicious_ips.txt

echo [2/4] Starting Flask App...
start cmd /k "python app.py"

timeout /t 3 > nul

echo [3/4] Starting Real-time Log Parser...
start cmd /k "python parser.py"

echo [4/4] Opening Dashboard in Browser...
start http://127.0.0.1:5000/dashboard

echo ✅ All systems launched successfully.
pause
