@echo off
title Ariadne - Web Scanner
echo Ariadne v1.0 - Starting...
echo.
if not exist "venv" (
  echo Creating virtual environment...
  python -m venv venv
  echo Installing dependencies...
  venv\Scripts\pip install -r requirements.txt
)
echo.
echo Starting on http://127.0.0.1:5000
echo Press Ctrl+C to stop
echo.
venv\Scripts\python backend.py
pause
