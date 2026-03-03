#!/usr/bin/env bash
echo "Ariadne v1.0 - Starting..."
echo ""
if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
  echo "Installing dependencies..."
  venv/bin/pip install -r requirements.txt
fi
echo ""
echo "Starting on http://127.0.0.1:5000"
echo "Press Ctrl+C to stop"
echo ""
venv/bin/python backend.py
