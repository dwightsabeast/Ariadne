@echo off
echo Checking for Python virtual environment...

REM Create a virtual environment if it doesn't exist
IF NOT EXIST venv (
    echo "Creating virtual environment..."
    python -m venv venv
)

REM Activate the virtual environment
call venv\Scripts\activate

REM Install dependencies from the requirements file
echo "Installing/verifying dependencies..."
pip install -r requirements.txt

REM Run the application
echo "Starting Ariadne backend..."
python backend.py
