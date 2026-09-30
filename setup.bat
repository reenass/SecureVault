@echo off
echo ==================================================
echo   🔒 SECURE CLOUD STORAGE - SETUP (WINDOWS)
echo ==================================================
echo.

REM Check Python
echo 1️⃣  Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found! Please install Python 3.8+
    pause
    exit /b 1
)
echo ✅ Python found
echo.

REM Create virtual environment
echo 2️⃣  Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)
echo.

REM Activate virtual environment
echo 3️⃣  Activating virtual environment...
call venv\Scripts\activate.bat
echo ✅ Virtual environment activated
echo.

REM Install dependencies
echo 4️⃣  Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
echo ✅ Dependencies installed
echo.

REM Create directories
echo 5️⃣  Creating directories...
if not exist "uploads" mkdir uploads
if not exist "keys" mkdir keys
if not exist "instance" mkdir instance
if not exist "migrations" mkdir migrations
echo ✅ Directories created
echo.

REM Initialize database
echo 6️⃣  Initializing database...
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('✅ Database initialized')"
echo.

echo ==================================================
echo   ✅ SETUP COMPLETE!
echo ==================================================
echo.
echo 🚀 To start the application, run:
echo    start.bat
echo.
echo 📱 Then open: http://localhost:5000
echo.
pause
