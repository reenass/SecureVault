@echo off
echo 🚀 Starting Secure Cloud Storage...
echo.

REM Activate virtual environment
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
    echo ✅ Virtual environment activated
) else (
    echo ❌ Virtual environment not found!
    echo Please run: setup.bat first
    pause
    exit /b 1
)

REM Check database
if not exist "instance\storage.db" (
    echo ⚠️  Database not found. Creating...
    python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('✅ Database created')"
)

echo.
echo ==================================================
echo   🔒 SECURE CLOUD STORAGE
echo   Running on: http://localhost:5000
echo ==================================================
echo.
echo Press Ctrl+C to stop
echo.

REM Run the application
python run.py
