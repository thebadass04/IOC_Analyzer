@echo off
REM ============================================================================
REM IOC Analyzer - Development Mode
REM ============================================================================

echo.
echo ============================================================================
echo   IOC Analyzer - Development Mode
echo ============================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install dependencies if needed
if not exist "venv" (
    echo [INFO] Virtual environment not found
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt --quiet
)

REM Create required directories
if not exist "logs" mkdir logs
if not exist "results" mkdir results

REM Run the application
echo [INFO] Starting IOC Analyzer in development mode...
echo [INFO] Press Ctrl+C to stop the server
echo.
python app.py
