@echo off
REM ============================================================================
REM IOC Analyzer - Build Script
REM ============================================================================
setlocal enabledelayedexpansion

echo.
echo ============================================================================
echo   IOC Analyzer - Build Process
echo ============================================================================
echo.

REM Check if Python is installed
echo [1/6] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)
echo [OK] Python found

REM Check if pip is installed
echo.
echo [2/6] Checking pip installation...
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not installed or not in PATH
    pause
    exit /b 1
)
echo [OK] pip found

REM Clean previous builds
echo.
echo [3/6] Cleaning previous builds...
if exist "build" (
    echo Removing build directory...
    rmdir /s /q "build"
)
if exist "dist" (
    echo Removing dist directory...
    rmdir /s /q "dist"
)
if exist "*.spec~" (
    echo Removing backup spec files...
    del /q "*.spec~"
)
echo [OK] Cleanup complete

REM Ensure required directories exist
echo.
echo [4/6] Creating required directories...
if not exist "logs" mkdir logs
if not exist "results" mkdir results
if not exist "templates" (
    echo [ERROR] templates directory not found!
    pause
    exit /b 1
)
if not exist "static" (
    echo [ERROR] static directory not found!
    pause
    exit /b 1
)
echo [OK] Directories verified

REM Install/Update dependencies
echo.
echo [5/6] Installing dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    echo Please check requirements.txt and your internet connection
    pause
    exit /b 1
)
echo [OK] Dependencies installed

REM Build executable
echo.
echo [6/6] Building executable with PyInstaller...
pyinstaller --clean ioc_analyzer.spec
if errorlevel 1 (
    echo [ERROR] Build failed!
    echo Check the output above for errors
    pause
    exit /b 1
)

REM Verify build
echo.
echo ============================================================================
echo   Build Verification
echo ============================================================================
if exist "dist\IOC_Analyzer.exe" (
    echo [OK] Build successful!
    echo.
    echo Executable location: dist\IOC_Analyzer.exe
    
    REM Get file size
    for %%A in ("dist\IOC_Analyzer.exe") do (
        set size=%%~zA
        set /a sizeMB=!size! / 1048576
        echo Executable size: !sizeMB! MB
    )
    
    echo.
    echo ============================================================================
    echo   Next Steps
    echo ============================================================================
    echo 1. Test the executable: dist\IOC_Analyzer.exe
    echo 2. Configure your VirusTotal API key in Settings
    echo 3. The application will create logs and results directories automatically
    echo ============================================================================
) else (
    echo [ERROR] Executable not found after build!
    echo Something went wrong during the build process
    pause
    exit /b 1
)

echo.
pause
