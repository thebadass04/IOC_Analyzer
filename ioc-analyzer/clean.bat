@echo off
REM ============================================================================
REM IOC Analyzer - Clean Build Artifacts
REM ============================================================================

echo.
echo ============================================================================
echo   IOC Analyzer - Cleanup Script
echo ============================================================================
echo.

echo [INFO] Cleaning build artifacts...

REM Remove build directories
if exist "build" (
    echo [CLEAN] Removing build directory...
    rmdir /s /q "build"
)

if exist "dist" (
    echo [CLEAN] Removing dist directory...
    rmdir /s /q "dist"
)

REM Remove Python cache
if exist "__pycache__" (
    echo [CLEAN] Removing __pycache__ directory...
    rmdir /s /q "__pycache__"
)

for /d /r %%d in (__pycache__) do @if exist "%%d" (
    echo [CLEAN] Removing %%d...
    rmdir /s /q "%%d"
)

REM Remove .pyc files
echo [CLEAN] Removing .pyc files...
del /s /q *.pyc >nul 2>&1

REM Remove backup spec files
if exist "*.spec~" (
    echo [CLEAN] Removing backup spec files...
    del /q "*.spec~"
)

REM Remove log files (optional - uncomment if needed)
REM if exist "logs\*.log" (
REM     echo [CLEAN] Removing log files...
REM     del /q "logs\*.log"
REM )

REM Remove result files (optional - uncomment if needed)
REM if exist "results\*.json" (
REM     echo [CLEAN] Removing result files...
REM     del /q "results\*.json"
REM )

echo.
echo [OK] Cleanup complete!
echo.
pause
