@echo off
setlocal EnableDelayedExpansion

title MalMon v2 - Dynamic Malware Analyzer
echo.
echo  =============================================
echo     TriageEye - Built for quick triage (Windows)
echo  =============================================
echo.

:: Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found in PATH.
    echo        Please install Python 3.9+ and make sure it's added to PATH.
    echo.
    pause
    exit /b 1
)

echo [*] Checking virtual environment...

if not exist venv (
    echo [i] Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)

echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

echo [*] Installing / updating required packages...
python -m pip install -r requirements.txt --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Some packages could not be installed.
    echo           Continuing anyway...
)

echo.
echo  =============================================
echo     Environment ready. Starting TriageEye...
echo  =============================================
echo.

python TriageEye.py

echo.
echo  =============================================
echo               Analysis finished
echo  =============================================
echo.

pause