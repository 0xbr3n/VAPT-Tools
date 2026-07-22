@echo off
REM Run this ONCE on the offline machine after copying the SCR Automater folder.
REM It recreates the Python venv from the pre-downloaded wheels (no internet).
setlocal
cd /d "%~dp0.."

where python >nul 2>nul
if errorlevel 1 (
    echo [!] Python 3.9+ is required on this machine. Install it from the offline
    echo     installer ^(python.org^) first, then re-run this script.
    pause
    exit /b 1
)

REM The scanning tools + wheels must have been downloaded first (INSTALL.cmd /
REM setup_tools.ps1 on a machine with internet). Without them nothing can run.
if not exist tools\wheels (
    echo.
    echo [!] The scanning tools have not been downloaded yet.
    echo     This machine is missing the tools\ folder that INSTALL.cmd creates.
    echo.
    echo     ON A MACHINE WITH INTERNET, run this once:
    echo         INSTALL.cmd
    echo     ^(that downloads the scanners + databases and builds everything^).
    echo.
    echo     If this IS an offline machine, copy the whole SCR-Automater folder
    echo     — INCLUDING its tools\ folder — from the online machine first.
    echo.
    pause
    exit /b 1
)

echo Creating local virtual environment...
if exist .venv rmdir /s /q .venv
python -m venv .venv
call .venv\Scripts\activate.bat

echo Installing bandit + checkov from local wheels (offline)...
python -m pip install --no-index --find-links tools\wheels bandit checkov
if errorlevel 1 (
    echo [!] Wheel install failed. Ensure tools\wheels was populated by INSTALL.cmd
    pause
    exit /b 1
)

echo.
echo Offline setup complete. Scan with:
echo    run_scan.cmd "C:\path\to\client\source"
pause
