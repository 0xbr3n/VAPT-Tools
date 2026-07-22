@echo off
REM ============================================================================
REM  SCR Automater - ONE-CLICK INSTALLER (run on a machine WITH internet).
REM  Downloads every scanning tool + vulnerability database, then builds the
REM  local Python environment. After this finishes you can scan straight away
REM  and every scan afterwards runs fully offline.
REM
REM  Just double-click this file, or run it from a terminal.
REM ============================================================================
setlocal
cd /d "%~dp0"
title SCR Automater - Installer

echo.
echo ============================================================
echo   SCR Automater - one-click installation
echo ============================================================
echo   This will download the scanning tools (~2-3 GB) and set
echo   up everything. It needs internet and can take a while.
echo ============================================================
echo.

REM --- 1. Require Python 3.9+ -------------------------------------------------
set PYFOUND=
where python >nul 2>nul && set PYFOUND=1
if not defined PYFOUND ( where py >nul 2>nul && set PYFOUND=1 )
if not defined PYFOUND (
    echo [!] Python 3.9+ was not found on this machine.
    echo.
    echo     Install it first from https://www.python.org/downloads/
    echo     IMPORTANT: on the first installer screen, tick
    echo        "Add python.exe to PATH"
    echo     then re-run this installer.
    echo.
    pause
    exit /b 1
)
echo [i] Python found. Continuing...
echo.

REM --- 2. Note about the OWASP Dependency-Check NVD database ------------------
REM  depcheck is OFF by default (Grype is the primary CVE scanner), so we skip
REM  its slow 30-60 min NVD download here. To enable it later, get a free key
REM  at https://nvd.nist.gov/developers/request-an-api-key, save it in
REM  setup\nvd_api_key.txt, and run:  setup\setup_tools.ps1  (without -SkipDepCheckDb)

REM --- 3. Download tools + build the environment -----------------------------
echo [i] Downloading tools and building the environment...
echo     (progress is shown below; please wait)
echo.
powershell -ExecutionPolicy Bypass -NoProfile -File "setup\setup_tools.ps1" -SkipDepCheckDb
set RC=%ERRORLEVEL%

echo.
if not "%RC%"=="0" (
    echo [!] Setup reported an error (code %RC%). Scroll up to see which tool failed.
    echo     You can re-run this installer to retry - it will resume/redownload.
    echo     If one specific tool failed, the others still installed and scans
    echo     will run with whatever is present.
    echo.
    pause
    exit /b %RC%
)

REM --- 4. Done ---------------------------------------------------------------
echo ============================================================
echo   INSTALLATION COMPLETE
echo ============================================================
echo   To run a scan (fully offline from here on):
echo.
echo      run_scan.cmd "C:\path\to\the\source\code"  --pdf
echo.
echo   The report (HTML + PDF) opens from the reports\ folder.
echo ============================================================
echo.
pause
