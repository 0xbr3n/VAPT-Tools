@echo off
REM SCR Automater - one-click offline source code review.
REM Usage:  run_scan.cmd "C:\path\to\client\source"  [extra args]
REM Extra args are passed through, e.g.:  --skip depcheck   --only semgrep,gitleaks
setlocal
cd /d "%~dp0"

set TARGET=%~1
if "%TARGET%"=="" set /p TARGET=Enter path to the source code folder to review:
if "%TARGET%"=="" (echo No target given. & exit /b 1)

REM --- Locate a working Python ---------------------------------------------
REM Do NOT trust a shipped .venv: its python.exe is only a stub that points at
REM the machine that CREATED it. Test that it actually runs; if not, rebuild.
set PYEXE=.venv\Scripts\python.exe
"%PYEXE%" --version >nul 2>nul
if errorlevel 1 (
    echo [i] No usable local environment found on this machine.
    echo     Building one now from the bundled offline wheels...
    echo.
    call "%~dp0setup\setup_offline.cmd"
    if errorlevel 1 (echo [!] Setup failed. See messages above. & pause & exit /b 1)
)

REM If the venv still isn't usable, fall back to a system Python on PATH.
"%PYEXE%" --version >nul 2>nul
if errorlevel 1 (
    where python >nul 2>nul || (echo [!] Python 3.9+ not found. Install it from python.org, then re-run. & pause & exit /b 1)
    set PYEXE=python
)

shift
set EXTRA=
:collect
if "%~1"=="" goto run
set EXTRA=%EXTRA% %1
shift
goto collect

:run
%PYEXE% -m scr --target "%TARGET%" --pdf %EXTRA%
echo.
pause
