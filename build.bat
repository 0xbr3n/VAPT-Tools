@echo off
REM Build a standalone single-file vapt_toolkit.exe on Windows.
REM Run this ONCE on a Windows build machine with internet access.
REM The resulting dist\vapt_toolkit.exe is self-contained.

setlocal
cd /d "%~dp0"

set PY=python
set NAME=vapt_toolkit

echo [1/4] Creating clean virtualenv (.\.buildvenv)...
%PY% -m venv .buildvenv
call .buildvenv\Scripts\activate.bat

echo [2/4] Installing runtime deps + PyInstaller...
pip install --upgrade pip wheel
pip install -r requirements.txt
pip install pyinstaller
if errorlevel 1 goto :err

echo [3/4] Building single-file binary with PyInstaller...
pyinstaller --onefile --clean --name %NAME% ^
  --collect-all cryptography ^
  --collect-all certifi ^
  vapt_toolkit.py
if errorlevel 1 goto :err

echo [4/4] Done.
echo.
echo Binary location: %CD%\dist\%NAME%.exe
echo.
echo Quick test:
echo   dist\%NAME%.exe
echo   dist\%NAME%.exe 4
echo.
echo The .exe is self-contained. Copy to any 64-bit Windows machine.
goto :end

:err
echo [!] Build failed.
exit /b 1

:end
endlocal
