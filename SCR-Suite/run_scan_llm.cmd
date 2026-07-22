@echo off
REM ============================================================
REM  SCR Automater - scan a codebase WITH the local LLM
REM  reasoning pass (per-finding FP review + vector suggestions)
REM  running on the local Ollama model.
REM
REM  Usage:   run_scan_llm.cmd "C:\path\to\client\source"
REM  (Install Ollama and pull the model once beforehand - see LLM_LAYER.md.)
REM ============================================================
setlocal
cd /d "%~dp0"

if "%~1"=="" (
    echo Usage: run_scan_llm.cmd "C:\path\to\client\source"
    echo   optional extra args are passed through, e.g.  --pdf  --only manual
    exit /b 1
)

set "LLM_BACKEND=onprem"
set "LLM_ENDPOINT=http://127.0.0.1:11434"
set "LLM_MODEL=qwen2.5-coder:14b"

curl -s -o nul "%LLM_ENDPOINT%/api/tags"
if errorlevel 1 (
    echo [scr] Ollama not responding - trying to start it...
    where ollama >nul 2>&1 && start "" /b ollama serve
    ping -n 6 127.0.0.1 >nul
)

echo [scr] LLM: %LLM_MODEL% @ %LLM_ENDPOINT%   (per-finding FP review + vector suggestions ON)
echo.

set "TARGET=%~1"
shift
REM re-collect any extra args after the target
set "EXTRA="
:collect
if not "%~1"=="" ( set "EXTRA=%EXTRA% %1" & shift & goto collect )

python -m scr --target "%TARGET%" --pdf --llm-backend onprem %EXTRA%

endlocal
