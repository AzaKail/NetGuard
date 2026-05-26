@echo off
setlocal

set "ROOT=%~dp0"
set "SERVER_PY=%ROOT%server\.venv\Scripts\python.exe"
set "URL=http://127.0.0.1:8000"

title NetGuard.AI server

if not exist "%SERVER_PY%" (
    echo Server virtual environment was not found:
    echo %SERVER_PY%
    echo.
    echo Run these commands in the server folder first:
    echo python -m venv .venv
    echo .\.venv\Scripts\Activate.ps1
    echo python -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

start "" "%URL%"
cd /d "%ROOT%server"
"%SERVER_PY%" -m uvicorn app.main:app --host 0.0.0.0 --port 8000

echo.
echo Server stopped.
pause
