@echo off
setlocal

set "ROOT=%~dp0"
set "SERVER_PY=%ROOT%server\.venv\Scripts\python.exe"
set "AGENT_EXE=%ROOT%agent\dist\agent.exe"
set "URL=http://127.0.0.1:8000"

title NetGuard.AI demo launcher
echo NetGuard.AI MVP demo
echo.

if not exist "%SERVER_PY%" (
    echo Server virtual environment was not found:
    echo %SERVER_PY%
    echo.
    echo Open PowerShell in server folder and run:
    echo python -m venv .venv
    echo .\.venv\Scripts\Activate.ps1
    echo python -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

if not exist "%AGENT_EXE%" (
    echo Agent executable was not found:
    echo %AGENT_EXE%
    echo.
    echo Open PowerShell in agent folder and run:
    echo .\.venv\Scripts\Activate.ps1
    echo pyinstaller --onefile --name agent agent.py
    echo.
    pause
    exit /b 1
)

echo Starting server...
start "NetGuard Server" cmd /k "cd /d ""%ROOT%server"" && "".venv\Scripts\python.exe"" -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

echo Waiting a few seconds...
timeout /t 5 /nobreak >nul

echo Opening web panel...
start "" "%URL%"

echo Starting demo agent...
start "NetGuard Demo Agent" cmd /k "cd /d ""%ROOT%agent"" && ""dist\agent.exe"" --server %URL% --interval 1 --simulate --host demo-pc"

echo.
echo Demo started.
echo Web panel: %URL%
echo.
pause
