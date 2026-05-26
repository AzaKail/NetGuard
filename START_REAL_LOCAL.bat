@echo off
setlocal

set "ROOT=%~dp0"
set "SERVER_PY=%ROOT%server\.venv\Scripts\python.exe"
set "AGENT_EXE=%ROOT%agent\dist\agent.exe"
set "URL=http://127.0.0.1:8000"

title NetGuard.AI real local start
echo NetGuard.AI real local mode
echo.
echo This starts the real server and the real agent.
echo The agent reads actual network interface counters from this PC.
echo.

if not exist "%SERVER_PY%" (
    echo Server virtual environment was not found:
    echo %SERVER_PY%
    echo.
    pause
    exit /b 1
)

if not exist "%AGENT_EXE%" (
    echo Agent executable was not found:
    echo %AGENT_EXE%
    echo.
    echo Rebuild the agent first:
    echo cd agent
    echo .\.venv\Scripts\Activate.ps1
    echo pyinstaller --onefile --name agent agent.py
    echo.
    pause
    exit /b 1
)

echo Starting server...
start "NetGuard Server" cmd /k "cd /d ""%ROOT%server"" && "".venv\Scripts\python.exe"" -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

echo Waiting for server startup...
timeout /t 5 /nobreak >nul

echo Opening web panel...
start "" "%URL%"

echo Starting real agent...
start "NetGuard Real Agent" cmd /k "cd /d ""%ROOT%agent"" && ""dist\agent.exe"" --server %URL% --interval 5"

echo.
echo Real mode started.
echo Web panel: %URL%
echo.
pause
