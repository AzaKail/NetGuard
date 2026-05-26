@echo off
setlocal

set "ROOT=%~dp0"
set "AGENT_EXE=%ROOT%agent\dist\agent.exe"
set "DEFAULT_SERVER=http://127.0.0.1:8000"

title NetGuard.AI demo agent

if not exist "%AGENT_EXE%" (
    echo Agent executable was not found:
    echo %AGENT_EXE%
    echo.
    echo Build it first in the agent folder:
    echo .\.venv\Scripts\Activate.ps1
    echo pyinstaller --onefile --name agent agent.py
    echo.
    pause
    exit /b 1
)

echo NetGuard.AI demo agent
echo.
echo Press Enter if the server is running on this PC.
set /p "SERVER=Server URL [%DEFAULT_SERVER%]: "
if "%SERVER%"=="" set "SERVER=%DEFAULT_SERVER%"

cd /d "%ROOT%agent"
"%AGENT_EXE%" --server "%SERVER%" --interval 1 --simulate --host demo-pc

echo.
echo Demo agent stopped.
pause
