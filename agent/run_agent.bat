@echo off
setlocal

set "EXE=%~dp0dist\agent.exe"
set "DEFAULT_SERVER=http://127.0.0.1:8000"
set "DEFAULT_INTERVAL=5"

if not exist "%EXE%" (
    echo agent.exe was not found here:
    echo %EXE%
    echo.
    echo Build it first with:
    echo pyinstaller --onefile --name agent agent.py
    echo.
    pause
    exit /b 1
)

echo NetGuard.AI agent
echo.
echo If the server runs on this PC, press Enter.
echo If it runs on another PC, enter something like http://192.168.1.10:8000
echo.
set /p "SERVER=Server URL [%DEFAULT_SERVER%]: "
if "%SERVER%"=="" set "SERVER=%DEFAULT_SERVER%"

echo.
echo Starting agent...
echo Server: %SERVER%
echo Interval: %DEFAULT_INTERVAL%s
echo.

"%EXE%" --server "%SERVER%" --interval %DEFAULT_INTERVAL%

echo.
echo Agent stopped.
pause
