@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator
    pause
    exit /b 1
)
echo Stopping and removing CyberFence Agent...
sc stop CyberFenceAgent
sc delete CyberFenceAgent
echo Removing install directory...
rmdir /S /Q "C:\Program Files\CyberFence" 2>nul
echo Done. Logs and quarantine kept in %APPDATA%\CyberFence\
pause
