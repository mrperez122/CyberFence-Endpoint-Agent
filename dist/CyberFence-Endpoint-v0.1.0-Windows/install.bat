@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  CyberFence Endpoint Protection - Installer
echo ============================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Please run this installer as Administrator.
    echo Right-click install.bat and select "Run as administrator"
    pause
    exit /b 1
)

:: Create install directory
set INSTALL_DIR=C:\Program Files\CyberFence
echo [1/6] Creating install directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Copy files
echo [2/6] Copying agent binary...
copy /Y "cf-agent.exe" "%INSTALL_DIR%\cf-agent.exe" >nul

:: Create config directory
set CONFIG_DIR=%ProgramData%\CyberFence
echo [3/6] Creating config directory: %CONFIG_DIR%
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%CONFIG_DIR%\config.toml" copy /Y "config.toml" "%CONFIG_DIR%\config.toml" >nul

:: Create log directory
set LOG_DIR=%APPDATA%\CyberFence\logs
echo [4/6] Creating log directory: %LOG_DIR%
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

:: Register Windows Service
echo [5/6] Registering Windows Service...
sc stop CyberFenceAgent >nul 2>&1
sc delete CyberFenceAgent >nul 2>&1
sc create CyberFenceAgent binPath= "\"%INSTALL_DIR%\cf-agent.exe\"" start= auto DisplayName= "CyberFence Endpoint Agent"
sc description CyberFenceAgent "CyberFence Endpoint Protection - real-time file monitoring and malware scanning"
sc failure CyberFenceAgent reset= 30 actions= restart/5000/restart/10000/restart/30000

:: Start the service
echo [6/6] Starting CyberFence Agent...
sc start CyberFenceAgent

echo.
echo ============================================
echo  Installation Complete!
echo ============================================
echo.
echo  Service status:
sc query CyberFenceAgent | findstr STATE
echo.
echo  Log files:  %APPDATA%\CyberFence\logs\
echo  Config:     %ProgramData%\CyberFence\config.toml
echo.
echo  NOTE: Install ClamAV for malware scanning:
echo    choco install clamav -y
echo    freshclam.exe
echo.
pause
