@echo off
:: ──────────────────────────────────────────────────────────────────────────
:: CyberFence Engine — Virus Definition Updater
:: Called by the MSI installer on first install (via Custom Action)
:: Can also be run manually at any time to pull fresh definitions.
:: ──────────────────────────────────────────────────────────────────────────
setlocal EnableDelayedExpansion

set "INSTALL_DIR=%~dp0.."
set "ENGINE_DIR=%~dp0"
set "DB_DIR=%ENGINE_DIR%db"
set "LOG_DIR=%INSTALL_DIR%logs"
set "FRESHCLAM=%ENGINE_DIR%freshclam.exe"
set "CONF=%ENGINE_DIR%freshclam.conf"

:: Create directories if needed
if not exist "%DB_DIR%"  mkdir "%DB_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo.
echo  CyberFence Engine — Updating Virus Definitions
echo  ================================================
echo  Engine:   ClamAV 1.4.4 LTS (CyberFence Engine)
echo  Database: %DB_DIR%
echo  Log:      %LOG_DIR%\freshclam.log
echo.

:: Check network before running
ping -n 1 database.clamav.net >nul 2>&1
if errorlevel 1 (
    echo  [WARNING] Cannot reach database.clamav.net
    echo  Check your internet connection and try again.
    echo.
    echo  The agent will run but scanning may use outdated definitions.
    echo  Re-run this script when connectivity is restored.
    goto :end
)

echo  Downloading latest definitions from database.clamav.net ...
echo  This may take a few minutes on first run (100-200 MB).
echo.

"%FRESHCLAM%" --config-file="%CONF%" --datadir="%DB_DIR%" --log="%LOG_DIR%\freshclam.log"

if errorlevel 1 (
    echo.
    echo  [ERROR] freshclam update failed (exit code %ERRORLEVEL%).
    echo  Check %LOG_DIR%\freshclam.log for details.
    echo.
    echo  Common causes:
    echo    - Firewall blocking outbound on port 443/80
    echo    - Antivirus software blocking freshclam.exe
    echo    - No internet connectivity
) else (
    echo.
    echo  [OK] Virus definitions updated successfully.
    echo  Definition files written to: %DB_DIR%
    echo.
    echo  Restarting CyberFenceAgent service to load new definitions...
    net stop CyberFenceAgent >nul 2>&1
    net start CyberFenceAgent >nul 2>&1
    if errorlevel 1 (
        echo  [INFO] Service restart skipped (may not be installed yet).
    ) else (
        echo  [OK] CyberFenceAgent restarted.
    )
)

:end
echo.
echo  Done. Press any key to close.
pause >nul
endlocal
