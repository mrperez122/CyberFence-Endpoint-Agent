@echo off
echo Creating EICAR test file in Downloads...
echo X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > "%USERPROFILE%\Downloads\eicar_test.com"
echo.
echo EICAR file created. Watch for:
echo   - Windows notification: "Threat Detected"
echo   - Tray icon turns red
echo   - File deleted from Downloads
echo   - Dashboard shows the detection
echo.
echo Waiting 5 seconds...
timeout /t 5 /nobreak >nul
echo.
echo Check scan log:
type "%APPDATA%\CyberFence\logs\scans-%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2%.jsonl" 2>nul || echo (no scan log yet - ClamAV may not be installed)
pause
