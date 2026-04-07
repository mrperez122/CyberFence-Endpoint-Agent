CyberFence Endpoint Protection Agent v0.1.0
==========================================
Windows Prototype - April 2026

QUICK START
-----------
1. Right-click install.bat → Run as Administrator
2. Install ClamAV for malware scanning:
   choco install clamav -y
   freshclam.exe
3. Run test-eicar.bat to validate detection works
4. Launch the Dashboard UI separately (see below)

WHAT THIS DOES
--------------
- Watches Downloads, Desktop, Documents, Temp in real-time
- Scans every new/modified file using the CyberFence Engine
- Quarantines infected files (AES-256-GCM encrypted)
- Logs all events to %APPDATA%\CyberFence\logs\
- Exposes status via \\.\pipe\CyberFenceAgent for the dashboard UI

FILES
-----
cf-agent.exe   - Background service binary (Windows x64)
install.bat    - Installs and starts the Windows Service
uninstall.bat  - Removes the service
test-eicar.bat - Creates a safe EICAR test file to validate scanning
config.toml    - Default configuration (copied to %ProgramData%\CyberFence\)
README.txt     - This file

SERVICE MANAGEMENT
------------------
Start:   sc start CyberFenceAgent
Stop:    sc stop CyberFenceAgent
Status:  sc query CyberFenceAgent
Logs:    %APPDATA%\CyberFence\logs\

CONFIGURATION
-------------
Edit %ProgramData%\CyberFence\config.toml
Key settings:
  log_level = "INFO"     (ERROR/WARN/INFO/DEBUG)
  [monitor]
  debounce_ms = 250
  [scanner]
  enabled = true

DASHBOARD UI
------------
The dashboard requires Node.js + Tauri. Build from source:
  cd ui
  npm install
  npm run tauri build
  (or: npm run tauri dev  for development mode)

VALIDATION TEST
---------------
1. Run install.bat
2. Run test-eicar.bat
3. Within 3 seconds:
   - eicar_test.com disappears from Downloads
   - Windows notification appears
   - Log entry: {"verdict":"INFECTED","threatName":"Eicar-Signature"}

REQUIREMENTS
------------
- Windows 10 version 1903+ (x64)
- ClamAV (for scanning): https://www.clamav.net/downloads
- Admin rights for service installation

REPOSITORY
----------
https://github.com/mrperez122/CyberFence-Endpoint-Agent
