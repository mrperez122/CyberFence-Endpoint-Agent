# CyberFence Endpoint Protection — Integration Guide

This document explains how the three prototype components connect into a
working Windows prototype, how to run it, and how to validate end-to-end behavior.

---

## How the Components Communicate

```
┌──────────────────────────────────────────────────────────────────────┐
│                         cf-agent.exe                                  │
│                                                                        │
│  OS kernel (ReadDirectoryChangesW)                                     │
│     ↓ file event                                                       │
│  cf-monitor::FileMonitor                                               │
│     ↓ FileEvent [tokio MPSC, cap=2000]                                │
│  EventFanout                                                           │
│     ├──► cf-logger::EventLogger  → agent-YYYY-MM-DD.jsonl (audit)     │
│     └──► cf-scanner::ScanEngine → CyberFence Engine (clamscan.exe)    │
│              ↓ ScanResult                                               │
│          IntegrationWorker                                             │
│              ├──► scan_logger  → scans-YYYY-MM-DD.jsonl               │
│              ├──► AgentState   → in-memory threat/history list         │
│              └──► IpcServer   → ThreatAlert push event                │
│                                                                        │
│  IpcServer ◄──[ \\.\pipe\CyberFenceAgent ]──► Tauri UI               │
│     Commands:  GetStatus, GetThreats, RunQuickScan, …                  │
│     Events:    ThreatAlert, ScanProgress, ScanComplete                 │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
         ↑
    Windows SCM (auto-start on boot)
```

### Channel topology

| Channel | Type | Producer | Consumer |
|---------|------|----------|----------|
| `monitor_tx` | `mpsc<FileEvent>` | FileMonitor | EventFanout |
| `logger_tx` | `mpsc<FileEvent>` | EventFanout | EventLogger |
| `scanner_tx` | `mpsc<FileEvent>` | EventFanout | ScanEngine |
| `result_tx` | `mpsc<ScanResult>` | ScanEngine | IntegrationWorker |
| `scan_trigger_tx` | `mpsc<ScanTrigger>` | IpcServer handler | Scheduler task |
| IPC named pipe | `\\.\pipe\CyberFenceAgent` | Tauri UI | IpcServer |
| IPC broadcast | `broadcast<AgentEvent>` | IntegrationWorker | All UI clients |

### How file events trigger scans

1. `notify-rs` detects a file change via `ReadDirectoryChangesW`
2. `cf-monitor` debounces (250ms), applies exclusion rules, emits `FileEvent`
3. `EventFanout` clones the event to both `logger_tx` and `scanner_tx`
4. `ScanEngine` checks `event.is_scannable()` — only Created/Modified/Renamed pass
5. `tokio::task::spawn_blocking` runs `clamscan.exe` as a subprocess
6. `ScanResult { verdict: Infected("Win.Trojan.Generic"), duration_ms: 842 }` emitted
7. `IntegrationWorker` receives it:
   - Writes to `scans-2026-04-07.jsonl`
   - Calls `AgentState::record_threat()`
   - Broadcasts `AgentEvent::ThreatAlert` to connected UI clients

### How the UI gets data

**Two independent paths** — both work simultaneously:

| Path | When used | Latency |
|------|-----------|---------|
| Named pipe | UI is open, agent is running | < 1ms |
| JSONL log files | UI opens after detection, agent restarted | Reads disk |

The named pipe path (`IpcClient::get_threats()`) reads `AgentState` in memory.
The log file path (`log_reader::read_recent_scans()`) parses `scans-*.jsonl`.
If the pipe is not available, the Tauri `commands.rs` automatically falls back to log files.

---

## Prerequisites

### Windows (required)

```powershell
# 1. Rust stable
winget install Rustlang.Rustup
# or: https://rustup.rs

# 2. Node.js 18+ (for dashboard UI)
winget install OpenJS.NodeJS

# 3. CyberFence Engine (ClamAV)
choco install clamav -y
# Download virus definitions (required before first scan):
freshclam.exe

# 4. Tauri CLI (for dashboard)
npm install -g @tauri-apps/cli
```

### macOS / Linux (development only)

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# ClamAV (macOS)
brew install clamav
cp /opt/homebrew/etc/clamav/freshclam.conf.sample \
   /opt/homebrew/etc/clamav/freshclam.conf
# Remove "Example" line, then:
freshclam

# ClamAV (Ubuntu)
sudo apt install clamav && sudo freshclam
```

---

## Running the Full Prototype

### Option A — Console mode (development, any OS)

Run all three components manually in separate terminals:

**Terminal 1 — Start the agent**
```bash
cd cyberfence-endpoint-agent
RUST_LOG=debug cargo run --bin cf-agent
```

Expected output:
```
INFO CyberFence Endpoint Agent starting version=0.1.0
INFO Resolved watch directories dirs=[".../Downloads", ".../Desktop", ".../Documents"]
INFO CyberFence Engine (clamscan) found at ... path=...
INFO ScanEngine started — waiting for file events
INFO IPC server listening (Unix socket) path=/tmp/cyberfence/agent.sock
INFO CyberFence agent fully started
```

**Terminal 2 — Start the dashboard UI**
```bash
cd cyberfence-endpoint-agent/ui
npm install
npm run tauri dev
```

The UI opens automatically. On Windows it also creates a tray icon.

**Terminal 3 — Trigger a test event**
```bash
# macOS / Linux
touch ~/Downloads/test.exe
echo "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" \
  > ~/Downloads/eicar.com

# Windows
echo X > %USERPROFILE%\Downloads\test.exe
```

### Option B — Windows Service (production)

```powershell
# Build release binary
cargo build --release --bin cf-agent

# Install as Windows Service (run as Administrator)
New-Item -ItemType Directory -Force -Path "C:\Program Files\CyberFence"
Copy-Item .\target\release\cf-agent.exe "C:\Program Files\CyberFence\"
Copy-Item .\config.toml "$env:PROGRAMDATA\CyberFence\config.toml"

sc.exe create CyberFenceAgent `
    binPath= '"C:\Program Files\CyberFence\cf-agent.exe"' `
    start= auto `
    DisplayName= "CyberFence Endpoint Agent"

sc.exe description CyberFenceAgent "CyberFence Endpoint Protection"
sc.exe start CyberFenceAgent

# Build and launch the dashboard UI
cd ui
npm install
npm run tauri build
.\src-tauri\target\release\cyberfence-ui.exe
```

---

## Validating End-to-End Behavior

### Test 1 — File event detection

```bash
# Create a file in a watched directory
touch ~/Downloads/test_event.pdf
```

Expected: Within 1 second, log entry appears:
```json
{"level":"INFO","message":"FILE_EVENT","kind":"CREATED","path":"...test_event.pdf","scan_readiness":"PendingScan","is_scannable":true}
```

Dashboard: files_monitored_today counter increments.

### Test 2 — EICAR malware detection (safe test file)

```bash
# The EICAR string is universally detected as "Eicar-Signature"
# It is NOT real malware — completely safe to create
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > ~/Downloads/eicar.com
```

Expected within 3 seconds:
1. `ERROR MALWARE DETECTED verdict=INFECTED virus=Eicar-Signature path=.../eicar.com`
2. `scans-YYYY-MM-DD.jsonl` entry: `{"verdict":"INFECTED","threatName":"Eicar-Signature","action":"QUARANTINED"}`
3. `eicar.com` deleted from Downloads
4. Encrypted `.cfq` file appears in quarantine vault
5. Dashboard Threats view shows the detection
6. Windows toast notification: "🚨 Threat Detected — Eicar-Signature"
7. Tray icon turns red

### Test 3 — Clean file (no alert)

```bash
echo "Hello, world! This is a normal document." > ~/Documents/notes.txt
```

Expected: File scanned (DEBUG log), no alert, no quarantine. Dashboard not updated.

### Test 4 — Dashboard quick scan

1. Open dashboard → click "Quick Scan"
2. UI sends `RunQuickScan` command via named pipe
3. Agent logs: `UI requested quick scan`
4. Scan runs across Downloads, Desktop, Documents
5. Dashboard shows progress bar

### Test 5 — Excluded file (not scanned)

```bash
echo "rotation" > ~/Downloads/debug.log
```

Expected: No FileEvent logged (`.log` is excluded by default).

### Test 6 — Service restart (Windows)

```powershell
sc.exe stop CyberFenceAgent
sc.exe start CyberFenceAgent
sc.exe query CyberFenceAgent  # → STATE: RUNNING within 10 seconds
```

---

## Log Locations

| File | Contents | Location |
|------|----------|----------|
| `agent-YYYY-MM-DD.jsonl` | File events (monitor audit trail) | `%APPDATA%\CyberFence\logs\` |
| `scans-YYYY-MM-DD.jsonl` | Scan results (verdict, threat name, action) | `%APPDATA%\CyberFence\logs\` |
| `quarantine/` | Encrypted `.cfq` vault files | `%APPDATA%\CyberFence\quarantine\` |

Read logs in PowerShell:
```powershell
# Stream scan results in real-time
Get-Content "$env:APPDATA\CyberFence\logs\scans-$(Get-Date -f yyyy-MM-dd).jsonl" -Wait |
  ForEach-Object { $_ | ConvertFrom-Json | Format-List }
```

---

## Architecture for Future Extensions

The prototype is pre-wired for two future integrations:

### CrowdSec threat intelligence (Phase 3)

Add `cf-crowdsec` crate. In `IntegrationWorker`, after a scan result arrives:
```rust
if is_threat {
    let score = crowdsec_client.check_hash(&sha256).await;
    // enrich ThreatPayload with crowdsec_score before recording
}
```

The `ThreatPayload` struct already has room for the score field.

### CyberFence cloud backend (Phase 4)

Add a `cloud_sync` task in `run_agent()`:
```rust
let cloud_sync = tokio::spawn(async move {
    // POST scan results to CyberFence API via mTLS
    // Receive policy updates + signature definitions
});
```

The `AgentState` and `IpcServer` don't change — only a new background task is added.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| "CyberFence Engine not found" warning | ClamAV not installed or not in PATH | `choco install clamav -y` then `freshclam` |
| "Cannot connect to IPC pipe" in UI | Agent not running | `sc start CyberFenceAgent` or `cargo run --bin cf-agent` |
| No scan results after file creation | File excluded by config | Check `excluded_extensions` in config.toml |
| EICAR not detected | Definitions not downloaded | Run `freshclam.exe` |
| High CPU during full scan | Normal — clamscan is CPU-bound | Default: CPU/2 workers; reduce with `scanner.worker_threads = 1` |
