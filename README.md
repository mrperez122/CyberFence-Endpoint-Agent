# CyberFence Endpoint Protection Agent

Real-time endpoint protection for Windows and macOS.
Built with **Rust** · **Tauri 2** · **CyberFence Engine** · **CrowdSec**

---

## Current Status

| Component | Crate | Status | Phase |
|-----------|-------|--------|-------|
| Shared event types | `cf-common` | ✅ Complete | 1 |
| Config loader | `cf-config` | ✅ Complete | 1 |
| File system monitor | `cf-monitor` | ✅ Complete | 1 |
| Structured logger | `cf-logger` | ✅ Complete | 1 |
| Windows background service | `agent/service.rs` | ✅ Complete | 2 |
| CyberFence scan engine | `cf-scanner` | ✅ Complete | 2 |
| Heuristics engine | `cf-heuristics` | 🔜 Sprint 4 | 2 |
| Threat broker | `cf-broker` | 🔜 Sprint 4 | 2 |
| Tauri dashboard UI | `ui/` | 🔜 Sprint 7 | 3 |

---

## Architecture

```
Windows SCM / Ctrl-C
  ↓
agent/src/main.rs        ← dual-mode: service OR console
  ↓
run_agent()              ← tokio multi-thread runtime
  ├─ FileMonitor         ← notify-rs → ReadDirectoryChangesW
  │     ↓ FileEvent [MPSC, cap=2000]
  ├─ EventFanout         ← fan-out to multiple consumers
  │     ├─ EventLogger   ← JSONL audit log to disk
  │     └─ ScanEngine    ← CyberFence Engine (ClamAV subprocess)
  │            ↓ ScanResult
  └─ ScanResultWorker    ← log threats, future: quarantine + broker
```

---

## Quick Start

### Prerequisites

- [Rust stable](https://rustup.rs/) 1.76+
- Windows 10/11 (for service mode) or any OS (for console mode)
- CyberFence Engine (ClamAV) — see [Engine Setup](#cyberFence-engine-setup) below

### Run in console mode (development)

```bash
# Clone
git clone https://github.com/mrperez122/CyberFence-Endpoint-Agent
cd CyberFence-Endpoint-Agent

# Run with debug logging
RUST_LOG=debug cargo run --bin cf-agent

# Or default INFO level
cargo run --bin cf-agent
```

The agent starts monitoring **Downloads**, **Desktop**, and **Documents** immediately.
Drop a file into any of those directories — you will see structured log output.

### Run all tests

```bash
cargo test --workspace
```

### Run integration tests (file monitoring)

```bash
cargo test --test monitor_integration -- --nocapture
```

Integration tests use real temp directories and verify:
- File created → `FileEvent::Created` received within 3 seconds
- File deleted → `FileEvent::Deleted` received
- `.log` extension → event filtered out (excluded)
- `.exe` created → `is_scannable()` returns `true`
- Multiple events → all IDs are unique UUIDs

---

## Windows Background Service

### Install as Windows Service (run as Administrator)

```cmd
REM Build the release binary first
cargo build --release --bin cf-agent

REM Copy to install location
mkdir "C:\Program Files\CyberFence"
copy target\release\cf-agent.exe "C:\Program Files\CyberFence\"
copy config.toml "%PROGRAMDATA%\CyberFence\config.toml"

REM Register with Windows Service Control Manager
sc create CyberFenceAgent ^
    binPath= "\"C:\Program Files\CyberFence\cf-agent.exe\"" ^
    start= auto ^
    DisplayName= "CyberFence Endpoint Agent"

sc description CyberFenceAgent "CyberFence Endpoint Protection — real-time file monitoring and malware scanning"

REM Start the service
sc start CyberFenceAgent
```

### Verify it's running

```cmd
sc query CyberFenceAgent
```

Expected output:
```
SERVICE_NAME: CyberFenceAgent
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
```

### View logs

```cmd
REM View today's log
type "%APPDATA%\CyberFence\logs\agent-2026-04-07.jsonl"

REM Stream logs in real-time (PowerShell)
Get-Content "%APPDATA%\CyberFence\logs\agent-2026-04-07.jsonl" -Wait
```

### Stop and uninstall

```cmd
sc stop CyberFenceAgent
sc delete CyberFenceAgent
```

---

## Dual-Mode Detection

The binary auto-detects whether it's running as a Windows Service or in console mode:

```
cf-agent.exe launched
    │
    ├─ Is the SCM trying to start us?
    │   YES → service::try_start_as_service() → SCM takes over → run_agent()
    │   NO  → console mode → build tokio runtime directly → run_agent()
    └─────────────────────────────────────────────────────────────────────
```

**Development:** just `cargo run` — always console mode, Ctrl-C to stop.
**Production:** `sc start CyberFenceAgent` — service mode, controlled by SCM.

---

## CyberFence Engine Setup

### Windows

```cmd
REM Using Chocolatey
choco install clamav -y

REM Download definitions (required before first scan)
freshclam.exe
```

### macOS

```bash
brew install clamav
cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
# Remove the "Example" line from freshclam.conf, then:
freshclam
```

If ClamAV is not found, the agent runs in **monitor-only mode**:
file events are logged but not scanned. A `WARN` is written to the log.

---

## Configuration

Copy `config.toml` to the platform config directory:

| Platform | Path |
|----------|------|
| Windows | `%PROGRAMDATA%\CyberFence\config.toml` |
| macOS | `/etc/cyberfence/config.toml` |
| Dev | Project root (auto-loaded) |

Key settings:

```toml
log_level = "INFO"   # TRACE / DEBUG / INFO / WARN / ERROR

[monitor]
debounce_ms      = 250    # merge burst events on the same file
ring_buffer_cap  = 2000   # max queued unprocessed events
max_file_size_mb = 256    # skip very large files from scanning

[scanner]
enabled          = true   # set false to disable scanning entirely
timeout_secs     = 30     # per-file scan timeout
```

---

## Log Output

Every file event is written as one JSON line:

```jsonc
{
  "timestamp": "2026-04-07T14:00:00.123Z",
  "level": "INFO",
  "target": "cf_logger::event_logger",
  "message": "FILE_EVENT",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "kind": "CREATED",
  "path": "C:\\Users\\Carlos\\Downloads\\setup.exe",
  "extension": "exe",
  "size_bytes": 2048576,
  "watch_root": "C:\\Users\\Carlos\\Downloads",
  "scan_readiness": "PendingScan",
  "is_scannable": true
}
```

Parse with `jq`:

```bash
# macOS / Linux dev
tail -f /tmp/cyberfence/logs/agent-$(date +%Y-%m-%d).jsonl | jq '.'

# Windows PowerShell
Get-Content "$env:APPDATA\CyberFence\logs\agent-$(Get-Date -f yyyy-MM-dd).jsonl" -Wait |
    ForEach-Object { $_ | ConvertFrom-Json }
```

---

## Project Structure

```
cyberfence-endpoint-agent/
├── Cargo.toml                     workspace root
├── config.toml                    default config (dev)
│
├── crates/
│   ├── cf-common/                 FileEvent, ScanResult, CfError, Severity
│   ├── cf-config/                 TOML config + platform path resolution
│   ├── cf-monitor/                file watcher (notify-rs, filter, debounce)
│   ├── cf-scanner/                CyberFence Engine + quarantine
│   └── cf-logger/                 tracing subscriber + JSONL log
│
├── agent/
│   ├── src/
│   │   ├── main.rs                entry point — dual console/service mode
│   │   └── service.rs             Windows Service wrapper (SCM integration)
│   └── tests/
│       └── monitor_integration.rs integration tests (real FS operations)
│
└── ui/                            Tauri 2 dashboard (Phase 3)
```

---

## Phase 3 Integration Points

The file monitor is pre-wired for the scanner and UI:

- `FileEvent.is_scannable()` → scanner reads this to decide whether to process
- `ScanReadiness::PendingScan` → pre-tagged on every scannable event
- `EventFanout` → already broadcasts to scanner channel; add UI channel in Phase 3
- Named pipe IPC server (`agent/ipc_server.rs`) — stub ready for Phase 3

---

## License

UNLICENSED — Proprietary. © 2026 CyberFence / Perez Technology Group.
