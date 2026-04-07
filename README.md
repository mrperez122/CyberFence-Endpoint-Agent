# CyberFence Endpoint Protection Agent

Real-time endpoint protection agent for Windows and macOS.  
Built with Rust · Tauri · ClamAV · CrowdSec

---

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| `cf-common` | ✅ Complete | Shared event types, errors |
| `cf-config` | ✅ Complete | TOML config loader + validation |
| `cf-monitor` | ✅ Complete | Real-time file system monitoring |
| `cf-logger` | ✅ Complete | Structured JSON logging |
| `cf-agent` | ✅ Complete | Main binary — wires everything together |
| `cf-scanner` | 🔜 Phase 2 | ClamAV integration |
| `cf-heuristics` | 🔜 Phase 2 | Behavioral rule engine |
| `cf-broker` | 🔜 Phase 2 | Threat aggregation |
| `cf-crowdsec` | 🔜 Phase 2 | Threat intelligence |
| `cf-ui` | 🔜 Phase 3 | Tauri dashboard |

---

## Architecture

```
OS Kernel (inotify / ReadDirectoryChangesW / FSEvents)
    ↓
cf-monitor::watcher        ← notify-rs OS watcher
    ↓  raw Event
cf-monitor::filter         ← exclusion rules, size limits
    ↓  FileEvent
tokio MPSC channel         ← bounded, backpressure-safe
    ↓
cf-logger::EventLogger     ← JSONL audit log
    ↓  (Phase 2)
cf-scanner                 ← ClamAV FFI scan
    ↓  (Phase 2)
cf-broker                  ← threat aggregation + quarantine
```

---

## Quick Start

### Prerequisites

- [Rust stable](https://rustup.rs/) (1.76+)
- Windows 10/11 or macOS 12+

### Run (dev mode)

```bash
# Clone the repo
git clone https://github.com/mrperez122/CyberFence-Endpoint-Agent
cd CyberFence-Endpoint-Agent

# Run with debug logging
RUST_LOG=debug cargo run --bin cf-agent

# Or use INFO level (less noise)
cargo run --bin cf-agent
```

The agent will start watching your **Downloads**, **Desktop**, and **Documents** directories and log every file change to stdout and to the log file.

### Test it

While the agent is running, open another terminal and:

```bash
# macOS / Linux
touch ~/Downloads/test-malware-sample.exe
echo "hello" > ~/Desktop/suspicious.ps1
rm ~/Downloads/test-malware-sample.exe
```

You will see structured log output like:

```json
{"timestamp":"2026-04-07T01:00:00Z","level":"INFO","message":"FILE_EVENT","event_id":"550e8400...","kind":"CREATED","path":"/Users/carlos/Downloads/test-malware-sample.exe","extension":"exe","scan_readiness":"PendingScan","is_scannable":true}
```

### Run tests

```bash
cargo test --workspace
```

### Lint

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

---

## Configuration

Copy `config.toml` to the platform config directory:

| Platform | Path |
|----------|------|
| Windows  | `%PROGRAMDATA%\CyberFence\config.toml` |
| macOS    | `/etc/cyberfence/config.toml` |
| Dev      | Project root (loaded automatically) |

Key settings:

```toml
log_level = "INFO"                  # TRACE/DEBUG/INFO/WARN/ERROR

[monitor]
debounce_ms       = 250             # merge burst events on same file
ring_buffer_cap   = 2000            # max queued unprocessed events
max_file_size_mb  = 256             # skip very large files
excluded_extensions = ["log", "tmp", "db-wal"]
```

---

## Project Structure

```
cyberfence-endpoint-agent/
├── Cargo.toml                   # workspace root
├── config.toml                  # default config (dev)
├── crates/
│   ├── cf-common/               # shared types: FileEvent, Severity, CfError
│   ├── cf-config/               # TOML config loader + platform path resolution
│   ├── cf-monitor/              # file watcher (notify-rs), filter, debounce
│   └── cf-logger/               # tracing subscriber + EventLogger
└── agent/
    └── src/main.rs              # binary entry point
```

---

## Log Output

Logs are written to:

| Platform | Path |
|----------|------|
| Windows  | `%APPDATA%\CyberFence\logs\agent-YYYY-MM-DD.jsonl` |
| macOS    | `~/Library/Logs/CyberFence/agent-YYYY-MM-DD.jsonl` |
| Linux    | `/tmp/cyberfence/logs/agent-YYYY-MM-DD.jsonl` |

Each line is a JSON object. Use `jq` to parse:

```bash
tail -f ~/Library/Logs/CyberFence/agent-$(date +%Y-%m-%d).jsonl | jq '.'
```

---

## Phase 2 Integration Points

The file monitoring output is already structured for scanner integration.
Each `FileEvent` has:

- `is_scannable()` → returns `true` for Created/Modified/Renamed files that exist
- `scan_readiness` → `PendingScan` | `Excluded` | `FileGone`
- `path` + `size_bytes` → ready to pass to ClamAV `cl_scanfile()`
- `id` + `timestamp` → for correlation with scan results in SQLite

Phase 2 will add `cf-scanner` as a second consumer of the MPSC channel
via the `EventFanout` broadcaster (already stubbed in `cf-logger::event_logger`).

---

## License

UNLICENSED — Proprietary. © 2026 CyberFence / Perez Technology Group.
