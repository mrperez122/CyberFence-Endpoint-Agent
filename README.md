# CyberFence Endpoint Agent

Real-time endpoint protection agent for Windows and macOS, built with Rust and Tauri 2. Developed by **Perez Technology Group (PTG)** as part of the CyberFence security platform.

---

## Overview

The CyberFence Endpoint Agent monitors the local filesystem and system events in real time, correlating threat signals against the CrowdSec intelligence network. A native desktop UI (Tauri 2) surfaces alerts, agent status, and configuration options to the end user.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Rust (multi-crate workspace) |
| Desktop UI | Tauri 2 |
| Threat Intelligence | CrowdSec |
| Platform | Windows, macOS |

---

## Workspace Crates

| Crate | Purpose |
|---|---|
| `cf-common` | Shared event types, error definitions, and data structures |
| `cf-config` | Configuration loader — reads and validates agent config files |
| `cf-monitor` | Filesystem monitor — watches paths for suspicious activity |
| `cf-logger` | Structured logging — outputs JSON-formatted logs for SIEM ingestion |

---

## Repository Structure

```
CyberFence-Endpoint-Agent/
├── Cargo.toml                # Workspace manifest
├── cf-common/
│   └── src/lib.rs            # Shared types and events
├── cf-config/
│   └── src/lib.rs            # Config parsing
├── cf-monitor/
│   └── src/lib.rs            # Filesystem monitoring logic
├── cf-logger/
│   └── src/lib.rs            # Structured logging
├── src-tauri/                # Tauri 2 shell (desktop UI)
│   ├── src/
│   ├── tauri.conf.json
│   └── Cargo.toml
├── ui/                       # Frontend for Tauri window
│   └── src/
└── package.json
```

---

## Setup Instructions

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [Node.js](https://nodejs.org/) 18+
- [Tauri CLI v2](https://tauri.app/start/prerequisites/)
- Windows: Microsoft C++ Build Tools
- macOS: Xcode Command Line Tools
- A CrowdSec account (for threat intelligence API key)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/mrperez122/CyberFence-Endpoint-Agent.git
   cd CyberFence-Endpoint-Agent
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Configure the agent:
   ```bash
   cp config.example.toml config.toml
   ```
   Set your CrowdSec API key and monitored paths in `config.toml`.

4. Run in development mode:
   ```bash
   npm run tauri dev
   ```

5. Build for production:
   ```bash
   npm run tauri build
   ```
   Output installers will be in `src-tauri/target/release/bundle/`.

---

## CrowdSec Integration

The agent queries the [CrowdSec](https://www.crowdsec.net/) Central API to enrich local events with globally-sourced threat intelligence. IP addresses and behavioral patterns observed on the endpoint are cross-referenced against CrowdSec's community blocklists.

---

## CyberFence Platform

| Repository | Description |
|---|---|
| [CyberFence-For-Flutter](https://github.com/mrperez122/CyberFence-For-Flutter) | Active iOS + Android app |
| [CyberFence-for-Mac](https://github.com/mrperez122/CyberFence-for-Mac) | Native macOS app |
| [Cyberfence-Analytics-Web-App](https://github.com/mrperez122/Cyberfence-Analytics-Web-App) | Analytics dashboard |

**Website:** [https://cyberfenceplatform.com](https://cyberfenceplatform.com)  
**Support:** support@cyberfenceplatform.com

---

*Perez Technology Group (PTG) — Orlando, FL*
