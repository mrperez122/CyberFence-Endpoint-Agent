//! Windows Service integration for the CyberFence Endpoint Agent.
//!
//! This module provides everything needed to run `cf-agent.exe` as a
//! proper Windows Service controlled by the Service Control Manager (SCM).
//!
//! # Service lifecycle
//!
//! ```text
//! SCM                  cf-agent.exe
//!  │                       │
//!  │  StartService()        │
//!  ├──────────────────────►│  ffi_service_main() called by SCM
//!  │                       │  ↓ registers service_main with SCM
//!  │                       │  ↓ calls our async_service_main()
//!  │                       │  ↓ starts tokio runtime
//!  │                       │  ↓ spawns all agent tasks
//!  │                       │  ↓ reports SERVICE_RUNNING to SCM
//!  │  ControlService(STOP)  │
//!  ├──────────────────────►│  control_handler(Stop) called
//!  │                       │  ↓ sets shutdown flag
//!  │                       │  ↓ tasks drain + exit
//!  │                       │  ↓ reports SERVICE_STOPPED to SCM
//! ```
//!
//! # Installation (run as Administrator)
//!
//! ```cmd
//! sc create CyberFenceAgent binPath= "C:\Program Files\CyberFence\cf-agent.exe" start= auto
//! sc description CyberFenceAgent "CyberFence Endpoint Protection — real-time file monitoring and malware scanning"
//! sc start CyberFenceAgent
//! ```
//!
//! # Uninstall
//!
//! ```cmd
//! sc stop CyberFenceAgent
//! sc delete CyberFenceAgent
//! ```

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use tracing::{error, info};

// ── Service constants ──────────────────────────────────────────────────────────
const SERVICE_NAME: &str = "CyberFenceAgent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// ── Windows Service entry point ───────────────────────────────────────────────

// Registers `ffi_service_main` as the entry point the SCM calls.
// This macro generates the extern "system" glue needed by the SCM.
define_windows_service!(ffi_service_main, cf_service_main);

/// Called by the SCM when the service is started.
/// Runs the tokio runtime and all agent tasks.
fn cf_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("Service exited with error: {}", e);
    }
}

fn run_service() -> windows_service::Result<()> {
    // Channel for the SCM control handler to signal shutdown
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Register with the SCM. This gives us a status handle to update.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("SCM Stop/Shutdown received — initiating graceful shutdown");
                // Signal the runtime to stop
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report to SCM: we are starting
    status_handle.set_service_status(ServiceStatus {
        service_type:    SERVICE_TYPE,
        current_state:   ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code:       ServiceExitCode::Win32(0),
        checkpoint:      0,
        wait_hint:       Duration::from_secs(10),
        process_id:      None,
    })?;

    // Build the tokio runtime and run the agent
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("cf-agent-worker")
        .enable_all()
        .build()
        .map_err(|e| {
            error!("Failed to build tokio runtime: {}", e);
            windows_service::Error::Winapi(std::io::Error::from(
                std::io::ErrorKind::Other,
            ))
        })?;

    // Report to SCM: we are running
    status_handle.set_service_status(ServiceStatus {
        service_type:     SERVICE_TYPE,
        current_state:    ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code:        ServiceExitCode::Win32(0),
        checkpoint:       0,
        wait_hint:        Duration::ZERO,
        process_id:       None,
    })?;

    info!("CyberFence Agent service started — SCM status: RUNNING");

    // Run the agent's async main, waiting for either completion or SCM stop
    runtime.block_on(async move {
        // Spawn the main agent logic
        let agent_handle = tokio::spawn(crate::run_agent());

        // Wait for SCM stop signal (blocking recv on std channel in background)
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            let _ = shutdown_rx.recv(); // blocks until SCM sends Stop
            let _ = stop_tx.send(());
        });

        tokio::select! {
            _ = &mut stop_rx => {
                info!("SCM stop signal received — agent shutting down");
            }
            result = agent_handle => {
                match result {
                    Ok(Err(e)) => error!("Agent task returned error: {}", e),
                    Err(e)     => error!("Agent task panicked: {}", e),
                    Ok(Ok(())) => info!("Agent task completed normally"),
                }
            }
        }
    });

    // Report to SCM: we have stopped
    status_handle.set_service_status(ServiceStatus {
        service_type:     SERVICE_TYPE,
        current_state:    ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code:        ServiceExitCode::Win32(0),
        checkpoint:       0,
        wait_hint:        Duration::ZERO,
        process_id:       None,
    })?;

    info!("CyberFence Agent service stopped cleanly");
    Ok(())
}

/// Attempt to start the process as a Windows Service.
/// Returns `Ok(true)` if the service dispatcher took over (we are running as a service).
/// Returns `Ok(false)` if we are NOT running as a service (console/dev mode).
pub fn try_start_as_service() -> windows_service::Result<bool> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) means we are NOT
        // running under the SCM — fall through to console mode.
        Err(windows_service::Error::Winapi(ref e))
            if e.raw_os_error() == Some(1063) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
