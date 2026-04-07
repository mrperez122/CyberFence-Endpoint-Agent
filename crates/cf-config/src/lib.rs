//! cf-config — configuration loader for the CyberFence agent.
//!
//! Reads `config.toml` from the platform-specific config directory,
//! validates all fields, and exposes a single `AgentConfig` struct
//! that all other crates depend on.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── MonitorConfig ─────────────────────────────────────────────────────────────

/// Configuration for the file monitoring component (cf-monitor).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Whether file monitoring is enabled at all.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Debounce window in milliseconds.
    /// Events that arrive within this window for the same path are merged.
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,

    /// Maximum number of unprocessed events to buffer before dropping oldest.
    #[serde(default = "default_ring_buffer_cap")]
    pub ring_buffer_cap: usize,

    /// Additional directories to watch beyond the defaults.
    #[serde(default)]
    pub extra_watch_dirs: Vec<PathBuf>,

    /// Paths to exclude from monitoring (exact prefix match).
    #[serde(default = "default_exclusions")]
    pub exclusions: Vec<PathBuf>,

    /// File extensions to skip entirely (without the dot, lowercase).
    #[serde(default = "default_excluded_extensions")]
    pub excluded_extensions: Vec<String>,

    /// Maximum file size in MB to consider for scanning.
    /// Files larger than this will be logged but marked Excluded.
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled:               true,
            debounce_ms:           250,
            ring_buffer_cap:       2000,
            extra_watch_dirs:      vec![],
            exclusions:            default_exclusions(),
            excluded_extensions:   default_excluded_extensions(),
            max_file_size_mb:      256,
        }
    }
}

// ── AgentConfig ───────────────────────────────────────────────────────────────

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Logging level: "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE"
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Directory where JSON log files are written.
    /// Defaults to the platform log directory.
    #[serde(default)]
    pub log_dir: Option<PathBuf>,

    /// File monitoring settings.
    #[serde(default)]
    pub monitor: MonitorConfig,

    /// Malware scanning settings.
    #[serde(default)]
    pub scanner: ScannerConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            log_level: "INFO".into(),
            log_dir:   None,
            monitor:   MonitorConfig::default(),
            scanner:   ScannerConfig::default(),
        }
    }
}

// ── Loader ────────────────────────────────────────────────────────────────────

impl AgentConfig {
    /// Load configuration from the given path.
    /// If the file does not exist, returns `AgentConfig::default()`.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "config.toml not found — using defaults"
            );
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;

        let config: AgentConfig = toml::from_str(&raw)
            .with_context(|| format!("parsing config from {}", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Load from the default platform-specific path.
    ///
    /// | Platform | Path                                               |
    /// |----------|----------------------------------------------------|
    /// | Windows  | `%PROGRAMDATA%\CyberFence\config.toml`             |
    /// | macOS    | `/etc/cyberfence/config.toml`                      |
    /// | Linux    | `/etc/cyberfence/config.toml`                      |
    pub fn load_default() -> Result<Self> {
        let path = default_config_path();
        Self::load(&path)
    }

    /// Validate all fields and return an error if anything is out of range.
    fn validate(&self) -> Result<()> {
        let valid_levels = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
        if !valid_levels.contains(&self.log_level.to_uppercase().as_str()) {
            anyhow::bail!(
                "Invalid log_level '{}'. Must be one of: {:?}",
                self.log_level,
                valid_levels
            );
        }
        if self.monitor.debounce_ms > 5000 {
            anyhow::bail!("monitor.debounce_ms must be <= 5000 ms");
        }
        if self.monitor.ring_buffer_cap < 10 {
            anyhow::bail!("monitor.ring_buffer_cap must be >= 10");
        }
        Ok(())
    }

    /// Return the resolved list of directories to monitor.
    /// Combines platform defaults with `extra_watch_dirs` from config.
    pub fn watch_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = default_watch_dirs();
        dirs.extend(self.monitor.extra_watch_dirs.clone());
        // Remove dirs that don't exist on this machine
        dirs.retain(|d| d.exists());
        dirs
    }
}

// ── Platform defaults ─────────────────────────────────────────────────────────

fn default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into());
        PathBuf::from(base).join("CyberFence").join("config.toml")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/cyberfence/config.toml")
    }
}

/// Default directories to watch. Expands environment variables at runtime.
pub fn default_watch_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".into());
        let user = PathBuf::from(user);
        let temp = std::env::var("TEMP")
            .or_else(|_| std::env::var("TMP"))
            .unwrap_or_else(|_| "C:\\Windows\\Temp".into());

        vec![
            user.join("Downloads"),
            user.join("Desktop"),
            user.join("Documents"),
            PathBuf::from(temp),
            user.join("AppData").join("Roaming").join("Microsoft")
                .join("Windows").join("Start Menu").join("Programs").join("Startup"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let home = PathBuf::from(home);
        vec![
            home.join("Downloads"),
            home.join("Desktop"),
            home.join("Documents"),
            PathBuf::from("/tmp"),
        ]
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let home = PathBuf::from(home);
        vec![
            home.join("Downloads"),
            home.join("Desktop"),
            home.join("Documents"),
            PathBuf::from("/tmp"),
        ]
    }
}

// ── serde defaults ────────────────────────────────────────────────────────────

fn default_true()                  -> bool           { true }
fn default_debounce_ms()           -> u64            { 250 }
fn default_ring_buffer_cap()       -> usize          { 2000 }
fn default_max_file_size_mb()      -> u64            { 256 }
fn default_log_level()             -> String         { "INFO".into() }

fn default_exclusions() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from("C:\\Windows\\SoftwareDistribution"),
            PathBuf::from("C:\\Windows\\Temp\\WinStore"),
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![PathBuf::from("/tmp/cyberfence")]
    }
}

fn default_excluded_extensions() -> Vec<String> {
    vec![
        "log".into(), "tmp".into(), "db-wal".into(),
        "db-shm".into(), "part".into(), "crdownload".into(),
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = AgentConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_log_level_fails_validation() {
        let mut config = AgentConfig::default();
        config.log_level = "VERBOSE".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn debounce_too_high_fails_validation() {
        let mut config = AgentConfig::default();
        config.monitor.debounce_ms = 9999;
        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_toml_string() {
        let toml_str = r#"
            log_level = "DEBUG"
            [monitor]
            debounce_ms = 300
            max_file_size_mb = 100
        "#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.log_level, "DEBUG");
        assert_eq!(config.monitor.debounce_ms, 300);
        assert_eq!(config.monitor.max_file_size_mb, 100);
    }
}

// ── ScannerConfig ─────────────────────────────────────────────────────────────

/// Configuration for the scanning engine (cf-scanner).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Whether scanning is enabled. When false, FileEvents are still logged
    /// but not passed to ClamAV.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to the `clamscan` (or `clamscan.exe`) binary.
    /// Leave empty to auto-detect from PATH.
    #[serde(default)]
    pub clamscan_path: Option<std::path::PathBuf>,

    /// Path to the ClamAV virus definitions directory.
    /// Leave empty to use the ClamAV default.
    #[serde(default)]
    pub definitions_dir: Option<std::path::PathBuf>,

    /// Maximum file size in MB to scan. Larger files are marked Skipped.
    #[serde(default = "default_scan_max_mb")]
    pub max_file_size_mb: u64,

    /// Timeout in seconds for a single file scan.
    /// Prevents the agent from hanging on corrupted/malicious archives.
    #[serde(default = "default_scan_timeout_secs")]
    pub timeout_secs: u64,

    /// Number of parallel scan workers.
    /// 0 = use half the available CPU cores.
    #[serde(default)]
    pub worker_threads: usize,

    /// Whether to scan inside archives (.zip, .tar, .gz, etc.)
    #[serde(default = "default_true")]
    pub scan_archives: bool,

    /// Paths to include in a full/quick scan (in addition to watch dirs).
    #[serde(default)]
    pub full_scan_paths: Vec<std::path::PathBuf>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled:          true,
            clamscan_path:    None,
            definitions_dir:  None,
            max_file_size_mb: 256,
            timeout_secs:     30,
            worker_threads:   0,
            scan_archives:    true,
            full_scan_paths:  vec![],
        }
    }
}

fn default_scan_max_mb()      -> u64 { 256 }
fn default_scan_timeout_secs() -> u64 { 30 }
