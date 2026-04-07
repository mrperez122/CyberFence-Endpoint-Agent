//! ClamAV subprocess adapter.
//!
//! Wraps the `clamscan` CLI to scan a single file and parse the result.
//!
//! # How ClamAV is installed
//!
//! ## Windows
//! 1. Download from https://www.clamav.net/downloads
//! 2. Run the installer (adds `clamscan.exe` to Program Files)
//! 3. Run `freshclam.exe` once to download virus definitions
//! 4. Optionally add `C:\Program Files\ClamAV` to PATH
//!
//! ## macOS
//! ```bash
//! brew install clamav
//! cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
//! # Remove the Example line from freshclam.conf, then:
//! freshclam
//! ```
//!
//! ## Linux (dev/test)
//! ```bash
//! sudo apt install clamav clamav-daemon
//! sudo freshclam
//! ```
//!
//! # clamscan output format
//!
//! Clean file:
//! ```text
//! /path/to/file.txt: OK
//! ```
//!
//! Infected file:
//! ```text
//! /path/to/eicar.com: Eicar-Signature FOUND
//! ```
//!
//! Suspicious (heuristic):
//! ```text
//! /path/to/file.exe: Heuristics.Broken.Executable FOUND
//! ```

use cf_common::scan::ScanVerdict;
use cf_config::ScannerConfig;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Locate the `clamscan` binary on this system.
/// Priority:
///   1. Explicit path in ScannerConfig
///   2. Common Windows install paths
///   3. PATH lookup via `which`/`where`
pub fn find_clamscan(config: &ScannerConfig) -> Option<PathBuf> {
    // 1. Explicit config path
    if let Some(ref p) = config.clamscan_path {
        if p.exists() {
            return Some(p.clone());
        }
    }

    // 2. Windows default install locations
    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files (x86)\ClamAV\clamscan.exe",
        ];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // 3. macOS Homebrew default
    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/opt/homebrew/bin/clamscan",
            "/usr/local/bin/clamscan",
            "/usr/bin/clamscan",
        ];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // 4. Linux / fallback PATH lookup
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let candidates = ["/usr/bin/clamscan", "/usr/local/bin/clamscan"];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(p);
            }
        }
    }

    None
}

/// Scan a single file by invoking `clamscan` as a subprocess.
///
/// Returns a `ScanVerdict` and the raw ClamAV output line.
pub async fn scan_file(
    clamscan_bin: &Path,
    file_path: &Path,
    config: &ScannerConfig,
) -> (ScanVerdict, String) {
    let mut cmd = Command::new(clamscan_bin);

    // Core flags
    cmd.arg("--no-summary")   // don't print the stats footer
       .arg("--infected")     // only print infected files (still prints FOUND lines)
       .arg("--stdout");      // all output to stdout

    // Optional: definitions directory
    if let Some(ref db) = config.definitions_dir {
        cmd.arg(format!("--database={}", db.display()));
    }

    // Archive scanning
    if !config.scan_archives {
        cmd.arg("--no-archive");
    }

    // The file to scan
    cmd.arg(file_path);

    debug!(
        path = %file_path.display(),
        "Invoking clamscan"
    );

    // Enforce timeout
    let scan_future = cmd.output();
    let result = timeout(
        Duration::from_secs(config.timeout_secs),
        scan_future,
    )
    .await;

    match result {
        // Timeout
        Err(_) => {
            warn!(
                path = %file_path.display(),
                timeout_secs = config.timeout_secs,
                "ClamAV scan timed out"
            );
            (
                ScanVerdict::Error(format!(
                    "Scan timed out after {} seconds",
                    config.timeout_secs
                )),
                String::new(),
            )
        }

        // Process failed to start
        Ok(Err(e)) => {
            warn!(error = %e, "Failed to start clamscan process");
            (ScanVerdict::Error(format!("Process error: {}", e)), String::new())
        }

        // clamscan exited
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if !stderr.is_empty() {
                debug!(stderr = %stderr.trim(), "clamscan stderr");
            }

            // clamscan exit codes:
            //   0 = No virus found
            //   1 = Virus(es) found
            //   2 = Some error(s) occurred
            match output.status.code() {
                Some(0) => {
                    debug!(path = %file_path.display(), "CLEAN");
                    (ScanVerdict::Clean, stdout)
                }

                Some(1) => {
                    // Parse the virus name from the output line
                    // Format: "/path/to/file: VirusName FOUND"
                    let virus_name = parse_virus_name(&stdout)
                        .unwrap_or_else(|| "Unknown".to_string());

                    if virus_name.starts_with("Heuristics.") || virus_name.starts_with("PUA.") {
                        (ScanVerdict::Suspicious(virus_name), stdout)
                    } else {
                        (ScanVerdict::Infected(virus_name), stdout)
                    }
                }

                Some(2) | _ => {
                    let msg = if !stderr.is_empty() {
                        stderr.trim().to_string()
                    } else {
                        stdout.trim().to_string()
                    };
                    (ScanVerdict::Error(msg), stdout)
                }
            }
        }
    }
}

/// Extract the virus name from a clamscan output line.
/// Example: "/tmp/eicar.com: Eicar-Signature FOUND" → "Eicar-Signature"
fn parse_virus_name(output: &str) -> Option<String> {
    // Look for a line ending in " FOUND"
    for line in output.lines() {
        if line.ends_with(" FOUND") {
            // Strip " FOUND" suffix, then take the part after the last ": "
            let without_found = line.trim_end_matches(" FOUND");
            if let Some(colon_pos) = without_found.rfind(": ") {
                return Some(without_found[colon_pos + 2..].to_string());
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_infected_output() {
        let output = "/tmp/eicar.com: Eicar-Signature FOUND\n";
        assert_eq!(parse_virus_name(output), Some("Eicar-Signature".to_string()));
    }

    #[test]
    fn parses_heuristic_output() {
        let output = "/tmp/suspicious.exe: Heuristics.Broken.Executable FOUND\n";
        assert_eq!(
            parse_virus_name(output),
            Some("Heuristics.Broken.Executable".to_string())
        );
    }

    #[test]
    fn returns_none_for_clean_output() {
        let output = ""; // --infected suppresses clean output
        assert_eq!(parse_virus_name(output), None);
    }

    #[test]
    fn parses_path_with_colon_in_name() {
        // Windows paths have drive letter colons
        let output = "C:\\Users\\test\\Downloads\\malware.exe: Win.Trojan.Generic FOUND\n";
        assert_eq!(parse_virus_name(output), Some("Win.Trojan.Generic".to_string()));
    }
}
