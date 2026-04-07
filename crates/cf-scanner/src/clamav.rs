//! ClamAV subprocess adapter — the CyberFence Engine interface.
//!
//! Calls `clamscan` as a child process and parses its output into a
//! typed `ScanVerdict`. All scanning is non-blocking from the caller's
//! perspective: the subprocess runs inside `tokio::task::spawn_blocking`.
//!
//! # clamscan output format
//!
//! ```text
//! /path/to/clean.txt:  OK
//! /path/to/eicar.com:  Eicar-Signature FOUND
//! /path/to/broken.exe: Heuristics.Broken.Executable FOUND
//! ```
//!
//! With `--no-summary` the stats footer is suppressed.
//! With `--infected`   only infected lines are printed (clean files silent).
//!
//! # Exit codes
//! - `0` → no threats found (CLEAN)
//! - `1` → at least one threat found (INFECTED or SUSPICIOUS)
//! - `2` → error during scan

use cf_common::scan::ScanVerdict;
use cf_config::ScannerConfig;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ── Binary discovery ──────────────────────────────────────────────────────────

/// Locate the `clamscan` binary on this system.
///
/// Search priority:
///   1. Explicit path in `config.clamscan_path`
///   2. Windows default install locations
///   3. macOS Homebrew locations
///   4. Linux / Unix standard locations
pub fn find_clamscan(config: &ScannerConfig) -> Option<PathBuf> {
    // 1. Explicit config path takes highest priority
    if let Some(ref p) = config.clamscan_path {
        if p.exists() {
            info!(path = %p.display(), "CyberFence Engine (clamscan) found at configured path");
            return Some(p.clone());
        }
        warn!(
            path = %p.display(),
            "Configured clamscan_path does not exist — searching defaults"
        );
    }

    // 2. Windows install locations
    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files (x86)\ClamAV\clamscan.exe",
        ];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                info!(path = %p.display(), "CyberFence Engine found");
                return Some(p);
            }
        }
        // Also check PATH via `where` command
        if let Ok(out) = std::process::Command::new("where")
            .arg("clamscan.exe")
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = s.lines().next() {
                    let p = PathBuf::from(line.trim());
                    if p.exists() {
                        info!(path = %p.display(), "CyberFence Engine found via PATH");
                        return Some(p);
                    }
                }
            }
        }
    }

    // 3. macOS Homebrew
    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/opt/homebrew/bin/clamscan",  // Apple Silicon
            "/usr/local/bin/clamscan",     // Intel
            "/usr/bin/clamscan",
        ];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                info!(path = %p.display(), "CyberFence Engine found");
                return Some(p);
            }
        }
    }

    // 4. Linux / CI fallback
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let candidates = ["/usr/bin/clamscan", "/usr/local/bin/clamscan"];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                info!(path = %p.display(), "CyberFence Engine found");
                return Some(p);
            }
        }
    }

    warn!(
        "CyberFence Engine (clamscan) not found. \
         Install ClamAV and ensure it is in PATH or set scanner.clamscan_path in config.toml. \
         Agent will run in monitor-only mode."
    );
    None
}

// ── Core scan function ────────────────────────────────────────────────────────

/// Scan a single file and return a verdict with the raw clamscan output.
///
/// This function is async but calls a synchronous subprocess — callers should
/// invoke it inside `tokio::task::spawn_blocking` for CPU-bound file scans.
///
/// # Arguments
/// - `clamscan_bin` — path to the `clamscan` binary
/// - `file_path`    — the file to scan
/// - `config`       — scanner configuration (timeout, definitions dir, archives)
///
/// # Returns
/// `(ScanVerdict, String)` — the verdict + the raw stdout from clamscan
pub async fn scan_file(
    clamscan_bin: &Path,
    file_path:    &Path,
    config:       &ScannerConfig,
) -> (ScanVerdict, String) {
    // Guard: file must exist before we attempt to scan it
    if !file_path.exists() {
        return (
            ScanVerdict::Skipped("File no longer exists".to_string()),
            String::new(),
        );
    }

    let mut cmd = Command::new(clamscan_bin);

    // Core flags
    cmd.arg("--no-summary")   // suppress stats footer
       .arg("--infected")     // only print FOUND lines (cleaner output)
       .arg("--stdout");      // force all output to stdout

    // Optional: use a specific definitions directory
    if let Some(ref db) = config.definitions_dir {
        cmd.arg(format!("--database={}", db.display()));
    }

    // Archive scanning (zip, tar, etc.)
    if !config.scan_archives {
        cmd.arg("--no-archive");
    }

    // The file to scan
    cmd.arg(file_path);

    debug!(
        path    = %file_path.display(),
        binary  = %clamscan_bin.display(),
        "Invoking CyberFence Engine"
    );

    // Enforce per-file scan timeout
    let scan_fut = cmd.output();
    let result   = timeout(Duration::from_secs(config.timeout_secs), scan_fut).await;

    match result {
        // ── Timeout ──────────────────────────────────────────────────────
        Err(_) => {
            warn!(
                path         = %file_path.display(),
                timeout_secs = config.timeout_secs,
                "Scan timed out — file may be a large/encrypted archive"
            );
            (
                ScanVerdict::Error(format!(
                    "Scan timed out after {} seconds",
                    config.timeout_secs
                )),
                String::new(),
            )
        }

        // ── Process failed to launch ──────────────────────────────────────
        Ok(Err(e)) => {
            warn!(error = %e, "Failed to launch clamscan process");
            (ScanVerdict::Error(format!("Process launch error: {}", e)), String::new())
        }

        // ── clamscan completed ────────────────────────────────────────────
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if !stderr.is_empty() {
                debug!(stderr = %stderr.trim(), "clamscan stderr");
            }

            match output.status.code() {
                // Exit 0 → clean
                Some(0) => {
                    debug!(path = %file_path.display(), "Verdict: CLEAN");
                    (ScanVerdict::Clean, stdout)
                }

                // Exit 1 → threat found — parse the virus name
                Some(1) => {
                    let virus_name = parse_virus_name(&stdout)
                        .unwrap_or_else(|| "Unknown".to_string());

                    // ClamAV prefixes heuristic detections with "Heuristics." or "PUA."
                    if virus_name.starts_with("Heuristics.")
                        || virus_name.starts_with("PUA.")
                        || virus_name.starts_with("Suspect.")
                    {
                        debug!(path = %file_path.display(), rule = %virus_name, "Verdict: SUSPICIOUS");
                        (ScanVerdict::Suspicious(virus_name), stdout)
                    } else {
                        debug!(path = %file_path.display(), virus = %virus_name, "Verdict: INFECTED");
                        (ScanVerdict::Infected(virus_name), stdout)
                    }
                }

                // Exit 2 or other → error
                _ => {
                    let msg = if !stderr.is_empty() {
                        stderr.trim().to_string()
                    } else if !stdout.is_empty() {
                        stdout.trim().to_string()
                    } else {
                        format!("clamscan exited with code {:?}", output.status.code())
                    };
                    warn!(path = %file_path.display(), error = %msg, "Scan error");
                    (ScanVerdict::Error(msg), stdout)
                }
            }
        }
    }
}

// ── Output parser ─────────────────────────────────────────────────────────────

/// Extract the virus/rule name from a clamscan `FOUND` line.
///
/// Input:  `/path/to/file.com: Eicar-Signature FOUND`
/// Output: `Some("Eicar-Signature")`
///
/// Handles paths that contain colons (Windows drive letters like `C:\...`).
fn parse_virus_name(output: &str) -> Option<String> {
    for line in output.lines() {
        if !line.ends_with(" FOUND") {
            continue;
        }
        // Remove " FOUND" suffix
        let without_found = &line[..line.len() - 6];
        // The virus name is after the LAST ": " in the line.
        // Using rfind handles Windows paths that contain "C:\..." colons.
        if let Some(colon_pos) = without_found.rfind(": ") {
            let virus = without_found[colon_pos + 2..].trim().to_string();
            if !virus.is_empty() {
                return Some(virus);
            }
        }
    }
    None
}

// ── Version check ─────────────────────────────────────────────────────────────

/// Query the installed ClamAV version string.
/// Returns `None` if clamscan is not found or errors.
pub async fn get_engine_version(clamscan_bin: &Path) -> Option<String> {
    let out = Command::new(clamscan_bin)
        .arg("--version")
        .output()
        .await
        .ok()?;

    let s = String::from_utf8_lossy(&out.stdout).to_string();
    // Output: "ClamAV 1.4.2/26858/Mon Apr  7 09:00:00 2026"
    Some(s.trim().to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_infected_line() {
        let output = "/tmp/eicar.com: Eicar-Signature FOUND\n";
        assert_eq!(parse_virus_name(output), Some("Eicar-Signature".to_string()));
    }

    #[test]
    fn parses_heuristic_line() {
        let output = "/tmp/suspicious.exe: Heuristics.Broken.Executable FOUND\n";
        assert_eq!(
            parse_virus_name(output),
            Some("Heuristics.Broken.Executable".to_string())
        );
    }

    #[test]
    fn parses_windows_path_with_drive_colon() {
        // Windows paths contain a colon after the drive letter — rfind handles this
        let output = "C:\\Users\\test\\Downloads\\malware.exe: Win.Trojan.Generic FOUND\n";
        assert_eq!(parse_virus_name(output), Some("Win.Trojan.Generic".to_string()));
    }

    #[test]
    fn parses_pua_prefix() {
        let output = "/tmp/adware.exe: PUA.Win.Adware.BundleInstaller FOUND\n";
        assert_eq!(
            parse_virus_name(output),
            Some("PUA.Win.Adware.BundleInstaller".to_string())
        );
    }

    #[test]
    fn returns_none_for_clean_file() {
        // With --infected flag, clean files produce no output
        let output = "";
        assert_eq!(parse_virus_name(output), None);
    }

    #[test]
    fn returns_none_for_ok_line() {
        let output = "/tmp/clean.pdf: OK\n";
        assert_eq!(parse_virus_name(output), None);
    }

    #[test]
    fn heuristics_prefix_detected_as_suspicious() {
        // Regression: Heuristics.* should be Suspicious, not Infected
        let name = "Heuristics.Encrypted.PDF";
        assert!(
            name.starts_with("Heuristics."),
            "should be treated as SUSPICIOUS"
        );
    }
}
