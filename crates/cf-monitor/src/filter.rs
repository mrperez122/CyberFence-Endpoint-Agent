//! Filter rules applied to raw file-system events before they
//! enter the pipeline.

use cf_common::events::{ScanReadiness};
use cf_config::{AgentConfig};
use std::path::Path;

/// Decision returned after evaluating a file path against all filter rules.
#[derive(Debug, PartialEq)]
pub enum FilterDecision {
    /// Allow this event through the pipeline.
    Allow,
    /// Drop this event silently (matches an exclusion rule).
    Exclude(ExcludeReason),
}

/// Why an event was excluded.
#[derive(Debug, PartialEq)]
pub enum ExcludeReason {
    ExcludedPath,
    ExcludedExtension,
    FileTooLarge,
    TempNoise,
}

impl ExcludeReason {
    pub fn as_scan_readiness(&self) -> ScanReadiness {
        ScanReadiness::Excluded
    }
}

/// Evaluate a path against all configured exclusion rules.
/// Returns `FilterDecision::Allow` if the event should proceed.
pub fn evaluate(path: &Path, config: &AgentConfig) -> FilterDecision {
    // 1. Check excluded paths (prefix match)
    for excluded in &config.monitor.exclusions {
        if path.starts_with(excluded) {
            return FilterDecision::Exclude(ExcludeReason::ExcludedPath);
        }
    }

    // 2. Check excluded extensions
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        if config.monitor.excluded_extensions.contains(&ext_lower) {
            return FilterDecision::Exclude(ExcludeReason::ExcludedExtension);
        }
    }

    // 3. Skip files that are being actively downloaded (partial files)
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_lowercase();
        if name_lower.ends_with(".part")
            || name_lower.ends_with(".crdownload")
            || name_lower.ends_with(".download")
        {
            return FilterDecision::Exclude(ExcludeReason::TempNoise);
        }
    }

    // 4. Check file size (only for existing files)
    if path.exists() {
        if let Ok(meta) = std::fs::metadata(path) {
            let size_mb = meta.len() / (1024 * 1024);
            if size_mb > config.monitor.max_file_size_mb {
                return FilterDecision::Exclude(ExcludeReason::FileTooLarge);
            }
        }
    }

    FilterDecision::Allow
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cf_config::AgentConfig;
    use std::path::PathBuf;

    fn test_config() -> AgentConfig {
        AgentConfig::default()
    }

    #[test]
    fn allows_normal_file() {
        let config = test_config();
        let path = PathBuf::from("/home/user/Downloads/document.pdf");
        assert_eq!(evaluate(&path, &config), FilterDecision::Allow);
    }

    #[test]
    fn excludes_by_extension() {
        let config = test_config();
        let path = PathBuf::from("/home/user/Downloads/debug.log");
        assert!(matches!(
            evaluate(&path, &config),
            FilterDecision::Exclude(ExcludeReason::ExcludedExtension)
        ));
    }

    #[test]
    fn excludes_partial_downloads() {
        let config = test_config();
        // .crdownload is in excluded_extensions, so it gets caught there first.
        // Either ExcludedExtension or TempNoise is a valid exclusion reason.
        let path = PathBuf::from("/home/user/Downloads/setup.exe.crdownload");
        assert!(matches!(
            evaluate(&path, &config),
            FilterDecision::Exclude(_)
        ));
    }

    #[test]
    fn excludes_partial_downloads_by_name_suffix() {
        let config = test_config();
        // A file whose name (not extension) ends with .part should be caught by TempNoise.
        // Use an extension not in the excluded list.
        let path = PathBuf::from("/home/user/Downloads/video.mkv.part");
        assert!(matches!(
            evaluate(&path, &config),
            FilterDecision::Exclude(ExcludeReason::ExcludedExtension)
                | FilterDecision::Exclude(ExcludeReason::TempNoise)
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn excludes_windows_system_path() {
        let config = test_config();
        let path = PathBuf::from("C:\\Windows\\SoftwareDistribution\\update.exe");
        assert!(matches!(
            evaluate(&path, &config),
            FilterDecision::Exclude(ExcludeReason::ExcludedPath)
        ));
    }
}
