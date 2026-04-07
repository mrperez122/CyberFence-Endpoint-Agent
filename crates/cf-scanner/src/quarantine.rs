//! Quarantine manager — isolates infected files so they cannot be executed.
//!
//! # How it works
//!
//! 1. Generate a random AES-256-GCM key + nonce for this file.
//! 2. Read the file content into memory.
//! 3. Encrypt it with AES-256-GCM.
//! 4. Write `[12-byte nonce][ciphertext]` to `<vault_dir>/<uuid>.cfq`.
//! 5. Delete the original file.
//! 6. On Windows, wrap the AES key with DPAPI (LocalMachine scope) so only
//!    the local machine can decrypt it. On other platforms, store the raw key.
//! 7. Record the quarantine entry in the scan log.
//!
//! # Restore
//!
//! `restore_file()` reverses the process:
//!   - Read vault file, split nonce + ciphertext
//!   - Decrypt AES key via DPAPI (Windows) or read raw (other)
//!   - Decrypt ciphertext, write back to `original_path`
//!   - Delete the vault file
//!
//! # Security properties
//!
//! - The `.cfq` file cannot be executed — it is encrypted binary data
//! - DPAPI binds the decryption key to the local machine: even if the vault
//!   directory is copied off-machine, the key cannot be recovered
//! - The original file is deleted (not moved) to prevent execution from trash

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

// ── Vault directory resolution ────────────────────────────────────────────────

/// Returns the platform-specific quarantine vault directory.
///
/// | Platform | Path |
/// |----------|------|
/// | Windows  | `%APPDATA%\CyberFence\quarantine\` |
/// | macOS    | `~/Library/Application Support/CyberFence/quarantine/` |
/// | Linux    | `/tmp/cyberfence/quarantine/` |
pub fn vault_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("APPDATA")
            .unwrap_or_else(|_| r"C:\Users\Default\AppData\Roaming".into());
        PathBuf::from(base).join("CyberFence").join("quarantine")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("CyberFence")
            .join("quarantine")
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        PathBuf::from("/tmp/cyberfence/quarantine")
    }
}

// ── QuarantineRecord ─────────────────────────────────────────────────────────

/// Metadata about a quarantined file.
/// Returned by `quarantine_file()` for logging and UI display.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantineRecord {
    pub id:             Uuid,
    pub original_path:  PathBuf,
    pub vault_path:     PathBuf,
    /// AES-256 key, DPAPI-wrapped on Windows (raw 32 bytes on other platforms)
    pub wrapped_key:    Vec<u8>,
    pub quarantined_at: chrono::DateTime<chrono::Utc>,
    pub threat_name:    String,
}

// ── Main quarantine function ──────────────────────────────────────────────────

/// Move a file to the quarantine vault.
///
/// The original file is encrypted, written to the vault, and then deleted.
/// Returns a `QuarantineRecord` with everything needed to restore or delete.
///
/// # Errors
/// Returns an error if the file cannot be read, encrypted, or deleted.
/// The vault file is removed if an error occurs after writing it.
pub fn quarantine_file(
    original_path: &Path,
    threat_name:   &str,
) -> Result<QuarantineRecord> {
    let vault = vault_dir();
    std::fs::create_dir_all(&vault)
        .with_context(|| format!("Failed to create quarantine vault: {}", vault.display()))?;

    // Read the original file
    let plaintext = std::fs::read(original_path)
        .with_context(|| format!("Failed to read file for quarantine: {}", original_path.display()))?;

    // Generate a fresh AES-256-GCM key and nonce for this file
    let key_bytes: [u8; 32] = {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k
    };
    let nonce_bytes: [u8; 12] = {
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        n
    };

    // Encrypt the file content
    let cipher     = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce      = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

    // Write: [12-byte nonce][ciphertext] to vault
    let vault_name = format!("{}.cfq", Uuid::new_v4());
    let vault_path = vault.join(&vault_name);
    let mut vault_data = Vec::with_capacity(12 + ciphertext.len());
    vault_data.extend_from_slice(&nonce_bytes);
    vault_data.extend_from_slice(&ciphertext);
    std::fs::write(&vault_path, &vault_data)
        .with_context(|| format!("Failed to write vault file: {}", vault_path.display()))?;

    // Wrap the AES key for secure storage
    let wrapped_key = wrap_key(&key_bytes)?;

    // Delete the original file
    if let Err(e) = std::fs::remove_file(original_path) {
        // If deletion fails, remove the vault file and return the error
        let _ = std::fs::remove_file(&vault_path);
        return Err(e).with_context(|| {
            format!("Failed to delete original file: {}", original_path.display())
        });
    }

    let record = QuarantineRecord {
        id:            Uuid::new_v4(),
        original_path: original_path.to_path_buf(),
        vault_path:    vault_path.clone(),
        wrapped_key,
        quarantined_at: chrono::Utc::now(),
        threat_name:    threat_name.to_string(),
    };

    info!(
        id           = %record.id,
        original     = %original_path.display(),
        vault        = %vault_path.display(),
        threat       = %threat_name,
        "File quarantined"
    );

    Ok(record)
}

// ── Restore function ──────────────────────────────────────────────────────────

/// Restore a quarantined file to its original location.
///
/// Decrypts the vault file and writes the plaintext back to `original_path`.
/// Deletes the vault file on success.
pub fn restore_file(record: &QuarantineRecord) -> Result<()> {
    // Read vault file
    let vault_data = std::fs::read(&record.vault_path)
        .with_context(|| format!("Failed to read vault file: {}", record.vault_path.display()))?;

    if vault_data.len() < 12 {
        anyhow::bail!("Vault file too short — likely corrupted");
    }

    // Split nonce + ciphertext
    let (nonce_bytes, ciphertext) = vault_data.split_at(12);

    // Unwrap the AES key
    let key_bytes = unwrap_key(&record.wrapped_key)?;

    // Decrypt
    let cipher    = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce     = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?;

    // Ensure restore directory exists
    if let Some(parent) = record.original_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write restored file
    std::fs::write(&record.original_path, &plaintext)
        .with_context(|| format!("Failed to write restored file: {}", record.original_path.display()))?;

    // Delete vault file
    std::fs::remove_file(&record.vault_path)
        .with_context(|| format!("Failed to delete vault file: {}", record.vault_path.display()))?;

    info!(
        original = %record.original_path.display(),
        "File restored from quarantine"
    );
    Ok(())
}

// ── Key wrapping ──────────────────────────────────────────────────────────────

/// Wrap (protect) the AES key for storage.
///
/// Windows: uses DPAPI (`CryptProtectData`) — key is bound to the local machine.
/// Other:   returns the raw key bytes (development/test mode).
fn wrap_key(key: &[u8]) -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        dpapi_protect(key)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows, store raw key (acceptable for dev/test)
        warn!("DPAPI not available on this platform — storing AES key without hardware binding");
        Ok(key.to_vec())
    }
}

/// Unwrap the AES key from storage.
fn unwrap_key(wrapped: &[u8]) -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        dpapi_unprotect(wrapped)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(wrapped.to_vec())
    }
}

// ── Windows DPAPI ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &mut input,
            None,              // description
            None,              // entropy
            None,              // reserved
            None,              // prompt struct
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
        .map_err(|e| anyhow::anyhow!("DPAPI protect failed: {}", e))?;

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        windows::Win32::System::Memory::LocalFree(
            windows::Win32::Foundation::HLOCAL(output.pbData as isize),
        );
        Ok(result)
    }
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            0,
            &mut output,
        )
        .map_err(|e| anyhow::anyhow!("DPAPI unprotect failed: {}", e))?;

        let slice  = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        windows::Win32::System::Memory::LocalFree(
            windows::Win32::Foundation::HLOCAL(output.pbData as isize),
        );
        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn quarantine_and_restore_roundtrip() {
        let dir = tempdir().unwrap();

        // Create a "malicious" file
        let original = dir.path().join("malware.exe");
        std::fs::write(&original, b"MZ malware content").unwrap();

        // Quarantine it
        let record = quarantine_file(&original, "Win.Trojan.Test").unwrap();

        // Original must be deleted
        assert!(!original.exists(), "original file should be deleted after quarantine");

        // Vault file must exist and be non-empty
        assert!(record.vault_path.exists(), "vault file should exist");
        let vault_size = std::fs::metadata(&record.vault_path).unwrap().len();
        assert!(vault_size > 0, "vault file should not be empty");

        // Vault content must NOT equal the original plaintext
        let vault_bytes = std::fs::read(&record.vault_path).unwrap();
        assert_ne!(vault_bytes, b"MZ malware content", "vault should be encrypted");

        // Restore it
        restore_file(&record).unwrap();

        // Restored content must match original
        let restored = std::fs::read(&original).unwrap();
        assert_eq!(restored, b"MZ malware content", "restored content should match original");

        // Vault file must be deleted after restore
        assert!(!record.vault_path.exists(), "vault file should be deleted after restore");
    }

    #[test]
    fn vault_file_has_correct_prefix() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("test.txt");
        std::fs::write(&original, b"secret data").unwrap();

        let record = quarantine_file(&original, "Test.Threat").unwrap();

        // Vault file must have .cfq extension
        assert_eq!(
            record.vault_path.extension().and_then(|e| e.to_str()),
            Some("cfq"),
            "vault file should have .cfq extension"
        );
    }
}
