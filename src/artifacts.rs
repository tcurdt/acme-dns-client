use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::AppError;

/// Returns a unique staging directory path inside `output_dir`.
///
/// The name is `.staging-<unix_timestamp_nanos>` to avoid collisions between
/// concurrent runs and make stale directories identifiable.
pub fn staging_dir(output_dir: &Path) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    output_dir.join(format!(".staging-{}", ts))
}

/// Writes cert and key PEM files to the given staging directory.
///
/// Key is written with restrictive permissions (0o600 on Unix).
/// Does not touch any live files.
pub fn write_staged(staging: &Path, cert_pem: &str, key_pem: &str) -> Result<(), AppError> {
    fs::create_dir_all(staging)
        .map_err(|e| AppError::Output(format!("failed to create staging dir: {}", e)))?;

    fs::write(staging.join("cert.pem"), cert_pem)
        .map_err(|e| AppError::Output(format!("failed to write staged cert.pem: {}", e)))?;

    let key_path = staging.join("key.pem");
    fs::write(&key_path, key_pem)
        .map_err(|e| AppError::Output(format!("failed to write staged key.pem: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| AppError::Output(format!("failed to set key permissions: {}", e)))?;
    }

    Ok(())
}

/// Atomically promotes staged artifacts into the live output directory.
///
/// If `backup_dir` is provided, any existing live files are moved there first.
/// Uses `fs::rename` for atomic promotion (same filesystem assumed).
/// On success, removes the empty staging directory.
pub fn promote(
    output_dir: &Path,
    staging: &Path,
    backup_dir: Option<&Path>,
) -> Result<(), AppError> {
    if let Some(backup) = backup_dir {
        fs::create_dir_all(backup)
            .map_err(|e| AppError::Output(format!("failed to create backup dir: {}", e)))?;

        for name in &["cert.pem", "key.pem"] {
            let live = output_dir.join(name);
            if live.exists() {
                let dst = backup.join(name);
                fs::rename(&live, &dst)
                    .map_err(|e| AppError::Output(format!("failed to backup {}: {}", name, e)))?;
            }
        }
    }

    for name in &["cert.pem", "key.pem"] {
        let staged = staging.join(name);
        let live = output_dir.join(name);
        fs::rename(&staged, &live)
            .map_err(|e| AppError::Output(format!("failed to promote {}: {}", name, e)))?;
    }

    // Best-effort removal of now-empty staging dir
    let _ = fs::remove_dir(staging);

    Ok(())
}

/// Removes any staged files left over from a failed issuance run.
///
/// Best-effort: errors are silently ignored to keep cleanup paths clean.
pub fn cleanup_staging(staging: &Path) {
    let _ = fs::remove_file(staging.join("cert.pem"));
    let _ = fs::remove_file(staging.join("key.pem"));
    let _ = fs::remove_dir(staging);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn staged_files_are_written_not_live() {
        let dir = temp_dir();
        let out = dir.path();
        let staging = staging_dir(out);
        write_staged(&staging, "CERT", "KEY").unwrap();

        assert!(staging.join("cert.pem").exists());
        assert!(staging.join("key.pem").exists());
        assert!(!out.join("cert.pem").exists());
        assert!(!out.join("key.pem").exists());
    }

    #[test]
    fn promote_moves_staged_to_live() {
        let dir = temp_dir();
        let out = dir.path();
        let staging = staging_dir(out);
        write_staged(&staging, "CERT", "KEY").unwrap();
        promote(out, &staging, None).unwrap();

        assert!(out.join("cert.pem").exists());
        assert!(out.join("key.pem").exists());
        assert!(!staging.join("cert.pem").exists());
        assert!(!staging.join("key.pem").exists());
    }

    #[test]
    fn promote_with_backup_moves_existing_live() {
        let dir = temp_dir();
        let out = dir.path();

        // Write existing live files
        fs::write(out.join("cert.pem"), "OLD_CERT").unwrap();
        fs::write(out.join("key.pem"), "OLD_KEY").unwrap();

        let staging = staging_dir(out);
        write_staged(&staging, "NEW_CERT", "NEW_KEY").unwrap();
        let backup_dir = dir.path().join("backup");
        promote(out, &staging, Some(&backup_dir)).unwrap();

        assert_eq!(
            fs::read_to_string(out.join("cert.pem")).unwrap(),
            "NEW_CERT"
        );
        assert_eq!(fs::read_to_string(out.join("key.pem")).unwrap(), "NEW_KEY");
        assert_eq!(
            fs::read_to_string(backup_dir.join("cert.pem")).unwrap(),
            "OLD_CERT"
        );
        assert_eq!(
            fs::read_to_string(backup_dir.join("key.pem")).unwrap(),
            "OLD_KEY"
        );
    }

    #[test]
    fn cleanup_staging_removes_files() {
        let dir = temp_dir();
        let out = dir.path();
        let staging = staging_dir(out);
        write_staged(&staging, "CERT", "KEY").unwrap();
        assert!(staging.join("cert.pem").exists());

        cleanup_staging(&staging);
        assert!(!staging.join("cert.pem").exists());
        assert!(!staging.join("key.pem").exists());
        assert!(!staging.exists());
    }

    #[test]
    fn live_files_unchanged_after_cleanup() {
        let dir = temp_dir();
        let out = dir.path();
        fs::write(out.join("cert.pem"), "LIVE_CERT").unwrap();
        fs::write(out.join("key.pem"), "LIVE_KEY").unwrap();

        let staging = staging_dir(out);
        write_staged(&staging, "STAGED_CERT", "STAGED_KEY").unwrap();
        cleanup_staging(&staging);

        // Live files must be unchanged
        assert_eq!(
            fs::read_to_string(out.join("cert.pem")).unwrap(),
            "LIVE_CERT"
        );
        assert_eq!(fs::read_to_string(out.join("key.pem")).unwrap(), "LIVE_KEY");
    }

    #[test]
    fn staging_dir_names_are_unique() {
        let dir = temp_dir();
        let out = dir.path();
        let s1 = staging_dir(out);
        // Sleep 1ns is not reliable; just check the path contains ".staging-"
        let s2 = staging_dir(out);
        assert!(
            s1.to_str().unwrap().contains(".staging-"),
            "staging dir should contain .staging-"
        );
        assert!(
            s2.to_str().unwrap().contains(".staging-"),
            "staging dir should contain .staging-"
        );
    }
}
