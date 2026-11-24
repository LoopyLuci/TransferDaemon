//! Auto-update mechanism for TransferDaemon.
//!
//! Checks for new versions on GitHub releases, downloads updates,
//! and prompts the user to restart.

use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Current version of TransferDaemon.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// GitHub repository for releases.
pub const GITHUB_REPO: &str = "anomalyco/TransferDaemon";

/// Check interval for updates (24 hours).
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

// ---------------------------------------------------------------------------
// Update Info
// ---------------------------------------------------------------------------

/// Information about an available update.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
    pub published_at: String,
    pub size_bytes: u64,
}

/// Result of an update check.
#[derive(Debug)]
pub enum UpdateCheckResult {
    /// No update available.
    UpToDate,
    /// An update is available.
    UpdateAvailable(UpdateInfo),
    /// Failed to check for updates.
    Error(String),
}

// ---------------------------------------------------------------------------
// Version Comparison
// ---------------------------------------------------------------------------

/// Compare two semantic version strings.
/// Returns:
/// - Ordering::Less if v1 < v2
/// - Ordering::Equal if v1 == v2
/// - Ordering::Greater if v1 > v2
fn compare_versions(v1: &str, v2: &str) -> std::cmp::Ordering {
    let parse_version = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };

    let parts1 = parse_version(v1);
    let parts2 = parse_version(v2);

    for (a, b) in parts1.iter().zip(parts2.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    parts1.len().cmp(&parts2.len())
}

// ---------------------------------------------------------------------------
// Update Checker
// ---------------------------------------------------------------------------

/// Check for available updates.
pub async fn check_for_updates() -> UpdateCheckResult {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    // Use curl to fetch the GitHub API response
    let output = Command::new("curl")
        .args(["-s", "-H", "Accept: application/vnd.github.v3+json", &url])
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                return UpdateCheckResult::Error(
                    String::from_utf8_lossy(&output.stderr).to_string()
                );
            }

            let json_str = String::from_utf8_lossy(&output.stdout);

            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(json) => {
                    let version = json["tag_name"]
                        .as_str()
                        .unwrap_or("unknown")
                        .trim_start_matches('v')
                        .to_string();

                    if compare_versions(&version, CURRENT_VERSION) != std::cmp::Ordering::Greater {
                        return UpdateCheckResult::UpToDate;
                    }

                    let download_url = json["html_url"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    let release_notes = json["body"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    let published_at = json["published_at"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    // Get the first asset size (installer)
                    let size_bytes = json["assets"]
                        .as_array()
                        .and_then(|assets| assets.first())
                        .and_then(|asset| asset["size"].as_u64())
                        .unwrap_or(0);

                    UpdateCheckResult::UpdateAvailable(UpdateInfo {
                        version,
                        download_url,
                        release_notes,
                        published_at,
                        size_bytes,
                    })
                }
                Err(e) => UpdateCheckResult::Error(format!("Failed to parse response: {e}")),
            }
        }
        Err(e) => UpdateCheckResult::Error(format!("Network error: {e}")),
    }
}

/// Download an update.
pub async fn download_update(info: &UpdateInfo) -> Result<std::path::PathBuf, String> {
    let temp_dir = std::env::temp_dir();
    let filename = format!("transferdaemon-update-{}", info.version);
    let temp_path = temp_dir.join(&filename);

    // Use curl to download the file
    let output = Command::new("curl")
        .args(["-L", "-o", temp_path.to_str().unwrap_or(""), &info.download_url])
        .output()
        .map_err(|e| format!("Download failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Download failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(temp_path)
}

/// Get the config directory for storing update check timestamps.
fn config_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("transferdaemon")
}

/// Get the path to the update check timestamp file.
fn last_check_path() -> std::path::PathBuf {
    config_dir().join("last_update_check")
}

/// Get the last check timestamp.
pub fn get_last_check_time() -> SystemTime {
    let path = last_check_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let timestamp: u64 = content.trim().parse().unwrap_or(0);
            UNIX_EPOCH + Duration::from_secs(timestamp)
        }
        Err(_) => SystemTime::UNIX_EPOCH,
    }
}

/// Update the last check timestamp.
pub fn update_last_check_time() {
    let path = last_check_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = std::fs::write(&path, now.to_string());
}

/// Check if an update check is due.
pub fn is_update_check_due() -> bool {
    let last_check = get_last_check_time();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    match now.checked_sub(last_check.duration_since(UNIX_EPOCH).unwrap_or_default()) {
        Some(elapsed) => elapsed > CHECK_INTERVAL,
        None => true,
    }
}

// ---------------------------------------------------------------------------
// Platform-specific installation
// ---------------------------------------------------------------------------

/// Install an update.
pub fn install_update(update_path: &std::path::Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        // On Windows, run the installer
        Command::new(update_path)
            .arg("/S") // Silent install
            .spawn()
            .map_err(|e| format!("Failed to start installer: {e}"))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, mount the DMG and copy the app
        let mount_point = std::env::temp_dir().join("transferdaemon-update-mount");

        // Mount the DMG
        let output = Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-mountpoint", mount_point.to_str().unwrap_or(""), update_path.to_str().unwrap_or("")])
            .output()
            .map_err(|e| format!("Failed to mount DMG: {e}"))?;

        if !output.status.success() {
            return Err(format!("Failed to mount DMG: {}", String::from_utf8_lossy(&output.stderr)));
        }

        // Find the .app bundle in the mounted volume
        let entries = std::fs::read_dir(&mount_point)
            .map_err(|e| format!("Failed to read mounted volume: {e}"))?;

        let mut app_path = None;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {e}"))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("app") {
                app_path = Some(path);
                break;
            }
        }

        let app_path = app_path.ok_or("No .app bundle found in DMG")?;

        // Copy to /Applications
        let app_name = app_path.file_name().ok_or("Invalid app name")?;
        let dest = std::path::PathBuf::from("/Applications").join(app_name);

        // Remove existing app if present
        if dest.exists() {
            Command::new("rm")
                .args(["-rf", dest.to_str().unwrap_or("")])
                .output()
                .map_err(|e| format!("Failed to remove existing app: {e}"))?;
        }

        // Copy new app
        Command::new("cp")
            .args(["-R", app_path.to_str().unwrap_or(""), dest.to_str().unwrap_or("")])
            .output()
            .map_err(|e| format!("Failed to copy app: {e}"))?;

        // Unmount the DMG
        Command::new("hdiutil")
            .args(["detach", mount_point.to_str().unwrap_or(""), "-force"])
            .output()
            .map_err(|e| format!("Failed to unmount DMG: {e}"))?;

        // Launch the new app
        Command::new("open")
            .arg(dest.to_str().unwrap_or(""))
            .spawn()
            .map_err(|e| format!("Failed to launch app: {e}"))?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, install the deb/rpm package
        let ext = update_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "deb" => {
                Command::new("sudo")
                    .arg("dpkg")
                    .arg("-i")
                    .arg(update_path)
                    .spawn()
                    .map_err(|e| format!("Failed to install deb: {e}"))?;
                Ok(())
            }
            "rpm" => {
                Command::new("sudo")
                    .arg("rpm")
                    .arg("-U")
                    .arg(update_path)
                    .spawn()
                    .map_err(|e| format!("Failed to install rpm: {e}"))?;
                Ok(())
            }
            _ => Err(format!("Unsupported package format: {ext}")),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(format!(
            "Auto-update not supported on this platform (payload: {})",
            update_path.display()
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version() {
        assert!(!CURRENT_VERSION.is_empty());
    }

    #[test]
    fn test_github_repo() {
        assert!(GITHUB_REPO.contains('/'));
    }

    #[test]
    fn test_version_comparison() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.1.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("1.1.0", "1.0.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), std::cmp::Ordering::Greater);
    }
}
