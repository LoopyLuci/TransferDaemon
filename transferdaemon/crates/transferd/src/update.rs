//! Updates: find the latest release, download it, check it, and (when the user chose) install it.
//!
//! Releases come from GitHub. The daemon asks for them with `curl` (built into Windows 10 and later, and on most other
//! systems), so no TLS stack is compiled in. Every download is checked against the SHA-256 GitHub publishes for it
//! before it is kept, and a file without a published checksum is refused.
//!
//! The policy lives in `updates.json` in the data folder:
//! * `manual` (the default): the daemon never asks GitHub by itself. The user checks, downloads or installs.
//! * `download`: the daemon checks every few hours and downloads (verified) a newer release, ready to install.
//! * `install`: as `download`, and it also puts the new program file in place. The new version runs after a restart.
//!
//! Every step is written to the activity log.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use transferd_activity::Level;

/// The version of this build. Releases are published with the same number (`v2.3.0` is `2.3.0`).
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Where releases are published.
pub const GITHUB_REPO: &str = "LoopyLuci/TransferDaemon";
/// How often a `download` or `install` policy checks.
const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
/// The first check waits this long after start-up, so start-up is not slowed by the network.
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(90);
const POLICY_FILE: &str = "updates.json";
const USER_AGENT: &str = "TransferDaemon-updates";
/// Windows: the running program file is moved aside to this name before the new one takes its place.
const OLD_SUFFIX: &str = "exe.old";

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// A version such as `2.4.0-dev`, `v2.3.0` or `2.3.0-rc.1`. Build metadata (`+...`) is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub numbers: Vec<u64>,
    pub pre: Vec<String>,
}

/// Parse a version. `None` when it does not start with numbers.
pub fn parse_version(text: &str) -> Option<Version> {
    let trimmed = text.trim().trim_start_matches(['v', 'V']);
    let without_build = trimmed.split('+').next()?;
    let (core, pre) = match without_build.split_once('-') {
        Some((core, pre)) => (core, pre.split('.').map(str::to_string).collect()),
        None => (without_build, Vec::new()),
    };
    let mut numbers = core.split('.').map(|part| part.parse::<u64>()).collect::<Result<Vec<_>, _>>().ok()?;
    if numbers.is_empty() {
        return None;
    }
    while numbers.len() < 3 {
        numbers.push(0);
    }
    Some(Version { numbers, pre })
}

/// Semantic-version order: numbers first; a pre-release is older than the release it leads up to.
pub fn compare_versions(a: &Version, b: &Version) -> Ordering {
    let len = a.numbers.len().max(b.numbers.len());
    for i in 0..len {
        let x = a.numbers.get(i).copied().unwrap_or(0);
        let y = b.numbers.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => compare_pre(&a.pre, &b.pre),
    }
}

fn compare_pre(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            // Numbers sort before words, as in semver.
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

/// Is `candidate` a newer version than `installed`? Unreadable versions are never newer.
pub fn is_newer(candidate: &str, installed: &str) -> bool {
    match (parse_version(candidate), parse_version(installed)) {
        (Some(c), Some(i)) => compare_versions(&c, &i) == Ordering::Greater,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Releases
// ---------------------------------------------------------------------------

/// A file attached to a release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    /// The SHA-256 GitHub publishes for the file, lower-case hex.
    pub sha256: Option<String>,
    pub url: String,
}

/// A published release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub name: String,
    pub published_at: String,
    pub notes: String,
    pub url: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}

/// Read one release from GitHub's JSON. `None` when it has no usable tag.
pub fn parse_release(json: &serde_json::Value) -> Option<Release> {
    let tag = json.get("tag_name")?.as_str()?;
    let version = tag.trim().trim_start_matches(['v', 'V']).to_string();
    parse_version(&version)?;
    let assets = json
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|list| list.iter().filter_map(parse_asset).collect())
        .unwrap_or_default();
    Some(Release {
        version,
        name: json.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        published_at: json.get("published_at").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        notes: json.get("body").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        url: json.get("html_url").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        draft: json.get("draft").and_then(|v| v.as_bool()).unwrap_or(false),
        prerelease: json.get("prerelease").and_then(|v| v.as_bool()).unwrap_or(false),
        assets,
    })
}

fn parse_asset(json: &serde_json::Value) -> Option<Asset> {
    let name = json.get("name")?.as_str()?.to_string();
    let url = json.get("browser_download_url")?.as_str()?.to_string();
    // GitHub's `digest` is "sha256:<hex>". Anything else is ignored, and the download is refused later.
    let sha256 = json
        .get("digest")
        .and_then(|d| d.as_str())
        .and_then(|d| d.strip_prefix("sha256:"))
        .map(|hex| hex.to_ascii_lowercase())
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    Some(Asset { name, size: json.get("size").and_then(|s| s.as_u64()).unwrap_or(0), sha256, url })
}

/// The Windows program file for a version, as the release names it.
pub fn program_asset_name(version: &str) -> Option<String> {
    if cfg!(windows) {
        Some(format!("transferd-{version}.exe"))
    } else {
        None
    }
}

fn curl(args: &[&str]) -> Command {
    let mut cmd = Command::new("curl");
    cmd.args(["--silent", "--show-error", "--location"]).args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window pops up for each request.
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

fn fetch_json(url: &str) -> Result<serde_json::Value, String> {
    let output = curl(&["--fail", "--max-time", "20", "-H", "Accept: application/vnd.github+json", "-H", &format!("User-Agent: {USER_AGENT}"), url])
        .output()
        .map_err(|e| format!("could not run curl: {e}"))?;
    if !output.status.success() {
        return Err(format!("GitHub did not answer: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("GitHub's answer was not JSON: {e}"))
}

/// The newest published release (what GitHub marks as latest).
pub fn fetch_latest() -> Result<Release, String> {
    let json = fetch_json(&format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest"))?;
    parse_release(&json).ok_or_else(|| "the latest release has no version tag".to_string())
}

/// The newest release that has an Android app (`.apk`) attached.
pub fn fetch_apk() -> Result<(Release, Asset), String> {
    let json = fetch_json(&format!("https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=20"))?;
    for release in json.as_array().into_iter().flatten().filter_map(parse_release) {
        if release.draft {
            continue;
        }
        if let Some(asset) = release.assets.iter().find(|a| a.name.to_ascii_lowercase().ends_with(".apk")).cloned() {
            return Ok((release, asset));
        }
    }
    Err("no release has an Android app (.apk) attached yet".to_string())
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

/// The SHA-256 of a file, lower-case hex.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Refuse a file whose SHA-256 is not the one GitHub published. The file is removed when it does not match.
pub fn verify_digest(path: &Path, expected: Option<&str>) -> Result<(), String> {
    let Some(expected) = expected else {
        let _ = fs::remove_file(path);
        return Err("GitHub published no checksum for this file, so it was not kept".to_string());
    };
    let got = sha256_file(path).map_err(|e| format!("could not read the download: {e}"))?;
    if got.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        let _ = fs::remove_file(path);
        Err("the download does not match GitHub's checksum, so it was discarded".to_string())
    }
}

/// A file name with no folders in it, whatever the release says.
fn safe_file_name(name: &str) -> Option<String> {
    Path::new(name).file_name().and_then(|n| n.to_str()).filter(|n| !n.is_empty() && *n != "." && *n != "..").map(str::to_string)
}

/// `dir/name`, or `dir/name (2)`, `(3)`... so an existing file is never overwritten.
fn unused_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) => (stem.to_string(), format!(".{ext}")),
        None => (name.to_string(), String::new()),
    };
    (2..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|candidate| !candidate.exists())
        .unwrap_or(first)
}

/// Download `asset` into `dir`, check it, and return where it is. With `unique`, an existing file is not replaced.
pub fn download_verified(asset: &Asset, dir: &Path, unique: bool) -> Result<PathBuf, String> {
    let name = safe_file_name(&asset.name).ok_or_else(|| format!("refusing the file name {:?}", asset.name))?;
    fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let part = dir.join(format!("{name}.part"));
    let output = curl(&["--fail", "--max-time", "1800", "-H", &format!("User-Agent: {USER_AGENT}"), "-o"])
        .arg(&part)
        .arg(&asset.url)
        .output()
        .map_err(|e| format!("could not run curl: {e}"))?;
    if !output.status.success() {
        let _ = fs::remove_file(&part);
        return Err(format!("download failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    if let Err(e) = verify_digest(&part, asset.sha256.as_deref()) {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    let target = if unique { unused_path(dir, &name) } else { dir.join(&name) };
    if target.exists() {
        let _ = fs::remove_file(&target);
    }
    fs::rename(&part, &target).map_err(|e| format!("could not keep the download: {e}"))?;
    Ok(target)
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// What the daemon does by itself. See the module notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    #[default]
    Manual,
    Download,
    Install,
}

impl Policy {
    pub fn parse(text: &str) -> Option<Policy> {
        match text.trim().to_ascii_lowercase().as_str() {
            "manual" => Some(Policy::Manual),
            "download" => Some(Policy::Download),
            "install" => Some(Policy::Install),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Manual => "manual",
            Policy::Download => "download",
            Policy::Install => "install",
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct PolicyFile {
    #[serde(default)]
    policy: Policy,
}

fn policy_path() -> PathBuf {
    transferd_control::client::data_dir().join(POLICY_FILE)
}

/// The saved policy. A missing or unreadable file means `manual`.
pub fn load_policy() -> Policy {
    fs::read_to_string(policy_path())
        .ok()
        .and_then(|text| serde_json::from_str::<PolicyFile>(&text).ok())
        .map(|file| file.policy)
        .unwrap_or_default()
}

/// Save the policy. Takes effect at the daemon's next check, without a restart.
pub fn set_policy(policy: Policy) -> Result<(), String> {
    let path = policy_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(&PolicyFile { policy }).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).and_then(|_| fs::rename(&tmp, &path)).map_err(|e| format!("could not save the update policy: {e}"))?;
    transferd_activity::record(Level::Info, "updates", "updates", format!("update policy set to {}", policy.as_str()), &[]);
    Ok(())
}

// ---------------------------------------------------------------------------
// What the daemon knows
// ---------------------------------------------------------------------------

/// The update state, as the windows show it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub policy: Policy,
    /// Latest published version, once checked.
    pub latest_version: String,
    pub published_at: String,
    pub release_notes: String,
    pub release_url: String,
    /// Unix seconds of the last successful check; zero when never.
    pub checked_at: u64,
    pub error: String,
    /// A version downloaded and verified, waiting to be installed. Empty when there is none.
    pub staged_version: String,
    /// Installed, and the daemon must restart to run the new version.
    pub restart_required: bool,
    pub asset_name: String,
    pub asset_size: u64,
}

#[derive(Default)]
struct Inner {
    snap: Snapshot,
    asset: Option<Asset>,
    staged: Option<PathBuf>,
}

fn inner() -> MutexGuard<'static, Inner> {
    static STATE: OnceLock<Mutex<Inner>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Inner::default())).lock().unwrap_or_else(|p| p.into_inner())
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The current state, with the saved policy.
pub fn snapshot() -> Snapshot {
    let mut snap = inner().snap.clone();
    snap.policy = load_policy();
    snap
}

/// Whether the latest release is newer than this build.
pub fn update_available(snap: &Snapshot) -> bool {
    is_newer(&snap.latest_version, CURRENT_VERSION)
}

fn note_failure(context: &str, error: &str) {
    inner().snap.error = error.to_string();
    transferd_activity::record(Level::Warn, "updates", "updates", format!("{context}: {error}"), &[]);
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Ask GitHub for the latest release and remember it. Does not download anything.
pub fn check_now() -> Result<Snapshot, String> {
    let release = match fetch_latest() {
        Ok(release) => release,
        Err(e) => {
            note_failure("update check failed", &e);
            return Err(e);
        }
    };
    let asset = program_asset_name(&release.version).and_then(|name| release.assets.iter().find(|a| a.name == name).cloned());
    {
        let mut g = inner();
        g.snap.latest_version = release.version.clone();
        g.snap.published_at = release.published_at.clone();
        g.snap.release_notes = release.notes.clone();
        g.snap.release_url = release.url.clone();
        g.snap.checked_at = now_secs();
        g.snap.error.clear();
        g.snap.asset_name = asset.as_ref().map(|a| a.name.clone()).unwrap_or_default();
        g.snap.asset_size = asset.as_ref().map(|a| a.size).unwrap_or(0);
        g.asset = asset;
    }
    let newer = is_newer(&release.version, CURRENT_VERSION);
    transferd_activity::record(
        Level::Info,
        "updates",
        "updates",
        if newer {
            format!("update check: {} is available (this is {CURRENT_VERSION})", release.version)
        } else {
            format!("update check: {CURRENT_VERSION} is the latest release")
        },
        &[],
    );
    Ok(snapshot())
}

/// Download the latest release's program file (if it is newer than this build), verify it, and keep it ready.
pub fn download_latest() -> Result<Snapshot, String> {
    check_now()?;
    let (version, asset) = {
        let g = inner();
        (g.snap.latest_version.clone(), g.asset.clone())
    };
    if !is_newer(&version, CURRENT_VERSION) {
        return Err(format!("this is already the latest release ({CURRENT_VERSION})"));
    }
    if inner().snap.staged_version == version {
        return Ok(snapshot());
    }
    let asset = asset.ok_or_else(|| format!("release {version} has no program file for this system"))?;
    transferd_activity::record(Level::Info, "updates", "updates", format!("downloading {} ({} bytes)", asset.name, asset.size), &[]);
    let path = match download_verified(&asset, &updates_dir(), false) {
        Ok(path) => path,
        Err(e) => {
            note_failure("download failed", &e);
            return Err(e);
        }
    };
    {
        let mut g = inner();
        g.snap.staged_version = version.clone();
        g.snap.error.clear();
        g.staged = Some(path);
    }
    transferd_activity::record(Level::Info, "updates", "updates", format!("update {version} downloaded and verified"), &[]);
    Ok(snapshot())
}

/// The folder downloads go to: `updates` in the data folder.
pub fn updates_dir() -> PathBuf {
    transferd_control::client::data_dir().join("updates")
}

/// Put the staged program file in place of the running one. Windows only: the running file is moved aside (Windows
/// allows that), and the new one takes its name. The new version runs after a restart.
pub fn install_staged() -> Result<Snapshot, String> {
    let (version, staged) = {
        let g = inner();
        (g.snap.staged_version.clone(), g.staged.clone())
    };
    let staged = staged.ok_or_else(|| "nothing is downloaded yet".to_string())?;
    if !cfg!(windows) {
        return Err(format!("automatic install is only available on Windows; the new file is at {}", staged.display()));
    }
    let current = std::env::current_exe().map_err(|e| format!("could not find the running daemon: {e}"))?;
    let old = current.with_extension(OLD_SUFFIX);
    let _ = fs::remove_file(&old);
    fs::rename(&current, &old).map_err(|e| {
        let message = format!("could not move the running daemon aside: {e}");
        note_failure("install failed", &message);
        message
    })?;
    if let Err(e) = fs::copy(&staged, &current) {
        let _ = fs::rename(&old, &current);
        let message = format!("could not put the new daemon in place: {e}");
        note_failure("install failed", &message);
        return Err(message);
    }
    {
        let mut g = inner();
        g.snap.restart_required = true;
        g.snap.error.clear();
    }
    transferd_activity::record(Level::Info, "updates", "updates", format!("installed {version}; restart the daemon to run it"), &[]);
    Ok(snapshot())
}

/// Remove what an earlier install left behind (the program file it moved aside).
pub fn clean_up_after_install() {
    if let Ok(current) = std::env::current_exe() {
        let _ = fs::remove_file(current.with_extension(OLD_SUFFIX));
    }
}

/// Install the latest release: download it first when it is not already downloaded.
pub fn apply_latest() -> Result<Snapshot, String> {
    let staged = inner().snap.staged_version.clone();
    if staged.is_empty() || !is_newer(&staged, CURRENT_VERSION) {
        download_latest()?;
    }
    install_staged()
}

/// The Android app: the newest release that has one, downloaded into the Downloads folder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApkInfo {
    pub version: String,
    pub asset_name: String,
    pub size: u64,
    pub url: String,
    pub sha256: String,
    pub saved_path: String,
}

pub fn apk_info() -> Result<ApkInfo, String> {
    let (release, asset) = fetch_apk()?;
    Ok(ApkInfo {
        version: release.version,
        asset_name: asset.name,
        size: asset.size,
        url: asset.url,
        sha256: asset.sha256.unwrap_or_default(),
        saved_path: String::new(),
    })
}

pub fn save_apk() -> Result<ApkInfo, String> {
    let (release, asset) = fetch_apk()?;
    let dir = dirs::download_dir().unwrap_or_else(|| transferd_control::client::data_dir().join("downloads"));
    let path = download_verified(&asset, &dir, true).inspect_err(|e| note_failure("saving the app failed", e))?;
    transferd_activity::record(Level::Info, "updates", "updates", format!("saved {} {} to {}", asset.name, release.version, path.display()), &[]);
    Ok(ApkInfo {
        version: release.version,
        asset_name: asset.name,
        size: asset.size,
        url: asset.url,
        sha256: asset.sha256.unwrap_or_default(),
        saved_path: path.display().to_string(),
    })
}

/// Runs for the life of the daemon. Under `manual` it does nothing: the daemon makes no request by itself.
pub fn start_background() {
    clean_up_after_install();
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_AFTER).await;
        loop {
            run_policy_cycle().await;
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

async fn run_policy_cycle() {
    let policy = load_policy();
    if policy == Policy::Manual {
        return;
    }
    // Each step records its own failure in the activity log, so the result needs no handling here.
    let _ = tokio::task::spawn_blocking(move || -> Result<(), String> {
        check_now()?;
        if update_available(&snapshot()) {
            download_latest()?;
            if policy == Policy::Install {
                install_staged()?;
            }
        }
        Ok(())
    })
    .await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_numbers_not_text() {
        assert!(is_newer("2.10.0", "2.9.0"));
        assert!(is_newer("2.3.1", "2.3.0"));
        assert!(!is_newer("2.3.0", "2.3.0"));
        assert!(!is_newer("2.2.9", "2.3.0"));
        assert!(is_newer("v2.3.0", "2.2.0"), "a leading v is ignored");
        assert!(is_newer("3", "2.9.9"), "missing parts count as zero");
    }

    #[test]
    fn a_pre_release_is_older_than_its_release() {
        assert!(is_newer("2.3.0", "2.3.0-rc.1"));
        assert!(is_newer("2.3.0-rc.2", "2.3.0-rc.1"));
        assert!(is_newer("2.3.0-rc.10", "2.3.0-rc.9"), "numeric parts compare as numbers");
        assert!(is_newer("2.4.0-dev", "2.3.0"));
        assert!(!is_newer("2.3.0-rc.1", "2.3.0"));
    }

    #[test]
    fn unreadable_versions_are_never_newer() {
        assert!(!is_newer("unknown", "2.3.0"));
        assert!(!is_newer("2.3.0", "garbage"));
        assert!(parse_version("").is_none());
        assert_eq!(parse_version("1.2+build.7").unwrap().numbers, vec![1, 2, 0]);
    }

    #[test]
    fn a_release_is_read_from_github_json() {
        let json = serde_json::json!({
            "tag_name": "v2.3.0",
            "name": "v2.3.0 - overlay",
            "published_at": "2026-10-11T01:50:31Z",
            "body": "notes",
            "html_url": "https://github.com/LoopyLuci/TransferDaemon/releases/tag/v2.3.0",
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "transferd-2.3.0.exe", "size": 10, "browser_download_url": "https://example.test/t.exe",
                 "digest": "sha256:BA591C70422465B30CD6BAB7EB9D1A3E4B0C0F7CB6AA5B4FB2B8E8A1A6C2D3E4"},
                {"name": "no-digest.exe", "size": 1, "browser_download_url": "https://example.test/n.exe"}
            ]
        });
        let release = parse_release(&json).unwrap();
        assert_eq!(release.version, "2.3.0");
        assert_eq!(release.assets.len(), 2);
        assert_eq!(
            release.assets[0].sha256.as_deref(),
            Some("ba591c70422465b30cd6bab7eb9d1a3e4b0c0f7cb6aa5b4fb2b8e8a1a6c2d3e4"),
            "the digest is kept in lower case"
        );
        assert_eq!(release.assets[1].sha256, None, "no digest, no checksum");
        assert!(parse_release(&serde_json::json!({"name": "no tag"})).is_none());
    }

    #[test]
    fn a_file_name_from_a_release_cannot_leave_its_folder() {
        assert_eq!(safe_file_name("../../evil.exe").as_deref(), Some("evil.exe"));
        assert_eq!(safe_file_name("TransferDaemon-1.0.0.apk").as_deref(), Some("TransferDaemon-1.0.0.apk"));
        assert_eq!(safe_file_name(".."), None);
        assert_eq!(safe_file_name(""), None);
    }

    #[test]
    fn a_download_that_does_not_match_its_checksum_is_discarded() {
        let dir = std::env::temp_dir().join(format!("td-update-verify-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("payload.bin");
        fs::write(&file, b"abc").unwrap();
        // SHA-256 of "abc".
        let good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_file(&file).unwrap(), good);
        let upper = good.to_uppercase();
        assert!(verify_digest(&file, Some(upper.as_str())).is_ok());
        fs::write(&file, b"abc").unwrap();
        assert!(verify_digest(&file, Some("00")).is_err());
        assert!(!file.exists(), "a mismatch removes the file");
        fs::write(&file, b"abc").unwrap();
        assert!(verify_digest(&file, None).is_err(), "no published checksum means no keeping it");
        assert!(!file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_paths_never_overwrite() {
        let dir = std::env::temp_dir().join(format!("td-update-unique-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("app.apk"), b"1").unwrap();
        assert_eq!(unused_path(&dir, "app.apk"), dir.join("app (2).apk"));
        fs::write(dir.join("app (2).apk"), b"2").unwrap();
        assert_eq!(unused_path(&dir, "app.apk"), dir.join("app (3).apk"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_policy_words_are_read_in_any_case() {
        assert_eq!(Policy::parse(" Install "), Some(Policy::Install));
        assert_eq!(Policy::parse("download"), Some(Policy::Download));
        assert_eq!(Policy::parse("auto"), None);
        assert_eq!(Policy::default(), Policy::Manual, "manual is the default");
    }
}
