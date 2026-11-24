//! The recovery-phrase cache that lets a daemon unlock its encrypted store by itself after a restart.
//!
//! The store (`user_data.enc`) is encrypted with a key derived from the recovery phrase, so a daemon that starts at
//! boot (or is restarted by a launcher, a service manager, or ABP) cannot read its identity and contacts until
//! someone gives it the phrase. The cache keeps the phrase next to the store, protected by the operating system:
//!
//! * **Windows**: DPAPI (`CryptProtectData`), bound to the signed-in user; another user or another machine cannot
//!   decrypt it. File format: `TDP1` + the DPAPI blob.
//! * **Elsewhere**: the plain phrase in a file only its owner can read (0600), inside the app's private data folder
//!   (Android's app sandbox). The format the mobile daemon always used, so old caches keep working.
//!
//! `TRANSFERD_AUTO_UNLOCK=off` turns the cache off (the phrase is then needed on every start).

use std::path::Path;

const MAGIC: &[u8] = b"TDP1";

/// Whether the cache is wanted (on unless `TRANSFERD_AUTO_UNLOCK` is `off`/`0`/`false`).
pub fn enabled() -> bool {
    !matches!(std::env::var("TRANSFERD_AUTO_UNLOCK").as_deref(), Ok("off") | Ok("0") | Ok("false"))
}

pub fn write(path: &Path, phrase: &str) -> std::io::Result<()> {
    let bytes = protect(phrase.as_bytes())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

pub fn read(path: &Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    let plain = if let Some(blob) = raw.strip_prefix(MAGIC) { unprotect(blob)? } else { raw };
    let s = String::from_utf8(plain).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(windows)]
fn protect(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    out.extend(dpapi::run(plain, true)?);
    Ok(out)
}

#[cfg(windows)]
fn unprotect(blob: &[u8]) -> Option<Vec<u8>> {
    dpapi::run(blob, false).ok()
}

#[cfg(not(windows))]
fn protect(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(plain.to_vec())
}

#[cfg(not(windows))]
fn unprotect(_blob: &[u8]) -> Option<Vec<u8>> {
    None // a DPAPI blob written on Windows cannot be opened here
}

#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn run(data: &[u8], encrypt: bool) -> std::io::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: input points at `data` for the call's duration; DPAPI allocates output with LocalAlloc, which is
        // copied out and freed below.
        let ok = unsafe {
            if encrypt {
                CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(),
                                 CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(),
                                   CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if ok == 0 || output.pbData.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: DPAPI returned cbData valid bytes at pbData.
        let out = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData as _);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_reads_old_plain_caches() {
        let dir = std::env::temp_dir().join(format!("td-phrase-{}", std::process::id()));
        let p = dir.join("user_data.phrase");
        write(&p, "abandon ability able about above absent absorb abstract absurd abuse access accident").expect("write");
        assert_eq!(read(&p).as_deref(), Some("abandon ability able about above absent absorb abstract absurd abuse access accident"));
        #[cfg(windows)]
        {
            let raw = std::fs::read(&p).unwrap_or_default();
            assert!(raw.starts_with(MAGIC), "protected on Windows");
            assert!(!String::from_utf8_lossy(&raw).contains("abandon"), "not readable as text");
        }
        std::fs::write(&p, "legacy plain phrase\n").ok();
        assert_eq!(read(&p).as_deref(), Some("legacy plain phrase"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
