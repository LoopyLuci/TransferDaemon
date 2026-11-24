//! On-device rotating file logger for Android.
//!
//! Writes to `<external_files_dir>/log_0.txt` and rotates up to 10 files.
//! Every message is also forwarded to logcat via `__android_log_write`.
//! Pull logs from a device with:
//!   adb pull /sdcard/Android/data/com.transferdaemon.app/files/log_0.txt

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const TAG: &[u8] = b"TransferDaemon\0";
const MAX_LOGS: u32 = 10;

extern "C" {
    fn __android_log_write(prio: i32, tag: *const u8, text: *const u8) -> i32;
}

fn logcat(msg: &str) {
    let s = format!("{msg}\0");
    unsafe { __android_log_write(4, TAG.as_ptr(), s.as_ptr() as *const u8) };
}

// ── Global logger state ───────────────────────────────────────────────────────

struct FileLogger {
    file: Mutex<Option<File>>,
}

static LOGGER: OnceLock<FileLogger> = OnceLock::new();

impl FileLogger {
    fn write(&self, msg: &str) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let line = format!("[{secs}] {msg}\n");
        if let Ok(mut guard) = self.file.lock() {
            if let Some(ref mut f) = *guard {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
        logcat(msg);
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the file logger.  `base_dir` is the app's external (or internal)
/// files directory, obtained from `AndroidApp::external_data_path()`.
/// Safe to call multiple times; only the first call takes effect.
pub fn init(base_dir: &std::path::Path) {
    LOGGER.get_or_init(|| {
        let log_dir = base_dir.join("TransferDaemon");
        if let Err(e) = fs::create_dir_all(&log_dir) {
            logcat(&format!("logger: cannot create dir {:?}: {e}", log_dir));
        }

        // Rotate: log_9 deleted, log_{n} → log_{n+1}, new log_0 created.
        for i in (0..MAX_LOGS).rev() {
            let old = log_dir.join(format!("log_{i}.txt"));
            if old.exists() {
                if i + 1 < MAX_LOGS {
                    let new = log_dir.join(format!("log_{}.txt", i + 1));
                    let _ = fs::rename(&old, &new);
                } else {
                    let _ = fs::remove_file(&old);
                }
            }
        }

        let log_path = log_dir.join("log_0.txt");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .map_err(|e| logcat(&format!("logger: cannot open {log_path:?}: {e}")))
            .ok();

        logcat(&format!("Logger initialised → {log_path:?}"));
        FileLogger { file: Mutex::new(file) }
    });
}

/// Write a log line.  Panics if `init()` was not called first.
pub fn log(msg: &str) {
    if let Some(logger) = LOGGER.get() {
        logger.write(msg);
    } else {
        logcat(msg);
    }
}

/// Convenience macro: log!("hello {}", value)
#[macro_export]
macro_rules! alog {
    ($($arg:tt)*) => {
        $crate::platform::android_logger::log(&format!($($arg)*))
    };
}
