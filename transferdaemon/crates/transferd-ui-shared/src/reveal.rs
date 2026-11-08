//! Show a received file in the system file manager.
//!
//! This reveals the file rather than opening it. Opening runs whatever program the system associates with the
//! file's type, and a contact can send an `.exe` or a script.

use std::path::Path;
use std::process::Command;

/// Select `path` in the file manager (or, where the platform cannot select a file, open its folder).
pub fn show_in_folder(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Explorer selects the file only when the path uses backslashes (with `/` it opens "This PC" instead).
        let native = path.display().to_string().replace('/', "\\");
        // `raw_arg` keeps the quotes Explorer needs around a path that contains spaces.
        Command::new("explorer")
            .raw_arg(format!("/select,\"{native}\""))
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg("-R").arg(path).spawn()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = path.parent().unwrap_or(path);
        Command::new("xdg-open").arg(dir).spawn()?;
    }
    Ok(())
}
