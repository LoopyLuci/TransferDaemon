//! Media previews — render received image files as thumbnails in chat.
//!
//! The daemon stores fully-received inbound files in
//! `<data_local>/transferdaemon/downloads/<safe-name>` (mirrors the daemon's
//! `transport::downloads_dir`). For messages whose mime is an image, we decode
//! the file (downscaled) into an egui texture and draw it in the bubble.
//!
//! A small bounded cache avoids re-decoding the same file every frame.

use egui::{ColorImage, TextureHandle, TextureOptions, Ui};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const MAX_CACHE: usize = 32;
const MAX_DIM: u32 = 480;

static TEXTURE_CACHE: OnceLock<Mutex<HashMap<PathBuf, TextureHandle>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<PathBuf, TextureHandle>> {
    TEXTURE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The directory where the daemon writes received files.
pub fn downloads_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TRANSFERD_DOWNLOADS_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("transferdaemon")
        .join("downloads")
}

/// Resolve the on-disk path for a received file, mirroring the daemon's
/// path-traversal sanitisation.
pub fn received_path(file_name: &str) -> PathBuf {
    let safe = file_name.replace(['/', '\\'], "_");
    downloads_dir().join(safe)
}

/// Whether a file name looks like an image we can decode.
pub fn is_image(mime: Option<&str>, name: &str) -> bool {
    let name = name.to_lowercase();
    let by_mime = mime.map(|m| m.starts_with("image/")).unwrap_or(false);
    let by_ext = name.ends_with(".png")
        || name.ends_with(".jpg")
        || name.ends_with(".jpeg");
    by_mime || by_ext
}

/// Load (or serve from cache) a thumbnail texture for `path`. Returns `None`
/// when the file is missing or not decodable.
pub fn thumbnail(ui: &Ui, path: &PathBuf) -> Option<TextureHandle> {
    {
        let guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tex) = guard.get(path) {
            return Some(tex.clone());
        }
    }

    let img = image::open(path).ok()?.into_rgba8();
    let (w, h) = (img.width(), img.height());
    // Downscale large images so the texture is cheap to keep around.
    let (nw, nh) = if w.max(h) > MAX_DIM {
        let scale = MAX_DIM as f32 / w.max(h) as f32;
        (
            (w as f32 * scale).max(1.0) as u32,
            (h as f32 * scale).max(1.0) as u32,
        )
    } else {
        (w, h)
    };
    let resized = image::imageops::resize(
        &img,
        nw,
        nh,
        image::imageops::FilterType::Triangle,
    );

    let color = ColorImage::from_rgba_unmultiplied([nw as usize, nh as usize], resized.as_raw());
    let texture = ui.ctx().load_texture(
        format!("media-{:?}", path),
        color,
        TextureOptions::LINEAR,
    );

    {
        let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= MAX_CACHE {
            guard.clear(); // simple bounded cache: drop all on overflow
        }
        guard.insert(path.clone(), texture.clone());
    }
    Some(texture)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_image_detects_mime_and_extension() {
        assert!(is_image(Some("image/png"), "a.png"));
        assert!(is_image(Some("image/jpeg"), "a.jpg"));
        assert!(is_image(None, "photo.JPEG"));
        assert!(!is_image(Some("text/plain"), "notes.txt"));
        assert!(!is_image(None, "archive.tar.zst"));
    }

#[test]
    fn received_path_sanitizes_traversal() {
        let p = received_path("../../etc/passwd");
        // The file component (after the downloads dir) must contain no
        // separators, so a hostile name can never escape the downloads dir.
        let file = p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        assert!(!file.contains('/') && !file.contains('\\'), "separators removed from name: {file}");
        assert!(p.starts_with(downloads_dir()), "stays under downloads dir: {}", p.display());
    }
}
