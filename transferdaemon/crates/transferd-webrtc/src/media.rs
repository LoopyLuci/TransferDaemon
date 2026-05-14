//! MediaCapture abstraction and platform implementations.
//!
//! - `DesktopMediaCapture` (feature `desktop-capture`): real camera + mic via
//!   nokhwa and cpal.  Falls back to silence/no-video if hardware is absent.
//! - `MockMediaCapture`: deterministic synthetic sources for tests and CI.
//! - `SilentCapture`: stub for audio-only paths.

use async_trait::async_trait;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::mpsc;
use crate::types::{AudioSamples, VideoFrame};

#[cfg(feature = "desktop-capture")]
mod desktop_capture;
#[cfg(feature = "desktop-capture")]
pub use desktop_capture::DesktopMediaCapture;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait MediaCapture: Send + Sync {
    /// Begin producing audio frames (480 samples @ 48 kHz each).
    async fn start_audio(&self) -> mpsc::Receiver<AudioSamples>;
    /// Signal the audio capture to stop. The receiver's channel will close.
    async fn stop_audio(&self);
    /// Begin producing video frames.  Returns `None` for audio-only implementations.
    async fn start_video(&self) -> Option<mpsc::Receiver<VideoFrame>>;
    /// Signal video capture to stop.
    async fn stop_video(&self);
}

// ---------------------------------------------------------------------------
// MockMediaCapture — deterministic synthetic sources for tests and CI
// ---------------------------------------------------------------------------

pub struct MockMediaCapture {
    /// Sine-wave frequency for generated audio (default 440 Hz).
    pub audio_freq_hz: f32,
    /// Whether to produce video frames at all.
    pub video_enabled: bool,
    /// Set to true after stop_audio() / stop_video().
    audio_stopped: Arc<AtomicBool>,
    video_stopped: Arc<AtomicBool>,
}

impl Default for MockMediaCapture {
    fn default() -> Self {
        Self {
            audio_freq_hz:  440.0,
            video_enabled:  false,
            audio_stopped: Arc::new(AtomicBool::new(false)),
            video_stopped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl MockMediaCapture {
    pub fn new_with_video() -> Self {
        Self { video_enabled: true, ..Default::default() }
    }

    pub fn with_freq(hz: f32) -> Self {
        Self { audio_freq_hz: hz, ..Default::default() }
    }
}

#[async_trait]
impl MediaCapture for MockMediaCapture {
    async fn start_audio(&self) -> mpsc::Receiver<AudioSamples> {
        let (tx, rx) = mpsc::channel(32);
        let freq = self.audio_freq_hz;
        let stopped = self.audio_stopped.clone();
        self.audio_stopped.store(false, Ordering::Relaxed);
        tokio::spawn(async move {
            let mut phase = 0.0f32;
            loop {
                if stopped.load(Ordering::Relaxed) { break; }
                let samples: AudioSamples = (0..480)
                    .map(|_| {
                        let s = (2.0 * std::f32::consts::PI * phase).sin() * 0.5;
                        phase = (phase + freq / 48000.0).rem_euclid(1.0);
                        s
                    })
                    .collect();
                if tx.send(samples).await.is_err() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        rx
    }

    async fn stop_audio(&self) {
        self.audio_stopped.store(true, Ordering::Relaxed);
    }

    async fn start_video(&self) -> Option<mpsc::Receiver<VideoFrame>> {
        if !self.video_enabled { return None; }
        let (tx, rx) = mpsc::channel(4);
        let stopped = self.video_stopped.clone();
        self.video_stopped.store(false, Ordering::Relaxed);
        tokio::spawn(async move {
            let mut luma: u8 = 0;
            loop {
                if stopped.load(Ordering::Relaxed) { break; }
                // Color-bars pattern: RGBA with cycling luma.
                let rgba: Vec<u8> = (0..640 * 480 * 4)
                    .map(|i| match i % 4 {
                        3 => 255,   // alpha
                        _ => luma,  // R / G / B cycling luma
                    })
                    .collect();
                luma = luma.wrapping_add(1);
                if tx.send(VideoFrame { width: 640, height: 480, rgba }).await.is_err() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(33)).await;
            }
        });
        Some(rx)
    }

    async fn stop_video(&self) {
        self.video_stopped.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// SilentCapture — produces silence and no video (useful for unit test stubs)
// ---------------------------------------------------------------------------

pub struct SilentCapture;

#[async_trait]
impl MediaCapture for SilentCapture {
    async fn start_audio(&self) -> mpsc::Receiver<AudioSamples> {
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                let silence = vec![0.0f32; 480];
                if tx.send(silence).await.is_err() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        rx
    }
    async fn stop_audio(&self) {}
    async fn start_video(&self) -> Option<mpsc::Receiver<VideoFrame>> { None }
    async fn stop_video(&self) {}
}

// ---------------------------------------------------------------------------
// Factory — picks the best available backend at runtime
// ---------------------------------------------------------------------------

/// Return the best `MediaCapture` available on this machine.
///
/// With the `desktop-capture` feature, attempts real hardware (nokhwa/cpal).
/// Without it (or in CI), returns a `MockMediaCapture` that generates
/// synthetic colour-bar video and a 440 Hz sine-wave tone.
pub fn new_default_capture(video: bool) -> Arc<dyn MediaCapture> {
    #[cfg(feature = "desktop-capture")]
    {
        let _ = video; // DesktopMediaCapture always tries camera; returns None if absent
        return Arc::new(DesktopMediaCapture::new());
    }
    #[cfg(not(feature = "desktop-capture"))]
    {
        if video {
            Arc::new(MockMediaCapture::new_with_video())
        } else {
            Arc::new(SilentCapture)
        }
    }
}

// ---------------------------------------------------------------------------
// Utility: drain a channel without blocking
// ---------------------------------------------------------------------------

pub fn try_drain<T>(rx: &mut mpsc::Receiver<T>) -> Vec<T> {
    let mut out = Vec::new();
    while let Ok(v) = rx.try_recv() { out.push(v); }
    out
}
