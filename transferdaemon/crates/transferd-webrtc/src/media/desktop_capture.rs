//! Real hardware media capture for desktop platforms.
//!
//! Video: nokhwa (Windows MediaFoundation / Linux v4l2 / macOS AVFoundation).
//! Audio: cpal  (WASAPI / ALSA / CoreAudio).
//!
//! Both are blocking APIs bridged into tokio channels via `spawn_blocking`.
//! If hardware is unavailable the streams fall back to silence / no video
//! rather than crashing the call.

use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc as std_mpsc,
};
use tokio::sync::mpsc;

use crate::media::MediaCapture;
use crate::types::{AudioSamples, VideoFrame};

// ---------------------------------------------------------------------------
// DesktopMediaCapture
// ---------------------------------------------------------------------------

pub struct DesktopMediaCapture {
    audio_stopped: Arc<AtomicBool>,
    video_stopped: Arc<AtomicBool>,
}

impl DesktopMediaCapture {
    pub fn new() -> Self {
        Self {
            audio_stopped: Arc::new(AtomicBool::new(false)),
            video_stopped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for DesktopMediaCapture {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl MediaCapture for DesktopMediaCapture {
    // ── Audio ────────────────────────────────────────────────────────────────

    async fn start_audio(&self) -> mpsc::Receiver<AudioSamples> {
        let (tok_tx, tok_rx) = mpsc::channel::<AudioSamples>(32);
        let stopped = self.audio_stopped.clone();
        self.audio_stopped.store(false, Ordering::Relaxed);

        tokio::task::spawn_blocking(move || {
            capture_audio(tok_tx, stopped);
        });

        tok_rx
    }

    async fn stop_audio(&self) {
        self.audio_stopped.store(true, Ordering::Relaxed);
    }

    // ── Video ────────────────────────────────────────────────────────────────

    async fn start_video(&self) -> Option<mpsc::Receiver<VideoFrame>> {
        let (tok_tx, tok_rx) = mpsc::channel::<VideoFrame>(4);
        let stopped = self.video_stopped.clone();
        self.video_stopped.store(false, Ordering::Relaxed);

        tokio::task::spawn_blocking(move || {
            if !capture_video(tok_tx, stopped) {
                // Camera unavailable — channel drops, caller sees None on recv.
            }
        });

        // Return the receiver; it may produce 0 frames if no camera is found,
        // but we return Some so the overlay stays visible (shows controls).
        Some(tok_rx)
    }

    async fn stop_video(&self) {
        self.video_stopped.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Audio capture (cpal)
// ---------------------------------------------------------------------------

fn silence_loop(tok_tx: mpsc::Sender<AudioSamples>, stopped: Arc<AtomicBool>) {
    while !stopped.load(Ordering::Relaxed) {
        if tok_tx.blocking_send(vec![0.0f32; 480]).is_err() { break; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn capture_audio(tok_tx: mpsc::Sender<AudioSamples>, stopped: Arc<AtomicBool>) {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let host = cpal::default_host();
    let device = match host.default_input_device() {
        Some(d) => d,
        None => { silence_loop(tok_tx, stopped); return; }
    };
    let config = match device.default_input_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("transferd-webrtc: no audio input config: {e}");
            silence_loop(tok_tx, stopped);
            return;
        }
    };

    let (raw_tx, raw_rx) = std_mpsc::sync_channel::<Vec<f32>>(64);
    let err_fn = |e| eprintln!("transferd-webrtc: audio stream error: {e}");
    let cfg: cpal::StreamConfig = config.config();

    let stream_result = match config.sample_format() {
        cpal::SampleFormat::F32 => {
            let tx = raw_tx.clone();
            device.build_input_stream(
                &cfg,
                move |data: &[f32], _: &cpal::InputCallbackInfo| {
                    let _ = tx.try_send(data.to_vec());
                },
                err_fn,
                None,
            )
        }
        cpal::SampleFormat::I16 => {
            let tx = raw_tx.clone();
            device.build_input_stream(
                &cfg,
                move |data: &[i16], _: &cpal::InputCallbackInfo| {
                    let floats: Vec<f32> = data
                        .iter()
                        .map(|&s| s as f32 / i16::MAX as f32)
                        .collect();
                    let _ = tx.try_send(floats);
                },
                err_fn,
                None,
            )
        }
        cpal::SampleFormat::U16 => {
            let tx = raw_tx.clone();
            device.build_input_stream(
                &cfg,
                move |data: &[u16], _: &cpal::InputCallbackInfo| {
                    let floats: Vec<f32> = data
                        .iter()
                        .map(|&s| (s as f32 / u16::MAX as f32) * 2.0 - 1.0)
                        .collect();
                    let _ = tx.try_send(floats);
                },
                err_fn,
                None,
            )
        }
        // I32, F64, etc. — best-effort silence fallback.
        _ => {
            eprintln!("transferd-webrtc: unsupported audio sample format");
            silence_loop(tok_tx, stopped);
            return;
        }
    };

    let stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("transferd-webrtc: build_input_stream failed: {e}");
            silence_loop(tok_tx, stopped);
            return;
        }
    };

    if let Err(e) = stream.play() {
        eprintln!("transferd-webrtc: stream.play() failed: {e}");
        silence_loop(tok_tx, stopped);
        return;
    }

    // Chunk raw samples into 480-sample (10 ms @ 48 kHz) frames.
    let mut buf = Vec::<f32>::with_capacity(960);
    loop {
        if stopped.load(Ordering::Relaxed) { break; }
        match raw_rx.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(chunk) => {
                buf.extend_from_slice(&chunk);
                while buf.len() >= 480 {
                    let frame: AudioSamples = buf.drain(..480).collect();
                    if tok_tx.blocking_send(frame).is_err() {
                        return;
                    }
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(stream);
}

// ---------------------------------------------------------------------------
// Video capture (nokhwa)
// ---------------------------------------------------------------------------

/// Returns `false` if the camera could not be opened (caller may log).
fn capture_video(tok_tx: mpsc::Sender<VideoFrame>, stopped: Arc<AtomicBool>) -> bool {
    use nokhwa::{
        Camera,
        pixel_format::RgbAFormat,
        utils::{CameraIndex, RequestedFormat, RequestedFormatType},
    };

    let format = RequestedFormat::new::<RgbAFormat>(
        RequestedFormatType::AbsoluteHighestResolution,
    );

    let mut camera = match Camera::new(CameraIndex::Index(0), format) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("transferd-webrtc: camera unavailable: {e}");
            return false;
        }
    };

    if let Err(e) = camera.open_stream() {
        eprintln!("transferd-webrtc: camera open_stream failed: {e}");
        return false;
    }

    while !stopped.load(Ordering::Relaxed) {
        match camera.frame() {
            Ok(buf) => match buf.decode_image::<RgbAFormat>() {
                Ok(img) => {
                    let frame = VideoFrame {
                        width:  img.width(),
                        height: img.height(),
                        rgba:   img.into_raw(),
                    };
                    if tok_tx.blocking_send(frame).is_err() { break; }
                }
                Err(e) => eprintln!("transferd-webrtc: frame decode error: {e}"),
            },
            Err(_) => {
                // Camera hiccup — brief pause, keep trying.
                std::thread::sleep(std::time::Duration::from_millis(33));
            }
        }
    }

    let _ = camera.stop_stream();
    true
}
