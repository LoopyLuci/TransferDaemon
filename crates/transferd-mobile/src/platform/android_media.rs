//! Android media capture — implements the `MediaCapture` trait via JNI calls to
//! `CameraHelper.java` (Camera2) and `AudioHelper.java` (AudioRecord).
//!
//! Flow:
//!   start_audio/start_video → stores tokio Sender in a global → calls Java static start()
//!   Java → deliverFrame / deliverAudio JNI callbacks → push to Sender
//!   stop_audio/stop_video → drops Sender (closes channel) → calls Java static stop()

use android_activity::AndroidApp;
use async_trait::async_trait;
use jni::objects::{JByteArray, JClass};
use jni::sys::jint;
use jni::JNIEnv;
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc;
use transferd_webrtc::{
    media::MediaCapture,
    types::{AudioSamples, VideoFrame},
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

/// AndroidApp stored once on startup so JNI trigger functions can reach the JVM.
static APP: OnceLock<Mutex<AndroidApp>> = OnceLock::new();

/// Channel senders filled by start_* and cleared by stop_*.
static VIDEO_TX: Mutex<Option<mpsc::Sender<VideoFrame>>> = Mutex::new(None);
static AUDIO_TX: Mutex<Option<mpsc::Sender<AudioSamples>>> = Mutex::new(None);

/// Store the AndroidApp so trigger functions can call into the JVM later.
pub fn init(app: AndroidApp) {
    APP.set(Mutex::new(app)).ok();
}

// ---------------------------------------------------------------------------
// AndroidMediaCapture
// ---------------------------------------------------------------------------

pub struct AndroidMediaCapture {
    video: bool,
}

impl AndroidMediaCapture {
    pub fn new(video: bool) -> Self {
        Self { video }
    }
}

#[async_trait]
impl MediaCapture for AndroidMediaCapture {
    async fn start_audio(&self) -> mpsc::Receiver<AudioSamples> {
        let (tx, rx) = mpsc::channel(32);
        *AUDIO_TX.lock().unwrap() = Some(tx);
        trigger_java("AudioHelper", "start", "()V");
        rx
    }

    async fn stop_audio(&self) {
        *AUDIO_TX.lock().unwrap() = None; // drops sender → channel closes
        trigger_java("AudioHelper", "stop", "()V");
    }

    async fn start_video(&self) -> Option<mpsc::Receiver<VideoFrame>> {
        if !self.video {
            return None;
        }
        let (tx, rx) = mpsc::channel(4);
        *VIDEO_TX.lock().unwrap() = Some(tx);
        trigger_java("CameraHelper", "start", "()V");
        Some(rx)
    }

    async fn stop_video(&self) {
        *VIDEO_TX.lock().unwrap() = None; // drops sender → channel closes
        trigger_java("CameraHelper", "stop", "()V");
    }
}

// ---------------------------------------------------------------------------
// JNI trigger: call a static void method on a Java helper class
// ---------------------------------------------------------------------------

fn trigger_java(class_short: &str, method: &str, sig: &str) {
    let app_lock = match APP.get() {
        Some(l) => l,
        None => {
            super::super::platform::android_logger::log(&format!(
                "android_media: trigger_java({class_short}.{method}) — APP not set"
            ));
            return;
        }
    };
    let app = app_lock.lock().unwrap();
    unsafe {
        let vm_ptr = app.vm_as_ptr() as *mut jni::sys::JavaVM;
        let vm = match jni::JavaVM::from_raw(vm_ptr) {
            Ok(v) => v,
            Err(e) => {
                super::super::platform::android_logger::log(&format!(
                    "android_media: JavaVM::from_raw failed: {e:?}"
                ));
                return;
            }
        };
        let mut env = vm.get_env().unwrap_or_else(|_| {
            vm.attach_current_thread_permanently()
                .expect("attach JNI thread for trigger_java")
        });
        let class_path = format!("com/transferdaemon/app/{class_short}");
        match env.find_class(&class_path) {
            Ok(cls) => {
                if let Err(e) = env.call_static_method(cls, method, sig, &[]) {
                    super::super::platform::android_logger::log(&format!(
                        "android_media: {class_short}.{method} failed: {e:?}"
                    ));
                }
            }
            Err(e) => {
                super::super::platform::android_logger::log(&format!(
                    "android_media: find_class {class_short} failed: {e:?}"
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JNI callbacks: Java → Rust
// ---------------------------------------------------------------------------

/// Called by `CameraHelper.deliverFrame(byte[] yuv, int width, int height)`.
/// Converts I420 YUV to RGBA and pushes a `VideoFrame` to the active call session.
#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_CameraHelper_deliverFrame(
    env: JNIEnv,
    _class: JClass,
    yuv_array: JByteArray,
    width: jint,
    height: jint,
) {
    let yuv = match env.convert_byte_array(&yuv_array) {
        Ok(v) => v,
        Err(_) => return,
    };
    let rgba = yuv_i420_to_rgba(&yuv, width as u32, height as u32);
    let frame = VideoFrame { width: width as u32, height: height as u32, rgba };
    if let Ok(guard) = VIDEO_TX.lock() {
        if let Some(tx) = &*guard {
            let _ = tx.try_send(frame);
        }
    }
}

/// Called by `AudioHelper.deliverAudio(byte[] pcm16leBytes)`.
/// Converts interleaved PCM‑16 LE to 480‑sample f32 chunks and sends them.
#[no_mangle]
pub extern "system" fn Java_com_transferdaemon_app_AudioHelper_deliverAudio(
    env: JNIEnv,
    _class: JClass,
    pcm_array: JByteArray,
) {
    let pcm = match env.convert_byte_array(&pcm_array) {
        Ok(v) => v,
        Err(_) => return,
    };
    // PCM is i16 LE → normalise to f32 [-1, 1]
    let f32_samples: Vec<f32> = pcm
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]) as f32 / 32768.0)
        .collect();

    if let Ok(guard) = AUDIO_TX.lock() {
        if let Some(tx) = &*guard {
            // The WebRTC session expects 480-sample frames (10 ms @ 48 kHz).
            for chunk in f32_samples.chunks(480) {
                let mut frame = chunk.to_vec();
                frame.resize(480, 0.0); // pad last chunk if needed
                let _ = tx.try_send(frame);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// YUV I420 → RGBA conversion (BT.601 coefficients, no SIMD)
// ---------------------------------------------------------------------------

/// Converts an I420 (planar YUV 4:2:0) byte buffer to packed RGBA.
///
/// Camera2 ImageFormat.YUV_420_888 is stored as I420 when the app reads all
/// three planes sequentially into one byte array via `CameraHelper.java`.
fn yuv_i420_to_rgba(yuv: &[u8], width: u32, height: u32) -> Vec<u8> {
    let w = width as usize;
    let h = height as usize;
    let y_size = w * h;
    let uv_plane_size = w / 2 * (h / 2);

    // Guard against malformed buffers.
    if yuv.len() < y_size + 2 * uv_plane_size {
        return vec![0u8; w * h * 4];
    }

    let y_plane = &yuv[..y_size];
    let u_plane = &yuv[y_size..y_size + uv_plane_size];
    let v_plane = &yuv[y_size + uv_plane_size..y_size + 2 * uv_plane_size];

    let mut rgba = vec![255u8; w * h * 4];

    for row in 0..h {
        for col in 0..w {
            let y = y_plane[row * w + col] as f32;
            let uv_row = row / 2;
            let uv_col = col / 2;
            let uv_idx = uv_row * (w / 2) + uv_col;
            let u = u_plane[uv_idx] as f32 - 128.0;
            let v = v_plane[uv_idx] as f32 - 128.0;

            // BT.601 full-range
            let r = (y + 1.402 * v).clamp(0.0, 255.0) as u8;
            let g = (y - 0.344_136 * u - 0.714_136 * v).clamp(0.0, 255.0) as u8;
            let b = (y + 1.772 * u).clamp(0.0, 255.0) as u8;

            let base = (row * w + col) * 4;
            rgba[base]     = r;
            rgba[base + 1] = g;
            rgba[base + 2] = b;
            // rgba[base + 3] already 255
        }
    }
    rgba
}
