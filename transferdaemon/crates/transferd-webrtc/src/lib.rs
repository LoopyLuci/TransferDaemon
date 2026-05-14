//! transferd-webrtc — WebRTC call infrastructure for TransferDaemon.
//!
//! Default build: pure-Rust `SimulatedCallSession` (no hardware, fast tests).
//! Enable the `real-webrtc` feature to swap in `webrtc-rs` + `cpal` + `nokhwa`.

pub mod media;
pub mod manager;
pub mod session;
pub mod types;
#[cfg(feature = "grpc-signaling")]
pub mod grpc_signaling;

pub use manager::CallManager;
pub use media::{MediaCapture, MockMediaCapture, SilentCapture, new_default_capture};
#[cfg(feature = "desktop-capture")]
pub use media::DesktopMediaCapture;
pub use session::SimulatedCallSession;
pub use types::{AudioSamples, CallState, IceCandidateInit, VideoFrame};
