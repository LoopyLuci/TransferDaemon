//! transferd-webrtc — WebRTC call infrastructure for TransferDaemon.
//!
//! Default build: pure-Rust `SimulatedCallSession` (no hardware, fast tests).
//! Enable the `real-webrtc` feature to swap in `webrtc-rs` + `cpal` + `nokhwa`.

pub mod media;
pub mod manager;
pub mod session;
pub mod types;

pub use manager::CallManager;
pub use media::{MediaCapture, MockMediaCapture, SilentCapture};
pub use session::SimulatedCallSession;
pub use types::{AudioSamples, CallState, IceCandidateInit, VideoFrame};
