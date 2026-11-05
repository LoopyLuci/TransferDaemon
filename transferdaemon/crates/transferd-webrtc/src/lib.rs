//! transferd-webrtc — WebRTC call infrastructure for TransferDaemon.
//!
//! Default build: pure-Rust `SimulatedCallSession` (no hardware, fast tests).
//! Enable the `real-webrtc` feature to swap in `webrtc-rs` + `cpal` + `nokhwa`.

#[cfg(feature = "grpc-signaling")]
pub mod grpc_signaling;
pub mod manager;
pub mod media;
#[cfg(feature = "real-webrtc")]
pub mod rtc_session;
pub mod session;
pub mod types;

pub use manager::CallManager;
#[cfg(feature = "desktop-capture")]
pub use media::DesktopMediaCapture;
pub use media::{new_default_capture, MediaCapture, MockMediaCapture, SilentCapture};
#[cfg(feature = "real-webrtc")]
pub use rtc_session::{RtcCallSession, WebRtcError};
pub use session::SimulatedCallSession;
pub use types::{AudioSamples, CallState, IceCandidateInit, VideoFrame};
