//! Authenticated tonic channel wrapper.
//!
//! The daemon authenticates every gRPC call with an `Authorization: Bearer
//! <token>` header. `AuthChannel` wraps a `Channel` so every request carries
//! that header transparently, keeping call sites unchanged.

use std::pin::Pin;
use std::task::{Context, Poll};

use http::{HeaderValue, Request, Response};
use tonic::body::BoxBody;
use tonic::transport::{Channel, Error};
use tower::Service;

/// A `Channel` that attaches an `Authorization: Bearer <token>` header to every
/// request. Clone, so it can be handed to generated tonic clients directly.
#[derive(Clone)]
pub struct AuthChannel {
    inner: Channel,
    auth: HeaderValue,
}

impl AuthChannel {
    /// Wrap `channel` so requests carry the given bearer token.
    pub fn new(channel: Channel, token: &str) -> Self {
        let auth = HeaderValue::from_str(&format!("Bearer {token}"))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer "));
        Self { inner: channel, auth }
    }
}

impl Service<Request<BoxBody>> for AuthChannel {
    type Response = Response<tonic::transport::Body>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<BoxBody>) -> Self::Future {
        request.headers_mut().insert("authorization", self.auth.clone());
        Box::pin(self.inner.call(request))
    }
}

// ---------------------------------------------------------------------------
// Token resolution
// ---------------------------------------------------------------------------

/// Location of the daemon's auth-token file: `<data-local>/transferdaemon/daemon_token`.
///
/// `TRANSFERD_DATA_DIR` overrides the data directory (portable installs/tests).
pub fn token_file_path() -> std::path::PathBuf {
    let base = std::env::var_os("TRANSFERD_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            dirs::data_local_dir().unwrap_or_else(|| std::path::PathBuf::from("."))
        });
    base.join("transferdaemon").join("daemon_token")
}

/// Resolve the auth token a client should present: `TRANSFERD_TOKEN` env var,
/// else the token file, else `None` (daemon is unauthenticated / dev mode).
pub fn resolve_token() -> Option<String> {
    if let Ok(token) = std::env::var("TRANSFERD_TOKEN") {
        return if token.is_empty() { None } else { Some(token) };
    }
    read_token_file(&token_file_path())
}

/// Read a token previously written by the daemon.
pub fn read_token_file(path: &std::path::Path) -> Option<String> {
    let token = std::fs::read_to_string(path).ok()?;
    let token = token.trim();
    if token.is_empty() { None } else { Some(token.to_owned()) }
}

/// Persist `token` to the token file, creating parent dirs. On Unix the file is
/// created with owner-only permissions (0o600).
pub fn write_token_file(path: &std::path::Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}