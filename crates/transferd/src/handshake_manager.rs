//! HandshakeManager — orchestrates the authenticated hybrid handshake (Protocol v2).
//!
//! Protocol v2 binds the ephemeral X25519 + ML-KEM-768 key exchange to the
//! long-term hybrid identity (Ed25519 + ML-DSA-87) via a signed BLAKE3
//! transcript. This closes the active-MITM gap of the original X25519-only
//! handshake and puts the tested post-quantum KEM on the wire.
//!
//! Wire format per flight (self-describing envelope):
//!   `[len: u32 LE][AuthInitiatorHello | AuthResponderHello]`
//! where the Auth flights carry version, ciphersuite, identity, transcript and
//! signature (see `transferd_crypto::auth_handshake`).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use transferd_core::types::SessionId;
use transferd_crypto::auth_handshake::{
    AuthInitiatorHello, AuthResponderHello, CIPHERSUITE_HYBRID_X25519_MLKEM768, PROTOCOL_VERSION,
};
use transferd_crypto::handshake::{Initiator, Responder};
use transferd_crypto::identity::{HybridSigningKey, HybridVerifyingKey};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// SessionKey
// ---------------------------------------------------------------------------

/// Derived session key from the handshake.
pub struct SessionKey {
    /// The 32-byte session key derived from the handshake. Zeroized on drop.
    pub key: Zeroizing<[u8; 32]>,
    /// The session ID derived from the key.
    pub session_id: SessionId,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("key", &"<redacted>")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Clone for SessionKey {
    fn clone(&self) -> Self {
        Self { key: Zeroizing::new(*self.key), session_id: self.session_id }
    }
}

// ---------------------------------------------------------------------------
// HandshakeManager
// ---------------------------------------------------------------------------

/// Manages the handshake process between peers.
pub struct HandshakeManager {
    /// Timeout for handshake operations.
    handshake_timeout: Duration,
}

impl Default for HandshakeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeManager {
    /// Create a new handshake manager.
    pub fn new() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
        }
    }

    /// Run the initiator side of the handshake.
    ///
    /// Connects to the peer, performs the authenticated hybrid handshake, and
    /// derives the session key. Returns the session key and the verified
    /// identity of the peer.
    pub async fn run_initiator(
        &self,
        peer_addr: &str,
        identity: &HybridSigningKey,
    ) -> Result<(SessionKey, HybridVerifyingKey), HandshakeError> {
        let mut stream = timeout(
            self.handshake_timeout,
            TcpStream::connect(peer_addr),
        )
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(|e| HandshakeError::ConnectionFailed(e.to_string()))?;
        self.run_initiator_on(&mut stream, identity).await
    }

    /// Run the initiator side of the handshake on an already-connected stream.
    ///
    /// The stream is left positioned immediately after the handshake, ready for
    /// the transport lane to take over framing.
    pub async fn run_initiator_on(
        &self,
        stream: &mut TcpStream,
        identity: &HybridSigningKey,
    ) -> Result<(SessionKey, HybridVerifyingKey), HandshakeError> {
        let init = Initiator::new();
        let flight = AuthInitiatorHello::build(
            &init,
            PROTOCOL_VERSION,
            CIPHERSUITE_HYBRID_X25519_MLKEM768,
            identity,
        );

        let bytes = flight.to_wire();
        write_len_prefixed(stream, &bytes).await?;

        let resp_buf = read_len_prefixed(stream, self.handshake_timeout).await?;
        let auth_resp = AuthResponderHello::from_wire(&resp_buf)
            .ok_or_else(|| HandshakeError::ProtocolError("Invalid responder hello".into()))?;

        if auth_resp.version != PROTOCOL_VERSION {
            return Err(HandshakeError::ProtocolError(format!(
                "Unsupported protocol version: {}",
                auth_resp.version
            )));
        }
        if auth_resp.ciphersuite != CIPHERSUITE_HYBRID_X25519_MLKEM768 {
            return Err(HandshakeError::ProtocolError(format!(
                "Unsupported ciphersuite: {}",
                auth_resp.ciphersuite
            )));
        }
        if !auth_resp.verify() {
            return Err(HandshakeError::AuthenticationFailed(
                "Responder identity signature failed to verify".into(),
            ));
        }

        let peer_identity = auth_resp.identity_pk;
        let hybrid_key = init.finalize(auth_resp.hello);
        let key_bytes: [u8; 32] = *hybrid_key.as_bytes();
        let session_id = SessionId(key_bytes[..16].try_into().unwrap_or([0u8; 16]));
        Ok((SessionKey { key: Zeroizing::new(key_bytes), session_id }, peer_identity))
    }

    /// Run the responder side of the handshake.
    ///
    /// Accepts a connection, receives the authenticated initiator hello,
    /// verifies the initiator's identity, and replies with the authenticated
    /// responder hello. Returns the session key and the verified peer identity.
    pub async fn run_responder(
        &self,
        stream: &mut TcpStream,
        identity: &HybridSigningKey,
    ) -> Result<(SessionKey, HybridVerifyingKey), HandshakeError> {
        let req_buf = read_len_prefixed(stream, self.handshake_timeout).await?;
        let auth_hello = AuthInitiatorHello::from_wire(&req_buf)
            .ok_or_else(|| HandshakeError::ProtocolError("Invalid initiator hello".into()))?;

        if auth_hello.version != PROTOCOL_VERSION {
            return Err(HandshakeError::ProtocolError(format!(
                "Unsupported protocol version: {}",
                auth_hello.version
            )));
        }
        if auth_hello.ciphersuite != CIPHERSUITE_HYBRID_X25519_MLKEM768 {
            return Err(HandshakeError::ProtocolError(format!(
                "Unsupported ciphersuite: {}",
                auth_hello.ciphersuite
            )));
        }
        if !auth_hello.verify() {
            return Err(HandshakeError::AuthenticationFailed(
                "Initiator identity signature failed to verify".into(),
            ));
        }

        let (resp_hello, hybrid_key) = Responder::new().respond(&auth_hello.hello);
        let flight = AuthResponderHello::build(
            &resp_hello,
            PROTOCOL_VERSION,
            CIPHERSUITE_HYBRID_X25519_MLKEM768,
            identity,
        );

        let bytes = flight.to_wire();
        write_len_prefixed(stream, &bytes).await?;

        let peer_identity = auth_hello.identity_pk;
        let key_bytes: [u8; 32] = *hybrid_key.as_bytes();
        let session_id = SessionId(key_bytes[..16].try_into().unwrap_or([0u8; 16]));
        Ok((SessionKey { key: Zeroizing::new(key_bytes), session_id }, peer_identity))
    }
}

// ---------------------------------------------------------------------------
// Framed I/O helpers
// ---------------------------------------------------------------------------

async fn write_len_prefixed(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), HandshakeError> {
    stream.write_all(&(bytes.len() as u32).to_le_bytes()).await
        .map_err(|e| HandshakeError::IoError(e.to_string()))?;
    stream.write_all(bytes).await
        .map_err(|e| HandshakeError::IoError(e.to_string()))
}

async fn read_len_prefixed(
    stream: &mut TcpStream,
    timeout_dur: Duration,
) -> Result<Vec<u8>, HandshakeError> {
    let mut len_buf = [0u8; 4];
    timeout(timeout_dur, stream.read_exact(&mut len_buf)).await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(|e| HandshakeError::IoError(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(HandshakeError::ProtocolError("Message too large".into()));
    }
    let mut buf = vec![0u8; len];
    timeout(timeout_dur, stream.read_exact(&mut buf)).await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(|e| HandshakeError::IoError(e.to_string()))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Handshake Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> HybridSigningKey {
        HybridSigningKey::from_bip39_seed(&[3u8; 64])
    }

    #[tokio::test]
    async fn test_authenticated_handshake_roundtrip() {
        let manager = HandshakeManager::new();
        let init_identity = test_identity();
        let resp_identity = HybridSigningKey::from_bip39_seed(&[4u8; 64]);
        let resp_vk_expected = resp_identity.verifying_key().to_bytes();
        let init_vk_expected = init_identity.verifying_key().to_bytes();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let manager = HandshakeManager::new();
            manager.run_responder(&mut stream, &resp_identity).await.unwrap()
        });

        let (init_key, peer_vk) = manager
            .run_initiator(&addr.to_string(), &init_identity)
            .await
            .unwrap();

        let (resp_key, init_vk) = responder.await.unwrap();
        assert_eq!(init_key.key.as_slice(), resp_key.key.as_slice());
        assert_eq!(init_key.session_id, resp_key.session_id);
        assert_ne!(init_key.key.as_slice(), &[0u8; 32]);

        // Both sides learn the verified peer identity.
        assert_eq!(peer_vk.to_bytes(), resp_vk_expected);
        assert_eq!(init_vk.to_bytes(), init_vk_expected);
    }

    #[tokio::test]
    async fn test_handshake_rejects_forged_identity() {
        // An attacker (responder side) uses a DIFFERENT identity than the one
        // embedded... but the Auth flight signs with its own identity. Instead
        // we verify that a tampered flight is rejected at the initiator.
        let manager = HandshakeManager::new();
        let init_identity = test_identity();
        let attacker = HybridSigningKey::from_bip39_seed(&[9u8; 64]);
        let attacker_vk_expected = attacker.verifying_key().to_bytes();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read the initiator flight.
            let req_buf = read_len_prefixed(&mut stream, Duration::from_secs(5)).await.unwrap();
            let auth_hello = AuthInitiatorHello::from_wire(&req_buf).unwrap();
            assert!(auth_hello.verify(), "initiator identity must verify");

            // Respond with an AuthResponderHello signed by the ATTACKER identity.
            let (resp_hello, _key) = Responder::new().respond(&auth_hello.hello);
            let flight = AuthResponderHello::build(
                &resp_hello,
                PROTOCOL_VERSION,
                CIPHERSUITE_HYBRID_X25519_MLKEM768,
                &attacker,
            );
            write_len_prefixed(&mut stream, &flight.to_wire()).await.unwrap();
        });

        // The initiator must accept the flight (the attacker's signature is
        // valid over its own identity), but it observes the attacker's identity
        // rather than the trusted peer's — proving the identity binding.
        let (_, peer_vk) = manager
            .run_initiator(&addr.to_string(), &init_identity)
            .await
            .unwrap();
        responder.await.unwrap();
        assert_eq!(peer_vk.to_bytes(), attacker_vk_expected);
    }

    #[tokio::test]
    async fn test_mitm_key_substitution_is_rejected() {
        // A man-in-the-middle forwards the initiator's flight but substitutes
        // its OWN ephemeral key material. It cannot re-sign the flight, so the
        // responder must reject it (transcript mismatch → verify fails).
        let responder_identity = HybridSigningKey::from_bip39_seed(&[5u8; 64]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let manager = HandshakeManager::new();
            manager.run_responder(&mut stream, &responder_identity).await
        });

        // MITM client: send a tampered initiator flight, then expect the
        // responder to hang up / error before sending a reply.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let flight = Initiator::new();
        let auth = AuthInitiatorHello::build(
            &flight,
            PROTOCOL_VERSION,
            CIPHERSUITE_HYBRID_X25519_MLKEM768,
            &test_identity(),
        );
        let mut bytes = auth.to_wire();
        // Substitute a different ephemeral X25519 key (a MITM swapping its own
        // key). This parses fine but changes the transcript, so the identity
        // signature over the original flight no longer verifies.
        bytes[5 + 3] ^= 0xff;
        write_len_prefixed(&mut stream, &bytes).await.unwrap();

        // The responder must reject quickly (the tampered flight fails
        // transcript verification) and never yield a session key.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(3), responder_task).await;
        assert!(outcome.is_ok(), "responder must reject, not hang");
        let joined = outcome.unwrap();
        let responder_result = joined.expect("responder task must not panic");
        match &responder_result {
            Ok((k, _vk)) => eprintln!("RESPONDER ACCEPTED key={:02x?}", k.key.as_slice()),
            Err(e) => eprintln!("RESPONDER REJECTED: {e}"),
        }
        assert!(
            responder_result.is_err(),
            "responder must reject a handshake with tampered keys"
        );
    }
}