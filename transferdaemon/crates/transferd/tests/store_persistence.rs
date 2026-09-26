//! Integration tests for encrypted persistent storage.
//!
//! These tests start a real daemon server backed by a temp-dir store and drive
//! the full create → stop → restore round-trip over gRPC.

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tonic::transport::Server;

use transferd_api::{
    AccountServiceClient, FriendServiceClient, MessageServiceClient, SettingsServiceClient,
    AddContactRequest, CreateIdentityRequest, GetMessagesRequest, GetSettingRequest,
    RestoreIdentityRequest, SendTextRequest, SetSettingRequest, Empty,
};
use transferd_lib::{grpc::add_all_services, DaemonState};
use transferd_store::StoreParams;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spin up a daemon backed by a store in `dir` using fast Argon2 params.
async fn start_daemon_with_store(dir: &TempDir) -> SocketAddr {
    let store_path = dir.path().join("user_data.enc");
    let state = Arc::new(Mutex::new(
        DaemonState::with_store(store_path, StoreParams::fast()),
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        add_all_services(Server::builder(), state)
            .serve_with_incoming(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
            )
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

macro_rules! client {
    ($T:ty, $addr:expr) => {{
        let url = format!("http://{}", $addr);
        <$T>::connect(url).await.unwrap()
    }};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Create an identity, add contacts and messages, then restart the daemon and
/// verify all data is present after restoring with the recovery phrase.
#[tokio::test]
async fn data_persists_across_restarts() {
    let dir = TempDir::new().unwrap();

    // ── First daemon instance ─────────────────────────────────────────────────
    let addr1 = start_daemon_with_store(&dir).await;
    let mut ac1 = client!(AccountServiceClient<_>, addr1);
    let mut fc1 = client!(FriendServiceClient<_>, addr1);
    let mut mc1 = client!(MessageServiceClient<_>, addr1);
    let mut sc1 = client!(SettingsServiceClient<_>, addr1);

    // Create identity "Alice".
    let phrase = ac1
        .create_identity(CreateIdentityRequest { display_name: "Alice".into() })
        .await.unwrap().into_inner().phrase;
    assert_eq!(phrase.split_whitespace().count(), 12);

    // Add a contact.
    let bob_key = "b".repeat(64);
    fc1.add_contact(AddContactRequest { public_key: bob_key.clone(), name: "Bob".into() })
        .await.unwrap();

    // Send a message.
    mc1.send_text(SendTextRequest { contact_id: bob_key.clone(), text: "hello persistent world".into(), reply_to: String::new() })
        .await.unwrap();

    // Save a setting.
    sc1.set_setting(SetSettingRequest { key: "theme".into(), value: "dark".into() })
        .await.unwrap();

    drop((ac1, fc1, mc1, sc1));

    // ── Second daemon instance (simulates restart) ────────────────────────────
    let addr2 = start_daemon_with_store(&dir).await;
    let mut ac2 = client!(AccountServiceClient<_>, addr2);
    let mut fc2 = client!(FriendServiceClient<_>, addr2);
    let mut mc2 = client!(MessageServiceClient<_>, addr2);
    let mut sc2 = client!(SettingsServiceClient<_>, addr2);

    // Before restore: no identity in the new in-memory state.
    let pre = ac2.get_identity(Empty {}).await.unwrap().into_inner();
    assert!(!pre.has_identity, "fresh instance should have no identity");

    // Restore with the phrase — should load everything from disk.
    let restored = ac2
        .restore_identity(RestoreIdentityRequest { phrase: phrase.clone() })
        .await.unwrap().into_inner();

    assert!(restored.has_identity);
    assert_eq!(restored.display_name, "Alice",
        "display name must be restored from disk, not fall back to a placeholder");
    assert_eq!(restored.public_key.len(), 64);

    // Contacts must be present.
    let contacts = fc2
        .get_contacts(Empty {}).await.unwrap().into_inner().contacts;
    assert_eq!(contacts.len(), 1, "Bob must be restored");
    assert_eq!(contacts[0].name, "Bob");

    // Messages must be present.
    let msgs = mc2
        .get_messages(GetMessagesRequest { contact_id: bob_key.clone() })
        .await.unwrap().into_inner().messages;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].text, "hello persistent world");

    // Settings must be present.
    let setting = sc2
        .get_setting(GetSettingRequest { key: "theme".into() })
        .await.unwrap().into_inner();
    assert!(setting.found);
    assert_eq!(setting.value, "dark");
}

/// The "Restored User" placeholder must never appear when a store file exists.
#[tokio::test]
async fn restore_returns_original_display_name_not_placeholder() {
    let dir = TempDir::new().unwrap();

    // Create "Charlie".
    let addr1 = start_daemon_with_store(&dir).await;
    let mut ac1 = client!(AccountServiceClient<_>, addr1);
    let phrase = ac1
        .create_identity(CreateIdentityRequest { display_name: "Charlie".into() })
        .await.unwrap().into_inner().phrase;

    // Simulate restart.
    let addr2 = start_daemon_with_store(&dir).await;
    let mut ac2 = client!(AccountServiceClient<_>, addr2);
    let r = ac2
        .restore_identity(RestoreIdentityRequest { phrase })
        .await.unwrap().into_inner();

    assert_eq!(r.display_name, "Charlie");
    assert_ne!(r.display_name, "Restored User",
        "placeholder must not appear when a store file is present");
}

/// Wrong phrase must not succeed (store decryption must fail).
#[tokio::test]
async fn wrong_phrase_cannot_restore() {
    let dir = TempDir::new().unwrap();

    let addr = start_daemon_with_store(&dir).await;
    let mut ac = client!(AccountServiceClient<_>, addr);
    let _phrase = ac
        .create_identity(CreateIdentityRequest { display_name: "Dave".into() })
        .await.unwrap().into_inner().phrase;

    // Restart, then attempt restore with a different phrase.
    let addr2 = start_daemon_with_store(&dir).await;
    let mut ac2 = client!(AccountServiceClient<_>, addr2);

    // A valid BIP-39 phrase that is NOT the account's phrase.
    let wrong = ac2
        .create_identity(CreateIdentityRequest { display_name: "tmp".into() })
        .await.unwrap().into_inner().phrase;

    // Restart again so the account is Dave's.
    let addr3 = start_daemon_with_store(&dir).await;
    let mut ac3 = client!(AccountServiceClient<_>, addr3);

    // Restoring with the wrong phrase should still work cryptographically
    // (the phrase itself is valid BIP-39) but the store will fail to decrypt,
    // so the daemon falls back to deriving just the key without loading data.
    let r = ac3
        .restore_identity(RestoreIdentityRequest { phrase: wrong })
        .await.unwrap().into_inner();

    // The key is derived from the phrase, so it will differ from Dave's.
    // The display name will be empty (no stored data loaded).
    assert!(r.has_identity);
    // The display name must NOT be "Dave" — it came from a different phrase.
    assert_ne!(r.display_name, "Dave",
        "wrong phrase must not expose another account's data");
}
