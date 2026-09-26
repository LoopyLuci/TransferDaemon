//! End-to-end test using the shared test utilities.
//!
//! Tests the full daemon stack: identity creation, contact management,
//! messaging, and settings.

#![cfg(test)]

use transferd_tests::TestDaemon;

/// Helper to create an AccountServiceClient.
async fn account_client(addr: &str) -> transferd_api::AccountServiceClient<
    tonic::transport::Channel,
> {
    transferd_api::AccountServiceClient::connect(addr.to_owned())
        .await
        .unwrap()
}

/// Helper to create a FriendServiceClient.
async fn friend_client(addr: &str) -> transferd_api::FriendServiceClient<
    tonic::transport::Channel,
> {
    transferd_api::FriendServiceClient::connect(addr.to_owned())
        .await
        .unwrap()
}

/// Helper to create a MessageServiceClient.
async fn message_client(addr: &str) -> transferd_api::MessageServiceClient<
    tonic::transport::Channel,
> {
    transferd_api::MessageServiceClient::connect(addr.to_owned())
        .await
        .unwrap()
}

#[tokio::test]
async fn test_daemon_starts_and_creates_identity() {
    let daemon = TestDaemon::start().await;
    let mut client = account_client(&daemon.addr).await;

    let phrase_reply = client
        .create_identity(transferd_api::CreateIdentityRequest {
            display_name: "TestUser".into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!phrase_reply.phrase.is_empty());

    let identity = client
        .get_identity(transferd_api::Empty {})
        .await
        .unwrap()
        .into_inner();

    assert!(identity.has_identity);
    assert!(!identity.public_key.is_empty());
    assert_eq!(identity.display_name, "TestUser");
}

#[tokio::test]
async fn test_add_and_list_contacts() {
    let daemon = TestDaemon::start().await;
    let mut acct = account_client(&daemon.addr).await;
    let mut friend = friend_client(&daemon.addr).await;

    // Create identity first
    acct.create_identity(transferd_api::CreateIdentityRequest {
        display_name: "TestUser".into(),
    })
    .await
    .unwrap();

    // Add a contact
    let contact = friend
        .add_contact(transferd_api::AddContactRequest {
            public_key: format!("{:016x}", 2u8).repeat(4),
            name: "Alice".into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(contact.name, "Alice");

    // List contacts
    let contacts = friend
        .get_contacts(transferd_api::Empty {})
        .await
        .unwrap()
        .into_inner()
        .contacts;

    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "Alice");
}

#[tokio::test]
async fn test_send_and_receive_message() {
    let daemon = TestDaemon::start().await;
    let mut acct = account_client(&daemon.addr).await;
    let mut friend = friend_client(&daemon.addr).await;
    let mut msg_client = message_client(&daemon.addr).await;

    // Create identity
    acct.create_identity(transferd_api::CreateIdentityRequest {
        display_name: "TestUser".into(),
    })
    .await
    .unwrap();

    // Add contact
    let contact = friend
        .add_contact(transferd_api::AddContactRequest {
            public_key: format!("{:016x}", 2u8).repeat(4),
            name: "Alice".into(),
        })
        .await
        .unwrap()
        .into_inner();

    // Send message
    let msg = msg_client
        .send_text(transferd_api::SendTextRequest {
            contact_id: contact.id.clone(),
            text: "Hello!".into(),
            reply_to: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(msg.text, "Hello!");

    // Get messages
    let messages = msg_client
        .get_messages(transferd_api::GetMessagesRequest {
            contact_id: contact.id,
        })
        .await
        .unwrap()
        .into_inner()
        .messages;

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text, "Hello!");
}
