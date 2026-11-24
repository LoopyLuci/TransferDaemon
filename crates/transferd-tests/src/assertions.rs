//! Custom assertion helpers for TransferDaemon tests.
//!
//! Provides readable assertions with descriptive failure messages.

use std::fmt::Debug;

/// Assert that a `Result` is `Ok` and its value matches a predicate.
pub fn assert_result_ok<T: Debug>(result: &Result<T, impl Debug>, msg: &str) {
    assert!(result.is_ok(), "Expected Ok({msg}), got Err({:?})", result.as_ref().err());
}

/// Assert that a gRPC response has the expected status.
pub fn assert_grpc_success<T: std::fmt::Debug>(result: &Result<T, tonic::Status>, method: &str) {
    assert!(
        result.is_ok(),
        "gRPC call {method} failed: {:?}",
        result.as_ref().unwrap_err()
    );
}

/// Assert that an identity response has a public key.
pub fn assert_has_identity(reply: &transferd_api::IdentityReply) {
    assert!(reply.has_identity, "Expected has_identity to be true");
    assert!(!reply.public_key.is_empty(), "Expected non-empty public_key");
    assert!(!reply.display_name.is_empty(), "Expected non-empty display_name");
}

/// Assert that a contact list contains a specific contact.
pub fn assert_contact_exists(contacts: &[transferd_api::ContactReply], public_key: &str) {
    assert!(
        contacts.iter().any(|c| c.id == public_key),
        "Expected contact with public_key {public_key} in list of {} contacts",
        contacts.len()
    );
}

/// Assert that a message has a specific status.
pub fn assert_message_status(msg: &transferd_api::MessageReply, expected_status: &str) {
    assert_eq!(
        msg.status, expected_status,
        "Expected message status '{expected_status}', got '{}'",
        msg.status
    );
}
