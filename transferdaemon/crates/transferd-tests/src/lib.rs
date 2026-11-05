//! Shared test utilities for TransferDaemon integration tests.
//!
//! This crate provides reusable test infrastructure:
//! - `TestDaemon`: in-process gRPC daemon for testing
//! - `TestFixture`: test data generators
//! - `TestAssertions`: custom assertion helpers
//! - `TestPort`: random port allocation

pub mod assertions;
pub mod daemon;
pub mod fixtures;

/// Re-export key types for convenience.
pub use daemon::TestDaemon;
pub use fixtures::TestFixture;
