//! State replicated across a person's own devices: a Raft log of SQL statements, applied to SQLite on every device
//! (the capabilities of CockroachDB that TransferD needs: strongly consistent, survives losing a minority of
//! devices, any device can read and write through the leader).
//!
//!   raft   the consensus core: a pure state machine, tested under loss, partitions and crashes
//!   node   a device's replica: durable Raft state, the TCP transport between devices, SQLite, the client API

pub mod node;
pub mod raft;
