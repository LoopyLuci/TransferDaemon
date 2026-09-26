#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the handshake message parser
    // This tests that malformed handshake messages don't crash the parser
    let _ = transferd_lib::handshake_manager::HandshakeMessage::from_bytes(data);
});
