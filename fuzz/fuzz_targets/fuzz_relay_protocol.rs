#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the relay protocol frame parser
    // This tests that malformed relay frames don't crash the protocol parser
    if let Some((tag, body)) = relayd::protocol::split(data) {
        // Test deserialization of each message type
        match tag {
            relayd::protocol::Tag::Register => {
                let _ = bincode::deserialize::<relayd::protocol::RegisterMsg>(body);
            }
            relayd::protocol::Tag::Forward => {
                let _ = bincode::deserialize::<relayd::protocol::ForwardMsg>(body);
            }
            relayd::protocol::Tag::Keepalive => {
                let _ = bincode::deserialize::<relayd::protocol::KeepaliveMsg>(body);
            }
            _ => {}
        }
    }
});

