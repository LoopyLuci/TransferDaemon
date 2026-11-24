#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Every chunk a peer sends is decoded into a WireMsg. Malformed bytes must
    // come back as an error, never as a panic or an abort.
    let _ = transferd_lib::wire::WireMsg::decode(data);
});
