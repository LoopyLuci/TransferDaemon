#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the backup format parser
    // This tests that malformed backup files don't crash the parser
    let _ = std::fs::write("fuzz_backup_test.bin", data);
    let _ = transferd_lib::backup::import_backup(
        &std::path::PathBuf::from("fuzz_backup_test.bin"),
        "fuzz",
    );
});
