#![no_main]

use dmg::SparseImageReader;
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Read, Seek, SeekFrom};

// Drive the .sparseimage (`sprs`) header parser and band-mapped reader on
// attacker-controlled bytes. Invariant: never panic — a malformed header,
// out-of-range band table entry, or overflowing physical band offset must
// return an error or zeros, never crash. (`.sparsebundle` is a directory
// format with no single-buffer entry point, so it is not fuzzed here.)
fuzz_target!(|data: &[u8]| {
    if let Ok(mut reader) = SparseImageReader::open(Cursor::new(data)) {
        // Cap work so a huge declared total_sectors can't OOM/hang the fuzzer.
        let size = reader.virtual_disk_size().min(16 * 1024 * 1024);
        if size > 0 && reader.seek(SeekFrom::Start(0)).is_ok() {
            let mut buf = vec![0u8; 64 * 1024];
            let mut remaining = size;
            while remaining > 0 {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => remaining = remaining.saturating_sub(n as u64),
                    Err(_) => break,
                }
            }
        }
    }
});
