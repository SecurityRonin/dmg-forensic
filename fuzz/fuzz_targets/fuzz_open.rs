#![no_main]

use dmg::DmgReader;
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Read, Seek, SeekFrom};

// DmgReader<R> is generic over R: Read + Seek — use Cursor for in-memory fuzzing.
// Read the whole (capped) virtual disk so every block's codec — zero/raw/ADC/
// zlib/bzip2/LZFSE/LZMA — is exercised on attacker-controlled input, not just
// the block covering sector 0.
fuzz_target!(|data: &[u8]| {
    if let Ok(mut reader) = DmgReader::open(Cursor::new(data)) {
        // Cap work so a huge declared sector_count can't OOM/hang the fuzzer.
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
