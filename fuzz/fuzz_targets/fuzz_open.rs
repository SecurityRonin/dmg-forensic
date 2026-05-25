#![no_main]

use dmg::DmgReader;
use libfuzzer_sys::fuzz_target;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};

// DmgReader<R> is generic over R: Read + Seek — use Cursor for in-memory fuzzing.
fuzz_target!(|data: &[u8]| {
    if let Ok(mut reader) = DmgReader::open(Cursor::new(data)) {
        let size = reader.virtual_disk_size();
        if size > 0 {
            let _ = reader.seek(SeekFrom::Start(0));
            let mut buf = [0u8; 512];
            let _ = reader.read(&mut buf);
        }
    }
});
