//! Regression tests for fuzzer-found crashes, turned into permanent coverage.
//!
//! Both inputs previously aborted the process: `oversized_alloc.bin` requested a
//! multi-terabyte allocation from an attacker-controlled size, and
//! `mul_overflow.bin` triggered an integer-multiply overflow panic. The reader
//! must now handle any malformed image gracefully — open may fail, reads may
//! error — but it must never panic, overflow, or abort.

use dmg::DmgReader;
use std::io::{Cursor, Read, Seek, SeekFrom};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/fuzz_regression");

/// Open and fully traverse a (malformed) image; the only assertion is that it
/// completes without panicking or aborting.
fn drive(name: &str) {
    let bytes =
        std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"));
    if let Ok(mut r) = DmgReader::open(Cursor::new(bytes)) {
        let size = r.virtual_disk_size().min(16 * 1024 * 1024);
        if size > 0 && r.seek(SeekFrom::Start(0)).is_ok() {
            let mut buf = vec![0u8; 64 * 1024];
            let mut remaining = size;
            while remaining > 0 {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => remaining = remaining.saturating_sub(n as u64),
                }
            }
        }
    }
}

#[test]
fn oversized_allocation_does_not_abort() {
    drive("oversized_alloc.bin");
}

#[test]
fn multiply_overflow_does_not_panic() {
    drive("mul_overflow.bin");
}
