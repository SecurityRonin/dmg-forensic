//! Integration tests against committed DMG corpus.
//!
//! Fixtures in `tests/data/` are produced by macOS `hdiutil` (Apple tool,
//! independent from the Rust parser), satisfying the doer-checker principle.
//!
//! `hfsplus_udro.dmg`  — 4 MiB HFS+ disk, UDRO (raw blocks), GPT-wrapped
//! `hfsplus_compressed.dmg` — same disk, UDZO (zlib-compressed blocks)
//!
//! The disk layout is:
//!   sector 0:    MBR
//!   sector 1:    GPT primary header
//!   sectors 2-33: GPT partition table
//!   sectors 40-8151: HFS+ partition (`Apple_HFS`)
//!   sectors 8152-8158: free
//!   sectors 8159-8190: GPT backup partition table
//!   sector 8191: GPT backup header
//!
//! HFS+ volume header is at byte offset 40*512+1024 = 21504 in the virtual disk.

use dmg::DmgReader;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn open(name: &str) -> DmgReader<BufReader<File>> {
    let path = format!("{DATA_DIR}/{name}");
    let f = File::open(Path::new(&path)).unwrap_or_else(|e| panic!("open {name}: {e}"));
    DmgReader::open(BufReader::new(f)).unwrap_or_else(|e| panic!("DmgReader::open {name}: {e}"))
}

// ── hfsplus_udro.dmg — 4 MiB HFS+ UDIF/UDRO (raw blocks, hdiutil) ───────────

#[test]
fn hfsplus_opens() {
    let _ = open("hfsplus_udro.dmg");
}

#[test]
fn hfsplus_virtual_disk_size_is_4mib() {
    // hdiutil create -size 4m → 4 MiB virtual disk = 8192 sectors × 512 bytes
    assert_eq!(
        open("hfsplus_udro.dmg").virtual_disk_size(),
        4 * 1024 * 1024
    );
}

#[test]
fn hfsplus_sector0_readable() {
    let mut r = open("hfsplus_udro.dmg");
    r.seek(SeekFrom::Start(0)).expect("seek");
    let mut buf = [0u8; 512];
    r.read_exact(&mut buf).expect("read sector 0");
}

#[test]
fn hfsplus_seek_and_read_stable() {
    let mut r = open("hfsplus_udro.dmg");
    let mut a = [0u8; 512];
    r.seek(SeekFrom::Start(0)).expect("seek");
    r.read_exact(&mut a).expect("first read");
    let mut b = [0u8; 512];
    r.seek(SeekFrom::Start(0)).expect("seek again");
    r.read_exact(&mut b).expect("second read");
    assert_eq!(a, b, "repeated reads at offset 0 must be identical");
}

#[test]
fn hfsplus_seek_from_end() {
    let mut r = open("hfsplus_udro.dmg");
    let size = r.virtual_disk_size();
    r.seek(SeekFrom::End(-512)).expect("seek from end");
    let mut buf = [0u8; 512];
    r.read_exact(&mut buf).expect("read last sector");
    let pos = r.stream_position().expect("stream_position");
    assert_eq!(
        pos, size,
        "after reading last sector, position must equal virtual_disk_size"
    );
}

#[test]
fn hfsplus_hfs_volume_header_magic() {
    // GPT-wrapped HFS+ disk: HFS+ partition starts at sector 40.
    // Volume header is at 1024 bytes into the partition = byte 40*512+1024 = 21504.
    // Magic: 0x482B ("H+")
    let mut r = open("hfsplus_udro.dmg");
    r.seek(SeekFrom::Start(40 * 512 + 1024))
        .expect("seek to HFS+ volume header");
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).expect("read HFS+ magic");
    assert_eq!(
        buf,
        [0x48, 0x2B],
        "HFS+ volume header magic must be 0x482B at offset 21504"
    );
}

// ── hfsplus_compressed.dmg — UDZO (zlib-compressed) variant ──────────────────

#[test]
fn compressed_dmg_opens() {
    let _ = open("hfsplus_compressed.dmg");
}

#[test]
fn compressed_dmg_virtual_disk_size_matches_uncompressed() {
    // UDZO compression is transparent — virtual size must equal the uncompressed image
    let uncompressed = open("hfsplus_udro.dmg").virtual_disk_size();
    let compressed = open("hfsplus_compressed.dmg").virtual_disk_size();
    assert_eq!(
        uncompressed, compressed,
        "UDZO compressed DMG must expose the same virtual_disk_size as the raw UDRO image"
    );
}

#[test]
fn compressed_dmg_sector0_matches_uncompressed() {
    // Decompressed content must be bit-for-bit identical to the raw image at sector 0
    let mut raw = open("hfsplus_udro.dmg");
    raw.seek(SeekFrom::Start(0)).expect("seek raw");
    let mut raw_buf = [0u8; 512];
    raw.read_exact(&mut raw_buf).expect("read raw sector 0");

    let mut comp = open("hfsplus_compressed.dmg");
    comp.seek(SeekFrom::Start(0)).expect("seek compressed");
    let mut comp_buf = [0u8; 512];
    comp.read_exact(&mut comp_buf)
        .expect("read compressed sector 0");

    assert_eq!(
        raw_buf, comp_buf,
        "sector 0 must decompress to same bytes as raw UDRO image"
    );
}

#[test]
fn compressed_dmg_hfs_volume_header_magic() {
    // Same as UDRO: HFS+ volume header at 40*512+1024 = 21504
    let mut r = open("hfsplus_compressed.dmg");
    r.seek(SeekFrom::Start(40 * 512 + 1024)).expect("seek");
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).expect("read HFS+ magic");
    assert_eq!(
        buf,
        [0x48, 0x2B],
        "compressed DMG must decompress to valid HFS+ at offset 21504"
    );
}

// ── All codecs (UDBZ/ULFO/ULMO/UDCO) match the raw image, byte-for-byte ──────
// Each fixture is `hdiutil convert` of hfsplus_udro.dmg to a different codec, so
// the decoded virtual disk MUST be identical to the raw image. This validates
// every block codec against an independent oracle (Apple's hdiutil).

fn read_full(name: &str) -> Vec<u8> {
    let mut r = open(name);
    let mut v = Vec::new();
    r.read_to_end(&mut v)
        .unwrap_or_else(|e| panic!("read_to_end {name}: {e}"));
    v
}

#[test]
fn every_codec_decodes_to_the_raw_image() {
    let reference = read_full("hfsplus_udro.dmg");
    assert!(!reference.is_empty());
    for name in [
        "hfsplus_compressed.dmg", // zlib  (UDZO)
        "hfsplus_bzip2.dmg",      // bzip2 (UDBZ)
        "hfsplus_lzfse.dmg",      // LZFSE (ULFO)
        "hfsplus_lzma.dmg",       // LZMA  (ULMO)
        "hfsplus_adc.dmg",        // ADC   (UDCO)
    ] {
        assert_eq!(
            read_full(name),
            reference,
            "{name} must decode to the same bytes as the raw UDRO image"
        );
    }
}
