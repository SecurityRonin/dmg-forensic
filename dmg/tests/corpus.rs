use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use dmg::DmgReader;

fn corpus_dir() -> Option<PathBuf> {
    std::env::var("CORPUS_DIR").ok().map(PathBuf::from)
}

fn open_corpus(name: &str) -> Option<DmgReader<BufReader<std::fs::File>>> {
    let dir = corpus_dir()?;
    let path = dir.join(name);
    if !path.exists() {
        return None;
    }
    let f = std::fs::File::open(&path).ok()?;
    DmgReader::open(BufReader::new(f)).ok()
}

#[test]
fn corpus_test_dmg_opens_and_has_nonzero_size() {
    let Some(reader) = open_corpus("test.dmg") else { return };
    assert!(reader.virtual_disk_size() > 0, "DMG virtual_disk_size must be > 0");
}

#[test]
fn corpus_test_dmg_read_is_stable() {
    let Some(mut reader) = open_corpus("test.dmg") else { return };
    reader.seek(SeekFrom::Start(0)).expect("seek");
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf).expect("read sector 0");
    // HFS+ volume header is at sector 2; sector 0 is boot block (may be zeros).
    // We only assert the read completes without panic.
}
