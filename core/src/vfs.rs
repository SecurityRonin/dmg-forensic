//! `forensic-vfs` integration: a decoded DMG as an [`ImageSource`].
//!
//! A decoded DMG (UDIF) is a read-only, randomly-addressable byte stream — the
//! `ImageSource` contract. [`DmgReader`] maps virtual sectors to compressed /
//! raw / zero runs through a `Read + Seek` cursor (the read advances an internal
//! position, so it needs `&mut self`). It is therefore wrapped here:
//! [`DmgSource`] holds the reader behind a poison-recovering `Mutex` and serves
//! `read_at` by seeking then reading under the lock. Reads serialize through the
//! mutex. Behind the `vfs` feature.

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::sync::Arc;

    use forensic_vfs::ImageSource;

    use super::DmgSource;
    use crate::DmgReader;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfsplus_compressed.dmg"
    );

    /// Open a real committed DMG and drive it through the `ImageSource` API,
    /// cross-checking the positioned read against the reader's own `Read` path
    /// (the oracle) so the wrapper is proven to delegate faithfully. Skips
    /// cleanly if the fixture is absent (it is excluded from the packaged crate).
    #[test]
    fn dmg_reader_is_an_image_source() {
        let Ok(bytes) = std::fs::read(FIXTURE) else {
            eprintln!("skipping: fixture {FIXTURE} not present");
            return;
        };

        // Oracle: the reader's own Read path for the first sector.
        let mut direct = DmgReader::open(Cursor::new(bytes.clone())).expect("open dmg");
        let expected_len = direct.virtual_disk_size();
        let mut expected = vec![0u8; 512];
        direct.read_exact(&mut expected).expect("direct read");

        // The load-bearing claim: a DmgReader composes as a dyn ImageSource.
        let reader = DmgReader::open(Cursor::new(bytes)).expect("open dmg");
        let src: Arc<dyn ImageSource> = Arc::new(DmgSource::new(reader));
        assert_eq!(src.len(), expected_len);
        assert!(!src.is_empty());

        // Positioned read matches the direct read, byte for byte.
        let mut buf = vec![0u8; 512];
        let n = src.read_at(0, &mut buf).expect("read_at");
        assert_eq!(n, 512);
        assert_eq!(buf, expected);

        // A read starting at EOF yields 0 (ImageSource short-read contract).
        let mut eof = [0u8; 16];
        assert_eq!(src.read_at(expected_len, &mut eof).expect("eof read"), 0);
    }
}
