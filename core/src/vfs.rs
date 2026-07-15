//! `forensic-vfs` integration: a decoded DMG as an [`ImageSource`].
//!
//! A decoded DMG (UDIF) is a read-only, randomly-addressable byte stream — the
//! `ImageSource` contract. [`DmgReader`] maps virtual sectors to compressed /
//! raw / zero runs through a `Read + Seek` cursor (the read advances an internal
//! position, so it needs `&mut self`). It is therefore wrapped here:
//! [`DmgSource`] holds the reader behind a poison-recovering `Mutex` and serves
//! `read_at` by seeking then reading under the lock. Reads serialize through the
//! mutex. Behind the `vfs` feature.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Mutex, PoisonError};

use forensic_vfs::{ImageSource, VfsError, VfsResult};

use crate::DmgReader;

/// A decoded [`DmgReader`] presented as a read-only [`ImageSource`].
///
/// Construction records the virtual disk size once; `read_at` locks the reader,
/// seeks, and fills the buffer. Because a DMG read advances an internal cursor
/// (`&mut self`), reads **serialize through the mutex** — correct and
/// `Send + Sync`, at the cost of no intra-source read parallelism. The lock is
/// poison-recovering, so one panicking reader does not wedge the source.
pub struct DmgSource<R: Read + Seek + Send> {
    inner: Mutex<DmgReader<R>>,
    len: u64,
}

impl<R: Read + Seek + Send> DmgSource<R> {
    /// Wrap an open [`DmgReader`], recording its virtual disk size as the source
    /// length.
    pub fn new(reader: DmgReader<R>) -> Self {
        let len = reader.virtual_disk_size();
        Self {
            inner: Mutex::new(reader),
            len,
        }
    }
}

impl<R: Read + Seek + Send + 'static> ImageSource for DmgSource<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let io_err = |op: &'static str| move |source: std::io::Error| VfsError::Io { op, source };
        let avail = self.len.saturating_sub(offset);
        if avail == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(avail) as usize;
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .seek(SeekFrom::Start(offset))
            .map_err(io_err("dmg::seek"))?;
        let mut total = 0;
        while total < want {
            match guard
                .read(&mut buf[total..want])
                .map_err(io_err("dmg::read"))?
            {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }
}

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
