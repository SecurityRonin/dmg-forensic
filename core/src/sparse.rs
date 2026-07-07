//! Apple sparse-image readers: `.sparseimage` (single `sprs` file) and
//! `.sparsebundle` (a bundle directory of band files).
//!
//! Both expose a virtual disk over a set of fixed-size *bands*. Unallocated
//! bands (`.sparseimage` table entry 0 / a missing `.sparsebundle` band file)
//! read back as zeros, so the reader materialises a flat image identical to
//! `hdiutil convert … -format UDTO`.

use std::io::{self, Read, Seek, SeekFrom};

use crate::DmgError;

const SPRS_MAGIC: u32 = 0x7370_7273; // b"sprs"
const SPARSE_HEADER_SIZE: u64 = 4096;
const SECTOR: u64 = 512;
/// Byte offset of the band table within the 4096-byte header.
const BAND_TABLE_OFFSET: usize = 0x40;

/// Bounds-checked big-endian `u32` read: yields 0 (never panics) when `off`
/// is out of range, so a truncated/hostile header cannot crash the reader.
fn be_u32(data: &[u8], off: usize) -> u32 {
    let Some(end) = off.checked_add(4) else {
        return 0;
    };
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..end) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

/// Reader for a single-file `.sparseimage` (`sprs` magic).
///
/// The 4096-byte header carries a band table mapping each virtual band to a
/// 1-based physical band number (0 = unallocated hole). Physical bands are
/// stored sequentially after the header.
pub struct SparseImageReader<R: Read + Seek> {
    inner: R,
    band_size: u64,
    virtual_size: u64,
    /// Total file size, used to reject/zero-fill out-of-bounds band references.
    file_size: u64,
    /// Virtual band → physical band number (1-based; 0 = hole).
    table: Vec<u32>,
    position: u64,
}

impl<R: Read + Seek> SparseImageReader<R> {
    /// Open a `.sparseimage`, parsing and validating the 4096-byte `sprs` header.
    pub fn open(mut reader: R) -> Result<Self, DmgError> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        if file_size < SPARSE_HEADER_SIZE {
            return Err(DmgError::BadSparseHeader(format!(
                "file too small for 4096-byte sparse header: {file_size} bytes"
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; SPARSE_HEADER_SIZE as usize];
        reader.read_exact(&mut header)?;

        let magic = be_u32(&header, 0x00);
        if magic != SPRS_MAGIC {
            return Err(DmgError::NotSparseImage(magic));
        }

        let sectors_per_band = u64::from(be_u32(&header, 0x08));
        if sectors_per_band == 0 {
            return Err(DmgError::BadSparseHeader(
                "sectors_per_band is 0 (would divide by zero)".into(),
            ));
        }
        let band_size = sectors_per_band.saturating_mul(SECTOR);
        let total_sectors = u64::from(be_u32(&header, 0x10));
        let virtual_size = total_sectors.saturating_mul(SECTOR);

        // num_virtual_bands = ceil(total_sectors / sectors_per_band).
        let num_bands = total_sectors.div_ceil(sectors_per_band);

        // The band table lives inside the 4096-byte header at 0x40. A count that
        // would overrun the header is rejected — this is both the structural
        // bound and the allocation-bomb guard (max (4096-64)/4 = 1008 entries).
        let max_bands = (SPARSE_HEADER_SIZE as usize - BAND_TABLE_OFFSET) / 4;
        if num_bands > max_bands as u64 {
            return Err(DmgError::BadSparseHeader(format!(
                "band table of {num_bands} entries overruns the 4096-byte header (max {max_bands})"
            )));
        }
        let num_bands = num_bands as usize;
        let mut table = Vec::with_capacity(num_bands);
        for i in 0..num_bands {
            table.push(be_u32(&header, BAND_TABLE_OFFSET + i * 4));
        }

        Ok(Self {
            inner: reader,
            band_size,
            virtual_size,
            file_size,
            table,
            position: 0,
        })
    }

    /// Total virtual disk size in bytes (`total_sectors × 512`).
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_size
    }
}

impl<R: Read + Seek> Read for SparseImageReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.virtual_size {
            return Ok(0);
        }
        let vband = (self.position / self.band_size) as usize;
        let off = self.position % self.band_size;
        let band_remaining = self.band_size - off;
        let disk_remaining = self.virtual_size - self.position;
        let to_read = (buf.len() as u64).min(band_remaining).min(disk_remaining) as usize;

        // vband < table.len() holds by construction (num_bands = ceil), so the
        // default only guards a future invariant break — treat as a hole.
        let phys = self.table.get(vband).copied().unwrap_or(0);
        if phys == 0 {
            buf[..to_read].fill(0);
        } else {
            let file_off = (u64::from(phys) - 1)
                .checked_mul(self.band_size)
                .and_then(|v| v.checked_add(SPARSE_HEADER_SIZE))
                .and_then(|v| v.checked_add(off))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "sparse band offset overflow")
                })?;
            if file_off >= self.file_size {
                buf[..to_read].fill(0);
            } else {
                let avail = (self.file_size - file_off).min(to_read as u64) as usize;
                self.inner.seek(SeekFrom::Start(file_off))?;
                self.inner.read_exact(&mut buf[..avail])?;
                if avail < to_read {
                    buf[avail..to_read].fill(0);
                }
            }
        }

        self.position += to_read as u64;
        Ok(to_read)
    }
}

impl<R: Read + Seek> Seek for SparseImageReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.position = seek_within(self.position, self.virtual_size, pos);
        Ok(self.position)
    }
}

/// Saturating seek shared by both readers: a malformed offset clamps, never panics.
fn seek_within(current: u64, size: u64, pos: SeekFrom) -> u64 {
    match pos {
        SeekFrom::Start(n) => n,
        SeekFrom::End(n) => {
            if n >= 0 {
                size.saturating_add(n as u64)
            } else {
                size.saturating_sub(n.unsigned_abs())
            }
        }
        SeekFrom::Current(n) => {
            if n >= 0 {
                current.saturating_add(n as u64)
            } else {
                current.saturating_sub(n.unsigned_abs())
            }
        }
    }
}

#[cfg(test)]
mod sparseimage_tests {
    use super::SparseImageReader;
    use crate::DmgError;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    const HDR: usize = 4096;

    /// Build a synthetic `.sparseimage` in memory.
    ///
    /// `spb` = sectors per band; `table` maps virtual band → physical band
    /// (1-based, 0 = hole); `phys[p-1]` is the full `band_size`-byte content of
    /// physical band `p`, stored sequentially after the 4096-byte header.
    fn build(spb: u32, total_sectors: u32, table: &[u32], phys: &[Vec<u8>]) -> Vec<u8> {
        let band_size = spb as usize * 512;
        let mut file = vec![0u8; HDR];
        file[0..4].copy_from_slice(&0x7370_7273u32.to_be_bytes()); // "sprs"
        file[4..8].copy_from_slice(&3u32.to_be_bytes()); // version
        file[8..12].copy_from_slice(&spb.to_be_bytes()); // sectors_per_band
        file[16..20].copy_from_slice(&total_sectors.to_be_bytes()); // total_sectors
        for (i, &e) in table.iter().enumerate() {
            let o = 0x40 + i * 4;
            file[o..o + 4].copy_from_slice(&e.to_be_bytes());
        }
        for b in phys {
            assert_eq!(b.len(), band_size, "phys band must be band_size");
            file.extend_from_slice(b);
        }
        file
    }

    /// `band_size` = 2×512 = 1024; 3 virtual bands; virtual band 1 is a hole.
    /// v0→phys1 (starts with the HFS+ `H+` magic), v2→phys2 (0xCC filled).
    fn sample() -> Vec<u8> {
        let mut band0 = vec![0xAAu8; 1024];
        band0[0..4].copy_from_slice(&[0x48, 0x2b, 0x00, 0x04]);
        let band2 = vec![0xCCu8; 1024];
        build(2, 6, &[1, 0, 2], &[band0, band2])
    }

    #[test]
    fn bad_magic_is_not_sparse_image() {
        let mut f = sample();
        f[0] = 0;
        assert!(matches!(
            SparseImageReader::open(Cursor::new(f)),
            Err(DmgError::NotSparseImage(_))
        ));
    }

    #[test]
    fn zero_sectors_per_band_is_bad_header() {
        let mut f = sample();
        f[8..12].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            SparseImageReader::open(Cursor::new(f)),
            Err(DmgError::BadSparseHeader(_))
        ));
    }

    #[test]
    fn file_too_small_is_bad_header() {
        assert!(matches!(
            SparseImageReader::open(Cursor::new(vec![0u8; 100])),
            Err(DmgError::BadSparseHeader(_))
        ));
    }

    #[test]
    fn band_table_overrun_is_bad_header() {
        // spb=1 → num_bands = total_sectors; 5000 > (4096-64)/4 = 1008.
        let mut f = vec![0u8; HDR + 512];
        f[0..4].copy_from_slice(&0x7370_7273u32.to_be_bytes());
        f[8..12].copy_from_slice(&1u32.to_be_bytes());
        f[16..20].copy_from_slice(&5000u32.to_be_bytes());
        assert!(matches!(
            SparseImageReader::open(Cursor::new(f)),
            Err(DmgError::BadSparseHeader(_))
        ));
    }

    #[test]
    fn virtual_disk_size_is_total_sectors_times_512() {
        let r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        assert_eq!(r.virtual_disk_size(), 6 * 512);
    }

    #[test]
    fn reads_allocated_band_magic() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x48, 0x2b, 0x00, 0x04]);
    }

    #[test]
    fn hole_band_reads_zeros() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        r.seek(SeekFrom::Start(1024)).unwrap();
        let mut buf = [0xFFu8; 1024];
        r.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn second_allocated_band_reads_content() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        r.seek(SeekFrom::Start(2048)).unwrap();
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xCC, 0xCC, 0xCC, 0xCC]);
    }

    #[test]
    fn read_across_band_boundary() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        r.seek(SeekFrom::Start(1023)).unwrap();
        let mut buf = [0xEEu8; 2];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xAA, 0x00]);
    }

    #[test]
    fn seek_within_band_reads_offset() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        r.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);
    }

    #[test]
    fn seek_from_end_and_current() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 6 * 512);
        assert_eq!(r.seek(SeekFrom::End(-2048)).unwrap(), 1024);
        assert_eq!(r.seek(SeekFrom::Current(1024)).unwrap(), 2048);
        assert_eq!(r.seek(SeekFrom::Current(-2048)).unwrap(), 0);
    }

    #[test]
    fn read_past_eof_returns_zero() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        r.seek(SeekFrom::Start(6 * 512)).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn empty_buffer_reads_zero() {
        let mut r = SparseImageReader::open(Cursor::new(sample())).unwrap();
        assert_eq!(r.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn physical_band_past_file_reads_zeros() {
        // Table points v0 → physical band 99, far past the file → graceful zeros.
        let band0 = vec![0xAAu8; 1024];
        let f = build(2, 2, &[99], &[band0]);
        let mut r = SparseImageReader::open(Cursor::new(f)).unwrap();
        let mut buf = [0xFFu8; 512];
        r.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }
}
