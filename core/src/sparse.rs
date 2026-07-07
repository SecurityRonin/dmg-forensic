//! Apple sparse-image readers: `.sparseimage` (single `sprs` file) and
//! `.sparsebundle` (a bundle directory of band files).

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

    /// band_size = 2×512 = 1024; 3 virtual bands; virtual band 1 is a hole.
    /// v0→phys1 (starts with the HFS+ 'H+' magic), v2→phys2 (0xCC filled).
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
        let err = SparseImageReader::open(Cursor::new(f)).unwrap_err();
        assert!(matches!(err, DmgError::NotSparseImage(_)));
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
        let err = SparseImageReader::open(Cursor::new(vec![0u8; 100])).unwrap_err();
        assert!(matches!(err, DmgError::BadSparseHeader(_)));
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
