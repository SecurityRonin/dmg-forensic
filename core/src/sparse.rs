//! Apple sparse-image readers: `.sparseimage` (single `sprs` file) and
//! `.sparsebundle` (a bundle directory of band files).
//!
//! Both expose a virtual disk over a set of fixed-size *bands*. Unallocated
//! bands (`.sparseimage` table entry 0 / a missing `.sparsebundle` band file)
//! read back as zeros, so the reader materialises a flat image identical to
//! `hdiutil convert … -format UDTO`.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::DmgError;

const SPRS_MAGIC: u32 = 0x7370_7273; // b"sprs"
const SPARSE_HEADER_SIZE: u64 = 4096;
const SECTOR: u64 = 512;
/// Byte offset of the band table within the 4096-byte header.
const BAND_TABLE_OFFSET: usize = 0x40;

/// Bounds-checked big-endian `u32` read: yields 0 (never panics) when `off`
/// is out of range, so a truncated/hostile header cannot crash the reader.
fn be_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    // `get(off..).get(..4)` never overflows and yields None (→ 0) when the
    // 4-byte window falls outside the header.
    if let Some(s) = data.get(off..).and_then(|s| s.get(..4)) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

/// Reader for a single-file `.sparseimage` (`sprs` magic).
///
/// The 4096-byte header carries a band table *indexed by physical slot* (0-based
/// position of a stored band after the header); each entry is `virtual_band + 1`,
/// or 0 for an unused slot. Inverting it gives virtual band → physical slot; a
/// virtual band with no slot is an unallocated hole that reads back as zeros.
/// (This inverse-map layout was confirmed byte-identical to `hdiutil`'s UDTO raw
/// oracle — see `tests/sparse_images.rs`.)
pub struct SparseImageReader<R: Read + Seek> {
    inner: R,
    band_size: u64,
    virtual_size: u64,
    /// Total file size, used to zero-fill reads into a truncated band.
    file_size: u64,
    /// Virtual band → physical slot (0-based position after the header).
    band_slot: HashMap<u64, u64>,
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

        // Physical band slots stored after the header. `ceil` so a truncated
        // trailing band is still mapped; `band_size >= 512` rules out div-by-0.
        let phys_region = file_size.saturating_sub(SPARSE_HEADER_SIZE);
        let nphys = phys_region.div_ceil(band_size);

        // The slot-indexed table lives inside the 4096-byte header at 0x40. More
        // slots than fit there would need a multi-node table we do not support —
        // reject loudly rather than silently drop bands. This is also the
        // allocation-bomb guard (the map holds at most 1008 entries).
        let max_slots = (SPARSE_HEADER_SIZE as usize - BAND_TABLE_OFFSET) / 4;
        if nphys > max_slots as u64 {
            return Err(DmgError::BadSparseHeader(format!(
                "{nphys} physical bands exceed the single 4096-byte band table (max {max_slots}); multi-node tables unsupported"
            )));
        }

        // Invert the slot → (virtual_band + 1) table into virtual band → slot.
        let mut band_slot = HashMap::new();
        for slot in 0..nphys {
            let v = be_u32(&header, BAND_TABLE_OFFSET + slot as usize * 4);
            if v != 0 {
                band_slot.insert(u64::from(v) - 1, slot);
            }
        }

        Ok(Self {
            inner: reader,
            band_size,
            virtual_size,
            file_size,
            band_slot,
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
        let vband = self.position / self.band_size;
        let off = self.position % self.band_size;
        let band_remaining = self.band_size - off;
        let disk_remaining = self.virtual_size - self.position;
        let to_read = (buf.len() as u64).min(band_remaining).min(disk_remaining) as usize;

        match self.band_slot.get(&vband) {
            // No physical slot for this virtual band → unallocated hole.
            None => buf[..to_read].fill(0),
            Some(&slot) => {
                // slot < 1008 and band_size <= u32::MAX*512, so the offset stays
                // well within u64; saturate anyway to stay panic-free.
                let file_off = SPARSE_HEADER_SIZE
                    .saturating_add(slot.saturating_mul(self.band_size))
                    .saturating_add(off);
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

const SPARSEBUNDLE_TYPE: &str = "com.apple.diskimage.sparsebundle";

/// Reader for a `.sparsebundle` directory.
///
/// `Info.plist` gives the band size and total virtual size; the `bands/`
/// directory holds band files named by lowercase-hex band index. A missing
/// band file (or bytes past a short band file's end) reads back as zeros.
pub struct SparseBundleReader {
    bands_dir: PathBuf,
    band_size: u64,
    virtual_size: u64,
    position: u64,
}

impl SparseBundleReader {
    /// Open a `.sparsebundle` directory, parsing and validating `Info.plist`.
    pub fn open(dir: &Path) -> Result<Self, DmgError> {
        let info_path = dir.join("Info.plist");
        let xml = match std::fs::read_to_string(&info_path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(DmgError::MissingInfoPlist)
            }
            Err(e) => return Err(DmgError::Io(e)),
        };

        let info = parse_info_plist(&xml)?;

        match info.bundle_type.as_deref() {
            Some(SPARSEBUNDLE_TYPE) => {}
            other => {
                return Err(DmgError::BadInfoPlist(format!(
                    "diskimage-bundle-type is {other:?}, expected {SPARSEBUNDLE_TYPE:?}"
                )))
            }
        }

        let band_size = info
            .band_size
            .ok_or_else(|| DmgError::BadInfoPlist("missing band-size key".into()))?;
        if band_size == 0 {
            return Err(DmgError::BadInfoPlist(
                "band-size is 0 (would divide by zero)".into(),
            ));
        }
        let virtual_size = info
            .size
            .ok_or_else(|| DmgError::BadInfoPlist("missing size key".into()))?;

        Ok(Self {
            bands_dir: dir.join("bands"),
            band_size,
            virtual_size,
            position: 0,
        })
    }

    /// Total virtual disk size in bytes (the plist `size` key).
    pub fn virtual_disk_size(&self) -> u64 {
        self.virtual_size
    }
}

impl Read for SparseBundleReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.virtual_size {
            return Ok(0);
        }
        let band = self.position / self.band_size;
        let off = self.position % self.band_size;
        let band_remaining = self.band_size - off;
        let disk_remaining = self.virtual_size - self.position;
        let to_read = (buf.len() as u64).min(band_remaining).min(disk_remaining) as usize;

        let path = self.bands_dir.join(format!("{band:x}"));
        match std::fs::File::open(&path) {
            Ok(mut f) => {
                let flen = f.seek(SeekFrom::End(0))?;
                if off >= flen {
                    buf[..to_read].fill(0);
                } else {
                    let avail = (flen - off).min(to_read as u64) as usize;
                    f.seek(SeekFrom::Start(off))?;
                    f.read_exact(&mut buf[..avail])?;
                    if avail < to_read {
                        buf[avail..to_read].fill(0);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => buf[..to_read].fill(0),
            Err(e) => return Err(e),
        }

        self.position += to_read as u64;
        Ok(to_read)
    }
}

impl Seek for SparseBundleReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.position = seek_within(self.position, self.virtual_size, pos);
        Ok(self.position)
    }
}

/// The three `Info.plist` fields the reader needs.
struct BundleInfo {
    band_size: Option<u64>,
    size: Option<u64>,
    bundle_type: Option<String>,
}

/// Parse the `.sparsebundle` `Info.plist`, extracting `band-size`, `size`, and
/// `diskimage-bundle-type`. Any non-integer value under a size key is a loud error.
fn parse_info_plist(xml: &str) -> Result<BundleInfo, DmgError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut band_size = None;
    let mut size = None;
    let mut bundle_type = None;
    let mut current_key: Option<String> = None;
    let mut elem: Option<Vec<u8>> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => elem = Some(e.name().as_ref().to_vec()),
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default();
                let t = text.trim();
                if t.is_empty() {
                    continue;
                }
                match elem.as_deref() {
                    Some(b"key") => current_key = Some(t.to_string()),
                    Some(b"integer") => {
                        let key = current_key.as_deref();
                        if key == Some("band-size") || key == Some("size") {
                            let v: u64 = t.parse().map_err(|_| {
                                DmgError::BadInfoPlist(format!(
                                    "non-integer value {t:?} for key {key:?}"
                                ))
                            })?;
                            if key == Some("band-size") {
                                band_size = Some(v);
                            } else {
                                size = Some(v);
                            }
                        }
                    }
                    Some(b"string") if current_key.as_deref() == Some("diskimage-bundle-type") => {
                        bundle_type = Some(t.to_string());
                    }
                    _ => {}
                }
            }
            Ok(Event::End(_)) => elem = None,
            Ok(Event::Eof) => break,
            Err(e) => return Err(DmgError::BadInfoPlist(e.to_string())),
            _ => {}
        }
    }

    Ok(BundleInfo {
        band_size,
        size,
        bundle_type,
    })
}

#[cfg(test)]
mod sparseimage_tests {
    use super::SparseImageReader;
    use crate::DmgError;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    const HDR: usize = 4096;

    /// Build a synthetic `.sparseimage` in memory.
    ///
    /// `spb` = sectors per band. `bands[v]` is virtual band `v`'s content
    /// (`None` = unallocated hole). Allocated bands are stored in ascending
    /// virtual order after the 4096-byte header; the band table at 0x40 is
    /// indexed by physical slot and holds `virtual_band + 1` for each slot
    /// (0 = unused) — the layout `hdiutil` writes, confirmed against its UDTO
    /// raw oracle in `tests/sparse_images.rs`.
    fn build(spb: u32, bands: &[Option<Vec<u8>>]) -> Vec<u8> {
        let band_size = spb as usize * 512;
        let total_sectors = (bands.len() * spb as usize) as u32;
        let mut file = vec![0u8; HDR];
        file[0..4].copy_from_slice(&0x7370_7273u32.to_be_bytes()); // "sprs"
        file[4..8].copy_from_slice(&3u32.to_be_bytes()); // version
        file[8..12].copy_from_slice(&spb.to_be_bytes()); // sectors_per_band
        file[16..20].copy_from_slice(&total_sectors.to_be_bytes()); // total_sectors
        let mut slot = 0usize;
        for (v, b) in bands.iter().enumerate() {
            if let Some(content) = b {
                assert_eq!(content.len(), band_size, "band must be band_size");
                let o = 0x40 + slot * 4;
                file[o..o + 4].copy_from_slice(&((v as u32) + 1).to_be_bytes());
                file.extend_from_slice(content);
                slot += 1;
            }
        }
        file
    }

    /// `band_size` = 2×512 = 1024; 3 virtual bands; virtual band 1 is a hole.
    /// v0 starts with the HFS+ `H+` magic, v2 is 0xCC filled.
    fn sample() -> Vec<u8> {
        let mut b0 = vec![0xAAu8; 1024];
        b0[0..4].copy_from_slice(&[0x48, 0x2b, 0x00, 0x04]);
        let b2 = vec![0xCCu8; 1024];
        build(2, &[Some(b0), None, Some(b2)])
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
    fn too_many_physical_bands_is_bad_header() {
        // band_size=512 (spb=1); 1009 physical bands overrun the (4096-64)/4 =
        // 1008-entry single-header band table → loud error, not silent truncation.
        let mut f = vec![0u8; HDR + 1009 * 512];
        f[0..4].copy_from_slice(&0x7370_7273u32.to_be_bytes());
        f[8..12].copy_from_slice(&1u32.to_be_bytes()); // sectors_per_band = 1
        f[16..20].copy_from_slice(&1009u32.to_be_bytes());
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
    fn unmapped_virtual_band_reads_zeros() {
        // Only virtual band 0 is allocated; bands 1 and 2 have no slot → zeros.
        let f = build(2, &[Some(vec![0xAAu8; 1024]), None, None]);
        let mut r = SparseImageReader::open(Cursor::new(f)).unwrap();
        r.seek(SeekFrom::Start(2048)).unwrap();
        let mut buf = [0xFFu8; 512];
        r.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn truncated_physical_band_tail_reads_zeros() {
        // One allocated band, but the file is truncated mid-band: the present
        // half reads real bytes, the missing tail reads zeros.
        let mut f = build(2, &[Some(vec![0xAAu8; 1024])]);
        f.truncate(HDR + 512);
        let mut r = SparseImageReader::open(Cursor::new(f)).unwrap();
        let mut buf = [0u8; 1024];
        r.read_exact(&mut buf).unwrap();
        assert!(buf[..512].iter().all(|&b| b == 0xAA));
        assert!(buf[512..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_starting_in_truncated_region_reads_zeros() {
        // Seek past the present bytes of a truncated band: the band's file offset
        // is wholly past EOF → zeros (never a short-read panic).
        let mut f = build(2, &[Some(vec![0xAAu8; 1024])]);
        f.truncate(HDR + 512);
        let mut r = SparseImageReader::open(Cursor::new(f)).unwrap();
        r.seek(SeekFrom::Start(600)).unwrap();
        let mut buf = [0xFFu8; 8];
        r.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }
}

#[cfg(test)]
mod sparsebundle_tests {
    use super::SparseBundleReader;
    use crate::DmgError;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::TempDir;

    /// Assemble a `<name>.sparsebundle` directory with the given Info.plist body
    /// and band files. `bands` are `(index, bytes)`; omitted indices are holes.
    fn bundle(plist: &str, bands: &[(u64, Vec<u8>)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Info.plist"), plist).unwrap();
        let bands_dir = dir.path().join("bands");
        fs::create_dir(&bands_dir).unwrap();
        for (idx, bytes) in bands {
            let mut f = fs::File::create(bands_dir.join(format!("{idx:x}"))).unwrap();
            f.write_all(bytes).unwrap();
        }
        dir
    }

    fn plist(band_size: Option<u64>, size: Option<u64>, bundle_type: Option<&str>) -> String {
        use std::fmt::Write as _;
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n",
        );
        if let Some(t) = bundle_type {
            let _ = writeln!(
                body,
                "  <key>diskimage-bundle-type</key><string>{t}</string>"
            );
        }
        if let Some(b) = band_size {
            let _ = writeln!(body, "  <key>band-size</key><integer>{b}</integer>");
        }
        if let Some(s) = size {
            let _ = writeln!(body, "  <key>size</key><integer>{s}</integer>");
        }
        body.push_str("</dict>\n</plist>\n");
        body
    }

    /// A realistic Info.plist, including keys the reader ignores (a non-target
    /// `<string>` and `<integer>`) plus an escaped whitespace-only value that is
    /// skipped — mirrors what `hdiutil` writes.
    fn valid_plist() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\
         \t<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n\
         \t<key>band-size</key><integer>1024</integer>\n\
         \t<key>bundle-backingstore-version</key><integer>1</integer>\n\
         \t<key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string>\n\
         \t<key>pad</key><string>&#32;</string>\n\
         \t<key>size</key><integer>3072</integer>\n\
         </dict>\n</plist>\n"
            .to_string()
    }

    /// band-size 1024, size 3072 (3 bands): band 0 present (0xAA, `H+` magic),
    /// band 1 a hole (missing file), band 2 present but half-length (0xCC).
    fn valid_bundle() -> TempDir {
        let mut b0 = vec![0xAAu8; 1024];
        b0[0..4].copy_from_slice(&[0x48, 0x2b, 0x00, 0x04]);
        let b2 = vec![0xCCu8; 512];
        bundle(&valid_plist(), &[(0, b0), (2, b2)])
    }

    #[test]
    fn missing_info_plist_errors() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::MissingInfoPlist)
        ));
    }

    #[test]
    fn malformed_plist_errors() {
        let dir = bundle("<plist><dict><key>oops", &[]);
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }

    #[test]
    fn wrong_bundle_type_errors() {
        let dir = bundle(
            &plist(Some(1024), Some(3072), Some("com.apple.diskimage.sparse")),
            &[],
        );
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }

    #[test]
    fn missing_band_size_errors() {
        let dir = bundle(
            &plist(None, Some(3072), Some("com.apple.diskimage.sparsebundle")),
            &[],
        );
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }

    #[test]
    fn zero_band_size_errors() {
        let dir = bundle(
            &plist(
                Some(0),
                Some(3072),
                Some("com.apple.diskimage.sparsebundle"),
            ),
            &[],
        );
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }

    #[test]
    fn missing_size_errors() {
        let dir = bundle(
            &plist(Some(1024), None, Some("com.apple.diskimage.sparsebundle")),
            &[],
        );
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }

    #[test]
    fn non_integer_band_size_errors() {
        let xml = "<plist version=\"1.0\">\n<dict>\n\
                   <key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string>\n\
                   <key>band-size</key><integer>notanumber</integer>\n\
                   <key>size</key><integer>3072</integer>\n</dict>\n</plist>\n";
        let dir = bundle(xml, &[]);
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }

    #[test]
    fn virtual_disk_size_matches_plist_size() {
        let dir = valid_bundle();
        let r = SparseBundleReader::open(dir.path()).unwrap();
        assert_eq!(r.virtual_disk_size(), 3072);
    }

    #[test]
    fn reads_present_band_magic() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x48, 0x2b, 0x00, 0x04]);
    }

    #[test]
    fn missing_band_file_reads_zeros() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        r.seek(SeekFrom::Start(1024)).unwrap(); // band 1 = hole
        let mut buf = [0xFFu8; 1024];
        r.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn partial_band_tail_reads_zeros() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        r.seek(SeekFrom::Start(2048)).unwrap(); // band 2 = 512 real bytes + 512 zeros
        let mut buf = [0u8; 1024];
        r.read_exact(&mut buf).unwrap();
        assert!(buf[..512].iter().all(|&b| b == 0xCC));
        assert!(buf[512..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_across_band_boundary() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        r.seek(SeekFrom::Start(1023)).unwrap();
        let mut buf = [0xEEu8; 2];
        r.read_exact(&mut buf).unwrap(); // band0 tail 0xAA, then band1 hole 0x00
        assert_eq!(buf, [0xAA, 0x00]);
    }

    #[test]
    fn seek_within_band_reads_offset() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        r.seek(SeekFrom::Start(500)).unwrap();
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);
    }

    #[test]
    fn seek_from_end_and_current() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 3072);
        assert_eq!(r.seek(SeekFrom::End(-1024)).unwrap(), 2048);
        assert_eq!(r.seek(SeekFrom::Current(-2048)).unwrap(), 0);
    }

    #[test]
    fn read_past_eof_returns_zero() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        r.seek(SeekFrom::Start(3072)).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn empty_buffer_reads_zero() {
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        assert_eq!(r.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn read_wholly_past_short_band_reads_zeros() {
        // band 2 is 512 bytes; read starting at offset 512 within it (virtual
        // 2560) is entirely past the file's end → zeros.
        let dir = valid_bundle();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        r.seek(SeekFrom::Start(2560)).unwrap();
        let mut buf = [0xFFu8; 512];
        r.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn bands_path_that_is_a_file_errors_on_read() {
        // `bands` is a regular file, so opening `bands/0` fails with a
        // not-NotFound error (ENOTDIR) — surfaced loudly, not swallowed to zeros.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Info.plist"), valid_plist()).unwrap();
        fs::write(dir.path().join("bands"), b"not a directory").unwrap();
        let mut r = SparseBundleReader::open(dir.path()).unwrap();
        let mut buf = [0u8; 16];
        assert!(r.read(&mut buf).is_err());
    }

    #[test]
    fn info_plist_that_is_a_directory_is_io_error() {
        // Info.plist exists but is a directory → a read error that is not
        // NotFound → surfaced as DmgError::Io, distinct from MissingInfoPlist.
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("Info.plist")).unwrap();
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::Io(_))
        ));
    }

    #[test]
    fn mismatched_xml_tags_error() {
        // quick-xml's end-name check rejects the mismatched close tag.
        let dir = bundle("<plist version=\"1.0\">\n<dict></nope>\n</plist>\n", &[]);
        assert!(matches!(
            SparseBundleReader::open(dir.path()),
            Err(DmgError::BadInfoPlist(_))
        ));
    }
}
