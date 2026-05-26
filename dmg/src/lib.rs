//! Pure-Rust forensic Apple Disk Image (DMG/UDIF) reader.
//!
//! A DMG file uses the UDIF (Universal Disk Image Format) container:
//! - 512-byte **koly** trailer at the very end of the file (all big-endian)
//! - XML plist at `xml_offset` containing partition block tables (`blkx` array)
//! - Each blkx `Data` field is a base64-encoded **mish** block describing
//!   how virtual sectors map to data in the file
//!
//! Supported block types: zero (0x00), raw (0x01), ignore (0x02), zlib (0x80000005).
//! bzip2 (0x80000006) and LZFSE (0x80000007) return `NotSupported`.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use base64::Engine;
use flate2::read::ZlibDecoder;
use quick_xml::Reader;
use quick_xml::events::Event;
use thiserror::Error;

const KOLY_MAGIC: u32 = 0x6B6F6C79; // b"koly"
const MISH_MAGIC: u32 = 0x6D697368; // b"mish"
const KOLY_SIZE: u64 = 512;

const BLK_ZERO: u32 = 0x0000_0000;
const BLK_RAW: u32 = 0x0000_0001;
const BLK_IGNORE: u32 = 0x0000_0002;
const BLK_ZLIB: u32 = 0x8000_0005;
const BLK_COMMENT: u32 = 0x7FFF_FFFE;
const BLK_TERM: u32 = 0xFFFF_FFFF;

/// Errors returned by `DmgReader`.
#[derive(Debug, Error)]
pub enum DmgError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("not a DMG: missing koly magic")]
    NotADmg,
    #[error("file too small to contain koly trailer")]
    FileTooSmall,
    #[error("invalid mish block: {0}")]
    BadMish(String),
    #[error("invalid plist XML: {0}")]
    BadPlist(String),
    #[error("decompression error: {0}")]
    Compression(String),
    #[error("unsupported compression type: {0:#010x}")]
    NotSupported(u32),
}

/// One BLKXRun entry from a mish block.
#[derive(Debug, Clone)]
struct BlkxRun {
    entry_type: u32,
    sector_start: u64,
    sector_count: u64,
    /// Byte offset relative to the partition's `data_offset`.
    data_offset: u64,
    data_length: u64,
}

/// One partition (mish block) within the DMG.
#[derive(Debug, Clone)]
struct Partition {
    /// Absolute byte offset in the file for this partition's data.
    file_data_offset: u64,
    /// First virtual sector of this partition.
    sector_base: u64,
    runs: Vec<BlkxRun>,
}

impl Partition {
    /// True if this partition contains the given virtual sector.
    fn total_sectors(&self) -> u64 {
        self.runs
            .iter()
            .filter(|r| r.entry_type != BLK_COMMENT && r.entry_type != BLK_TERM)
            .map(|r| r.sector_start + r.sector_count)
            .max()
            .unwrap_or(0)
    }

    fn contains_sector(&self, vsec: u64) -> bool {
        if vsec < self.sector_base {
            return false;
        }
        let local = vsec - self.sector_base;
        local < self.total_sectors()
    }

    /// Find the run covering local sector `local_sec` (relative to sector_base).
    fn run_for(&self, local_sec: u64) -> Option<&BlkxRun> {
        self.runs.iter().find(|r| {
            r.entry_type != BLK_TERM
                && r.entry_type != BLK_COMMENT
                && local_sec >= r.sector_start
                && local_sec < r.sector_start + r.sector_count
        })
    }
}

/// Read-only Apple DMG (UDIF) reader implementing `Read + Seek`.
pub struct DmgReader<R: Read + Seek> {
    inner: R,
    sector_count: u64,
    partitions: Vec<Partition>,
    position: u64,
}

impl<R: Read + Seek> DmgReader<R> {
    /// Open a DMG file, parsing the koly trailer and XML plist.
    pub fn open(mut reader: R) -> Result<Self, DmgError> {
        // Confirm the file is large enough to hold the koly trailer.
        let file_size = reader.seek(SeekFrom::End(0))?;
        if file_size < KOLY_SIZE {
            return Err(DmgError::FileTooSmall);
        }

        // Read the 512-byte koly trailer.
        reader.seek(SeekFrom::Start(file_size - KOLY_SIZE))?;
        let mut koly = [0u8; 512];
        reader.read_exact(&mut koly)?;

        let magic = u32::from_be_bytes(koly[0..4].try_into().unwrap());
        if magic != KOLY_MAGIC {
            return Err(DmgError::NotADmg);
        }

        let xml_offset = u64::from_be_bytes(koly[216..224].try_into().unwrap());
        let xml_length = u64::from_be_bytes(koly[224..232].try_into().unwrap());
        let sector_count = u64::from_be_bytes(koly[492..500].try_into().unwrap());

        // Read the XML plist.
        reader.seek(SeekFrom::Start(xml_offset))?;
        let mut xml_bytes = vec![0u8; xml_length as usize];
        reader.read_exact(&mut xml_bytes)?;
        let xml = std::str::from_utf8(&xml_bytes)
            .map_err(|e| DmgError::BadPlist(e.to_string()))?;

        let partitions = parse_plist(xml)?;

        Ok(Self { inner: reader, sector_count, partitions, position: 0 })
    }

    /// Total virtual disk size in bytes (`sector_count × 512`).
    pub fn virtual_disk_size(&self) -> u64 {
        self.sector_count * 512
    }
}

impl<R: Read + Seek> Read for DmgReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let disk_size = self.virtual_disk_size();
        if self.position >= disk_size {
            return Ok(0);
        }

        let vsec = self.position / 512;
        let sec_offset = self.position % 512;

        // Find the partition and run covering this sector.
        let part = self
            .partitions
            .iter()
            .find(|p| p.contains_sector(vsec))
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no partition"))?;

        let local_sec = vsec - part.sector_base;
        let run = part
            .run_for(local_sec)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no run"))?;

        // Byte offset within this run (relative to the run's first sector).
        let bytes_into_run = (local_sec - run.sector_start) * 512 + sec_offset;
        let run_total_bytes = run.sector_count * 512;
        let available_in_run = run_total_bytes.saturating_sub(bytes_into_run);
        let to_read = buf.len().min(available_in_run as usize);

        match run.entry_type {
            BLK_ZERO | BLK_IGNORE => {
                buf[..to_read].fill(0);
            }
            BLK_RAW => {
                let file_pos =
                    part.file_data_offset + run.data_offset + bytes_into_run;
                self.inner.seek(SeekFrom::Start(file_pos))?;
                self.inner.read_exact(&mut buf[..to_read])?;
            }
            BLK_ZLIB => {
                // Decompress the entire run, then slice.
                let file_pos = part.file_data_offset + run.data_offset;
                self.inner.seek(SeekFrom::Start(file_pos))?;
                let mut compressed = vec![0u8; run.data_length as usize];
                self.inner.read_exact(&mut compressed)?;
                let mut decompressed = Vec::with_capacity(run.sector_count as usize * 512);
                ZlibDecoder::new(Cursor::new(compressed))
                    .read_to_end(&mut decompressed)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let start = bytes_into_run as usize;
                let end = (start + to_read).min(decompressed.len());
                if start >= decompressed.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "zlib underrun"));
                }
                buf[..end - start].copy_from_slice(&decompressed[start..end]);
            }
            t => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported block type {t:#010x}"),
                ));
            }
        }

        self.position += to_read as u64;
        Ok(to_read)
    }
}

impl<R: Read + Seek> Seek for DmgReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let disk_size = self.virtual_disk_size();
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if n >= 0 {
                    disk_size.saturating_add(n as u64)
                } else {
                    disk_size.saturating_sub((-n) as u64)
                }
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.position.saturating_add(n as u64)
                } else {
                    self.position.saturating_sub((-n) as u64)
                }
            }
        };
        self.position = new_pos;
        Ok(self.position)
    }
}

// ── XML plist parser ──────────────────────────────────────────────────────────

/// Parse the XML plist and extract all mish (blkx) partitions.
fn parse_plist(xml: &str) -> Result<Vec<Partition>, DmgError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut in_blkx = false;
    let mut in_data = false;
    let mut last_key = String::new();
    let mut partitions = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"key" => {}
                b"array" if last_key == "blkx" => {
                    in_blkx = true;
                }
                b"data" if in_blkx => {
                    in_data = true;
                }
                _ => {}
            },
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default();
                let trimmed = text.trim();
                if e.is_empty() || trimmed.is_empty() {
                    continue;
                }
                // Check if this text is for a <key> element
                if trimmed != "blkx" && !in_blkx {
                    last_key = trimmed.to_string();
                    continue;
                }
                if trimmed == "blkx" {
                    last_key = "blkx".to_string();
                    continue;
                }
                if in_data && in_blkx {
                    // base64-encoded mish block
                    let cleaned: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
                    let raw = base64::engine::general_purpose::STANDARD
                        .decode(cleaned.as_bytes())
                        .map_err(|e| DmgError::BadPlist(e.to_string()))?;
                    let partition = parse_mish(&raw)?;
                    partitions.push(partition);
                    in_data = false;
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"array" {
                    in_blkx = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(DmgError::BadPlist(e.to_string())),
            _ => {}
        }
    }
    Ok(partitions)
}

/// Parse a raw mish block into a `Partition`.
///
/// Real mish layout (all big-endian):
///   0-3:    magic "mish"
///   4-7:    version
///   8-15:   firstSectorNumber
///   16-23:  sectorCount
///   24-31:  dataStart (byte offset into data fork)
///   32-35:  decompressBufferRequested
///   36-63:  reserved (28 bytes)
///   64-67:  checksum.type
///   68-71:  checksum.size (= 32 u32 words)
///   72-199: checksum.data (128 bytes)
///   200-203: blockDescriptorCount
///   204+:   BLKXRun entries (40 bytes each)
fn parse_mish(data: &[u8]) -> Result<Partition, DmgError> {
    if data.len() < 204 {
        return Err(DmgError::BadMish("too short".into()));
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if magic != MISH_MAGIC {
        return Err(DmgError::BadMish(format!("bad magic {magic:#010x}")));
    }
    let sector_number = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let file_data_offset = u64::from_be_bytes(data[24..32].try_into().unwrap());
    let block_descriptors = u32::from_be_bytes(data[200..204].try_into().unwrap()) as usize;

    let runs_start = 204;
    let run_size = 40;
    if data.len() < runs_start + block_descriptors * run_size {
        return Err(DmgError::BadMish("truncated run list".into()));
    }

    let mut runs = Vec::with_capacity(block_descriptors);
    for i in 0..block_descriptors {
        let o = runs_start + i * run_size;
        let entry_type = u32::from_be_bytes(data[o..o + 4].try_into().unwrap());
        let sector_start = u64::from_be_bytes(data[o + 8..o + 16].try_into().unwrap());
        let sector_count = u64::from_be_bytes(data[o + 16..o + 24].try_into().unwrap());
        let data_offset = u64::from_be_bytes(data[o + 24..o + 32].try_into().unwrap());
        let data_length = u64::from_be_bytes(data[o + 32..o + 40].try_into().unwrap());
        runs.push(BlkxRun { entry_type, sector_start, sector_count, data_offset, data_length });
        if entry_type == BLK_TERM {
            break;
        }
    }

    Ok(Partition { file_data_offset, sector_base: sector_number, runs })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Synthetic DMG builder ─────────────────────────────────────────────────

    /// One run entry for the test DMG builder.
    struct RunDef {
        entry_type: u32,
        sector_start: u64,
        sector_count: u64,
        data: Vec<u8>, // raw or pre-compressed bytes; empty for zero/ignore
    }

    /// Build a minimal synthetic DMG in memory.
    ///
    /// Layout:
    ///   [data bytes for all raw/compressed runs]
    ///   [xml plist]
    ///   [512-byte koly trailer]
    fn make_dmg(sector_count: u64, runs: Vec<RunDef>) -> Vec<u8> {
        let mut file: Vec<u8> = Vec::new();

        // Phase 1: write all run data and track offsets.
        let mish_data_offset = 0u64; // data fork starts at byte 0
        let mut run_file_offsets: Vec<u64> = Vec::new();
        for r in &runs {
            run_file_offsets.push(file.len() as u64);
            file.extend_from_slice(&r.data);
        }

        // Phase 2: build the mish block (binary, big-endian).
        // Header is 204 bytes before the first run entry (see parse_mish layout comment).
        let block_descriptors = runs.len() + 1; // +1 for BLK_TERM terminator
        let total_data_written: u64 = run_file_offsets.last().map_or(0, |&off| {
            let last = &runs[runs.len() - 1];
            off + last.data.len() as u64
        });
        let mut mish: Vec<u8> = Vec::new();
        mish.extend_from_slice(&MISH_MAGIC.to_be_bytes());     // 0-3
        mish.extend_from_slice(&1u32.to_be_bytes());           // 4-7:  version
        mish.extend_from_slice(&0u64.to_be_bytes());           // 8-15: sector_number
        mish.extend_from_slice(&sector_count.to_be_bytes());   // 16-23: sector_count
        mish.extend_from_slice(&mish_data_offset.to_be_bytes()); // 24-31: data_offset
        mish.extend_from_slice(&0u32.to_be_bytes());           // 32-35: buffers_needed
        mish.extend_from_slice(&[0u8; 28]);                    // 36-63: reserved
        // Checksum at offset 64 (136 bytes: type + size + data[32 u32s])
        mish.extend_from_slice(&2u32.to_be_bytes());           // 64-67: checksum.type (CRC32)
        mish.extend_from_slice(&32u32.to_be_bytes());          // 68-71: checksum.size
        mish.extend_from_slice(&[0u8; 128]);                   // 72-199: checksum.data (zeros)
        mish.extend_from_slice(&(block_descriptors as u32).to_be_bytes()); // 200-203: count

        // Runs at offset 204 (40 bytes each: type + reserved + sec_start + sec_count + d_off + d_len)
        for (i, r) in runs.iter().enumerate() {
            let data_off = run_file_offsets[i];
            let data_len = r.data.len() as u64;
            mish.extend_from_slice(&r.entry_type.to_be_bytes());
            mish.extend_from_slice(&0u32.to_be_bytes()); // reserved
            mish.extend_from_slice(&r.sector_start.to_be_bytes());
            mish.extend_from_slice(&r.sector_count.to_be_bytes());
            mish.extend_from_slice(&data_off.to_be_bytes());
            mish.extend_from_slice(&data_len.to_be_bytes());
        }
        // Terminator run (BLK_TERM, 40 bytes)
        mish.extend_from_slice(&BLK_TERM.to_be_bytes());      // type
        mish.extend_from_slice(&0u32.to_be_bytes());           // reserved
        mish.extend_from_slice(&sector_count.to_be_bytes());  // sector_start = end
        mish.extend_from_slice(&0u64.to_be_bytes());           // sector_count = 0
        mish.extend_from_slice(&total_data_written.to_be_bytes()); // data_offset
        mish.extend_from_slice(&0u64.to_be_bytes());           // data_length = 0

        // Phase 3: base64-encode the mish block.
        let mish_b64 = base64::engine::general_purpose::STANDARD.encode(&mish);

        // Phase 4: build the XML plist.
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n  <key>resource-fork</key>\n  <dict>\n\
             <key>blkx</key>\n<array>\n<dict>\n\
             <key>Data</key><data>{mish_b64}</data>\n\
             </dict>\n</array>\n  </dict>\n</dict>\n</plist>\n"
        );

        let xml_offset = file.len() as u64;
        let xml_length = xml.len() as u64;
        file.extend_from_slice(xml.as_bytes());

        // Phase 5: build the 512-byte koly trailer.
        let mut koly = [0u8; 512];
        koly[0..4].copy_from_slice(&KOLY_MAGIC.to_be_bytes());
        koly[4..8].copy_from_slice(&4u32.to_be_bytes()); // version
        koly[8..12].copy_from_slice(&512u32.to_be_bytes()); // header_size
        koly[216..224].copy_from_slice(&xml_offset.to_be_bytes());
        koly[224..232].copy_from_slice(&xml_length.to_be_bytes());
        koly[492..500].copy_from_slice(&sector_count.to_be_bytes());
        file.extend_from_slice(&koly);
        file
    }

    fn raw_run(sector_start: u64, data: Vec<u8>) -> RunDef {
        assert!(data.len() % 512 == 0, "raw data must be sector-aligned");
        RunDef {
            entry_type: BLK_RAW,
            sector_start,
            sector_count: data.len() as u64 / 512,
            data,
        }
    }

    fn zero_run(sector_start: u64, sector_count: u64) -> RunDef {
        RunDef { entry_type: BLK_ZERO, sector_start, sector_count, data: vec![] }
    }

    fn zlib_run(sector_start: u64, uncompressed: &[u8]) -> RunDef {
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(uncompressed).unwrap();
        let compressed = enc.finish().unwrap();
        RunDef {
            entry_type: BLK_ZLIB,
            sector_start,
            sector_count: uncompressed.len() as u64 / 512,
            data: compressed,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn file_too_small_returns_err() {
        let result = DmgReader::open(Cursor::new(b"tiny"));
        assert!(matches!(result, Err(DmgError::FileTooSmall)));
    }

    #[test]
    fn not_a_dmg_returns_err() {
        // 512 bytes of zeros — no koly magic
        let result = DmgReader::open(Cursor::new(vec![0u8; 512]));
        assert!(matches!(result, Err(DmgError::NotADmg)));
    }

    #[test]
    fn virtual_disk_size_is_512_times_sector_count() {
        let payload = vec![0xBBu8; 512];
        let dmg = make_dmg(1, vec![raw_run(0, payload)]);
        let reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        assert_eq!(reader.virtual_disk_size(), 512);
    }

    #[test]
    fn read_raw_block_returns_correct_bytes() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let dmg = make_dmg(1, vec![raw_run(0, payload.clone())]);
        let mut reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        let mut buf = vec![0u8; 512];
        reader.read_exact(&mut buf).expect("read_exact");
        assert_eq!(buf, payload);
    }

    #[test]
    fn read_zeroed_block_returns_zeros() {
        let dmg = make_dmg(2, vec![zero_run(0, 2)]);
        let mut reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        let mut buf = vec![0xFFu8; 512];
        reader.read_exact(&mut buf).expect("read_exact");
        assert!(buf.iter().all(|&b| b == 0), "expected all zeros");
    }

    #[test]
    fn seek_and_read_at_offset() {
        let mut payload = vec![0u8; 512];
        payload[100] = 0xAB;
        payload[101] = 0xCD;
        let dmg = make_dmg(1, vec![raw_run(0, payload)]);
        let mut reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        reader.seek(SeekFrom::Start(100)).expect("seek");
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(buf, [0xAB, 0xCD]);
    }

    #[test]
    fn read_across_run_boundary() {
        let mut sector0 = vec![0xAAu8; 512];
        sector0[511] = 0xBB;
        let mut sector1 = vec![0xCCu8; 512];
        sector1[0] = 0xDD;
        let mut payload = sector0;
        payload.extend_from_slice(&sector1);
        let dmg = make_dmg(2, vec![raw_run(0, payload)]);
        let mut reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        reader.seek(SeekFrom::Start(511)).expect("seek");
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).expect("read");
        // byte 511 = sector0[511] = 0xBB; byte 512 = sector1[0] = 0xDD
        assert_eq!(buf, [0xBB, 0xDD]);
    }

    #[test]
    fn zlib_block_decompressed_correctly() {
        let uncompressed: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let dmg = make_dmg(1, vec![zlib_run(0, &uncompressed)]);
        let mut reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        let mut buf = vec![0u8; 512];
        reader.read_exact(&mut buf).expect("read_exact");
        assert_eq!(buf, uncompressed);
    }

    #[test]
    fn multiple_partitions_both_readable() {
        let p0 = vec![0xAAu8; 512];
        let p1 = vec![0xBBu8; 512];
        // Two separate runs at sector 0 and sector 1
        let mut payload = p0.clone();
        payload.extend_from_slice(&p1);
        let dmg = make_dmg(2, vec![raw_run(0, payload)]);
        let mut reader = DmgReader::open(Cursor::new(dmg)).expect("open");
        let mut buf = [0u8; 512];
        reader.read_exact(&mut buf).expect("read sector 0");
        assert_eq!(&buf[..], &p0[..]);
        reader.read_exact(&mut buf).expect("read sector 1");
        assert_eq!(&buf[..], &p1[..]);
    }
}
