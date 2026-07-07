//! Forensic Apple Disk Image (DMG / UDIF) anomaly auditor.
//!
//! A DMG is identified by its `koly` trailer — the last 512 bytes of the file —
//! which points at the data fork and the XML (plist) block table. A happy-path
//! reader trusts those pointers; this auditor checks them, surfacing a corrupt or
//! post-hoc-edited trailer (bad signature, unexpected version, or offset/length
//! fields that run past the end of the file). Each anomaly is an OBSERVATION
//! graded by severity ("consistent with", never a verdict) and converts to a
//! [`forensicnomicon::report::Finding`] via [`Observation`].
//!
//! It parses the koly trailer itself over raw bytes rather than through
//! `dmg-core`'s reader (which normalizes exactly the fields an auditor must see),
//! so it takes `&[u8]` / any `Read + Seek` — never a decoded stream.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use forensicnomicon::report::{Category, Evidence, Observation, Severity};

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "dmg-forensic";

/// UDIF koly trailer size, in bytes (fixed by the format).
pub const KOLY_LEN: usize = 512;

/// koly trailer signature: the ASCII `koly` as a big-endian `u32`.
pub const KOLY_MAGIC: u32 = 0x6b6f_6c79;

/// The documented UDIF trailer version.
const KOLY_VERSION: u32 = 4;

/// Classification of a DMG forensic anomaly, carrying the offending value +
/// location to reproduce it (per CLAUDE.md "Show the unrecognized value").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// The file is smaller than a 512-byte koly trailer — truncated or not a DMG.
    TrailerTooSmall {
        /// Total bytes available.
        len: usize,
    },
    /// The koly signature is not `koly` — not a UDIF trailer, or the trailer was
    /// overwritten.
    SignatureInvalid {
        /// The four bytes found where the signature was expected.
        found: u32,
    },
    /// The koly version field is not the documented value 4.
    VersionUnexpected {
        /// The version recorded in the trailer.
        version: u32,
    },
    /// The data-fork offset+length runs past the end of the file — consistent
    /// with a truncated image or a tampered pointer.
    DataForkOutOfBounds {
        /// Data-fork offset from the trailer.
        offset: u64,
        /// Data-fork length from the trailer.
        length: u64,
        /// Actual file length.
        file_len: u64,
    },
    /// The XML (plist block-table) offset+length runs past the end of the file.
    XmlOutOfBounds {
        /// XML offset from the trailer.
        offset: u64,
        /// XML length from the trailer.
        length: u64,
        /// Actual file length.
        file_len: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::TrailerTooSmall { .. }
            | AnomalyKind::SignatureInvalid { .. }
            | AnomalyKind::DataForkOutOfBounds { .. }
            | AnomalyKind::XmlOutOfBounds { .. } => Severity::High,
            AnomalyKind::VersionUnexpected { .. } => Severity::Low,
        }
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::TrailerTooSmall { .. } => "DMG-KOLY-TRAILER-TOO-SMALL",
            AnomalyKind::SignatureInvalid { .. } => "DMG-KOLY-SIGNATURE-INVALID",
            AnomalyKind::VersionUnexpected { .. } => "DMG-KOLY-VERSION-UNEXPECTED",
            AnomalyKind::DataForkOutOfBounds { .. } => "DMG-KOLY-DATAFORK-OUT-OF-BOUNDS",
            AnomalyKind::XmlOutOfBounds { .. } => "DMG-KOLY-XML-OUT-OF-BOUNDS",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::VersionUnexpected { .. } => Category::Structure,
            _ => Category::Integrity,
        }
    }

    /// Human-readable, "consistent with" note including the offending values.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::TrailerTooSmall { len } => format!(
                "file is {len} byte(s) — smaller than the 512-byte UDIF koly trailer; \
                 consistent with a truncated image or a non-DMG file"
            ),
            AnomalyKind::SignatureInvalid { found } => format!(
                "koly trailer signature is 0x{found:08x}, not 'koly' (0x6b6f6c79); consistent \
                 with a non-UDIF file or an overwritten trailer"
            ),
            AnomalyKind::VersionUnexpected { version } => {
                format!("koly trailer version is {version}, not the documented 4")
            }
            AnomalyKind::DataForkOutOfBounds {
                offset,
                length,
                file_len,
            } => format!(
                "koly data-fork range [{offset}, {offset}+{length}) runs past the {file_len}-byte \
                 file; consistent with a truncated image or a tampered pointer"
            ),
            AnomalyKind::XmlOutOfBounds {
                offset,
                length,
                file_len,
            } => format!(
                "koly XML block-table range [{offset}, {offset}+{length}) runs past the \
                 {file_len}-byte file; consistent with a corrupt or tampered plist pointer"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::TrailerTooSmall { len } => vec![Evidence {
                field: "file_len".to_string(),
                value: len.to_string(),
                location: None,
            }],
            AnomalyKind::SignatureInvalid { found } => vec![Evidence {
                field: "koly.signature".to_string(),
                value: format!("0x{found:08x}"),
                location: None,
            }],
            AnomalyKind::VersionUnexpected { version } => vec![Evidence {
                field: "koly.version".to_string(),
                value: version.to_string(),
                location: None,
            }],
            AnomalyKind::DataForkOutOfBounds {
                offset,
                length,
                file_len,
            } => vec![Evidence {
                field: "koly.data_fork".to_string(),
                value: format!("offset={offset}, length={length}, file_len={file_len}"),
                location: None,
            }],
            AnomalyKind::XmlOutOfBounds {
                offset,
                length,
                file_len,
            } => vec![Evidence {
                field: "koly.xml".to_string(),
                value: format!("offset={offset}, length={length}, file_len={file_len}"),
                location: None,
            }],
        }
    }
}

/// A DMG forensic anomaly: an observation graded by severity, with a stable code
/// and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

/// Read a big-endian `u32` at `off`, yielding 0 out of range (never panics).
fn be_u32(b: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    if let Some(s) = b.get(off..off + 4) {
        a.copy_from_slice(s);
    }
    u32::from_be_bytes(a)
}

/// Read a big-endian `u64` at `off`, yielding 0 out of range (never panics).
fn be_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    if let Some(s) = b.get(off..off + 8) {
        a.copy_from_slice(s);
    }
    u64::from_be_bytes(a)
}

/// Audit a koly trailer (its raw bytes) against the known total file length.
///
/// This is the pure core: the caller supplies the last [`KOLY_LEN`] bytes and the
/// file's true length, so a large image never has to be read whole.
#[must_use]
pub fn audit_trailer(trailer: &[u8], file_len: u64) -> Vec<Anomaly> {
    let mut out = Vec::new();

    if trailer.len() < KOLY_LEN {
        out.push(Anomaly::new(AnomalyKind::TrailerTooSmall {
            len: trailer.len(),
        }));
        return out;
    }

    // Signature is load-bearing: without it the remaining offsets are not koly
    // fields at all, so a mismatch is reported alone.
    let signature = be_u32(trailer, 0);
    if signature != KOLY_MAGIC {
        out.push(Anomaly::new(AnomalyKind::SignatureInvalid {
            found: signature,
        }));
        return out;
    }

    let version = be_u32(trailer, 4);
    if version != KOLY_VERSION {
        out.push(Anomaly::new(AnomalyKind::VersionUnexpected { version }));
    }

    let df_offset = be_u64(trailer, 0x18);
    let df_length = be_u64(trailer, 0x20);
    if df_offset.saturating_add(df_length) > file_len {
        out.push(Anomaly::new(AnomalyKind::DataForkOutOfBounds {
            offset: df_offset,
            length: df_length,
            file_len,
        }));
    }

    let xml_offset = be_u64(trailer, 0xd8);
    let xml_length = be_u64(trailer, 0xe0);
    if xml_offset.saturating_add(xml_length) > file_len {
        out.push(Anomaly::new(AnomalyKind::XmlOutOfBounds {
            offset: xml_offset,
            length: xml_length,
            file_len,
        }));
    }

    out
}

/// Audit a whole DMG given as bytes (locates the koly trailer at the tail).
#[must_use]
pub fn audit(data: &[u8]) -> Vec<Anomaly> {
    if data.len() < KOLY_LEN {
        return vec![Anomaly::new(AnomalyKind::TrailerTooSmall {
            len: data.len(),
        })];
    }
    let trailer = &data[data.len() - KOLY_LEN..];
    audit_trailer(trailer, data.len() as u64)
}

/// Audit a seekable reader without loading the whole image: seek to the end, read
/// the last [`KOLY_LEN`] bytes, and check them against the file length.
pub fn audit_reader<R: Read + Seek>(mut reader: R) -> io::Result<Vec<Anomaly>> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < KOLY_LEN as u64 {
        return Ok(vec![Anomaly::new(AnomalyKind::TrailerTooSmall {
            len: usize::try_from(file_len).unwrap_or(usize::MAX),
        })]);
    }
    reader.seek(SeekFrom::End(-(KOLY_LEN as i64)))?;
    let mut trailer = [0u8; KOLY_LEN];
    reader.read_exact(&mut trailer)?;
    Ok(audit_trailer(&trailer, file_len))
}

/// Audit a DMG file by path.
pub fn audit_path(path: &Path) -> io::Result<Vec<Anomaly>> {
    audit_reader(std::fs::File::open(path)?)
}
