[![Crates.io (dmg-core)](https://img.shields.io/crates/v/dmg-core.svg?label=dmg-core)](https://crates.io/crates/dmg-core)
[![Crates.io (dmg-forensic)](https://img.shields.io/crates/v/dmg-forensic.svg?label=dmg-forensic)](https://crates.io/crates/dmg-forensic)
[![Docs.rs](https://img.shields.io/docsrs/dmg-core)](https://docs.rs/dmg-core)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/dmg-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dmg-forensic/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://securityronin.github.io/dmg-forensic/)

**Read and audit macOS Disk Images (DMG/UDIF) in pure Rust — a `Read + Seek` virtual disk with every block codec, plus a koly-trailer anomaly auditor. Zero C dependencies.**

Point it at a `.dmg` and get graded forensic findings from the structure a happy-path reader trusts blindly:

```rust
use std::path::Path;

// The differentiator: audit the koly trailer for tampering / corruption.
for a in dmg_forensic::audit_path(Path::new("evidence.dmg"))? {
    println!("[{:?}] {}: {}", a.severity, a.code, a.note);
}
// [High] DMG-KOLY-XML-OUT-OF-BOUNDS: koly XML block-table range [..] runs past the file …
# Ok::<(), std::io::Error>(())
```

## Two crates

- **`dmg-core`** (imported as `dmg`) — the reader. `DmgReader` over any `Read + Seek`: locates the 512-byte `koly` trailer, parses the embedded XML plist block table (`blkx`/`mish`), and serves the virtual sector stream through `Read + Seek`, decompressing on demand. Every codec `hdiutil` emits — **ADC, zlib, bzip2, LZFSE, LZMA** — all pure Rust, no C bindings, fuzzed against malformed input.
- **`dmg-forensic`** — the analyzer. `audit_path` / `audit_reader` / `audit` parse the raw koly trailer (not the reader's normalized view) and emit graded `forensicnomicon` findings.

```toml
[dependencies]
dmg-core = "0.1"       # the reader (import as `dmg`)
dmg-forensic = "0.1"   # the koly-trailer auditor
```

## Reading the virtual disk

```rust
use dmg::DmgReader;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

let mut reader = DmgReader::open(File::open("disk.dmg")?)?;
println!("virtual disk: {} bytes", reader.virtual_disk_size());

let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;        // first sector
reader.seek(SeekFrom::Start(1 << 20))?; // seek anywhere
# Ok::<(), dmg::DmgError>(())
```

Because `DmgReader` is `Read + Seek`, it drops straight into any partition or filesystem analyzer that accepts a reader.

## Anomaly codes

| Code | Severity | Meaning |
|------|----------|---------|
| `DMG-KOLY-SIGNATURE-INVALID` | High | trailer signature is not `koly` — not UDIF, or overwritten |
| `DMG-KOLY-VERSION-UNEXPECTED` | Low | version field is not the documented 4 |
| `DMG-KOLY-DATAFORK-OUT-OF-BOUNDS` | High | data-fork offset+length runs past the file end |
| `DMG-KOLY-XML-OUT-OF-BOUNDS` | High | XML block-table offset+length runs past the file end |
| `DMG-KOLY-TRAILER-TOO-SMALL` | High | file is smaller than a 512-byte koly trailer |

Each finding is an observation ("consistent with", never a verdict) carrying the offending value + field as evidence.

## Trust, but verify

Panic-free by construction: every koly field is read through a bounds-checked reader (0 out of range, never a panic), every pointer is range-checked against the file length, and `audit_reader` never loads a multi-GB image — it seeks to the tail and reads only the 512-byte trailer. Codecs are validated against real `hdiutil`-produced DMGs, and a real Apple-made DMG audits clean. See the [validation](https://securityronin.github.io/dmg-forensic/validation/) writeup.

---

[Privacy Policy](https://securityronin.github.io/dmg-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/dmg-forensic/terms/) · © 2026 Security Ronin Ltd
