[![Crates.io](https://img.shields.io/crates/v/dmg-core.svg)](https://crates.io/crates/dmg-core)
[![Docs.rs](https://img.shields.io/docsrs/dmg-core)](https://docs.rs/dmg-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/dmg/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dmg/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust forensic Apple Disk Image (DMG/UDIF) reader — every block codec, a `Read + Seek` virtual disk, zero C dependencies.**

Decodes macOS DMG containers (UDIF): locates the 512-byte `koly` trailer at EOF, parses the embedded XML plist for partition block tables (`blkx`/`mish`), and serves the virtual sector stream through `Read + Seek`, decompressing blocks on demand. Every codec `hdiutil` emits is supported — **ADC, zlib, bzip2, LZFSE, LZMA** — all in pure Rust. `#![forbid(unsafe_code)]` is not used (the workspace denies unsafe), there are no C bindings, and the parser is fuzzed against malformed input.

```toml
[dependencies]
dmg-core = "0.1"   # imported as `dmg`
```

## Quick start

```rust
use dmg::DmgReader;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

// `open` takes any `Read + Seek` (a File, a Cursor, a decoded container…).
let mut reader = DmgReader::open(File::open("disk.dmg")?)?;
println!("virtual disk: {} bytes", reader.virtual_disk_size());

let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;       // first sector
reader.seek(SeekFrom::Start(1 << 20))?; // seek anywhere
# Ok::<(), dmg::DmgError>(())
```

Because `DmgReader` is `Read + Seek`, it drops straight into any partition or filesystem analyzer that accepts a reader.

## Supported block types

| Type | Value | Notes |
|------|-------|-------|
| Zero / Ignore | `0x00000000` / `0x00000002` | sparse region → zero bytes |
| Raw | `0x00000001` | stored verbatim |
| ADC | `0x80000004` | Apple Data Compression (UDCO) |
| zlib | `0x80000005` | UDZO |
| bzip2 | `0x80000006` | UDBZ |
| LZFSE | `0x80000007` | ULFO |
| LZMA | `0x80000008` | ULMO (XZ-framed) |

Every codec is validated against real `hdiutil`-produced fixtures (each converts byte-identically to the raw image). Block sizes are bounded against the file and a per-block cap, so a malformed image fails loud rather than over-allocating.

---

[Privacy Policy](https://securityronin.github.io/dmg/privacy/) · [Terms of Service](https://securityronin.github.io/dmg/terms/) · © 2026 Security Ronin Ltd
