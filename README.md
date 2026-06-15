[![Crates.io](https://img.shields.io/crates/v/dmg.svg)](https://crates.io/crates/dmg)
[![Docs.rs](https://img.shields.io/docsrs/dmg)](https://docs.rs/dmg)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/dmg/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dmg/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust forensic Apple Disk Image (DMG/UDIF) reader — koly trailer, mish block tables, zlib decompression.**

Decodes macOS DMG containers using the UDIF (Universal Disk Image Format): locates the 512-byte koly trailer at EOF, parses the embedded XML plist for partition block tables (blkx), and decompresses zlib runs on demand. Exposes a `Read + Seek` interface over the virtual sector stream. Zero unsafe code, no C bindings.

```toml
[dependencies]
dmg = "0.1"
```

---

## Usage

### Open a DMG and read sectors

```rust
use dmg::DmgReader;
use std::io::{Read, Seek, SeekFrom};

let mut reader = DmgReader::open("disk.dmg")?;

println!("Virtual disk size: {} bytes", reader.virtual_disk_size());

// Read the first sector
let mut sector = [0u8; 512];
reader.read_exact(&mut sector)?;

// Seek anywhere
reader.seek(SeekFrom::Start(1_048_576))?;
```

### Pass to a filesystem crate

`DmgReader` implements `Read + Seek`, so it drops directly into any crate that accepts a reader:

```rust
use dmg::DmgReader;

let reader = DmgReader::open("disk.dmg")?;
// e.g. ext4fs_forensic::Filesystem::open(reader)?;
```

---

## Supported block types

| Type | Value | Description |
|------|-------|-------------|
| Zero | `0x00000000` | Sparse zero region — returns zero bytes |
| Raw | `0x00000001` | Uncompressed data stored verbatim |
| Ignore | `0x00000002` | Ignored region — returns zero bytes |
| zlib | `0x80000005` | zlib-compressed data — decompressed on read |
| Comment | `0x7FFFFFFE` | Internal comment entry — skipped |
| Terminator | `0xFFFFFFFF` | End of block table marker |

bzip2 (`0x80000006`) and LZFSE (`0x80000007`) return `DmgError::NotSupported`. Most forensic images use zlib or raw.

---

## Related crates

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) | ISO 9660 | Optical disc images: multi-session, UDF bridge, Rock Ridge, Joliet, El Torito |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/dmg/privacy/) · [Terms of Service](https://securityronin.github.io/dmg/terms/) · © 2026 Security Ronin Ltd
