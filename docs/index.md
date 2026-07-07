# dmg-forensic

A pure-Rust, read-only Apple Disk Image (DMG / UDIF) toolkit for digital
forensics: a container reader (`dmg-core`) that decodes every block codec
`hdiutil` emits with **no C dependencies**, and an anomaly auditor
(`dmg-forensic`) that checks the koly trailer a happy-path reader would trust
blindly.

## What you get

- **`dmg-core`** — `DmgReader` over any `Read + Seek`: locates the 512-byte `koly`
  trailer, parses the embedded XML plist block table (`blkx`/`mish`), and serves
  the virtual sector stream through `Read + Seek`, decompressing on demand. Every
  codec `hdiutil` produces is supported — **ADC, zlib, bzip2, LZFSE, LZMA** — all
  in pure Rust.
- **`dmg-forensic`** — `audit_path` / `audit_reader` / `audit` emit graded
  `forensicnomicon` findings from the koly trailer: an invalid signature, an
  unexpected version, and data-fork / XML pointer ranges that run past the end of
  the file (truncation or a tampered trailer). It parses the raw trailer itself
  rather than through the reader, so it sees exactly the fields a reader would
  normalize away.

## Quick start

```rust
use std::path::Path;

// Audit a DMG's koly trailer for structural anomalies.
let anomalies = dmg_forensic::audit_path(Path::new("evidence.dmg"))?;
for a in &anomalies {
    println!("[{:?}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), std::io::Error>(())
```

See [Validation](validation.md) for how correctness is established.
