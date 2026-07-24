# dmg-forensic — Design: Purpose & Scope

This is a **library** repository (two published crates plus a `publish = false`
debug CLI), not a product. This document records its purpose, scope, and
boundaries; the load-bearing decisions and their rationale live in
[`docs/decisions/`](decisions/).

## Purpose

Read and audit Apple Disk Images in pure Rust, with no C dependencies, so that:

- any Rust partition/filesystem analyzer can treat a DMG or Apple sparse image as
  a plain `Read + Seek` virtual disk, decompressing on demand; and
- a DFIR pipeline can grade the DMG's `koly` trailer for corruption or tampering
  before trusting the pointers a happy-path reader would follow blindly.

## What it does

- **`dmg-core`** (imported as `dmg`) — the reader.
  - `DmgReader<R: Read + Seek>`: locates the 512-byte big-endian `koly` trailer at
    the end of the file, parses the embedded XML plist block table (`blkx` array of
    base64-encoded `mish` blocks), and serves the virtual sector stream through
    `Read + Seek`, decoding each block on demand.
  - Every UDIF block codec `hdiutil` emits: zero, raw, ignore, **ADC** (in-crate
    LZSS), **zlib/UDZO**, **bzip2/UDBZ**, **LZFSE/ULFO**, **LZMA/ULMO** — all pure
    Rust (ADR 0004).
  - Apple sparse images: `SparseImageReader` (`.sparseimage`, `sprs`) and
    `SparseBundleReader` (`.sparsebundle`), behind the same virtual-disk interface
    (ADR 0005).
  - Optional `vfs` feature: implements `forensic-vfs::ImageSource` so the decoded
    disk composes into the fleet VFS stack (ADR 0006).
- **`dmg-forensic`** — the analyzer. `audit` / `audit_trailer` / `audit_reader` /
  `audit_path` parse the raw koly trailer (independent of the reader, ADR 0003) and
  emit graded `forensicnomicon::report` findings, each carrying the offending value
  and field as evidence:

  | Code | Severity | Meaning |
  |------|----------|---------|
  | `DMG-KOLY-TRAILER-TOO-SMALL` | High | file smaller than a 512-byte koly trailer |
  | `DMG-KOLY-SIGNATURE-INVALID` | High | trailer signature is not `koly` |
  | `DMG-KOLY-VERSION-UNEXPECTED` | Low | version field is not the documented 4 |
  | `DMG-KOLY-DATAFORK-OUT-OF-BOUNDS` | High | data-fork offset+length past file end |
  | `DMG-KOLY-XML-OUT-OF-BOUNDS` | High | XML block-table offset+length past file end |

  Findings are observations ("consistent with", never a verdict); the analyst or
  tribunal draws conclusions.

## Users

- **Fleet orchestration** (issen / `disk4n6`, `forensic-vfs`) — links `dmg-core`
  to mount/traverse DMGs and `dmg-forensic` to fold koly anomalies into the unified
  `forensicnomicon::report` timeline.
- **Third-party Rust developers** — link `dmg-core` alone for a C-free DMG /
  sparse-image reader.
- The `dmg4n6` CLI is a **debug/standalone** front-end for local inspection only;
  it is unpublished and is not the end-user tool.

## Architectural placement

`dmg-core` is a CONTAINER-layer crate (decode a raw source format → addressable
byte stream). `dmg-forensic` is a PARSER-side auditor that depends only on the
`forensicnomicon` KNOWLEDGE leaf. The two-crate split and dependency direction are
ADRs 0001 and 0003.

## Scope

- UDIF DMG reading (all `hdiutil` codecs) and virtual-disk exposure.
- Apple `.sparseimage` and `.sparsebundle` reading behind the same interface.
- koly-trailer structural anomaly auditing.
- Read-only, positioned/lazy access — a multi-GB image is never read whole; the
  auditor reads only the 512-byte tail.

## Non-goals

- **No inner-filesystem parsing.** The reader serves bytes; interpreting HFS+ /
  APFS / a partition map inside the image is the job of the consuming filesystem
  analyzers, not this crate.
- **No encrypted-DMG decryption.** There is no password/AEA/EncryptedRoot handling;
  an encrypted image is not decoded (verified: no crypto paths in `core/src`).
- **No writing or image editing.** The crates are read-only; nothing emits or
  mutates a DMG.
- **Not an end-user CLI or GUI.** `dmg4n6` is a debug shell (`publish = false`); the
  shipped user surface is issen / `disk4n6`.

## Validation approach

Correctness is established against independent oracles and real artifacts, labelled
by tier, in [`docs/validation.md`](validation.md): reader codecs and sparse readers
are cross-checked byte-for-byte against `hdiutil` (tier 2); a well-formed DMG audits
clean (tier-2 specificity); tamper-detection rules are specified by the koly layout
and crafted-trailer tests (tier-3 sensitivity, by nature — no third-party
known-answer artifact exists for deliberate corruption). All parsers are fuzzed
(`fuzz_open`, `fuzz_sparse`) to guarantee they never panic on arbitrary input.
