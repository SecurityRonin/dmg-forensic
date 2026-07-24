# 3. `dmg-forensic` parses the raw koly trailer, independent of `dmg-core`

Date: 2026-07-24
Status: Accepted

## Context

The fleet default is that `<x>-forensic` depends on `<x>-core`. But the standard
carves out a binding exception (`ronin-issen/CLAUDE.md` → "`-forensic` is NOT
required to depend on `-core`"): a `-core` reader is built to read *valid* data
robustly, so it normalizes or rejects exactly the malformed/edited fields a
forensic auditor must SEE. The auditor should parse the raw structure itself when
the reader's happy-path API would hide the anomaly.

The DMG koly trailer is the canonical case. `DmgReader::open` in `dmg-core` reads
the trailer to locate the data fork and XML block table and then *trusts* those
pointers; a post-hoc-edited or corrupt trailer is precisely what the reader would
either normalize away or refuse to open. An auditor that went through the reader
could never report "the XML pointer runs past the end of the file", because the
reader would already have failed or masked it.

## Decision

`dmg-forensic` parses the koly trailer over raw bytes and does **not** depend on
`dmg-core`:

1. `forensic/Cargo.toml` declares only `forensicnomicon` as a dependency — no
   `dmg-core`.
2. The auditor accepts `&[u8]` (`audit`, `audit_trailer`) or any `Read + Seek`
   (`audit_reader`, `audit_path`) and reads the fixed koly field offsets itself
   (signature `0x00`, version `0x04`, data-fork `0x18`/`0x20`, XML `0xd8`/`0xe0`),
   per the module doc comment in `forensic/src/lib.rs`.
3. Integer fields are read through local bounds-checked helpers (`be_u32` /
   `be_u64` yield 0 out of range, never panic); pointer ranges are range-checked
   against the true file length with `saturating_add` before comparison.

## Consequences

- The auditor sees a corrupt/overwritten trailer verbatim and can grade it, which
  a reader-backed audit could not (it emits `DMG-KOLY-SIGNATURE-INVALID`,
  `-DATAFORK-OUT-OF-BOUNDS`, `-XML-OUT-OF-BOUNDS`, etc., each carrying the
  offending value + field as evidence).
- `audit_reader` never loads a multi-GB image: it seeks to the tail and reads only
  the 512-byte trailer, so auditing is O(1) in image size.
- `dmg-forensic`'s dependency tree is minimal (`forensicnomicon` only), and the
  two crates evolve independently.
- The koly field offsets are duplicated as small constants here rather than
  imported from the reader; this is deliberate (the auditor must own its view of
  the layout, not inherit the reader's), and the offsets are covered by the
  crafted-trailer tests in `forensic/tests/audit.rs`.
