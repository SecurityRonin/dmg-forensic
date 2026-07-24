# 5. Apple sparse-image readers behind the same `Read + Seek` interface

Date: 2026-07-24
Status: Accepted

## Context

Apple ships two more disk-image families alongside the UDIF `.dmg`: the
`.sparseimage` (a single file with an `sprs` band table) and the `.sparsebundle`
(a directory of hex-named band files with an `Info.plist`, the format Time Machine
and Sumuri RECON produce). A DFIR consumer that can read a DMG virtual disk wants
to read these the same way, without a second, differently-shaped API.

Support was added TDD across commits `321afe2`…`c433816`
(`SparseImageReader`, `SparseBundleReader`), with a correctness fix in `ad0f3a7`
after the `hdiutil` oracle disagreed.

## Decision

1. Add `SparseImageReader` (`.sparseimage`, `sprs`) and `SparseBundleReader`
   (`.sparsebundle`) in `core/src/sparse.rs`, re-exported from `dmg-core`
   (`pub use sparse::{SparseBundleReader, SparseImageReader}`).
2. Expose both behind the **same `Read + Seek` virtual-disk interface** as
   `DmgReader`, so any partition/filesystem analyzer that accepts a reader drops
   onto them unchanged.
3. The `sprs` band table is stored **slot-indexed** (indexed by physical slot,
   value = virtual band + 1); the reader inverts it accordingly (commit
   `ad0f3a7`).

## Consequences

- One repository covers the Apple disk-image family (DMG + sparse image + sparse
  bundle) under one interface; consumers select a constructor, not a code path.
- Correctness is a **tier-2** cross-tool check: readers are validated against a
  self-minted `hdiutil` image flattened with `hdiutil convert -format UDTO`, with
  a full-image SHA-256 match (`core/tests/sparse_images.rs`, env-gated on macOS).
  The full-image SHA was load-bearing — it caught the band-table direction error
  that per-offset spot-checks passed (see `docs/validation.md`).
- The `sprs` header parser is fuzzed (`fuzz_sparse`) to guarantee it never panics
  on arbitrary bytes.
- This is explicitly **not** tier-1: the image is self-minted and the oracle
  shares `hdiutil`'s codebase, so a captured real-world acquisition (e.g. a Sumuri
  RECON bundle) may still carry quirks the synthetic scenario misses.
