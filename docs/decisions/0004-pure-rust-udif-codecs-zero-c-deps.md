# 4. Pure-Rust UDIF codecs, zero C dependencies, and the `unsafe` posture

Date: 2026-07-24
Status: Accepted

## Context

UDIF stores its virtual sectors in per-block compressed runs. A full DMG reader
must decode every codec `hdiutil` emits: zero, raw, ignore, ADC (`0x80000004`),
zlib/UDZO (`0x80000005`), bzip2/UDBZ (`0x80000006`), LZFSE/ULFO (`0x80000007`),
and LZMA/ULMO (`0x80000008`). The obvious implementations for bzip2, LZMA, and
LZFSE are C libraries wrapped by `-sys` crates.

Two fleet disciplines bear directly on the choice:

- **Batteries-included** (`ronin-issen/CLAUDE.md`): a forensic tool must do the
  whole job from one static binary; a codec that isn't compiled in is a
  capability that isn't there in the field. So all codecs are non-optional.
- **`unsafe` is an avoidable cost-benefit exception** (`CLAUDE.core.md`): a C-FFI
  `-sys` dependency is the worst kind of `unsafe` liability — the compiler has
  zero visibility into C, and it breaks the pure-Rust posture. For a parser of
  untrusted, attacker-crafted input (every evidence image), that reintroduces the
  C/C++ memory-corruption class that safe Rust deletes by construction.

Full codec support landed pure-Rust in commit `a9a11a9` ("feat: full UDIF codec
support (ADC/zlib/bzip2/LZFSE/LZMA), all pure Rust"); fuzzer-found crashes were
then hardened in `ed4be56`.

## Decision

1. Decode every UDIF codec with **pure-Rust** crates and no C bindings:
   `flate2` (zlib), `bzip2-rs` (bzip2), `lzma-rs` (LZMA), `lzfse_rust` (LZFSE);
   ADC is decoded **in-crate** (`adc_decompress`, `core/src/lib.rs` — a small
   LZSS variant with no ecosystem crate). All are declared in
   `[workspace.dependencies]`.
2. All codecs are compiled in unconditionally (no per-codec Cargo features): a
   `.dmg` produced by any `hdiutil` invocation decodes from the zero-config path.
3. **`unsafe_code = "deny"`** at the workspace root (`[workspace.lints.rust]`),
   and the codebase contains **zero** `unsafe` blocks and zero
   `#[allow(unsafe_code)]` sites (verified by grep across `core/` and `forensic/`).

## Consequences

- The reader is a portable, C-free static library: no build-time C toolchain, no
  cross-compilation of `-sys` crates, and the attacker-controlled decode path
  stays inside safe Rust.
- Every decoder is fuzzed against malformed input (`fuzz_open`, `fuzz_sparse`) and
  the block I/O is bounded (commit `ed4be56`), the runtime partner to the static
  no-C posture.
- The workspace declares `deny` rather than the fleet-default `forbid(unsafe)`,
  even though there is currently no `unsafe` and no allow site to justify the
  downgrade (`forbid` would be achievable and is the fleet goal). The README
  correctly does **not** carry an "unsafe-forbidden" badge. The reason `deny` was
  chosen over `forbid` is not documented: rationale reconstructed from the lint
  config; original intent not recovered in available history. A future pass may
  tighten this to `forbid`.
