# 1. Reader/analyzer two-crate split (Pattern A: `core/` + `forensic/`)

Date: 2026-07-24
Status: Accepted

## Context

The repository reads Apple Disk Images (DMG/UDIF) *and* audits them for
structural anomalies. These are two different jobs with two different callers: a
reader is linked by any partition/filesystem analyzer that wants the decoded
sector stream, while an auditor is linked by a DFIR pipeline that wants graded
findings. The fleet Crate-structure standard (`ronin-issen/CLAUDE.md` → "Crate-
structure standard — reader/analyzer split") mandates that a single-format repo
ship exactly two crates: `<x>-core` (the raw reader, no findings) and
`<x>-forensic` (the anomaly auditor emitting `forensicnomicon::report` findings),
in one workspace named `<x>-forensic`.

The repo began life as a single `dmg` crate and was restructured into this shape
(commit `ee1f849` — "refactor: restructure to Pattern A — repo dmg ->
dmg-forensic, dmg/ -> core/").

## Decision

Ship two library crates from one workspace (`Cargo.toml` `members = ["core",
"forensic", "cli"]`):

1. **`core/` → `dmg-core`** — the reader. `DmgReader` over any `Read + Seek`
   plus the sparse-image readers; decodes and serves the virtual sector stream.
   No findings.
2. **`forensic/` → `dmg-forensic`** — the auditor. `audit_path` / `audit_reader`
   / `audit` emit graded `forensicnomicon::report` findings.
3. A third `cli/` member (`dmg4n6`) exists as a debug/standalone front-end only
   and is `publish = false` (`cli/Cargo.toml`); the fleet end-user CLI is
   issen / `disk4n6`. The CLI member does not make this a product-tier repo.

The workspace is named `dmg-forensic` (the analyzer is the headline) even though
it also holds the reader, per the standard.

## Consequences

- A downstream that only needs the decoded stream depends on `dmg-core` alone and
  never pulls the auditor or `forensicnomicon`.
- The analyzer is versioned and released independently of the reader (see ADR
  0009), and the reader is reusable by any Rust project, not just forensic ones.
- `dmg-core` sits in the CONTAINER layer of the fleet architecture (decode a raw
  source format → addressable byte stream); `dmg-forensic` is a PARSER-side
  auditor. The dependency direction between them is settled separately in ADR
  0003.
