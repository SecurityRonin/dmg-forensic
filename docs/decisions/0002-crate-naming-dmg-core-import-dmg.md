# 2. Crate naming: publish `dmg-core`, import as `dmg`

Date: 2026-07-24
Status: Accepted

## Context

The natural reader name is the bare `dmg`. The fleet Crate naming grammar
(`ronin-issen/CLAUDE.md` → "Crate naming grammar") says: if the bare `<x>` name
is taken on crates.io by a third party we can safely co-exist with, publish
`<x>-core` with `[lib] name = "<x>"` so consumers still write `use <x>::…`; if
the bare name belongs to a *popular* crate whose import we must not hijack, keep
the `<x>_core` import path instead.

The repo was explicitly renamed to this form (commit `f350e95` — "refactor(naming):
publish as dmg-core (lib name dmg)").

## Decision

- Publish the reader crate as **`dmg-core`** (`core/Cargo.toml` `name =
  "dmg-core"`) with **`[lib] name = "dmg"`**, so downstream code imports it as
  `use dmg::DmgReader`.
- Publish the analyzer as **`dmg-forensic`** (imported `dmg_forensic`).
- The debug CLI crate is `dmg-forensic-cli`, binary `dmg4n6`, following the
  `<x>4n6` binary convention.

## Decision drivers / evidence

- `core/Cargo.toml`: `name = "dmg-core"`, `[lib] name = "dmg"`.
- README and `docs/index.md` document the `dmg` import path for consumers.
- The rename commit `f350e95` predates the Pattern-A restructure, establishing
  the published-name/import-name split before the two-crate layout landed.

The rename chose the *co-exist* branch of the grammar (keep the `dmg` import
path) rather than the *popular-crate* branch (`dmg_core` import). The specific
crates.io occupant of the bare `dmg` name that motivated the `-core` suffix is
not named in the commit history: rationale reconstructed from the naming-grammar
rule and the rename commit; the original conflicting crate not recovered in
available history.

## Consequences

- Consumers get a short `use dmg::…` path regardless of the published package
  name; the package name `dmg-core` is self-describing on crates.io as "the core
  reader of the `dmg-forensic` suite".
- Renaming after first publish would be a new package (crates.io names are claimed
  forever); the name was settled before publishing, honoring the grammar's
  "settle names before publishing" rule.
