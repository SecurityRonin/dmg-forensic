# 7. CI-verified MSRV floor, distinct from the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`CLAUDE.core.md` → "Rust MSRV & Toolchain Policy") splits
two numbers that must not be conflated: the **dev toolchain** (what we build /
fmt / clippy with — pinned to current stable, an internal choice) and the
**declared MSRV** (`rust-version` — a downstream-facing compatibility promise).
Published libraries keep a low, CI-verified MSRV so they stay reusable by
third parties on older toolchains; only apps set MSRV = the pinned toolchain.

`dmg-core` and `dmg-forensic` are published libraries, so they take the library
branch of the policy.

## Decision

1. **Dev/CI toolchain** is pinned to current stable in `rust-toolchain.toml`
   (`channel = "1.96.0"`, with `rustfmt` + `clippy` components declared there).
2. **Declared MSRV** is set once in `[workspace.package]` (`rust-version =
   "1.85"`) and inherited by every member, well below the dev pin.
3. A dedicated CI job verifies it: `ci.yml` runs an `msrv` job named "MSRV (1.85)"
   on `dtolnay/rust-toolchain@…  # 1.85`, so the promise is a checked guarantee,
   not a hopeful number.

## Consequences

- The declared MSRV is an enforced contract: a build against 1.85 is exercised on
  every push, and raising it is a deliberate, near-breaking change (it narrows the
  crates.io audience).
- Developing on 1.96 while promising 1.85 ends toolchain-drift fmt/clippy churn
  without lying to downstream about compatibility.
- The floor is 1.85 rather than the fleet's usual `1.75`/`1.80` library floor. The
  specific driver that lifted it to 1.85 (a dependency's own MSRV, or a language
  feature used) is not recorded in the commit history: rationale reconstructed
  from the workspace manifest and CI config; the exact reason 1.85 was chosen over
  a lower floor not recovered in available history.
