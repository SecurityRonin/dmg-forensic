# 6. Optional `vfs` feature: implement `forensic-vfs::ImageSource`

Date: 2026-07-24
Status: Accepted

## Context

The fleet VFS standard (`ronin-issen/CLAUDE.md` → "VFS & Universal Container
Abstraction") composes evidence images through `forensic-vfs`: a decoded
container exposes the positioned-byte `ImageSource` edge so a whole stack (e.g.
`E01 → GPT → BitLocker → NTFS`, or here `DMG → partition map → filesystem`) reads
as one `Arc<dyn ImageSource>` that workers share. For a DMG to participate, its
decoded virtual disk must implement that trait.

But `forensic-vfs` is a heavier dependency than a bare reader needs, and a
third-party consumer of `dmg-core` who only wants a `Read + Seek` virtual disk
should not have to pull it. Support was added in commit `bac4d8d` (with an
`ImageSource` composition RED test in `5f6b6b1`) and the dep bumped to 0.3 in
`95c8399`.

## Decision

1. Implement `forensic-vfs::ImageSource` for the decoded DMG in
   `core/src/vfs.rs`.
2. Gate it behind an **optional, off-by-default `vfs` Cargo feature**
   (`core/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, `forensic-vfs = { version =
   "0.3", optional = true }`).
3. Fleet consumers that compose the DMG into a VFS stack enable `vfs`; a plain
   reader consumer does not, and never sees `forensic-vfs` in its tree.

## Consequences

- `dmg-core` plugs into the fleet's format-agnostic image stack — a consumer asks
  the abstraction to open a path and never special-cases DMG.
- The default build stays lean for third-party reuse (`Read + Seek` only), which
  is the sanctioned exception to batteries-included: the slim path is for outside
  consumers, and every fleet binary that composes the VFS turns the feature on.
- This is the one place the crate departs from "all capability compiled in": the
  `vfs` integration is an optional dependency, deliberately, because it is a fleet-
  composition concern rather than a decode capability.
