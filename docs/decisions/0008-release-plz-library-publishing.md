# 8. release-plz PR-based library publishing (and the tag-collision guard)

Date: 2026-07-24
Status: Accepted

## Context

This repo publishes **library crates** (`dmg-core`, `dmg-forensic`) to crates.io;
its only binary (`dmg4n6`) is `publish = false`. The fleet release standard
(`ronin-issen/CLAUDE.md` → "Library crate publishing — release-plz") is binding:
library crates release via release-plz (a PR that computes SemVer bumps from
conventional-commit types and, on merge, publishes), **not** a hand-cut version
bump and **not** the tag-driven `release.yml` binary pipeline. The merge of the
release PR is the one reviewable checkpoint before an irreversible crates.io
publish.

Adopted in commit `4bb3696` ("chore(release): adopt release-plz for library
publishing (fleet standard)"), with the tag-name guard in `0f6dc42`.

## Decision

1. Add `release-plz.yml` (two jobs on push to `main`: open/update the release PR,
   and publish crates whose manifest version is ahead of crates.io) and
   `release-plz.toml`.
2. Set **`git_tag_name = "dmg-core-vX.Y.Z"` form** so release-plz's per-crate tags
   never collide with the bare `v[0-9]*` tags a binary release pipeline uses
   (commit `0f6dc42` — "set git_tag_name to dmg-core-vX.Y.Z form (avoid v* binary-
   tag collision)"). This is the release-plz-side half of the fleet's dual guard;
   there is no `v[0-9]*` binary `release.yml` here because the CLI is unpublished.
3. Bootstrap `cargo-vet` with the aggregate audit imports (commit `6e43faa`) so
   the supply-chain-review gate is a real, low-maintenance check.

## Consequences

- Versions bump from commit *types* (`feat`→minor, `fix`→patch, breaking→major);
  a `docs`/`chore`/`test`-only change rides along without cutting a release.
- The release PR yields a changelog for free and a last look before publish; the
  crates.io token is provisioned once as an org secret, run by the automation.
- Each library crate versions independently (the workspace `version` is shared for
  DRY, but release-plz can still cut per-crate tags under the prefixed name).
- The reader/analyzer split (ADR 0001) is what makes independent library
  publishing meaningful: two crates, two release cadences, one PR checkpoint.
