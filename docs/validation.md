# Validation

Correctness is established against independent oracles and real-world artifacts,
not fixtures we both encoded and graded ourselves. Each claim is labelled by
**tier** — the trustworthiness of the check:

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data validated by an independent oracle.
- **Tier 2** — real engine/tool output confirmed by an independent oracle, but we
  chose the scenario, so it can miss real-world quirks.
- **Tier 3** — fixture and expected answer both authored here; legitimate only
  where no external oracle exists (detection rules defined by spec, robustness
  properties), never as the sole check of a value-producing path.

The UDIF container and its `koly` trailer are a reverse-engineered Apple format;
`dmg-core`'s block codecs and the trailer layout are cross-checked against
`hdiutil`, Apple's own tooling. Provenance and hashes for every committed fixture
are in `core/tests/data/README.md`.

## Reader codec decode — tier 1 / tier 2

`dmg-core` decodes each UDIF block codec against a real `hdiutil`-made DMG, with
`hdiutil` (a different codebase) as the independent oracle: ADC, zlib (UDZO),
bzip2 (UDBZ), LZFSE (ULFO), and LZMA (ULMO). A byte-match between the pure-Rust
decoder and `hdiutil`'s output is genuine cross-tool agreement. Tests:
`core/tests/real_images.rs`.

## Analyzer koly audit — specificity (tier 1/2) + sensitivity (tier 3)

`dmg-forensic` parses the koly trailer and grades:

| Code | Meaning |
|------|---------|
| `DMG-KOLY-SIGNATURE-INVALID` | trailer signature is not `koly` (not UDIF, or overwritten) |
| `DMG-KOLY-VERSION-UNEXPECTED` | version field is not the documented 4 |
| `DMG-KOLY-DATAFORK-OUT-OF-BOUNDS` | data-fork offset+length runs past the file end |
| `DMG-KOLY-XML-OUT-OF-BOUNDS` | XML block-table offset+length runs past the file end |
| `DMG-KOLY-TRAILER-TOO-SMALL` | file is smaller than a 512-byte koly trailer |

- **Specificity (tier 1/2):** a real `hdiutil`-made DMG audits **clean** — zero
  anomalies (`a_real_apple_made_dmg_audits_clean`). The real artifact is the
  independent oracle for "a well-formed DMG produces no false positives".
- **Sensitivity (tier 3, by nature):** the out-of-bounds and bad-signature rules
  detect deliberate corruption/tampering that does not occur in benign DMGs, so
  there is no third-party known-answer artifact. Correctness is defined by the
  rule plus the koly layout; the crafted trailers in `forensic/tests/audit.rs`
  specify behavior. Each finding carries the offending value + field as evidence
  ("consistent with", never a verdict).

## Robustness

The koly trailer is read through bounds-checked integer readers that yield 0 out
of range rather than panic; every offset/length pointer is range-checked against
the file length before use; and a large image is never read whole — `audit_reader`
seeks to the tail and reads only the 512-byte trailer.
