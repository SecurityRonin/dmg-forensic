//! Auditor tests: a real Apple-made DMG audits clean; crafted koly tampering is
//! surfaced. Real DMG fixtures live in the reader member's tests/data.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::Path;

use dmg_forensic::{audit, audit_path, audit_reader, audit_trailer, Anomaly, AnomalyKind};
use forensicnomicon::report::Observation;

/// Build a well-formed koly trailer with the given fork/XML pointers.
fn koly(df_off: u64, df_len: u64, xml_off: u64, xml_len: u64) -> Vec<u8> {
    let mut t = vec![0u8; 512];
    t[0..4].copy_from_slice(&0x6b6f_6c79u32.to_be_bytes()); // 'koly'
    t[4..8].copy_from_slice(&4u32.to_be_bytes()); // version 4
    t[8..12].copy_from_slice(&512u32.to_be_bytes()); // header size
    t[0x18..0x20].copy_from_slice(&df_off.to_be_bytes());
    t[0x20..0x28].copy_from_slice(&df_len.to_be_bytes());
    t[0xd8..0xe0].copy_from_slice(&xml_off.to_be_bytes());
    t[0xe0..0xe8].copy_from_slice(&xml_len.to_be_bytes());
    t
}

#[test]
fn a_well_formed_koly_within_bounds_is_clean() {
    // fork [0,1000) + xml [1000,1200) inside a 1_000_000-byte file.
    let t = koly(0, 1000, 1000, 200);
    assert!(audit_trailer(&t, 1_000_000).is_empty());
}

#[test]
fn a_bad_signature_is_flagged() {
    let mut t = koly(0, 1000, 1000, 200);
    t[0] = 0x00; // corrupt the 'k'
    let found: Vec<_> = audit_trailer(&t, 1_000_000)
        .into_iter()
        .map(|a| a.code)
        .collect();
    assert!(found.contains(&"DMG-KOLY-SIGNATURE-INVALID"), "{found:?}");
}

#[test]
fn an_unexpected_version_is_flagged() {
    let mut t = koly(0, 1000, 1000, 200);
    t[4..8].copy_from_slice(&7u32.to_be_bytes());
    let found: Vec<_> = audit_trailer(&t, 1_000_000)
        .into_iter()
        .map(|a| a.code)
        .collect();
    assert!(found.contains(&"DMG-KOLY-VERSION-UNEXPECTED"), "{found:?}");
}

#[test]
fn out_of_bounds_datafork_and_xml_are_flagged() {
    // both pointers run past a tiny 2000-byte file.
    let t = koly(0, 5000, 9000, 200);
    let codes: Vec<_> = audit_trailer(&t, 2000)
        .into_iter()
        .map(|a| a.code)
        .collect();
    assert!(
        codes.contains(&"DMG-KOLY-DATAFORK-OUT-OF-BOUNDS"),
        "{codes:?}"
    );
    assert!(codes.contains(&"DMG-KOLY-XML-OUT-OF-BOUNDS"), "{codes:?}");
}

#[test]
fn too_small_a_file_is_flagged() {
    let codes: Vec<_> = audit(&[0u8; 100]).into_iter().map(|a| a.code).collect();
    assert_eq!(codes, vec!["DMG-KOLY-TRAILER-TOO-SMALL"]);
}

#[test]
fn a_real_apple_made_dmg_audits_clean() {
    // Real hdiutil-made UDRO DMG (independent oracle: Apple's own tooling built it).
    let dmg = include_bytes!("../../core/tests/data/hfsplus_udro.dmg");
    let anomalies = audit(dmg);
    assert!(
        anomalies.is_empty(),
        "a real DMG should be clean, got: {anomalies:?}"
    );
}

#[test]
fn audit_trailer_rejects_a_short_slice() {
    // The public core entry point handles a sub-512-byte slice without panicking.
    let codes: Vec<_> = audit_trailer(&[0u8; 10], 10)
        .into_iter()
        .map(|a| a.code)
        .collect();
    assert_eq!(codes, vec!["DMG-KOLY-TRAILER-TOO-SMALL"]);
}

#[test]
fn every_kind_exposes_a_complete_observation() {
    let kinds = [
        AnomalyKind::TrailerTooSmall { len: 1 },
        AnomalyKind::SignatureInvalid { found: 0 },
        AnomalyKind::VersionUnexpected { version: 7 },
        AnomalyKind::DataForkOutOfBounds {
            offset: 1,
            length: 2,
            file_len: 0,
        },
        AnomalyKind::XmlOutOfBounds {
            offset: 1,
            length: 2,
            file_len: 0,
        },
    ];
    for kind in kinds {
        let anomaly = Anomaly::new(kind);
        let observation: &dyn Observation = &anomaly;
        assert!(observation.severity().is_some());
        assert!(!observation.code().is_empty());
        assert!(!observation.note().is_empty());
        assert!(!observation.evidence().is_empty());
        // category() varies by kind; just exercise the arm.
        let _ = observation.category();
    }
}

#[test]
fn audit_reader_and_path_are_consistent() {
    // A synthetic image (2000 zero bytes + a koly with out-of-bounds pointers).
    let mut image = vec![0u8; 2000];
    image.extend_from_slice(&koly(0, 5000, 9000, 200));
    let via_reader = audit_reader(Cursor::new(&image)).unwrap();
    assert!(via_reader
        .iter()
        .any(|a| a.code == "DMG-KOLY-DATAFORK-OUT-OF-BOUNDS"));

    // A reader shorter than the trailer is flagged too-small (not a panic/error).
    let small = audit_reader(Cursor::new(vec![0u8; 10])).unwrap();
    assert_eq!(small.len(), 1);
    assert_eq!(small[0].code, "DMG-KOLY-TRAILER-TOO-SMALL");

    // The real DMG audits clean through the by-path entry point as well.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../core/tests/data/hfsplus_udro.dmg"
    );
    assert!(audit_path(Path::new(path)).unwrap().is_empty());
}
