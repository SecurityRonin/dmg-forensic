//! End-to-end CLI dispatch tests over a real DMG (Humble Object entry point).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use dmg_forensic_cli::dispatch;

const DMG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/data/hfsplus_udro.dmg"
);

fn run(cmd: &[&str]) -> Result<String, String> {
    let owned: Vec<String> = cmd.iter().map(|s| (*s).to_string()).collect();
    let mut buf = Vec::new();
    dispatch(&owned, &mut buf)
        .map_err(|e| e.to_string())
        .map(|()| String::from_utf8(buf).unwrap())
}

#[test]
fn info_prints_the_virtual_disk_size() {
    let out = run(&["dmg4n6", "info", DMG]).expect("info ok");
    assert!(out.contains("virtual disk size"), "{out}");
}

#[test]
fn audit_reports_a_clean_real_dmg() {
    let out = run(&["dmg4n6", "audit", DMG]).expect("audit ok");
    assert!(out.contains("no anomalies"), "{out}");
}

#[test]
fn no_args_is_a_usage_error() {
    assert!(run(&["dmg4n6"]).is_err());
}

#[test]
fn audit_prints_findings_for_a_tampered_koly() {
    // A 512-byte all-zero file has a bad koly signature -> audit surfaces it,
    // exercising the finding-printing path.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[0u8; 512]).unwrap();
    let path = f.path().to_str().unwrap();
    let out = run(&["dmg4n6", "audit", path]).expect("audit ok");
    assert!(out.contains("DMG-KOLY-SIGNATURE-INVALID"), "{out}");
}

#[test]
fn info_on_a_missing_file_is_an_io_error() {
    let err = run(&["dmg4n6", "info", "/no/such/image.dmg"]).unwrap_err();
    assert!(err.contains("I/O error"), "{err}");
}

/// A sink that fails every write — to exercise the write-error propagation path.
struct FailWriter;

impl Write for FailWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("boom"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_write_error_is_propagated_not_swallowed() {
    let owned: Vec<String> = ["dmg4n6", "info", DMG]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut w = FailWriter;
    assert!(dispatch(&owned, &mut w).is_err());
}

#[test]
fn info_on_a_non_dmg_file_is_a_dmg_error() {
    // A tiny text file is not a valid DMG -> dmg-core rejects it (Dmg error path).
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"not a dmg").unwrap();
    let path = f.path().to_str().unwrap();
    let err = run(&["dmg4n6", "info", path]).unwrap_err();
    assert!(err.contains("dmg error"), "{err}");
}
