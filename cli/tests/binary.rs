//! End-to-end CLI dispatch tests over a real DMG (Humble Object entry point).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use dmg_forensic_cli::dispatch;

const DMG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/data/hfsplus_udro.dmg"
);

fn run(args: &[&str]) -> Result<String, String> {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let mut buf = Vec::new();
    dispatch(&argv, &mut buf)
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
