//! dmg4n6 CLI logic. Humble Object: every decision lives in testable functions
//! here; `main.rs` is a thin, irreducible shell.
//!
//! Subcommands:
//! - `dmg4n6 info <file>`  — print the decoded virtual disk size.
//! - `dmg4n6 audit <file>` — run the koly-trailer audit and print graded findings.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::Write;

const USAGE: &str = "usage: dmg4n6 <info|audit> <file.dmg>";

/// Errors surfaced by the CLI.
#[derive(Debug)]
pub enum CliError {
    /// Wrong/insufficient arguments; carries the usage text.
    Usage(String),
    /// An I/O error while writing output or opening the image.
    Io(std::io::Error),
    /// The image could not be parsed/read by dmg-core.
    Dmg(dmg::DmgError),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(u) => write!(f, "{u}"),
            CliError::Io(e) => write!(f, "I/O error: {e}"),
            CliError::Dmg(e) => write!(f, "dmg error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<dmg::DmgError> for CliError {
    fn from(e: dmg::DmgError) -> Self {
        CliError::Dmg(e)
    }
}

/// Dispatch a parsed argv to a subcommand, writing output to `out`.
pub fn dispatch(args: &[String], out: &mut dyn Write) -> Result<(), CliError> {
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("info"), Some(path)) => info(path, out),
        (Some("audit"), Some(path)) => audit(path, out),
        _ => Err(CliError::Usage(USAGE.to_string())),
    }
}

/// `info`: decode the image and print its virtual disk size.
fn info(path: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let reader = dmg::DmgReader::open(std::fs::File::open(path)?)?;
    writeln!(
        out,
        "virtual disk size: {} bytes",
        reader.virtual_disk_size()
    )?;
    Ok(())
}

/// `audit`: run the koly-trailer audit and print each finding (or a clean message).
fn audit(path: &str, out: &mut dyn Write) -> Result<(), CliError> {
    let anomalies = dmg_forensic::audit_path(std::path::Path::new(path))?;
    if anomalies.is_empty() {
        writeln!(out, "no anomalies found")?;
        return Ok(());
    }
    for a in &anomalies {
        writeln!(out, "[{:?}] {}: {}", a.severity, a.code, a.note)?;
    }
    Ok(())
}
