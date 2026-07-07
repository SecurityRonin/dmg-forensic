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
    // RED stub.
    let _ = (args, out);
    Err(CliError::Usage(USAGE.to_string()))
}
