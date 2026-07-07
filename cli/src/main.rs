//! Thin shell for the `dmg4n6` binary — all logic lives in `dmg_forensic_cli`
//! (Humble Object). Exercised end-to-end by the `binary_*` integration tests.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = dmg_forensic_cli::dispatch(&args, &mut out) {
        eprintln!("{e}");
        std::process::exit(2);
    }
}
