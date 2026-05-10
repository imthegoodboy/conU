use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--check") => {
            println!("{}", conu_core::scaffold_status("conud"));
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("conud {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("unknown option: {unknown}");
            print_help();
            ExitCode::from(2)
        }
        None => {
            println!("conUD scaffold ready. Local IPC arrives in Phase 4.");
            ExitCode::SUCCESS
        }
    }
}

fn print_help() {
    println!(
        r"conud - conU local runtime daemon scaffold

Usage:
  conud
  conud --check
  conud --help
  conud --version"
    );
}
