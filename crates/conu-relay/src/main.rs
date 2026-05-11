use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--check") => {
            println!("{}", conu_core::scaffold_status("conu-relay"));
            println!("relay: websocket relay ready; ciphertext bodies only; payloads not observed");
            ExitCode::SUCCESS
        }
        Some("--serve") => {
            let addr = args.next().unwrap_or_else(|| "127.0.0.1:8787".to_string());
            let token = env::var("CONU_RELAY_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "local-dev-token".to_string());
            match conu_relay::RelayConfig::new(addr, token).and_then(conu_relay::run_blocking) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("conu-relay {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("unknown option: {unknown}");
            print_help();
            ExitCode::from(2)
        }
        None => {
            println!("conU relay ready. Use `conu-relay --serve 127.0.0.1:8787`.");
            println!("payloads not observed");
            ExitCode::SUCCESS
        }
    }
}

fn print_help() {
    println!(
        r"conu-relay - conU relay and bootstrap scaffold

Usage:
  conu-relay
  conu-relay --serve [addr]
  conu-relay --check
  conu-relay --help
  conu-relay --version

Environment:
  CONU_RELAY_TOKEN   shared runtime session token; defaults to local-dev-token"
    );
}
