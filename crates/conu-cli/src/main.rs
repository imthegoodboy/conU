use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next();

    match command.as_deref() {
        Some("status") => {
            let json = args.any(|arg| arg == "--json");
            print_status(json);
            ExitCode::SUCCESS
        }
        Some("components") => {
            print_components();
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("conu {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("unknown command: {unknown}");
            print_help();
            ExitCode::from(2)
        }
        None => {
            print_banner();
            ExitCode::SUCCESS
        }
    }
}

fn print_banner() {
    println!(
        r"                 __  __
  ___ ___  _ __ |  \/  |
 / __/ _ \| '_ \| |\/| |
| (_| (_) | | | | |  | |
 \___\___/|_| |_|_|  |_|

agent-native encrypted overlay
{}",
        conu_core::PRODUCT_LAW
    );
}

fn print_status(json: bool) {
    if json {
        println!(
            "{{\n  \"component\": \"conu-cli\",\n  \"status\": \"scaffold_ready\",\n  \"payloadVisibility\": \"opaque\",\n  \"productLaw\": \"{}\"\n}}",
            conu_core::PRODUCT_LAW
        );
    } else {
        println!("{}", conu_core::scaffold_status("conu-cli"));
    }
}

fn print_components() {
    for component in conu_core::COMPONENTS {
        println!("{} - {}", component.name, component.responsibility);
    }
}

fn print_help() {
    println!(
        r"conu - agent-native encrypted communication fabric

Usage:
  conu
  conu status [--json]
  conu components
  conu --help
  conu --version"
    );
}
