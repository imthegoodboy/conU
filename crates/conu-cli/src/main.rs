use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let stdin_payload = if needs_stdin_payload(&args) {
        let mut payload = Vec::new();
        if let Err(error) = io::stdin().read_to_end(&mut payload) {
            eprintln!("conU failed to read stdin payload: {error}");
            return ExitCode::from(1);
        }
        payload
    } else {
        Vec::new()
    };
    let output = conu_cli::run_with_stdin(args, stdin_payload);

    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }

    ExitCode::from(output.code as u8)
}

fn needs_stdin_payload(args: &[String]) -> bool {
    matches!(
        args,
        [command, subcommand, ..]
            if command == "messages"
                && subcommand == "send"
                && args.iter().any(|arg| arg == "--stdin")
    )
}
