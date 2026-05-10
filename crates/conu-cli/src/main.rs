use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let output = conu_cli::run(env::args().skip(1));

    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }

    ExitCode::from(output.code as u8)
}
