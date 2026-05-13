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
            if ((command == "messages" && subcommand == "send")
                || (command == "streams" && subcommand == "write")
                || (command == "rooms" && subcommand == "publish"))
                && args.iter().any(|arg| arg == "--stdin")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_payload_is_read_for_message_stream_and_room_writes() {
        assert!(needs_stdin_payload(&[
            "messages".to_string(),
            "send".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
            "--stdin".to_string(),
        ]));
        assert!(needs_stdin_payload(&[
            "streams".to_string(),
            "write".to_string(),
            "stream_1".to_string(),
            "--stdin".to_string(),
        ]));
        assert!(needs_stdin_payload(&[
            "rooms".to_string(),
            "publish".to_string(),
            "room.dev".to_string(),
            "agent.a".to_string(),
            "build".to_string(),
            "--stdin".to_string(),
        ]));
        assert!(!needs_stdin_payload(&[
            "streams".to_string(),
            "open".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
        ]));
    }
}
