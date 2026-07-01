use std::env;
use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;

const MAX_CLI_STDIN_PAYLOAD_BYTES: u64 = 64 * 1024;
const MAX_CLI_STDIN_RELAY_TOKEN_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StdinReadPlan {
    label: &'static str,
    max_bytes: u64,
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let interactive_menu = should_run_interactive_menu(&args);
    let stdin_payload = if let Some(plan) = stdin_read_plan(&args) {
        match read_bounded_stdin(io::stdin(), plan) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("conU failed to read {}: {error}", plan.label);
                return ExitCode::from(1);
            }
        }
    } else {
        Vec::new()
    };
    let output = if interactive_menu {
        match conu_cli::run_terminal_menu() {
            Ok(output) => output,
            Err(error) => {
                eprintln!("conU menu failed: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        conu_cli::run_with_stdin(args, stdin_payload)
    };

    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }

    ExitCode::from(output.code as u8)
}

fn should_run_interactive_menu(args: &[String]) -> bool {
    let menu_command = args.is_empty() || (args.len() == 1 && args[0] == "menu");
    menu_command && io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn read_bounded_stdin<R: Read>(mut reader: R, plan: StdinReadPlan) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    let limit = plan.max_bytes.saturating_add(1);
    Read::by_ref(&mut reader)
        .take(limit)
        .read_to_end(&mut payload)
        .map_err(|error| error.to_string())?;
    if payload.len() as u64 > plan.max_bytes {
        return Err(format!("input exceeds {} bytes", plan.max_bytes));
    }
    Ok(payload)
}

fn stdin_read_plan(args: &[String]) -> Option<StdinReadPlan> {
    match args {
        [command, subcommand, ..]
            if ((command == "messages" && subcommand == "send")
                || (command == "streams" && subcommand == "write")
                || (command == "rooms" && subcommand == "publish"))
                && args.iter().any(|arg| arg == "--stdin") =>
        {
            Some(StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        }
        [command, subcommand, action, ..]
            if command == "relay" && subcommand == "credential" && action == "set" =>
        {
            args.iter()
                .any(|arg| arg == "--stdin")
                .then_some(StdinReadPlan {
                    label: "relay credential token",
                    max_bytes: MAX_CLI_STDIN_RELAY_TOKEN_BYTES,
                })
        }
        [command, subcommand, action, ..]
            if command == "peers"
                && subcommand == "trust"
                && action != "--help"
                && option_value(args, "--card").as_deref() == Some("-") =>
        {
            Some(StdinReadPlan {
                label: "peer card",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        }
        _ => None,
    }
}

fn option_value(args: &[String], option: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == option).then(|| window[1].clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_payload_is_read_for_message_stream_and_room_writes() {
        assert_eq!(
            stdin_read_plan(&[
                "messages".to_string(),
                "send".to_string(),
                "agent.a".to_string(),
                "agent.b".to_string(),
                "--stdin".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        );
        assert_eq!(
            stdin_read_plan(&[
                "streams".to_string(),
                "write".to_string(),
                "stream_1".to_string(),
                "--stdin".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        );
        assert_eq!(
            stdin_read_plan(&[
                "rooms".to_string(),
                "publish".to_string(),
                "room.dev".to_string(),
                "agent.a".to_string(),
                "build".to_string(),
                "--stdin".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        );
        assert_eq!(
            stdin_read_plan(&[
                "streams".to_string(),
                "open".to_string(),
                "agent.a".to_string(),
                "agent.b".to_string(),
            ]),
            None
        );
    }

    #[test]
    fn relay_credential_set_reads_bounded_stdin_token() {
        assert_eq!(
            stdin_read_plan(&[
                "relay".to_string(),
                "credential".to_string(),
                "set".to_string(),
                "--stdin".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "relay credential token",
                max_bytes: MAX_CLI_STDIN_RELAY_TOKEN_BYTES,
            })
        );
        assert_eq!(
            stdin_read_plan(&[
                "relay".to_string(),
                "credential".to_string(),
                "set".to_string(),
            ]),
            None
        );
        assert_eq!(
            stdin_read_plan(&[
                "relay".to_string(),
                "credential".to_string(),
                "status".to_string(),
                "--stdin".to_string(),
            ]),
            None
        );
    }

    #[test]
    fn peer_card_dash_reads_bounded_stdin() {
        assert_eq!(
            stdin_read_plan(&[
                "peers".to_string(),
                "trust".to_string(),
                "--card".to_string(),
                "-".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "peer card",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        );
        assert_eq!(
            stdin_read_plan(&[
                "peers".to_string(),
                "trust".to_string(),
                "--card".to_string(),
                "peer-card.json".to_string(),
            ]),
            None
        );
    }

    #[test]
    fn interactive_menu_requires_tty_only_menu_invocations() {
        assert!(!should_run_interactive_menu(&["dashboard".to_string()]));
        assert!(!should_run_interactive_menu(&[
            "menu".to_string(),
            "--help".to_string()
        ]));
    }

    #[test]
    fn bounded_stdin_rejects_oversized_payload_without_echoing_contents() {
        let secret_marker = "private-stdin-marker";
        let mut input = Vec::from(secret_marker.as_bytes());
        input.resize((MAX_CLI_STDIN_PAYLOAD_BYTES + 1) as usize, b'a');
        let error = read_bounded_stdin(
            input.as_slice(),
            StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            },
        )
        .expect_err("oversized stdin fails closed");

        assert!(error.contains("input exceeds"));
        assert!(!error.contains(secret_marker));
    }

    #[test]
    fn bounded_stdin_rejects_oversized_relay_token_without_echoing_contents() {
        let secret_marker = "private-relay-token-marker";
        let mut input = Vec::from(secret_marker.as_bytes());
        input.resize((MAX_CLI_STDIN_RELAY_TOKEN_BYTES + 1) as usize, b'a');
        let error = read_bounded_stdin(
            input.as_slice(),
            StdinReadPlan {
                label: "relay credential token",
                max_bytes: MAX_CLI_STDIN_RELAY_TOKEN_BYTES,
            },
        )
        .expect_err("oversized token fails closed");

        assert!(error.contains("input exceeds"));
        assert!(!error.contains(secret_marker));
    }
}
