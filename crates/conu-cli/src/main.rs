use std::env;
use std::io::{self, IsTerminal, Read, Write};
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
    let interactive_connect = should_run_interactive_connect(&args);
    let interactive_chat = should_run_interactive_chat(&args);
    let stdin_payload = if interactive_chat {
        Vec::new()
    } else if let Some(plan) = stdin_read_plan(&args) {
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
    } else if interactive_connect {
        match conu_cli::run_connect_terminal_selector() {
            Ok(output) => output,
            Err(error) => {
                eprintln!("conU connect selector failed: {error}");
                return ExitCode::from(1);
            }
        }
    } else if interactive_chat {
        match run_interactive_chat(&args) {
            Ok(output) => output,
            Err(error) => {
                eprintln!("conU chat failed: {error}");
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
    is_interactive_menu_invocation(args) && io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn should_run_interactive_connect(args: &[String]) -> bool {
    is_interactive_connect_invocation(args)
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
}

fn should_run_interactive_chat(args: &[String]) -> bool {
    is_interactive_chat_invocation(args) && io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn is_interactive_menu_invocation(args: &[String]) -> bool {
    args.is_empty() || (args.len() == 1 && args[0] == "menu")
}

fn is_interactive_connect_invocation(args: &[String]) -> bool {
    args.len() == 1 && args[0] == "connect"
}

fn is_interactive_chat_invocation(args: &[String]) -> bool {
    matches!(args, [command] if command == "chat")
        || matches!(args, [command, from, to]
            if command == "chat" && !from.trim().is_empty() && !to.trim().is_empty())
}

fn run_interactive_chat(args: &[String]) -> Result<conu_cli::CliOutput, String> {
    println!("conU chat");
    println!("one private agent message");
    println!();

    let (from, to, peer) = if args.len() == 3 {
        println!("from agent: {}", args[1]);
        println!("to agent: {}", args[2]);
        (args[1].clone(), args[2].clone(), None)
    } else {
        (
            prompt_required("from agent: ")?,
            prompt_required("to agent: ")?,
            prompt_optional("peer node (optional, Enter for local): ")?,
        )
    };
    let message = prompt_message("message: ")?;

    let mut args = vec!["chat".to_string(), from, to];
    if let Some(peer) = peer {
        args.push("--peer".to_string());
        args.push(peer);
    }
    args.push("--stdin".to_string());

    Ok(conu_cli::run_with_stdin(args, message))
}

fn prompt_required(prompt: &str) -> Result<String, String> {
    let value = prompt_line(prompt)?;
    let value = value.trim();
    if value.is_empty() {
        return Err("required field was empty; contentsDisplayed=false".to_string());
    }
    Ok(value.to_string())
}

fn prompt_optional(prompt: &str) -> Result<Option<String>, String> {
    let value = prompt_line(prompt)?;
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

fn prompt_message(prompt: &str) -> Result<Vec<u8>, String> {
    let value = prompt_line(prompt)?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err("message was empty; contentsDisplayed=false".to_string());
    }
    if value.len() as u64 > MAX_CLI_STDIN_PAYLOAD_BYTES {
        return Err(format!(
            "message exceeds {} bytes; contentsDisplayed=false",
            MAX_CLI_STDIN_PAYLOAD_BYTES
        ));
    }
    Ok(value.as_bytes().to_vec())
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| error.to_string())?;
    Ok(value)
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
        [command, ..]
            if matches!(command.as_str(), "send" | "chat" | "reply")
                && args.iter().any(|arg| arg == "--stdin") =>
        {
            Some(StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        }
        [command, subcommand, ..]
            if ((command == "messages" && matches!(subcommand.as_str(), "send" | "reply"))
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
        [command, subcommand, ..] if command == "relay" && subcommand == "setup" => args
            .iter()
            .any(|arg| arg == "--token-stdin")
            .then_some(StdinReadPlan {
                label: "relay credential token",
                max_bytes: MAX_CLI_STDIN_RELAY_TOKEN_BYTES,
            }),
        [command, ..] if command == "online" => args
            .iter()
            .any(|arg| arg == "--token-stdin")
            .then_some(StdinReadPlan {
                label: "relay credential token",
                max_bytes: MAX_CLI_STDIN_RELAY_TOKEN_BYTES,
            }),
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
                "chat".to_string(),
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
                "reply".to_string(),
                "agent.b".to_string(),
                "env_1".to_string(),
                "--stdin".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "stdin payload",
                max_bytes: MAX_CLI_STDIN_PAYLOAD_BYTES,
            })
        );
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
                "messages".to_string(),
                "reply".to_string(),
                "agent.b".to_string(),
                "env_1".to_string(),
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
                "setup".to_string(),
                "wss://relay.example.com/conu".to_string(),
                "--token-stdin".to_string(),
            ]),
            Some(StdinReadPlan {
                label: "relay credential token",
                max_bytes: MAX_CLI_STDIN_RELAY_TOKEN_BYTES,
            })
        );
        assert_eq!(
            stdin_read_plan(&[
                "online".to_string(),
                "wss://relay.example.com/conu".to_string(),
                "--token-stdin".to_string(),
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
                "setup".to_string(),
                "wss://relay.example.com/conu".to_string(),
            ]),
            None
        );
        assert_eq!(
            stdin_read_plan(&[
                "online".to_string(),
                "wss://relay.example.com/conu".to_string(),
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
        assert!(is_interactive_menu_invocation(&[]));
        assert!(is_interactive_menu_invocation(&["menu".to_string()]));
        assert!(!is_interactive_menu_invocation(&[
            "menu".to_string(),
            "--help".to_string()
        ]));
        assert!(!is_interactive_menu_invocation(&["dashboard".to_string()]));

        assert!(!should_run_interactive_menu(&["dashboard".to_string()]));
        assert!(!should_run_interactive_menu(&[
            "menu".to_string(),
            "--help".to_string()
        ]));
    }

    #[test]
    fn interactive_connect_requires_plain_connect_invocation() {
        assert!(is_interactive_connect_invocation(&["connect".to_string()]));
        assert!(!is_interactive_connect_invocation(&[]));
        assert!(!is_interactive_connect_invocation(&[
            "connect".to_string(),
            "--help".to_string()
        ]));
        assert!(!is_interactive_connect_invocation(&[
            "connect".to_string(),
            "local".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string()
        ]));

        assert!(!should_run_interactive_connect(&[]));
        assert!(!should_run_interactive_connect(&[
            "connect".to_string(),
            "--help".to_string()
        ]));
        assert!(!should_run_interactive_connect(&[
            "connect".to_string(),
            "local".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string()
        ]));
    }

    #[test]
    fn interactive_chat_requires_plain_chat_invocation() {
        assert!(is_interactive_chat_invocation(&["chat".to_string()]));
        assert!(is_interactive_chat_invocation(&[
            "chat".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
        ]));
        assert!(!is_interactive_chat_invocation(&[]));
        assert!(!is_interactive_chat_invocation(&[
            "chat".to_string(),
            "--help".to_string()
        ]));
        assert!(!is_interactive_chat_invocation(&[
            "chat".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
            "--peer".to_string(),
            "node.remote".to_string(),
        ]));
        assert!(!is_interactive_chat_invocation(&[
            "chat".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
            "--stdin".to_string()
        ]));

        assert!(!should_run_interactive_chat(&[]));
        assert!(!should_run_interactive_chat(&[
            "chat".to_string(),
            "--help".to_string()
        ]));
        assert!(!should_run_interactive_chat(&[
            "chat".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
            "--peer".to_string(),
            "node.remote".to_string(),
        ]));
        assert!(!should_run_interactive_chat(&[
            "chat".to_string(),
            "agent.a".to_string(),
            "agent.b".to_string(),
            "--stdin".to_string()
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
