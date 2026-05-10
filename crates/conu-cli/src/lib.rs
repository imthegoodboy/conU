//! CLI rendering and command dispatch for conU.
//!
//! Phase 2 builds the user-facing command shell only. Commands that need real
//! identity, daemon, IPC, relay, or persistence are represented as honest
//! previews and point to their owning future phase.

/// A rendered CLI command result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutput {
    fn success(stdout: impl Into<String>) -> Self {
        Self {
            code: 0,
            stdout: finish(stdout.into()),
            stderr: String::new(),
        }
    }

    fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            code,
            stdout: String::new(),
            stderr: finish(stderr.into()),
        }
    }
}

/// Dispatch a conU CLI invocation.
pub fn run<I, S>(args: I) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return CliOutput::success(render_dashboard());
    };

    match command {
        "init" => render_init(&args[1..]),
        "status" => render_status(&args[1..]),
        "agents" | "peers" => render_agents(&args[1..]),
        "pair" => render_pair(&args[1..]),
        "join" => render_join(&args[1..]),
        "connect" => render_connect(&args[1..]),
        "watch" => render_watch(&args[1..]),
        "components" => render_components(&args[1..]),
        "start" => render_reserved_phase("start", "Phase 4", "conUD daemon lifecycle"),
        "--help" | "-h" | "help" => CliOutput::success(render_help()),
        "--version" | "-V" => CliOutput::success(format!("conu {}", env!("CARGO_PKG_VERSION"))),
        unknown => CliOutput::failure(
            2,
            format!("unknown command: {unknown}\n\n{}", render_help()),
        ),
    }
}

fn render_dashboard() -> String {
    format!(
        r"                 __  __
  ___ ___  _ __ |  \/  |
 / __/ _ \| '_ \| |\/| |
| (_| (_) | | | | |  | |
 \___\___/|_| |_|_|  |_|

agent-native encrypted overlay
{}

control room
  runtime       offline        conUD starts in Phase 4
  node          not initialized identity arrives in Phase 3
  local agents  none           registration arrives in Phase 5
  remote peers  none           pairing arrives in Phase 7
  network       offline        relay arrives in Phase 8

quick commands
  conu init
  conu status
  conu agents
  conu pair
  conu join <code>
  conu connect
  conu watch",
        conu_core::PRODUCT_LAW
    )
}

fn render_init(args: &[String]) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    CliOutput::success(
        r"conU init

status: ready for Phase 3
action: no files written in Phase 2
next: Phase 3 will create the local node identity and trust store",
    )
}

fn render_status(args: &[String]) -> CliOutput {
    match json_flag(args) {
        Ok(true) => CliOutput::success(render_status_json()),
        Ok(false) => CliOutput::success(
            r"conU status

runtime
  conUD         offline
  local IPC     not available until Phase 4
  relay         not available until Phase 8

identity
  node          not initialized
  trust store   not initialized

agents
  local         0 registered
  remote        0 visible

privacy
  payload view  contents are not displayed by conU",
        ),
        Err(error) => error,
    }
}

fn render_agents(args: &[String]) -> CliOutput {
    match json_flag(args) {
        Ok(true) => CliOutput::success(
            r#"{
  "local": [],
  "remote": [],
  "status": "agent registration arrives in Phase 5"
}"#,
        ),
        Ok(false) => CliOutput::success(
            r"conU agents

local agents
  none registered yet

remote agents
  none visible yet

next
  Phase 5: local agent registration
  Phase 9: remote discovery and presence",
        ),
        Err(error) => error,
    }
}

fn render_pair(args: &[String]) -> CliOutput {
    match json_flag(args) {
        Ok(true) => CliOutput::success(
            r#"{
  "status": "reserved",
  "phase": "Phase 7",
  "message": "pairing code generation is not active in Phase 2"
}"#,
        ),
        Ok(false) => CliOutput::success(
            r"conU pair

status: reserved for Phase 7
code: not generated in Phase 2
purpose: create trust between two conUD runtimes",
        ),
        Err(error) => error,
    }
}

fn render_join(args: &[String]) -> CliOutput {
    if args.iter().any(|arg| arg == "--json") {
        return match join_code(args) {
            Ok(_) => CliOutput::success(
                r#"{
  "status": "reserved",
  "phase": "Phase 7",
  "message": "join validation is not active in Phase 2"
}"#,
            ),
            Err(error) => error,
        };
    }

    match join_code(args) {
        Ok(_) => CliOutput::success(
            r"conU join

status: reserved for Phase 7
code: accepted for command shape only
action: no trust entry created in Phase 2",
        ),
        Err(error) => error,
    }
}

fn render_connect(args: &[String]) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    CliOutput::success(
        r"conU connect

selector
  source local agent   none registered
  target remote agent  none visible
  mode                 message | stream | room | observe

status: waiting for Phase 5 local agents and Phase 9 remote discovery",
    )
}

fn render_watch(args: &[String]) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    CliOutput::success(
        r"conU watch

transport view
  local-agent   -> conUD -> encrypted route -> remote conUD -> remote-agent
  route         inactive
  latency       n/a
  streams       0
  packets       0
  contents      not displayed

status: live stream animation arrives in Phase 10",
    )
}

fn render_components(args: &[String]) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    let mut output = String::from("conU components\n\n");
    for component in conu_core::COMPONENTS {
        output.push_str(component.name);
        output.push_str("\n  ");
        output.push_str(component.responsibility);
        output.push('\n');
    }
    CliOutput::success(output)
}

fn render_reserved_phase(command: &str, phase: &str, owner: &str) -> CliOutput {
    CliOutput::success(format!(
        "conU {command}\n\nstatus: reserved for {phase}\nowner: {owner}"
    ))
}

fn render_status_json() -> String {
    r#"{
  "runtime": {
    "conud": "offline",
    "localIpc": "phase_4",
    "relay": "phase_8"
  },
  "identity": {
    "node": "not_initialized",
    "trustStore": "not_initialized"
  },
  "agents": {
    "local": 0,
    "remote": 0
  },
  "privacy": {
    "contentsDisplayed": false
  }
}"#
    .to_string()
}

fn render_help() -> String {
    r"conu - agent-native encrypted communication fabric

Usage:
  conu
  conu init
  conu status [--json]
  conu agents [--json]
  conu peers [--json]
  conu pair [--json]
  conu join <code> [--json]
  conu connect
  conu watch
  conu components
  conu --help
  conu --version

Phase 2 builds the CLI control room. Runtime identity, IPC, pairing, relay, and streaming arrive in later phases."
        .to_string()
}

fn json_flag(args: &[String]) -> Result<bool, CliOutput> {
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            return Err(CliOutput::failure(2, format!("unknown option: {arg}")));
        }
    }
    Ok(json)
}

fn join_code(args: &[String]) -> Result<&str, CliOutput> {
    let mut code = None;
    for arg in args {
        if arg == "--json" {
            continue;
        }
        if code.is_some() {
            return Err(CliOutput::failure(2, "usage: conu join <code> [--json]"));
        }
        code = Some(arg.as_str());
    }

    match code {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(CliOutput::failure(2, "usage: conu join <code> [--json]")),
    }
}

fn reject_args(args: &[String]) -> Option<CliOutput> {
    args.first()
        .map(|arg| CliOutput::failure(2, format!("unexpected argument: {arg}")))
}

fn finish(mut output: String) -> String {
    while output.ends_with('\n') {
        output.pop();
    }
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_renders_control_room() {
        let output = run(Vec::<String>::new());

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("control room"));
        assert!(output.stdout.contains("conu init"));
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn phase_two_commands_are_registered() {
        for command in ["init", "status", "agents", "pair", "connect", "watch"] {
            let output = run([command]);
            assert_eq!(output.code, 0, "{command} failed: {}", output.stderr);
        }

        let join = run(["join", "123456"]);
        assert_eq!(join.code, 0);
    }

    #[test]
    fn status_json_is_machine_readable_shape() {
        let output = run(["status", "--json"]);

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("\"conud\": \"offline\""));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
    }

    #[test]
    fn join_requires_a_code() {
        let output = run(["join"]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("usage: conu join <code>"));
    }

    #[test]
    fn watch_never_prints_message_contents() {
        let output = run(["watch"]);

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("contents      not displayed"));
        assert!(!output.stdout.contains("Review this code"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn unknown_command_fails_with_help() {
        let output = run(["unknown"]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("unknown command"));
        assert!(output.stderr.contains("Usage:"));
    }
}
