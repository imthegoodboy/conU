//! CLI rendering and command dispatch for conU.
//!
//! Phase 3 adds local persistent identity and state while keeping daemon, IPC,
//! relay, and messaging features as honest previews.

use std::path::PathBuf;

use conu_core::state::{self, InitReport, StateSnapshot};

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
    run_with_home(args, None)
}

/// Dispatch a conU CLI invocation with an explicit state home.
///
/// This is mostly used by tests and smoke checks so they do not touch a real
/// user profile.
pub fn run_with_home<I, S>(args: I, home_override: Option<PathBuf>) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return CliOutput::success(render_dashboard(home_override));
    };

    match command {
        "init" => render_init(&args[1..], home_override),
        "status" => render_status(&args[1..], home_override),
        "agents" | "peers" => render_agents(&args[1..], home_override),
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

fn render_dashboard(home_override: Option<PathBuf>) -> String {
    let snapshot = state::read_state(home_override).ok();
    let node = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.node.as_ref())
        .map(|node| node.node_id.as_str())
        .unwrap_or("not initialized");
    let state = snapshot
        .as_ref()
        .map(initialization_label)
        .unwrap_or("unavailable");

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
  node          {node}
  state         {state}
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

fn render_init(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    match state::init_state(home_override) {
        Ok(report) => CliOutput::success(render_init_report(&report)),
        Err(error) => CliOutput::failure(1, format!("conU init failed\n\n{error}")),
    }
}

fn render_status(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let snapshot = match state::read_state(home_override) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_status_json(&snapshot)),
        Ok(false) => CliOutput::success(render_status_text(&snapshot)),
        Err(error) => error,
    }
}

fn render_agents(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let snapshot = match state::read_state(home_override) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let registry_state = ready_label(snapshot.agent_registry_exists);

    match json_flag(args) {
        Ok(true) => CliOutput::success(format!(
            r#"{{
  "local": [],
  "remote": [],
  "registry": "{}",
  "registryPath": "{}",
  "status": "agent registration arrives in Phase 5"
}}"#,
            registry_state,
            json_escape(&snapshot.paths.agent_registry.display().to_string())
        )),
        Ok(false) => CliOutput::success(format!(
            r"conU agents

local agents
  none registered yet
  registry      {}
  path          {}

remote agents
  none visible yet

next
  Phase 5: local agent registration
  Phase 9: remote discovery and presence",
            registry_state,
            snapshot.paths.agent_registry.display()
        )),
        Err(error) => error,
    }
}

fn render_pair(args: &[String]) -> CliOutput {
    match json_flag(args) {
        Ok(true) => CliOutput::success(
            r#"{
  "status": "reserved",
  "phase": "Phase 7",
  "message": "pairing code generation is not active in Phase 3"
}"#,
        ),
        Ok(false) => CliOutput::success(
            r"conU pair

status: reserved for Phase 7
code: not generated in Phase 3
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
  "message": "join validation is not active in Phase 3"
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
action: no trust entry created in Phase 3",
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

fn render_init_report(report: &InitReport) -> String {
    let repaired =
        report.config_created || report.trust_store_created || report.agent_registry_created;
    let status = if report.node_created {
        "created"
    } else if repaired {
        "repaired"
    } else {
        "already initialized"
    };

    format!(
        r"conU init

status: {status}
node: {}
name: {}
state path: {}

files
  node identity  {}
  config         {}
  trust store    {}
  agent registry {}

next
  conu status
  conu start     reserved for Phase 4",
        report.node.node_id,
        report.node.display_name,
        report.paths.home.display(),
        created_label(report.node_created),
        created_label(report.config_created),
        created_label(report.trust_store_created),
        created_label(report.agent_registry_created)
    )
}

fn render_status_text(snapshot: &StateSnapshot) -> String {
    let node = snapshot
        .node
        .as_ref()
        .map(|node| node.node_id.as_str())
        .unwrap_or("not initialized");
    let display_name = snapshot
        .node
        .as_ref()
        .map(|node| node.display_name.as_str())
        .unwrap_or("not initialized");

    format!(
        r"conU status

runtime
  conUD         offline
  local IPC     not available until Phase 4
  relay         not available until Phase 8

identity
  state         {}
  node          {}
  name          {}
  state path    {}
  config        {}
  trust store   {}

agents
  local         0 registered
  registry      {}
  remote        0 visible

privacy
  payload view  contents are not displayed by conU",
        initialization_label(snapshot),
        node,
        display_name,
        snapshot.paths.home.display(),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        ready_label(snapshot.agent_registry_exists)
    )
}

fn render_status_json(snapshot: &StateSnapshot) -> String {
    let node = snapshot
        .node
        .as_ref()
        .map(|node| node.node_id.as_str())
        .unwrap_or("not_initialized");
    let display_name = snapshot
        .node
        .as_ref()
        .map(|node| node.display_name.as_str())
        .unwrap_or("not_initialized");

    format!(
        r#"{{
  "runtime": {{
    "conud": "offline",
    "localIpc": "phase_4",
    "relay": "phase_8"
  }},
  "identity": {{
    "state": "{}",
    "node": "{}",
    "displayName": "{}",
    "statePath": "{}",
    "config": "{}",
    "trustStore": "{}"
  }},
  "agents": {{
    "local": 0,
    "registry": "{}",
    "remote": 0
  }},
  "privacy": {{
    "contentsDisplayed": false
  }}
}}"#,
        initialization_label(snapshot),
        json_escape(node),
        json_escape(display_name),
        json_escape(&snapshot.paths.home.display().to_string()),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        ready_label(snapshot.agent_registry_exists)
    )
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

Phase 3 adds local identity and persistent state. Daemon IPC, pairing, relay, and streaming arrive in later phases."
        .to_string()
}

fn initialization_label(snapshot: &StateSnapshot) -> &'static str {
    if snapshot.is_initialized() {
        "initialized"
    } else {
        "not_initialized"
    }
}

fn ready_label(is_ready: bool) -> &'static str {
    if is_ready { "ready" } else { "not_initialized" }
}

fn created_label(created: bool) -> &'static str {
    if created { "created" } else { "kept" }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            value if value.is_control() => escaped.push_str(&format!("\\u{:04x}", value as u32)),
            value => escaped.push(value),
        }
    }

    escaped
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
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn dashboard_renders_control_room() {
        let output = run_with_home(Vec::<String>::new(), Some(temp_home("dashboard")));

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("control room"));
        assert!(output.stdout.contains("conu init"));
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn phase_three_commands_are_registered() {
        let home = temp_home("commands");

        for command in ["init", "status", "agents", "pair", "connect", "watch"] {
            let output = run_with_home([command], Some(home.clone()));
            assert_eq!(output.code, 0, "{command} failed: {}", output.stderr);
        }

        let join = run(["join", "123456"]);
        assert_eq!(join.code, 0);
    }

    #[test]
    fn init_creates_state_and_status_reads_it() {
        let home = temp_home("init-status");

        let init = run_with_home(["init"], Some(home.clone()));
        let status = run_with_home(["status"], Some(home));

        assert_eq!(init.code, 0, "{}", init.stderr);
        assert!(init.stdout.contains("status: created"));
        assert!(init.stdout.contains("node_"));
        assert_eq!(status.code, 0, "{}", status.stderr);
        assert!(status.stdout.contains("state         initialized"));
        assert!(status.stdout.contains("trust store   ready"));
    }

    #[test]
    fn init_is_idempotent() {
        let home = temp_home("init-idempotent");

        let first = run_with_home(["init"], Some(home.clone()));
        let second = run_with_home(["init"], Some(home));

        assert_eq!(first.code, 0, "{}", first.stderr);
        assert_eq!(second.code, 0, "{}", second.stderr);
        assert!(first.stdout.contains("status: created"));
        assert!(second.stdout.contains("status: already initialized"));
        assert!(second.stdout.contains("node identity  kept"));
    }

    #[test]
    fn status_json_is_machine_readable_shape() {
        let home = temp_home("status-json");
        let init = run_with_home(["init"], Some(home.clone()));
        assert_eq!(init.code, 0, "{}", init.stderr);

        let output = run_with_home(["status", "--json"], Some(home));

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("\"conud\": \"offline\""));
        assert!(output.stdout.contains("\"state\": \"initialized\""));
        assert!(output.stdout.contains("\"node\": \"node_"));
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

    fn temp_home(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        std::env::temp_dir().join(format!("conu-cli-test-{label}-{}-{nonce}", process::id()))
    }
}
