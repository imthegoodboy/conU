//! CLI rendering and command dispatch for conU.
//!
//! Phase 5 adds conUD runtime detection and metadata-only local agent
//! registration.

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use conu_core::agents::{
    self, AgentPresence, AgentRegistration, LocalAgentRecord, PresenceHeartbeat,
};
use conu_core::runtime::{self, RuntimeState, RuntimeStatus, StopReport};
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
        "connect" => render_connect(&args[1..], home_override),
        "watch" => render_watch(&args[1..]),
        "components" => render_components(&args[1..]),
        "start" => render_start(&args[1..], home_override),
        "stop" => render_stop(&args[1..], home_override),
        "--help" | "-h" | "help" => CliOutput::success(render_help()),
        "--version" | "-V" => CliOutput::success(format!("conu {}", env!("CARGO_PKG_VERSION"))),
        unknown => CliOutput::failure(
            2,
            format!("unknown command: {unknown}\n\n{}", render_help()),
        ),
    }
}

fn render_dashboard(home_override: Option<PathBuf>) -> String {
    let snapshot = state::read_state(home_override.clone()).ok();
    let runtime_status = runtime::read_runtime(home_override.clone()).ok();
    let local_agents = agents::list_local_agents(home_override)
        .map(|agents| agents.len())
        .unwrap_or(0);
    let node = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.node.as_ref())
        .map(|node| node.node_id.as_str())
        .unwrap_or("not initialized");
    let state = snapshot
        .as_ref()
        .map(initialization_label)
        .unwrap_or("unavailable");
    let runtime_state = runtime_status
        .as_ref()
        .map(runtime_state_label)
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
  runtime       {runtime_state}
  node          {node}
  state         {state}
  local agents  {local_agents}
  remote peers  none           pairing arrives in Phase 7
  network       offline        relay arrives in Phase 8

quick commands
  conu init
  conu status
  conu agents
  conu agents register <agent-id> <display-name>
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
    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let runtime_status = match runtime::read_runtime(home_override.clone()) {
        Ok(status) => status,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let local_agents = match agents::list_local_agents(home_override) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_status_json(
            &snapshot,
            &runtime_status,
            &local_agents,
        )),
        Ok(false) => CliOutput::success(render_status_text(
            &snapshot,
            &runtime_status,
            &local_agents,
        )),
        Err(error) => error,
    }
}

fn render_agents(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("register") => render_agent_register(&args[1..], home_override),
        Some("heartbeat") => render_agent_heartbeat(&args[1..], home_override),
        _ => render_agents_list(args, home_override),
    }
}

fn render_agents_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let local_agents = match agents::list_local_agents(home_override) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let registry_state = ready_label(snapshot.agent_registry_exists);

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_agents_json(
            &local_agents,
            registry_state,
            &snapshot.paths.agent_registry.display().to_string(),
        )),
        Ok(false) => CliOutput::success(render_agents_text(
            &local_agents,
            registry_state,
            &snapshot.paths.agent_registry.display().to_string(),
        )),
        Err(error) => error,
    }
}

fn render_agent_register(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_register_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let registration =
        match AgentRegistration::new(&parsed.agent_id, &parsed.display_name, &parsed.kind) {
            Ok(registration) => registration,
            Err(error) => {
                return CliOutput::failure(2, format!("conU agents register failed\n\n{error}"));
            }
        };

    let submission = match agents::submit_registration(home_override.clone(), registration) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU agents register failed\n\n{error}"));
        }
    };
    let processed = wait_for_agent(home_override.clone(), &parsed.agent_id);
    let status = if processed { "registered" } else { "queued" };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "agentId": "{}",
  "requestId": "{}",
  "processed": {},
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.agent_id),
            json_escape(&submission.request_id),
            processed
        ));
    }

    CliOutput::success(format!(
        r"conU agents register

status: {status}
agent: {}
name: {}
kind: {}
request: {}
gateway: file IPC

privacy
  payload view  contents are not displayed by conU",
        parsed.agent_id, parsed.display_name, parsed.kind, submission.request_id
    ))
}

fn render_agent_heartbeat(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_heartbeat_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let heartbeat = match PresenceHeartbeat::new(&parsed.agent_id, parsed.presence) {
        Ok(heartbeat) => heartbeat,
        Err(error) => {
            return CliOutput::failure(2, format!("conU agents heartbeat failed\n\n{error}"));
        }
    };
    let submission = match agents::submit_presence_heartbeat(home_override.clone(), heartbeat) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU agents heartbeat failed\n\n{error}"));
        }
    };
    let processed = wait_for_agent_presence(home_override, &parsed.agent_id, parsed.presence);
    let status = if processed {
        "presence updated"
    } else {
        "queued"
    };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "agentId": "{}",
  "presence": "{}",
  "requestId": "{}",
  "processed": {},
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.agent_id),
            parsed.presence.as_str(),
            json_escape(&submission.request_id),
            processed
        ));
    }

    CliOutput::success(format!(
        r"conU agents heartbeat

status: {status}
agent: {}
presence: {}
request: {}
gateway: file IPC

privacy
  payload view  contents are not displayed by conU",
        parsed.agent_id,
        parsed.presence.as_str(),
        submission.request_id
    ))
}

fn render_agents_json(agents: &[LocalAgentRecord], registry: &str, registry_path: &str) -> String {
    let local_items = agents
        .iter()
        .map(|agent| {
            format!(
                r#"    {{
      "agentId": "{}",
      "displayName": "{}",
      "kind": "{}",
      "presence": "{}",
      "nodeId": "{}",
      "capabilities": {{
        "messages": {},
        "streams": {},
        "rooms": {},
        "files": {},
        "presence": {}
      }}
    }}"#,
                json_escape(&agent.agent_id),
                json_escape(&agent.display_name),
                json_escape(&agent.kind),
                agent.presence.as_str(),
                json_escape(&agent.node_id),
                agent.capabilities.messages,
                agent.capabilities.streams,
                agent.capabilities.rooms,
                agent.capabilities.files,
                agent.capabilities.presence
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let local = if local_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{local_items}\n  ]")
    };

    format!(
        r#"{{
  "local": {},
  "remote": [],
  "registry": "{}",
  "registryPath": "{}",
  "status": "local agent registration active"
}}"#,
        local,
        registry,
        json_escape(registry_path)
    )
}

fn render_agents_text(agents: &[LocalAgentRecord], registry: &str, registry_path: &str) -> String {
    let local = if agents.is_empty() {
        "  none registered yet".to_string()
    } else {
        agents
            .iter()
            .map(|agent| {
                format!(
                    "  {}  {}  {}  kind {}",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.display_name,
                    agent.kind
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU agents

local agents
{local}
  registry      {}
  path          {}

remote agents
  none visible yet

next
  conu agents register <agent-id> <display-name>
  conu agents heartbeat <agent-id>
  Phase 9: remote discovery and presence",
        registry, registry_path
    )
}

struct RegisterArgs {
    agent_id: String,
    display_name: String,
    kind: String,
    json: bool,
}

struct HeartbeatArgs {
    agent_id: String,
    presence: AgentPresence,
    json: bool,
}

fn parse_register_args(args: &[String]) -> Result<RegisterArgs, CliOutput> {
    let mut json = false;
    let mut kind = "local-agent".to_string();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--kind" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(
                        2,
                        "usage: conu agents register <agent-id> <display-name> [--kind <kind>] [--json]",
                    ));
                };
                kind = value.clone();
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => {
                positional.push(value.to_string());
                index += 1;
            }
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(
            2,
            "usage: conu agents register <agent-id> <display-name> [--kind <kind>] [--json]",
        ));
    }

    Ok(RegisterArgs {
        agent_id: positional.remove(0),
        display_name: positional.remove(0),
        kind,
        json,
    })
}

fn parse_heartbeat_args(args: &[String]) -> Result<HeartbeatArgs, CliOutput> {
    let mut json = false;
    let mut presence = AgentPresence::Ready;
    let mut agent_id = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--presence" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(
                        2,
                        "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]",
                    ));
                };
                presence = parse_presence(value)?;
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(
                        2,
                        "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]",
                    ));
                }
                agent_id = Some(value.to_string());
                index += 1;
            }
        }
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(
            2,
            "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]",
        ));
    };

    Ok(HeartbeatArgs {
        agent_id,
        presence,
        json,
    })
}

fn parse_presence(value: &str) -> Result<AgentPresence, CliOutput> {
    match value {
        "ready" => Ok(AgentPresence::Ready),
        "busy" => Ok(AgentPresence::Busy),
        "idle" => Ok(AgentPresence::Idle),
        "offline" => Ok(AgentPresence::Offline),
        _ => Err(CliOutput::failure(
            2,
            "presence must be ready, busy, idle, or offline",
        )),
    }
}

fn wait_for_agent(home_override: Option<PathBuf>, agent_id: &str) -> bool {
    if !runtime_is_live(home_override.clone()) {
        return false;
    }

    for _ in 0..40 {
        if agents::agent_exists(home_override.clone(), agent_id).unwrap_or(false) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }

    false
}

fn wait_for_agent_presence(
    home_override: Option<PathBuf>,
    agent_id: &str,
    presence: AgentPresence,
) -> bool {
    if !runtime_is_live(home_override.clone()) {
        return false;
    }

    for _ in 0..40 {
        if agents::list_local_agents(home_override.clone())
            .map(|agents| {
                agents
                    .iter()
                    .any(|agent| agent.agent_id == agent_id && agent.presence == presence)
            })
            .unwrap_or(false)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }

    false
}

fn runtime_is_live(home_override: Option<PathBuf>) -> bool {
    runtime::read_runtime(home_override)
        .map(|status| status.is_live())
        .unwrap_or(false)
}

fn render_pair(args: &[String]) -> CliOutput {
    match json_flag(args) {
        Ok(true) => CliOutput::success(
            r#"{
  "status": "reserved",
  "phase": "Phase 7",
  "message": "pairing code generation is not active in Phase 5"
}"#,
        ),
        Ok(false) => CliOutput::success(
            r"conU pair

status: reserved for Phase 7
code: not generated in Phase 5
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
  "message": "join validation is not active in Phase 5"
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
action: no trust entry created in Phase 5",
        ),
        Err(error) => error,
    }
}

fn render_connect(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }
    let local_agents = agents::list_local_agents(home_override).unwrap_or_default();
    let local = if local_agents.is_empty() {
        "none registered".to_string()
    } else {
        local_agents
            .iter()
            .map(|agent| {
                format!(
                    "{} ({}, {})",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.kind
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    CliOutput::success(format!(
        r"conU connect

selector
  source local agent   {local}
  target remote agent  none visible
  mode                 message | stream | room | observe

status: waiting for Phase 6 local messaging and Phase 9 remote discovery",
    ))
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

fn render_start(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let current = match runtime::read_runtime(home_override.clone()) {
        Ok(status) => status,
        Err(error) => return CliOutput::failure(1, format!("conU start failed\n\n{error}")),
    };
    if current.is_live() {
        return CliOutput::success(render_start_report(&current, false, json));
    }

    let daemon = resolve_conud_executable();
    let mut command = Command::new(&daemon);
    command
        .arg("--serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(home) = home_override.as_ref() {
        command.env("CONU_HOME", home);
    }

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return CliOutput::failure(
                1,
                format!(
                    "conU start failed\n\ncould not launch conUD at {}: {error}\nset CONUD_EXE to the conud binary path if it is not beside conu",
                    daemon.display()
                ),
            );
        }
    };

    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        match runtime::read_runtime(home_override.clone()) {
            Ok(status) if status.is_live() => {
                return CliOutput::success(render_start_report(&status, true, json));
            }
            Ok(_) => {}
            Err(error) => return CliOutput::failure(1, format!("conU start failed\n\n{error}")),
        }
    }

    CliOutput::failure(
        1,
        format!(
            "conU start launched pid {} but no fresh conUD heartbeat was detected",
            child.id()
        ),
    )
}

fn render_stop(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let report = match runtime::request_runtime_stop(home_override.clone()) {
        Ok(report) => report,
        Err(error) => return CliOutput::failure(1, format!("conU stop failed\n\n{error}")),
    };

    if report.requested {
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(100));
            match runtime::read_runtime(home_override.clone()) {
                Ok(status) if !status.is_live() => {
                    return CliOutput::success(render_stop_report(
                        &StopReport {
                            requested: true,
                            status,
                        },
                        json,
                    ));
                }
                Ok(_) => {}
                Err(error) => return CliOutput::failure(1, format!("conU stop failed\n\n{error}")),
            }
        }
    }

    CliOutput::success(render_stop_report(&report, json))
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
  conu start",
        report.node.node_id,
        report.node.display_name,
        report.paths.home.display(),
        created_label(report.node_created),
        created_label(report.config_created),
        created_label(report.trust_store_created),
        created_label(report.agent_registry_created)
    )
}

fn render_status_text(
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    local_agents: &[LocalAgentRecord],
) -> String {
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
  conUD         {}
  pid           {}
  health        {}
  local IPC     file gateway active
  relay         not available until Phase 8

identity
  state         {}
  node          {}
  name          {}
  state path    {}
  config        {}
  trust store   {}

agents
  local         {} registered
  registry      {}
  remote        0 visible

privacy
  payload view  contents are not displayed by conU",
        runtime_state_label(runtime_status),
        runtime_pid_label(runtime_status),
        runtime_health_label(runtime_status),
        initialization_label(snapshot),
        node,
        display_name,
        snapshot.paths.home.display(),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        local_agents.len(),
        ready_label(snapshot.agent_registry_exists)
    )
}

fn render_status_json(
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    local_agents: &[LocalAgentRecord],
) -> String {
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
    "conud": "{}",
    "pid": {},
    "heartbeatAgeSecs": {},
    "localHealth": "{}",
    "localIpc": "file_gateway",
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
    "local": {},
    "registry": "{}",
    "remote": 0
  }},
  "privacy": {{
    "contentsDisplayed": false
  }}
}}"#,
        runtime_status.state.as_str(),
        json_u32(runtime_status.pid),
        json_u64(runtime_status.heartbeat_age_secs()),
        json_escape(runtime_health_label(runtime_status)),
        initialization_label(snapshot),
        json_escape(node),
        json_escape(display_name),
        json_escape(&snapshot.paths.home.display().to_string()),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        local_agents.len(),
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
  conu agents register <agent-id> <display-name> [--kind <kind>] [--json]
  conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]
  conu peers [--json]
  conu pair [--json]
  conu join <code> [--json]
  conu connect
  conu watch
  conu start [--json]
  conu stop [--json]
  conu components
  conu --help
  conu --version

Phase 5 adds metadata-only local agent registration through the conUD file gateway. Pairing, relay, messaging, and streaming arrive in later phases."
        .to_string()
}

fn render_start_report(status: &RuntimeStatus, launched: bool, json: bool) -> String {
    if json {
        return format!(
            r#"{{
  "status": "{}",
  "launched": {},
  "pid": {},
  "health": "{}",
  "contentsDisplayed": false
}}"#,
            status.state.as_str(),
            launched,
            json_u32(status.pid),
            json_escape(runtime_health_label(status))
        );
    }

    let action = if launched {
        "launched"
    } else {
        "already running"
    };

    format!(
        r"conU start

status: {action}
conUD: {}
pid: {}
health: {}

privacy
  payload view  contents are not displayed by conU",
        runtime_state_label(status),
        runtime_pid_label(status),
        runtime_health_label(status)
    )
}

fn render_stop_report(report: &StopReport, json: bool) -> String {
    if json {
        return format!(
            r#"{{
  "requested": {},
  "status": "{}",
  "pid": {},
  "contentsDisplayed": false
}}"#,
            report.requested,
            report.status.state.as_str(),
            json_u32(report.status.pid)
        );
    }

    let action = if report.requested {
        "stop requested"
    } else {
        "not running"
    };

    format!(
        r"conU stop

status: {action}
conUD: {}
pid: {}

privacy
  payload view  contents are not displayed by conU",
        runtime_state_label(&report.status),
        runtime_pid_label(&report.status)
    )
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

fn runtime_state_label(status: &RuntimeStatus) -> &'static str {
    match status.state {
        RuntimeState::Offline => "offline",
        RuntimeState::Starting => "starting",
        RuntimeState::Running => "running",
        RuntimeState::Stopping => "stopping",
        RuntimeState::Stopped => "stopped",
        RuntimeState::Stale => "stale",
    }
}

fn runtime_health_label(status: &RuntimeStatus) -> &'static str {
    match status.state {
        RuntimeState::Starting | RuntimeState::Running | RuntimeState::Stopping => {
            "file heartbeat ok"
        }
        RuntimeState::Stale => "stale heartbeat",
        RuntimeState::Offline | RuntimeState::Stopped => "offline",
    }
}

fn runtime_pid_label(status: &RuntimeStatus) -> String {
    status
        .pid
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn json_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn resolve_conud_executable() -> PathBuf {
    if let Ok(value) = env::var("CONUD_EXE") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }

    if let Ok(mut path) = env::current_exe() {
        path.set_file_name(format!("conud{}", env::consts::EXE_SUFFIX));
        if path.exists() {
            return path;
        }
    }

    PathBuf::from(format!("conud{}", env::consts::EXE_SUFFIX))
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
    fn phase_five_commands_are_registered() {
        let home = temp_home("commands");

        for command in [
            "init", "status", "agents", "pair", "connect", "watch", "stop",
        ] {
            let output = run_with_home([command], Some(home.clone()));
            assert_eq!(output.code, 0, "{command} failed: {}", output.stderr);
        }

        let join = run(["join", "123456"]);
        assert_eq!(join.code, 0);
    }

    #[test]
    fn agents_register_queues_metadata_request() {
        let home = temp_home("agent-register-queued");

        let output = run_with_home(
            [
                "agents",
                "register",
                "agent.codex",
                "Codex Desktop",
                "--kind",
                "coding-agent",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: queued"));
        assert!(
            output
                .stdout
                .contains("payload view  contents are not displayed")
        );
        assert!(state::StatePaths::from_home(home).ipc_inbox_dir.exists());
    }

    #[test]
    fn agents_list_persisted_local_agent() {
        let home = temp_home("agent-list");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        agents::submit_registration(Some(home.clone()), registration).expect("request submits");
        agents::process_gateway_requests(Some(home.clone())).expect("request processes");

        let output = run_with_home(["agents"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("agent.codex"));
        assert!(output.stdout.contains("Codex Desktop"));
        assert!(output.stdout.contains("ready"));
    }

    #[test]
    fn agents_json_lists_persisted_local_agent() {
        let home = temp_home("agent-json");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        agents::submit_registration(Some(home.clone()), registration).expect("request submits");
        agents::process_gateway_requests(Some(home.clone())).expect("request processes");

        let output = run_with_home(["agents", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"agentId\": \"agent.codex\""));
        assert!(output.stdout.contains("\"displayName\": \"Codex Desktop\""));
    }

    #[test]
    fn agents_heartbeat_queues_presence_request() {
        let home = temp_home("agent-heartbeat");
        let output = run_with_home(
            ["agents", "heartbeat", "agent.codex", "--presence", "busy"],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: queued"));
        assert!(output.stdout.contains("presence: busy"));
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
    fn status_detects_runtime_heartbeat() {
        let home = temp_home("status-runtime");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");

        let status = run_with_home(["status"], Some(home));

        assert_eq!(status.code, 0, "{}", status.stderr);
        assert!(status.stdout.contains("conUD         running"));
        assert!(status.stdout.contains("health        file heartbeat ok"));
    }

    #[test]
    fn start_reports_already_running_without_spawning() {
        let home = temp_home("start-running");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");

        let start = run_with_home(["start"], Some(home));

        assert_eq!(start.code, 0, "{}", start.stderr);
        assert!(start.stdout.contains("status: already running"));
    }

    #[test]
    fn stop_requests_running_runtime() {
        let home = temp_home("stop-running");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");
        let stop_path = state::StatePaths::from_home(home.clone()).runtime_stop_request;

        let stop = run_with_home(["stop"], Some(home));

        assert_eq!(stop.code, 0, "{}", stop.stderr);
        assert!(stop.stdout.contains("status: stop requested"));
        assert!(stop_path.exists());
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
        assert!(output.stdout.contains("\"localIpc\": \"file_gateway\""));
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
