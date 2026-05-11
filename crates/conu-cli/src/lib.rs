//! CLI rendering and command dispatch for conU.
//!
//! Phase 13 adds conUD runtime detection, metadata-only local/remote agent
//! visibility, encrypted-at-rest local opaque envelopes, remote session
//! mirrors, stream/watch metadata, route selection, and security audit output.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use conu_core::agents::{
    self, AgentPresence, AgentRegistration, LocalAgentRecord, PresenceHeartbeat,
};
use conu_core::messages::{self, DeliveryReceipt, InboxEntry, LocalMessage};
use conu_core::routes::{self, RouteProbe, RouteRecord, RouteSyncReport, RouteTransport};
use conu_core::runtime::{self, RuntimeState, RuntimeStatus, StopReport};
use conu_core::security::{self, SecurityAudit, SecurityReport};
use conu_core::sessions::{self, RemoteAgentRecord, RemoteSession, SessionSyncReport};
use conu_core::state::{self, InitReport, StateSnapshot};
use conu_core::streams::{self, StreamEvent, StreamRecord};
use conu_core::trust::{self, TrustStatus, TrustedPeer};
use conu_protocol::OpaquePayload;

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
    run_with_home_and_stdin(args, None, Vec::new())
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
    run_with_home_and_stdin(args, home_override, Vec::new())
}

/// Dispatch a conU CLI invocation with explicit stdin bytes.
pub fn run_with_stdin<I, S>(args: I, stdin_payload: Vec<u8>) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    run_with_home_and_stdin(args, None, stdin_payload)
}

/// Dispatch a conU CLI invocation with explicit state and stdin bytes.
pub fn run_with_home_and_stdin<I, S>(
    args: I,
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput
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
        "agents" => render_agents(&args[1..], home_override),
        "peers" => render_peers(&args[1..], home_override),
        "messages" => render_messages(&args[1..], home_override, stdin_payload),
        "streams" => render_streams(&args[1..], home_override, stdin_payload),
        "sessions" => render_sessions(&args[1..], home_override),
        "routes" => render_routes(&args[1..], home_override),
        "security" => render_security(&args[1..], home_override),
        "pair" => render_pair(&args[1..], home_override),
        "join" => render_join(&args[1..], home_override),
        "connect" => render_connect(&args[1..], home_override),
        "watch" => render_watch(&args[1..], home_override),
        "doctor" => render_doctor(&args[1..], home_override),
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
    let local_agents = agents::list_local_agents(home_override.clone())
        .map(|agents| agents.len())
        .unwrap_or(0);
    let trusted_peers = trust::list_peers(home_override.clone())
        .map(|peers| {
            peers
                .iter()
                .filter(|peer| peer.status == TrustStatus::Trusted)
                .count()
        })
        .unwrap_or(0);
    let route_records = routes::list_routes(home_override.clone()).unwrap_or_default();
    let remote_agents = sessions::list_remote_agents(home_override)
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
  remote agents {remote_agents}
  remote peers  {trusted_peers} trusted
  routes        direct {} relay {}
  network       direct when available, relay fallback

quick commands
  conu init
  conu status
  conu agents
  conu agents register <agent-id> <display-name>
  conu messages send <from-agent> <to-agent> --stdin
  conu streams open <from-agent> <to-agent>
  conu routes sync
  conu security audit
  conu doctor
  conu pair
  conu peers
  conu join <code>
  conu connect
  conu watch",
        conu_core::PRODUCT_LAW,
        selected_direct_route_count(&route_records),
        selected_relay_route_count(&route_records)
    )
}

fn render_init(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    match state::init_state(home_override) {
        Ok(report) => match security::ensure_security_state_from_paths(&report.paths) {
            Ok(security) => CliOutput::success(render_init_report(&report, &security)),
            Err(error) => CliOutput::failure(1, format!("conU init failed\n\n{error}")),
        },
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
    let local_agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let peers = match trust::list_peers(home_override.clone()) {
        Ok(peers) => peers,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let sessions = match sessions::list_remote_sessions(home_override.clone()) {
        Ok(sessions) => sessions,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let remote_agents = match sessions::list_remote_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let stream_records = match streams::list_streams(home_override.clone()) {
        Ok(streams) => streams,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let route_records = match routes::list_routes(home_override.clone()) {
        Ok(routes) => routes,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let security_audit =
        security::security_audit(home_override).unwrap_or_else(|_| empty_security_audit());

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_status_json(
            &snapshot,
            &runtime_status,
            &local_agents,
            &remote_agents,
            &sessions,
            &stream_records,
            &route_records,
            &peers,
            &security_audit,
        )),
        Ok(false) => CliOutput::success(render_status_text(
            &snapshot,
            &runtime_status,
            &local_agents,
            &remote_agents,
            &sessions,
            &stream_records,
            &route_records,
            &peers,
            &security_audit,
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
    let local_agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let remote_agents = match sessions::list_remote_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let registry_state = ready_label(snapshot.agent_registry_exists);

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_agents_json(
            &local_agents,
            &remote_agents,
            registry_state,
            &snapshot.paths.agent_registry.display().to_string(),
        )),
        Ok(false) => CliOutput::success(render_agents_text(
            &local_agents,
            &remote_agents,
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

fn render_agents_json(
    agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    registry: &str,
    registry_path: &str,
) -> String {
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
    let remote_items = remote_agents
        .iter()
        .map(|agent| {
            format!(
                r#"    {{
      "agentId": "{}",
      "displayName": "{}",
      "kind": "{}",
      "presence": "{}",
      "nodeId": "{}",
      "peerNodeId": "{}",
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
                json_escape(&agent.peer_node_id),
                agent.capabilities.messages,
                agent.capabilities.streams,
                agent.capabilities.rooms,
                agent.capabilities.files,
                agent.capabilities.presence
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let remote = if remote_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{remote_items}\n  ]")
    };

    format!(
        r#"{{
  "local": {},
  "remote": {},
  "registry": "{}",
  "registryPath": "{}",
  "status": "agent registry active"
}}"#,
        local,
        remote,
        registry,
        json_escape(registry_path)
    )
}

fn render_agents_text(
    agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    registry: &str,
    registry_path: &str,
) -> String {
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
    let remote = if remote_agents.is_empty() {
        "  none visible yet".to_string()
    } else {
        remote_agents
            .iter()
            .map(|agent| {
                format!(
                    "  {}  {}  {}  peer {}",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.display_name,
                    agent.peer_node_id
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
{remote}

next
  conu agents register <agent-id> <display-name>
  conu agents heartbeat <agent-id>
  conu sessions sync",
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

fn render_messages(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("send") => render_message_send(&args[1..], home_override, stdin_payload),
        Some("inbox") => render_message_inbox(&args[1..], home_override),
        Some("receipts") => render_message_receipts(&args[1..], home_override),
        _ => CliOutput::failure(2, render_messages_usage()),
    }
}

fn render_message_send(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_message_send_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.stdin {
        return CliOutput::failure(2, render_messages_usage());
    }
    if stdin_payload.is_empty() {
        return CliOutput::failure(2, "stdin payload is empty");
    }

    let before = inbox_ids(home_override.clone(), &parsed.to_agent_id);
    let payload_bytes = stdin_payload.len();
    let message = match LocalMessage::new(
        &parsed.from_agent_id,
        &parsed.to_agent_id,
        OpaquePayload::from_bytes(stdin_payload),
    ) {
        Ok(message) => message,
        Err(error) => {
            return CliOutput::failure(2, format!("conU messages send failed\n\n{error}"));
        }
    };
    let submission = match messages::submit_local_message(home_override.clone(), message) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages send failed\n\n{error}"));
        }
    };
    let delivered = wait_for_message_delivery(
        home_override,
        &parsed.to_agent_id,
        before,
        submission.payload_bytes,
    );
    let status = if delivered.is_some() {
        "delivered"
    } else {
        "queued"
    };

    if parsed.json {
        let envelope_id = delivered
            .as_ref()
            .map(|entry| json_string(&entry.envelope_id))
            .unwrap_or_else(|| "null".to_string());
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "requestId": "{}",
  "envelopeId": {},
  "payloadBytes": {},
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.from_agent_id),
            json_escape(&parsed.to_agent_id),
            json_escape(&submission.request_id),
            envelope_id,
            payload_bytes
        ));
    }

    let envelope_line = delivered
        .as_ref()
        .map(|entry| format!("envelope: {}", entry.envelope_id))
        .unwrap_or_else(|| "envelope: pending".to_string());

    CliOutput::success(format!(
        r"conU messages send

status: {status}
from: {}
to: {}
request: {}
{envelope_line}
bytes: {}

privacy
  payload view  contents are not displayed by conU",
        parsed.from_agent_id, parsed.to_agent_id, submission.request_id, payload_bytes
    ))
}

fn render_message_inbox(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_message_inbox_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let entries = match messages::list_agent_inbox(home_override, &parsed.agent_id) {
        Ok(entries) => entries,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages inbox failed\n\n{error}"));
        }
    };

    if parsed.json {
        return CliOutput::success(render_inbox_json(&parsed.agent_id, &entries));
    }

    CliOutput::success(render_inbox_text(&parsed.agent_id, &entries))
}

fn render_message_receipts(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let receipts = match messages::list_receipts(home_override) {
        Ok(receipts) => receipts,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages receipts failed\n\n{error}"));
        }
    };

    if json {
        return CliOutput::success(render_receipts_json(&receipts));
    }

    CliOutput::success(render_receipts_text(&receipts))
}

fn render_inbox_json(agent_id: &str, entries: &[InboxEntry]) -> String {
    let messages = entries
        .iter()
        .map(|entry| {
            format!(
                r#"    {{
      "envelopeId": "{}",
      "fromAgentId": "{}",
      "toAgentId": "{}",
      "receiptId": "{}",
      "payloadBytes": {},
      "deliveredAtUnix": {}
    }}"#,
                json_escape(&entry.envelope_id),
                json_escape(&entry.from_agent_id),
                json_escape(&entry.to_agent_id),
                json_escape(&entry.receipt_id),
                entry.payload_bytes,
                entry.delivered_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let messages = if messages.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{messages}\n  ]")
    };

    format!(
        r#"{{
  "agentId": "{}",
  "messages": {},
  "contentsDisplayed": false
}}"#,
        json_escape(agent_id),
        messages
    )
}

fn render_inbox_text(agent_id: &str, entries: &[InboxEntry]) -> String {
    let messages = if entries.is_empty() {
        "  none delivered yet".to_string()
    } else {
        entries
            .iter()
            .map(|entry| {
                format!(
                    "  {}  from {}  bytes {}  receipt {}",
                    entry.envelope_id, entry.from_agent_id, entry.payload_bytes, entry.receipt_id
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU messages inbox

agent: {agent_id}
messages
{messages}

privacy
  payload view  contents are not displayed by conU"
    )
}

fn render_receipts_json(receipts: &[DeliveryReceipt]) -> String {
    let receipts = receipts
        .iter()
        .map(|receipt| {
            format!(
                r#"    {{
      "receiptId": "{}",
      "envelopeId": "{}",
      "fromAgentId": "{}",
      "toAgentId": "{}",
      "status": "{}",
      "payloadBytes": {},
      "deliveredAtUnix": {}
    }}"#,
                json_escape(&receipt.receipt_id),
                json_escape(&receipt.envelope_id),
                json_escape(&receipt.from_agent_id),
                json_escape(&receipt.to_agent_id),
                json_escape(&receipt.status),
                receipt.payload_bytes,
                receipt.delivered_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let receipts = if receipts.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{receipts}\n  ]")
    };

    format!(
        r#"{{
  "receipts": {},
  "contentsDisplayed": false
}}"#,
        receipts
    )
}

fn render_receipts_text(receipts: &[DeliveryReceipt]) -> String {
    let receipts = if receipts.is_empty() {
        "  none recorded yet".to_string()
    } else {
        receipts
            .iter()
            .map(|receipt| {
                format!(
                    "  {}  {}  {} -> {}  bytes {}",
                    receipt.receipt_id,
                    receipt.status,
                    receipt.from_agent_id,
                    receipt.to_agent_id,
                    receipt.payload_bytes
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU messages receipts

receipts
{receipts}

privacy
  payload view  contents are not displayed by conU"
    )
}

struct MessageSendArgs {
    from_agent_id: String,
    to_agent_id: String,
    stdin: bool,
    json: bool,
}

struct MessageInboxArgs {
    agent_id: String,
    json: bool,
}

fn parse_message_send_args(args: &[String]) -> Result<MessageSendArgs, CliOutput> {
    let mut json = false;
    let mut stdin = false;
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--stdin" => stdin = true,
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => positional.push(value.to_string()),
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }

    Ok(MessageSendArgs {
        from_agent_id: positional.remove(0),
        to_agent_id: positional.remove(0),
        stdin,
        json,
    })
}

fn parse_message_inbox_args(args: &[String]) -> Result<MessageInboxArgs, CliOutput> {
    let mut json = false;
    let mut agent_id = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                }
                agent_id = Some(value.to_string());
            }
        }
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(2, render_messages_usage()));
    };

    Ok(MessageInboxArgs { agent_id, json })
}

fn render_messages_usage() -> String {
    r"usage:
  conu messages send <from-agent> <to-agent> --stdin [--json]
  conu messages inbox <agent-id> [--json]
  conu messages receipts [--json]"
        .to_string()
}

fn render_streams(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("open") => render_stream_open(&args[1..], home_override),
        Some("write") => render_stream_write(&args[1..], home_override, stdin_payload),
        Some("close") => render_stream_close(&args[1..], home_override),
        _ => render_streams_list(args, home_override),
    }
}

fn render_stream_open(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_stream_open_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    match streams::open_stream(
        home_override,
        &parsed.from_agent_id,
        &parsed.to_agent_id,
        &parsed.kind,
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_stream_json(&report.stream, "opened"))
            } else {
                CliOutput::success(render_stream_open_text(&report.stream))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU streams open failed\n\n{error}")),
    }
}

fn render_stream_write(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_stream_io_args(args, "write") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.stdin {
        return CliOutput::failure(2, "usage: conu streams write <stream-id> --stdin [--json]");
    }
    if stdin_payload.is_empty() {
        return CliOutput::failure(2, "stdin payload is empty");
    }

    match streams::write_stream(
        home_override,
        &parsed.stream_id,
        OpaquePayload::from_bytes(stdin_payload),
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_stream_event_json(&report.stream, &report.event))
            } else {
                CliOutput::success(render_stream_write_text(&report.stream, &report.event))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU streams write failed\n\n{error}")),
    }
}

fn render_stream_close(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_stream_io_args(args, "close") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    match streams::close_stream(home_override, &parsed.stream_id) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_stream_event_json(&report.stream, &report.event))
            } else {
                CliOutput::success(render_stream_close_text(&report.stream))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU streams close failed\n\n{error}")),
    }
}

fn render_streams_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let streams = match streams::list_streams(home_override) {
        Ok(streams) => streams,
        Err(error) => return CliOutput::failure(1, format!("conU streams failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_streams_json(&streams)),
        Ok(false) => CliOutput::success(render_streams_text(&streams)),
        Err(error) => error,
    }
}

fn render_streams_json(streams: &[StreamRecord]) -> String {
    let items = streams
        .iter()
        .map(|stream| {
            format!(
                r#"    {{
      "streamId": "{}",
      "fromAgentId": "{}",
      "toAgentId": "{}",
      "kind": "{}",
      "state": "{}",
      "route": "{}",
      "chunksWritten": {},
      "bytesWritten": {},
      "backpressureWindow": {}
    }}"#,
                json_escape(&stream.stream_id),
                json_escape(&stream.from_agent_id),
                json_escape(&stream.to_agent_id),
                json_escape(&stream.kind),
                stream.state.as_str(),
                json_escape(&stream.route),
                stream.chunks_written,
                stream.bytes_written,
                stream.backpressure_window
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let streams_json = if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{items}\n  ]")
    };

    format!(
        r#"{{
  "streams": {},
  "contentsDisplayed": false
}}"#,
        streams_json
    )
}

fn render_streams_text(streams: &[StreamRecord]) -> String {
    let lines = if streams.is_empty() {
        "  none opened yet".to_string()
    } else {
        streams
            .iter()
            .map(|stream| {
                format!(
                    "  {}  {} -> {}  {}  chunks {}  bytes {}",
                    stream.stream_id,
                    stream.from_agent_id,
                    stream.to_agent_id,
                    stream.state.as_str(),
                    stream.chunks_written,
                    stream.bytes_written
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU streams

streams
{lines}

privacy
  payload view  contents are not displayed by conU

next
  conu streams open <from-agent> <to-agent>"
    )
}

fn render_stream_open_text(stream: &StreamRecord) -> String {
    format!(
        r"conU streams open

status: opened
stream: {}
from: {}
to: {}
kind: {}
route: {}
backpressure window: {}

privacy
  payload view  contents are not displayed by conU",
        stream.stream_id,
        stream.from_agent_id,
        stream.to_agent_id,
        stream.kind,
        stream.route,
        stream.backpressure_window
    )
}

fn render_stream_write_text(stream: &StreamRecord, event: &StreamEvent) -> String {
    format!(
        r"conU streams write

status: chunk recorded
stream: {}
bytes: {}
chunks: {}
total bytes: {}

privacy
  payload view  contents are not displayed by conU",
        stream.stream_id, event.payload_bytes, stream.chunks_written, stream.bytes_written
    )
}

fn render_stream_close_text(stream: &StreamRecord) -> String {
    format!(
        r"conU streams close

status: closed
stream: {}
chunks: {}
bytes: {}

privacy
  payload view  contents are not displayed by conU",
        stream.stream_id, stream.chunks_written, stream.bytes_written
    )
}

fn render_stream_json(stream: &StreamRecord, status: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "streamId": "{}",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "kind": "{}",
  "state": "{}",
  "route": "{}",
  "chunksWritten": {},
  "bytesWritten": {},
  "backpressureWindow": {},
  "contentsDisplayed": false
}}"#,
        status,
        json_escape(&stream.stream_id),
        json_escape(&stream.from_agent_id),
        json_escape(&stream.to_agent_id),
        json_escape(&stream.kind),
        stream.state.as_str(),
        json_escape(&stream.route),
        stream.chunks_written,
        stream.bytes_written,
        stream.backpressure_window
    )
}

fn render_stream_event_json(stream: &StreamRecord, event: &StreamEvent) -> String {
    format!(
        r#"{{
  "status": "{}",
  "streamId": "{}",
  "eventId": "{}",
  "payloadBytes": {},
  "chunksWritten": {},
  "bytesWritten": {},
  "contentsDisplayed": false
}}"#,
        json_escape(&event.event_type),
        json_escape(&stream.stream_id),
        json_escape(&event.event_id),
        event.payload_bytes,
        stream.chunks_written,
        stream.bytes_written
    )
}

struct StreamOpenArgs {
    from_agent_id: String,
    to_agent_id: String,
    kind: String,
    json: bool,
}

struct StreamIoArgs {
    stream_id: String,
    stdin: bool,
    json: bool,
}

fn parse_stream_open_args(args: &[String]) -> Result<StreamOpenArgs, CliOutput> {
    let mut json = false;
    let mut kind = "message".to_string();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--kind" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_streams_usage()));
                };
                kind = value.clone();
            }
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_streams_usage()));
    }

    Ok(StreamOpenArgs {
        from_agent_id: positional[0].clone(),
        to_agent_id: positional[1].clone(),
        kind,
        json,
    })
}

fn parse_stream_io_args(args: &[String], command: &'static str) -> Result<StreamIoArgs, CliOutput> {
    let mut json = false;
    let mut stdin = false;
    let mut stream_id = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--stdin" => stdin = true,
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => {
                if stream_id.is_some() {
                    return Err(CliOutput::failure(2, render_streams_usage()));
                }
                stream_id = Some(value.to_string());
            }
        }
    }

    let Some(stream_id) = stream_id else {
        return Err(CliOutput::failure(
            2,
            format!("usage: conu streams {command} <stream-id> [--stdin] [--json]"),
        ));
    };

    Ok(StreamIoArgs {
        stream_id,
        stdin,
        json,
    })
}

fn render_streams_usage() -> String {
    r"usage:
  conu streams [--json]
  conu streams open <from-agent> <to-agent> [--kind <kind>] [--json]
  conu streams write <stream-id> --stdin [--json]
  conu streams close <stream-id> [--json]"
        .to_string()
}

fn render_sessions(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("sync") => render_sessions_sync(&args[1..], home_override),
        _ => render_sessions_list(args, home_override),
    }
}

fn render_sessions_sync(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match json_flag(args) {
        Ok(json) => match sessions::sync_remote_sessions(home_override) {
            Ok(report) => {
                if json {
                    CliOutput::success(render_sessions_report_json(&report))
                } else {
                    CliOutput::success(render_sessions_report_text(&report))
                }
            }
            Err(error) => CliOutput::failure(1, format!("conU sessions sync failed\n\n{error}")),
        },
        Err(error) => error,
    }
}

fn render_sessions_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let remote_sessions = match sessions::list_remote_sessions(home_override.clone()) {
        Ok(sessions) => sessions,
        Err(error) => return CliOutput::failure(1, format!("conU sessions failed\n\n{error}")),
    };
    let remote_agents = match sessions::list_remote_agents(home_override) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU sessions failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_sessions_json(&remote_sessions, &remote_agents)),
        Ok(false) => CliOutput::success(render_sessions_text(&remote_sessions, &remote_agents)),
        Err(error) => error,
    }
}

fn render_sessions_json(
    remote_sessions: &[RemoteSession],
    remote_agents: &[RemoteAgentRecord],
) -> String {
    let session_items = remote_sessions
        .iter()
        .map(|session| {
            format!(
                r#"    {{
      "peerNodeId": "{}",
      "displayName": "{}",
      "state": "{}",
      "route": "{}",
      "relayEndpoint": "{}",
      "reconnectAttempts": {},
      "remoteAgentCount": {}
    }}"#,
                json_escape(&session.peer_node_id),
                json_escape(&session.display_name),
                session.state.as_str(),
                json_escape(&session.route),
                json_escape(&session.relay_endpoint),
                session.reconnect_attempts,
                session.remote_agent_count
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let sessions_json = if session_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{session_items}\n  ]")
    };

    format!(
        r#"{{
  "sessions": {},
  "remoteAgents": {},
  "contentsDisplayed": false
}}"#,
        sessions_json,
        remote_agents.len()
    )
}

fn render_sessions_text(
    remote_sessions: &[RemoteSession],
    remote_agents: &[RemoteAgentRecord],
) -> String {
    let sessions_text = if remote_sessions.is_empty() {
        "  none synced yet".to_string()
    } else {
        remote_sessions
            .iter()
            .map(|session| {
                format!(
                    "  {}  {}  route {}  agents {}",
                    session.peer_node_id,
                    session.state.as_str(),
                    session.route,
                    session.remote_agent_count
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU sessions

remote sessions
{sessions_text}

remote agents
  visible       {}

privacy
  payload view  contents are not displayed by conU

next
  conu sessions sync",
        remote_agents.len()
    )
}

fn render_sessions_report_json(report: &SessionSyncReport) -> String {
    format!(
        r#"{{
  "status": "synced",
  "sessionsSynced": {},
  "remoteAgentsSynced": {},
  "connected": {},
  "reconnecting": {},
  "offline": {},
  "contentsDisplayed": false
}}"#,
        report.sessions_synced,
        report.remote_agents_synced,
        report.connected,
        report.reconnecting,
        report.offline
    )
}

fn render_sessions_report_text(report: &SessionSyncReport) -> String {
    format!(
        r"conU sessions sync

status: synced
sessions: {}
remote agents: {}
connected: {}
reconnecting: {}
offline: {}

privacy
  payload view  contents are not displayed by conU",
        report.sessions_synced,
        report.remote_agents_synced,
        report.connected,
        report.reconnecting,
        report.offline
    )
}

fn render_routes(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("sync") => render_routes_sync(&args[1..], home_override),
        Some("probes") => render_route_probes(&args[1..], home_override),
        None | Some("--json") => render_routes_list(args, home_override),
        Some(_) => CliOutput::failure(2, render_routes_usage()),
    }
}

fn render_routes_sync(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    match routes::sync_routes(home_override) {
        Ok(report) => {
            if json {
                CliOutput::success(render_routes_report_json(&report))
            } else {
                CliOutput::success(render_routes_report_text(&report))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU routes sync failed\n\n{error}")),
    }
}

fn render_routes_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let route_records = match routes::list_routes(home_override) {
        Ok(routes) => routes,
        Err(error) => return CliOutput::failure(1, format!("conU routes failed\n\n{error}")),
    };

    if json {
        CliOutput::success(render_routes_json(&route_records))
    } else {
        CliOutput::success(render_routes_text(&route_records))
    }
}

fn render_route_probes(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let probes = match routes::list_route_probes(home_override) {
        Ok(probes) => probes,
        Err(error) => {
            return CliOutput::failure(1, format!("conU routes probes failed\n\n{error}"));
        }
    };

    if json {
        CliOutput::success(render_route_probes_json(&probes))
    } else {
        CliOutput::success(render_route_probes_text(&probes))
    }
}

fn render_routes_json(route_records: &[RouteRecord]) -> String {
    let route_items = route_records
        .iter()
        .map(|route| {
            format!(
                r#"    {{
      "routeId": "{}",
      "peerNodeId": "{}",
      "displayName": "{}",
      "transport": "{}",
      "endpoint": "{}",
      "state": "{}",
      "score": {},
      "latencyMs": {},
      "directAttempted": {},
      "relayFallback": {},
      "natProfile": "{}",
      "failureReason": {},
      "updatedAtUnix": {}
    }}"#,
                json_escape(&route.route_id),
                json_escape(&route.peer_node_id),
                json_escape(&route.display_name),
                route.transport.as_str(),
                json_escape(&route.endpoint),
                route.state.as_str(),
                route.score,
                json_u64(route.latency_ms),
                route.direct_attempted,
                route.relay_fallback,
                route.nat_profile.as_str(),
                json_optional_string(route.failure_reason.as_deref()),
                route.updated_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let routes_json = if route_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{route_items}\n  ]")
    };

    format!(
        r#"{{
  "routes": {},
  "selectedDirect": {},
  "selectedRelay": {},
  "relayFallbacks": {},
  "contentsDisplayed": false
}}"#,
        routes_json,
        selected_direct_route_count(route_records),
        selected_relay_route_count(route_records),
        relay_fallback_route_count(route_records)
    )
}

fn render_routes_text(route_records: &[RouteRecord]) -> String {
    let selected_text = route_records
        .iter()
        .filter(|route| route.is_selected())
        .map(render_route_line)
        .collect::<Vec<_>>()
        .join("\n");
    let selected_text = if selected_text.is_empty() {
        "  none selected yet".to_string()
    } else {
        selected_text
    };

    let candidates_text = route_records
        .iter()
        .filter(|route| !route.is_selected())
        .map(render_route_line)
        .collect::<Vec<_>>()
        .join("\n");
    let candidates_text = if candidates_text.is_empty() {
        "  none recorded yet".to_string()
    } else {
        candidates_text
    };

    format!(
        r"conU routes

selected
{selected_text}

candidates
{candidates_text}

summary
  selected direct  {}
  selected relay   {}
  relay fallbacks  {}

privacy
  payload view     contents are not displayed by conU

next
  conu routes sync",
        selected_direct_route_count(route_records),
        selected_relay_route_count(route_records),
        relay_fallback_route_count(route_records)
    )
}

fn render_route_line(route: &RouteRecord) -> String {
    let latency = route
        .latency_ms
        .map(|latency| format!("{latency}ms"))
        .unwrap_or_else(|| "n/a".to_string());
    let state = if route.relay_fallback {
        "fallback"
    } else {
        route.state.as_str()
    };

    format!(
        "  {}  {}  {}  score {}  latency {}  endpoint {}",
        route.peer_node_id,
        route.transport.as_str(),
        state,
        route.score,
        latency,
        route.endpoint
    )
}

fn render_route_probes_json(probes: &[RouteProbe]) -> String {
    let probe_items = probes
        .iter()
        .map(|probe| {
            format!(
                r#"    {{
      "probeId": "{}",
      "routeId": "{}",
      "peerNodeId": "{}",
      "transport": "{}",
      "endpoint": "{}",
      "outcome": "{}",
      "score": {},
      "latencyMs": {},
      "createdAtUnix": {}
    }}"#,
                json_escape(&probe.probe_id),
                json_escape(&probe.route_id),
                json_escape(&probe.peer_node_id),
                probe.transport.as_str(),
                json_escape(&probe.endpoint),
                json_escape(&probe.outcome),
                probe.score,
                json_u64(probe.latency_ms),
                probe.created_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let probes_json = if probe_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{probe_items}\n  ]")
    };

    format!(
        r#"{{
  "probes": {},
  "contentsDisplayed": false
}}"#,
        probes_json
    )
}

fn render_route_probes_text(probes: &[RouteProbe]) -> String {
    let mut recent = probes.iter().rev().take(12).collect::<Vec<_>>();
    recent.reverse();
    let probes_text = recent
        .iter()
        .map(|probe| {
            let latency = probe
                .latency_ms
                .map(|latency| format!("{latency}ms"))
                .unwrap_or_else(|| "n/a".to_string());
            format!(
                "  {}  {}  {}  score {}  latency {}",
                probe.peer_node_id,
                probe.transport.as_str(),
                probe.outcome,
                probe.score,
                latency
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let probes_text = if probes_text.is_empty() {
        "  none recorded yet".to_string()
    } else {
        probes_text
    };

    format!(
        r"conU route probes

recent probes
{probes_text}

privacy
  payload view  contents are not displayed by conU"
    )
}

fn render_routes_report_json(report: &RouteSyncReport) -> String {
    format!(
        r#"{{
  "status": "synced",
  "peers": {},
  "candidates": {},
  "directAttempts": {},
  "directAvailable": {},
  "selectedDirect": {},
  "selectedRelay": {},
  "relayFallbacks": {},
  "probesRecorded": {},
  "contentsDisplayed": false
}}"#,
        report.peers,
        report.candidates,
        report.direct_attempts,
        report.direct_available,
        report.selected_direct,
        report.selected_relay,
        report.relay_fallbacks,
        report.probes_recorded
    )
}

fn render_routes_report_text(report: &RouteSyncReport) -> String {
    format!(
        r"conU routes sync

status: synced
trusted peers: {}
candidates: {}
direct attempts: {}
direct available: {}
selected direct: {}
selected relay: {}
relay fallbacks: {}
probes recorded: {}

privacy
  payload view  contents are not displayed by conU",
        report.peers,
        report.candidates,
        report.direct_attempts,
        report.direct_available,
        report.selected_direct,
        report.selected_relay,
        report.relay_fallbacks,
        report.probes_recorded
    )
}

fn render_routes_usage() -> String {
    r"usage:
  conu routes [--json]
  conu routes sync [--json]
  conu routes probes [--json]"
        .to_string()
}

fn render_security(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let remaining = match args.first().map(String::as_str) {
        None => args,
        Some("audit") => &args[1..],
        Some(_) => return CliOutput::failure(2, render_security_usage()),
    };
    let json = match json_flag(remaining) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let init = match state::init_state(home_override.clone()) {
        Ok(init) => init,
        Err(error) => {
            return CliOutput::failure(1, format!("conU security audit failed\n\n{error}"));
        }
    };
    let report = match security::ensure_security_state_from_paths(&init.paths) {
        Ok(report) => report,
        Err(error) => {
            return CliOutput::failure(1, format!("conU security audit failed\n\n{error}"));
        }
    };
    let audit = match security::security_audit(home_override) {
        Ok(audit) => audit,
        Err(error) => {
            return CliOutput::failure(1, format!("conU security audit failed\n\n{error}"));
        }
    };

    if json {
        CliOutput::success(render_security_json(&audit, &report))
    } else {
        CliOutput::success(render_security_text(&audit, &report))
    }
}

fn render_security_json(audit: &SecurityAudit, report: &SecurityReport) -> String {
    format!(
        r#"{{
  "initialized": {},
  "identitySigningKey": {},
  "identityExchangeKey": {},
  "storageKey": {},
  "replayCache": {},
  "keyRotationPlan": {},
  "localPayloadEncryption": {},
  "signedAgentCards": {},
  "peerKeyExchange": {},
  "signingKeyId": "{}",
  "exchangeKeyId": "{}",
  "storageKeyId": "{}",
  "contentsDisplayed": false
}}"#,
        audit.initialized,
        audit.identity_signing_key,
        audit.identity_exchange_key,
        audit.storage_key,
        audit.replay_cache,
        audit.key_rotation_plan,
        audit.local_payload_encryption,
        audit.signed_agent_cards,
        audit.peer_key_exchange,
        json_escape(&report.signing_key_id),
        json_escape(&report.exchange_key_id),
        json_escape(&report.storage_key_id)
    )
}

fn render_security_text(audit: &SecurityAudit, report: &SecurityReport) -> String {
    format!(
        r"conU security audit

status: {}

keys
  signing key   {}  {}
  exchange key  {}  {}
  storage key   {}  {}

controls
  local payloads  {}
  agent cards     {}
  peer exchange   {}
  replay cache    {}
  rotation plan   {}

privacy
  payload view    contents are not displayed by conU
  key view        private keys are not displayed",
        ready_label(audit.initialized),
        ready_label(audit.identity_signing_key),
        report.signing_key_id,
        ready_label(audit.identity_exchange_key),
        report.exchange_key_id,
        ready_label(audit.storage_key),
        report.storage_key_id,
        if audit.local_payload_encryption {
            "encrypted at rest"
        } else {
            "not ready"
        },
        if audit.signed_agent_cards {
            "signed with Ed25519"
        } else {
            "not ready"
        },
        if audit.peer_key_exchange {
            "X25519 ready"
        } else {
            "not ready"
        },
        ready_label(audit.replay_cache),
        ready_label(audit.key_rotation_plan)
    )
}

fn render_security_usage() -> String {
    "usage: conu security audit [--json]".to_string()
}

fn inbox_ids(home_override: Option<PathBuf>, agent_id: &str) -> HashSet<String> {
    messages::list_agent_inbox(home_override, agent_id)
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.envelope_id)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default()
}

fn wait_for_message_delivery(
    home_override: Option<PathBuf>,
    to_agent_id: &str,
    before: HashSet<String>,
    payload_bytes: usize,
) -> Option<InboxEntry> {
    if !runtime_is_live(home_override.clone()) {
        return None;
    }

    for _ in 0..40 {
        if let Ok(entries) = messages::list_agent_inbox(home_override.clone(), to_agent_id) {
            if let Some(entry) = entries.into_iter().find(|entry| {
                !before.contains(&entry.envelope_id) && entry.payload_bytes == payload_bytes
            }) {
                return Some(entry);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    None
}

fn render_peers(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("revoke") => render_peer_revoke(&args[1..], home_override),
        _ => render_peer_list(args, home_override),
    }
}

fn render_peer_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let peers = match trust::list_peers(home_override) {
        Ok(peers) => peers,
        Err(error) => return CliOutput::failure(1, format!("conU peers failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_peers_json(&peers)),
        Ok(false) => CliOutput::success(render_peers_text(&peers)),
        Err(error) => error,
    }
}

fn render_peer_revoke(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let (peer_node_id, json) = match parse_peer_revoke_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let report = match trust::revoke_peer(home_override, &peer_node_id) {
        Ok(report) => report,
        Err(error) => return CliOutput::failure(1, format!("conU peers revoke failed\n\n{error}")),
    };

    if json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "peerNodeId": "{}",
  "changed": {},
  "contentsDisplayed": false
}}"#,
            report.peer.status.as_str(),
            json_escape(&report.peer.peer_node_id),
            report.changed
        ));
    }

    CliOutput::success(format!(
        r"conU peers revoke

status: {}
peer: {}
changed: {}

privacy
  payload view  contents are not displayed by conU",
        report.peer.status.as_str(),
        report.peer.peer_node_id,
        report.changed
    ))
}

fn render_peers_json(peers: &[TrustedPeer]) -> String {
    let trusted = trusted_peer_count(peers);
    let peer_items = peers
        .iter()
        .map(|peer| {
            format!(
                r#"    {{
      "peerNodeId": "{}",
      "displayName": "{}",
      "status": "{}",
      "source": "{}",
      "updatedAtUnix": {}
    }}"#,
                json_escape(&peer.peer_node_id),
                json_escape(&peer.display_name),
                peer.status.as_str(),
                json_escape(&peer.source),
                peer.updated_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let peers = if peer_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{peer_items}\n  ]")
    };

    format!(
        r#"{{
  "peers": {},
  "trusted": {},
  "contentsDisplayed": false
}}"#,
        peers, trusted
    )
}

fn render_peers_text(peers: &[TrustedPeer]) -> String {
    let rows = if peers.is_empty() {
        "  none trusted yet".to_string()
    } else {
        peers
            .iter()
            .map(|peer| {
                format!(
                    "  {}  {}  {}",
                    peer.peer_node_id,
                    peer.status.as_str(),
                    peer.display_name
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU peers

trusted peers
{rows}

next
  conu pair
  conu join <code>
  conu peers revoke <peer-node-id>"
    )
}

fn parse_peer_revoke_args(args: &[String]) -> Result<(String, bool), CliOutput> {
    let mut json = false;
    let mut peer = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(CliOutput::failure(2, format!("unknown option: {value}")));
            }
            value => {
                if peer.is_some() {
                    return Err(CliOutput::failure(
                        2,
                        "usage: conu peers revoke <peer-node-id> [--json]",
                    ));
                }
                peer = Some(value.to_string());
            }
        }
    }

    let Some(peer) = peer else {
        return Err(CliOutput::failure(
            2,
            "usage: conu peers revoke <peer-node-id> [--json]",
        ));
    };

    Ok((peer, json))
}

fn render_pair(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match json_flag(args) {
        Ok(json) => match trust::create_pairing_invite(home_override) {
            Ok(invite) => {
                if json {
                    CliOutput::success(format!(
                        r#"{{
  "status": "pairing_code_created",
  "code": "{}",
  "peerNodeId": "{}",
  "expiresAtUnix": {},
  "relay": "service_available",
  "contentsDisplayed": false
}}"#,
                        invite.code,
                        json_escape(&invite.peer_node_id),
                        invite.expires_at_unix
                    ))
                } else {
                    CliOutput::success(format!(
                        r"conU pair

status: pairing code created
code: {}
peer: {}
expires at unix: {}
relay: service available; pairing rendezvous still local

next
  conu join {}",
                        invite.code, invite.peer_node_id, invite.expires_at_unix, invite.code
                    ))
                }
            }
            Err(error) => CliOutput::failure(1, format!("conU pair failed\n\n{error}")),
        },
        Err(error) => error,
    }
}

fn render_join(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = args.iter().any(|arg| arg == "--json");

    match join_code(args) {
        Ok(code) => match trust::join_pairing_code(home_override, code) {
            Ok(report) => {
                if json {
                    CliOutput::success(format!(
                        r#"{{
  "status": "trusted",
  "peerNodeId": "{}",
  "displayName": "{}",
  "contentsDisplayed": false
}}"#,
                        json_escape(&report.peer.peer_node_id),
                        json_escape(&report.peer.display_name)
                    ))
                } else {
                    CliOutput::success(format!(
                        r"conU join

status: trusted
peer: {}
name: {}
source: local pairing code

next
  conu peers",
                        report.peer.peer_node_id, report.peer.display_name
                    ))
                }
            }
            Err(error) => CliOutput::failure(1, format!("conU join failed\n\n{error}")),
        },
        Err(error) => error,
    }
}

fn render_connect(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }
    let local_agents = agents::list_local_agents(home_override.clone()).unwrap_or_default();
    let route_records = routes::list_routes(home_override.clone()).unwrap_or_default();
    let remote_agents = sessions::list_remote_agents(home_override).unwrap_or_default();
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
    let remote = if remote_agents.is_empty() {
        "none visible".to_string()
    } else {
        remote_agents
            .iter()
            .map(|agent| {
                format!(
                    "{} ({}, peer {})",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.peer_node_id
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    CliOutput::success(format!(
        r"conU connect

selector
  source local agent   {local}
  target remote agent  {remote}
  route plan           direct {} | relay {}
  mode                 message | stream | room | observe

status: stream sessions use `conu streams open`; interactive selector remains future work",
        selected_direct_route_count(&route_records),
        selected_relay_route_count(&route_records)
    ))
}

fn render_watch(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if let Some(error) = reject_args(args) {
        return error;
    }

    let stream_records = streams::list_streams(home_override.clone()).unwrap_or_default();
    let events = streams::list_events(home_override).unwrap_or_default();
    let open_streams = stream_records
        .iter()
        .filter(|stream| stream.state.as_str() == "open")
        .count();
    let total_packets: u64 = stream_records
        .iter()
        .map(|stream| stream.chunks_written)
        .sum();
    let total_bytes: usize = stream_records
        .iter()
        .map(|stream| stream.bytes_written)
        .sum();
    let latest = events.last();
    let flow = latest
        .map(|event| {
            format!(
                "{}  == encrypted stream ==>  {}",
                event.from_agent_id, event.to_agent_id
            )
        })
        .unwrap_or_else(|| "local-agent   -> conUD -> encrypted route -> remote-agent".to_string());
    let route = latest
        .map(|event| event.route.as_str())
        .unwrap_or("inactive");
    let stream_id = latest
        .map(|event| event.stream_id.as_str())
        .unwrap_or("none");
    let latest_event = latest
        .map(|event| event.event_type.as_str())
        .unwrap_or("idle");

    CliOutput::success(format!(
        r"conU watch

transport view
  {flow}
  route         {route}
  stream        {stream_id}
  event         {latest_event}
  open streams  {open_streams}
  packets       {total_packets}
  bytes         {total_bytes}
  contents      not displayed

animation
  [agent] >>> private packets >>> [agent]

status: stream metadata only",
    ))
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorBinary {
    name: &'static str,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorLogScan {
    payload_safe: bool,
    scanned_files: usize,
    issues: usize,
}

fn render_doctor(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU doctor failed\n\n{error}")),
    };
    let runtime_status = match runtime::read_runtime(home_override.clone()) {
        Ok(status) => status,
        Err(error) => return CliOutput::failure(1, format!("conU doctor failed\n\n{error}")),
    };
    let security_audit =
        security::security_audit(home_override).unwrap_or_else(|_| empty_security_audit());
    let binaries = release_binaries();
    let log_scan = scan_payload_safe_logs(&snapshot);
    let status = doctor_status(&snapshot, &security_audit, &binaries, &log_scan);

    if json {
        CliOutput::success(render_doctor_json(
            status,
            &snapshot,
            &runtime_status,
            &security_audit,
            &binaries,
            &log_scan,
        ))
    } else {
        CliOutput::success(render_doctor_text(
            status,
            &snapshot,
            &runtime_status,
            &security_audit,
            &binaries,
            &log_scan,
        ))
    }
}

fn render_doctor_json(
    status: &str,
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> String {
    format!(
        r#"{{
  "status": "{}",
  "statePath": "{}",
  "initialized": {},
  "runtime": {{
    "state": "{}",
    "health": "{}",
    "pid": {}
  }},
  "binaries": {{
    "conu": {},
    "conud": {},
    "conuRelay": {},
    "conuMcp": {}
  }},
  "security": {{
    "initialized": {},
    "localPayloadEncryption": {},
    "signedAgentCards": {},
    "peerKeyExchange": {},
    "replayCache": {},
    "keyRotationPlan": {}
  }},
  "logs": {{
    "payloadSafe": {},
    "scannedFiles": {},
    "issues": {}
  }},
  "releaseGates": {{
    "localInstallReady": {},
    "publicInternetReady": false,
    "knownLimitsDocumented": true
  }},
  "privacy": {{
    "contentsDisplayed": false
  }}
}}"#,
        json_escape(status),
        json_escape(&snapshot.paths.home.display().to_string()),
        snapshot.is_initialized(),
        runtime_status.state.as_str(),
        json_escape(runtime_health_label(runtime_status)),
        json_u32(runtime_status.pid),
        doctor_binary_json(binaries, "conu"),
        doctor_binary_json(binaries, "conud"),
        doctor_binary_json(binaries, "conu-relay"),
        doctor_binary_json(binaries, "conu-mcp"),
        security.initialized,
        security.local_payload_encryption,
        security.signed_agent_cards,
        security.peer_key_exchange,
        security.replay_cache,
        security.key_rotation_plan,
        log_scan.payload_safe,
        log_scan.scanned_files,
        log_scan.issues,
        local_install_ready(snapshot, security, binaries, log_scan)
    )
}

fn render_doctor_text(
    status: &str,
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> String {
    format!(
        r"conU doctor

status: {status}
state path: {}

runtime
  conUD       {}
  health      {}
  pid         {}

binaries
{}

security
  initialized        {}
  local payloads     {}
  signed agents      {}
  peer exchange      {}
  replay guard       {}
  key rotation plan  {}

logs
  payload safe       {}
  scanned files      {}
  issues             {}

release gates
  local install      {}
  public internet    not ready; live remote data plane remains future work
  known limits       documented

privacy
  payload view       contents are not displayed by conU",
        snapshot.paths.home.display(),
        runtime_state_label(runtime_status),
        runtime_health_label(runtime_status),
        runtime_pid_label(runtime_status),
        doctor_binaries_text(binaries),
        ready_label(security.initialized),
        if security.local_payload_encryption {
            "encrypted at rest"
        } else {
            "not ready"
        },
        ready_label(security.signed_agent_cards),
        ready_label(security.peer_key_exchange),
        ready_label(security.replay_cache),
        ready_label(security.key_rotation_plan),
        yes_no(log_scan.payload_safe),
        log_scan.scanned_files,
        log_scan.issues,
        yes_no(local_install_ready(snapshot, security, binaries, log_scan))
    )
}

fn doctor_status(
    snapshot: &StateSnapshot,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> &'static str {
    if !snapshot.is_initialized() {
        "needs_init"
    } else if !log_scan.payload_safe {
        "privacy_attention"
    } else if !security_controls_ready(security) {
        "needs_security_audit"
    } else if !all_required_binaries_present(binaries) {
        "missing_binaries"
    } else {
        "ready_for_local_use"
    }
}

fn local_install_ready(
    snapshot: &StateSnapshot,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> bool {
    snapshot.is_initialized()
        && security_controls_ready(security)
        && all_required_binaries_present(binaries)
        && log_scan.payload_safe
}

fn security_controls_ready(security: &SecurityAudit) -> bool {
    security.initialized
        && security.local_payload_encryption
        && security.signed_agent_cards
        && security.peer_key_exchange
        && security.replay_cache
        && security.key_rotation_plan
}

fn all_required_binaries_present(binaries: &[DoctorBinary]) -> bool {
    ["conu", "conud", "conu-relay", "conu-mcp"]
        .iter()
        .all(|name| doctor_binary_present(binaries, name))
}

fn release_binaries() -> Vec<DoctorBinary> {
    vec![
        DoctorBinary {
            name: "conu",
            path: env::current_exe().ok(),
        },
        DoctorBinary {
            name: "conud",
            path: resolve_companion_executable("conud", "CONUD_EXE"),
        },
        DoctorBinary {
            name: "conu-relay",
            path: resolve_companion_executable("conu-relay", "CONU_RELAY_EXE"),
        },
        DoctorBinary {
            name: "conu-mcp",
            path: resolve_companion_executable("conu-mcp", "CONU_MCP_EXE"),
        },
    ]
}

fn doctor_binary_present(binaries: &[DoctorBinary], name: &str) -> bool {
    binaries
        .iter()
        .any(|binary| binary.name == name && binary.path.is_some())
}

fn doctor_binary_json(binaries: &[DoctorBinary], name: &str) -> String {
    binaries
        .iter()
        .find(|binary| binary.name == name)
        .and_then(|binary| binary.path.as_ref())
        .map(|path| json_string(&path.display().to_string()))
        .unwrap_or_else(|| "null".to_string())
}

fn doctor_binaries_text(binaries: &[DoctorBinary]) -> String {
    binaries
        .iter()
        .map(|binary| {
            let path = binary
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "not found".to_string());
            format!("  {:<11} {}", binary.name, path)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn resolve_companion_executable(binary_name: &str, env_var: &str) -> Option<PathBuf> {
    if let Ok(value) = env::var(env_var) {
        let path = PathBuf::from(value);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_name = format!("{binary_name}{}", env::consts::EXE_SUFFIX);
    if let Ok(mut path) = env::current_exe() {
        path.set_file_name(&executable_name);
        if path.exists() {
            return Some(path);
        }
    }

    let path_value = env::var_os("PATH")?;
    for directory in env::split_paths(&path_value) {
        let candidate = directory.join(&executable_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn scan_payload_safe_logs(snapshot: &StateSnapshot) -> DoctorLogScan {
    let log_dir = &snapshot.paths.logs_dir;
    if !log_dir.exists() {
        return DoctorLogScan {
            payload_safe: true,
            scanned_files: 0,
            issues: 0,
        };
    }

    let mut scanned_files = 0;
    let mut issues = 0;
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("log") {
                continue;
            }
            scanned_files += 1;
            let Ok(contents) = fs::read_to_string(&path) else {
                issues += 1;
                continue;
            };
            if FORBIDDEN_LOG_TERMS
                .iter()
                .any(|term| contents.contains(term))
            {
                issues += 1;
            }
        }
    }

    DoctorLogScan {
        payload_safe: issues == 0,
        scanned_files,
        issues,
    }
}

const FORBIDDEN_LOG_TERMS: &[&str] = &[
    "private message contents",
    "Review this code",
    "payload_text",
    "payload_hex",
    "secret_key_hex",
];

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

fn render_init_report(report: &InitReport, security: &SecurityReport) -> String {
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
  security keys  {}

next
  conu status
  conu security audit
  conu start",
        report.node.node_id,
        report.node.display_name,
        report.paths.home.display(),
        created_label(report.node_created),
        created_label(report.config_created),
        created_label(report.trust_store_created),
        created_label(report.agent_registry_created),
        created_label(
            security.identity_signing_key_created
                || security.identity_exchange_key_created
                || security.storage_key_created
        )
    )
}

fn render_status_text(
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    local_agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    sessions: &[RemoteSession],
    stream_records: &[StreamRecord],
    route_records: &[RouteRecord],
    peers: &[TrustedPeer],
    security: &SecurityAudit,
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
  relay         service available via conu-relay
  routes        direct {} relay {} fallback {}

identity
  state         {}
  node          {}
  name          {}
  state path    {}
  config        {}
  trust store   {}
  security      {}

agents
  local         {} registered
  remote        {} visible
  registry      {}
  trusted peers {}
  sessions      {}
  streams       {}
  routes        {} selected

privacy
  local storage encrypted at rest: {}
  agent cards   signed: {}
  replay guard  active: {}
  payload view  contents are not displayed by conU",
        runtime_state_label(runtime_status),
        runtime_pid_label(runtime_status),
        runtime_health_label(runtime_status),
        selected_direct_route_count(route_records),
        selected_relay_route_count(route_records),
        relay_fallback_route_count(route_records),
        initialization_label(snapshot),
        node,
        display_name,
        snapshot.paths.home.display(),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        ready_label(security.initialized),
        local_agents.len(),
        remote_agents.len(),
        ready_label(snapshot.agent_registry_exists),
        trusted_peer_count(peers),
        sessions.len(),
        stream_records.len(),
        selected_route_count(route_records),
        yes_no(security.local_payload_encryption),
        yes_no(security.signed_agent_cards),
        yes_no(security.replay_cache)
    )
}

fn render_status_json(
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    local_agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    sessions: &[RemoteSession],
    stream_records: &[StreamRecord],
    route_records: &[RouteRecord],
    peers: &[TrustedPeer],
    security: &SecurityAudit,
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
    "relay": "service_available",
    "selectedDirectRoutes": {},
    "selectedRelayRoutes": {},
    "relayFallbacks": {}
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
    "remote": {},
    "registry": "{}",
    "trustedPeers": {},
    "sessions": {},
    "streams": {},
    "routes": {}
  }},
  "security": {{
    "initialized": {},
    "localPayloadEncryption": {},
    "signedAgentCards": {},
    "peerKeyExchange": {},
    "replayCache": {},
    "keyRotationPlan": {}
  }},
  "privacy": {{
    "contentsDisplayed": false
  }}
}}"#,
        runtime_status.state.as_str(),
        json_u32(runtime_status.pid),
        json_u64(runtime_status.heartbeat_age_secs()),
        json_escape(runtime_health_label(runtime_status)),
        selected_direct_route_count(route_records),
        selected_relay_route_count(route_records),
        relay_fallback_route_count(route_records),
        initialization_label(snapshot),
        json_escape(node),
        json_escape(display_name),
        json_escape(&snapshot.paths.home.display().to_string()),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        local_agents.len(),
        remote_agents.len(),
        ready_label(snapshot.agent_registry_exists),
        trusted_peer_count(peers),
        sessions.len(),
        stream_records.len(),
        selected_route_count(route_records),
        security.initialized,
        security.local_payload_encryption,
        security.signed_agent_cards,
        security.peer_key_exchange,
        security.replay_cache,
        security.key_rotation_plan
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
  conu messages send <from-agent> <to-agent> --stdin [--json]
  conu messages inbox <agent-id> [--json]
  conu messages receipts [--json]
  conu streams [--json]
  conu streams open <from-agent> <to-agent> [--kind <kind>] [--json]
  conu streams write <stream-id> --stdin [--json]
  conu streams close <stream-id> [--json]
  conu sessions [--json]
  conu sessions sync [--json]
  conu routes [--json]
  conu routes sync [--json]
  conu routes probes [--json]
  conu security audit [--json]
  conu peers [--json]
  conu peers revoke <peer-node-id> [--json]
  conu pair [--json]
  conu join <code> [--json]
  conu connect
  conu watch
  conu doctor [--json]
  conu start [--json]
  conu stop [--json]
  conu components
  conu --help
  conu --version

Phase 15 adds release readiness checks, packaging paths, and service templates while payload contents remain hidden."
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

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn empty_security_audit() -> SecurityAudit {
    SecurityAudit {
        initialized: false,
        identity_signing_key: false,
        identity_exchange_key: false,
        storage_key: false,
        replay_cache: false,
        key_rotation_plan: false,
        local_payload_encryption: false,
        signed_agent_cards: false,
        peer_key_exchange: false,
        contents_displayed: false,
    }
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

fn trusted_peer_count(peers: &[TrustedPeer]) -> usize {
    peers
        .iter()
        .filter(|peer| peer.status == TrustStatus::Trusted)
        .count()
}

fn selected_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.is_selected())
        .count()
}

fn selected_direct_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.is_selected() && route.transport == RouteTransport::DirectQuic)
        .count()
}

fn selected_relay_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.is_selected() && route.transport == RouteTransport::RelayWebSocket)
        .count()
}

fn relay_fallback_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.relay_fallback)
        .count()
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

fn json_optional_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
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

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
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
    use std::fs;
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
    fn phase_thirteen_commands_are_registered() {
        let home = temp_home("commands");

        for command in [
            "init", "status", "agents", "streams", "sessions", "security", "pair", "peers",
            "routes", "connect", "watch", "doctor", "stop",
        ] {
            let output = run_with_home([command], Some(home.clone()));
            assert_eq!(output.code, 0, "{command} failed: {}", output.stderr);
        }

        let receipts = run_with_home(["messages", "receipts"], Some(home));
        assert_eq!(receipts.code, 0);
    }

    #[test]
    fn pair_and_join_create_trusted_peer() {
        let home = temp_home("pair-join");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);

        let join = run_with_home(["join", &code], Some(home.clone()));
        let peers = run_with_home(["peers"], Some(home));

        assert_eq!(pair.code, 0, "{}", pair.stderr);
        assert_eq!(join.code, 0, "{}", join.stderr);
        assert!(join.stdout.contains("status: trusted"));
        assert!(peers.stdout.contains("peer_"));
        assert!(peers.stdout.contains("trusted"));
    }

    #[test]
    fn peers_json_and_revoke_are_metadata_only() {
        let home = temp_home("peers-revoke");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("join");

        let peers = run_with_home(["peers", "--json"], Some(home.clone()));
        let revoke = run_with_home(
            ["peers", "revoke", &joined.peer.peer_node_id, "--json"],
            Some(home.clone()),
        );
        let revoked = run_with_home(["peers"], Some(home));

        assert_eq!(peers.code, 0, "{}", peers.stderr);
        assert!(peers.stdout.contains("\"status\": \"trusted\""));
        assert!(peers.stdout.contains("\"contentsDisplayed\": false"));
        assert_eq!(revoke.code, 0, "{}", revoke.stderr);
        assert!(revoke.stdout.contains("\"status\": \"revoked\""));
        assert!(revoked.stdout.contains("revoked"));
    }

    #[test]
    fn sessions_sync_makes_remote_agent_visible() {
        let home = temp_home("sessions-sync");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);
        let join = run_with_home(["join", &code], Some(home.clone()));
        let sync = run_with_home(["sessions", "sync"], Some(home.clone()));
        let sessions = run_with_home(["sessions"], Some(home.clone()));
        let agents = run_with_home(["agents", "--json"], Some(home.clone()));
        let status = run_with_home(["status", "--json"], Some(home));

        assert_eq!(join.code, 0, "{}", join.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(sync.stdout.contains("remote agents: 1"));
        assert!(sessions.stdout.contains("connected"));
        assert!(agents.stdout.contains("\"remote\": ["));
        assert!(agents.stdout.contains("agent.remote."));
        assert!(status.stdout.contains("\"remote\": 1"));
        assert!(status.stdout.contains("\"sessions\": 1"));
        assert!(!agents.stdout.contains("private message contents"));
    }

    #[test]
    fn routes_sync_selects_relay_fallback_without_payloads() {
        let home = temp_home("routes-relay");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);
        let join = run_with_home(["join", &code], Some(home.clone()));
        let sync = run_with_home(["routes", "sync", "--json"], Some(home.clone()));
        let routes = run_with_home(["routes", "--json"], Some(home.clone()));
        let probes = run_with_home(["routes", "probes"], Some(home));

        assert_eq!(join.code, 0, "{}", join.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(sync.stdout.contains("\"selectedRelay\": 1"));
        assert!(sync.stdout.contains("\"relayFallbacks\": 1"));
        assert!(routes.stdout.contains("\"transport\": \"relay-websocket\""));
        assert!(routes.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            probes
                .stdout
                .contains("payload view  contents are not displayed")
        );
        assert!(!routes.stdout.contains("private message contents"));
        assert!(!probes.stdout.contains("private message contents"));
    }

    #[test]
    fn routes_sync_prefers_configured_direct_quic_candidate() {
        let home = temp_home("routes-direct");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);
        let join = run_with_home(["join", &code], Some(home.clone()));
        let peer_id = join
            .stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("peer: "))
            .expect("peer id line")
            .to_string();
        let config_key = format!("direct_quic_{}", config_key_suffix_for_test(&peer_id));
        fs::write(
            state::StatePaths::from_home(home.clone()).config,
            format!(
                "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"public\"\n{config_key} = \"quic://127.0.0.1:9443\"\n"
            ),
        )
        .expect("config writes");

        let sync = run_with_home(["routes", "sync", "--json"], Some(home.clone()));
        let routes = run_with_home(["routes"], Some(home.clone()));
        let session_sync = run_with_home(["sessions", "sync"], Some(home.clone()));
        let sessions = run_with_home(["sessions"], Some(home));

        assert_eq!(join.code, 0, "{}", join.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(sync.stdout.contains("\"selectedDirect\": 1"));
        assert!(sync.stdout.contains("\"selectedRelay\": 0"));
        assert!(routes.stdout.contains("direct-quic"));
        assert!(session_sync.stdout.contains("sessions: 1"));
        assert!(sessions.stdout.contains("route direct-quic"));
        assert!(!routes.stdout.contains("private message contents"));
    }

    #[test]
    fn streams_flow_and_watch_are_metadata_only() {
        let home = temp_home("streams-flow");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");

        let opened = run_with_home(
            ["streams", "open", "agent.sender", "agent.receiver"],
            Some(home.clone()),
        );
        let stream_id = stream_id_from_output(&opened.stdout);
        let written = run_with_home_and_stdin(
            ["streams", "write", &stream_id, "--stdin"],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );
        let watch = run_with_home(["watch"], Some(home.clone()));
        let closed = run_with_home(["streams", "close", &stream_id], Some(home.clone()));
        let listed = run_with_home(["streams", "--json"], Some(home));

        assert_eq!(opened.code, 0, "{}", opened.stderr);
        assert_eq!(written.code, 0, "{}", written.stderr);
        assert_eq!(closed.code, 0, "{}", closed.stderr);
        assert!(written.stdout.contains("bytes: 24"));
        assert!(watch.stdout.contains("private packets"));
        assert!(watch.stdout.contains("contents      not displayed"));
        assert!(listed.stdout.contains("\"streams\": ["));
        assert!(listed.stdout.contains("\"state\": \"closed\""));
        assert!(!watch.stdout.contains("private message contents"));
        assert!(!listed.stdout.contains("private message contents"));
    }

    #[test]
    fn security_audit_reports_hardened_controls_without_keys_or_payloads() {
        let home = temp_home("security-audit");
        let output = run_with_home(["security", "audit", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"localPayloadEncryption\": true"));
        assert!(output.stdout.contains("\"signedAgentCards\": true"));
        assert!(output.stdout.contains("\"peerKeyExchange\": true"));
        assert!(output.stdout.contains("\"replayCache\": true"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("secret_key_hex"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn doctor_reports_setup_and_privacy_without_payloads() {
        let home = temp_home("doctor");
        let before_init = run_with_home(["doctor", "--json"], Some(home.clone()));
        let init = run_with_home(["init"], Some(home.clone()));
        let after_init = run_with_home(["doctor"], Some(home.clone()));

        assert_eq!(before_init.code, 0, "{}", before_init.stderr);
        assert!(before_init.stdout.contains("\"status\": \"needs_init\""));
        assert_eq!(init.code, 0, "{}", init.stderr);
        assert_eq!(after_init.code, 0, "{}", after_init.stderr);
        assert!(after_init.stdout.contains("conU doctor"));
        assert!(
            after_init
                .stdout
                .contains("payload view       contents are not displayed")
        );
        assert!(!after_init.stdout.contains("private message contents"));
    }

    #[test]
    fn doctor_detects_payload_text_in_logs() {
        let home = temp_home("doctor-logs");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("bad.log"),
            "event=test private message contents\n",
        )
        .expect("log writes");

        let output = run_with_home(["doctor", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"privacy_attention\""));
        assert!(output.stdout.contains("\"payloadSafe\": false"));
        assert!(
            !output
                .stdout
                .contains("event=test private message contents")
        );
    }

    #[test]
    fn join_rejects_unknown_local_pairing_code() {
        let output = run_with_home(["join", "123456"], Some(temp_home("join-missing")));

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("not available locally"));
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
    fn messages_send_queues_opaque_stdin_payload() {
        let home = temp_home("message-send-queued");

        let output = run_with_home_and_stdin(
            [
                "messages",
                "send",
                "agent.sender",
                "agent.receiver",
                "--stdin",
            ],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );
        let request = std::fs::read_dir(state::StatePaths::from_home(home).message_ipc_inbox_dir)
            .expect("message inbox reads")
            .next()
            .expect("message request exists")
            .expect("message request entry");
        let request_text = std::fs::read_to_string(request.path()).expect("request reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: queued"));
        assert!(output.stdout.contains("bytes: 24"));
        assert!(!output.stdout.contains("private message contents"));
        assert!(request_text.contains("payload_len = 24"));
        assert!(request_text.contains("payload_privacy = \"encrypted_at_rest\""));
        assert!(request_text.contains("payload_ciphertext_hex"));
        assert!(!request_text.contains("payload_hex"));
        assert!(!request_text.contains("private message contents"));
    }

    #[test]
    fn messages_inbox_lists_metadata_without_payload() {
        let home = temp_home("message-inbox");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");

        let output = run_with_home(["messages", "inbox", "agent.receiver"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("from agent.sender"));
        assert!(output.stdout.contains("bytes 24"));
        assert!(
            output
                .stdout
                .contains("payload view  contents are not displayed")
        );
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn messages_inbox_json_lists_metadata_without_payload() {
        let home = temp_home("message-inbox-json");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes([7, 8, 9]),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");

        let output = run_with_home(
            ["messages", "inbox", "agent.receiver", "--json"],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"fromAgentId\": \"agent.sender\""));
        assert!(output.stdout.contains("\"payloadBytes\": 3"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
    }

    #[test]
    fn messages_send_requires_stdin_flag() {
        let output = run(["messages", "send", "agent.sender", "agent.receiver"]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("conu messages send"));
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
        assert!(output.stdout.contains("\"remote\": 0"));
        assert!(output.stdout.contains("\"trustedPeers\": 0"));
        assert!(output.stdout.contains("\"sessions\": 0"));
        assert!(output.stdout.contains("\"streams\": 0"));
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

    fn pairing_code_from_output(output: &str) -> String {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix("code: "))
            .expect("pairing code line")
            .to_string()
    }

    fn stream_id_from_output(output: &str) -> String {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix("stream: "))
            .expect("stream id line")
            .to_string()
    }

    fn config_key_suffix_for_test(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn register_test_agent(home: &PathBuf, agent_id: &str) {
        let registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid registration");
        agents::submit_registration(Some(home.clone()), registration).expect("request submits");
        agents::process_gateway_requests(Some(home.clone())).expect("request processes");
    }
}
