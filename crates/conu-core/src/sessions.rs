//! Remote runtime session and discovery state.
//!
//! Phase 9 keeps remote discovery file-backed and metadata-only. conUD owns
//! this mirror so the CLI can show trusted remote agents without reading or
//! transporting private payloads.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::AgentCapabilities;

use crate::agents::AgentPresence;
use crate::routes::{self, RouteTransport};
use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus, TrustedPeer};

const SESSION_VERSION: &str = "1";
const DEFAULT_RELAY_ENDPOINT: &str = "ws://127.0.0.1:8787";

/// Runtime session state visible to CLI and future routing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionState {
    Connected,
    Reconnecting,
    Offline,
}

impl RemoteSessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::Offline => "offline",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "connected" => Self::Connected,
            "reconnecting" => Self::Reconnecting,
            _ => Self::Offline,
        }
    }
}

/// Metadata for one remote runtime session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSession {
    pub peer_node_id: String,
    pub display_name: String,
    pub state: RemoteSessionState,
    pub route: String,
    pub relay_endpoint: String,
    pub reconnect_attempts: u64,
    pub remote_agent_count: usize,
    pub last_seen_unix: u64,
    pub updated_at_unix: u64,
}

/// Remote agent card mirrored from trusted runtime metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAgentRecord {
    pub agent_id: String,
    pub display_name: String,
    pub peer_node_id: String,
    pub node_id: String,
    pub kind: String,
    pub presence: AgentPresence,
    pub last_seen_unix: u64,
    pub capabilities: AgentCapabilities,
}

/// Summary of a conUD remote session sync pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSyncReport {
    pub sessions_synced: usize,
    pub remote_agents_synced: usize,
    pub connected: usize,
    pub reconnecting: usize,
    pub offline: usize,
}

/// Errors produced by remote session/discovery state.
#[derive(Debug)]
pub enum SessionError {
    State(StateError),
    Trust(trust::TrustError),
    Route(routes::RouteError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRecord {
        reason: String,
    },
}

impl SessionError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Route(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRecord { reason } => write!(formatter, "invalid session record: {reason}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<StateError> for SessionError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<trust::TrustError> for SessionError {
    fn from(error: trust::TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<routes::RouteError> for SessionError {
    fn from(error: routes::RouteError) -> Self {
        Self::Route(error)
    }
}

/// Sync remote sessions from the local trust store.
pub fn sync_remote_sessions(
    home_override: Option<PathBuf>,
) -> Result<SessionSyncReport, SessionError> {
    let init = state::init_state(home_override)?;
    sync_remote_sessions_from_paths(&init.paths)
}

/// Sync remote sessions from already resolved state paths.
pub fn sync_remote_sessions_from_paths(
    paths: &StatePaths,
) -> Result<SessionSyncReport, SessionError> {
    ensure_session_files(paths)?;

    let peers = trust::list_peers(Some(paths.home.clone()))?;
    routes::sync_routes_from_paths(paths)?;
    let previous = read_sessions(paths)?
        .into_iter()
        .map(|session| (session.peer_node_id.clone(), session))
        .collect::<HashMap<_, _>>();
    let relay_endpoint = relay_endpoint(paths)?;
    let now = current_unix_seconds();
    let mut sessions = Vec::new();
    let mut remote_agents = Vec::new();

    for peer in peers {
        let prior = previous.get(&peer.peer_node_id);
        let selected_route = routes::selected_route_for_peer_from_paths(paths, &peer.peer_node_id)?;
        let session = session_from_peer(&peer, prior, &relay_endpoint, selected_route, now);
        if peer.status == TrustStatus::Trusted {
            remote_agents.push(remote_agent_from_peer(&peer, now));
        }
        sessions.push(session);
    }

    write_sessions(paths, &sessions)?;
    write_remote_agents(paths, &remote_agents)?;
    append_session_log(paths, &sessions, remote_agents.len())?;

    Ok(report_from_sessions(&sessions, remote_agents.len()))
}

/// Read remote runtime sessions.
pub fn list_remote_sessions(
    home_override: Option<PathBuf>,
) -> Result<Vec<RemoteSession>, SessionError> {
    let paths = StatePaths::resolve(home_override)?;
    read_sessions(&paths)
}

/// Read mirrored remote agent cards.
pub fn list_remote_agents(
    home_override: Option<PathBuf>,
) -> Result<Vec<RemoteAgentRecord>, SessionError> {
    let paths = StatePaths::resolve(home_override)?;
    read_remote_agents(&paths)
}

fn session_from_peer(
    peer: &TrustedPeer,
    prior: Option<&RemoteSession>,
    relay_endpoint: &str,
    selected_route: Option<routes::RouteRecord>,
    now: u64,
) -> RemoteSession {
    let state = if peer.status == TrustStatus::Trusted {
        RemoteSessionState::Connected
    } else {
        RemoteSessionState::Offline
    };
    let reconnect_attempts = match state {
        RemoteSessionState::Connected => 0,
        RemoteSessionState::Reconnecting => prior
            .map(|session| session.reconnect_attempts.saturating_add(1))
            .unwrap_or(1),
        RemoteSessionState::Offline => prior.map(|session| session.reconnect_attempts).unwrap_or(0),
    };
    let last_seen_unix = match state {
        RemoteSessionState::Connected => now,
        _ => prior.map(|session| session.last_seen_unix).unwrap_or(now),
    };
    let remote_agent_count = usize::from(peer.status == TrustStatus::Trusted);
    let (route, endpoint) = match selected_route {
        Some(route) if peer.status == TrustStatus::Trusted => {
            let route_label = match route.transport {
                RouteTransport::DirectQuic => "direct-quic",
                RouteTransport::RelayWebSocket => "relay-websocket",
            };
            (route_label.to_string(), route.endpoint)
        }
        _ => ("relay-websocket".to_string(), relay_endpoint.to_string()),
    };

    RemoteSession {
        peer_node_id: peer.peer_node_id.clone(),
        display_name: peer.display_name.clone(),
        state,
        route,
        relay_endpoint: endpoint,
        reconnect_attempts,
        remote_agent_count,
        last_seen_unix,
        updated_at_unix: now,
    }
}

fn remote_agent_from_peer(peer: &TrustedPeer, now: u64) -> RemoteAgentRecord {
    let suffix = identifier_suffix(&peer.peer_node_id);
    RemoteAgentRecord {
        agent_id: format!("agent.remote.{suffix}"),
        display_name: format!("{} remote agent", peer.display_name),
        peer_node_id: peer.peer_node_id.clone(),
        node_id: peer.peer_node_id.clone(),
        kind: "remote-agent".to_string(),
        presence: AgentPresence::Ready,
        last_seen_unix: now,
        capabilities: AgentCapabilities::basic(),
    }
}

fn report_from_sessions(sessions: &[RemoteSession], remote_agents: usize) -> SessionSyncReport {
    SessionSyncReport {
        sessions_synced: sessions.len(),
        remote_agents_synced: remote_agents,
        connected: sessions
            .iter()
            .filter(|session| session.state == RemoteSessionState::Connected)
            .count(),
        reconnecting: sessions
            .iter()
            .filter(|session| session.state == RemoteSessionState::Reconnecting)
            .count(),
        offline: sessions
            .iter()
            .filter(|session| session.state == RemoteSessionState::Offline)
            .count(),
    }
}

fn ensure_session_files(paths: &StatePaths) -> Result<(), SessionError> {
    fs::create_dir_all(&paths.sessions_dir).map_err(|error| {
        SessionError::io("create sessions directory", &paths.sessions_dir, error)
    })?;
    fs::create_dir_all(&paths.agents_dir)
        .map_err(|error| SessionError::io("create agents directory", &paths.agents_dir, error))?;
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| SessionError::io("create logs directory", &paths.logs_dir, error))
}

fn read_sessions(paths: &StatePaths) -> Result<Vec<RemoteSession>, SessionError> {
    if !paths.session_registry.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&paths.session_registry).map_err(|error| {
        SessionError::io("read session registry", &paths.session_registry, error)
    })?;
    parse_sessions(&contents)
}

fn write_sessions(paths: &StatePaths, sessions: &[RemoteSession]) -> Result<(), SessionError> {
    let mut sorted = sessions.to_vec();
    sorted.sort_by(|left, right| left.peer_node_id.cmp(&right.peer_node_id));
    let mut contents = format!(
        "# conU remote session registry\nversion = \"{}\"\n",
        SESSION_VERSION
    );

    for session in sorted {
        contents.push_str("\n[[session]]\n");
        contents.push_str(&format!(
            "peer_node_id = \"{}\"\n",
            escape_file_value(&session.peer_node_id)
        ));
        contents.push_str(&format!(
            "display_name = \"{}\"\n",
            escape_file_value(&session.display_name)
        ));
        contents.push_str(&format!("state = \"{}\"\n", session.state.as_str()));
        contents.push_str(&format!(
            "route = \"{}\"\n",
            escape_file_value(&session.route)
        ));
        contents.push_str(&format!(
            "relay_endpoint = \"{}\"\n",
            escape_file_value(&session.relay_endpoint)
        ));
        contents.push_str(&format!(
            "reconnect_attempts = {}\n",
            session.reconnect_attempts
        ));
        contents.push_str(&format!(
            "remote_agent_count = {}\n",
            session.remote_agent_count
        ));
        contents.push_str(&format!("last_seen_unix = {}\n", session.last_seen_unix));
        contents.push_str(&format!("updated_at_unix = {}\n", session.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    fs::write(&paths.session_registry, contents)
        .map_err(|error| SessionError::io("write session registry", &paths.session_registry, error))
}

fn read_remote_agents(paths: &StatePaths) -> Result<Vec<RemoteAgentRecord>, SessionError> {
    if !paths.remote_agent_registry.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&paths.remote_agent_registry).map_err(|error| {
        SessionError::io(
            "read remote agent registry",
            &paths.remote_agent_registry,
            error,
        )
    })?;
    parse_remote_agents(&contents)
}

fn write_remote_agents(
    paths: &StatePaths,
    agents: &[RemoteAgentRecord],
) -> Result<(), SessionError> {
    let mut sorted = agents.to_vec();
    sorted.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    let mut contents = format!(
        "# conU remote agent registry\nversion = \"{}\"\n",
        SESSION_VERSION
    );

    for agent in sorted {
        contents.push_str("\n[[remote_agent]]\n");
        contents.push_str(&format!(
            "agent_id = \"{}\"\n",
            escape_file_value(&agent.agent_id)
        ));
        contents.push_str(&format!(
            "display_name = \"{}\"\n",
            escape_file_value(&agent.display_name)
        ));
        contents.push_str(&format!(
            "peer_node_id = \"{}\"\n",
            escape_file_value(&agent.peer_node_id)
        ));
        contents.push_str(&format!(
            "node_id = \"{}\"\n",
            escape_file_value(&agent.node_id)
        ));
        contents.push_str(&format!("kind = \"{}\"\n", escape_file_value(&agent.kind)));
        contents.push_str(&format!("presence = \"{}\"\n", agent.presence.as_str()));
        contents.push_str(&format!("last_seen_unix = {}\n", agent.last_seen_unix));
        contents.push_str(&format!("cap_messages = {}\n", agent.capabilities.messages));
        contents.push_str(&format!("cap_streams = {}\n", agent.capabilities.streams));
        contents.push_str(&format!("cap_rooms = {}\n", agent.capabilities.rooms));
        contents.push_str(&format!("cap_files = {}\n", agent.capabilities.files));
        contents.push_str(&format!("cap_presence = {}\n", agent.capabilities.presence));
        contents.push_str("payload_displayed = false\n");
    }

    fs::write(&paths.remote_agent_registry, contents).map_err(|error| {
        SessionError::io(
            "write remote agent registry",
            &paths.remote_agent_registry,
            error,
        )
    })
}

fn parse_sessions(contents: &str) -> Result<Vec<RemoteSession>, SessionError> {
    let mut sessions = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[session]]" {
            if !current.is_empty() {
                sessions.push(session_from_values(&current)?);
                current.clear();
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        current.insert(key.trim().to_string(), clean_value(value));
    }

    if !current.is_empty() {
        sessions.push(session_from_values(&current)?);
    }

    Ok(sessions)
}

fn parse_remote_agents(contents: &str) -> Result<Vec<RemoteAgentRecord>, SessionError> {
    let mut agents = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[remote_agent]]" {
            if !current.is_empty() {
                agents.push(remote_agent_from_values(&current)?);
                current.clear();
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        current.insert(key.trim().to_string(), clean_value(value));
    }

    if !current.is_empty() {
        agents.push(remote_agent_from_values(&current)?);
    }

    Ok(agents)
}

fn session_from_values(values: &HashMap<String, String>) -> Result<RemoteSession, SessionError> {
    Ok(RemoteSession {
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        state: RemoteSessionState::from_str(&required(values, "state")?),
        route: validate_identifier(required(values, "route")?, "route")?,
        relay_endpoint: validate_endpoint(required(values, "relay_endpoint")?)?,
        reconnect_attempts: parse_u64(&required(values, "reconnect_attempts")?)?,
        remote_agent_count: parse_usize(&required(values, "remote_agent_count")?)?,
        last_seen_unix: parse_u64(&required(values, "last_seen_unix")?)?,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn remote_agent_from_values(
    values: &HashMap<String, String>,
) -> Result<RemoteAgentRecord, SessionError> {
    let presence = values
        .get("presence")
        .and_then(|value| match value.as_str() {
            "ready" => Some(AgentPresence::Ready),
            "busy" => Some(AgentPresence::Busy),
            "idle" => Some(AgentPresence::Idle),
            "offline" => Some(AgentPresence::Offline),
            _ => None,
        })
        .ok_or_else(|| SessionError::InvalidRecord {
            reason: "presence must be ready, busy, idle, or offline".to_string(),
        })?;

    Ok(RemoteAgentRecord {
        agent_id: validate_identifier(required(values, "agent_id")?, "agent id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        node_id: validate_identifier(required(values, "node_id")?, "node id")?,
        kind: validate_identifier(required(values, "kind")?, "kind")?,
        presence,
        last_seen_unix: parse_u64(&required(values, "last_seen_unix")?)?,
        capabilities: AgentCapabilities {
            messages: parse_bool(values.get("cap_messages")).unwrap_or(true),
            streams: parse_bool(values.get("cap_streams")).unwrap_or(false),
            rooms: parse_bool(values.get("cap_rooms")).unwrap_or(false),
            files: parse_bool(values.get("cap_files")).unwrap_or(false),
            presence: parse_bool(values.get("cap_presence")).unwrap_or(true),
        },
    })
}

fn relay_endpoint(paths: &StatePaths) -> Result<String, SessionError> {
    let contents = match fs::read_to_string(&paths.config) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DEFAULT_RELAY_ENDPOINT.to_string());
        }
        Err(error) => return Err(SessionError::io("read relay config", &paths.config, error)),
    };
    let values = parse_key_values(&contents);
    let endpoint = values
        .get("default_relay")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_RELAY_ENDPOINT.to_string());
    validate_endpoint(endpoint)
}

fn append_session_log(
    paths: &StatePaths,
    sessions: &[RemoteSession],
    remote_agents: usize,
) -> Result<(), SessionError> {
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| SessionError::io("create logs directory", &paths.logs_dir, error))?;
    let path = paths.logs_dir.join("sessions.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| SessionError::io("open session log", &path, error))?;
    let report = report_from_sessions(sessions, remote_agents);
    writeln!(
        file,
        "event=session_sync sessions={} connected={} reconnecting={} offline={} remote_agents={} payload=not_observed",
        report.sessions_synced,
        report.connected,
        report.reconnecting,
        report.offline,
        report.remote_agents_synced
    )
    .map_err(|error| SessionError::io("write session log", &path, error))
}

fn parse_key_values(contents: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_string(), clean_value(value));
    }

    values
}

fn clean_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, SessionError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| SessionError::InvalidRecord {
            reason: format!("missing {key}"),
        })
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, SessionError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(SessionError::InvalidRecord {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 140 {
        return Err(SessionError::InvalidRecord {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(SessionError::InvalidRecord {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_display_name(value: String) -> Result<String, SessionError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(SessionError::InvalidRecord {
            reason: "display name cannot be empty".to_string(),
        });
    }
    if value.len() > 120 {
        return Err(SessionError::InvalidRecord {
            reason: "display name is too long".to_string(),
        });
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(SessionError::InvalidRecord {
            reason: "display name cannot contain newlines".to_string(),
        });
    }
    Ok(value)
}

fn validate_endpoint(value: String) -> Result<String, SessionError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(SessionError::InvalidRecord {
            reason: "relay endpoint cannot be empty".to_string(),
        });
    }
    if value.len() > 200 {
        return Err(SessionError::InvalidRecord {
            reason: "relay endpoint is too long".to_string(),
        });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(SessionError::InvalidRecord {
            reason: "relay endpoint cannot contain whitespace".to_string(),
        });
    }
    Ok(value)
}

fn parse_u64(value: &str) -> Result<u64, SessionError> {
    value
        .parse::<u64>()
        .map_err(|_| SessionError::InvalidRecord {
            reason: "expected unsigned integer".to_string(),
        })
}

fn parse_usize(value: &str) -> Result<usize, SessionError> {
    value
        .parse::<usize>()
        .map_err(|_| SessionError::InvalidRecord {
            reason: "expected unsigned count".to_string(),
        })
}

fn parse_bool(value: Option<&String>) -> Option<bool> {
    match value?.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn identifier_suffix(value: &str) -> String {
    let sanitized = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect::<String>();
    sanitized
        .trim_start_matches("peer_")
        .chars()
        .take(32)
        .collect()
}

fn escape_file_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust;
    use std::env;
    use std::process;

    #[test]
    fn sync_creates_session_and_remote_agent_for_trusted_peer() {
        let home = test_home("sync-trusted");
        state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");

        let report = sync_remote_sessions(Some(home.clone())).expect("sync succeeds");
        let sessions = list_remote_sessions(Some(home.clone())).expect("sessions read");
        let remote_agents = list_remote_agents(Some(home)).expect("remote agents read");

        assert_eq!(report.connected, 1);
        assert_eq!(report.remote_agents_synced, 1);
        assert_eq!(sessions[0].peer_node_id, joined.peer.peer_node_id);
        assert_eq!(sessions[0].state, RemoteSessionState::Connected);
        assert_eq!(remote_agents[0].peer_node_id, joined.peer.peer_node_id);
        assert_eq!(remote_agents[0].presence, AgentPresence::Ready);
    }

    #[test]
    fn revoked_peer_is_offline_and_not_visible_as_remote_agent() {
        let home = test_home("sync-revoked");
        state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        trust::revoke_peer(Some(home.clone()), &joined.peer.peer_node_id).expect("revokes");

        let report = sync_remote_sessions(Some(home.clone())).expect("sync succeeds");
        let sessions = list_remote_sessions(Some(home.clone())).expect("sessions read");
        let remote_agents = list_remote_agents(Some(home)).expect("remote agents read");

        assert_eq!(report.offline, 1);
        assert_eq!(remote_agents.len(), 0);
        assert_eq!(sessions[0].state, RemoteSessionState::Offline);
        assert_eq!(sessions[0].remote_agent_count, 0);
    }

    #[test]
    fn session_log_is_payload_safe() {
        let home = test_home("session-log");
        state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");

        sync_remote_sessions(Some(home.clone())).expect("sync succeeds");
        let log = fs::read_to_string(home.join("logs").join("sessions.log")).expect("log reads");

        assert!(log.contains("payload=not_observed"));
        assert!(!log.contains("private message contents"));
        assert!(!log.contains("Review this code"));
    }

    fn test_home(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "conu-sessions-test-{}-{}-{name}",
            process::id(),
            current_unix_seconds()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }
}
