//! Remote runtime session and discovery state.
//!
//! Phase 9 keeps remote discovery file-backed and metadata-only. conUD owns
//! this mirror so the CLI can show trusted remote agents without reading or
//! transporting private payloads.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::AgentCapabilities;

use crate::agents::{self, AgentPresence, SignedAgentCard};
use crate::relay_endpoint::{self, RelayEndpointError};
use crate::routes::{self, RouteTransport};
use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus, TrustedPeer};
use crate::{direct_transport, relay_delivery};

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
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub signing_public_key_hex: Option<String>,
    pub signature_hex: Option<String>,
}

impl RemoteAgentRecord {
    pub fn agent_card_signed(&self) -> bool {
        self.signature_algorithm.as_deref() == Some(crate::security::AGENT_CARD_SIGNATURE_ALGORITHM)
            && self.signature_key_id.is_some()
            && self.signing_public_key_hex.is_some()
            && self.signature_hex.is_some()
    }
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
    Agent(agents::AgentError),
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

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
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

impl From<agents::AgentError> for SessionError {
    fn from(error: agents::AgentError) -> Self {
        Self::Agent(error)
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
    let previous_remote_agents = signed_remote_agents_by_peer(paths)?;
    let relay_endpoint = session_metadata_endpoint(&relay_endpoint(paths)?, "relay-websocket")?;
    let now = current_unix_seconds();
    let mut sessions = Vec::new();
    let mut remote_agents = Vec::new();

    for peer in peers {
        let prior = previous.get(&peer.peer_node_id);
        let signed_agents = previous_remote_agents
            .get(&peer.peer_node_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|agent| remote_agent_matches_trusted_peer(agent, &peer))
            .collect::<Vec<_>>();
        let remote_agent_count = if peer.status == TrustStatus::Trusted {
            signed_agents.len().max(1)
        } else {
            0
        };
        let selected_route = routes::selected_route_for_peer_from_paths(paths, &peer.peer_node_id)?;
        let session = session_from_peer(
            &peer,
            prior,
            &relay_endpoint,
            selected_route,
            remote_agent_count,
            now,
        );
        if peer.status == TrustStatus::Trusted {
            if signed_agents.is_empty() {
                remote_agents.push(remote_agent_from_peer(&peer, now));
            } else {
                remote_agents.extend(signed_agents.into_iter().map(|mut agent| {
                    agent.presence = AgentPresence::Ready;
                    agent.last_seen_unix = now;
                    agent
                }));
            }
        }
        sessions.push(session);
    }

    write_sessions(paths, &sessions)?;
    write_remote_agents(paths, &remote_agents)?;
    relay_delivery::queue_signed_agent_card_exchange_from_paths(paths, &local_node_id(paths)?)
        .map_err(|_| SessionError::InvalidRecord {
            reason: "failed to queue signed agent-card exchange".to_string(),
        })?;
    record_session_log(paths, &sessions, remote_agents.len());

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

/// Import and verify a signed remote agent card from a trusted peer node.
pub fn trust_remote_agent_card(
    home_override: Option<PathBuf>,
    card: SignedAgentCard,
) -> Result<RemoteAgentRecord, SessionError> {
    let init = state::init_state(home_override)?;
    ensure_session_files(&init.paths)?;
    validate_signed_agent_card_shape(&card)?;
    if !agents::verify_signed_agent_card(&card)? {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card signature does not verify".to_string(),
        });
    }

    let Some(trusted_peer) = trust::list_peers(Some(init.paths.home.clone()))?
        .into_iter()
        .find(|peer| peer.peer_node_id == card.node_id && peer.status == TrustStatus::Trusted)
    else {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent node is not trusted".to_string(),
        });
    };
    validate_agent_card_peer_binding(&card, &trusted_peer)?;

    let mut agents = read_remote_agents(&init.paths)?;
    if agents
        .iter()
        .any(|agent| agent.agent_id == card.agent_id && agent.peer_node_id != card.node_id)
    {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent id is already used by another peer".to_string(),
        });
    }

    let now = current_unix_seconds();
    let record = remote_agent_from_signed_card(card, now);
    agents.retain(|agent| {
        if agent.peer_node_id != record.peer_node_id {
            return true;
        }
        agent.agent_card_signed() && agent.agent_id != record.agent_id
    });
    agents.push(record.clone());
    write_remote_agents(&init.paths, &agents)?;

    Ok(record)
}

fn session_from_peer(
    peer: &TrustedPeer,
    prior: Option<&RemoteSession>,
    relay_endpoint: &str,
    selected_route: Option<routes::RouteRecord>,
    remote_agent_count: usize,
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
        signature_algorithm: None,
        signature_key_id: None,
        signing_public_key_hex: None,
        signature_hex: None,
    }
}

fn remote_agent_from_signed_card(card: SignedAgentCard, now: u64) -> RemoteAgentRecord {
    RemoteAgentRecord {
        agent_id: card.agent_id,
        display_name: card.display_name,
        peer_node_id: card.node_id.clone(),
        node_id: card.node_id,
        kind: card.kind,
        presence: AgentPresence::Ready,
        last_seen_unix: now,
        capabilities: card.capabilities,
        signature_algorithm: Some(card.signature_algorithm),
        signature_key_id: Some(card.signature_key_id),
        signing_public_key_hex: Some(card.signing_public_key_hex),
        signature_hex: Some(card.signature_hex),
    }
}

fn signed_remote_agents_by_peer(
    paths: &StatePaths,
) -> Result<HashMap<String, Vec<RemoteAgentRecord>>, SessionError> {
    let mut by_peer: HashMap<String, Vec<RemoteAgentRecord>> = HashMap::new();
    for agent in read_remote_agents(paths)? {
        if agent.agent_card_signed() {
            by_peer
                .entry(agent.peer_node_id.clone())
                .or_default()
                .push(agent);
        }
    }
    Ok(by_peer)
}

fn validate_agent_card_peer_binding(
    card: &SignedAgentCard,
    peer: &TrustedPeer,
) -> Result<(), SessionError> {
    let Some(peer_signing_key) = peer.signing_public_key_hex.as_deref() else {
        return Err(SessionError::InvalidRecord {
            reason: "trusted peer card does not include a signing key".to_string(),
        });
    };
    if peer_signing_key != card.signing_public_key_hex {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card signing key does not match trusted peer".to_string(),
        });
    }
    Ok(())
}

fn remote_agent_matches_trusted_peer(agent: &RemoteAgentRecord, peer: &TrustedPeer) -> bool {
    peer.status == TrustStatus::Trusted
        && peer.signing_public_key_hex.as_deref() == agent.signing_public_key_hex.as_deref()
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
    state::ensure_state_directory(&paths.sessions_dir)?;
    state::ensure_state_directory(&paths.agents_dir)?;
    state::ensure_state_directory(&paths.logs_dir)?;
    Ok(())
}

fn local_node_id(paths: &StatePaths) -> Result<String, SessionError> {
    state::read_state(Some(paths.home.clone()))?
        .node
        .map(|node| node.node_id)
        .ok_or_else(|| SessionError::InvalidRecord {
            reason: "local node identity is missing".to_string(),
        })
}

fn read_sessions(paths: &StatePaths) -> Result<Vec<RemoteSession>, SessionError> {
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.session_registry,
        "inspect session registry",
        "read session registry",
    )?
    else {
        return Ok(Vec::new());
    };
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
        let relay_endpoint = session_metadata_endpoint(&session.relay_endpoint, &session.route)?;
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
            escape_file_value(&relay_endpoint)
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

    state::write_regular_state_file(
        &paths.session_registry,
        &contents,
        "inspect session registry",
        "create session registry",
        "open session registry",
        "write session registry",
    )?;
    Ok(())
}

fn read_remote_agents(paths: &StatePaths) -> Result<Vec<RemoteAgentRecord>, SessionError> {
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.remote_agent_registry,
        "inspect remote agent registry",
        "read remote agent registry",
    )?
    else {
        return Ok(Vec::new());
    };
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
        if let Some(value) = &agent.signature_algorithm {
            contents.push_str(&format!(
                "signature_algorithm = \"{}\"\n",
                escape_file_value(value)
            ));
        }
        if let Some(value) = &agent.signature_key_id {
            contents.push_str(&format!(
                "signature_key_id = \"{}\"\n",
                escape_file_value(value)
            ));
        }
        if let Some(value) = &agent.signing_public_key_hex {
            contents.push_str(&format!(
                "signing_public_key_hex = \"{}\"\n",
                escape_file_value(value)
            ));
        }
        if let Some(value) = &agent.signature_hex {
            contents.push_str(&format!(
                "signature_hex = \"{}\"\n",
                escape_file_value(value)
            ));
        }
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.remote_agent_registry,
        &contents,
        "inspect remote agent registry",
        "create remote agent registry",
        "open remote agent registry",
        "write remote agent registry",
    )?;
    Ok(())
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
        insert_session_value(&mut current, key, value)?;
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
        insert_session_value(&mut current, key, value)?;
    }

    if !current.is_empty() {
        agents.push(remote_agent_from_values(&current)?);
    }

    Ok(agents)
}

fn session_from_values(values: &HashMap<String, String>) -> Result<RemoteSession, SessionError> {
    let route = validate_identifier(required(values, "route")?, "route")?;
    let relay_endpoint = session_metadata_endpoint(&required(values, "relay_endpoint")?, &route)?;
    Ok(RemoteSession {
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        state: RemoteSessionState::from_str(&required(values, "state")?),
        route,
        relay_endpoint,
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

    let mut record = RemoteAgentRecord {
        agent_id: validate_identifier(required(values, "agent_id")?, "agent id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        node_id: validate_identifier(required(values, "node_id")?, "node id")?,
        kind: validate_identifier(required(values, "kind")?, "kind")?,
        presence,
        last_seen_unix: parse_u64(&required(values, "last_seen_unix")?)?,
        capabilities: AgentCapabilities {
            messages: parse_capability_bool(values, "cap_messages", true)?,
            streams: parse_capability_bool(values, "cap_streams", false)?,
            rooms: parse_capability_bool(values, "cap_rooms", false)?,
            files: parse_capability_bool(values, "cap_files", false)?,
            presence: parse_capability_bool(values, "cap_presence", true)?,
        },
        signature_algorithm: optional_clean(values.get("signature_algorithm")),
        signature_key_id: optional_clean(values.get("signature_key_id")),
        signing_public_key_hex: optional_clean(values.get("signing_public_key_hex")),
        signature_hex: optional_clean(values.get("signature_hex")),
    };

    validate_remote_agent_signature_state(&mut record)?;
    Ok(record)
}

fn validate_signed_agent_card_shape(card: &SignedAgentCard) -> Result<(), SessionError> {
    validate_identifier(card.agent_id.clone(), "agent id")?;
    validate_display_name(card.display_name.clone())?;
    validate_identifier(card.node_id.clone(), "node id")?;
    validate_identifier(card.kind.clone(), "kind")?;
    validate_identifier(card.signature_algorithm.clone(), "signature algorithm")?;
    validate_identifier(card.signature_key_id.clone(), "signature key id")?;
    validate_identifier(card.signing_public_key_hex.clone(), "signing public key")?;
    validate_identifier(card.signature_hex.clone(), "signature")?;
    Ok(())
}

fn validate_remote_agent_signature_state(
    record: &mut RemoteAgentRecord,
) -> Result<(), SessionError> {
    let signature_fields = [
        record.signature_algorithm.is_some(),
        record.signature_key_id.is_some(),
        record.signing_public_key_hex.is_some(),
        record.signature_hex.is_some(),
    ];
    let populated = signature_fields.iter().filter(|present| **present).count();
    if populated == 0 {
        return Ok(());
    }
    if populated != signature_fields.len() {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent signature metadata is incomplete".to_string(),
        });
    }
    if record.peer_node_id != record.node_id {
        return Err(SessionError::InvalidRecord {
            reason: "signed remote agent peer node does not match card node".to_string(),
        });
    }

    let card = signed_agent_card_from_remote_record(record)?;
    validate_signed_agent_card_shape(&card)?;
    if !agents::verify_signed_agent_card(&card)? {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card signature does not verify".to_string(),
        });
    }

    Ok(())
}

fn signed_agent_card_from_remote_record(
    record: &RemoteAgentRecord,
) -> Result<SignedAgentCard, SessionError> {
    let Some(signature_algorithm) = record.signature_algorithm.clone() else {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card is missing signature algorithm".to_string(),
        });
    };
    let Some(signature_key_id) = record.signature_key_id.clone() else {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card is missing signature key id".to_string(),
        });
    };
    let Some(signing_public_key_hex) = record.signing_public_key_hex.clone() else {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card is missing signing public key".to_string(),
        });
    };
    let Some(signature_hex) = record.signature_hex.clone() else {
        return Err(SessionError::InvalidRecord {
            reason: "remote agent card is missing signature".to_string(),
        });
    };

    Ok(SignedAgentCard {
        agent_id: record.agent_id.clone(),
        display_name: record.display_name.clone(),
        node_id: record.node_id.clone(),
        kind: record.kind.clone(),
        capabilities: record.capabilities.clone(),
        signature_algorithm,
        signature_key_id,
        signing_public_key_hex,
        signature_hex,
    })
}

fn relay_endpoint(paths: &StatePaths) -> Result<String, SessionError> {
    let contents = match state::read_optional_regular_state_file(
        &paths.config,
        "inspect relay config",
        "read relay config",
    )? {
        Some(contents) => contents,
        None => return Ok(DEFAULT_RELAY_ENDPOINT.to_string()),
    };
    let values = parse_key_values(&contents);
    let endpoint = values
        .get("default_relay")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_RELAY_ENDPOINT.to_string());
    validate_endpoint(endpoint, "relay-websocket")
}

fn append_session_log(
    paths: &StatePaths,
    sessions: &[RemoteSession],
    remote_agents: usize,
) -> Result<(), SessionError> {
    state::ensure_state_directory(&paths.logs_dir)?;
    let path = paths.logs_dir.join("sessions.log");
    let report = report_from_sessions(sessions, remote_agents);
    let line = format!(
        "event=session_sync sessions={} connected={} reconnecting={} offline={} remote_agents={} payload=not_observed",
        report.sessions_synced,
        report.connected,
        report.reconnecting,
        report.offline,
        report.remote_agents_synced
    );

    state::append_regular_state_file(
        &path,
        &(line + "\n"),
        "inspect session log",
        "create session log",
        "open session log",
        "write session log",
    )?;
    Ok(())
}

fn record_session_log(paths: &StatePaths, sessions: &[RemoteSession], remote_agents: usize) {
    let _ = append_session_log(paths, sessions, remote_agents);
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

fn optional_clean(value: Option<&String>) -> Option<String> {
    value.map(|value| value.trim().to_string()).filter(|value| {
        !value.is_empty() && !matches!(value.as_str(), "none" | "null" | "not available")
    })
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

fn insert_session_value(
    values: &mut HashMap<String, String>,
    key: &str,
    value: &str,
) -> Result<(), SessionError> {
    let key = key.trim();
    if values.contains_key(key) {
        let reason = if key.is_empty() {
            "duplicate empty session key".to_string()
        } else {
            format!("duplicate session key {key}")
        };
        return Err(SessionError::InvalidRecord { reason });
    }
    values.insert(key.to_string(), clean_value(value));
    Ok(())
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

fn validate_endpoint(value: String, route: &str) -> Result<String, SessionError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(SessionError::InvalidRecord {
            reason: "relay endpoint cannot be empty".to_string(),
        });
    }
    match route {
        "direct-quic" => {
            direct_transport::validate_direct_peer_endpoint(&value).map_err(|_| {
                SessionError::InvalidRecord {
                    reason: "session endpoint is invalid".to_string(),
                }
            })?;
            Ok(value)
        }
        _ => relay_endpoint::validate_relay_endpoint(value).map_err(|error| {
            let reason = match error {
                RelayEndpointError::Empty => "relay endpoint cannot be empty",
                RelayEndpointError::Scheme => "relay endpoint must start with ws:// or wss://",
                RelayEndpointError::Invalid => "relay endpoint is invalid",
            };
            SessionError::InvalidRecord {
                reason: reason.to_string(),
            }
        }),
    }
}

fn session_metadata_endpoint(value: &str, route: &str) -> Result<String, SessionError> {
    let value = value.trim().to_string();
    if route == "direct-quic" {
        return validate_endpoint(value, route);
    }
    relay_endpoint::metadata_relay_endpoint(&value).map_err(|error| {
        let reason = match error {
            RelayEndpointError::Empty => "relay endpoint cannot be empty",
            RelayEndpointError::Scheme => "relay endpoint must start with ws:// or wss://",
            RelayEndpointError::Invalid => "relay endpoint is invalid",
        };
        SessionError::InvalidRecord {
            reason: reason.to_string(),
        }
    })
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

fn parse_capability_bool(
    values: &HashMap<String, String>,
    key: &'static str,
    default: bool,
) -> Result<bool, SessionError> {
    let Some(value) = values.get(key) else {
        return Ok(default);
    };
    match value.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(SessionError::InvalidRecord {
            reason: format!("{key} must be true or false"),
        }),
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
    use crate::agents::{self, AgentRegistration};
    use crate::policy::{self, PeerPolicyUpdate};
    use crate::relay_delivery;
    use crate::security;
    use crate::trust;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
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

    #[test]
    fn session_sync_rejects_secret_bearing_relay_endpoint_without_echoing_value() {
        let home = test_home("session-secret-relay-config");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        let secret_endpoint = "wss://user:secret@relay.example.com/conu?token=private#fragment";
        fs::write(
            &init.paths.config,
            format!("version = \"1\"\ndefault_relay = \"{secret_endpoint}\"\n"),
        )
        .expect("config writes");

        let error = sync_remote_sessions(Some(home))
            .expect_err("secret-bearing relay endpoint should fail");
        let rendered = error.to_string();

        assert!(rendered.contains("relay endpoint is invalid"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("token=private"));
    }

    #[test]
    fn session_metadata_hides_relay_endpoint_path_segments() {
        let home = test_home("session-relay-path-config");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        let relay_endpoint = "wss://relay.example.com/conu/private-token";
        fs::write(
            &init.paths.config,
            format!("version = \"1\"\ndefault_relay = \"{relay_endpoint}\"\n"),
        )
        .expect("config writes");

        let report = sync_remote_sessions(Some(home.clone())).expect("sync succeeds");
        let sessions = list_remote_sessions(Some(home.clone())).expect("sessions read");
        let registry =
            fs::read_to_string(init.paths.session_registry).expect("session registry reads");

        assert_eq!(report.connected, 1);
        assert_eq!(sessions[0].relay_endpoint, "wss://relay.example.com");
        assert!(registry.contains("wss://relay.example.com"));
        assert!(!registry.contains("private-token"));
        assert!(!registry.contains("/conu"));
        assert!(!registry.contains(relay_endpoint));
    }

    #[test]
    fn session_sync_success_does_not_depend_on_session_log_write() {
        let home = test_home("session-log-collision");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        let session_log = init.paths.logs_dir.join("sessions.log");
        fs::create_dir(&session_log).expect("session log collision creates");

        let report = sync_remote_sessions(Some(home.clone())).expect("sync succeeds");
        let sessions = list_remote_sessions(Some(home)).expect("sessions read");

        assert_eq!(report.connected, 1);
        assert_eq!(sessions[0].peer_node_id, joined.peer.peer_node_id);
        assert!(session_log.is_dir());
    }

    #[test]
    fn session_registry_duplicate_key_fails_closed_without_payloads() {
        let home = test_home("session-duplicate-key");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        fs::write(
            &init.paths.session_registry,
            "# conU remote session registry\nversion = \"1\"\n\n[[session]]\npeer_node_id = \"node.safe\"\npeer_node_id = \"secret private session contents\"\ndisplay_name = \"Safe Peer\"\nstate = \"connected\"\nroute = \"relay-websocket\"\nrelay_endpoint = \"wss://relay.example.com\"\nreconnect_attempts = 0\nremote_agent_count = 1\nlast_seen_unix = 1\nupdated_at_unix = 1\npayload_displayed = false\n",
        )
        .expect("duplicate session registry writes");

        let error =
            list_remote_sessions(Some(home)).expect_err("duplicate session key fails closed");

        assert!(
            error
                .to_string()
                .contains("duplicate session key peer_node_id")
        );
        assert!(
            !error
                .to_string()
                .contains("secret private session contents")
        );
    }

    #[test]
    fn remote_agent_registry_duplicate_key_fails_closed_without_payloads() {
        let home = test_home("remote-agent-duplicate-key");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        fs::write(
            &init.paths.remote_agent_registry,
            "# conU remote agent registry\nversion = \"1\"\n\n[[remote_agent]]\nagent_id = \"agent.safe\"\ndisplay_name = \"Safe Agent\"\npeer_node_id = \"node.safe\"\nnode_id = \"node.safe\"\nkind = \"test-agent\"\npresence = \"ready\"\nlast_seen_unix = 1\ncap_messages = true\ncap_messages = \"secret private agent contents\"\ncap_streams = false\ncap_rooms = false\ncap_files = false\ncap_presence = true\npayload_displayed = false\n",
        )
        .expect("duplicate remote agent registry writes");

        let error =
            list_remote_agents(Some(home)).expect_err("duplicate remote agent key fails closed");

        assert!(
            error
                .to_string()
                .contains("duplicate session key cap_messages")
        );
        assert!(!error.to_string().contains("secret private agent contents"));
    }

    #[cfg(unix)]
    #[test]
    fn session_registry_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("session-registry-symlink");
        state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-session-registry");
        let outside_contents = "outside session registry\n";
        fs::write(&outside, outside_contents).expect("outside registry writes");
        symlink(&outside, &paths.session_registry).expect("session registry symlink creates");

        let error =
            sync_remote_sessions(Some(home)).expect_err("symlinked session registry fails closed");

        assert!(error.to_string().contains("inspect session registry"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside registry reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.session_registry)
                .expect("session registry metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_agent_registry_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("remote-agent-registry-symlink");
        state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-remote-agent-registry");
        let outside_contents = "outside remote agent registry\n";
        fs::write(&outside, outside_contents).expect("outside registry writes");
        symlink(&outside, &paths.remote_agent_registry)
            .expect("remote agent registry symlink creates");

        let error = sync_remote_sessions(Some(home))
            .expect_err("symlinked remote agent registry fails closed");

        assert!(error.to_string().contains("inspect remote agent registry"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside registry reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.remote_agent_registry)
                .expect("remote agent registry metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn trusted_signed_remote_agent_card_survives_session_sync() {
        let alice_home = test_home("signed-remote-alice");
        let bob_home = test_home("signed-remote-bob");
        state::init_state(Some(alice_home.clone())).expect("alice initializes");
        state::init_state(Some(bob_home.clone())).expect("bob initializes");
        let bob_peer = trust::export_peer_card(Some(bob_home.clone())).expect("bob peer card");
        trust::trust_peer_card(Some(alice_home.clone()), bob_peer).expect("alice trusts bob");
        register_agent(&bob_home, "agent.bob", true, true);
        let bob_agent_card =
            agents::export_agent_card(Some(bob_home), "agent.bob").expect("agent card exports");

        let imported = trust_remote_agent_card(Some(alice_home.clone()), bob_agent_card)
            .expect("signed remote agent imports");
        let report = sync_remote_sessions(Some(alice_home.clone())).expect("sessions sync");
        let remote_agents = list_remote_agents(Some(alice_home)).expect("remote agents read");

        assert_eq!(imported.agent_id, "agent.bob");
        assert!(imported.agent_card_signed());
        assert!(imported.capabilities.streams);
        assert!(imported.capabilities.rooms);
        assert_eq!(report.remote_agents_synced, 1);
        assert_eq!(remote_agents.len(), 1);
        assert_eq!(remote_agents[0].agent_id, "agent.bob");
        assert!(remote_agents[0].agent_card_signed());
        assert!(remote_agents[0].capabilities.streams);
        assert!(remote_agents[0].capabilities.rooms);
    }

    #[test]
    fn session_sync_queues_signed_agent_cards_without_payloads() {
        let alice_home = test_home("auto-card-alice");
        let bob_home = test_home("auto-card-bob");
        state::init_state(Some(alice_home.clone())).expect("alice initializes");
        state::init_state(Some(bob_home.clone())).expect("bob initializes");
        let bob_peer = trust::export_peer_card(Some(bob_home)).expect("bob peer card");
        trust::trust_peer_card(Some(alice_home.clone()), bob_peer.clone())
            .expect("alice trusts bob");
        policy::set_peer_policy(
            Some(alice_home.clone()),
            &bob_peer.node_id,
            PeerPolicyUpdate {
                messages: Some(true),
                streams: Some(true),
                rooms: Some(false),
                files: Some(false),
                mailbox: Some(false),
            },
        )
        .expect("policy grants");
        register_agent(&alice_home, "agent.alice", true, false);

        sync_remote_sessions(Some(alice_home.clone())).expect("sessions sync");
        let queue =
            relay_delivery::relay_queue_summary(Some(alice_home.clone())).expect("queue reads");
        let outbox = read_relay_outbox(&alice_home);

        assert_eq!(queue.queued, 1);
        assert!(outbox.contains("kind = \"agent_card\""));
        assert!(outbox.contains("payload_displayed = false"));
        assert!(!outbox.contains("conu-agent-card-v1"));
        assert!(!outbox.contains("signature_hex"));
        assert!(!outbox.contains("private message contents"));
    }

    #[test]
    fn tampered_signed_remote_agent_card_is_rejected() {
        let alice_home = test_home("signed-remote-tamper-alice");
        let bob_home = test_home("signed-remote-tamper-bob");
        state::init_state(Some(alice_home.clone())).expect("alice initializes");
        state::init_state(Some(bob_home.clone())).expect("bob initializes");
        let bob_peer = trust::export_peer_card(Some(bob_home.clone())).expect("bob peer card");
        trust::trust_peer_card(Some(alice_home.clone()), bob_peer).expect("alice trusts bob");
        register_agent(&bob_home, "agent.bob", true, false);
        let mut bob_agent_card =
            agents::export_agent_card(Some(bob_home), "agent.bob").expect("agent card exports");
        bob_agent_card.capabilities.rooms = true;

        let error = trust_remote_agent_card(Some(alice_home), bob_agent_card)
            .expect_err("tampered signed remote agent is rejected");

        assert!(error.to_string().contains("signature"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn signed_remote_agent_card_must_match_trusted_peer_signing_key() {
        let alice_home = test_home("signed-remote-wrong-key-alice");
        let bob_home = test_home("signed-remote-wrong-key-bob");
        let alice_init = state::init_state(Some(alice_home.clone())).expect("alice initializes");
        state::init_state(Some(bob_home.clone())).expect("bob initializes");
        let bob_peer = trust::export_peer_card(Some(bob_home)).expect("bob peer card");
        let bob_node_id = bob_peer.node_id.clone();
        trust::trust_peer_card(Some(alice_home.clone()), bob_peer).expect("alice trusts bob");

        let capabilities = AgentCapabilities::basic();
        let canonical = canonical_test_agent_card(
            "agent.bob",
            "Bob",
            &bob_node_id,
            "test-agent",
            &capabilities,
        );
        let signature = security::sign_agent_card_from_paths(&alice_init.paths, &canonical)
            .expect("wrong-key card signs");
        let card = SignedAgentCard {
            agent_id: "agent.bob".to_string(),
            display_name: "Bob".to_string(),
            node_id: bob_node_id,
            kind: "test-agent".to_string(),
            capabilities,
            signature_algorithm: signature.algorithm,
            signature_key_id: signature.key_id,
            signing_public_key_hex: signature.public_key_hex,
            signature_hex: signature.signature_hex,
        };

        let error = trust_remote_agent_card(Some(alice_home), card)
            .expect_err("wrong peer signing key is rejected");

        assert!(error.to_string().contains("signing key"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn malformed_remote_agent_capability_is_rejected() {
        let values = parse_key_values(
            "agent_id = \"agent.bob\"\n\
display_name = \"Bob\"\n\
peer_node_id = \"node.bob\"\n\
node_id = \"node.bob\"\n\
kind = \"test-agent\"\n\
presence = \"ready\"\n\
last_seen_unix = 1\n\
cap_messages = maybe\n",
        );

        let error = remote_agent_from_values(&values)
            .expect_err("malformed remote capability should fail closed");
        let rendered = error.to_string();

        assert!(rendered.contains("cap_messages must be true or false"));
        assert!(!rendered.contains("maybe"));
    }

    fn register_agent(home: &Path, agent_id: &str, streams: bool, rooms: bool) {
        let mut registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid registration");
        registration.capabilities.streams = streams;
        registration.capabilities.rooms = rooms;
        agents::submit_registration(Some(home.to_path_buf()), registration)
            .expect("registration submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("registration processes");
    }

    fn read_relay_outbox(home: &Path) -> String {
        let outbox = home.join("mailbox").join("relay").join("outbox");
        let mut contents = String::new();
        for entry in fs::read_dir(outbox).expect("outbox reads") {
            let path = entry.expect("outbox entry reads").path();
            if path.extension().and_then(|value| value.to_str()) == Some("relay") {
                contents.push_str(&fs::read_to_string(path).expect("outbox file reads"));
            }
        }
        contents
    }

    fn canonical_test_agent_card(
        agent_id: &str,
        display_name: &str,
        node_id: &str,
        kind: &str,
        capabilities: &AgentCapabilities,
    ) -> String {
        format!(
            "conu-agent-card-v1\nagent_id={}\ndisplay_name={}\nnode_id={}\nkind={}\ncap_messages={}\ncap_streams={}\ncap_rooms={}\ncap_files={}\ncap_presence={}\n",
            agent_id,
            display_name,
            node_id,
            kind,
            capabilities.messages,
            capabilities.streams,
            capabilities.rooms,
            capabilities.files,
            capabilities.presence
        )
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
