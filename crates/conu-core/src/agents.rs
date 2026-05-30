//! Local agent gateway and registry.
//!
//! Phase 5 implements metadata-only registration through a file-backed local
//! gateway. It does not route messages or store agent payloads.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::AgentCapabilities;

use crate::security::{self, SecurityError};
use crate::state::{self, StateError, StatePaths};

const REQUEST_VERSION: &str = "1";

/// Presence state published by a local agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPresence {
    Ready,
    Busy,
    Idle,
    Offline,
}

impl AgentPresence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Busy => "busy",
            Self::Idle => "idle",
            Self::Offline => "offline",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "ready" => Some(Self::Ready),
            "busy" => Some(Self::Busy),
            "idle" => Some(Self::Idle),
            "offline" => Some(Self::Offline),
            _ => None,
        }
    }
}

/// Metadata a local agent submits to conUD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub display_name: String,
    pub kind: String,
    pub capabilities: AgentCapabilities,
}

impl AgentRegistration {
    pub fn new(
        agent_id: impl Into<String>,
        display_name: impl Into<String>,
        kind: impl Into<String>,
    ) -> Result<Self, AgentError> {
        let agent_id = validate_identifier(agent_id.into(), "agent id")?;
        let display_name = validate_display_name(display_name.into())?;
        let kind = validate_kind(kind.into())?;

        Ok(Self {
            agent_id,
            display_name,
            kind,
            capabilities: AgentCapabilities::basic(),
        })
    }
}

/// Metadata a local agent submits to refresh presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceHeartbeat {
    pub agent_id: String,
    pub presence: AgentPresence,
}

impl PresenceHeartbeat {
    pub fn new(agent_id: impl Into<String>, presence: AgentPresence) -> Result<Self, AgentError> {
        Ok(Self {
            agent_id: validate_identifier(agent_id.into(), "agent id")?,
            presence,
        })
    }
}

/// Persisted local agent card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAgentRecord {
    pub agent_id: String,
    pub display_name: String,
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

/// Public signed local agent card that can be imported by a trusted peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAgentCard {
    pub agent_id: String,
    pub display_name: String,
    pub node_id: String,
    pub kind: String,
    pub capabilities: AgentCapabilities,
    pub signature_algorithm: String,
    pub signature_key_id: String,
    pub signing_public_key_hex: String,
    pub signature_hex: String,
}

/// Result of submitting an IPC-style request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySubmission {
    pub request_id: String,
    pub request_path: PathBuf,
}

/// Result of conUD processing local gateway requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayProcessReport {
    pub processed: usize,
    pub rejected: usize,
    pub registered_agents: Vec<String>,
    pub heartbeat_agents: Vec<String>,
}

/// Errors produced by local agent gateway and registry operations.
#[derive(Debug)]
pub enum AgentError {
    State(StateError),
    Security(SecurityError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRequest {
        reason: String,
    },
}

impl AgentError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Security(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRequest { reason } => write!(formatter, "invalid agent request: {reason}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<StateError> for AgentError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<SecurityError> for AgentError {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}

/// Submit a local agent registration request to the conUD gateway inbox.
pub fn submit_registration(
    home_override: Option<PathBuf>,
    registration: AgentRegistration,
) -> Result<GatewaySubmission, AgentError> {
    let init = state::init_state(home_override)?;
    let request_id = request_id("register");
    let request_path = init.paths.ipc_inbox_dir.join(format!("{request_id}.req"));
    let contents = render_registration_request(&request_id, &registration);
    write_new_file(&request_path, &contents)?;

    Ok(GatewaySubmission {
        request_id,
        request_path,
    })
}

/// Submit a local agent presence heartbeat request to the conUD gateway inbox.
pub fn submit_presence_heartbeat(
    home_override: Option<PathBuf>,
    heartbeat: PresenceHeartbeat,
) -> Result<GatewaySubmission, AgentError> {
    let init = state::init_state(home_override)?;
    let request_id = request_id("presence");
    let request_path = init.paths.ipc_inbox_dir.join(format!("{request_id}.req"));
    let contents = render_presence_request(&request_id, &heartbeat);
    write_new_file(&request_path, &contents)?;

    Ok(GatewaySubmission {
        request_id,
        request_path,
    })
}

/// Process pending gateway requests using the default state path resolution.
pub fn process_gateway_requests(
    home_override: Option<PathBuf>,
) -> Result<GatewayProcessReport, AgentError> {
    let init = state::init_state(home_override)?;
    process_gateway_requests_from_paths(&init.paths, &init.node.node_id)
}

/// Process pending gateway requests from already resolved state paths.
pub fn process_gateway_requests_from_paths(
    paths: &StatePaths,
    node_id: &str,
) -> Result<GatewayProcessReport, AgentError> {
    fs::create_dir_all(&paths.ipc_inbox_dir)
        .map_err(|error| AgentError::io("create IPC inbox", &paths.ipc_inbox_dir, error))?;
    fs::create_dir_all(&paths.ipc_processed_dir).map_err(|error| {
        AgentError::io(
            "create IPC processed directory",
            &paths.ipc_processed_dir,
            error,
        )
    })?;
    fs::create_dir_all(&paths.ipc_rejected_dir).map_err(|error| {
        AgentError::io(
            "create IPC rejected directory",
            &paths.ipc_rejected_dir,
            error,
        )
    })?;

    let mut report = GatewayProcessReport {
        processed: 0,
        rejected: 0,
        registered_agents: Vec::new(),
        heartbeat_agents: Vec::new(),
    };

    for request_path in pending_requests(paths)? {
        match process_one_request(paths, node_id, &request_path) {
            Ok(ProcessedRequest::Registered(agent_id)) => {
                report.processed += 1;
                report.registered_agents.push(agent_id);
                move_request(&request_path, &paths.ipc_processed_dir)?;
            }
            Ok(ProcessedRequest::Presence(agent_id)) => {
                report.processed += 1;
                report.heartbeat_agents.push(agent_id);
                move_request(&request_path, &paths.ipc_processed_dir)?;
            }
            Err(error) => {
                report.rejected += 1;
                reject_request(&request_path, &paths.ipc_rejected_dir, &error)?;
            }
        }
    }

    Ok(report)
}

/// Read the persisted local agent registry.
pub fn list_local_agents(
    home_override: Option<PathBuf>,
) -> Result<Vec<LocalAgentRecord>, AgentError> {
    let paths = StatePaths::resolve(home_override)?;
    read_registry(&paths)
}

/// Return true when an agent exists in the persisted registry.
pub fn agent_exists(home_override: Option<PathBuf>, agent_id: &str) -> Result<bool, AgentError> {
    Ok(list_local_agents(home_override)?
        .iter()
        .any(|agent| agent.agent_id == agent_id))
}

/// Export a public signed local agent card for trusted-peer import.
pub fn export_agent_card(
    home_override: Option<PathBuf>,
    agent_id: &str,
) -> Result<SignedAgentCard, AgentError> {
    let agent_id = validate_identifier(agent_id.to_string(), "agent id")?;
    let agents = list_local_agents(home_override)?;
    let agent = agents
        .iter()
        .find(|agent| agent.agent_id == agent_id)
        .ok_or_else(|| AgentError::InvalidRequest {
            reason: "agent is not registered locally".to_string(),
        })?;
    let card = signed_agent_card_from_record(agent)?;
    if !verify_signed_agent_card(&card)? {
        return Err(AgentError::InvalidRequest {
            reason: "local agent card signature does not verify".to_string(),
        });
    }
    Ok(card)
}

/// Export all public signed local agent cards.
pub fn export_agent_cards(
    home_override: Option<PathBuf>,
) -> Result<Vec<SignedAgentCard>, AgentError> {
    let agents = list_local_agents(home_override)?;
    agents.iter().map(signed_agent_card_from_record).collect()
}

/// Render a signed agent card as metadata-only key/value text for encrypted
/// control-plane exchange.
pub fn render_signed_agent_card_metadata(card: &SignedAgentCard) -> String {
    format!(
        "version = \"1\"\ntype = \"signed_agent_card\"\nagent_id = \"{}\"\ndisplay_name = \"{}\"\nnode_id = \"{}\"\nkind = \"{}\"\ncap_messages = {}\ncap_streams = {}\ncap_rooms = {}\ncap_files = {}\ncap_presence = {}\nsignature_algorithm = \"{}\"\nsignature_key_id = \"{}\"\nsigning_public_key_hex = \"{}\"\nsignature_hex = \"{}\"\npayload_displayed = false\n",
        escape_file_value(&card.agent_id),
        escape_file_value(&card.display_name),
        escape_file_value(&card.node_id),
        escape_file_value(&card.kind),
        card.capabilities.messages,
        card.capabilities.streams,
        card.capabilities.rooms,
        card.capabilities.files,
        card.capabilities.presence,
        escape_file_value(&card.signature_algorithm),
        escape_file_value(&card.signature_key_id),
        escape_file_value(&card.signing_public_key_hex),
        escape_file_value(&card.signature_hex)
    )
}

/// Parse a signed agent card exchanged as encrypted control-plane metadata.
pub fn parse_signed_agent_card_metadata(contents: &str) -> Result<SignedAgentCard, AgentError> {
    let values = parse_key_values(contents);
    if value_or_empty(&values, "version") != "1"
        || value_or_empty(&values, "type") != "signed_agent_card"
    {
        return Err(AgentError::InvalidRequest {
            reason: "unsupported signed agent card metadata".to_string(),
        });
    }

    Ok(SignedAgentCard {
        agent_id: validate_identifier(required(&values, "agent_id")?, "agent id")?,
        display_name: validate_display_name(required(&values, "display_name")?)?,
        node_id: validate_identifier(required(&values, "node_id")?, "node id")?,
        kind: validate_kind(required(&values, "kind")?)?,
        capabilities: AgentCapabilities {
            messages: parse_bool(values.get("cap_messages")).unwrap_or(true),
            streams: parse_bool(values.get("cap_streams")).unwrap_or(false),
            rooms: parse_bool(values.get("cap_rooms")).unwrap_or(false),
            files: parse_bool(values.get("cap_files")).unwrap_or(false),
            presence: parse_bool(values.get("cap_presence")).unwrap_or(true),
        },
        signature_algorithm: validate_identifier(
            required(&values, "signature_algorithm")?,
            "signature algorithm",
        )?,
        signature_key_id: validate_identifier(
            required(&values, "signature_key_id")?,
            "signature key id",
        )?,
        signing_public_key_hex: validate_hex_value(
            required(&values, "signing_public_key_hex")?,
            "signing public key",
            128,
        )?,
        signature_hex: validate_hex_value(required(&values, "signature_hex")?, "signature", 256)?,
    })
}

/// Verify the persisted local agent-card signature.
pub fn verify_local_agent_record(agent: &LocalAgentRecord) -> Result<bool, AgentError> {
    let Some(public_key_hex) = agent.signing_public_key_hex.as_deref() else {
        return Ok(false);
    };
    let Some(signature_hex) = agent.signature_hex.as_deref() else {
        return Ok(false);
    };

    Ok(security::verify_agent_card_signature(
        &canonical_agent_card(agent),
        public_key_hex,
        signature_hex,
    )?)
}

/// Verify a public signed agent card.
pub fn verify_signed_agent_card(card: &SignedAgentCard) -> Result<bool, AgentError> {
    if card.signature_algorithm != security::AGENT_CARD_SIGNATURE_ALGORITHM {
        return Ok(false);
    }
    Ok(security::verify_agent_card_signature(
        &canonical_signed_agent_card(card),
        &card.signing_public_key_hex,
        &card.signature_hex,
    )?)
}

enum ProcessedRequest {
    Registered(String),
    Presence(String),
}

fn process_one_request(
    paths: &StatePaths,
    node_id: &str,
    request_path: &Path,
) -> Result<ProcessedRequest, AgentError> {
    let contents = fs::read_to_string(request_path)
        .map_err(|error| AgentError::io("read IPC request", request_path, error))?;
    let values = parse_key_values(&contents);

    if value_or_empty(&values, "version") != REQUEST_VERSION {
        return Err(AgentError::InvalidRequest {
            reason: "unsupported request version".to_string(),
        });
    }

    match value_or_empty(&values, "type") {
        "register_agent" => {
            let registration = registration_from_values(&values)?;
            upsert_agent(paths, node_id, registration).map(ProcessedRequest::Registered)
        }
        "presence_heartbeat" => {
            let heartbeat = presence_from_values(&values)?;
            update_presence(paths, heartbeat).map(ProcessedRequest::Presence)
        }
        _ => Err(AgentError::InvalidRequest {
            reason: "unsupported request type".to_string(),
        }),
    }
}

fn upsert_agent(
    paths: &StatePaths,
    node_id: &str,
    registration: AgentRegistration,
) -> Result<String, AgentError> {
    let mut agents = read_registry(paths)?;
    let now = current_unix_seconds();
    let mut updated = false;

    for agent in &mut agents {
        if agent.agent_id == registration.agent_id {
            agent.display_name = registration.display_name.clone();
            agent.kind = registration.kind.clone();
            agent.presence = AgentPresence::Ready;
            agent.last_seen_unix = now;
            agent.capabilities = registration.capabilities.clone();
            sign_agent_record(paths, agent)?;
            updated = true;
            break;
        }
    }

    if !updated {
        let mut record = LocalAgentRecord {
            agent_id: registration.agent_id.clone(),
            display_name: registration.display_name,
            node_id: node_id.to_string(),
            kind: registration.kind,
            presence: AgentPresence::Ready,
            last_seen_unix: now,
            capabilities: registration.capabilities,
            signature_algorithm: None,
            signature_key_id: None,
            signing_public_key_hex: None,
            signature_hex: None,
        };
        sign_agent_record(paths, &mut record)?;
        agents.push(record);
    }

    write_registry(paths, &agents)?;
    append_agent_log(paths, "agent_registered", &registration.agent_id)?;

    Ok(registration.agent_id)
}

fn update_presence(paths: &StatePaths, heartbeat: PresenceHeartbeat) -> Result<String, AgentError> {
    let mut agents = read_registry(paths)?;
    let now = current_unix_seconds();
    let mut found = false;

    for agent in &mut agents {
        if agent.agent_id == heartbeat.agent_id {
            agent.presence = heartbeat.presence;
            agent.last_seen_unix = now;
            found = true;
            break;
        }
    }

    if !found {
        return Err(AgentError::InvalidRequest {
            reason: format!("unknown local agent {}", heartbeat.agent_id),
        });
    }

    write_registry(paths, &agents)?;
    append_agent_log(paths, "agent_presence", &heartbeat.agent_id)?;

    Ok(heartbeat.agent_id)
}

fn sign_agent_record(paths: &StatePaths, agent: &mut LocalAgentRecord) -> Result<(), AgentError> {
    let signature = security::sign_agent_card_from_paths(paths, &canonical_agent_card(agent))?;
    agent.signature_algorithm = Some(signature.algorithm);
    agent.signature_key_id = Some(signature.key_id);
    agent.signing_public_key_hex = Some(signature.public_key_hex);
    agent.signature_hex = Some(signature.signature_hex);

    Ok(())
}

fn canonical_agent_card(agent: &LocalAgentRecord) -> String {
    canonical_agent_card_fields(
        &agent.agent_id,
        &agent.display_name,
        &agent.node_id,
        &agent.kind,
        &agent.capabilities,
    )
}

fn canonical_signed_agent_card(card: &SignedAgentCard) -> String {
    canonical_agent_card_fields(
        &card.agent_id,
        &card.display_name,
        &card.node_id,
        &card.kind,
        &card.capabilities,
    )
}

fn canonical_agent_card_fields(
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

fn signed_agent_card_from_record(agent: &LocalAgentRecord) -> Result<SignedAgentCard, AgentError> {
    let Some(signature_algorithm) = agent.signature_algorithm.clone() else {
        return Err(AgentError::InvalidRequest {
            reason: "agent card is missing signature algorithm".to_string(),
        });
    };
    let Some(signature_key_id) = agent.signature_key_id.clone() else {
        return Err(AgentError::InvalidRequest {
            reason: "agent card is missing signature key id".to_string(),
        });
    };
    let Some(signing_public_key_hex) = agent.signing_public_key_hex.clone() else {
        return Err(AgentError::InvalidRequest {
            reason: "agent card is missing signing public key".to_string(),
        });
    };
    let Some(signature_hex) = agent.signature_hex.clone() else {
        return Err(AgentError::InvalidRequest {
            reason: "agent card is missing signature".to_string(),
        });
    };

    Ok(SignedAgentCard {
        agent_id: agent.agent_id.clone(),
        display_name: agent.display_name.clone(),
        node_id: agent.node_id.clone(),
        kind: agent.kind.clone(),
        capabilities: agent.capabilities.clone(),
        signature_algorithm,
        signature_key_id,
        signing_public_key_hex,
        signature_hex,
    })
}

fn read_registry(paths: &StatePaths) -> Result<Vec<LocalAgentRecord>, AgentError> {
    if !paths.agent_registry.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&paths.agent_registry)
        .map_err(|error| AgentError::io("read agent registry", &paths.agent_registry, error))?;
    parse_registry(&contents)
}

fn write_registry(paths: &StatePaths, agents: &[LocalAgentRecord]) -> Result<(), AgentError> {
    let mut sorted = agents.to_vec();
    sorted.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    let mut contents = String::from("# conU local agent registry\nversion = \"1\"\n");

    for agent in sorted {
        contents.push_str("\n[[agent]]\n");
        contents.push_str(&format!(
            "agent_id = \"{}\"\n",
            escape_file_value(&agent.agent_id)
        ));
        contents.push_str(&format!(
            "display_name = \"{}\"\n",
            escape_file_value(&agent.display_name)
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
    }

    fs::write(&paths.agent_registry, contents)
        .map_err(|error| AgentError::io("write agent registry", &paths.agent_registry, error))
}

fn parse_registry(contents: &str) -> Result<Vec<LocalAgentRecord>, AgentError> {
    let mut records = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with('#')
            || line == "version = \"1\""
            || line == "agents = []"
        {
            continue;
        }

        if line == "[[agent]]" {
            if !current.is_empty() {
                records.push(record_from_values(&current)?);
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
        records.push(record_from_values(&current)?);
    }

    Ok(records)
}

fn record_from_values(values: &HashMap<String, String>) -> Result<LocalAgentRecord, AgentError> {
    let agent_id = validate_identifier(required(values, "agent_id")?, "agent id")?;
    let display_name = validate_display_name(required(values, "display_name")?)?;
    let node_id = validate_identifier(required(values, "node_id")?, "node id")?;
    let kind = validate_kind(required(values, "kind")?)?;
    let presence = AgentPresence::from_str(&required(values, "presence")?).ok_or_else(|| {
        AgentError::InvalidRequest {
            reason: "presence must be ready, busy, idle, or offline".to_string(),
        }
    })?;
    let last_seen_unix = required(values, "last_seen_unix")?
        .parse::<u64>()
        .map_err(|_| AgentError::InvalidRequest {
            reason: "last_seen_unix must be an unsigned integer".to_string(),
        })?;

    Ok(LocalAgentRecord {
        agent_id,
        display_name,
        node_id,
        kind,
        presence,
        last_seen_unix,
        capabilities: AgentCapabilities {
            messages: parse_bool(values.get("cap_messages")).unwrap_or(true),
            streams: parse_bool(values.get("cap_streams")).unwrap_or(false),
            rooms: parse_bool(values.get("cap_rooms")).unwrap_or(false),
            files: parse_bool(values.get("cap_files")).unwrap_or(false),
            presence: parse_bool(values.get("cap_presence")).unwrap_or(true),
        },
        signature_algorithm: optional_clean(values.get("signature_algorithm")),
        signature_key_id: optional_clean(values.get("signature_key_id")),
        signing_public_key_hex: optional_clean(values.get("signing_public_key_hex")),
        signature_hex: optional_clean(values.get("signature_hex")),
    })
}

fn registration_from_values(
    values: &HashMap<String, String>,
) -> Result<AgentRegistration, AgentError> {
    let mut registration = AgentRegistration::new(
        required(values, "agent_id")?,
        required(values, "display_name")?,
        values
            .get("kind")
            .cloned()
            .unwrap_or_else(|| "local-agent".to_string()),
    )?;
    registration.capabilities = AgentCapabilities {
        messages: parse_bool(values.get("cap_messages")).unwrap_or(true),
        streams: parse_bool(values.get("cap_streams")).unwrap_or(false),
        rooms: parse_bool(values.get("cap_rooms")).unwrap_or(false),
        files: parse_bool(values.get("cap_files")).unwrap_or(false),
        presence: parse_bool(values.get("cap_presence")).unwrap_or(true),
    };
    Ok(registration)
}

fn presence_from_values(values: &HashMap<String, String>) -> Result<PresenceHeartbeat, AgentError> {
    let presence = values
        .get("presence")
        .and_then(|value| AgentPresence::from_str(value))
        .ok_or_else(|| AgentError::InvalidRequest {
            reason: "presence must be ready, busy, idle, or offline".to_string(),
        })?;
    PresenceHeartbeat::new(required(values, "agent_id")?, presence)
}

fn pending_requests(paths: &StatePaths) -> Result<Vec<PathBuf>, AgentError> {
    let mut requests = Vec::new();

    for entry in fs::read_dir(&paths.ipc_inbox_dir)
        .map_err(|error| AgentError::io("read IPC inbox", &paths.ipc_inbox_dir, error))?
    {
        let entry = entry
            .map_err(|error| AgentError::io("read IPC inbox entry", &paths.ipc_inbox_dir, error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("req") {
            requests.push(path);
        }
    }

    requests.sort();
    Ok(requests)
}

fn move_request(request_path: &Path, target_dir: &Path) -> Result<(), AgentError> {
    fs::create_dir_all(target_dir)
        .map_err(|error| AgentError::io("create IPC target directory", target_dir, error))?;
    let target = target_dir.join(
        request_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("request.req")),
    );
    ensure_ipc_archive_target_available(&target)?;
    fs::rename(request_path, &target)
        .map_err(|error| AgentError::io("move IPC request", request_path, error))
}

fn reject_request(
    request_path: &Path,
    target_dir: &Path,
    error: &AgentError,
) -> Result<(), AgentError> {
    fs::create_dir_all(target_dir)
        .map_err(|error| AgentError::io("create IPC rejected directory", target_dir, error))?;
    let target = target_dir.join(
        request_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("request.req")),
    );
    let error_path = target.with_extension("error");
    ensure_ipc_archive_target_available(&target)?;
    write_new_file_with_action(
        &error_path,
        &format!("{error}\n"),
        "create IPC rejection reason",
        "write IPC rejection reason",
    )?;
    fs::rename(request_path, &target)
        .map_err(|error| AgentError::io("move rejected IPC request", request_path, error))
}

fn ensure_ipc_archive_target_available(path: &Path) -> Result<(), AgentError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(AgentError::io(
            "reserve IPC archive target",
            path,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "archive target already exists",
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AgentError::io("inspect IPC archive target", path, error)),
    }
}

fn render_registration_request(request_id: &str, registration: &AgentRegistration) -> String {
    format!(
        "version = \"{}\"\ntype = \"register_agent\"\nrequest_id = \"{}\"\nagent_id = \"{}\"\ndisplay_name = \"{}\"\nkind = \"{}\"\ncap_messages = {}\ncap_streams = {}\ncap_rooms = {}\ncap_files = {}\ncap_presence = {}\n",
        REQUEST_VERSION,
        escape_file_value(request_id),
        escape_file_value(&registration.agent_id),
        escape_file_value(&registration.display_name),
        escape_file_value(&registration.kind),
        registration.capabilities.messages,
        registration.capabilities.streams,
        registration.capabilities.rooms,
        registration.capabilities.files,
        registration.capabilities.presence,
    )
}

fn render_presence_request(request_id: &str, heartbeat: &PresenceHeartbeat) -> String {
    format!(
        "version = \"{}\"\ntype = \"presence_heartbeat\"\nrequest_id = \"{}\"\nagent_id = \"{}\"\npresence = \"{}\"\n",
        REQUEST_VERSION,
        escape_file_value(request_id),
        escape_file_value(&heartbeat.agent_id),
        heartbeat.presence.as_str(),
    )
}

fn append_agent_log(paths: &StatePaths, event: &str, agent_id: &str) -> Result<(), AgentError> {
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| AgentError::io("create log directory", &paths.logs_dir, error))?;
    let log_path = paths.logs_dir.join("agents.log");
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .map_err(|error| AgentError::io("open agent log", &log_path, error))?;

    writeln!(
        file,
        "time={} event={} agent={} payload=not_observed",
        current_unix_seconds(),
        event,
        sanitize_log_value(agent_id)
    )
    .map_err(|error| AgentError::io("write agent log", &log_path, error))
}

fn write_new_file(path: &Path, contents: &str) -> Result<(), AgentError> {
    write_new_file_with_action(path, contents, "create IPC request", "write IPC request")
}

fn write_new_file_with_action(
    path: &Path,
    contents: &str,
    create_action: &'static str,
    write_action: &'static str,
) -> Result<(), AgentError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| AgentError::io(create_action, path, error))?;

    file.write_all(contents.as_bytes())
        .map_err(|error| AgentError::io(write_action, path, error))
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, AgentError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| AgentError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, AgentError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(AgentError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 80 {
        return Err(AgentError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(AgentError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_display_name(value: String) -> Result<String, AgentError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(AgentError::InvalidRequest {
            reason: "display name cannot be empty".to_string(),
        });
    }
    if value.len() > 120 {
        return Err(AgentError::InvalidRequest {
            reason: "display name is too long".to_string(),
        });
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(AgentError::InvalidRequest {
            reason: "display name cannot contain control characters".to_string(),
        });
    }
    Ok(value)
}

fn validate_kind(value: String) -> Result<String, AgentError> {
    let value = if value.trim().is_empty() {
        "local-agent".to_string()
    } else {
        value.trim().to_string()
    };
    validate_identifier(value, "agent kind")
}

fn validate_hex_value(
    value: String,
    field: &'static str,
    max_len: usize,
) -> Result<String, AgentError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(AgentError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > max_len {
        return Err(AgentError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AgentError::InvalidRequest {
            reason: format!("{field} must be hex"),
        });
    }
    Ok(value)
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

fn value_or_empty<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values.get(key).map(String::as_str).unwrap_or("")
}

fn parse_bool(value: Option<&String>) -> Option<bool> {
    value.and_then(|value| match value.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn optional_clean(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn request_id(prefix: &str) -> String {
    format!("{}_{}_{}", prefix, process::id(), current_unix_nanos())
}

fn escape_file_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect()
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_request_is_metadata_only() {
        let home = test_home("metadata");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");

        let submission = submit_registration(Some(home), registration).expect("request submits");
        let contents = fs::read_to_string(submission.request_path).expect("request reads");

        assert!(contents.contains("type = \"register_agent\""));
        assert!(contents.contains("agent_id = \"agent.codex\""));
        assert!(!contents.contains("private message contents"));
        assert!(!contents.contains("Review this code"));
    }

    #[test]
    fn process_registration_persists_agent() {
        let home = test_home("register");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        submit_registration(Some(home.clone()), registration).expect("request submits");

        let report = process_gateway_requests(Some(home.clone())).expect("requests process");
        let agents = list_local_agents(Some(home)).expect("agents read");

        assert_eq!(report.processed, 1);
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_id, "agent.codex");
        assert_eq!(agents[0].presence, AgentPresence::Ready);
        assert_eq!(
            agents[0].signature_algorithm.as_deref(),
            Some(security::AGENT_CARD_SIGNATURE_ALGORITHM)
        );
        assert!(verify_local_agent_record(&agents[0]).expect("signature verifies"));
    }

    #[test]
    fn export_agent_card_returns_signed_public_metadata() {
        let home = test_home("export-card");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        submit_registration(Some(home.clone()), registration).expect("request submits");
        process_gateway_requests(Some(home.clone())).expect("request processes");

        let card = export_agent_card(Some(home), "agent.codex").expect("card exports");

        assert_eq!(card.agent_id, "agent.codex");
        assert_eq!(
            card.signature_algorithm,
            security::AGENT_CARD_SIGNATURE_ALGORITHM
        );
        assert!(verify_signed_agent_card(&card).expect("signature verifies"));
        assert!(!format!("{card:?}").contains("private message contents"));
    }

    #[test]
    fn agent_card_signature_detects_tampering() {
        let home = test_home("signature-tamper");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        submit_registration(Some(home.clone()), registration).expect("request submits");
        process_gateway_requests(Some(home.clone())).expect("request processes");
        let mut agent = list_local_agents(Some(home))
            .expect("agents read")
            .pop()
            .expect("agent exists");

        assert!(verify_local_agent_record(&agent).expect("signature verifies"));
        agent.display_name = "Tampered Agent".to_string();
        assert!(!verify_local_agent_record(&agent).expect("tamper returns false"));
    }

    #[test]
    fn registration_is_idempotent() {
        let home = test_home("idempotent");
        let first = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        let second = AgentRegistration::new("agent.codex", "Codex Updated", "coding-agent")
            .expect("valid registration");
        submit_registration(Some(home.clone()), first).expect("first request submits");
        submit_registration(Some(home.clone()), second).expect("second request submits");

        process_gateway_requests(Some(home.clone())).expect("requests process");
        let agents = list_local_agents(Some(home)).expect("agents read");

        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].display_name, "Codex Updated");
    }

    #[test]
    fn presence_heartbeat_updates_existing_agent() {
        let home = test_home("presence");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        submit_registration(Some(home.clone()), registration).expect("registration submits");
        process_gateway_requests(Some(home.clone())).expect("registration processes");
        let heartbeat =
            PresenceHeartbeat::new("agent.codex", AgentPresence::Busy).expect("heartbeat valid");
        submit_presence_heartbeat(Some(home.clone()), heartbeat).expect("heartbeat submits");

        let report = process_gateway_requests(Some(home.clone())).expect("heartbeat processes");
        let agents = list_local_agents(Some(home)).expect("agents read");

        assert_eq!(report.processed, 1);
        assert_eq!(agents[0].presence, AgentPresence::Busy);
    }

    #[test]
    fn bad_request_is_rejected_without_payload() {
        let home = test_home("reject");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let bad = init.paths.ipc_inbox_dir.join("bad.req");
        fs::write(
            &bad,
            "version = \"1\"\ntype = \"secret private message contents\"\n",
        )
        .expect("bad request writes");

        let report = process_gateway_requests(Some(home.clone())).expect("requests process");
        let rejected_dir = StatePaths::from_home(home).ipc_rejected_dir;
        let rejected = fs::read_dir(&rejected_dir)
            .expect("rejected dir reads")
            .count();
        let error_text =
            fs::read_to_string(rejected_dir.join("bad.error")).expect("rejection reason reads");

        assert_eq!(report.rejected, 1);
        assert!(rejected >= 1);
        assert!(error_text.contains("unsupported request type"));
        assert!(!error_text.contains("secret private message contents"));
    }

    #[test]
    fn processed_request_archive_refuses_existing_marker() {
        let home = test_home("processed-collision");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        let submission =
            submit_registration(Some(home.clone()), registration).expect("request submits");
        let target = init.paths.ipc_processed_dir.join(
            submission
                .request_path
                .file_name()
                .expect("request filename"),
        );
        fs::write(&target, "existing processed marker").expect("existing marker writes");

        let error = process_gateway_requests(Some(home))
            .expect_err("existing processed marker should fail closed");

        assert!(error.to_string().contains("reserve IPC archive target"));
        assert_eq!(
            fs::read_to_string(&target).expect("existing marker reads"),
            "existing processed marker"
        );
        assert!(submission.request_path.exists());
    }

    #[test]
    fn rejected_request_archive_refuses_existing_marker() {
        let home = test_home("rejected-collision");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let bad = init.paths.ipc_inbox_dir.join("bad.req");
        fs::write(&bad, "version = \"1\"\ntype = \"unsupported\"\n").expect("bad request writes");
        let target = init.paths.ipc_rejected_dir.join("bad.req");
        let error_path = init.paths.ipc_rejected_dir.join("bad.error");
        fs::write(&target, "existing rejected marker").expect("existing marker writes");
        fs::write(&error_path, "existing rejection reason").expect("existing error writes");

        let error = process_gateway_requests(Some(home))
            .expect_err("existing rejected marker should fail closed");

        assert!(error.to_string().contains("reserve IPC archive target"));
        assert_eq!(
            fs::read_to_string(&target).expect("existing marker reads"),
            "existing rejected marker"
        );
        assert_eq!(
            fs::read_to_string(&error_path).expect("existing error reads"),
            "existing rejection reason"
        );
        assert!(bad.exists());
    }

    #[test]
    fn rejected_request_reason_refuses_existing_file() {
        let home = test_home("rejected-error-collision");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let bad = init.paths.ipc_inbox_dir.join("bad.req");
        fs::write(&bad, "version = \"1\"\ntype = \"unsupported\"\n").expect("bad request writes");
        let target = init.paths.ipc_rejected_dir.join("bad.req");
        let error_path = init.paths.ipc_rejected_dir.join("bad.error");
        fs::write(&error_path, "existing rejection reason").expect("existing error writes");

        let error = process_gateway_requests(Some(home))
            .expect_err("existing rejection reason should fail closed");

        assert!(error.to_string().contains("create IPC rejection reason"));
        assert_eq!(
            fs::read_to_string(&error_path).expect("existing error reads"),
            "existing rejection reason"
        );
        assert!(!target.exists());
        assert!(bad.exists());
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-agents-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
