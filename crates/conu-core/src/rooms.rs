//! Room and pub/sub metadata.
//!
//! Phase 14 gives agents a shared room/session surface without making conU the
//! conversation owner. Room publishes record topic, byte counts, participants,
//! route labels, and timestamps only. Payload bytes remain opaque and are never
//! written to room files, logs, or CLI views.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::OpaquePayload;

use crate::agents;
use crate::messages;
use crate::policy::{self, PeerPermission, PolicyError};
use crate::relay_delivery::{self, RemoteRoomEvent};
use crate::sessions;
use crate::state::{self, StateError, StatePaths};

const ROOM_VERSION: &str = "1";
const ROOM_BACKPRESSURE_WINDOW: usize = 64 * 1024;

/// One topic-level action controlled by room policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomTopicPermission {
    Publish,
    Subscribe,
}

impl RoomTopicPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
        }
    }
}

/// Lifecycle state for a conU room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomState {
    Open,
    Closed,
}

impl RoomState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "open" => Self::Open,
            _ => Self::Closed,
        }
    }
}

/// Whether a room participant is local or mirrored from trusted remote metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomParticipantScope {
    Local,
    Remote,
}

impl RoomParticipantScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }

    fn from_str(value: &str) -> Result<Self, RoomError> {
        match value {
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            _ => Err(RoomError::InvalidRequest {
                reason: "participant scope must be local or remote".to_string(),
            }),
        }
    }
}

/// One agent joined to a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomParticipant {
    pub agent_id: String,
    pub scope: RoomParticipantScope,
    pub joined_at_unix: u64,
}

/// Metadata for one room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRecord {
    pub room_id: String,
    pub display_name: String,
    pub state: RoomState,
    pub created_by_agent_id: String,
    pub participants: Vec<RoomParticipant>,
    pub topics: Vec<String>,
    pub events_published: u64,
    pub bytes_published: usize,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

/// One payload-safe room event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomEvent {
    pub event_id: String,
    pub room_id: String,
    pub topic: String,
    pub from_agent_id: String,
    pub event_type: String,
    pub route: String,
    pub payload_bytes: usize,
    pub created_at_unix: u64,
}

/// Result of creating a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomCreateReport {
    pub room: RoomRecord,
}

/// Result of joining a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomJoinReport {
    pub room: RoomRecord,
    pub joined: bool,
}

/// Result of publishing one opaque room event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPublishReport {
    pub room: RoomRecord,
    pub event: RoomEvent,
    pub local_deliveries: usize,
    pub remote_deliveries: usize,
}

/// Metadata-only per-topic authorization record for one joined agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomTopicPolicyRecord {
    pub room_id: String,
    pub agent_id: String,
    pub topic: String,
    pub publish: bool,
    pub subscribe: bool,
    pub updated_at_unix: u64,
}

impl RoomTopicPolicyRecord {
    pub fn denied(
        room_id: impl Into<String>,
        agent_id: impl Into<String>,
        topic: impl Into<String>,
    ) -> Self {
        Self {
            room_id: room_id.into(),
            agent_id: agent_id.into(),
            topic: topic.into(),
            publish: false,
            subscribe: false,
            updated_at_unix: 0,
        }
    }

    pub const fn allows(&self, permission: RoomTopicPermission) -> bool {
        match permission {
            RoomTopicPermission::Publish => self.publish,
            RoomTopicPermission::Subscribe => self.subscribe,
        }
    }
}

/// Partial room topic policy update. Unset fields preserve existing values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomTopicPolicyUpdate {
    pub publish: Option<bool>,
    pub subscribe: Option<bool>,
}

impl RoomTopicPolicyUpdate {
    pub const fn empty() -> Self {
        Self {
            publish: None,
            subscribe: None,
        }
    }

    pub const fn has_changes(&self) -> bool {
        self.publish.is_some() || self.subscribe.is_some()
    }
}

/// Peer-decrypted room event ready for local inbox delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteRoomEventDelivery {
    pub envelope_id: String,
    pub event_id: String,
    pub room_id: String,
    pub topic: String,
    pub peer_node_id: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub payload: OpaquePayload,
}

/// Errors produced by room operations.
#[derive(Debug)]
pub enum RoomError {
    State(StateError),
    Agent(agents::AgentError),
    Message(messages::MessageError),
    Policy(PolicyError),
    Session(sessions::SessionError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRequest {
        reason: String,
    },
}

impl RoomError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for RoomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Policy(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRequest { reason } => write!(formatter, "invalid room request: {reason}"),
        }
    }
}

impl std::error::Error for RoomError {}

impl From<StateError> for RoomError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<agents::AgentError> for RoomError {
    fn from(error: agents::AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<messages::MessageError> for RoomError {
    fn from(error: messages::MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<PolicyError> for RoomError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<sessions::SessionError> for RoomError {
    fn from(error: sessions::SessionError) -> Self {
        Self::Session(error)
    }
}

/// Create a room owned by a registered local agent.
pub fn create_room(
    home_override: Option<PathBuf>,
    room_id: &str,
    display_name: &str,
    created_by_agent_id: &str,
) -> Result<RoomCreateReport, RoomError> {
    let init = state::init_state(home_override)?;
    let room_id = validate_identifier(room_id.to_string(), "room id")?;
    let display_name = validate_display_name(display_name.to_string())?;
    let created_by_agent_id =
        validate_identifier(created_by_agent_id.to_string(), "creator agent id")?;

    validate_local_agent_can_use_rooms(
        &init.paths,
        &created_by_agent_id,
        "creator agent is not registered locally",
        "creator agent is not allowed to create rooms",
    )?;

    let mut rooms = read_rooms(&init.paths)?;
    if rooms.iter().any(|room| room.room_id == room_id) {
        return Err(RoomError::InvalidRequest {
            reason: "room already exists".to_string(),
        });
    }

    let now = current_unix_seconds();
    let room = RoomRecord {
        room_id,
        display_name,
        state: RoomState::Open,
        created_by_agent_id: created_by_agent_id.clone(),
        participants: vec![RoomParticipant {
            agent_id: created_by_agent_id,
            scope: RoomParticipantScope::Local,
            joined_at_unix: now,
        }],
        topics: Vec::new(),
        events_published: 0,
        bytes_published: 0,
        created_at_unix: now,
        updated_at_unix: now,
    };

    rooms.push(room.clone());
    write_rooms(&init.paths, &rooms)?;
    append_room_log(&init.paths, "room_created", &room.room_id, None, 0)?;

    Ok(RoomCreateReport { room })
}

/// Join a visible local or remote agent to an existing room.
pub fn join_room(
    home_override: Option<PathBuf>,
    room_id: &str,
    agent_id: &str,
) -> Result<RoomJoinReport, RoomError> {
    let init = state::init_state(home_override.clone())?;
    let room_id = validate_identifier(room_id.to_string(), "room id")?;
    let agent_id = validate_identifier(agent_id.to_string(), "agent id")?;
    let scope = visible_agent_scope(&init.paths, &agent_id)?;
    let mut rooms = read_rooms(&init.paths)?;
    let now = current_unix_seconds();
    let Some(index) = rooms.iter().position(|room| room.room_id == room_id) else {
        return Err(RoomError::InvalidRequest {
            reason: "room is not known".to_string(),
        });
    };

    if rooms[index].state != RoomState::Open {
        return Err(RoomError::InvalidRequest {
            reason: "room is closed".to_string(),
        });
    }

    if rooms[index]
        .participants
        .iter()
        .any(|participant| participant.agent_id == agent_id)
    {
        return Ok(RoomJoinReport {
            room: rooms[index].clone(),
            joined: false,
        });
    }

    rooms[index].participants.push(RoomParticipant {
        agent_id: agent_id.clone(),
        scope,
        joined_at_unix: now,
    });
    rooms[index].updated_at_unix = now;
    let room = rooms[index].clone();

    write_rooms(&init.paths, &rooms)?;
    append_room_log(
        &init.paths,
        "room_joined",
        &room.room_id,
        Some(&agent_id),
        0,
    )?;

    Ok(RoomJoinReport { room, joined: true })
}

/// Publish one opaque event to a room by byte count only.
pub fn publish_room_event(
    home_override: Option<PathBuf>,
    room_id: &str,
    from_agent_id: &str,
    topic: &str,
    payload: OpaquePayload,
) -> Result<RoomPublishReport, RoomError> {
    let init = state::init_state(home_override)?;
    let room_id = validate_identifier(room_id.to_string(), "room id")?;
    let from_agent_id = validate_identifier(from_agent_id.to_string(), "from agent id")?;
    let topic = validate_identifier(topic.to_string(), "topic")?;
    let payload_bytes = payload.len();

    validate_local_agent_can_use_rooms(
        &init.paths,
        &from_agent_id,
        "publishing agent must be registered locally",
        "publishing agent is not allowed to publish room events",
    )?;
    if payload.is_empty() {
        return Err(RoomError::InvalidRequest {
            reason: "payload cannot be empty".to_string(),
        });
    }
    if payload_bytes > ROOM_BACKPRESSURE_WINDOW {
        return Err(RoomError::InvalidRequest {
            reason: "event exceeds room backpressure window".to_string(),
        });
    }

    let mut rooms = read_rooms(&init.paths)?;
    let now = current_unix_seconds();
    let Some(index) = rooms.iter().position(|room| room.room_id == room_id) else {
        return Err(RoomError::InvalidRequest {
            reason: "room is not known".to_string(),
        });
    };

    if rooms[index].state != RoomState::Open {
        return Err(RoomError::InvalidRequest {
            reason: "room is closed".to_string(),
        });
    }
    if !rooms[index]
        .participants
        .iter()
        .any(|participant| participant.agent_id == from_agent_id)
    {
        return Err(RoomError::InvalidRequest {
            reason: "publishing agent is not joined to this room".to_string(),
        });
    }
    ensure_room_topic_allowed(
        &init.paths,
        &room_id,
        &from_agent_id,
        &topic,
        RoomTopicPermission::Publish,
    )?;

    if !rooms[index].topics.iter().any(|known| known == &topic) {
        rooms[index].topics.push(topic.clone());
        rooms[index].topics.sort();
    }
    rooms[index].events_published = rooms[index].events_published.saturating_add(1);
    rooms[index].bytes_published = rooms[index].bytes_published.saturating_add(payload_bytes);
    rooms[index].updated_at_unix = now;
    let room = rooms[index].clone();
    let event = RoomEvent {
        event_id: room_event_id(&room.room_id, &topic, now),
        room_id: room.room_id.clone(),
        topic,
        from_agent_id: from_agent_id.clone(),
        event_type: "published".to_string(),
        route: route_for_room(&room),
        payload_bytes,
        created_at_unix: now,
    };
    let local_recipients = local_room_recipients(&init.paths, &room, &from_agent_id, &event.topic)?;
    let remote_recipients =
        remote_room_recipients(&init.paths, &room, &from_agent_id, &event.topic)?;
    let local_deliveries = deliver_room_event_to_local_participants(
        &init.paths,
        &event,
        payload.clone(),
        &local_recipients,
    )?;
    let remote_deliveries = deliver_room_event_to_remote_participants(
        &init.paths,
        &init.node.node_id,
        &event,
        payload,
        &remote_recipients,
    )?;

    write_rooms(&init.paths, &rooms)?;
    append_event(&init.paths, event.clone())?;
    append_room_log(
        &init.paths,
        "room_event_published",
        &room.room_id,
        Some(&from_agent_id),
        payload_bytes,
    )?;

    Ok(RoomPublishReport {
        room,
        event,
        local_deliveries,
        remote_deliveries,
    })
}

/// Deliver a peer-decrypted room event to a local room participant inbox.
pub fn deliver_remote_room_event_from_paths(
    paths: &StatePaths,
    delivery: RemoteRoomEventDelivery,
) -> Result<messages::InboxEntry, RoomError> {
    let envelope_id = validate_identifier(delivery.envelope_id, "envelope id")?;
    let event_id = validate_identifier(delivery.event_id, "event id")?;
    let room_id = validate_identifier(delivery.room_id, "room id")?;
    let topic = validate_identifier(delivery.topic, "topic")?;
    let peer_node_id = validate_identifier(delivery.peer_node_id, "peer node id")?;
    let from_agent_id = validate_identifier(delivery.from_agent_id, "from agent id")?;
    let to_agent_id = validate_identifier(delivery.to_agent_id, "to agent id")?;
    let payload = delivery.payload;
    let payload_bytes = payload.len();

    if payload.is_empty() {
        return Err(RoomError::InvalidRequest {
            reason: "payload cannot be empty".to_string(),
        });
    }
    if payload_bytes > ROOM_BACKPRESSURE_WINDOW {
        return Err(RoomError::InvalidRequest {
            reason: "event exceeds room backpressure window".to_string(),
        });
    }

    validate_remote_room_sender(paths, &peer_node_id, &from_agent_id)?;
    validate_known_room_membership(paths, &room_id, &from_agent_id, &to_agent_id)?;
    ensure_room_topic_allowed(
        paths,
        &room_id,
        &from_agent_id,
        &topic,
        RoomTopicPermission::Publish,
    )?;
    ensure_room_topic_allowed(
        paths,
        &room_id,
        &to_agent_id,
        &topic,
        RoomTopicPermission::Subscribe,
    )?;
    let entry = messages::deliver_room_event_from_paths(
        paths,
        &envelope_id,
        &from_agent_id,
        &to_agent_id,
        payload,
    )?;
    let event = RoomEvent {
        event_id,
        room_id: room_id.clone(),
        topic,
        from_agent_id: from_agent_id.clone(),
        event_type: "received".to_string(),
        route: "room-relay".to_string(),
        payload_bytes,
        created_at_unix: current_unix_seconds(),
    };
    append_event_once(paths, event)?;
    append_room_log(
        paths,
        "room_event_received",
        &room_id,
        Some(&to_agent_id),
        payload_bytes,
    )?;

    Ok(entry)
}

/// List room metadata.
pub fn list_rooms(home_override: Option<PathBuf>) -> Result<Vec<RoomRecord>, RoomError> {
    let paths = StatePaths::resolve(home_override)?;
    read_rooms(&paths)
}

/// List payload-safe room events in chronological order.
pub fn list_room_events(home_override: Option<PathBuf>) -> Result<Vec<RoomEvent>, RoomError> {
    let paths = StatePaths::resolve(home_override)?;
    read_events(&paths)
}

/// List explicit room topic policy records.
pub fn list_room_topic_policies(
    home_override: Option<PathBuf>,
) -> Result<Vec<RoomTopicPolicyRecord>, RoomError> {
    let paths = StatePaths::resolve(home_override)?;
    read_topic_policies(&paths)
}

/// Read one explicit room topic policy record.
pub fn room_topic_policy(
    home_override: Option<PathBuf>,
    room_id: &str,
    agent_id: &str,
    topic: &str,
) -> Result<Option<RoomTopicPolicyRecord>, RoomError> {
    let paths = StatePaths::resolve(home_override)?;
    let room_id = validate_identifier(room_id.to_string(), "room id")?;
    let agent_id = validate_identifier(agent_id.to_string(), "agent id")?;
    let topic = validate_identifier(topic.to_string(), "topic")?;

    Ok(read_topic_policies(&paths)?.into_iter().find(|policy| {
        policy.room_id == room_id && policy.agent_id == agent_id && policy.topic == topic
    }))
}

/// Set one agent's publish/subscribe grants for a room topic.
pub fn set_room_topic_policy(
    home_override: Option<PathBuf>,
    room_id: &str,
    agent_id: &str,
    topic: &str,
    update: RoomTopicPolicyUpdate,
) -> Result<RoomTopicPolicyRecord, RoomError> {
    if !update.has_changes() {
        return Err(RoomError::InvalidRequest {
            reason: "at least one topic policy field must be set".to_string(),
        });
    }

    let init = state::init_state(home_override)?;
    let room_id = validate_identifier(room_id.to_string(), "room id")?;
    let agent_id = validate_identifier(agent_id.to_string(), "agent id")?;
    let topic = validate_identifier(topic.to_string(), "topic")?;
    ensure_topic_policy_agent_is_joined_if_room_exists(&init.paths, &room_id, &agent_id)?;

    let mut policies = read_topic_policies(&init.paths)?;
    let mut record = policies
        .iter()
        .find(|policy| {
            policy.room_id == room_id && policy.agent_id == agent_id && policy.topic == topic
        })
        .cloned()
        .unwrap_or_else(|| {
            RoomTopicPolicyRecord::denied(room_id.clone(), agent_id.clone(), topic.clone())
        });

    if let Some(value) = update.publish {
        record.publish = value;
    }
    if let Some(value) = update.subscribe {
        record.subscribe = value;
    }
    record.updated_at_unix = current_unix_seconds();

    policies.retain(|policy| {
        !(policy.room_id == record.room_id
            && policy.agent_id == record.agent_id
            && policy.topic == record.topic)
    });
    policies.push(record.clone());
    write_topic_policies(&init.paths, &policies)?;
    append_room_log(
        &init.paths,
        "room_topic_policy_updated",
        &record.room_id,
        Some(&record.agent_id),
        0,
    )?;

    Ok(record)
}

fn visible_agent_scope(
    paths: &StatePaths,
    agent_id: &str,
) -> Result<RoomParticipantScope, RoomError> {
    let local_agents = agents::list_local_agents(Some(paths.home.clone()))?;
    if let Some(agent) = local_agents.iter().find(|agent| agent.agent_id == agent_id) {
        if !agent.capabilities.rooms {
            return Err(RoomError::InvalidRequest {
                reason: "agent is not allowed to join rooms".to_string(),
            });
        }
        return Ok(RoomParticipantScope::Local);
    }

    if let Some(remote_agent) = sessions::list_remote_agents(Some(paths.home.clone()))?
        .into_iter()
        .find(|agent| agent.agent_id == agent_id)
    {
        if !remote_agent.capabilities.rooms {
            return Err(RoomError::InvalidRequest {
                reason: "remote agent is not advertised for rooms".to_string(),
            });
        }
        policy::ensure_peer_allowed_from_paths(
            paths,
            &remote_agent.peer_node_id,
            PeerPermission::Rooms,
        )?;
        return Ok(RoomParticipantScope::Remote);
    }

    Err(RoomError::InvalidRequest {
        reason: "agent is not visible locally or through trusted remote discovery".to_string(),
    })
}

fn validate_remote_room_sender(
    paths: &StatePaths,
    peer_node_id: &str,
    from_agent_id: &str,
) -> Result<(), RoomError> {
    let Some(remote_agent) = sessions::list_remote_agents(Some(paths.home.clone()))?
        .into_iter()
        .find(|agent| agent.agent_id == from_agent_id && agent.peer_node_id == peer_node_id)
    else {
        return Err(RoomError::InvalidRequest {
            reason: "remote room sender is not visible through trusted discovery".to_string(),
        });
    };

    if !remote_agent.capabilities.rooms {
        return Err(RoomError::InvalidRequest {
            reason: "remote room sender is not advertised for rooms".to_string(),
        });
    }
    policy::ensure_peer_allowed_from_paths(paths, peer_node_id, PeerPermission::Rooms)?;

    Ok(())
}

fn validate_known_room_membership(
    paths: &StatePaths,
    room_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
) -> Result<(), RoomError> {
    let rooms = read_rooms(paths)?;
    let Some(room) = rooms.iter().find(|room| room.room_id == room_id) else {
        return Ok(());
    };

    if room.state != RoomState::Open {
        return Err(RoomError::InvalidRequest {
            reason: "room is closed".to_string(),
        });
    }
    if !room.participants.iter().any(|participant| {
        participant.agent_id == from_agent_id && participant.scope == RoomParticipantScope::Remote
    }) {
        return Err(RoomError::InvalidRequest {
            reason: "remote room sender is not joined to this room".to_string(),
        });
    }
    if !room.participants.iter().any(|participant| {
        participant.agent_id == to_agent_id && participant.scope == RoomParticipantScope::Local
    }) {
        return Err(RoomError::InvalidRequest {
            reason: "local room recipient is not joined to this room".to_string(),
        });
    }

    Ok(())
}

fn validate_local_agent_can_use_rooms(
    paths: &StatePaths,
    agent_id: &str,
    missing_reason: &'static str,
    denied_reason: &'static str,
) -> Result<(), RoomError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let agent = registered
        .iter()
        .find(|agent| agent.agent_id == agent_id)
        .ok_or_else(|| RoomError::InvalidRequest {
            reason: missing_reason.to_string(),
        })?;

    if !agent.capabilities.rooms {
        return Err(RoomError::InvalidRequest {
            reason: denied_reason.to_string(),
        });
    }

    Ok(())
}

fn ensure_topic_policy_agent_is_joined_if_room_exists(
    paths: &StatePaths,
    room_id: &str,
    agent_id: &str,
) -> Result<(), RoomError> {
    let rooms = read_rooms(paths)?;
    let Some(room) = rooms.iter().find(|room| room.room_id == room_id) else {
        return Ok(());
    };

    if !room
        .participants
        .iter()
        .any(|participant| participant.agent_id == agent_id)
    {
        return Err(RoomError::InvalidRequest {
            reason: "agent is not joined to this room".to_string(),
        });
    }

    Ok(())
}

fn ensure_room_topic_allowed(
    paths: &StatePaths,
    room_id: &str,
    agent_id: &str,
    topic: &str,
    permission: RoomTopicPermission,
) -> Result<(), RoomError> {
    if room_topic_allows(paths, room_id, agent_id, topic, permission)? {
        return Ok(());
    }

    Err(RoomError::InvalidRequest {
        reason: format!(
            "agent is not allowed to {} topic {} in room {}",
            permission.as_str(),
            topic,
            room_id
        ),
    })
}

fn room_topic_allows(
    paths: &StatePaths,
    room_id: &str,
    agent_id: &str,
    topic: &str,
    permission: RoomTopicPermission,
) -> Result<bool, RoomError> {
    let policies = read_topic_policies(paths)?;
    let scoped = policies
        .iter()
        .filter(|policy| policy.room_id == room_id && policy.topic == topic)
        .collect::<Vec<_>>();

    if scoped.is_empty() {
        return Ok(true);
    }

    Ok(scoped
        .iter()
        .find(|policy| policy.agent_id == agent_id)
        .is_some_and(|policy| policy.allows(permission)))
}

fn read_rooms(paths: &StatePaths) -> Result<Vec<RoomRecord>, RoomError> {
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.room_registry,
        "inspect room registry",
        "read room registry",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_rooms(&contents)
}

fn write_rooms(paths: &StatePaths, rooms: &[RoomRecord]) -> Result<(), RoomError> {
    fs::create_dir_all(&paths.rooms_dir)
        .map_err(|error| RoomError::io("create rooms directory", &paths.rooms_dir, error))?;
    let mut sorted = rooms.to_vec();
    sorted.sort_by(|left, right| left.room_id.cmp(&right.room_id));
    let mut contents = format!("# conU room registry\nversion = \"{}\"\n", ROOM_VERSION);

    for room in sorted {
        let participants = room
            .participants
            .iter()
            .map(|participant| {
                format!(
                    "{}:{}:{}",
                    participant.agent_id,
                    participant.scope.as_str(),
                    participant.joined_at_unix
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let topics = room.topics.join(",");

        contents.push_str("\n[[room]]\n");
        contents.push_str(&format!(
            "room_id = \"{}\"\n",
            escape_file_value(&room.room_id)
        ));
        contents.push_str(&format!(
            "display_name = \"{}\"\n",
            escape_file_value(&room.display_name)
        ));
        contents.push_str(&format!("state = \"{}\"\n", room.state.as_str()));
        contents.push_str(&format!(
            "created_by_agent_id = \"{}\"\n",
            escape_file_value(&room.created_by_agent_id)
        ));
        contents.push_str(&format!(
            "participants = \"{}\"\n",
            escape_file_value(&participants)
        ));
        contents.push_str(&format!("topics = \"{}\"\n", escape_file_value(&topics)));
        contents.push_str(&format!("events_published = {}\n", room.events_published));
        contents.push_str(&format!("bytes_published = {}\n", room.bytes_published));
        contents.push_str(&format!("created_at_unix = {}\n", room.created_at_unix));
        contents.push_str(&format!("updated_at_unix = {}\n", room.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.room_registry,
        &contents,
        "inspect room registry",
        "create room registry",
        "open room registry",
        "write room registry",
    )?;
    Ok(())
}

fn append_event(paths: &StatePaths, event: RoomEvent) -> Result<(), RoomError> {
    fs::create_dir_all(&paths.rooms_dir)
        .map_err(|error| RoomError::io("create rooms directory", &paths.rooms_dir, error))?;
    let mut events = read_events(paths)?;
    events.push(event);
    write_events(paths, &events)
}

fn append_event_once(paths: &StatePaths, event: RoomEvent) -> Result<(), RoomError> {
    fs::create_dir_all(&paths.rooms_dir)
        .map_err(|error| RoomError::io("create rooms directory", &paths.rooms_dir, error))?;
    let mut events = read_events(paths)?;
    if events.iter().any(|known| known.event_id == event.event_id) {
        return Ok(());
    }
    events.push(event);
    write_events(paths, &events)
}

fn read_events(paths: &StatePaths) -> Result<Vec<RoomEvent>, RoomError> {
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.room_events,
        "inspect room events",
        "read room events",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_events(&contents)
}

fn write_events(paths: &StatePaths, events: &[RoomEvent]) -> Result<(), RoomError> {
    let mut contents = format!("# conU room event bus\nversion = \"{}\"\n", ROOM_VERSION);

    for event in events {
        contents.push_str("\n[[event]]\n");
        contents.push_str(&format!(
            "event_id = \"{}\"\n",
            escape_file_value(&event.event_id)
        ));
        contents.push_str(&format!(
            "room_id = \"{}\"\n",
            escape_file_value(&event.room_id)
        ));
        contents.push_str(&format!(
            "topic = \"{}\"\n",
            escape_file_value(&event.topic)
        ));
        contents.push_str(&format!(
            "from_agent_id = \"{}\"\n",
            escape_file_value(&event.from_agent_id)
        ));
        contents.push_str(&format!(
            "event_type = \"{}\"\n",
            escape_file_value(&event.event_type)
        ));
        contents.push_str(&format!(
            "route = \"{}\"\n",
            escape_file_value(&event.route)
        ));
        contents.push_str(&format!("payload_bytes = {}\n", event.payload_bytes));
        contents.push_str(&format!("created_at_unix = {}\n", event.created_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.room_events,
        &contents,
        "inspect room events",
        "create room events",
        "open room events",
        "write room events",
    )?;
    Ok(())
}

fn read_topic_policies(paths: &StatePaths) -> Result<Vec<RoomTopicPolicyRecord>, RoomError> {
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.room_policy,
        "inspect room topic policy",
        "read room topic policy",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_topic_policies(&contents)
}

fn write_topic_policies(
    paths: &StatePaths,
    policies: &[RoomTopicPolicyRecord],
) -> Result<(), RoomError> {
    fs::create_dir_all(&paths.rooms_dir)
        .map_err(|error| RoomError::io("create rooms directory", &paths.rooms_dir, error))?;
    let mut sorted = policies.to_vec();
    sorted.sort_by(|left, right| {
        left.room_id
            .cmp(&right.room_id)
            .then_with(|| left.topic.cmp(&right.topic))
            .then_with(|| left.agent_id.cmp(&right.agent_id))
    });

    let mut contents = format!("# conU room topic policy\nversion = \"{}\"\n", ROOM_VERSION);
    for policy in sorted {
        contents.push_str("\n[[topic_policy]]\n");
        contents.push_str(&format!(
            "room_id = \"{}\"\n",
            escape_file_value(&policy.room_id)
        ));
        contents.push_str(&format!(
            "agent_id = \"{}\"\n",
            escape_file_value(&policy.agent_id)
        ));
        contents.push_str(&format!(
            "topic = \"{}\"\n",
            escape_file_value(&policy.topic)
        ));
        contents.push_str(&format!("publish = {}\n", policy.publish));
        contents.push_str(&format!("subscribe = {}\n", policy.subscribe));
        contents.push_str(&format!("updated_at_unix = {}\n", policy.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.room_policy,
        &contents,
        "inspect room topic policy",
        "create room topic policy",
        "open room topic policy",
        "write room topic policy",
    )?;
    Ok(())
}

fn parse_rooms(contents: &str) -> Result<Vec<RoomRecord>, RoomError> {
    let mut rooms = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[room]]" {
            if !current.is_empty() {
                rooms.push(room_from_values(&current)?);
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
        rooms.push(room_from_values(&current)?);
    }

    Ok(rooms)
}

fn parse_events(contents: &str) -> Result<Vec<RoomEvent>, RoomError> {
    let mut events = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[event]]" {
            if !current.is_empty() {
                events.push(event_from_values(&current)?);
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
        events.push(event_from_values(&current)?);
    }

    Ok(events)
}

fn parse_topic_policies(contents: &str) -> Result<Vec<RoomTopicPolicyRecord>, RoomError> {
    let mut policies = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[topic_policy]]" {
            if !current.is_empty() {
                policies.push(topic_policy_from_values(&current)?);
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
        policies.push(topic_policy_from_values(&current)?);
    }

    Ok(policies)
}

fn room_from_values(values: &HashMap<String, String>) -> Result<RoomRecord, RoomError> {
    let topics = split_list(values.get("topics").map(String::as_str).unwrap_or(""))
        .into_iter()
        .map(|topic| validate_identifier(topic, "topic"))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RoomRecord {
        room_id: validate_identifier(required(values, "room_id")?, "room id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        state: RoomState::from_str(&required(values, "state")?),
        created_by_agent_id: validate_identifier(
            required(values, "created_by_agent_id")?,
            "creator agent id",
        )?,
        participants: parse_participants(&required(values, "participants")?)?,
        topics,
        events_published: parse_u64(&required(values, "events_published")?)?,
        bytes_published: parse_usize(&required(values, "bytes_published")?)?,
        created_at_unix: parse_u64(&required(values, "created_at_unix")?)?,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn event_from_values(values: &HashMap<String, String>) -> Result<RoomEvent, RoomError> {
    Ok(RoomEvent {
        event_id: validate_identifier(required(values, "event_id")?, "event id")?,
        room_id: validate_identifier(required(values, "room_id")?, "room id")?,
        topic: validate_identifier(required(values, "topic")?, "topic")?,
        from_agent_id: validate_identifier(required(values, "from_agent_id")?, "from agent id")?,
        event_type: validate_identifier(required(values, "event_type")?, "event type")?,
        route: validate_identifier(required(values, "route")?, "route")?,
        payload_bytes: parse_usize(&required(values, "payload_bytes")?)?,
        created_at_unix: parse_u64(&required(values, "created_at_unix")?)?,
    })
}

fn topic_policy_from_values(
    values: &HashMap<String, String>,
) -> Result<RoomTopicPolicyRecord, RoomError> {
    Ok(RoomTopicPolicyRecord {
        room_id: validate_identifier(required(values, "room_id")?, "room id")?,
        agent_id: validate_identifier(required(values, "agent_id")?, "agent id")?,
        topic: validate_identifier(required(values, "topic")?, "topic")?,
        publish: parse_bool(values, "publish")?,
        subscribe: parse_bool(values, "subscribe")?,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn parse_participants(value: &str) -> Result<Vec<RoomParticipant>, RoomError> {
    split_list(value)
        .into_iter()
        .map(|entry| {
            let parts = entry.split(':').collect::<Vec<_>>();
            if parts.len() != 3 {
                return Err(RoomError::InvalidRequest {
                    reason: "participant entry is malformed".to_string(),
                });
            }
            Ok(RoomParticipant {
                agent_id: validate_identifier(parts[0].to_string(), "participant agent id")?,
                scope: RoomParticipantScope::from_str(parts[1])?,
                joined_at_unix: parse_u64(parts[2])?,
            })
        })
        .collect()
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn route_for_room(room: &RoomRecord) -> String {
    if room
        .participants
        .iter()
        .any(|participant| participant.scope == RoomParticipantScope::Remote)
    {
        "room-relay".to_string()
    } else {
        "room-local".to_string()
    }
}

fn local_room_recipients(
    paths: &StatePaths,
    room: &RoomRecord,
    from_agent_id: &str,
    topic: &str,
) -> Result<Vec<String>, RoomError> {
    let mut recipients = Vec::new();
    for participant in room.participants.iter().filter(|participant| {
        participant.scope == RoomParticipantScope::Local && participant.agent_id != from_agent_id
    }) {
        if room_topic_allows(
            paths,
            &room.room_id,
            &participant.agent_id,
            topic,
            RoomTopicPermission::Subscribe,
        )? {
            recipients.push(participant.agent_id.clone());
        }
    }

    Ok(recipients)
}

fn remote_room_recipients(
    paths: &StatePaths,
    room: &RoomRecord,
    from_agent_id: &str,
    topic: &str,
) -> Result<Vec<(String, String)>, RoomError> {
    let remote_agents = sessions::list_remote_agents(Some(paths.home.clone()))?;
    let mut recipients = Vec::new();

    for participant in room.participants.iter().filter(|participant| {
        participant.scope == RoomParticipantScope::Remote && participant.agent_id != from_agent_id
    }) {
        let Some(remote_agent) = remote_agents
            .iter()
            .find(|agent| agent.agent_id == participant.agent_id)
        else {
            return Err(RoomError::InvalidRequest {
                reason: "remote room participant is no longer visible".to_string(),
            });
        };
        if !remote_agent.capabilities.rooms {
            return Err(RoomError::InvalidRequest {
                reason: "remote room participant is not advertised for rooms".to_string(),
            });
        }
        policy::ensure_peer_allowed_from_paths(
            paths,
            &remote_agent.peer_node_id,
            PeerPermission::Rooms,
        )?;
        if room_topic_allows(
            paths,
            &room.room_id,
            &remote_agent.agent_id,
            topic,
            RoomTopicPermission::Subscribe,
        )? {
            recipients.push((
                remote_agent.agent_id.clone(),
                remote_agent.peer_node_id.clone(),
            ));
        }
    }

    Ok(recipients)
}

fn deliver_room_event_to_local_participants(
    paths: &StatePaths,
    event: &RoomEvent,
    payload: OpaquePayload,
    recipients: &[String],
) -> Result<usize, RoomError> {
    for recipient in recipients {
        messages::deliver_room_event_from_paths(
            paths,
            &room_delivery_id(&event.event_id, recipient),
            &event.from_agent_id,
            recipient,
            payload.clone(),
        )?;
    }

    Ok(recipients.len())
}

fn deliver_room_event_to_remote_participants(
    paths: &StatePaths,
    local_node_id: &str,
    event: &RoomEvent,
    payload: OpaquePayload,
    recipients: &[(String, String)],
) -> Result<usize, RoomError> {
    for (recipient_agent_id, peer_node_id) in recipients {
        let remote = RemoteRoomEvent::new(
            event.event_id.clone(),
            event.room_id.clone(),
            event.topic.clone(),
            event.from_agent_id.clone(),
            recipient_agent_id.clone(),
            peer_node_id.clone(),
            payload.clone(),
        )
        .map_err(|error| RoomError::InvalidRequest {
            reason: error.to_string(),
        })?;
        relay_delivery::submit_remote_room_event_from_paths(paths, local_node_id, remote).map_err(
            |error| RoomError::InvalidRequest {
                reason: error.to_string(),
            },
        )?;
    }

    Ok(recipients.len())
}

fn append_room_log(
    paths: &StatePaths,
    event: &'static str,
    room_id: &str,
    agent_id: Option<&str>,
    payload_bytes: usize,
) -> Result<(), RoomError> {
    state::ensure_state_directory(&paths.logs_dir)?;
    let path = paths.logs_dir.join("rooms.log");

    let line = format!(
        "time={} event={} room={} agent={} bytes={} payload=not_observed",
        current_unix_seconds(),
        event,
        sanitize_log_value(room_id),
        agent_id
            .map(sanitize_log_value)
            .unwrap_or_else(|| "none".to_string()),
        payload_bytes
    );

    state::append_regular_state_file(
        &path,
        &(line + "\n"),
        "inspect room log",
        "create room log",
        "open room log",
        "write room log",
    )?;
    Ok(())
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, RoomError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| RoomError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, RoomError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RoomError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 140 {
        return Err(RoomError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RoomError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_display_name(value: String) -> Result<String, RoomError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RoomError::InvalidRequest {
            reason: "display name cannot be empty".to_string(),
        });
    }
    if value.len() > 120 {
        return Err(RoomError::InvalidRequest {
            reason: "display name is too long".to_string(),
        });
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(RoomError::InvalidRequest {
            reason: "display name cannot contain control characters".to_string(),
        });
    }
    Ok(value)
}

fn parse_u64(value: &str) -> Result<u64, RoomError> {
    value.parse::<u64>().map_err(|_| RoomError::InvalidRequest {
        reason: "expected unsigned integer".to_string(),
    })
}

fn parse_usize(value: &str) -> Result<usize, RoomError> {
    value
        .parse::<usize>()
        .map_err(|_| RoomError::InvalidRequest {
            reason: "expected unsigned count".to_string(),
        })
}

fn parse_bool(values: &HashMap<String, String>, key: &'static str) -> Result<bool, RoomError> {
    match values.get(key).map(String::as_str) {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(_) => Err(RoomError::InvalidRequest {
            reason: format!("{key} must be true or false"),
        }),
    }
}

fn clean_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
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

fn room_event_id(room_id: &str, topic: &str, now: u64) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    room_id.hash(&mut hasher);
    topic.hash(&mut hasher);
    now.hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);
    format!("room_event_{:016x}", hasher.finish())
}

fn room_delivery_id(event_id: &str, recipient: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    event_id.hash(&mut hasher);
    recipient.hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);
    format!("room_env_{:016x}", hasher.finish())
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
    use crate::agents::{AgentRegistration, process_gateway_requests, submit_registration};
    use crate::policy::{self, PeerPolicyUpdate};
    use crate::trust;
    use std::env;
    use std::process;

    #[test]
    fn room_flow_records_metadata_only() {
        let home = test_home("flow");
        register_agent(&home, "agent.codex");
        register_agent(&home, "agent.hermes");

        let created = create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");
        let joined =
            join_room(Some(home.clone()), "room.dev", "agent.hermes").expect("agent joins");
        let published = publish_room_event(
            Some(home.clone()),
            "room.dev",
            "agent.hermes",
            "build",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("event publishes");
        let rooms = list_rooms(Some(home.clone())).expect("rooms list");
        let events = list_room_events(Some(home.clone())).expect("events list");
        let inbox = messages::list_agent_inbox(Some(home.clone()), "agent.codex")
            .expect("creator inbox reads");
        let received = messages::read_message_payload(
            Some(home.clone()),
            "agent.codex",
            &inbox[0].envelope_id,
        )
        .expect("room payload reads");
        let registry = fs::read_to_string(StatePaths::from_home(home.clone()).room_registry)
            .expect("registry");
        let event_file =
            fs::read_to_string(StatePaths::from_home(home.clone()).room_events).expect("events");
        let log = fs::read_to_string(home.join("logs").join("rooms.log")).expect("log reads");

        assert_eq!(created.room.participants.len(), 1);
        assert!(joined.joined);
        assert_eq!(published.event.payload_bytes, 24);
        assert_eq!(published.event.route, "room-local");
        assert_eq!(published.local_deliveries, 1);
        assert_eq!(rooms[0].participants.len(), 2);
        assert_eq!(events.len(), 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].from_agent_id, "agent.hermes");
        assert_eq!(inbox[0].payload_bytes, 24);
        assert_eq!(received.as_bytes(), b"private message contents");
        assert!(registry.contains("payload_displayed = false"));
        assert!(event_file.contains("payload_displayed = false"));
        assert!(log.contains("payload=not_observed"));
        assert!(!registry.contains("private message contents"));
        assert!(!event_file.contains("private message contents"));
        assert!(!log.contains("private message contents"));
    }

    #[test]
    fn room_publish_queues_remote_relay_events_without_payloads() {
        let alice_home = test_home("remote-fanout-alice");
        let bob_home = test_home("remote-fanout-bob");
        state::init_state(Some(alice_home.clone())).expect("alice initializes");
        state::init_state(Some(bob_home.clone())).expect("bob initializes");
        let bob_peer = trust::export_peer_card(Some(bob_home.clone())).expect("bob peer card");
        trust::trust_peer_card(Some(alice_home.clone()), bob_peer.clone())
            .expect("alice trusts bob");
        policy::set_peer_policy(
            Some(alice_home.clone()),
            &bob_peer.node_id,
            PeerPolicyUpdate {
                messages: Some(false),
                streams: Some(false),
                rooms: Some(true),
                files: Some(false),
                mailbox: Some(false),
            },
        )
        .expect("alice grants rooms");
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let bob_agent_card =
            agents::export_agent_card(Some(bob_home.clone()), "agent.bob").expect("bob card");
        sessions::trust_remote_agent_card(Some(alice_home.clone()), bob_agent_card)
            .expect("bob remote agent imports");

        create_room(
            Some(alice_home.clone()),
            "room.dev",
            "Dev Room",
            "agent.alice",
        )
        .expect("room creates");
        join_room(Some(alice_home.clone()), "room.dev", "agent.bob").expect("remote agent joins");
        let published = publish_room_event(
            Some(alice_home.clone()),
            "room.dev",
            "agent.alice",
            "build",
            OpaquePayload::from_bytes(b"private room event".to_vec()),
        )
        .expect("room event publishes");
        let paths = StatePaths::from_home(alice_home);
        let requests = fs::read_dir(&paths.relay_outbox_dir)
            .expect("relay outbox reads")
            .map(|entry| entry.expect("relay entry").path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("relay"))
            .collect::<Vec<_>>();
        let request = fs::read_to_string(&requests[0]).expect("relay request reads");

        assert_eq!(published.local_deliveries, 0);
        assert_eq!(published.remote_deliveries, 1);
        assert_eq!(published.event.route, "room-relay");
        assert_eq!(requests.len(), 1);
        assert!(request.contains("type = \"relay_room_event\""));
        assert!(request.contains("kind = \"room_event\""));
        assert!(request.contains("payload_privacy = \"peer_encrypted\""));
        assert!(request.contains("payload_ciphertext_hex"));
        assert!(request.contains("payload_displayed = false"));
        assert!(!request.contains("private room event"));
        assert!(!request.contains("room.dev"));
        assert!(!request.contains("build"));
    }

    #[test]
    fn room_topic_policy_filters_subscribers_without_payloads() {
        let home = test_home("topic-filter");
        register_agent(&home, "agent.codex");
        register_agent(&home, "agent.hermes");
        register_agent(&home, "agent.ops");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");
        join_room(Some(home.clone()), "room.dev", "agent.hermes").expect("hermes joins");
        join_room(Some(home.clone()), "room.dev", "agent.ops").expect("ops joins");
        set_room_topic_policy(
            Some(home.clone()),
            "room.dev",
            "agent.hermes",
            "build",
            RoomTopicPolicyUpdate {
                publish: Some(true),
                subscribe: Some(false),
            },
        )
        .expect("publisher grant writes");
        set_room_topic_policy(
            Some(home.clone()),
            "room.dev",
            "agent.codex",
            "build",
            RoomTopicPolicyUpdate {
                publish: Some(false),
                subscribe: Some(true),
            },
        )
        .expect("codex subscriber grant writes");
        set_room_topic_policy(
            Some(home.clone()),
            "room.dev",
            "agent.ops",
            "build",
            RoomTopicPolicyUpdate {
                publish: Some(false),
                subscribe: Some(false),
            },
        )
        .expect("ops deny writes");

        let published = publish_room_event(
            Some(home.clone()),
            "room.dev",
            "agent.hermes",
            "build",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("event publishes");
        let codex_inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.codex").expect("codex inbox");
        let ops_inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.ops").expect("ops inbox");
        let policy_file =
            fs::read_to_string(StatePaths::from_home(home.clone()).room_policy).expect("policy");
        let log = fs::read_to_string(home.join("logs").join("rooms.log")).expect("log reads");

        assert_eq!(published.local_deliveries, 1);
        assert_eq!(codex_inbox.len(), 1);
        assert!(ops_inbox.is_empty());
        assert!(policy_file.contains("[[topic_policy]]"));
        assert!(policy_file.contains("payload_displayed = false"));
        assert!(log.contains("room_topic_policy_updated"));
        assert!(!policy_file.contains("private message contents"));
        assert!(!log.contains("private message contents"));
    }

    #[test]
    fn room_topic_policy_requires_publish_grant_when_configured() {
        let home = test_home("topic-publish-deny");
        register_agent(&home, "agent.codex");
        register_agent(&home, "agent.hermes");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");
        join_room(Some(home.clone()), "room.dev", "agent.hermes").expect("hermes joins");
        set_room_topic_policy(
            Some(home.clone()),
            "room.dev",
            "agent.codex",
            "build",
            RoomTopicPolicyUpdate {
                publish: Some(false),
                subscribe: Some(true),
            },
        )
        .expect("topic policy writes");

        let error = publish_room_event(
            Some(home),
            "room.dev",
            "agent.hermes",
            "build",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect_err("publisher without explicit grant fails");

        assert!(error.to_string().contains("not allowed to publish"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[cfg(unix)]
    #[test]
    fn room_registry_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("registry-symlink");
        register_agent(&home, "agent.codex");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-room-registry");
        let outside_contents = "outside room registry\n";
        fs::write(&outside, outside_contents).expect("outside registry writes");
        symlink(&outside, &paths.room_registry).expect("room registry symlink creates");

        let error = create_room(Some(home), "room.dev", "Dev Room", "agent.codex")
            .expect_err("symlinked room registry fails closed");

        assert!(error.to_string().contains("inspect room registry"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside registry reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.room_registry)
                .expect("room registry metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn inbound_room_topic_policy_requires_remote_publish_grant() {
        let alice_home = test_home("inbound-topic-alice");
        let bob_home = test_home("inbound-topic-bob");
        state::init_state(Some(alice_home.clone())).expect("alice initializes");
        state::init_state(Some(bob_home.clone())).expect("bob initializes");
        let alice_peer = trust::export_peer_card(Some(alice_home.clone())).expect("alice card");
        trust::trust_peer_card(Some(bob_home.clone()), alice_peer.clone())
            .expect("bob trusts alice");
        policy::set_peer_policy(
            Some(bob_home.clone()),
            &alice_peer.node_id,
            PeerPolicyUpdate {
                messages: Some(false),
                streams: Some(false),
                rooms: Some(true),
                files: Some(false),
                mailbox: Some(false),
            },
        )
        .expect("bob grants alice rooms");
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let alice_agent_card =
            agents::export_agent_card(Some(alice_home), "agent.alice").expect("alice card exports");
        sessions::trust_remote_agent_card(Some(bob_home.clone()), alice_agent_card)
            .expect("alice remote agent imports");
        create_room(Some(bob_home.clone()), "room.dev", "Dev Room", "agent.bob")
            .expect("bob room creates");
        join_room(Some(bob_home.clone()), "room.dev", "agent.alice").expect("alice remote joins");
        set_room_topic_policy(
            Some(bob_home.clone()),
            "room.dev",
            "agent.bob",
            "build",
            RoomTopicPolicyUpdate {
                publish: Some(false),
                subscribe: Some(true),
            },
        )
        .expect("local subscribe policy writes");

        let error = deliver_remote_room_event_from_paths(
            &StatePaths::from_home(bob_home),
            RemoteRoomEventDelivery {
                envelope_id: "roomenv.test".to_string(),
                event_id: "room_event.test".to_string(),
                room_id: "room.dev".to_string(),
                topic: "build".to_string(),
                peer_node_id: alice_peer.node_id,
                from_agent_id: "agent.alice".to_string(),
                to_agent_id: "agent.bob".to_string(),
                payload: OpaquePayload::from_bytes(b"private message contents".to_vec()),
            },
        )
        .expect_err("remote publisher without topic grant fails");

        assert!(error.to_string().contains("not allowed to publish"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn room_publish_requires_joined_agent() {
        let home = test_home("requires-joined");
        register_agent(&home, "agent.codex");
        register_agent(&home, "agent.hermes");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");

        let error = publish_room_event(
            Some(home),
            "room.dev",
            "agent.hermes",
            "build",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect_err("unjoined publisher fails");

        assert!(error.to_string().contains("not joined"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn room_publish_requires_local_publisher() {
        let home = test_home("requires-local-publisher");
        register_agent(&home, "agent.codex");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");

        let error = publish_room_event(
            Some(home),
            "room.dev",
            "agent.remote",
            "build",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect_err("nonlocal publisher fails");

        assert!(error.to_string().contains("registered locally"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn room_join_requires_visible_agent() {
        let home = test_home("visible-agent");
        register_agent(&home, "agent.codex");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");

        let error = join_room(Some(home), "room.dev", "agent.missing")
            .expect_err("missing agent cannot join");

        assert!(error.to_string().contains("not visible"));
    }

    #[test]
    fn room_create_requires_room_capability() {
        let home = test_home("create-capability");
        register_basic_agent(&home, "agent.codex");

        let error = create_room(Some(home), "room.dev", "Dev Room", "agent.codex")
            .expect_err("creator without room capability fails");

        assert!(error.to_string().contains("not allowed to create rooms"));
    }

    #[test]
    fn room_join_requires_room_capability() {
        let home = test_home("join-capability");
        register_agent(&home, "agent.codex");
        register_basic_agent(&home, "agent.hermes");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");

        let error = join_room(Some(home), "room.dev", "agent.hermes")
            .expect_err("participant without room capability fails");

        assert!(error.to_string().contains("not allowed to join rooms"));
    }

    #[test]
    fn room_event_enforces_backpressure_window() {
        let home = test_home("backpressure");
        register_agent(&home, "agent.codex");
        create_room(Some(home.clone()), "room.dev", "Dev Room", "agent.codex")
            .expect("room creates");

        let error = publish_room_event(
            Some(home),
            "room.dev",
            "agent.codex",
            "build",
            OpaquePayload::from_bytes(vec![7; ROOM_BACKPRESSURE_WINDOW + 1]),
        )
        .expect_err("oversized event fails");

        assert!(error.to_string().contains("backpressure"));
    }

    fn register_agent(home: &Path, agent_id: &str) {
        let mut registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        registration.capabilities.rooms = true;
        submit_registration(Some(home.to_path_buf()), registration).expect("submits");
        process_gateway_requests(Some(home.to_path_buf())).expect("processes");
    }

    fn register_basic_agent(home: &Path, agent_id: &str) {
        let registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        submit_registration(Some(home.to_path_buf()), registration).expect("submits");
        process_gateway_requests(Some(home.to_path_buf())).expect("processes");
    }

    fn test_home(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "conu-rooms-test-{}-{}-{name}",
            process::id(),
            current_unix_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }
}
