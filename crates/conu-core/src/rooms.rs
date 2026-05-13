//! Room and pub/sub metadata.
//!
//! Phase 14 gives agents a shared room/session surface without making conU the
//! conversation owner. Room publishes record topic, byte counts, participants,
//! route labels, and timestamps only. Payload bytes remain opaque and are never
//! written to room files, logs, or CLI views.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::OpaquePayload;

use crate::agents;
use crate::messages;
use crate::sessions;
use crate::state::{self, StateError, StatePaths};

const ROOM_VERSION: &str = "1";
const ROOM_BACKPRESSURE_WINDOW: usize = 64 * 1024;

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
}

/// Errors produced by room operations.
#[derive(Debug)]
pub enum RoomError {
    State(StateError),
    Agent(agents::AgentError),
    Message(messages::MessageError),
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
    let init = state::init_state(home_override.clone())?;
    let room_id = validate_identifier(room_id.to_string(), "room id")?;
    let display_name = validate_display_name(display_name.to_string())?;
    let created_by_agent_id =
        validate_identifier(created_by_agent_id.to_string(), "creator agent id")?;

    if !agents::agent_exists(home_override, &created_by_agent_id)? {
        return Err(RoomError::InvalidRequest {
            reason: "creator agent is not registered locally".to_string(),
        });
    }

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
    let scope = visible_agent_scope(home_override, &agent_id)?;
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

    if !agents::agent_exists(Some(init.paths.home.clone()), &from_agent_id)? {
        return Err(RoomError::InvalidRequest {
            reason: "publishing agent must be registered locally".to_string(),
        });
    }
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
    let local_recipients = local_room_recipients(&room, &from_agent_id);
    let local_deliveries =
        deliver_room_event_to_local_participants(&init.paths, &event, payload, &local_recipients)?;

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
    })
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

fn visible_agent_scope(
    home_override: Option<PathBuf>,
    agent_id: &str,
) -> Result<RoomParticipantScope, RoomError> {
    if agents::agent_exists(home_override.clone(), agent_id)? {
        return Ok(RoomParticipantScope::Local);
    }

    let remote_visible = sessions::list_remote_agents(home_override)?
        .into_iter()
        .any(|agent| agent.agent_id == agent_id);
    if remote_visible {
        return Ok(RoomParticipantScope::Remote);
    }

    Err(RoomError::InvalidRequest {
        reason: "agent is not visible locally or through trusted remote discovery".to_string(),
    })
}

fn read_rooms(paths: &StatePaths) -> Result<Vec<RoomRecord>, RoomError> {
    if !paths.room_registry.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&paths.room_registry)
        .map_err(|error| RoomError::io("read room registry", &paths.room_registry, error))?;
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

    fs::write(&paths.room_registry, contents)
        .map_err(|error| RoomError::io("write room registry", &paths.room_registry, error))
}

fn append_event(paths: &StatePaths, event: RoomEvent) -> Result<(), RoomError> {
    fs::create_dir_all(&paths.rooms_dir)
        .map_err(|error| RoomError::io("create rooms directory", &paths.rooms_dir, error))?;
    let mut events = read_events(paths)?;
    events.push(event);
    write_events(paths, &events)
}

fn read_events(paths: &StatePaths) -> Result<Vec<RoomEvent>, RoomError> {
    if !paths.room_events.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&paths.room_events)
        .map_err(|error| RoomError::io("read room events", &paths.room_events, error))?;
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

    fs::write(&paths.room_events, contents)
        .map_err(|error| RoomError::io("write room events", &paths.room_events, error))
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
        "room-relay-metadata".to_string()
    } else {
        "room-local".to_string()
    }
}

fn local_room_recipients(room: &RoomRecord, from_agent_id: &str) -> Vec<String> {
    room.participants
        .iter()
        .filter(|participant| {
            participant.scope == RoomParticipantScope::Local
                && participant.agent_id != from_agent_id
        })
        .map(|participant| participant.agent_id.clone())
        .collect()
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

fn append_room_log(
    paths: &StatePaths,
    event: &'static str,
    room_id: &str,
    agent_id: Option<&str>,
    payload_bytes: usize,
) -> Result<(), RoomError> {
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| RoomError::io("create logs directory", &paths.logs_dir, error))?;
    let path = paths.logs_dir.join("rooms.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| RoomError::io("open room log", &path, error))?;

    writeln!(
        file,
        "time={} event={} room={} agent={} bytes={} payload=not_observed",
        current_unix_seconds(),
        event,
        sanitize_log_value(room_id),
        agent_id
            .map(sanitize_log_value)
            .unwrap_or_else(|| "none".to_string()),
        payload_bytes
    )
    .map_err(|error| RoomError::io("write room log", &path, error))
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
