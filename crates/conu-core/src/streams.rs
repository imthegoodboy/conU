//! Stream lifecycle and payload-safe watch events.
//!
//! Phase 10 records stream metadata, chunk byte counts, and transport events.
//! Stream contents stay opaque and are not written to logs, event files, or CLI
//! watch output.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::OpaquePayload;

use crate::agents;
use crate::direct_transport;
use crate::policy::{self, PeerPermission, PolicyError};
use crate::relay_delivery::{self, RemoteStreamChunk};
use crate::routes;
use crate::sessions;
use crate::state::{self, StateError, StatePaths};

const STREAM_VERSION: &str = "1";
const DEFAULT_BACKPRESSURE_WINDOW: usize = 64 * 1024;

/// Lifecycle state for a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open,
    Closed,
}

impl StreamState {
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

/// Metadata for one active or closed stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRecord {
    pub stream_id: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub kind: String,
    pub state: StreamState,
    pub route: String,
    pub chunks_written: u64,
    pub bytes_written: usize,
    pub backpressure_window: usize,
    pub opened_at_unix: u64,
    pub updated_at_unix: u64,
}

/// Metadata event consumed by `conu watch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    pub event_id: String,
    pub stream_id: String,
    pub event_type: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub route: String,
    pub payload_bytes: usize,
    pub created_at_unix: u64,
}

/// Result of opening a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenReport {
    pub stream: StreamRecord,
}

/// Result of writing one opaque chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWriteReport {
    pub stream: StreamRecord,
    pub event: StreamEvent,
}

/// Result of closing a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCloseReport {
    pub stream: StreamRecord,
    pub event: StreamEvent,
}

/// Errors produced by stream operations.
#[derive(Debug)]
pub enum StreamError {
    State(StateError),
    Agent(agents::AgentError),
    Session(sessions::SessionError),
    Policy(PolicyError),
    Route(routes::RouteError),
    Relay(relay_delivery::RelayDeliveryError),
    Direct(direct_transport::DirectTransportError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRequest {
        reason: String,
    },
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Policy(error) => write!(formatter, "{error}"),
            Self::Route(error) => write!(formatter, "{error}"),
            Self::Relay(error) => write!(formatter, "{error}"),
            Self::Direct(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRequest { reason } => {
                write!(formatter, "invalid stream request: {reason}")
            }
        }
    }
}

impl std::error::Error for StreamError {}

impl From<StateError> for StreamError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<agents::AgentError> for StreamError {
    fn from(error: agents::AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<sessions::SessionError> for StreamError {
    fn from(error: sessions::SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<PolicyError> for StreamError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<routes::RouteError> for StreamError {
    fn from(error: routes::RouteError) -> Self {
        Self::Route(error)
    }
}

impl From<relay_delivery::RelayDeliveryError> for StreamError {
    fn from(error: relay_delivery::RelayDeliveryError) -> Self {
        Self::Relay(error)
    }
}

impl From<direct_transport::DirectTransportError> for StreamError {
    fn from(error: direct_transport::DirectTransportError) -> Self {
        Self::Direct(error)
    }
}

/// Open a stream between a local agent and a visible local or remote agent.
pub fn open_stream(
    home_override: Option<PathBuf>,
    from_agent_id: &str,
    to_agent_id: &str,
    kind: &str,
) -> Result<StreamOpenReport, StreamError> {
    let init = state::init_state(home_override.clone())?;
    let from_agent_id = validate_identifier(from_agent_id.to_string(), "from agent id")?;
    let to_agent_id = validate_identifier(to_agent_id.to_string(), "to agent id")?;
    let kind = validate_identifier(kind.to_string(), "stream kind")?;

    validate_stream_agents(Some(init.paths.home.clone()), &from_agent_id, &to_agent_id)?;
    let route = stream_route_for_target(&init.paths, &to_agent_id)?;

    let now = current_unix_seconds();
    let stream = StreamRecord {
        stream_id: stream_id(&from_agent_id, &to_agent_id, now),
        from_agent_id,
        to_agent_id,
        kind,
        state: StreamState::Open,
        route,
        chunks_written: 0,
        bytes_written: 0,
        backpressure_window: DEFAULT_BACKPRESSURE_WINDOW,
        opened_at_unix: now,
        updated_at_unix: now,
    };

    let mut streams = read_streams(&init.paths)?;
    streams.push(stream.clone());
    write_streams(&init.paths, &streams)?;
    append_event(&init.paths, event_for(&stream, "opened", 0, now))?;
    record_stream_log(&init.paths, "stream_opened", &stream, 0);

    Ok(StreamOpenReport { stream })
}

fn stream_route_for_target(paths: &StatePaths, to_agent_id: &str) -> Result<String, StreamError> {
    if agents::agent_exists(Some(paths.home.clone()), to_agent_id)? {
        return Ok("local".to_string());
    }

    let remote_agents = sessions::list_remote_agents(Some(paths.home.clone()))?;
    let Some(remote_agent) = remote_agents
        .into_iter()
        .find(|agent| agent.agent_id == to_agent_id)
    else {
        return Ok("metadata-relay".to_string());
    };

    let selected = routes::selected_route_for_peer_from_paths(paths, &remote_agent.peer_node_id)?;
    Ok(selected
        .map(|route| route.transport.as_str().to_string())
        .unwrap_or_else(|| "metadata-relay".to_string()))
}

/// Record an opaque stream chunk by byte count only.
pub fn write_stream(
    home_override: Option<PathBuf>,
    stream_id: &str,
    payload: OpaquePayload,
) -> Result<StreamWriteReport, StreamError> {
    let init = state::init_state(home_override)?;
    let stream_id = validate_identifier(stream_id.to_string(), "stream id")?;
    let payload_bytes = payload.len();
    let mut streams = read_streams(&init.paths)?;
    let now = current_unix_seconds();
    let Some(index) = streams
        .iter()
        .position(|stream| stream.stream_id == stream_id)
    else {
        return Err(StreamError::InvalidRequest {
            reason: "stream is not known".to_string(),
        });
    };

    if streams[index].state != StreamState::Open {
        return Err(StreamError::InvalidRequest {
            reason: "stream is closed".to_string(),
        });
    }
    if payload_bytes > streams[index].backpressure_window {
        return Err(StreamError::InvalidRequest {
            reason: "chunk exceeds stream backpressure window".to_string(),
        });
    }
    validate_stream_agents(
        Some(init.paths.home.clone()),
        &streams[index].from_agent_id,
        &streams[index].to_agent_id,
    )?;

    let remote_peer_node_id = remote_peer_for_stream_target(&init.paths, &streams[index])?;
    if let Some(peer_node_id) = remote_peer_node_id {
        let chunk = RemoteStreamChunk::new(
            streams[index].stream_id.clone(),
            streams[index].from_agent_id.clone(),
            streams[index].to_agent_id.clone(),
            peer_node_id,
            payload,
        )?;
        match streams[index].route.as_str() {
            "direct-quic" => match direct_transport::send_direct_stream_chunk_from_paths(
                &init.paths,
                &init.node.node_id,
                chunk.clone(),
            ) {
                Ok(_) => {}
                Err(error) if error.is_safe_for_relay_fallback() => {
                    relay_delivery::submit_remote_stream_chunk_from_paths(
                        &init.paths,
                        &init.node.node_id,
                        chunk,
                    )?;
                    streams[index].route = "relay-websocket".to_string();
                }
                Err(error) => return Err(StreamError::Direct(error)),
            },
            "relay-websocket" | "metadata-relay" => {
                relay_delivery::submit_remote_stream_chunk_from_paths(
                    &init.paths,
                    &init.node.node_id,
                    chunk,
                )?;
            }
            _ => {
                return Err(StreamError::InvalidRequest {
                    reason: "remote stream bytes require an available direct or relay route"
                        .to_string(),
                });
            }
        }
    }

    streams[index].chunks_written = streams[index].chunks_written.saturating_add(1);
    streams[index].bytes_written = streams[index].bytes_written.saturating_add(payload_bytes);
    streams[index].updated_at_unix = now;
    let stream = streams[index].clone();
    let event = event_for(&stream, "chunk", payload_bytes, now);

    write_streams(&init.paths, &streams)?;
    append_event(&init.paths, event.clone())?;
    record_stream_log(&init.paths, "stream_chunk", &stream, payload_bytes);

    Ok(StreamWriteReport { stream, event })
}

/// Close an open stream.
pub fn close_stream(
    home_override: Option<PathBuf>,
    stream_id: &str,
) -> Result<StreamCloseReport, StreamError> {
    let init = state::init_state(home_override)?;
    let stream_id = validate_identifier(stream_id.to_string(), "stream id")?;
    let mut streams = read_streams(&init.paths)?;
    let now = current_unix_seconds();
    let Some(index) = streams
        .iter()
        .position(|stream| stream.stream_id == stream_id)
    else {
        return Err(StreamError::InvalidRequest {
            reason: "stream is not known".to_string(),
        });
    };

    streams[index].state = StreamState::Closed;
    streams[index].updated_at_unix = now;
    let stream = streams[index].clone();
    let event = event_for(&stream, "closed", 0, now);

    write_streams(&init.paths, &streams)?;
    append_event(&init.paths, event.clone())?;
    record_stream_log(&init.paths, "stream_closed", &stream, 0);

    Ok(StreamCloseReport { stream, event })
}

/// List stream metadata.
pub fn list_streams(home_override: Option<PathBuf>) -> Result<Vec<StreamRecord>, StreamError> {
    let paths = StatePaths::resolve(home_override)?;
    read_streams(&paths)
}

/// List watch events in chronological order.
pub fn list_events(home_override: Option<PathBuf>) -> Result<Vec<StreamEvent>, StreamError> {
    let paths = StatePaths::resolve(home_override)?;
    read_events(&paths)
}

fn validate_stream_agents(
    home_override: Option<PathBuf>,
    from_agent_id: &str,
    to_agent_id: &str,
) -> Result<(), StreamError> {
    let local_agents = agents::list_local_agents(home_override.clone())?;
    let Some(source) = local_agents
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
    else {
        return Err(StreamError::InvalidRequest {
            reason: "source agent is not registered locally".to_string(),
        });
    };

    if !source.capabilities.streams {
        return Err(StreamError::InvalidRequest {
            reason: "source agent is not allowed to open streams".to_string(),
        });
    }

    if let Some(target) = local_agents
        .iter()
        .find(|agent| agent.agent_id == to_agent_id)
    {
        if !target.capabilities.streams {
            return Err(StreamError::InvalidRequest {
                reason: "target agent is not allowed to receive streams".to_string(),
            });
        }
        return Ok(());
    }

    if let Some(remote_target) = sessions::list_remote_agents(home_override.clone())?
        .into_iter()
        .find(|agent| agent.agent_id == to_agent_id)
    {
        if !remote_target.capabilities.streams {
            return Err(StreamError::InvalidRequest {
                reason: "target remote agent is not advertised for streams".to_string(),
            });
        }
        let paths = StatePaths::resolve(home_override)?;
        policy::ensure_peer_allowed_from_paths(
            &paths,
            &remote_target.peer_node_id,
            PeerPermission::Streams,
        )?;
        return Ok(());
    }

    Err(StreamError::InvalidRequest {
        reason: "target agent is not visible locally or through trusted remote discovery"
            .to_string(),
    })
}

fn remote_peer_for_stream_target(
    paths: &StatePaths,
    stream: &StreamRecord,
) -> Result<Option<String>, StreamError> {
    if agents::agent_exists(Some(paths.home.clone()), &stream.to_agent_id)? {
        return Ok(None);
    }

    Ok(sessions::list_remote_agents(Some(paths.home.clone()))?
        .into_iter()
        .find(|agent| agent.agent_id == stream.to_agent_id)
        .map(|agent| agent.peer_node_id))
}

fn read_streams(paths: &StatePaths) -> Result<Vec<StreamRecord>, StreamError> {
    if !state::state_directory_exists(&paths.streams_dir, "inspect streams directory")? {
        return Ok(Vec::new());
    }
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.stream_registry,
        "inspect stream registry",
        "read stream registry",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_streams(&contents)
}

fn write_streams(paths: &StatePaths, streams: &[StreamRecord]) -> Result<(), StreamError> {
    ensure_streams_directory(paths)?;
    let mut sorted = streams.to_vec();
    sorted.sort_by(|left, right| left.stream_id.cmp(&right.stream_id));
    let mut contents = format!("# conU stream registry\nversion = \"{}\"\n", STREAM_VERSION);

    for stream in sorted {
        contents.push_str("\n[[stream]]\n");
        contents.push_str(&format!(
            "stream_id = \"{}\"\n",
            escape_file_value(&stream.stream_id)
        ));
        contents.push_str(&format!(
            "from_agent_id = \"{}\"\n",
            escape_file_value(&stream.from_agent_id)
        ));
        contents.push_str(&format!(
            "to_agent_id = \"{}\"\n",
            escape_file_value(&stream.to_agent_id)
        ));
        contents.push_str(&format!("kind = \"{}\"\n", escape_file_value(&stream.kind)));
        contents.push_str(&format!("state = \"{}\"\n", stream.state.as_str()));
        contents.push_str(&format!(
            "route = \"{}\"\n",
            escape_file_value(&stream.route)
        ));
        contents.push_str(&format!("chunks_written = {}\n", stream.chunks_written));
        contents.push_str(&format!("bytes_written = {}\n", stream.bytes_written));
        contents.push_str(&format!(
            "backpressure_window = {}\n",
            stream.backpressure_window
        ));
        contents.push_str(&format!("opened_at_unix = {}\n", stream.opened_at_unix));
        contents.push_str(&format!("updated_at_unix = {}\n", stream.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.stream_registry,
        &contents,
        "inspect stream registry",
        "create stream registry",
        "open stream registry",
        "write stream registry",
    )?;
    Ok(())
}

fn append_event(paths: &StatePaths, event: StreamEvent) -> Result<(), StreamError> {
    ensure_streams_directory(paths)?;
    let mut events = read_events(paths)?;
    events.push(event);
    write_events(paths, &events)
}

fn read_events(paths: &StatePaths) -> Result<Vec<StreamEvent>, StreamError> {
    if !state::state_directory_exists(&paths.streams_dir, "inspect streams directory")? {
        return Ok(Vec::new());
    }
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.stream_events,
        "inspect stream events",
        "read stream events",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_events(&contents)
}

fn write_events(paths: &StatePaths, events: &[StreamEvent]) -> Result<(), StreamError> {
    ensure_streams_directory(paths)?;
    let mut contents = format!(
        "# conU stream event bus\nversion = \"{}\"\n",
        STREAM_VERSION
    );

    for event in events {
        contents.push_str("\n[[event]]\n");
        contents.push_str(&format!(
            "event_id = \"{}\"\n",
            escape_file_value(&event.event_id)
        ));
        contents.push_str(&format!(
            "stream_id = \"{}\"\n",
            escape_file_value(&event.stream_id)
        ));
        contents.push_str(&format!(
            "event_type = \"{}\"\n",
            escape_file_value(&event.event_type)
        ));
        contents.push_str(&format!(
            "from_agent_id = \"{}\"\n",
            escape_file_value(&event.from_agent_id)
        ));
        contents.push_str(&format!(
            "to_agent_id = \"{}\"\n",
            escape_file_value(&event.to_agent_id)
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
        &paths.stream_events,
        &contents,
        "inspect stream events",
        "create stream events",
        "open stream events",
        "write stream events",
    )?;
    Ok(())
}

fn ensure_streams_directory(paths: &StatePaths) -> Result<(), StreamError> {
    state::ensure_state_directory(&paths.streams_dir)?;
    Ok(())
}

fn parse_streams(contents: &str) -> Result<Vec<StreamRecord>, StreamError> {
    let mut streams = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[stream]]" {
            if !current.is_empty() {
                streams.push(stream_from_values(&current)?);
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
        streams.push(stream_from_values(&current)?);
    }

    Ok(streams)
}

fn parse_events(contents: &str) -> Result<Vec<StreamEvent>, StreamError> {
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

fn stream_from_values(values: &HashMap<String, String>) -> Result<StreamRecord, StreamError> {
    Ok(StreamRecord {
        stream_id: validate_identifier(required(values, "stream_id")?, "stream id")?,
        from_agent_id: validate_identifier(required(values, "from_agent_id")?, "from agent id")?,
        to_agent_id: validate_identifier(required(values, "to_agent_id")?, "to agent id")?,
        kind: validate_identifier(required(values, "kind")?, "stream kind")?,
        state: StreamState::from_str(&required(values, "state")?),
        route: validate_identifier(required(values, "route")?, "route")?,
        chunks_written: parse_u64(&required(values, "chunks_written")?)?,
        bytes_written: parse_usize(&required(values, "bytes_written")?)?,
        backpressure_window: parse_usize(&required(values, "backpressure_window")?)?,
        opened_at_unix: parse_u64(&required(values, "opened_at_unix")?)?,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn event_from_values(values: &HashMap<String, String>) -> Result<StreamEvent, StreamError> {
    Ok(StreamEvent {
        event_id: validate_identifier(required(values, "event_id")?, "event id")?,
        stream_id: validate_identifier(required(values, "stream_id")?, "stream id")?,
        event_type: validate_identifier(required(values, "event_type")?, "event type")?,
        from_agent_id: validate_identifier(required(values, "from_agent_id")?, "from agent id")?,
        to_agent_id: validate_identifier(required(values, "to_agent_id")?, "to agent id")?,
        route: validate_identifier(required(values, "route")?, "route")?,
        payload_bytes: parse_usize(&required(values, "payload_bytes")?)?,
        created_at_unix: parse_u64(&required(values, "created_at_unix")?)?,
    })
}

fn event_for(
    stream: &StreamRecord,
    event_type: &'static str,
    payload_bytes: usize,
    now: u64,
) -> StreamEvent {
    StreamEvent {
        event_id: event_id(&stream.stream_id, event_type, now),
        stream_id: stream.stream_id.clone(),
        event_type: event_type.to_string(),
        from_agent_id: stream.from_agent_id.clone(),
        to_agent_id: stream.to_agent_id.clone(),
        route: stream.route.clone(),
        payload_bytes,
        created_at_unix: now,
    }
}

fn append_stream_log(
    paths: &StatePaths,
    event: &'static str,
    stream: &StreamRecord,
    payload_bytes: usize,
) -> Result<(), StreamError> {
    state::ensure_state_directory(&paths.logs_dir)?;
    let path = paths.logs_dir.join("streams.log");

    let line = format!(
        "event={} stream={} from={} to={} route={} bytes={} chunks={} state={} payload=not_observed",
        event,
        stream.stream_id,
        stream.from_agent_id,
        stream.to_agent_id,
        stream.route,
        payload_bytes,
        stream.chunks_written,
        stream.state.as_str()
    );

    state::append_regular_state_file(
        &path,
        &(line + "\n"),
        "inspect stream log",
        "create stream log",
        "open stream log",
        "write stream log",
    )?;
    Ok(())
}

fn record_stream_log(
    paths: &StatePaths,
    event: &'static str,
    stream: &StreamRecord,
    payload_bytes: usize,
) {
    let _ = append_stream_log(paths, event, stream, payload_bytes);
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, StreamError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| StreamError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, StreamError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(StreamError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 140 {
        return Err(StreamError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(StreamError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn parse_u64(value: &str) -> Result<u64, StreamError> {
    value
        .parse::<u64>()
        .map_err(|_| StreamError::InvalidRequest {
            reason: "expected unsigned integer".to_string(),
        })
}

fn parse_usize(value: &str) -> Result<usize, StreamError> {
    value
        .parse::<usize>()
        .map_err(|_| StreamError::InvalidRequest {
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

fn stream_id(from_agent_id: &str, to_agent_id: &str, now: u64) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    from_agent_id.hash(&mut hasher);
    to_agent_id.hash(&mut hasher);
    now.hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);
    format!("stream_{:016x}", hasher.finish())
}

fn event_id(stream_id: &str, event_type: &str, now: u64) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    stream_id.hash(&mut hasher);
    event_type.hash(&mut hasher);
    now.hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);
    format!("event_{:016x}", hasher.finish())
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
    use crate::trust;
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process;

    #[test]
    fn stream_lifecycle_records_metadata_only() {
        let home = test_home("stream-lifecycle");
        register_agent(&home, "agent.a");
        register_agent(&home, "agent.b");

        let opened =
            open_stream(Some(home.clone()), "agent.a", "agent.b", "message").expect("stream opens");
        let written = write_stream(
            Some(home.clone()),
            &opened.stream.stream_id,
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("stream writes");
        let closed =
            close_stream(Some(home.clone()), &opened.stream.stream_id).expect("stream closes");
        let events = list_events(Some(home.clone())).expect("events read");
        let log = fs::read_to_string(home.join("logs").join("streams.log")).expect("log reads");

        assert_eq!(written.stream.bytes_written, 24);
        assert_eq!(written.stream.chunks_written, 1);
        assert_eq!(closed.stream.state, StreamState::Closed);
        assert_eq!(events.len(), 3);
        assert!(log.contains("payload=not_observed"));
        assert!(!log.contains("private message contents"));
        assert!(!log.contains("Review this code"));
    }

    #[test]
    fn stream_lifecycle_success_does_not_depend_on_stream_log_write() {
        let home = test_home("stream-log-collision");
        register_agent(&home, "agent.a");
        register_agent(&home, "agent.b");
        let stream_log = StatePaths::from_home(home.clone())
            .logs_dir
            .join("streams.log");
        fs::create_dir(&stream_log).expect("stream log collision creates");

        let opened =
            open_stream(Some(home.clone()), "agent.a", "agent.b", "message").expect("opens");
        let written = write_stream(
            Some(home.clone()),
            &opened.stream.stream_id,
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("writes");
        let closed = close_stream(Some(home.clone()), &opened.stream.stream_id).expect("closes");
        let events = list_events(Some(home)).expect("events read");

        assert_eq!(written.stream.chunks_written, 1);
        assert_eq!(closed.stream.state, StreamState::Closed);
        assert_eq!(events.len(), 3);
        assert!(stream_log.is_dir());
    }

    #[test]
    fn stream_write_enforces_backpressure_window() {
        let home = test_home("stream-backpressure");
        register_agent(&home, "agent.a");
        register_agent(&home, "agent.b");
        let opened =
            open_stream(Some(home.clone()), "agent.a", "agent.b", "message").expect("opens");
        let error = write_stream(
            Some(home),
            &opened.stream.stream_id,
            OpaquePayload::from_bytes(vec![7; DEFAULT_BACKPRESSURE_WINDOW + 1]),
        )
        .expect_err("oversized chunk fails");

        assert!(error.to_string().contains("backpressure"));
    }

    #[cfg(unix)]
    #[test]
    fn stream_registry_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("registry-symlink");
        register_agent(&home, "agent.a");
        register_agent(&home, "agent.b");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-stream-registry");
        let outside_contents = "outside stream registry\n";
        fs::write(&outside, outside_contents).expect("outside registry writes");
        symlink(&outside, &paths.stream_registry).expect("stream registry symlink creates");

        let error = open_stream(Some(home), "agent.a", "agent.b", "message")
            .expect_err("symlinked stream registry fails closed");

        assert!(error.to_string().contains("inspect stream registry"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside registry reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.stream_registry)
                .expect("stream registry metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn stream_directory_symlink_is_rejected_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("streams-dir-write-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-streams-dir-write");
        fs::remove_dir_all(&paths.streams_dir).expect("streams dir removes");
        fs::create_dir_all(&outside).expect("outside streams dir creates");
        symlink(&outside, &paths.streams_dir).expect("streams dir symlink creates");

        let error = write_streams(&paths, &[test_stream_record()])
            .expect_err("symlinked streams directory fails closed");

        assert!(error.to_string().contains("state directory"));
        assert!(!outside.join("registry.toml").exists());
        assert!(
            fs::symlink_metadata(&paths.streams_dir)
                .expect("streams dir metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn stream_listing_rejects_symlinked_stream_directory_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("streams-dir-list-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-streams-dir-list");
        fs::remove_dir_all(&paths.streams_dir).expect("streams dir removes");
        fs::create_dir_all(&outside).expect("outside streams dir creates");
        fs::write(
            outside.join("registry.toml"),
            test_stream_registry_contents(),
        )
        .expect("outside registry writes");
        symlink(&outside, &paths.streams_dir).expect("streams dir symlink creates");

        let error = list_streams(Some(home)).expect_err("symlinked streams directory fails closed");

        assert!(error.to_string().contains("inspect streams directory"));
    }

    #[cfg(unix)]
    #[test]
    fn stream_event_listing_rejects_symlinked_stream_directory_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("streams-dir-events-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-streams-dir-events");
        fs::remove_dir_all(&paths.streams_dir).expect("streams dir removes");
        fs::create_dir_all(&outside).expect("outside streams dir creates");
        fs::write(outside.join("events.toml"), test_stream_events_contents())
            .expect("outside events write");
        symlink(&outside, &paths.streams_dir).expect("streams dir symlink creates");

        let error = list_events(Some(home)).expect_err("symlinked streams directory fails closed");

        assert!(error.to_string().contains("inspect streams directory"));
    }

    #[cfg(unix)]
    #[test]
    fn stream_log_symlink_does_not_block_persisted_stream_open() {
        use std::os::unix::fs::symlink;

        let home = test_home("log-symlink");
        register_agent(&home, "agent.a");
        register_agent(&home, "agent.b");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-stream-log");
        let outside_contents = "outside stream log\n";
        fs::write(&outside, outside_contents).expect("outside log writes");
        symlink(&outside, paths.logs_dir.join("streams.log")).expect("stream log symlink creates");

        let opened = open_stream(Some(home.clone()), "agent.a", "agent.b", "message")
            .expect("stream opens despite symlinked stream log");
        let streams = list_streams(Some(home)).expect("streams read");

        assert_eq!(opened.stream.stream_id, streams[0].stream_id);
        assert_eq!(
            fs::read_to_string(&outside).expect("outside log reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(paths.logs_dir.join("streams.log"))
                .expect("stream log metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn remote_stream_write_queues_peer_encrypted_chunk_without_payload() {
        let alice_home = test_home("remote-stream-alice");
        let bob_home = test_home("remote-stream-bob");
        let bob_card = trust::export_peer_card(Some(bob_home.clone())).expect("bob card exports");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");
        grant_peer_policy(&alice_home, &bob_peer.peer_node_id, false, true, false);
        fs::write(
            StatePaths::from_home(alice_home.clone()).config,
            "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"public\"\ndirect_quic_endpoint = \"quic://127.0.0.1:9443\"\n",
        )
        .expect("config writes");
        routes::sync_routes(Some(alice_home.clone())).expect("routes sync");
        register_agent(&alice_home, "agent.alice");
        write_remote_agent(&alice_home, "agent.bob", &node_id(&bob_home));

        let opened = open_stream(
            Some(alice_home.clone()),
            "agent.alice",
            "agent.bob",
            "message",
        )
        .expect("remote stream opens");
        let written = write_stream(
            Some(alice_home.clone()),
            &opened.stream.stream_id,
            OpaquePayload::from_bytes(b"private stream chunk".to_vec()),
        )
        .expect("remote stream chunk queues");
        let paths = StatePaths::from_home(alice_home);
        let requests = fs::read_dir(&paths.relay_outbox_dir)
            .expect("relay outbox reads")
            .collect::<Result<Vec<_>, _>>()
            .expect("relay entries read");
        let contents = fs::read_to_string(requests[0].path()).expect("request reads");

        assert_eq!(opened.stream.route, "relay-websocket");
        assert_eq!(written.stream.chunks_written, 1);
        assert_eq!(written.stream.bytes_written, 20);
        assert_eq!(requests.len(), 1);
        assert!(contents.contains("type = \"relay_stream_chunk\""));
        assert!(contents.contains("kind = \"stream_chunk\""));
        assert!(contents.contains(&format!("stream_id = \"{}\"", opened.stream.stream_id)));
        assert!(contents.contains("payload_ciphertext_hex"));
        assert!(!contents.contains("private stream chunk"));
    }

    #[test]
    fn stream_requires_visible_target_agent() {
        let home = test_home("stream-target");
        register_agent(&home, "agent.a");

        let error = open_stream(Some(home), "agent.a", "agent.missing", "message")
            .expect_err("unknown target fails");

        assert!(error.to_string().contains("target agent"));
    }

    #[test]
    fn stream_open_requires_source_stream_capability() {
        let home = test_home("stream-source-capability");
        register_basic_agent(&home, "agent.a");
        register_agent(&home, "agent.b");

        let error = open_stream(Some(home), "agent.a", "agent.b", "message")
            .expect_err("source without stream capability fails");

        assert!(error.to_string().contains("not allowed to open streams"));
    }

    #[test]
    fn stream_open_requires_target_stream_capability() {
        let home = test_home("stream-target-capability");
        register_agent(&home, "agent.a");
        register_basic_agent(&home, "agent.b");

        let error = open_stream(Some(home), "agent.a", "agent.b", "message")
            .expect_err("target without stream capability fails");

        assert!(error.to_string().contains("not allowed to receive streams"));
    }

    fn register_agent(home: &Path, agent_id: &str) {
        let mut registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        registration.capabilities.streams = true;
        submit_registration(Some(home.to_path_buf()), registration).expect("submits");
        process_gateway_requests(Some(home.to_path_buf())).expect("processes");
    }

    fn register_basic_agent(home: &Path, agent_id: &str) {
        let registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        submit_registration(Some(home.to_path_buf()), registration).expect("submits");
        process_gateway_requests(Some(home.to_path_buf())).expect("processes");
    }

    fn write_remote_agent(home: &Path, agent_id: &str, peer_node_id: &str) {
        let paths = StatePaths::from_home(home.to_path_buf());
        fs::create_dir_all(&paths.agents_dir).expect("agents dir");
        fs::write(
            &paths.remote_agent_registry,
            format!(
                "# conU remote agent registry\nversion = \"1\"\n\n[[remote_agent]]\nagent_id = \"{agent_id}\"\ndisplay_name = \"Remote Bob\"\npeer_node_id = \"{peer_node_id}\"\nnode_id = \"{peer_node_id}\"\nkind = \"remote-agent\"\npresence = \"ready\"\nlast_seen_unix = {}\ncap_messages = true\ncap_streams = true\ncap_rooms = false\ncap_files = false\ncap_presence = true\npayload_displayed = false\n",
                current_unix_seconds()
            ),
        )
        .expect("remote agent writes");
    }

    fn grant_peer_policy(
        home: &Path,
        peer_node_id: &str,
        messages: bool,
        streams: bool,
        rooms: bool,
    ) {
        policy::set_peer_policy(
            Some(home.to_path_buf()),
            peer_node_id,
            policy::PeerPolicyUpdate {
                messages: Some(messages),
                streams: Some(streams),
                rooms: Some(rooms),
                files: Some(false),
                mailbox: Some(false),
            },
        )
        .expect("peer policy grants");
    }

    fn node_id(home: &Path) -> String {
        state::read_state(Some(home.to_path_buf()))
            .expect("state reads")
            .node
            .expect("node exists")
            .node_id
    }

    fn test_home(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "conu-streams-test-{}-{}-{name}",
            process::id(),
            current_unix_seconds()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[cfg(unix)]
    fn test_stream_record() -> StreamRecord {
        StreamRecord {
            stream_id: "stream.outside".to_string(),
            from_agent_id: "agent.outside.a".to_string(),
            to_agent_id: "agent.outside.b".to_string(),
            kind: "message".to_string(),
            state: StreamState::Open,
            route: "local".to_string(),
            chunks_written: 0,
            bytes_written: 0,
            backpressure_window: DEFAULT_BACKPRESSURE_WINDOW,
            opened_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    #[cfg(unix)]
    fn test_stream_registry_contents() -> &'static str {
        "# conU stream registry\nversion = \"1\"\n\n[[stream]]\nstream_id = \"stream.outside\"\nfrom_agent_id = \"agent.outside.a\"\nto_agent_id = \"agent.outside.b\"\nkind = \"message\"\nstate = \"open\"\nroute = \"local\"\nchunks_written = 0\nbytes_written = 0\nbackpressure_window = 65536\nopened_at_unix = 1\nupdated_at_unix = 1\npayload_displayed = false\n"
    }

    #[cfg(unix)]
    fn test_stream_events_contents() -> &'static str {
        "# conU stream event bus\nversion = \"1\"\n\n[[event]]\nevent_id = \"event.outside\"\nstream_id = \"stream.outside\"\nevent_type = \"chunk\"\nfrom_agent_id = \"agent.outside.a\"\nto_agent_id = \"agent.outside.b\"\nroute = \"local\"\npayload_bytes = 10\ncreated_at_unix = 1\npayload_displayed = false\n"
    }
}
