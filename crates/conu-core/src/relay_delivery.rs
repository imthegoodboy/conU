//! Relay-backed encrypted message delivery.
//!
//! This module is the first live internet data-plane slice. It queues local
//! agent bytes as peer-encrypted envelopes, syncs them over the blind WebSocket
//! relay, and delivers decrypted inbound envelopes into the addressed local
//! agent inbox. Logs and reports remain metadata-only.

use std::collections::{HashMap, hash_map::DefaultHasher};
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conu_protocol::OpaquePayload;

use crate::agents::{self, AgentError};
use crate::messages::{self, InboxEntry, MessageError};
use crate::policy::{self, PeerPermission, PolicyError};
use crate::relay::{
    RelayClientFrame, RelayEnvelopeKind, RelayForward, RelayFrameError, RelayHello,
    RelayOpaqueBody, RelayServerFrame, RelayWebSocketClient,
};
use crate::rooms;
use crate::security::{self, PeerEncryptedPayload, SecurityError};
use crate::sessions::{self, SessionError};
use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus, TrustedPeer};

const RELAY_REQUEST_VERSION: &str = "1";
const DEFAULT_RELAY_ENDPOINT: &str = "ws://127.0.0.1:8787";
const DEFAULT_RELAY_TOKEN: &str = "local-dev-token";
const MAX_RELAY_PAYLOAD_BYTES: usize = 64 * 1024;
const AGENT_CARD_TARGET_AGENT_ID: &str = "conu.discovery";
const ROOM_EVENT_PACKET_MAGIC: &[u8] = b"CONU_ROOM_EVENT_V1\0";

/// Opaque remote message submitted by a local agent.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteMessage {
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub peer_node_id: String,
    pub payload: OpaquePayload,
}

impl RemoteMessage {
    pub fn new(
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        payload: OpaquePayload,
    ) -> Result<Self, RelayDeliveryError> {
        if payload.is_empty() {
            return Err(RelayDeliveryError::InvalidRequest {
                reason: "room event payload cannot be empty".to_string(),
            });
        }
        validate_payload_size(payload.len())?;

        Ok(Self {
            from_agent_id: validate_identifier(from_agent_id.into(), "from agent id")?,
            to_agent_id: validate_identifier(to_agent_id.into(), "to agent id")?,
            peer_node_id: validate_identifier(peer_node_id.into(), "peer node id")?,
            payload,
        })
    }
}

impl fmt::Debug for RemoteMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteMessage")
            .field("from_agent_id", &self.from_agent_id)
            .field("to_agent_id", &self.to_agent_id)
            .field("peer_node_id", &self.peer_node_id)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<opaque>")
            .finish()
    }
}

/// Opaque stream chunk submitted by a local agent for relay delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteStreamChunk {
    pub stream_id: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub peer_node_id: String,
    pub payload: OpaquePayload,
}

impl RemoteStreamChunk {
    pub fn new(
        stream_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        payload: OpaquePayload,
    ) -> Result<Self, RelayDeliveryError> {
        validate_payload_size(payload.len())?;

        Ok(Self {
            stream_id: validate_identifier(stream_id.into(), "stream id")?,
            from_agent_id: validate_identifier(from_agent_id.into(), "from agent id")?,
            to_agent_id: validate_identifier(to_agent_id.into(), "to agent id")?,
            peer_node_id: validate_identifier(peer_node_id.into(), "peer node id")?,
            payload,
        })
    }
}

impl fmt::Debug for RemoteStreamChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteStreamChunk")
            .field("stream_id", &self.stream_id)
            .field("from_agent_id", &self.from_agent_id)
            .field("to_agent_id", &self.to_agent_id)
            .field("peer_node_id", &self.peer_node_id)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<opaque>")
            .finish()
    }
}

/// Opaque room event submitted by a local agent for relay fanout.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteRoomEvent {
    pub event_id: String,
    pub room_id: String,
    pub topic: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub peer_node_id: String,
    pub payload: OpaquePayload,
}

impl RemoteRoomEvent {
    pub fn new(
        event_id: impl Into<String>,
        room_id: impl Into<String>,
        topic: impl Into<String>,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        payload: OpaquePayload,
    ) -> Result<Self, RelayDeliveryError> {
        validate_payload_size(payload.len())?;

        Ok(Self {
            event_id: validate_identifier(event_id.into(), "room event id")?,
            room_id: validate_identifier(room_id.into(), "room id")?,
            topic: validate_identifier(topic.into(), "room topic")?,
            from_agent_id: validate_identifier(from_agent_id.into(), "from agent id")?,
            to_agent_id: validate_identifier(to_agent_id.into(), "to agent id")?,
            peer_node_id: validate_identifier(peer_node_id.into(), "peer node id")?,
            payload,
        })
    }
}

impl fmt::Debug for RemoteRoomEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRoomEvent")
            .field("event_id", &self.event_id)
            .field("room_id", &self.room_id)
            .field("topic", &self.topic)
            .field("from_agent_id", &self.from_agent_id)
            .field("to_agent_id", &self.to_agent_id)
            .field("peer_node_id", &self.peer_node_id)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<opaque>")
            .finish()
    }
}

/// Result of queueing a remote relay message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMessageSubmission {
    pub request_id: String,
    pub envelope_id: String,
    pub request_path: PathBuf,
    pub peer_node_id: String,
    pub payload_bytes: usize,
}

/// Result of queueing a remote relay stream chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStreamChunkSubmission {
    pub request_id: String,
    pub envelope_id: String,
    pub request_path: PathBuf,
    pub peer_node_id: String,
    pub stream_id: String,
    pub payload_bytes: usize,
}

/// Result of queueing a remote relay room event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRoomEventSubmission {
    pub request_id: String,
    pub envelope_id: String,
    pub event_id: String,
    pub request_path: PathBuf,
    pub peer_node_id: String,
    pub payload_bytes: usize,
}

/// One relay sync pass summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySyncReport {
    pub endpoint: String,
    pub connected: bool,
    pub queued: usize,
    pub sent: usize,
    pub received: usize,
    pub undelivered: usize,
    pub rejected: usize,
    pub inbox_entries: Vec<InboxEntry>,
}

/// Current relay queue counts for CLI status/watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayQueueSummary {
    pub queued: usize,
    pub sent: usize,
    pub rejected: usize,
}

/// Long-lived relay session owned by the daemon runtime.
#[derive(Default)]
pub struct RelayRuntimePump {
    endpoint: Option<String>,
    session_id: Option<String>,
    resume_endpoint: Option<String>,
    resume_session_id: Option<String>,
    client: Option<RelayWebSocketClient>,
}

impl fmt::Debug for RelayRuntimePump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayRuntimePump")
            .field("endpoint", &self.endpoint)
            .field(
                "session_id",
                &self.session_id.as_ref().map(|_| "<redacted>"),
            )
            .field("resume_endpoint", &self.resume_endpoint)
            .field(
                "resume_session_id",
                &self.resume_session_id.as_ref().map(|_| "<redacted>"),
            )
            .field("client", &self.client.as_ref().map(|_| "<connected>"))
            .finish()
    }
}

impl RelayRuntimePump {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn connected_endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn disconnect(&mut self) {
        self.endpoint = None;
        self.session_id = None;
        self.client = None;
    }

    /// Reuse a relay WebSocket session across daemon ticks when the endpoint is
    /// stable, reconnecting only after failures or endpoint changes.
    pub fn tick_from_paths(
        &mut self,
        paths: &StatePaths,
        node_id: &str,
        wait: Duration,
    ) -> Result<RelaySyncReport, RelayDeliveryError> {
        ensure_relay_dirs(paths)?;

        let queued_paths = pending_relay_requests(paths)?;
        let endpoint = relay_endpoint_for_sync(paths, &queued_paths)?;
        let mut report = RelaySyncReport {
            endpoint: endpoint.clone(),
            connected: false,
            queued: queued_paths.len(),
            sent: 0,
            received: 0,
            undelivered: 0,
            rejected: 0,
            inbox_entries: Vec::new(),
        };

        if self.endpoint.as_deref() != Some(endpoint.as_str()) || self.client.is_none() {
            self.disconnect();
            if self.resume_endpoint.as_deref() != Some(endpoint.as_str()) {
                self.resume_endpoint = None;
                self.resume_session_id = None;
            }
            let token = relay_token(paths)?;
            self.connect(&endpoint, node_id, &token)?;
        }
        report.connected = true;

        let client = self
            .client
            .as_mut()
            .ok_or_else(|| RelayDeliveryError::InvalidRequest {
                reason: "relay session is not connected".to_string(),
            })?;

        for request_path in queued_paths {
            let request = match read_relay_request(&request_path) {
                Ok(request) => request,
                Err(error) => {
                    report.rejected += 1;
                    move_relay_request(&paths.relay_rejected_dir, &request_path, "rejected")?;
                    append_relay_log(paths, "outbox_rejected", "", "", 0)?;
                    self.disconnect();
                    return Err(error);
                }
            };
            if let Err(error) = client.send(&RelayClientFrame::Forward(Box::new(
                request.to_forward_frame()?,
            ))) {
                self.disconnect();
                return Err(error.into());
            }
            if let Err(error) =
                drain_relay_frames(client, paths, &mut report, Duration::from_millis(600))
            {
                self.disconnect();
                return Err(error);
            }
        }

        if let Err(error) = drain_relay_frames(client, paths, &mut report, wait) {
            self.disconnect();
            return Err(error);
        }

        Ok(report)
    }

    fn connect(
        &mut self,
        endpoint: &str,
        node_id: &str,
        token: &str,
    ) -> Result<(), RelayDeliveryError> {
        let timeout = Duration::from_millis(500);
        let mut client = RelayWebSocketClient::connect(endpoint, timeout)?;
        let mut hello = RelayHello::new(node_id.to_string(), token.to_string())?;
        if self.resume_endpoint.as_deref() == Some(endpoint) {
            if let Some(resume_session_id) = &self.resume_session_id {
                hello = hello.with_resume_session_id(resume_session_id.clone())?;
            }
        }
        client.send(&RelayClientFrame::Hello(hello))?;

        match client.read()? {
            Some(RelayServerFrame::Welcome { session_id, .. }) => {
                self.endpoint = Some(endpoint.to_string());
                self.session_id = Some(session_id.clone());
                self.resume_endpoint = Some(endpoint.to_string());
                self.resume_session_id = Some(session_id);
                self.client = Some(client);
                Ok(())
            }
            Some(RelayServerFrame::Error { reason }) => {
                Err(RelayDeliveryError::InvalidRequest { reason })
            }
            _ => Err(RelayDeliveryError::InvalidRequest {
                reason: "relay did not welcome the runtime session".to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub enum RelayDeliveryError {
    State(StateError),
    Agent(AgentError),
    Message(MessageError),
    Security(SecurityError),
    Session(SessionError),
    Policy(PolicyError),
    Trust(trust::TrustError),
    Relay(RelayFrameError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRequest {
        reason: String,
    },
}

impl RelayDeliveryError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for RelayDeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Security(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Policy(error) => write!(formatter, "{error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Relay(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRequest { reason } => write!(formatter, "invalid relay request: {reason}"),
        }
    }
}

impl std::error::Error for RelayDeliveryError {}

impl From<StateError> for RelayDeliveryError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<AgentError> for RelayDeliveryError {
    fn from(error: AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<MessageError> for RelayDeliveryError {
    fn from(error: MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<SecurityError> for RelayDeliveryError {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}

impl From<SessionError> for RelayDeliveryError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<PolicyError> for RelayDeliveryError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<trust::TrustError> for RelayDeliveryError {
    fn from(error: trust::TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<RelayFrameError> for RelayDeliveryError {
    fn from(error: RelayFrameError) -> Self {
        Self::Relay(error)
    }
}

/// Queue a peer-encrypted remote message into the relay outbox.
pub fn submit_remote_message(
    home_override: Option<PathBuf>,
    message: RemoteMessage,
) -> Result<RemoteMessageSubmission, RelayDeliveryError> {
    let init = state::init_state(home_override)?;
    ensure_relay_dirs(&init.paths)?;
    validate_local_sender_can_message(&init.paths, &message.from_agent_id)?;
    let peer = trusted_peer_with_key(&init.paths, &message.peer_node_id)?;
    policy::ensure_peer_allowed_from_paths(
        &init.paths,
        &peer.peer_node_id,
        PeerPermission::Messages,
    )?;

    let relay_request_id = request_id("relayreq");
    let envelope_id = request_id("env");
    let aad = relay_aad(
        &envelope_id,
        &init.node.node_id,
        &peer.peer_node_id,
        &message.from_agent_id,
        &message.to_agent_id,
    );
    let encrypted = security::encrypt_for_peer_from_paths(
        &init.paths,
        peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
            RelayDeliveryError::InvalidRequest {
                reason: "trusted peer does not have an exchange public key".to_string(),
            }
        })?,
        message.payload.as_bytes(),
        &aad,
    )?;
    let request_path = init
        .paths
        .relay_outbox_dir
        .join(format!("{relay_request_id}.relay"));
    let contents = render_relay_request(RelayRequestRender {
        request_id: &relay_request_id,
        envelope_id: &envelope_id,
        kind: RelayEnvelopeKind::Message,
        stream_id: None,
        from_node_id: &init.node.node_id,
        to_node_id: &peer.peer_node_id,
        from_agent_id: &message.from_agent_id,
        to_agent_id: &message.to_agent_id,
        encrypted: &encrypted,
    });
    write_new_file(&request_path, &contents)?;

    Ok(RemoteMessageSubmission {
        request_id: relay_request_id,
        envelope_id,
        request_path,
        peer_node_id: peer.peer_node_id,
        payload_bytes: message.payload.len(),
    })
}

/// Queue a peer-encrypted stream chunk into the relay outbox.
pub fn submit_remote_stream_chunk(
    home_override: Option<PathBuf>,
    chunk: RemoteStreamChunk,
) -> Result<RemoteStreamChunkSubmission, RelayDeliveryError> {
    let init = state::init_state(home_override)?;
    submit_remote_stream_chunk_from_paths(&init.paths, &init.node.node_id, chunk)
}

/// Queue a peer-encrypted stream chunk from already resolved runtime state.
pub fn submit_remote_stream_chunk_from_paths(
    paths: &StatePaths,
    local_node_id: &str,
    chunk: RemoteStreamChunk,
) -> Result<RemoteStreamChunkSubmission, RelayDeliveryError> {
    ensure_relay_dirs(paths)?;
    validate_local_sender_can_stream(paths, &chunk.from_agent_id)?;
    let peer = trusted_peer_with_key(paths, &chunk.peer_node_id)?;
    policy::ensure_peer_allowed_from_paths(paths, &peer.peer_node_id, PeerPermission::Streams)?;

    let relay_request_id = request_id("streamreq");
    let envelope_id = request_id("streamenv");
    let aad = relay_stream_aad(
        &envelope_id,
        local_node_id,
        &peer.peer_node_id,
        &chunk.from_agent_id,
        &chunk.to_agent_id,
        &chunk.stream_id,
    );
    let encrypted = security::encrypt_for_peer_from_paths(
        paths,
        peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
            RelayDeliveryError::InvalidRequest {
                reason: "trusted peer does not have an exchange public key".to_string(),
            }
        })?,
        chunk.payload.as_bytes(),
        &aad,
    )?;
    let request_path = paths
        .relay_outbox_dir
        .join(format!("{relay_request_id}.relay"));
    let contents = render_relay_request(RelayRequestRender {
        request_id: &relay_request_id,
        envelope_id: &envelope_id,
        kind: RelayEnvelopeKind::StreamChunk,
        stream_id: Some(&chunk.stream_id),
        from_node_id: local_node_id,
        to_node_id: &peer.peer_node_id,
        from_agent_id: &chunk.from_agent_id,
        to_agent_id: &chunk.to_agent_id,
        encrypted: &encrypted,
    });
    write_new_file(&request_path, &contents)?;

    Ok(RemoteStreamChunkSubmission {
        request_id: relay_request_id,
        envelope_id,
        request_path,
        peer_node_id: peer.peer_node_id,
        stream_id: chunk.stream_id,
        payload_bytes: chunk.payload.len(),
    })
}

/// Queue a peer-encrypted room event from already resolved runtime state.
pub fn submit_remote_room_event_from_paths(
    paths: &StatePaths,
    local_node_id: &str,
    event: RemoteRoomEvent,
) -> Result<RemoteRoomEventSubmission, RelayDeliveryError> {
    ensure_relay_dirs(paths)?;
    validate_local_sender_can_room(paths, &event.from_agent_id)?;
    let peer = trusted_peer_with_key(paths, &event.peer_node_id)?;
    policy::ensure_peer_allowed_from_paths(paths, &peer.peer_node_id, PeerPermission::Rooms)?;

    let packet = render_room_event_packet(&event);
    validate_payload_size(packet.len()).map_err(|_| RelayDeliveryError::InvalidRequest {
        reason: "room event metadata plus payload is too large for relay delivery".to_string(),
    })?;
    let relay_request_id = request_id("roomreq");
    let envelope_id = request_id("roomenv");
    let aad = relay_room_event_aad(
        &envelope_id,
        local_node_id,
        &peer.peer_node_id,
        &event.from_agent_id,
        &event.to_agent_id,
    );
    let encrypted = security::encrypt_for_peer_from_paths(
        paths,
        peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
            RelayDeliveryError::InvalidRequest {
                reason: "trusted peer does not have an exchange public key".to_string(),
            }
        })?,
        &packet,
        &aad,
    )?;
    let request_path = paths
        .relay_outbox_dir
        .join(format!("{relay_request_id}.relay"));
    let contents = render_relay_request(RelayRequestRender {
        request_id: &relay_request_id,
        envelope_id: &envelope_id,
        kind: RelayEnvelopeKind::RoomEvent,
        stream_id: None,
        from_node_id: local_node_id,
        to_node_id: &peer.peer_node_id,
        from_agent_id: &event.from_agent_id,
        to_agent_id: &event.to_agent_id,
        encrypted: &encrypted,
    });
    write_new_file(&request_path, &contents)?;

    Ok(RemoteRoomEventSubmission {
        request_id: relay_request_id,
        envelope_id,
        event_id: event.event_id,
        request_path,
        peer_node_id: peer.peer_node_id,
        payload_bytes: event.payload.len(),
    })
}

fn queue_signed_agent_card_for_peer(
    paths: &StatePaths,
    local_node_id: &str,
    peer: &TrustedPeer,
    card: &agents::SignedAgentCard,
) -> Result<(), RelayDeliveryError> {
    let Some(peer_exchange_key) = peer.exchange_public_key_hex.as_deref() else {
        return Ok(());
    };
    let plaintext = agents::render_signed_agent_card_metadata(card);
    validate_payload_size(plaintext.len())?;
    let request_id = agent_card_exchange_id(&peer.peer_node_id, card);
    let envelope_id = format!("env_{request_id}");
    let aad = relay_agent_card_aad(
        &envelope_id,
        local_node_id,
        &peer.peer_node_id,
        &card.agent_id,
    );
    let encrypted = security::encrypt_for_peer_from_paths(
        paths,
        peer_exchange_key,
        plaintext.as_bytes(),
        &aad,
    )?;
    let request_path = paths.relay_outbox_dir.join(format!("{request_id}.relay"));
    let contents = render_relay_request(RelayRequestRender {
        request_id: &request_id,
        envelope_id: &envelope_id,
        kind: RelayEnvelopeKind::AgentCard,
        stream_id: None,
        from_node_id: local_node_id,
        to_node_id: &peer.peer_node_id,
        from_agent_id: &card.agent_id,
        to_agent_id: AGENT_CARD_TARGET_AGENT_ID,
        encrypted: &encrypted,
    });
    write_new_file(&request_path, &contents)
}

/// Connect to the configured relay, send pending remote messages, and receive
/// inbound encrypted envelopes for a bounded wait.
pub fn sync_relay_once(
    home_override: Option<PathBuf>,
    wait: Duration,
) -> Result<RelaySyncReport, RelayDeliveryError> {
    let init = state::init_state(home_override)?;
    sync_relay_once_from_paths(&init.paths, &init.node.node_id, wait)
}

/// Connect to the configured relay from already resolved runtime state.
pub fn sync_relay_once_from_paths(
    paths: &StatePaths,
    node_id: &str,
    wait: Duration,
) -> Result<RelaySyncReport, RelayDeliveryError> {
    ensure_relay_dirs(paths)?;

    let queued_paths = pending_relay_requests(paths)?;
    let endpoint = relay_endpoint_for_sync(paths, &queued_paths)?;
    let token = relay_token(paths)?;
    let timeout = Duration::from_millis(500);
    let mut client = RelayWebSocketClient::connect(&endpoint, timeout)?;
    client.send(&RelayClientFrame::Hello(RelayHello::new(
        node_id.to_string(),
        token,
    )?))?;

    let mut report = RelaySyncReport {
        endpoint,
        connected: false,
        queued: queued_paths.len(),
        sent: 0,
        received: 0,
        undelivered: 0,
        rejected: 0,
        inbox_entries: Vec::new(),
    };

    match client.read()? {
        Some(RelayServerFrame::Welcome { .. }) => report.connected = true,
        Some(RelayServerFrame::Error { reason }) => {
            return Err(RelayDeliveryError::InvalidRequest { reason });
        }
        _ => {
            return Err(RelayDeliveryError::InvalidRequest {
                reason: "relay did not welcome the runtime session".to_string(),
            });
        }
    }

    for request_path in queued_paths {
        let request = match read_relay_request(&request_path) {
            Ok(request) => request,
            Err(error) => {
                report.rejected += 1;
                move_relay_request(&paths.relay_rejected_dir, &request_path, "rejected")?;
                append_relay_log(paths, "outbox_rejected", "", "", 0)?;
                return Err(error);
            }
        };
        client.send(&RelayClientFrame::Forward(Box::new(
            request.to_forward_frame()?,
        )))?;
        drain_relay_frames(&mut client, paths, &mut report, Duration::from_millis(600))?;
    }

    drain_relay_frames(&mut client, paths, &mut report, wait)?;
    Ok(report)
}

/// Return relay queue counts without connecting to the network.
pub fn relay_queue_summary(
    home_override: Option<PathBuf>,
) -> Result<RelayQueueSummary, RelayDeliveryError> {
    let paths = StatePaths::resolve(home_override)?;
    Ok(RelayQueueSummary {
        queued: count_files_with_extension(&paths.relay_outbox_dir, "relay")?,
        sent: count_files_with_extension(&paths.relay_sent_dir, "sent")?,
        rejected: count_files_with_extension(&paths.relay_rejected_dir, "rejected")?,
    })
}

/// Queue public signed local agent cards for trusted peers over the encrypted
/// relay control plane. The relay sees ciphertext and routing metadata only.
pub fn queue_signed_agent_card_exchange_from_paths(
    paths: &StatePaths,
    local_node_id: &str,
) -> Result<usize, RelayDeliveryError> {
    ensure_relay_dirs(paths)?;
    let cards = agents::export_agent_cards(Some(paths.home.clone()))?;
    if cards.is_empty() {
        return Ok(0);
    }

    let peers = trust::list_peers(Some(paths.home.clone()))?;
    let mut queued = 0;
    for peer in peers {
        if peer.status != TrustStatus::Trusted
            || peer.exchange_public_key_hex.is_none()
            || peer.signing_public_key_hex.is_none()
            || !peer_policy_allows_agent_card_exchange(paths, &peer.peer_node_id)?
        {
            continue;
        }

        for card in &cards {
            if agent_card_exchange_exists(paths, &peer.peer_node_id, card) {
                continue;
            }
            queue_signed_agent_card_for_peer(paths, local_node_id, &peer, card)?;
            queued += 1;
        }
    }

    Ok(queued)
}

/// True when conUD should run the background relay pump.
pub fn relay_runtime_should_sync_from_paths(
    paths: &StatePaths,
) -> Result<bool, RelayDeliveryError> {
    if !relay_auto_sync_enabled(paths)? {
        return Ok(false);
    }
    if !pending_relay_requests(paths)?.is_empty() {
        return Ok(true);
    }
    if configured_default_relay(paths)?.is_some() {
        return Ok(true);
    }

    Ok(trust::list_peers(Some(paths.home.clone()))?
        .into_iter()
        .any(|peer| {
            peer.status == TrustStatus::Trusted
                && peer.exchange_public_key_hex.is_some()
                && peer.relay_endpoint.is_some()
        }))
}

fn drain_relay_frames(
    client: &mut RelayWebSocketClient,
    paths: &StatePaths,
    report: &mut RelaySyncReport,
    wait: Duration,
) -> Result<(), RelayDeliveryError> {
    let start = Instant::now();

    while start.elapsed() < wait {
        match client.read()? {
            Some(frame) => handle_relay_frame(paths, report, frame)?,
            None => {
                let remaining = wait.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    break;
                }
                thread::sleep(remaining.min(Duration::from_millis(25)));
            }
        }
    }

    Ok(())
}

fn handle_relay_frame(
    paths: &StatePaths,
    report: &mut RelaySyncReport,
    frame: RelayServerFrame,
) -> Result<(), RelayDeliveryError> {
    match frame {
        RelayServerFrame::Forwarded(forwarded) => {
            let forwarded = *forwarded;
            let incoming = IncomingRelayEnvelope {
                from_node_id: forwarded.from_node_id,
                to_node_id: forwarded.to_node_id,
                envelope_id: forwarded.envelope_id,
                kind: forwarded.kind,
                stream_id: forwarded.stream_id,
                payload_bytes: forwarded.payload_bytes,
                from_agent_id: forwarded.from_agent_id,
                to_agent_id: forwarded.to_agent_id,
                body: forwarded.body,
            };
            let entry = match receive_forwarded_envelope(paths, &incoming) {
                Ok(entry) => entry,
                Err(_) if incoming.kind == RelayEnvelopeKind::AgentCard => {
                    report.rejected += 1;
                    append_relay_log(
                        paths,
                        "agent_card_rejected",
                        &incoming.envelope_id,
                        &incoming.from_node_id,
                        incoming.payload_bytes,
                    )?;
                    None
                }
                Err(error) => return Err(error),
            };
            report.received += 1;
            if let Some(entry) = entry {
                report.inbox_entries.push(entry);
            }
        }
        RelayServerFrame::Sent {
            envelope_id,
            to_node_id,
            payload_bytes,
        } => {
            report.sent += 1;
            mark_sent_by_envelope(paths, &envelope_id)?;
            append_relay_log(
                paths,
                "outbox_sent",
                &envelope_id,
                &to_node_id,
                payload_bytes,
            )?;
        }
        RelayServerFrame::Undelivered {
            to_node_id,
            envelope_id,
            reason: _,
        } => {
            report.undelivered += 1;
            append_relay_log(paths, "outbox_undelivered", &envelope_id, &to_node_id, 0)?;
        }
        RelayServerFrame::Error { reason: _ } => {
            report.rejected += 1;
            append_relay_log(paths, "relay_error", "", "", 0)?;
        }
        RelayServerFrame::Welcome { .. } | RelayServerFrame::Pong => {}
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct IncomingRelayEnvelope {
    from_node_id: String,
    to_node_id: String,
    envelope_id: String,
    kind: RelayEnvelopeKind,
    stream_id: Option<String>,
    payload_bytes: usize,
    from_agent_id: Option<String>,
    to_agent_id: Option<String>,
    body: Option<RelayOpaqueBody>,
}

fn receive_forwarded_envelope(
    paths: &StatePaths,
    incoming: &IncomingRelayEnvelope,
) -> Result<Option<InboxEntry>, RelayDeliveryError> {
    let local = state::read_state(Some(paths.home.clone()))?
        .node
        .ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: "local node identity is missing".to_string(),
        })?;
    if incoming.to_node_id != local.node_id {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay envelope was not addressed to this node".to_string(),
        });
    }
    let peer = trusted_peer_with_key(paths, &incoming.from_node_id)?;
    let expected_sender_key = peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
        RelayDeliveryError::InvalidRequest {
            reason: "trusted peer does not have an exchange public key".to_string(),
        }
    })?;
    let from_agent_id =
        incoming
            .from_agent_id
            .as_deref()
            .ok_or_else(|| RelayDeliveryError::InvalidRequest {
                reason: "relay envelope is missing from_agent metadata".to_string(),
            })?;
    let to_agent_id =
        incoming
            .to_agent_id
            .as_deref()
            .ok_or_else(|| RelayDeliveryError::InvalidRequest {
                reason: "relay envelope is missing to_agent metadata".to_string(),
            })?;
    let body = incoming
        .body
        .as_ref()
        .ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: "relay envelope is missing encrypted body".to_string(),
        })?;
    if body.sender_exchange_public_key_hex != expected_sender_key {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay sender key does not match trusted peer card".to_string(),
        });
    }
    match incoming.kind {
        RelayEnvelopeKind::Message => policy::ensure_peer_allowed_from_paths(
            paths,
            &peer.peer_node_id,
            PeerPermission::Messages,
        )?,
        RelayEnvelopeKind::StreamChunk => policy::ensure_peer_allowed_from_paths(
            paths,
            &peer.peer_node_id,
            PeerPermission::Streams,
        )?,
        RelayEnvelopeKind::RoomEvent => policy::ensure_peer_allowed_from_paths(
            paths,
            &peer.peer_node_id,
            PeerPermission::Rooms,
        )?,
        RelayEnvelopeKind::AgentCard => {
            if !peer_policy_allows_agent_card_exchange(paths, &peer.peer_node_id)? {
                return Err(RelayDeliveryError::InvalidRequest {
                    reason: "peer is not allowed to exchange agent cards".to_string(),
                });
            }
        }
    }

    let encrypted = PeerEncryptedPayload {
        algorithm: body.algorithm.clone(),
        key_id: body.key_id.clone(),
        sender_exchange_public_key_hex: body.sender_exchange_public_key_hex.clone(),
        nonce_hex: body.nonce_hex.clone(),
        ciphertext_hex: body.ciphertext_hex.clone(),
        plaintext_len: incoming.payload_bytes,
    };
    let aad = match incoming.kind {
        RelayEnvelopeKind::Message => relay_aad(
            &incoming.envelope_id,
            &incoming.from_node_id,
            &incoming.to_node_id,
            from_agent_id,
            to_agent_id,
        ),
        RelayEnvelopeKind::StreamChunk => {
            let stream_id = incoming.stream_id.as_deref().ok_or_else(|| {
                RelayDeliveryError::InvalidRequest {
                    reason: "relay stream chunk is missing stream id".to_string(),
                }
            })?;
            relay_stream_aad(
                &incoming.envelope_id,
                &incoming.from_node_id,
                &incoming.to_node_id,
                from_agent_id,
                to_agent_id,
                stream_id,
            )
        }
        RelayEnvelopeKind::AgentCard => relay_agent_card_aad(
            &incoming.envelope_id,
            &incoming.from_node_id,
            &incoming.to_node_id,
            from_agent_id,
        ),
        RelayEnvelopeKind::RoomEvent => relay_room_event_aad(
            &incoming.envelope_id,
            &incoming.from_node_id,
            &incoming.to_node_id,
            from_agent_id,
            to_agent_id,
        ),
    };
    let plaintext =
        security::decrypt_from_peer_from_paths(paths, expected_sender_key, &encrypted, &aad)?;
    validate_payload_size(plaintext.len())?;
    let entry = match incoming.kind {
        RelayEnvelopeKind::Message => Some(messages::deliver_remote_envelope_from_paths(
            paths,
            &incoming.envelope_id,
            from_agent_id,
            to_agent_id,
            OpaquePayload::from_bytes(plaintext),
        )?),
        RelayEnvelopeKind::StreamChunk => {
            let stream_id = incoming.stream_id.as_deref().ok_or_else(|| {
                RelayDeliveryError::InvalidRequest {
                    reason: "relay stream chunk is missing stream id".to_string(),
                }
            })?;
            Some(messages::deliver_remote_stream_chunk_from_paths(
                paths,
                &incoming.envelope_id,
                stream_id,
                from_agent_id,
                to_agent_id,
                OpaquePayload::from_bytes(plaintext),
            )?)
        }
        RelayEnvelopeKind::AgentCard => {
            if to_agent_id != AGENT_CARD_TARGET_AGENT_ID {
                return Err(RelayDeliveryError::InvalidRequest {
                    reason: "relay agent card target is invalid".to_string(),
                });
            }
            let contents =
                String::from_utf8(plaintext).map_err(|_| RelayDeliveryError::InvalidRequest {
                    reason: "relay agent card metadata is not UTF-8".to_string(),
                })?;
            let card = agents::parse_signed_agent_card_metadata(&contents)?;
            if card.node_id != incoming.from_node_id || card.agent_id != from_agent_id {
                return Err(RelayDeliveryError::InvalidRequest {
                    reason: "relay agent card metadata does not match envelope metadata"
                        .to_string(),
                });
            }
            sessions::trust_remote_agent_card(Some(paths.home.clone()), card)?;
            None
        }
        RelayEnvelopeKind::RoomEvent => {
            let packet = parse_room_event_packet(&plaintext)?;
            Some(
                rooms::deliver_remote_room_event_from_paths(
                    paths,
                    rooms::RemoteRoomEventDelivery {
                        envelope_id: incoming.envelope_id.clone(),
                        event_id: packet.event_id,
                        room_id: packet.room_id,
                        topic: packet.topic,
                        peer_node_id: peer.peer_node_id.clone(),
                        from_agent_id: from_agent_id.to_string(),
                        to_agent_id: to_agent_id.to_string(),
                        payload: OpaquePayload::from_bytes(packet.payload),
                    },
                )
                .map_err(|error| RelayDeliveryError::InvalidRequest {
                    reason: error.to_string(),
                })?,
            )
        }
    };
    let log_event = match incoming.kind {
        RelayEnvelopeKind::AgentCard => "agent_card_imported",
        RelayEnvelopeKind::RoomEvent => "room_event_delivered",
        RelayEnvelopeKind::Message | RelayEnvelopeKind::StreamChunk => "inbox_delivered",
    };
    append_relay_log(
        paths,
        log_event,
        &incoming.envelope_id,
        &incoming.from_node_id,
        incoming.payload_bytes,
    )?;

    Ok(entry)
}

#[derive(Debug, Clone)]
struct RelayRequest {
    envelope_id: String,
    kind: RelayEnvelopeKind,
    stream_id: Option<String>,
    to_node_id: String,
    from_agent_id: String,
    to_agent_id: String,
    encrypted: PeerEncryptedPayload,
}

impl RelayRequest {
    fn to_forward_frame(&self) -> Result<RelayForward, RelayDeliveryError> {
        let body = RelayOpaqueBody::new(
            &self.encrypted.algorithm,
            &self.encrypted.key_id,
            &self.encrypted.sender_exchange_public_key_hex,
            &self.encrypted.nonce_hex,
            &self.encrypted.ciphertext_hex,
        )?;
        let forward = match self.kind {
            RelayEnvelopeKind::Message => RelayForward::with_body(
                &self.to_node_id,
                &self.envelope_id,
                &self.from_agent_id,
                &self.to_agent_id,
                self.encrypted.plaintext_len,
                body,
            )?,
            RelayEnvelopeKind::StreamChunk => RelayForward::with_stream_body(
                self.stream_id
                    .as_deref()
                    .ok_or_else(|| RelayDeliveryError::InvalidRequest {
                        reason: "relay stream chunk is missing stream id".to_string(),
                    })?,
                &self.to_node_id,
                &self.envelope_id,
                &self.from_agent_id,
                &self.to_agent_id,
                self.encrypted.plaintext_len,
                body,
            )?,
            RelayEnvelopeKind::AgentCard => RelayForward::with_agent_card_body(
                &self.to_node_id,
                &self.envelope_id,
                &self.from_agent_id,
                self.encrypted.plaintext_len,
                body,
            )?,
            RelayEnvelopeKind::RoomEvent => RelayForward::with_room_event_body(
                &self.to_node_id,
                &self.envelope_id,
                &self.from_agent_id,
                &self.to_agent_id,
                self.encrypted.plaintext_len,
                body,
            )?,
        };
        Ok(forward)
    }
}

fn read_relay_request(path: &Path) -> Result<RelayRequest, RelayDeliveryError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| RelayDeliveryError::io("read relay outbox request", path, error))?;
    let values = parse_key_values(&contents);

    if value_or_empty(&values, "version") != RELAY_REQUEST_VERSION {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "unsupported relay request version".to_string(),
        });
    }
    let request_type = value_or_empty(&values, "type");
    if !matches!(
        request_type,
        "relay_message" | "relay_stream_chunk" | "relay_agent_card" | "relay_room_event"
    ) {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "unsupported relay request type".to_string(),
        });
    }

    let _request_id = validate_identifier(required(&values, "request_id")?, "request id")?;
    let _from_node_id = validate_identifier(required(&values, "from_node_id")?, "from node id")?;
    let kind = relay_kind_from_values(&values)?;
    if !matches!(
        (request_type, kind),
        ("relay_message", RelayEnvelopeKind::Message)
            | ("relay_stream_chunk", RelayEnvelopeKind::StreamChunk)
            | ("relay_agent_card", RelayEnvelopeKind::AgentCard)
            | ("relay_room_event", RelayEnvelopeKind::RoomEvent)
    ) {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay request type does not match envelope kind".to_string(),
        });
    }
    let stream_id = values
        .get("stream_id")
        .map(|value| validate_identifier(value.clone(), "stream id"))
        .transpose()?;
    validate_relay_kind_stream(kind, stream_id.as_deref())?;
    let request = RelayRequest {
        envelope_id: validate_identifier(required(&values, "envelope_id")?, "envelope id")?,
        kind,
        stream_id,
        to_node_id: validate_identifier(required(&values, "to_node_id")?, "to node id")?,
        from_agent_id: validate_identifier(required(&values, "from_agent_id")?, "from agent id")?,
        to_agent_id: validate_identifier(required(&values, "to_agent_id")?, "to agent id")?,
        encrypted: PeerEncryptedPayload {
            algorithm: required(&values, "payload_cipher")?,
            key_id: required(&values, "payload_key_id")?,
            sender_exchange_public_key_hex: required(&values, "sender_exchange_public_key_hex")?,
            nonce_hex: required(&values, "payload_nonce_hex")?,
            ciphertext_hex: required(&values, "payload_ciphertext_hex")?,
            plaintext_len: parse_usize(&required(&values, "payload_len")?)?,
        },
    };
    validate_payload_size(request.encrypted.plaintext_len)?;
    Ok(request)
}

struct RelayRequestRender<'a> {
    request_id: &'a str,
    envelope_id: &'a str,
    kind: RelayEnvelopeKind,
    stream_id: Option<&'a str>,
    from_node_id: &'a str,
    to_node_id: &'a str,
    from_agent_id: &'a str,
    to_agent_id: &'a str,
    encrypted: &'a PeerEncryptedPayload,
}

fn render_relay_request(request: RelayRequestRender<'_>) -> String {
    let request_type = match request.kind {
        RelayEnvelopeKind::Message => "relay_message",
        RelayEnvelopeKind::StreamChunk => "relay_stream_chunk",
        RelayEnvelopeKind::AgentCard => "relay_agent_card",
        RelayEnvelopeKind::RoomEvent => "relay_room_event",
    };
    let stream_line = request
        .stream_id
        .map(|stream_id| format!("stream_id = \"{}\"\n", escape_file_value(stream_id)))
        .unwrap_or_default();

    format!(
        "version = \"{}\"\ntype = \"{}\"\nkind = \"{}\"\n{}request_id = \"{}\"\nenvelope_id = \"{}\"\nfrom_node_id = \"{}\"\nto_node_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\npayload_len = {}\npayload_privacy = \"peer_encrypted\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\nsender_exchange_public_key_hex = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\npayload_displayed = false\n",
        RELAY_REQUEST_VERSION,
        request_type,
        request.kind.as_str(),
        stream_line,
        escape_file_value(request.request_id),
        escape_file_value(request.envelope_id),
        escape_file_value(request.from_node_id),
        escape_file_value(request.to_node_id),
        escape_file_value(request.from_agent_id),
        escape_file_value(request.to_agent_id),
        request.encrypted.plaintext_len,
        escape_file_value(&request.encrypted.algorithm),
        escape_file_value(&request.encrypted.key_id),
        escape_file_value(&request.encrypted.sender_exchange_public_key_hex),
        escape_file_value(&request.encrypted.nonce_hex),
        escape_file_value(&request.encrypted.ciphertext_hex)
    )
}

fn peer_policy_allows_agent_card_exchange(
    paths: &StatePaths,
    peer_node_id: &str,
) -> Result<bool, RelayDeliveryError> {
    Ok(policy::peer_policy(Some(paths.home.clone()), peer_node_id)?.has_any_grant())
}

fn agent_card_exchange_exists(
    paths: &StatePaths,
    peer_node_id: &str,
    card: &agents::SignedAgentCard,
) -> bool {
    let request_id = agent_card_exchange_id(peer_node_id, card);
    paths
        .relay_outbox_dir
        .join(format!("{request_id}.relay"))
        .exists()
        || paths
            .relay_sent_dir
            .join(format!("{request_id}.sent"))
            .exists()
}

fn agent_card_exchange_id(peer_node_id: &str, card: &agents::SignedAgentCard) -> String {
    let mut hasher = DefaultHasher::new();
    peer_node_id.hash(&mut hasher);
    card.agent_id.hash(&mut hasher);
    card.signature_hex.hash(&mut hasher);
    format!("agentcard_{:016x}", hasher.finish())
}

fn ensure_relay_dirs(paths: &StatePaths) -> Result<(), RelayDeliveryError> {
    for directory in [
        &paths.mailbox_dir,
        &paths.relay_dir,
        &paths.relay_outbox_dir,
        &paths.relay_sent_dir,
        &paths.relay_rejected_dir,
        &paths.logs_dir,
    ] {
        fs::create_dir_all(directory)
            .map_err(|error| RelayDeliveryError::io("create relay directory", directory, error))?;
    }
    Ok(())
}

fn pending_relay_requests(paths: &StatePaths) -> Result<Vec<PathBuf>, RelayDeliveryError> {
    let mut requests = Vec::new();
    if !paths.relay_outbox_dir.exists() {
        return Ok(requests);
    }

    for entry in fs::read_dir(&paths.relay_outbox_dir).map_err(|error| {
        RelayDeliveryError::io("read relay outbox", &paths.relay_outbox_dir, error)
    })? {
        let entry = entry.map_err(|error| {
            RelayDeliveryError::io("read relay outbox entry", &paths.relay_outbox_dir, error)
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("relay") {
            requests.push(path);
        }
    }

    requests.sort();
    Ok(requests)
}

fn mark_sent_by_envelope(paths: &StatePaths, envelope_id: &str) -> Result<(), RelayDeliveryError> {
    for request_path in pending_relay_requests(paths)? {
        let request = read_relay_request(&request_path)?;
        if request.envelope_id == envelope_id {
            move_relay_request(&paths.relay_sent_dir, &request_path, "sent")?;
            return Ok(());
        }
    }
    Ok(())
}

fn move_relay_request(
    target_dir: &Path,
    request_path: &Path,
    extension: &str,
) -> Result<(), RelayDeliveryError> {
    fs::create_dir_all(target_dir).map_err(|error| {
        RelayDeliveryError::io("create relay marker directory", target_dir, error)
    })?;
    let stem = request_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("relay-request");
    let target = target_dir.join(format!("{stem}.{extension}"));
    fs::rename(request_path, &target)
        .map_err(|error| RelayDeliveryError::io("move relay request marker", request_path, error))
}

fn relay_endpoint_for_sync(
    paths: &StatePaths,
    queued_paths: &[PathBuf],
) -> Result<String, RelayDeliveryError> {
    if let Some(first) = queued_paths.first() {
        let request = read_relay_request(first)?;
        if let Some(peer) = trusted_peer(paths, &request.to_node_id)? {
            if let Some(endpoint) = peer.relay_endpoint {
                return validate_endpoint(endpoint);
            }
        }
    }

    for peer in trust::list_peers(Some(paths.home.clone()))? {
        if peer.status == TrustStatus::Trusted {
            if let Some(endpoint) = peer.relay_endpoint {
                return validate_endpoint(endpoint);
            }
        }
    }

    configured_relay_endpoint(paths)
}

fn configured_relay_endpoint(paths: &StatePaths) -> Result<String, RelayDeliveryError> {
    if let Some(endpoint) = configured_default_relay(paths)? {
        return validate_endpoint(endpoint);
    }

    Ok(DEFAULT_RELAY_ENDPOINT.to_string())
}

fn configured_default_relay(paths: &StatePaths) -> Result<Option<String>, RelayDeliveryError> {
    let contents = match fs::read_to_string(&paths.config) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => {
            return Err(RelayDeliveryError::io(
                "read conU config",
                &paths.config,
                error,
            ));
        }
    };
    let values = parse_key_values(&contents);
    Ok(values
        .get("default_relay")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn relay_auto_sync_enabled(paths: &StatePaths) -> Result<bool, RelayDeliveryError> {
    let contents = match fs::read_to_string(&paths.config) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(RelayDeliveryError::io(
                "read conU config",
                &paths.config,
                error,
            ));
        }
    };
    let values = parse_key_values(&contents);
    let value = values
        .get("relay_auto_sync")
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "true".to_string());

    Ok(!matches!(value.as_str(), "false" | "0" | "no" | "off"))
}

fn relay_token(paths: &StatePaths) -> Result<String, RelayDeliveryError> {
    relay_token_with_env(
        paths,
        env::var("CONU_RELAY_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty()),
    )
}

fn relay_token_with_env(
    paths: &StatePaths,
    env_token: Option<String>,
) -> Result<String, RelayDeliveryError> {
    if let Some(token) = env_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(token);
    }
    if let Some(token) = security::read_relay_credential_from_paths(paths)? {
        return Ok(token);
    }
    Ok(DEFAULT_RELAY_TOKEN.to_string())
}

fn trusted_peer_with_key(
    paths: &StatePaths,
    peer_node_id: &str,
) -> Result<TrustedPeer, RelayDeliveryError> {
    let peer =
        trusted_peer(paths, peer_node_id)?.ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: "peer is not trusted locally".to_string(),
        })?;
    if peer.status != TrustStatus::Trusted {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "peer is revoked".to_string(),
        });
    }
    if peer.exchange_public_key_hex.is_none() {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "peer is missing exchange public key; import a peer card first".to_string(),
        });
    }
    Ok(peer)
}

fn trusted_peer(
    paths: &StatePaths,
    peer_node_id: &str,
) -> Result<Option<TrustedPeer>, RelayDeliveryError> {
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    Ok(trust::list_peers(Some(paths.home.clone()))?
        .into_iter()
        .find(|peer| peer.peer_node_id == peer_node_id))
}

fn validate_local_sender_can_message(
    paths: &StatePaths,
    from_agent_id: &str,
) -> Result<(), RelayDeliveryError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let sender = registered
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
        .ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: "sender is not a registered local agent".to_string(),
        })?;

    if !sender.capabilities.messages {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "sender is not allowed to send messages".to_string(),
        });
    }

    Ok(())
}

fn validate_local_sender_can_stream(
    paths: &StatePaths,
    from_agent_id: &str,
) -> Result<(), RelayDeliveryError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let sender = registered
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
        .ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: "sender is not a registered local agent".to_string(),
        })?;

    if !sender.capabilities.streams {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "sender is not allowed to send stream chunks".to_string(),
        });
    }

    Ok(())
}

fn validate_local_sender_can_room(
    paths: &StatePaths,
    from_agent_id: &str,
) -> Result<(), RelayDeliveryError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let sender = registered
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
        .ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: "sender is not a registered local agent".to_string(),
        })?;

    if !sender.capabilities.rooms {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "sender is not allowed to send room events".to_string(),
        });
    }

    Ok(())
}

fn append_relay_log(
    paths: &StatePaths,
    event: &str,
    envelope_id: &str,
    peer_node_id: &str,
    payload_bytes: usize,
) -> Result<(), RelayDeliveryError> {
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| RelayDeliveryError::io("create log directory", &paths.logs_dir, error))?;
    let path = paths.logs_dir.join("relay-delivery.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| RelayDeliveryError::io("open relay delivery log", &path, error))?;

    writeln!(
        file,
        "time={} event={} envelope={} peer={} bytes={} payload=not_observed",
        current_unix_seconds(),
        sanitize_log_value(event),
        sanitize_log_value(envelope_id),
        sanitize_log_value(peer_node_id),
        payload_bytes
    )
    .map_err(|error| RelayDeliveryError::io("write relay delivery log", &path, error))
}

fn count_files_with_extension(path: &Path, extension: &str) -> Result<usize, RelayDeliveryError> {
    if !path.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in fs::read_dir(path)
        .map_err(|error| RelayDeliveryError::io("read relay queue directory", path, error))?
    {
        let entry =
            entry.map_err(|error| RelayDeliveryError::io("read relay queue entry", path, error))?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some(extension) {
            count += 1;
        }
    }
    Ok(count)
}

fn write_new_file(path: &Path, contents: &str) -> Result<(), RelayDeliveryError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| RelayDeliveryError::io("create relay file", path, error))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| RelayDeliveryError::io("write relay file", path, error))
}

fn relay_aad(
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
) -> Vec<u8> {
    format!(
        "conu:relay-message:v1:{envelope_id}:{from_node_id}:{to_node_id}:{from_agent_id}:{to_agent_id}"
    )
    .into_bytes()
}

fn relay_stream_aad(
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    stream_id: &str,
) -> Vec<u8> {
    format!(
        "conu:relay-stream-chunk:v1:{envelope_id}:{from_node_id}:{to_node_id}:{from_agent_id}:{to_agent_id}:{stream_id}"
    )
    .into_bytes()
}

fn relay_agent_card_aad(
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    agent_id: &str,
) -> Vec<u8> {
    format!("conu:relay-agent-card:v1:{envelope_id}:{from_node_id}:{to_node_id}:{agent_id}")
        .into_bytes()
}

fn relay_room_event_aad(
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
) -> Vec<u8> {
    format!(
        "conu:relay-room-event:v1:{envelope_id}:{from_node_id}:{to_node_id}:{from_agent_id}:{to_agent_id}"
    )
    .into_bytes()
}

#[derive(Debug, Clone)]
struct RoomEventPacket {
    event_id: String,
    room_id: String,
    topic: String,
    payload: Vec<u8>,
}

fn render_room_event_packet(event: &RemoteRoomEvent) -> Vec<u8> {
    let payload = event.payload.as_bytes();
    let mut packet = Vec::with_capacity(
        ROOM_EVENT_PACKET_MAGIC.len()
            + 2
            + event.event_id.len()
            + 2
            + event.room_id.len()
            + 2
            + event.topic.len()
            + 4
            + payload.len(),
    );
    packet.extend_from_slice(ROOM_EVENT_PACKET_MAGIC);
    push_packet_string(&mut packet, &event.event_id);
    push_packet_string(&mut packet, &event.room_id);
    push_packet_string(&mut packet, &event.topic);
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn parse_room_event_packet(bytes: &[u8]) -> Result<RoomEventPacket, RelayDeliveryError> {
    if !bytes.starts_with(ROOM_EVENT_PACKET_MAGIC) {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event packet is invalid".to_string(),
        });
    }

    let mut cursor = ROOM_EVENT_PACKET_MAGIC.len();
    let event_id = read_packet_identifier(bytes, &mut cursor, "room event id")?;
    let room_id = read_packet_identifier(bytes, &mut cursor, "room id")?;
    let topic = read_packet_identifier(bytes, &mut cursor, "room topic")?;
    if bytes.len().saturating_sub(cursor) < 4 {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event packet is truncated".to_string(),
        });
    }
    let payload_len = u32::from_be_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;
    if payload_len == 0 {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event payload cannot be empty".to_string(),
        });
    }
    validate_payload_size(payload_len)?;
    if bytes.len().saturating_sub(cursor) != payload_len {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event packet payload length mismatch".to_string(),
        });
    }

    Ok(RoomEventPacket {
        event_id,
        room_id,
        topic,
        payload: bytes[cursor..].to_vec(),
    })
}

fn push_packet_string(packet: &mut Vec<u8>, value: &str) {
    packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
    packet.extend_from_slice(value.as_bytes());
}

fn read_packet_identifier(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<String, RelayDeliveryError> {
    if bytes.len().saturating_sub(*cursor) < 2 {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event packet is truncated".to_string(),
        });
    }
    let len = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
    *cursor += 2;
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event packet is truncated".to_string(),
        });
    }
    let value = String::from_utf8(bytes[*cursor..*cursor + len].to_vec()).map_err(|_| {
        RelayDeliveryError::InvalidRequest {
            reason: "relay room event packet metadata is not UTF-8".to_string(),
        }
    })?;
    *cursor += len;
    validate_identifier(value, field)
}

fn relay_kind_from_values(
    values: &HashMap<String, String>,
) -> Result<RelayEnvelopeKind, RelayDeliveryError> {
    match values.get("kind").map(String::as_str).unwrap_or("message") {
        "message" => Ok(RelayEnvelopeKind::Message),
        "stream_chunk" => Ok(RelayEnvelopeKind::StreamChunk),
        "agent_card" => Ok(RelayEnvelopeKind::AgentCard),
        "room_event" => Ok(RelayEnvelopeKind::RoomEvent),
        _ => Err(RelayDeliveryError::InvalidRequest {
            reason: "unsupported relay envelope kind".to_string(),
        }),
    }
}

fn validate_relay_kind_stream(
    kind: RelayEnvelopeKind,
    stream_id: Option<&str>,
) -> Result<(), RelayDeliveryError> {
    match (kind, stream_id) {
        (RelayEnvelopeKind::StreamChunk, None) => Err(RelayDeliveryError::InvalidRequest {
            reason: "relay stream chunk is missing stream id".to_string(),
        }),
        (RelayEnvelopeKind::Message, Some(_)) => Err(RelayDeliveryError::InvalidRequest {
            reason: "relay message must not include stream id".to_string(),
        }),
        (RelayEnvelopeKind::AgentCard, Some(_)) => Err(RelayDeliveryError::InvalidRequest {
            reason: "relay agent card must not include stream id".to_string(),
        }),
        (RelayEnvelopeKind::RoomEvent, Some(_)) => Err(RelayDeliveryError::InvalidRequest {
            reason: "relay room event must not include stream id".to_string(),
        }),
        _ => Ok(()),
    }
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

fn required(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<String, RelayDeliveryError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| RelayDeliveryError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn value_or_empty<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values.get(key).map(String::as_str).unwrap_or("")
}

fn validate_endpoint(value: String) -> Result<String, RelayDeliveryError> {
    let value = value.trim().to_string();
    if !value.starts_with("ws://") && !value.starts_with("wss://") {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay endpoint must start with ws:// or wss://".to_string(),
        });
    }
    if value.len() > 220 || value.chars().any(char::is_whitespace) {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay endpoint is invalid".to_string(),
        });
    }
    Ok(value)
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, RelayDeliveryError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 140 {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_payload_size(bytes: usize) -> Result<(), RelayDeliveryError> {
    if bytes > MAX_RELAY_PAYLOAD_BYTES {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "payload is too large for relay message delivery".to_string(),
        });
    }
    Ok(())
}

fn parse_usize(value: &str) -> Result<usize, RelayDeliveryError> {
    value
        .parse::<usize>()
        .map_err(|_| RelayDeliveryError::InvalidRequest {
            reason: "expected unsigned integer".to_string(),
        })
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
    use crate::agents::AgentRegistration;

    #[test]
    fn remote_message_request_hides_literal_payload() {
        let alice_home = test_home("hide-alice");
        let bob_home = test_home("hide-bob");
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");

        let message = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            node_id(&bob_home),
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        let submission =
            submit_remote_message(Some(alice_home), message).expect("remote message submits");
        let contents = fs::read_to_string(submission.request_path).expect("request reads");

        assert!(contents.contains("payload_privacy = \"peer_encrypted\""));
        assert!(contents.contains("payload_ciphertext_hex"));
        assert!(!contents.contains("private message contents"));
        assert!(!contents.contains("Review this code"));
    }

    #[test]
    fn remote_message_requires_peer_message_policy() {
        let alice_home = test_home("policy-deny-alice");
        let bob_home = test_home("policy-deny-bob");
        let bob = trust::export_peer_card(Some(bob_home.clone())).expect("bob card");
        trust::trust_peer_card(Some(alice_home.clone()), bob).expect("alice trusts bob");
        register_agent(&alice_home, "agent.alice");
        let message = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            node_id(&bob_home),
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");

        let error = submit_remote_message(Some(alice_home), message)
            .expect_err("peer message policy is required");

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn relay_request_rejects_type_kind_mismatch() {
        let home = test_home("type-kind-mismatch");
        let init = state::init_state(Some(home)).expect("state initializes");
        fs::create_dir_all(&init.paths.relay_outbox_dir).expect("relay outbox");
        let path = init.paths.relay_outbox_dir.join("bad.relay");
        fs::write(
            &path,
            "version = \"1\"\ntype = \"relay_stream_chunk\"\nkind = \"message\"\nrequest_id = \"relayreq.1\"\nfrom_node_id = \"node.a\"\n",
        )
        .expect("request writes");

        let error = read_relay_request(&path).expect_err("mismatched request fails");

        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn remote_stream_chunk_requires_sender_stream_capability() {
        let alice_home = test_home("stream-capability-alice");
        let bob_home = test_home("stream-capability-bob");
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        let chunk = RemoteStreamChunk::new(
            "stream.1",
            "agent.alice",
            "agent.bob",
            node_id(&bob_home),
            OpaquePayload::from_bytes(b"private stream chunk".to_vec()),
        )
        .expect("stream chunk valid");

        let error = submit_remote_stream_chunk(Some(alice_home), chunk)
            .expect_err("sender without stream capability fails");

        assert!(error.to_string().contains("send stream chunks"));
        assert!(!error.to_string().contains("private stream chunk"));
    }

    fn trust_each_other(alice_home: &Path, bob_home: &Path) {
        let alice = trust::export_peer_card(Some(alice_home.to_path_buf())).expect("alice card");
        let bob = trust::export_peer_card(Some(bob_home.to_path_buf())).expect("bob card");
        let alice_peer =
            trust::trust_peer_card(Some(bob_home.to_path_buf()), alice).expect("bob trusts alice");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.to_path_buf()), bob).expect("alice trusts bob");
        grant_peer_policy(alice_home, &bob_peer.peer_node_id, true, true);
        grant_peer_policy(bob_home, &alice_peer.peer_node_id, true, true);
    }

    fn grant_peer_policy(home: &Path, peer_node_id: &str, messages: bool, streams: bool) {
        policy::set_peer_policy(
            Some(home.to_path_buf()),
            peer_node_id,
            policy::PeerPolicyUpdate {
                messages: Some(messages),
                streams: Some(streams),
                rooms: Some(false),
                files: Some(false),
                mailbox: Some(false),
            },
        )
        .expect("peer policy grants");
    }

    fn register_agent(home: &Path, agent_id: &str) {
        let registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        agents::submit_registration(Some(home.to_path_buf()), registration)
            .expect("registration submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("registration processes");
    }

    fn node_id(home: &Path) -> String {
        state::read_state(Some(home.to_path_buf()))
            .expect("state reads")
            .node
            .expect("node exists")
            .node_id
    }

    #[test]
    fn runtime_relay_pump_is_idle_without_relay_or_trusted_peer() {
        let home = test_home("runtime-idle");
        let init = state::init_state(Some(home)).expect("state initializes");

        let should_sync =
            relay_runtime_should_sync_from_paths(&init.paths).expect("relay decision succeeds");

        assert!(!should_sync);
    }

    #[test]
    fn runtime_relay_pump_runs_for_configured_relay() {
        let home = test_home("runtime-configured");
        let init = state::init_state(Some(home)).expect("state initializes");
        fs::write(
            &init.paths.config,
            "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nrelay_auto_sync = true\n",
        )
        .expect("config writes");

        let should_sync =
            relay_runtime_should_sync_from_paths(&init.paths).expect("relay decision succeeds");

        assert!(should_sync);
    }

    #[test]
    fn relay_endpoint_validation_accepts_wss() {
        let home = test_home("runtime-wss-configured");
        let init = state::init_state(Some(home)).expect("state initializes");
        fs::write(
            &init.paths.config,
            "version = \"1\"\ndefault_relay = \"wss://relay.example.com/conu\"\nrelay_auto_sync = true\n",
        )
        .expect("config writes");

        let should_sync =
            relay_runtime_should_sync_from_paths(&init.paths).expect("relay decision succeeds");
        let endpoint = configured_relay_endpoint(&init.paths).expect("endpoint reads");

        assert!(should_sync);
        assert_eq!(endpoint, "wss://relay.example.com/conu");
    }

    #[test]
    fn relay_token_prefers_env_then_stored_credential_without_echoing_secret() {
        let home = test_home("stored-relay-token");
        let init = state::init_state(Some(home)).expect("state initializes");
        let stored_token = "stored-relay-token-1234567890";
        security::store_relay_credential_from_paths(&init.paths, stored_token)
            .expect("stored relay credential writes");

        let from_store =
            relay_token_with_env(&init.paths, None).expect("stored relay token resolves");
        let from_env =
            relay_token_with_env(&init.paths, Some("env-relay-token-1234567890".to_string()))
                .expect("env relay token resolves");
        let stored_contents =
            fs::read_to_string(&init.paths.relay_credential).expect("credential reads");

        assert_eq!(from_store, stored_token);
        assert_eq!(from_env, "env-relay-token-1234567890");
        assert!(!stored_contents.contains(stored_token));
        assert!(!format!("{from_store:?}").contains("private message contents"));
    }

    #[test]
    fn runtime_relay_pump_respects_auto_sync_disable() {
        let home = test_home("runtime-disabled");
        let init = state::init_state(Some(home)).expect("state initializes");
        fs::write(
            &init.paths.config,
            "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nrelay_auto_sync = false\n",
        )
        .expect("config writes");

        let should_sync =
            relay_runtime_should_sync_from_paths(&init.paths).expect("relay decision succeeds");

        assert!(!should_sync);
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-relay-delivery-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
