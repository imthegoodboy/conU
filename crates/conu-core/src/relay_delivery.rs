//! Relay-backed encrypted message delivery.
//!
//! This module is the first live internet data-plane slice. It queues local
//! agent bytes as peer-encrypted envelopes, syncs them over the blind WebSocket
//! relay, and delivers decrypted inbound envelopes into the addressed local
//! agent inbox. Logs and reports remain metadata-only.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conu_protocol::OpaquePayload;

use crate::agents::{self, AgentError};
use crate::messages::{self, InboxEntry, MessageError};
use crate::relay::{
    RelayClientFrame, RelayForward, RelayFrameError, RelayHello, RelayOpaqueBody, RelayServerFrame,
    RelayWebSocketClient,
};
use crate::security::{self, PeerEncryptedPayload, SecurityError};
use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus, TrustedPeer};

const RELAY_REQUEST_VERSION: &str = "1";
const DEFAULT_RELAY_ENDPOINT: &str = "ws://127.0.0.1:8787";
const DEFAULT_RELAY_TOKEN: &str = "local-dev-token";
const MAX_RELAY_PAYLOAD_BYTES: usize = 64 * 1024;

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

/// Result of queueing a remote relay message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMessageSubmission {
    pub request_id: String,
    pub envelope_id: String,
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

#[derive(Debug)]
pub enum RelayDeliveryError {
    State(StateError),
    Agent(AgentError),
    Message(MessageError),
    Security(SecurityError),
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
    let contents = render_relay_request(
        &relay_request_id,
        &envelope_id,
        &init.node.node_id,
        &peer.peer_node_id,
        &message.from_agent_id,
        &message.to_agent_id,
        &encrypted,
    );
    write_new_file(&request_path, &contents)?;

    Ok(RemoteMessageSubmission {
        request_id: relay_request_id,
        envelope_id,
        request_path,
        peer_node_id: peer.peer_node_id,
        payload_bytes: message.payload.len(),
    })
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
    let token = relay_token();
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
        client.send(&RelayClientFrame::Forward(request.to_forward_frame()?))?;
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
            None => break,
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
        RelayServerFrame::Forwarded {
            from_node_id,
            to_node_id,
            envelope_id,
            payload_bytes,
            from_agent_id,
            to_agent_id,
            body,
        } => {
            let incoming = IncomingRelayEnvelope {
                from_node_id,
                to_node_id,
                envelope_id,
                payload_bytes,
                from_agent_id,
                to_agent_id,
                body,
            };
            let entry = receive_forwarded_envelope(paths, &incoming)?;
            report.received += 1;
            report.inbox_entries.push(entry);
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
    payload_bytes: usize,
    from_agent_id: Option<String>,
    to_agent_id: Option<String>,
    body: Option<RelayOpaqueBody>,
}

fn receive_forwarded_envelope(
    paths: &StatePaths,
    incoming: &IncomingRelayEnvelope,
) -> Result<InboxEntry, RelayDeliveryError> {
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

    let encrypted = PeerEncryptedPayload {
        algorithm: body.algorithm.clone(),
        key_id: body.key_id.clone(),
        sender_exchange_public_key_hex: body.sender_exchange_public_key_hex.clone(),
        nonce_hex: body.nonce_hex.clone(),
        ciphertext_hex: body.ciphertext_hex.clone(),
        plaintext_len: incoming.payload_bytes,
    };
    let aad = relay_aad(
        &incoming.envelope_id,
        &incoming.from_node_id,
        &incoming.to_node_id,
        from_agent_id,
        to_agent_id,
    );
    let plaintext =
        security::decrypt_from_peer_from_paths(paths, expected_sender_key, &encrypted, &aad)?;
    validate_payload_size(plaintext.len())?;
    let entry = messages::deliver_remote_envelope_from_paths(
        paths,
        &incoming.envelope_id,
        from_agent_id,
        to_agent_id,
        OpaquePayload::from_bytes(plaintext),
    )?;
    append_relay_log(
        paths,
        "inbox_delivered",
        &incoming.envelope_id,
        &incoming.from_node_id,
        incoming.payload_bytes,
    )?;

    Ok(entry)
}

#[derive(Debug, Clone)]
struct RelayRequest {
    envelope_id: String,
    to_node_id: String,
    from_agent_id: String,
    to_agent_id: String,
    encrypted: PeerEncryptedPayload,
}

impl RelayRequest {
    fn to_forward_frame(&self) -> Result<RelayForward, RelayDeliveryError> {
        Ok(RelayForward::with_body(
            &self.to_node_id,
            &self.envelope_id,
            &self.from_agent_id,
            &self.to_agent_id,
            self.encrypted.plaintext_len,
            RelayOpaqueBody::new(
                &self.encrypted.algorithm,
                &self.encrypted.key_id,
                &self.encrypted.sender_exchange_public_key_hex,
                &self.encrypted.nonce_hex,
                &self.encrypted.ciphertext_hex,
            )?,
        )?)
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
    if value_or_empty(&values, "type") != "relay_message" {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "unsupported relay request type".to_string(),
        });
    }

    let _request_id = validate_identifier(required(&values, "request_id")?, "request id")?;
    let _from_node_id = validate_identifier(required(&values, "from_node_id")?, "from node id")?;
    let request = RelayRequest {
        envelope_id: validate_identifier(required(&values, "envelope_id")?, "envelope id")?,
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

fn render_relay_request(
    request_id: &str,
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    encrypted: &PeerEncryptedPayload,
) -> String {
    format!(
        "version = \"{}\"\ntype = \"relay_message\"\nrequest_id = \"{}\"\nenvelope_id = \"{}\"\nfrom_node_id = \"{}\"\nto_node_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\npayload_len = {}\npayload_privacy = \"peer_encrypted\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\nsender_exchange_public_key_hex = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\npayload_displayed = false\n",
        RELAY_REQUEST_VERSION,
        escape_file_value(request_id),
        escape_file_value(envelope_id),
        escape_file_value(from_node_id),
        escape_file_value(to_node_id),
        escape_file_value(from_agent_id),
        escape_file_value(to_agent_id),
        encrypted.plaintext_len,
        escape_file_value(&encrypted.algorithm),
        escape_file_value(&encrypted.key_id),
        escape_file_value(&encrypted.sender_exchange_public_key_hex),
        escape_file_value(&encrypted.nonce_hex),
        escape_file_value(&encrypted.ciphertext_hex)
    )
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

fn relay_token() -> String {
    env::var("CONU_RELAY_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RELAY_TOKEN.to_string())
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
    if !value.starts_with("ws://") {
        return Err(RelayDeliveryError::InvalidRequest {
            reason: "relay endpoint must start with ws://".to_string(),
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

    fn trust_each_other(alice_home: &Path, bob_home: &Path) {
        let alice = trust::export_peer_card(Some(alice_home.to_path_buf())).expect("alice card");
        let bob = trust::export_peer_card(Some(bob_home.to_path_buf())).expect("bob card");
        trust::trust_peer_card(Some(alice_home.to_path_buf()), bob).expect("alice trusts bob");
        trust::trust_peer_card(Some(bob_home.to_path_buf()), alice).expect("bob trusts alice");
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
