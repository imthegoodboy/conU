//! Local opaque message routing.
//!
//! Phase 11 delivers local-only opaque envelopes between registered agents. The
//! runtime validates identities and encrypts conU-owned payload storage, while
//! CLI/log/receipt surfaces expose metadata only.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::{
    AgentId, Envelope, EnvelopeKind, OpaquePayload, PROTOCOL_VERSION, ProtocolError,
};

use crate::agents::{self, AgentError};
use crate::security::{self, EncryptedPayload, SecurityError};
use crate::state::{self, StateError, StatePaths};

const REQUEST_VERSION: &str = "1";
const MAX_LOCAL_PAYLOAD_BYTES: usize = 64 * 1024;

/// Opaque local message submitted by an agent.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalMessage {
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub payload: OpaquePayload,
}

impl LocalMessage {
    pub fn new(
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload: OpaquePayload,
    ) -> Result<Self, MessageError> {
        validate_payload_size(payload.len())?;

        Ok(Self {
            from_agent_id: validate_identifier(from_agent_id.into(), "from agent id")?,
            to_agent_id: validate_identifier(to_agent_id.into(), "to agent id")?,
            payload,
        })
    }
}

impl fmt::Debug for LocalMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalMessage")
            .field("from_agent_id", &self.from_agent_id)
            .field("to_agent_id", &self.to_agent_id)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<opaque>")
            .finish()
    }
}

/// Result of submitting a local message request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSubmission {
    pub request_id: String,
    pub request_path: PathBuf,
    pub payload_bytes: usize,
}

/// Metadata for a delivered local message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEntry {
    pub envelope_id: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub kind: String,
    pub stream_id: Option<String>,
    pub receipt_id: String,
    pub delivered_at_unix: u64,
    pub payload_bytes: usize,
}

/// Metadata-only delivery receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub receipt_id: String,
    pub envelope_id: String,
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub kind: String,
    pub stream_id: Option<String>,
    pub status: String,
    pub delivered_at_unix: u64,
    pub payload_bytes: usize,
}

/// Result of conUD processing local message requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageProcessReport {
    pub delivered: usize,
    pub rejected: usize,
    pub envelope_ids: Vec<String>,
}

/// Errors produced by local message routing.
#[derive(Debug)]
pub enum MessageError {
    State(StateError),
    Agent(AgentError),
    Protocol(ProtocolError),
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

impl MessageError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Security(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRequest { reason } => {
                write!(formatter, "invalid message request: {reason}")
            }
        }
    }
}

impl std::error::Error for MessageError {}

impl From<StateError> for MessageError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<AgentError> for MessageError {
    fn from(error: AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<ProtocolError> for MessageError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<SecurityError> for MessageError {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}

/// Submit a local opaque message into the message gateway inbox.
pub fn submit_local_message(
    home_override: Option<PathBuf>,
    message: LocalMessage,
) -> Result<MessageSubmission, MessageError> {
    let init = state::init_state(home_override)?;
    let request_id = request_id("message");
    let request_path = init
        .paths
        .message_ipc_inbox_dir
        .join(format!("{request_id}.msg"));
    let encrypted = security::encrypt_for_storage_from_paths(
        &init.paths,
        message.payload.as_bytes(),
        &message_request_aad(&request_id, &message.from_agent_id, &message.to_agent_id),
    )?;
    let contents = render_message_request(&request_id, &message, &encrypted);
    write_new_file(&request_path, &contents)?;

    Ok(MessageSubmission {
        request_id,
        request_path,
        payload_bytes: message.payload.len(),
    })
}

/// Process pending local message requests using default state path resolution.
pub fn process_message_requests(
    home_override: Option<PathBuf>,
) -> Result<MessageProcessReport, MessageError> {
    let init = state::init_state(home_override)?;
    process_message_requests_from_paths(&init.paths)
}

/// Process pending local message requests from already resolved state paths.
pub fn process_message_requests_from_paths(
    paths: &StatePaths,
) -> Result<MessageProcessReport, MessageError> {
    ensure_message_dirs(paths)?;

    let mut report = MessageProcessReport {
        delivered: 0,
        rejected: 0,
        envelope_ids: Vec::new(),
    };

    for request_path in pending_message_requests(paths)? {
        match process_one_message_request(paths, &request_path) {
            Ok(delivery) => {
                report.delivered += 1;
                report.envelope_ids.push(delivery.envelope_id.clone());
                write_processed_marker(paths, &request_path, &delivery)?;
                remove_file_if_exists(&request_path)?;
            }
            Err(error) => {
                report.rejected += 1;
                reject_message_request(paths, &request_path, &error)?;
            }
        }
    }

    Ok(report)
}

/// List metadata for messages delivered to a local agent inbox.
pub fn list_agent_inbox(
    home_override: Option<PathBuf>,
    agent_id: &str,
) -> Result<Vec<InboxEntry>, MessageError> {
    let agent_id = validate_identifier(agent_id.to_string(), "agent id")?;
    let paths = StatePaths::resolve(home_override)?;
    let inbox_dir = paths.message_inbox_dir.join(&agent_id);
    if !inbox_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&inbox_dir)
        .map_err(|error| MessageError::io("read agent message inbox", &inbox_dir, error))?
    {
        let entry = entry.map_err(|error| {
            MessageError::io("read agent message inbox entry", &inbox_dir, error)
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("env") {
            entries.push(read_inbox_entry(&path)?);
        }
    }

    entries.sort_by(|left, right| left.envelope_id.cmp(&right.envelope_id));
    Ok(entries)
}

/// Read opaque payload bytes for a delivered local message.
pub fn read_message_payload(
    home_override: Option<PathBuf>,
    agent_id: &str,
    envelope_id: &str,
) -> Result<OpaquePayload, MessageError> {
    let agent_id = validate_identifier(agent_id.to_string(), "agent id")?;
    let envelope_id = validate_identifier(envelope_id.to_string(), "envelope id")?;
    let paths = StatePaths::resolve(home_override)?;
    let path = paths
        .message_inbox_dir
        .join(agent_id)
        .join(format!("{envelope_id}.env"));
    let contents = fs::read_to_string(&path)
        .map_err(|error| MessageError::io("read local message", &path, error))?;
    let values = parse_key_values(&contents);
    let payload =
        payload_from_values(&paths, &values, &message_envelope_aad_from_values(&values)?)?;

    Ok(OpaquePayload::from_bytes(payload))
}

/// Deliver a peer-decrypted remote envelope to a local addressed agent inbox.
pub fn deliver_remote_envelope_from_paths(
    paths: &StatePaths,
    envelope_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    payload: OpaquePayload,
) -> Result<InboxEntry, MessageError> {
    let envelope_id = validate_identifier(envelope_id.to_string(), "envelope id")?;
    let from_agent_id = validate_identifier(from_agent_id.to_string(), "from agent id")?;
    let to_agent_id = validate_identifier(to_agent_id.to_string(), "to agent id")?;
    validate_payload_size(payload.len())?;
    validate_local_recipient_can_receive_messages(paths, &to_agent_id)?;

    let envelope = Envelope::new(
        &envelope_id,
        AgentId::new(from_agent_id)?,
        AgentId::new(to_agent_id)?,
        EnvelopeKind::Message,
        payload,
    )?;

    security::record_replay_id_from_paths(paths, &envelope_id, "relay_envelope")?;
    deliver_envelope_with_status(paths, envelope, "delivered_relay")
}

/// Deliver a peer-decrypted remote stream chunk to a local addressed agent inbox.
pub fn deliver_remote_stream_chunk_from_paths(
    paths: &StatePaths,
    envelope_id: &str,
    stream_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    payload: OpaquePayload,
) -> Result<InboxEntry, MessageError> {
    let envelope_id = validate_identifier(envelope_id.to_string(), "envelope id")?;
    let stream_id = validate_identifier(stream_id.to_string(), "stream id")?;
    let from_agent_id = validate_identifier(from_agent_id.to_string(), "from agent id")?;
    let to_agent_id = validate_identifier(to_agent_id.to_string(), "to agent id")?;
    validate_payload_size(payload.len())?;
    validate_local_recipient_can_receive_streams(paths, &to_agent_id)?;

    let mut envelope = Envelope::new(
        &envelope_id,
        AgentId::new(from_agent_id)?,
        AgentId::new(to_agent_id)?,
        EnvelopeKind::StreamChunk,
        payload,
    )?;
    envelope.meta.stream_id = Some(stream_id.clone());

    security::record_replay_id_from_paths(paths, &envelope_id, "relay_stream_chunk")?;
    deliver_envelope_with_status_and_stream(
        paths,
        envelope,
        "delivered_relay_stream",
        Some(stream_id),
    )
}

/// Deliver an opaque room event to a local subscribed agent inbox.
pub fn deliver_room_event_from_paths(
    paths: &StatePaths,
    envelope_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    payload: OpaquePayload,
) -> Result<InboxEntry, MessageError> {
    let envelope_id = validate_identifier(envelope_id.to_string(), "envelope id")?;
    let from_agent_id = validate_identifier(from_agent_id.to_string(), "from agent id")?;
    let to_agent_id = validate_identifier(to_agent_id.to_string(), "to agent id")?;
    validate_payload_size(payload.len())?;
    validate_local_recipient_can_receive_rooms(paths, &to_agent_id)?;

    let envelope = Envelope::new(
        &envelope_id,
        AgentId::new(from_agent_id)?,
        AgentId::new(to_agent_id)?,
        EnvelopeKind::Event,
        payload,
    )?;

    security::record_replay_id_from_paths(paths, &envelope_id, "room_event_envelope")?;
    deliver_envelope_with_status(paths, envelope, "delivered_room")
}

/// List metadata-only local delivery receipts.
pub fn list_receipts(home_override: Option<PathBuf>) -> Result<Vec<DeliveryReceipt>, MessageError> {
    let paths = StatePaths::resolve(home_override)?;
    if !paths.message_receipts_dir.exists() {
        return Ok(Vec::new());
    }

    let mut receipts = Vec::new();
    for entry in fs::read_dir(&paths.message_receipts_dir).map_err(|error| {
        MessageError::io(
            "read message receipts directory",
            &paths.message_receipts_dir,
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            MessageError::io(
                "read message receipt entry",
                &paths.message_receipts_dir,
                error,
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("receipt") {
            receipts.push(read_receipt(&path)?);
        }
    }

    receipts.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    Ok(receipts)
}

fn process_one_message_request(
    paths: &StatePaths,
    request_path: &Path,
) -> Result<InboxEntry, MessageError> {
    let contents = fs::read_to_string(request_path)
        .map_err(|error| MessageError::io("read message IPC request", request_path, error))?;
    let values = parse_key_values(&contents);

    if value_or_empty(&values, "version") != REQUEST_VERSION {
        return Err(MessageError::InvalidRequest {
            reason: "unsupported request version".to_string(),
        });
    }
    if value_or_empty(&values, "type") != "send_message" {
        return Err(MessageError::InvalidRequest {
            reason: "unsupported request type".to_string(),
        });
    }

    let request_id_value = validate_identifier(required(&values, "request_id")?, "request id")?;
    security::record_replay_id_from_paths(paths, &request_id_value, "message_request")?;
    let from_agent_id = required(&values, "from_agent_id")?;
    let to_agent_id = required(&values, "to_agent_id")?;
    let payload = OpaquePayload::from_bytes(payload_from_values(
        paths,
        &values,
        &message_request_aad(&request_id_value, &from_agent_id, &to_agent_id),
    )?);
    let message = LocalMessage::new(from_agent_id, to_agent_id, payload)?;

    validate_agents_can_message(paths, &message.from_agent_id, &message.to_agent_id)?;

    let envelope_id = request_id("env");
    let envelope = Envelope::new(
        &envelope_id,
        AgentId::new(message.from_agent_id.clone())?,
        AgentId::new(message.to_agent_id.clone())?,
        EnvelopeKind::Message,
        message.payload,
    )?;

    security::record_replay_id_from_paths(paths, &envelope_id, "message_envelope")?;
    deliver_envelope_with_status(paths, envelope, "delivered_local")
}

fn validate_agents_can_message(
    paths: &StatePaths,
    from_agent_id: &str,
    to_agent_id: &str,
) -> Result<(), MessageError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let sender = registered
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
        .ok_or_else(|| MessageError::InvalidRequest {
            reason: "sender is not a registered local agent".to_string(),
        })?;
    let recipient = registered
        .iter()
        .find(|agent| agent.agent_id == to_agent_id)
        .ok_or_else(|| MessageError::InvalidRequest {
            reason: "recipient is not a registered local agent".to_string(),
        })?;

    if !sender.capabilities.messages {
        return Err(MessageError::InvalidRequest {
            reason: "sender is not allowed to send messages".to_string(),
        });
    }
    if !recipient.capabilities.messages {
        return Err(MessageError::InvalidRequest {
            reason: "recipient is not allowed to receive messages".to_string(),
        });
    }

    Ok(())
}

fn validate_local_recipient_can_receive_messages(
    paths: &StatePaths,
    to_agent_id: &str,
) -> Result<(), MessageError> {
    validate_local_recipient_capability(
        paths,
        to_agent_id,
        |recipient| recipient.capabilities.messages,
        "recipient is not allowed to receive messages",
    )
}

fn validate_local_recipient_can_receive_streams(
    paths: &StatePaths,
    to_agent_id: &str,
) -> Result<(), MessageError> {
    validate_local_recipient_capability(
        paths,
        to_agent_id,
        |recipient| recipient.capabilities.streams,
        "recipient is not allowed to receive stream chunks",
    )
}

fn validate_local_recipient_can_receive_rooms(
    paths: &StatePaths,
    to_agent_id: &str,
) -> Result<(), MessageError> {
    validate_local_recipient_capability(
        paths,
        to_agent_id,
        |recipient| recipient.capabilities.rooms,
        "recipient is not allowed to receive room events",
    )
}

fn validate_local_recipient_capability(
    paths: &StatePaths,
    to_agent_id: &str,
    allowed: impl FnOnce(&agents::LocalAgentRecord) -> bool,
    denied_reason: &'static str,
) -> Result<(), MessageError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let recipient = registered
        .iter()
        .find(|agent| agent.agent_id == to_agent_id)
        .ok_or_else(|| MessageError::InvalidRequest {
            reason: "recipient is not a registered local agent".to_string(),
        })?;

    if !allowed(recipient) {
        return Err(MessageError::InvalidRequest {
            reason: denied_reason.to_string(),
        });
    }

    Ok(())
}

fn deliver_envelope_with_status(
    paths: &StatePaths,
    envelope: Envelope,
    status: &str,
) -> Result<InboxEntry, MessageError> {
    deliver_envelope_with_status_and_stream(paths, envelope, status, None)
}

fn deliver_envelope_with_status_and_stream(
    paths: &StatePaths,
    envelope: Envelope,
    status: &str,
    stream_id: Option<String>,
) -> Result<InboxEntry, MessageError> {
    let now = current_unix_seconds();
    let receipt_id = request_id("rcpt");
    let inbox_dir = paths.message_inbox_dir.join(envelope.to.as_str());
    fs::create_dir_all(&inbox_dir)
        .map_err(|error| MessageError::io("create agent message inbox", &inbox_dir, error))?;
    fs::create_dir_all(&paths.message_receipts_dir).map_err(|error| {
        MessageError::io(
            "create message receipts directory",
            &paths.message_receipts_dir,
            error,
        )
    })?;

    let entry = InboxEntry {
        envelope_id: envelope.id.clone(),
        from_agent_id: envelope.from.as_str().to_string(),
        to_agent_id: envelope.to.as_str().to_string(),
        kind: envelope_kind_label(envelope.kind).to_string(),
        stream_id,
        receipt_id,
        delivered_at_unix: now,
        payload_bytes: envelope.payload.len(),
    };
    let encrypted = security::encrypt_for_storage_from_paths(
        paths,
        envelope.payload.as_bytes(),
        &message_envelope_storage_aad(
            &entry.envelope_id,
            &entry.from_agent_id,
            &entry.to_agent_id,
            entry.stream_id.as_deref(),
        ),
    )?;
    let envelope_path = inbox_dir.join(format!("{}.env", entry.envelope_id));
    write_new_file(
        &envelope_path,
        &render_envelope_file(&entry, envelope.kind, &encrypted),
    )?;

    let receipt = DeliveryReceipt {
        receipt_id: entry.receipt_id.clone(),
        envelope_id: entry.envelope_id.clone(),
        from_agent_id: entry.from_agent_id.clone(),
        to_agent_id: entry.to_agent_id.clone(),
        kind: entry.kind.clone(),
        stream_id: entry.stream_id.clone(),
        status: status.to_string(),
        delivered_at_unix: now,
        payload_bytes: entry.payload_bytes,
    };
    let receipt_path = paths
        .message_receipts_dir
        .join(format!("{}.receipt", receipt.receipt_id));
    write_new_file(&receipt_path, &render_receipt(&receipt))?;
    append_message_log(paths, &entry, status)?;

    Ok(entry)
}

fn ensure_message_dirs(paths: &StatePaths) -> Result<(), MessageError> {
    for directory in [
        &paths.message_ipc_dir,
        &paths.message_ipc_inbox_dir,
        &paths.message_ipc_processed_dir,
        &paths.message_ipc_rejected_dir,
        &paths.messages_dir,
        &paths.message_inbox_dir,
        &paths.message_receipts_dir,
    ] {
        fs::create_dir_all(directory)
            .map_err(|error| MessageError::io("create message directory", directory, error))?;
    }

    Ok(())
}

fn pending_message_requests(paths: &StatePaths) -> Result<Vec<PathBuf>, MessageError> {
    let mut requests = Vec::new();

    for entry in fs::read_dir(&paths.message_ipc_inbox_dir).map_err(|error| {
        MessageError::io(
            "read message IPC inbox",
            &paths.message_ipc_inbox_dir,
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            MessageError::io(
                "read message IPC inbox entry",
                &paths.message_ipc_inbox_dir,
                error,
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("msg") {
            requests.push(path);
        }
    }

    requests.sort();
    Ok(requests)
}

fn write_processed_marker(
    paths: &StatePaths,
    request_path: &Path,
    delivery: &InboxEntry,
) -> Result<(), MessageError> {
    fs::create_dir_all(&paths.message_ipc_processed_dir).map_err(|error| {
        MessageError::io(
            "create message IPC processed directory",
            &paths.message_ipc_processed_dir,
            error,
        )
    })?;
    let marker_path = paths
        .message_ipc_processed_dir
        .join(replace_extension(request_path, "meta"));
    let contents = format!(
        "version = \"{}\"\ntype = \"send_message\"\nrequest_id = \"{}\"\nenvelope_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\nstatus = \"delivered_local\"\npayload_len = {}\npayload_displayed = false\n",
        REQUEST_VERSION,
        escape_file_value(&request_stem(request_path)),
        escape_file_value(&delivery.envelope_id),
        escape_file_value(&delivery.from_agent_id),
        escape_file_value(&delivery.to_agent_id),
        delivery.payload_bytes
    );

    fs::write(&marker_path, contents).map_err(|error| {
        MessageError::io("write message IPC processed marker", &marker_path, error)
    })
}

fn reject_message_request(
    paths: &StatePaths,
    request_path: &Path,
    error: &MessageError,
) -> Result<(), MessageError> {
    fs::create_dir_all(&paths.message_ipc_rejected_dir).map_err(|error| {
        MessageError::io(
            "create message IPC rejected directory",
            &paths.message_ipc_rejected_dir,
            error,
        )
    })?;
    let error_path = paths
        .message_ipc_rejected_dir
        .join(replace_extension(request_path, "error"));
    fs::write(&error_path, format!("{error}\n")).map_err(|error| {
        MessageError::io("write message IPC rejection reason", &error_path, error)
    })?;
    remove_file_if_exists(request_path)
}

fn read_inbox_entry(path: &Path) -> Result<InboxEntry, MessageError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| MessageError::io("read inbox metadata", path, error))?;
    let values = parse_key_values(&contents);

    Ok(InboxEntry {
        envelope_id: validate_identifier(required(&values, "envelope_id")?, "envelope id")?,
        from_agent_id: validate_identifier(required(&values, "from_agent_id")?, "from agent id")?,
        to_agent_id: validate_identifier(required(&values, "to_agent_id")?, "to agent id")?,
        kind: validate_identifier(
            values
                .get("kind")
                .cloned()
                .unwrap_or_else(|| "message".to_string()),
            "envelope kind",
        )?,
        stream_id: values
            .get("stream_id")
            .map(|value| validate_identifier(value.clone(), "stream id"))
            .transpose()?,
        receipt_id: validate_identifier(required(&values, "receipt_id")?, "receipt id")?,
        delivered_at_unix: parse_u64(&required(&values, "delivered_at_unix")?)?,
        payload_bytes: parse_usize(&required(&values, "payload_len")?)?,
    })
}

fn read_receipt(path: &Path) -> Result<DeliveryReceipt, MessageError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| MessageError::io("read message receipt", path, error))?;
    let values = parse_key_values(&contents);

    Ok(DeliveryReceipt {
        receipt_id: validate_identifier(required(&values, "receipt_id")?, "receipt id")?,
        envelope_id: validate_identifier(required(&values, "envelope_id")?, "envelope id")?,
        from_agent_id: validate_identifier(required(&values, "from_agent_id")?, "from agent id")?,
        to_agent_id: validate_identifier(required(&values, "to_agent_id")?, "to agent id")?,
        kind: validate_identifier(
            values
                .get("kind")
                .cloned()
                .unwrap_or_else(|| "message".to_string()),
            "envelope kind",
        )?,
        stream_id: values
            .get("stream_id")
            .map(|value| validate_identifier(value.clone(), "stream id"))
            .transpose()?,
        status: required(&values, "status")?,
        delivered_at_unix: parse_u64(&required(&values, "delivered_at_unix")?)?,
        payload_bytes: parse_usize(&required(&values, "payload_len")?)?,
    })
}

fn payload_from_values(
    paths: &StatePaths,
    values: &HashMap<String, String>,
    aad: &[u8],
) -> Result<Vec<u8>, MessageError> {
    if values.contains_key("payload_ciphertext_hex") {
        let encrypted = EncryptedPayload {
            algorithm: required(values, "payload_cipher")?,
            key_id: required(values, "payload_key_id")?,
            nonce_hex: required(values, "payload_nonce_hex")?,
            ciphertext_hex: required(values, "payload_ciphertext_hex")?,
            plaintext_len: parse_usize(&required(values, "payload_len")?)?,
        };
        validate_payload_size(encrypted.plaintext_len)?;
        let plaintext = security::decrypt_from_storage_from_paths(paths, &encrypted, aad)?;
        validate_payload_size(plaintext.len())?;
        return Ok(plaintext);
    }

    // Backward-compatible read for pre-Phase-11 local test/state files. New
    // writes always use payload_ciphertext_hex and encrypted-at-rest metadata.
    hex_decode(&required(values, "payload_hex")?)
}

fn message_request_aad(request_id: &str, from_agent_id: &str, to_agent_id: &str) -> Vec<u8> {
    format!("conu:message-request:v1:{request_id}:{from_agent_id}:{to_agent_id}").into_bytes()
}

fn message_envelope_aad(envelope_id: &str, from_agent_id: &str, to_agent_id: &str) -> Vec<u8> {
    format!("conu:message-envelope:v1:{envelope_id}:{from_agent_id}:{to_agent_id}").into_bytes()
}

fn message_stream_envelope_aad(
    envelope_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    stream_id: &str,
) -> Vec<u8> {
    format!("conu:stream-envelope:v1:{envelope_id}:{from_agent_id}:{to_agent_id}:{stream_id}")
        .into_bytes()
}

fn message_envelope_storage_aad(
    envelope_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    stream_id: Option<&str>,
) -> Vec<u8> {
    match stream_id {
        Some(stream_id) => {
            message_stream_envelope_aad(envelope_id, from_agent_id, to_agent_id, stream_id)
        }
        None => message_envelope_aad(envelope_id, from_agent_id, to_agent_id),
    }
}

fn message_envelope_aad_from_values(
    values: &HashMap<String, String>,
) -> Result<Vec<u8>, MessageError> {
    Ok(message_envelope_storage_aad(
        &required(values, "envelope_id")?,
        &required(values, "from_agent_id")?,
        &required(values, "to_agent_id")?,
        values.get("stream_id").map(String::as_str),
    ))
}

fn render_message_request(
    request_id: &str,
    message: &LocalMessage,
    encrypted: &EncryptedPayload,
) -> String {
    format!(
        "version = \"{}\"\ntype = \"send_message\"\nrequest_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\npayload_len = {}\npayload_privacy = \"encrypted_at_rest\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\n",
        REQUEST_VERSION,
        escape_file_value(request_id),
        escape_file_value(&message.from_agent_id),
        escape_file_value(&message.to_agent_id),
        message.payload.len(),
        escape_file_value(&encrypted.algorithm),
        escape_file_value(&encrypted.key_id),
        escape_file_value(&encrypted.nonce_hex),
        escape_file_value(&encrypted.ciphertext_hex)
    )
}

fn render_envelope_file(
    entry: &InboxEntry,
    kind: EnvelopeKind,
    encrypted: &EncryptedPayload,
) -> String {
    let stream_line = entry
        .stream_id
        .as_deref()
        .map(|stream_id| format!("stream_id = \"{}\"\n", escape_file_value(stream_id)))
        .unwrap_or_default();

    format!(
        "version = \"{}\"\nenvelope_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\nkind = \"{}\"\n{}receipt_id = \"{}\"\ndelivered_at_unix = {}\npayload_len = {}\npayload_privacy = \"encrypted_at_rest\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\n",
        PROTOCOL_VERSION,
        escape_file_value(&entry.envelope_id),
        escape_file_value(&entry.from_agent_id),
        escape_file_value(&entry.to_agent_id),
        envelope_kind_label(kind),
        stream_line,
        escape_file_value(&entry.receipt_id),
        entry.delivered_at_unix,
        entry.payload_bytes,
        escape_file_value(&encrypted.algorithm),
        escape_file_value(&encrypted.key_id),
        escape_file_value(&encrypted.nonce_hex),
        escape_file_value(&encrypted.ciphertext_hex)
    )
}

fn envelope_kind_label(kind: EnvelopeKind) -> &'static str {
    match kind {
        EnvelopeKind::Message => "message",
        EnvelopeKind::StreamChunk => "stream_chunk",
        EnvelopeKind::Event => "event",
        EnvelopeKind::Receipt => "receipt",
    }
}

fn render_receipt(receipt: &DeliveryReceipt) -> String {
    let stream_line = receipt
        .stream_id
        .as_deref()
        .map(|stream_id| format!("stream_id = \"{}\"\n", escape_file_value(stream_id)))
        .unwrap_or_default();

    format!(
        "version = \"{}\"\nreceipt_id = \"{}\"\nenvelope_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\nkind = \"{}\"\n{}status = \"{}\"\ndelivered_at_unix = {}\npayload_len = {}\npayload_displayed = false\n",
        REQUEST_VERSION,
        escape_file_value(&receipt.receipt_id),
        escape_file_value(&receipt.envelope_id),
        escape_file_value(&receipt.from_agent_id),
        escape_file_value(&receipt.to_agent_id),
        escape_file_value(&receipt.kind),
        stream_line,
        escape_file_value(&receipt.status),
        receipt.delivered_at_unix,
        receipt.payload_bytes
    )
}

fn append_message_log(
    paths: &StatePaths,
    entry: &InboxEntry,
    status: &str,
) -> Result<(), MessageError> {
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| MessageError::io("create log directory", &paths.logs_dir, error))?;
    let log_path = paths.logs_dir.join("messages.log");
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .map_err(|error| MessageError::io("open message log", &log_path, error))?;
    let stream_field = entry
        .stream_id
        .as_deref()
        .map(|stream_id| format!(" stream={}", sanitize_log_value(stream_id)))
        .unwrap_or_default();

    writeln!(
        file,
        "time={} event=envelope_delivered status={} envelope={} kind={}{} from={} to={} bytes={} payload=not_observed",
        current_unix_seconds(),
        sanitize_log_value(status),
        sanitize_log_value(&entry.envelope_id),
        sanitize_log_value(&entry.kind),
        stream_field,
        sanitize_log_value(&entry.from_agent_id),
        sanitize_log_value(&entry.to_agent_id),
        entry.payload_bytes
    )
    .map_err(|error| MessageError::io("write message log", &log_path, error))
}

fn write_new_file(path: &Path, contents: &str) -> Result<(), MessageError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| MessageError::io("create message file", path, error))?;

    file.write_all(contents.as_bytes())
        .map_err(|error| MessageError::io("write message file", path, error))
}

fn remove_file_if_exists(path: &Path) -> Result<(), MessageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MessageError::io("remove message IPC request", path, error)),
    }
}

fn replace_extension(path: &Path, extension: &str) -> PathBuf {
    path.file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("request.msg"))
        .with_extension(extension)
}

fn request_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("request")
        .to_string()
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, MessageError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| MessageError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, MessageError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(MessageError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 100 {
        return Err(MessageError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(MessageError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_payload_size(bytes: usize) -> Result<(), MessageError> {
    if bytes > MAX_LOCAL_PAYLOAD_BYTES {
        return Err(MessageError::InvalidRequest {
            reason: "payload is too large for the Phase 6 local gateway".to_string(),
        });
    }
    Ok(())
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

fn parse_u64(value: &str) -> Result<u64, MessageError> {
    value
        .parse::<u64>()
        .map_err(|_| MessageError::InvalidRequest {
            reason: "expected unsigned integer".to_string(),
        })
}

fn parse_usize(value: &str) -> Result<usize, MessageError> {
    value
        .parse::<usize>()
        .map_err(|_| MessageError::InvalidRequest {
            reason: "expected unsigned integer".to_string(),
        })
}

fn request_id(prefix: &str) -> String {
    format!("{}_{}_{}", prefix, process::id(), current_unix_nanos())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, MessageError> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        return Err(MessageError::InvalidRequest {
            reason: "payload_hex must have an even number of characters".to_string(),
        });
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    let mut chars = value.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    validate_payload_size(bytes.len())?;

    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, MessageError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(MessageError::InvalidRequest {
            reason: "payload_hex must contain only hex characters".to_string(),
        }),
    }
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
    use conu_protocol::AgentCapabilities;

    #[test]
    fn message_request_file_hides_literal_payload() {
        let home = test_home("request-redaction");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message is valid");

        let submission =
            submit_local_message(Some(home), message).expect("message request submits");
        let contents = fs::read_to_string(submission.request_path).expect("request reads");

        assert!(contents.contains("type = \"send_message\""));
        assert!(contents.contains("payload_len = 24"));
        assert!(contents.contains("payload_privacy = \"encrypted_at_rest\""));
        assert!(contents.contains("payload_ciphertext_hex"));
        assert!(!contents.contains("payload_hex"));
        assert!(!contents.contains("private message contents"));
        assert!(!contents.contains("Review this code"));
    }

    #[test]
    fn process_message_delivers_to_recipient_inbox() {
        let home = test_home("deliver");
        register_agent(&home, "agent.sender");
        register_agent(&home, "agent.receiver");
        let payload = OpaquePayload::from_bytes([1, 2, 3, 4]);
        let message =
            LocalMessage::new("agent.sender", "agent.receiver", payload).expect("message valid");
        submit_local_message(Some(home.clone()), message).expect("message submits");

        let report = process_message_requests(Some(home.clone())).expect("message processes");
        let inbox = list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let received =
            read_message_payload(Some(home.clone()), "agent.receiver", &inbox[0].envelope_id)
                .expect("payload reads");

        assert_eq!(report.delivered, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].from_agent_id, "agent.sender");
        assert_eq!(inbox[0].payload_bytes, 4);
        assert_eq!(received.as_bytes(), &[1, 2, 3, 4]);
        let paths = StatePaths::from_home(home);
        let envelope_file = fs::read_to_string(
            paths
                .message_inbox_dir
                .join("agent.receiver")
                .join(format!("{}.env", inbox[0].envelope_id)),
        )
        .expect("envelope file reads");
        assert!(envelope_file.contains("payload_privacy = \"encrypted_at_rest\""));
        assert!(envelope_file.contains("payload_ciphertext_hex"));
        assert!(!envelope_file.contains("payload_hex"));
    }

    #[test]
    fn remote_stream_chunk_delivers_kind_and_stream_metadata() {
        let home = test_home("remote-stream-chunk");
        let mut capabilities = AgentCapabilities::basic();
        capabilities.streams = true;
        register_agent_with_capabilities(&home, "agent.receiver", capabilities);
        let paths = StatePaths::from_home(home.clone());

        let entry = deliver_remote_stream_chunk_from_paths(
            &paths,
            "streamenv.1",
            "stream.1",
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private stream chunk".to_vec()),
        )
        .expect("stream chunk delivers");
        let inbox = list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let payload =
            read_message_payload(Some(home.clone()), "agent.receiver", &entry.envelope_id)
                .expect("payload reads");
        let envelope_file = fs::read_to_string(
            paths
                .message_inbox_dir
                .join("agent.receiver")
                .join(format!("{}.env", entry.envelope_id)),
        )
        .expect("envelope file reads");

        assert_eq!(entry.kind, "stream_chunk");
        assert_eq!(entry.stream_id.as_deref(), Some("stream.1"));
        assert_eq!(inbox[0].kind, "stream_chunk");
        assert_eq!(inbox[0].stream_id.as_deref(), Some("stream.1"));
        assert_eq!(payload.as_bytes(), b"private stream chunk");
        assert!(envelope_file.contains("kind = \"stream_chunk\""));
        assert!(envelope_file.contains("stream_id = \"stream.1\""));
        assert!(envelope_file.contains("payload_ciphertext_hex"));
        assert!(!envelope_file.contains("private stream chunk"));
    }

    #[test]
    fn remote_stream_chunk_requires_stream_recipient_capability() {
        let home = test_home("remote-stream-chunk-capability");
        register_agent(&home, "agent.receiver");
        let paths = StatePaths::from_home(home);

        let error = deliver_remote_stream_chunk_from_paths(
            &paths,
            "streamenv.1",
            "stream.1",
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private stream chunk".to_vec()),
        )
        .expect_err("stream chunk requires recipient capability");

        assert!(error.to_string().contains("stream chunks"));
        assert!(!error.to_string().contains("private stream chunk"));
    }

    #[test]
    fn room_event_requires_room_recipient_capability() {
        let home = test_home("room-event-capability");
        register_agent(&home, "agent.receiver");
        let paths = StatePaths::from_home(home);

        let error = deliver_room_event_from_paths(
            &paths,
            "roomenv.1",
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private room event".to_vec()),
        )
        .expect_err("room event requires recipient capability");

        assert!(error.to_string().contains("room events"));
        assert!(!error.to_string().contains("private room event"));
    }

    #[test]
    fn duplicate_message_request_id_is_rejected_by_replay_cache() {
        let home = test_home("replay");
        register_agent(&home, "agent.sender");
        register_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        let first =
            submit_local_message(Some(home.clone()), message.clone()).expect("first request");
        let second = submit_local_message(Some(home.clone()), message).expect("second request");
        let second_text = fs::read_to_string(&second.request_path).expect("second request reads");
        let rewritten = second_text.replace(&second.request_id, &first.request_id);
        fs::write(&second.request_path, rewritten).expect("duplicate request writes");

        let report = process_message_requests(Some(home)).expect("requests process");

        assert_eq!(report.delivered, 1);
        assert_eq!(report.rejected, 1);
    }

    #[test]
    fn unknown_recipient_is_rejected_without_payload() {
        let home = test_home("reject");
        register_agent(&home, "agent.sender");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"secret private message contents".to_vec()),
        )
        .expect("message valid");
        submit_local_message(Some(home.clone()), message).expect("message submits");

        let report = process_message_requests(Some(home.clone())).expect("message processes");
        let paths = StatePaths::from_home(home);
        let rejected = fs::read_dir(&paths.message_ipc_rejected_dir)
            .expect("rejected dir reads")
            .collect::<Result<Vec<_>, _>>()
            .expect("entries read");
        let error_text = fs::read_to_string(rejected[0].path()).expect("rejection reason reads");

        assert_eq!(report.rejected, 1);
        assert!(error_text.contains("recipient is not a registered local agent"));
        assert!(!error_text.contains("secret private message contents"));
        assert_eq!(
            fs::read_dir(&paths.message_ipc_inbox_dir)
                .expect("inbox reads")
                .count(),
            0
        );
    }

    #[test]
    fn delivery_receipt_is_metadata_only() {
        let home = test_home("receipt");
        register_agent(&home, "agent.sender");
        register_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        submit_local_message(Some(home.clone()), message).expect("message submits");

        process_message_requests(Some(home.clone())).expect("message processes");
        let receipts = list_receipts(Some(home.clone())).expect("receipts read");
        let receipt_file = fs::read_to_string(
            fs::read_dir(StatePaths::from_home(home).message_receipts_dir)
                .expect("receipt dir reads")
                .next()
                .expect("receipt exists")
                .expect("receipt entry")
                .path(),
        )
        .expect("receipt file reads");

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, "delivered_local");
        assert_eq!(receipts[0].payload_bytes, 24);
        assert!(receipt_file.contains("payload_displayed = false"));
        assert!(!receipt_file.contains("private message contents"));
    }

    fn register_agent(home: &Path, agent_id: &str) {
        let registration =
            agents::AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        register_agent_with_registration(home, registration);
    }

    fn register_agent_with_capabilities(
        home: &Path,
        agent_id: &str,
        capabilities: AgentCapabilities,
    ) {
        let mut registration =
            agents::AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        registration.capabilities = capabilities;
        register_agent_with_registration(home, registration);
    }

    fn register_agent_with_registration(home: &Path, registration: agents::AgentRegistration) {
        agents::submit_registration(Some(home.to_path_buf()), registration)
            .expect("registration submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("registration processes");
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-messages-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
