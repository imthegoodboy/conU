//! Authenticated direct QUIC transport.
//!
//! This module owns the first real direct data-plane path. QUIC provides the
//! socket/session substrate, while conU authenticates trusted peers at the
//! application layer with the existing X25519 peer-card keys before a route is
//! considered available or an opaque envelope is delivered.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conu_protocol::OpaquePayload;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::crypto::CryptoProvider;
use quinn::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use quinn::rustls::{DigitallySignedStruct, Error as RustlsError};
use quinn::{ClientConfig, Endpoint};

use crate::agents::{self, AgentError};
use crate::messages::{self, InboxEntry, MessageError};
use crate::policy::{self, PeerPermission, PolicyError};
use crate::relay_delivery::{RemoteMessage, RemoteStreamChunk};
use crate::security::{self, PeerEncryptedPayload, SecurityError};
use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus, TrustedPeer};

const DIRECT_VERSION: &str = "1";
const DEFAULT_DIRECT_TIMEOUT_MS: u64 = 700;
const MAX_DIRECT_FRAME_BYTES: usize = 80 * 1024;
const MAX_DIRECT_PAYLOAD_BYTES: usize = 64 * 1024;
/// A completed direct QUIC route probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectProbeReport {
    pub peer_node_id: String,
    pub endpoint: String,
    pub authenticated: bool,
    pub latency_ms: u64,
}

/// A direct delivery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectDeliveryReport {
    pub envelope_id: String,
    pub peer_node_id: String,
    pub payload_bytes: usize,
    pub route: String,
}

/// Bounded conUD direct listener tick result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRuntimeReport {
    pub enabled: bool,
    pub listening: bool,
    pub endpoint: Option<String>,
    pub received: usize,
    pub rejected: usize,
}

/// Long-lived direct QUIC listener owned by conUD.
pub struct DirectRuntimeServer {
    runtime: tokio::runtime::Runtime,
    endpoint_label: Option<String>,
    endpoint: Option<Endpoint>,
}

impl fmt::Debug for DirectRuntimeServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectRuntimeServer")
            .field("endpoint", &self.endpoint_label)
            .field("listening", &self.endpoint.is_some())
            .finish_non_exhaustive()
    }
}

impl DirectRuntimeServer {
    pub fn new() -> Result<Self, DirectTransportError> {
        Ok(Self {
            runtime: build_runtime()?,
            endpoint_label: None,
            endpoint: None,
        })
    }

    pub fn disconnect(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"shutdown");
        }
        self.endpoint_label = None;
    }

    /// Accept and process direct QUIC frames for a bounded wait.
    pub fn tick_from_paths(
        &mut self,
        paths: &StatePaths,
        local_node_id: &str,
        wait: Duration,
    ) -> Result<DirectRuntimeReport, DirectTransportError> {
        let Some(endpoint_label) = configured_direct_quic_endpoint_from_paths(paths)? else {
            self.disconnect();
            return Ok(DirectRuntimeReport {
                enabled: false,
                listening: false,
                endpoint: None,
                received: 0,
                rejected: 0,
            });
        };

        if self.endpoint_label.as_deref() != Some(endpoint_label.as_str())
            || self.endpoint.is_none()
        {
            self.disconnect();
            let bind_addr = endpoint_to_socket_addr(&endpoint_label, EndpointUse::Bind)?;
            let server_config = direct_server_config()?;
            let _guard = self.runtime.enter();
            let endpoint = Endpoint::server(server_config, bind_addr).map_err(|error| {
                DirectTransportError::network("bind direct QUIC listener", error)
            })?;
            self.endpoint_label = Some(endpoint_label.clone());
            self.endpoint = Some(endpoint);
        }

        let endpoint = self.endpoint.as_ref().cloned().ok_or_else(|| {
            DirectTransportError::InvalidRequest {
                reason: "direct QUIC listener is not available".to_string(),
            }
        })?;
        let mut report = DirectRuntimeReport {
            enabled: true,
            listening: true,
            endpoint: Some(endpoint_label),
            received: 0,
            rejected: 0,
        };

        let result = self.runtime.block_on(accept_direct_frames(
            endpoint,
            paths,
            local_node_id,
            wait,
            &mut report,
        ));
        if result.is_err() {
            self.disconnect();
        }
        result.map(|()| report)
    }
}

impl Drop for DirectRuntimeServer {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Errors produced by direct transport.
#[derive(Debug)]
pub enum DirectTransportError {
    State(StateError),
    Agent(AgentError),
    Message(MessageError),
    Policy(PolicyError),
    Security(SecurityError),
    Trust(trust::TrustError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Network {
        action: &'static str,
        reason: String,
    },
    InvalidRequest {
        reason: String,
    },
}

impl DirectTransportError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }

    fn network(action: &'static str, error: impl fmt::Display) -> Self {
        Self::Network {
            action,
            reason: sanitize_reason(&error.to_string()),
        }
    }

    pub fn is_safe_for_relay_fallback(&self) -> bool {
        match self {
            Self::Network { action, .. } => matches!(
                *action,
                "resolve direct QUIC endpoint"
                    | "open direct QUIC client"
                    | "connect direct QUIC"
                    | "open direct QUIC stream"
            ),
            Self::InvalidRequest { reason } => {
                reason.contains("direct QUIC endpoint") || reason.contains("direct endpoint")
            }
            _ => false,
        }
    }
}

impl fmt::Display for DirectTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Policy(error) => write!(formatter, "{error}"),
            Self::Security(error) => write!(formatter, "{error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::Network { action, reason } => write!(formatter, "{action}: {reason}"),
            Self::InvalidRequest { reason } => {
                write!(formatter, "invalid direct request: {reason}")
            }
        }
    }
}

impl std::error::Error for DirectTransportError {}

impl From<StateError> for DirectTransportError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<AgentError> for DirectTransportError {
    fn from(error: AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<MessageError> for DirectTransportError {
    fn from(error: MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<PolicyError> for DirectTransportError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<SecurityError> for DirectTransportError {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}

impl From<trust::TrustError> for DirectTransportError {
    fn from(error: trust::TrustError) -> Self {
        Self::Trust(error)
    }
}

/// Return the configured local direct QUIC endpoint, if present.
pub fn configured_direct_quic_endpoint(
    home_override: Option<PathBuf>,
) -> Result<Option<String>, DirectTransportError> {
    let paths = StatePaths::resolve(home_override)?;
    configured_direct_quic_endpoint_from_paths(&paths)
}

/// Return the configured local direct QUIC endpoint from resolved paths.
pub fn configured_direct_quic_endpoint_from_paths(
    paths: &StatePaths,
) -> Result<Option<String>, DirectTransportError> {
    let values = read_config(paths)?;
    let Some(endpoint) = values
        .get("direct_quic_endpoint")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    validate_direct_endpoint(&endpoint)?;
    Ok(Some(endpoint))
}

/// Probe a peer's direct QUIC endpoint and authenticate both peer-card keys.
pub fn probe_direct_quic_from_paths(
    paths: &StatePaths,
    local_node_id: &str,
    peer: &TrustedPeer,
    endpoint: &str,
    timeout: Duration,
) -> Result<DirectProbeReport, DirectTransportError> {
    let peer = trusted_peer_with_key(paths, &peer.peer_node_id)?;
    validate_direct_endpoint(endpoint)?;
    let probe_id = request_id("directprobe");
    let plaintext = format!(
        "direct-probe:{probe_id}:{local_node_id}:{}",
        peer.peer_node_id
    );
    let aad = direct_probe_aad(&probe_id, local_node_id, &peer.peer_node_id);
    let encrypted = security::encrypt_for_peer_from_paths(
        paths,
        peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
            DirectTransportError::InvalidRequest {
                reason: "trusted peer does not have an exchange public key".to_string(),
            }
        })?,
        plaintext.as_bytes(),
        &aad,
    )?;
    let request = DirectFrameRender {
        frame_type: "direct_probe",
        kind: DirectFrameKind::Probe,
        envelope_id: &probe_id,
        stream_id: None,
        from_node_id: local_node_id,
        to_node_id: &peer.peer_node_id,
        from_agent_id: "conu.direct",
        to_agent_id: "conu.direct",
        encrypted: &encrypted,
    };
    let frame = render_direct_frame(request);
    let start = Instant::now();
    let response = direct_client_round_trip(endpoint, frame.as_bytes(), timeout)?;
    let values = parse_direct_response(&response)?;
    validate_probe_response(paths, local_node_id, &peer, &probe_id, &values)?;

    Ok(DirectProbeReport {
        peer_node_id: peer.peer_node_id,
        endpoint: endpoint.to_string(),
        authenticated: true,
        latency_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    })
}

/// Send an opaque remote message directly to a trusted peer.
pub fn send_direct_message(
    home_override: Option<PathBuf>,
    message: RemoteMessage,
) -> Result<DirectDeliveryReport, DirectTransportError> {
    let init = state::init_state(home_override)?;
    send_direct_message_from_paths(&init.paths, &init.node.node_id, message)
}

/// Send an opaque remote message directly from resolved runtime state.
pub fn send_direct_message_from_paths(
    paths: &StatePaths,
    local_node_id: &str,
    message: RemoteMessage,
) -> Result<DirectDeliveryReport, DirectTransportError> {
    validate_local_sender_can_message(paths, &message.from_agent_id)?;
    let peer = trusted_peer_with_key(paths, &message.peer_node_id)?;
    policy::ensure_peer_allowed_from_paths(paths, &peer.peer_node_id, PeerPermission::Messages)?;
    let endpoint = direct_endpoint_for_peer(paths, &peer)?;
    let envelope_id = request_id("directenv");
    let aad = direct_message_aad(
        &envelope_id,
        local_node_id,
        &peer.peer_node_id,
        &message.from_agent_id,
        &message.to_agent_id,
    );
    let encrypted = security::encrypt_for_peer_from_paths(
        paths,
        peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
            DirectTransportError::InvalidRequest {
                reason: "trusted peer does not have an exchange public key".to_string(),
            }
        })?,
        message.payload.as_bytes(),
        &aad,
    )?;
    let response = send_direct_envelope(
        paths,
        &endpoint,
        DirectFrameRender {
            frame_type: "direct_message",
            kind: DirectFrameKind::Message,
            envelope_id: &envelope_id,
            stream_id: None,
            from_node_id: local_node_id,
            to_node_id: &peer.peer_node_id,
            from_agent_id: &message.from_agent_id,
            to_agent_id: &message.to_agent_id,
            encrypted: &encrypted,
        },
        &peer,
        local_node_id,
    )?;
    validate_delivery_ack(paths, local_node_id, &peer, &envelope_id, &response)?;
    append_direct_log(
        paths,
        "outbox_sent",
        &envelope_id,
        &peer.peer_node_id,
        encrypted.plaintext_len,
    )?;

    Ok(DirectDeliveryReport {
        envelope_id,
        peer_node_id: peer.peer_node_id,
        payload_bytes: message.payload.len(),
        route: "direct-quic".to_string(),
    })
}

/// Send an opaque remote stream chunk directly from resolved runtime state.
pub fn send_direct_stream_chunk_from_paths(
    paths: &StatePaths,
    local_node_id: &str,
    chunk: RemoteStreamChunk,
) -> Result<DirectDeliveryReport, DirectTransportError> {
    validate_local_sender_can_stream(paths, &chunk.from_agent_id)?;
    let peer = trusted_peer_with_key(paths, &chunk.peer_node_id)?;
    policy::ensure_peer_allowed_from_paths(paths, &peer.peer_node_id, PeerPermission::Streams)?;
    let endpoint = direct_endpoint_for_peer(paths, &peer)?;
    let envelope_id = request_id("directstream");
    let aad = direct_stream_aad(
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
            DirectTransportError::InvalidRequest {
                reason: "trusted peer does not have an exchange public key".to_string(),
            }
        })?,
        chunk.payload.as_bytes(),
        &aad,
    )?;
    let response = send_direct_envelope(
        paths,
        &endpoint,
        DirectFrameRender {
            frame_type: "direct_stream_chunk",
            kind: DirectFrameKind::StreamChunk,
            envelope_id: &envelope_id,
            stream_id: Some(&chunk.stream_id),
            from_node_id: local_node_id,
            to_node_id: &peer.peer_node_id,
            from_agent_id: &chunk.from_agent_id,
            to_agent_id: &chunk.to_agent_id,
            encrypted: &encrypted,
        },
        &peer,
        local_node_id,
    )?;
    validate_delivery_ack(paths, local_node_id, &peer, &envelope_id, &response)?;
    append_direct_log(
        paths,
        "outbox_sent",
        &envelope_id,
        &peer.peer_node_id,
        encrypted.plaintext_len,
    )?;

    Ok(DirectDeliveryReport {
        envelope_id,
        peer_node_id: peer.peer_node_id,
        payload_bytes: chunk.payload.len(),
        route: "direct-quic".to_string(),
    })
}

fn send_direct_envelope(
    paths: &StatePaths,
    endpoint: &str,
    frame: DirectFrameRender<'_>,
    peer: &TrustedPeer,
    local_node_id: &str,
) -> Result<HashMap<String, String>, DirectTransportError> {
    validate_direct_endpoint(endpoint)?;
    let envelope_id = frame.envelope_id.to_string();
    let request = render_direct_frame(frame);
    let response = direct_client_round_trip(
        endpoint,
        request.as_bytes(),
        Duration::from_millis(DEFAULT_DIRECT_TIMEOUT_MS),
    )?;
    let values = parse_direct_response(&response)?;
    if value_or_empty(&values, "type") != "direct_ack" {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct peer did not acknowledge the envelope".to_string(),
        });
    }
    if value_or_empty(&values, "envelope_id") != envelope_id {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct acknowledgement envelope mismatch".to_string(),
        });
    }
    if value_or_empty(&values, "from_node_id") != peer.peer_node_id
        || value_or_empty(&values, "to_node_id") != local_node_id
    {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct acknowledgement peer mismatch".to_string(),
        });
    }
    append_direct_log(paths, "ack_received", &envelope_id, &peer.peer_node_id, 0)?;
    Ok(values)
}

async fn accept_direct_frames(
    endpoint: Endpoint,
    paths: &StatePaths,
    local_node_id: &str,
    wait: Duration,
    report: &mut DirectRuntimeReport,
) -> Result<(), DirectTransportError> {
    let start = Instant::now();
    while start.elapsed() < wait {
        let remaining = wait.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        let incoming = match tokio::time::timeout(remaining, endpoint.accept()).await {
            Ok(Some(incoming)) => incoming,
            Ok(None) | Err(_) => break,
        };
        let handled = handle_one_incoming(paths, local_node_id, incoming, remaining).await;
        match handled {
            Ok(Some(_entry)) => report.received += 1,
            Ok(None) => report.received += 1,
            Err(_) => {
                report.rejected += 1;
                append_direct_log(paths, "inbox_rejected", "", "", 0)?;
            }
        }
    }
    Ok(())
}

async fn handle_one_incoming(
    paths: &StatePaths,
    local_node_id: &str,
    incoming: quinn::Incoming,
    wait: Duration,
) -> Result<Option<InboxEntry>, DirectTransportError> {
    let connection = tokio::time::timeout(wait, incoming)
        .await
        .map_err(|error| DirectTransportError::network("accept direct QUIC connection", error))?
        .map_err(|error| {
            DirectTransportError::network("establish direct QUIC connection", error)
        })?;
    let (mut send, mut recv) = tokio::time::timeout(wait, connection.accept_bi())
        .await
        .map_err(|error| DirectTransportError::network("accept direct QUIC stream", error))?
        .map_err(|error| DirectTransportError::network("accept direct QUIC stream", error))?;
    let request = recv
        .read_to_end(MAX_DIRECT_FRAME_BYTES)
        .await
        .map_err(|error| DirectTransportError::network("read direct QUIC frame", error))?;
    let (response, entry) = receive_direct_frame(paths, local_node_id, &request)?;
    send.write_all(response.as_bytes())
        .await
        .map_err(|error| DirectTransportError::network("write direct QUIC response", error))?;
    send.finish()
        .map_err(|error| DirectTransportError::network("finish direct QUIC response", error))?;
    let _ = tokio::time::timeout(wait, connection.closed()).await;
    Ok(entry)
}

fn receive_direct_frame(
    paths: &StatePaths,
    local_node_id: &str,
    bytes: &[u8],
) -> Result<(String, Option<InboxEntry>), DirectTransportError> {
    let contents =
        std::str::from_utf8(bytes).map_err(|_| DirectTransportError::InvalidRequest {
            reason: "direct frame metadata is not UTF-8".to_string(),
        })?;
    let values = parse_key_values(contents);
    if value_or_empty(&values, "version") != DIRECT_VERSION {
        return Err(DirectTransportError::InvalidRequest {
            reason: "unsupported direct frame version".to_string(),
        });
    }
    let kind = DirectFrameKind::from_str(value_or_empty(&values, "kind"))?;
    let envelope_id = validate_identifier(required(&values, "envelope_id")?, "envelope id")?;
    let from_node_id = validate_identifier(required(&values, "from_node_id")?, "from node id")?;
    let to_node_id = validate_identifier(required(&values, "to_node_id")?, "to node id")?;
    if to_node_id != local_node_id {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct frame was not addressed to this node".to_string(),
        });
    }
    let peer = trusted_peer_with_key(paths, &from_node_id)?;
    let from_agent_id = validate_identifier(required(&values, "from_agent_id")?, "from agent id")?;
    let to_agent_id = validate_identifier(required(&values, "to_agent_id")?, "to agent id")?;
    let body = encrypted_from_values(&values)?;
    let expected_sender_key = peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
        DirectTransportError::InvalidRequest {
            reason: "trusted peer does not have an exchange public key".to_string(),
        }
    })?;
    if body.sender_exchange_public_key_hex != expected_sender_key {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct sender key does not match trusted peer card".to_string(),
        });
    }

    let aad = match kind {
        DirectFrameKind::Probe => direct_probe_aad(&envelope_id, &from_node_id, &to_node_id),
        DirectFrameKind::Message => {
            policy::ensure_peer_allowed_from_paths(
                paths,
                &peer.peer_node_id,
                PeerPermission::Messages,
            )?;
            direct_message_aad(
                &envelope_id,
                &from_node_id,
                &to_node_id,
                &from_agent_id,
                &to_agent_id,
            )
        }
        DirectFrameKind::StreamChunk => {
            policy::ensure_peer_allowed_from_paths(
                paths,
                &peer.peer_node_id,
                PeerPermission::Streams,
            )?;
            let stream_id = validate_identifier(required(&values, "stream_id")?, "stream id")?;
            direct_stream_aad(
                &envelope_id,
                &from_node_id,
                &to_node_id,
                &from_agent_id,
                &to_agent_id,
                &stream_id,
            )
        }
    };
    let plaintext =
        security::decrypt_from_peer_from_paths(paths, expected_sender_key, &body, &aad)?;
    validate_payload_size(plaintext.len())?;

    let entry = match kind {
        DirectFrameKind::Probe => {
            let expected = format!("direct-probe:{envelope_id}:{from_node_id}:{to_node_id}");
            if plaintext != expected.as_bytes() {
                return Err(DirectTransportError::InvalidRequest {
                    reason: "direct probe challenge mismatch".to_string(),
                });
            }
            None
        }
        DirectFrameKind::Message => Some(messages::deliver_remote_envelope_from_paths(
            paths,
            &envelope_id,
            &from_agent_id,
            &to_agent_id,
            OpaquePayload::from_bytes(plaintext),
        )?),
        DirectFrameKind::StreamChunk => {
            let stream_id = validate_identifier(required(&values, "stream_id")?, "stream id")?;
            Some(messages::deliver_remote_stream_chunk_from_paths(
                paths,
                &envelope_id,
                &stream_id,
                &from_agent_id,
                &to_agent_id,
                OpaquePayload::from_bytes(plaintext),
            )?)
        }
    };

    let response_plaintext = match kind {
        DirectFrameKind::Probe => {
            format!("direct-probe-ok:{envelope_id}:{to_node_id}:{from_node_id}")
        }
        DirectFrameKind::Message | DirectFrameKind::StreamChunk => {
            format!("direct-ack:{envelope_id}:{to_node_id}:{from_node_id}")
        }
    };
    let response_aad = direct_response_aad(&envelope_id, &to_node_id, &from_node_id);
    let encrypted = security::encrypt_for_peer_from_paths(
        paths,
        expected_sender_key,
        response_plaintext.as_bytes(),
        &response_aad,
    )?;
    let response_type = if kind == DirectFrameKind::Probe {
        "direct_probe_ok"
    } else {
        "direct_ack"
    };
    let response = render_direct_response(
        response_type,
        kind,
        &envelope_id,
        &to_node_id,
        &from_node_id,
        encrypted.plaintext_len,
        &encrypted,
    );
    append_direct_log(
        paths,
        "inbox_delivered",
        &envelope_id,
        &from_node_id,
        body.plaintext_len,
    )?;

    Ok((response, entry))
}

fn direct_client_round_trip(
    endpoint: &str,
    frame: &[u8],
    timeout: Duration,
) -> Result<String, DirectTransportError> {
    let remote = endpoint_to_socket_addr(endpoint, EndpointUse::Connect)?;
    let runtime = build_runtime()?;
    runtime.block_on(async move {
        let bind = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let mut client = Endpoint::client(bind)
            .map_err(|error| DirectTransportError::network("open direct QUIC client", error))?;
        client.set_default_client_config(insecure_client_config()?);
        let connecting = client
            .connect(remote, "conu-direct")
            .map_err(|error| DirectTransportError::network("connect direct QUIC", error))?;
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|error| DirectTransportError::network("connect direct QUIC", error))?
            .map_err(|error| DirectTransportError::network("connect direct QUIC", error))?;
        let (mut send, mut recv) = tokio::time::timeout(timeout, connection.open_bi())
            .await
            .map_err(|error| DirectTransportError::network("open direct QUIC stream", error))?
            .map_err(|error| DirectTransportError::network("open direct QUIC stream", error))?;
        send.write_all(frame)
            .await
            .map_err(|error| DirectTransportError::network("write direct QUIC frame", error))?;
        send.finish()
            .map_err(|error| DirectTransportError::network("finish direct QUIC request", error))?;
        let response = tokio::time::timeout(timeout, recv.read_to_end(MAX_DIRECT_FRAME_BYTES))
            .await
            .map_err(|error| DirectTransportError::network("read direct QUIC response", error))?
            .map_err(|error| DirectTransportError::network("read direct QUIC response", error))?;
        connection.close(0u32.into(), b"done");
        client.wait_idle().await;
        String::from_utf8(response).map_err(|_| DirectTransportError::InvalidRequest {
            reason: "direct QUIC response metadata is not UTF-8".to_string(),
        })
    })
}

fn validate_probe_response(
    paths: &StatePaths,
    local_node_id: &str,
    peer: &TrustedPeer,
    probe_id: &str,
    values: &HashMap<String, String>,
) -> Result<(), DirectTransportError> {
    if value_or_empty(values, "type") != "direct_probe_ok" {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct peer did not return a probe acknowledgement".to_string(),
        });
    }
    if value_or_empty(values, "envelope_id") != probe_id
        || value_or_empty(values, "from_node_id") != peer.peer_node_id
        || value_or_empty(values, "to_node_id") != local_node_id
    {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct probe response metadata mismatch".to_string(),
        });
    }
    let encrypted = encrypted_from_values(values)?;
    let expected_sender_key = peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
        DirectTransportError::InvalidRequest {
            reason: "trusted peer does not have an exchange public key".to_string(),
        }
    })?;
    if encrypted.sender_exchange_public_key_hex != expected_sender_key {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct response key does not match trusted peer card".to_string(),
        });
    }
    let aad = direct_response_aad(probe_id, &peer.peer_node_id, local_node_id);
    let plaintext =
        security::decrypt_from_peer_from_paths(paths, expected_sender_key, &encrypted, &aad)?;
    let expected = format!(
        "direct-probe-ok:{probe_id}:{}:{local_node_id}",
        peer.peer_node_id
    );
    if plaintext != expected.as_bytes() {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct probe response challenge mismatch".to_string(),
        });
    }
    Ok(())
}

fn validate_delivery_ack(
    paths: &StatePaths,
    local_node_id: &str,
    peer: &TrustedPeer,
    envelope_id: &str,
    values: &HashMap<String, String>,
) -> Result<(), DirectTransportError> {
    let encrypted = encrypted_from_values(values)?;
    let expected_sender_key = peer.exchange_public_key_hex.as_deref().ok_or_else(|| {
        DirectTransportError::InvalidRequest {
            reason: "trusted peer does not have an exchange public key".to_string(),
        }
    })?;
    if encrypted.sender_exchange_public_key_hex != expected_sender_key {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct acknowledgement key does not match trusted peer card".to_string(),
        });
    }
    let aad = direct_response_aad(envelope_id, &peer.peer_node_id, local_node_id);
    let plaintext =
        security::decrypt_from_peer_from_paths(paths, expected_sender_key, &encrypted, &aad)?;
    let expected = format!(
        "direct-ack:{envelope_id}:{}:{local_node_id}",
        peer.peer_node_id
    );
    if plaintext != expected.as_bytes() {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct acknowledgement challenge mismatch".to_string(),
        });
    }
    Ok(())
}

fn read_config(paths: &StatePaths) -> Result<HashMap<String, String>, DirectTransportError> {
    let contents = match fs::read_to_string(&paths.config) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(DirectTransportError::io(
                "read conU config",
                &paths.config,
                error,
            ));
        }
    };
    Ok(parse_key_values(&contents))
}

fn direct_endpoint_for_peer(
    paths: &StatePaths,
    peer: &TrustedPeer,
) -> Result<String, DirectTransportError> {
    let values = read_config(paths)?;
    let keyed = format!("direct_quic_{}", config_key_suffix(&peer.peer_node_id));
    let endpoint = values
        .get(&keyed)
        .or(peer.direct_quic_endpoint.as_ref())
        .or_else(|| values.get("direct_quic_endpoint"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: "trusted peer does not have a direct QUIC endpoint".to_string(),
        })?;
    validate_direct_endpoint(&endpoint)?;
    Ok(endpoint)
}

fn direct_server_config() -> Result<quinn::ServerConfig, DirectTransportError> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["conu-direct".to_string()]).map_err(|error| {
            DirectTransportError::network("generate direct QUIC certificate", error)
        })?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut server_config =
        quinn::ServerConfig::with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
            .map_err(|error| {
                DirectTransportError::network("configure direct QUIC server", error)
            })?;
    Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: "direct transport config is shared unexpectedly".to_string(),
        })?
        .max_concurrent_uni_streams(0_u8.into());
    Ok(server_config)
}

fn insecure_client_config() -> Result<ClientConfig, DirectTransportError> {
    let crypto = quinn::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    Ok(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).map_err(|error| {
            DirectTransportError::network("configure direct QUIC client", error)
        })?,
    )))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(
            quinn::rustls::crypto::ring::default_provider(),
        )))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        quinn::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        quinn::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectFrameKind {
    Probe,
    Message,
    StreamChunk,
}

impl DirectFrameKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Message => "message",
            Self::StreamChunk => "stream_chunk",
        }
    }

    fn from_str(value: &str) -> Result<Self, DirectTransportError> {
        match value {
            "probe" => Ok(Self::Probe),
            "message" => Ok(Self::Message),
            "stream_chunk" => Ok(Self::StreamChunk),
            _ => Err(DirectTransportError::InvalidRequest {
                reason: "unsupported direct frame kind".to_string(),
            }),
        }
    }
}

struct DirectFrameRender<'a> {
    frame_type: &'a str,
    kind: DirectFrameKind,
    envelope_id: &'a str,
    stream_id: Option<&'a str>,
    from_node_id: &'a str,
    to_node_id: &'a str,
    from_agent_id: &'a str,
    to_agent_id: &'a str,
    encrypted: &'a PeerEncryptedPayload,
}

fn render_direct_frame(frame: DirectFrameRender<'_>) -> String {
    let stream_line = frame
        .stream_id
        .map(|stream_id| format!("stream_id = \"{}\"\n", escape_file_value(stream_id)))
        .unwrap_or_default();
    format!(
        "version = \"{}\"\ntype = \"{}\"\nkind = \"{}\"\n{}envelope_id = \"{}\"\nfrom_node_id = \"{}\"\nto_node_id = \"{}\"\nfrom_agent_id = \"{}\"\nto_agent_id = \"{}\"\npayload_len = {}\npayload_privacy = \"peer_encrypted\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\nsender_exchange_public_key_hex = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\npayload_displayed = false\n",
        DIRECT_VERSION,
        frame.frame_type,
        frame.kind.as_str(),
        stream_line,
        escape_file_value(frame.envelope_id),
        escape_file_value(frame.from_node_id),
        escape_file_value(frame.to_node_id),
        escape_file_value(frame.from_agent_id),
        escape_file_value(frame.to_agent_id),
        frame.encrypted.plaintext_len,
        escape_file_value(&frame.encrypted.algorithm),
        escape_file_value(&frame.encrypted.key_id),
        escape_file_value(&frame.encrypted.sender_exchange_public_key_hex),
        escape_file_value(&frame.encrypted.nonce_hex),
        escape_file_value(&frame.encrypted.ciphertext_hex)
    )
}

fn render_direct_response(
    response_type: &str,
    kind: DirectFrameKind,
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    plaintext_len: usize,
    encrypted: &PeerEncryptedPayload,
) -> String {
    format!(
        "version = \"{}\"\ntype = \"{}\"\nkind = \"{}\"\nenvelope_id = \"{}\"\nfrom_node_id = \"{}\"\nto_node_id = \"{}\"\npayload_len = {}\npayload_privacy = \"peer_encrypted\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\nsender_exchange_public_key_hex = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\npayload_displayed = false\n",
        DIRECT_VERSION,
        response_type,
        kind.as_str(),
        escape_file_value(envelope_id),
        escape_file_value(from_node_id),
        escape_file_value(to_node_id),
        plaintext_len,
        escape_file_value(&encrypted.algorithm),
        escape_file_value(&encrypted.key_id),
        escape_file_value(&encrypted.sender_exchange_public_key_hex),
        escape_file_value(&encrypted.nonce_hex),
        escape_file_value(&encrypted.ciphertext_hex)
    )
}

fn parse_direct_response(response: &str) -> Result<HashMap<String, String>, DirectTransportError> {
    let values = parse_key_values(response);
    if value_or_empty(&values, "version") != DIRECT_VERSION {
        return Err(DirectTransportError::InvalidRequest {
            reason: "unsupported direct response version".to_string(),
        });
    }
    Ok(values)
}

fn encrypted_from_values(
    values: &HashMap<String, String>,
) -> Result<PeerEncryptedPayload, DirectTransportError> {
    let plaintext_len = parse_usize(&required(values, "payload_len")?)?;
    validate_payload_size(plaintext_len)?;
    Ok(PeerEncryptedPayload {
        algorithm: required(values, "payload_cipher")?,
        key_id: required(values, "payload_key_id")?,
        sender_exchange_public_key_hex: required(values, "sender_exchange_public_key_hex")?,
        nonce_hex: required(values, "payload_nonce_hex")?,
        ciphertext_hex: required(values, "payload_ciphertext_hex")?,
        plaintext_len,
    })
}

fn validate_local_sender_can_message(
    paths: &StatePaths,
    from_agent_id: &str,
) -> Result<(), DirectTransportError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let sender = registered
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: "sender is not a registered local agent".to_string(),
        })?;
    if !sender.capabilities.messages {
        return Err(DirectTransportError::InvalidRequest {
            reason: "sender is not allowed to send messages".to_string(),
        });
    }
    Ok(())
}

fn validate_local_sender_can_stream(
    paths: &StatePaths,
    from_agent_id: &str,
) -> Result<(), DirectTransportError> {
    let registered = agents::list_local_agents(Some(paths.home.clone()))?;
    let sender = registered
        .iter()
        .find(|agent| agent.agent_id == from_agent_id)
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: "sender is not a registered local agent".to_string(),
        })?;
    if !sender.capabilities.streams {
        return Err(DirectTransportError::InvalidRequest {
            reason: "sender is not allowed to send stream chunks".to_string(),
        });
    }
    Ok(())
}

fn trusted_peer_with_key(
    paths: &StatePaths,
    peer_node_id: &str,
) -> Result<TrustedPeer, DirectTransportError> {
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    let peer = trust::list_peers(Some(paths.home.clone()))?
        .into_iter()
        .find(|peer| peer.peer_node_id == peer_node_id)
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: "peer is not trusted locally".to_string(),
        })?;
    if peer.status != TrustStatus::Trusted {
        return Err(DirectTransportError::InvalidRequest {
            reason: "peer is revoked".to_string(),
        });
    }
    if peer.exchange_public_key_hex.is_none() {
        return Err(DirectTransportError::InvalidRequest {
            reason: "peer is missing exchange public key; import a peer card first".to_string(),
        });
    }
    Ok(peer)
}

#[derive(Debug, Clone, Copy)]
enum EndpointUse {
    Bind,
    Connect,
}

fn endpoint_to_socket_addr(
    endpoint: &str,
    usage: EndpointUse,
) -> Result<SocketAddr, DirectTransportError> {
    validate_direct_endpoint(endpoint)?;
    let without_scheme = endpoint
        .strip_prefix("quic://")
        .or_else(|| endpoint.strip_prefix("udp://"))
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: "direct endpoint must start with quic:// or udp://".to_string(),
        })?;
    let mut addrs = without_scheme
        .to_socket_addrs()
        .map_err(|error| DirectTransportError::network("resolve direct QUIC endpoint", error))?;
    addrs
        .next()
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: match usage {
                EndpointUse::Bind => "direct bind endpoint did not resolve".to_string(),
                EndpointUse::Connect => "direct peer endpoint did not resolve".to_string(),
            },
        })
}

/// Validate that an endpoint cannot hide credentials, query strings, or spaces.
pub fn validate_direct_endpoint(endpoint: &str) -> Result<(), DirectTransportError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct endpoint cannot be empty".to_string(),
        });
    }
    if endpoint.len() > 220
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.contains('@')
        || endpoint.contains('?')
        || endpoint.contains('#')
    {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct endpoint is invalid".to_string(),
        });
    }
    let Some(without_scheme) = endpoint
        .strip_prefix("quic://")
        .or_else(|| endpoint.strip_prefix("udp://"))
    else {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct endpoint must start with quic:// or udp://".to_string(),
        });
    };
    if without_scheme.contains('/') {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct endpoint path is not supported".to_string(),
        });
    }
    let Some((host, port)) = without_scheme.rsplit_once(':') else {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct endpoint must include host and port".to_string(),
        });
    };
    if host.trim().is_empty() || !port.parse::<u16>().is_ok_and(|port| port > 0) {
        return Err(DirectTransportError::InvalidRequest {
            reason: "direct endpoint host or port is invalid".to_string(),
        });
    }
    Ok(())
}

fn append_direct_log(
    paths: &StatePaths,
    event: &str,
    envelope_id: &str,
    peer_node_id: &str,
    bytes: usize,
) -> Result<(), DirectTransportError> {
    fs::create_dir_all(&paths.logs_dir).map_err(|error| {
        DirectTransportError::io("create log directory", &paths.logs_dir, error)
    })?;
    let log_path = paths.logs_dir.join("direct.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| DirectTransportError::io("open direct log", &log_path, error))?;
    writeln!(
        file,
        "time={} event={} peer={} envelope={} bytes={} payload=not_observed",
        current_unix_seconds(),
        sanitize_log_value(event),
        sanitize_log_value(peer_node_id),
        sanitize_log_value(envelope_id),
        bytes
    )
    .map_err(|error| DirectTransportError::io("write direct log", &log_path, error))
}

fn direct_probe_aad(probe_id: &str, from_node_id: &str, to_node_id: &str) -> Vec<u8> {
    format!("conu:direct-quic-probe:v1:{probe_id}:{from_node_id}:{to_node_id}").into_bytes()
}

fn direct_message_aad(
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
) -> Vec<u8> {
    format!(
        "conu:direct-quic-message:v1:{envelope_id}:{from_node_id}:{to_node_id}:{from_agent_id}:{to_agent_id}"
    )
    .into_bytes()
}

fn direct_stream_aad(
    envelope_id: &str,
    from_node_id: &str,
    to_node_id: &str,
    from_agent_id: &str,
    to_agent_id: &str,
    stream_id: &str,
) -> Vec<u8> {
    format!(
        "conu:direct-quic-stream-chunk:v1:{envelope_id}:{from_node_id}:{to_node_id}:{from_agent_id}:{to_agent_id}:{stream_id}"
    )
    .into_bytes()
}

fn direct_response_aad(envelope_id: &str, from_node_id: &str, to_node_id: &str) -> Vec<u8> {
    format!("conu:direct-quic-response:v1:{envelope_id}:{from_node_id}:{to_node_id}").into_bytes()
}

fn build_runtime() -> Result<tokio::runtime::Runtime, DirectTransportError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| DirectTransportError::network("create direct QUIC runtime", error))
}

fn validate_payload_size(bytes: usize) -> Result<(), DirectTransportError> {
    if bytes > MAX_DIRECT_PAYLOAD_BYTES {
        return Err(DirectTransportError::InvalidRequest {
            reason: "payload is too large for direct transport".to_string(),
        });
    }
    Ok(())
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, DirectTransportError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(DirectTransportError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 180 {
        return Err(DirectTransportError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(DirectTransportError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn config_key_suffix(value: &str) -> String {
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
) -> Result<String, DirectTransportError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| DirectTransportError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn value_or_empty<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values.get(key).map(String::as_str).unwrap_or("")
}

fn parse_usize(value: &str) -> Result<usize, DirectTransportError> {
    value
        .parse::<usize>()
        .map_err(|_| DirectTransportError::InvalidRequest {
            reason: "expected unsigned integer".to_string(),
        })
}

fn request_id(prefix: &str) -> String {
    format!("{}_{}_{}", prefix, process::id(), current_unix_nanos())
}

fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect()
}

fn sanitize_reason(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || character.is_ascii_whitespace()
                || matches!(character, '-' | '_' | '.' | ':' | ',' | '(' | ')')
        })
        .take(180)
        .collect::<String>()
        .trim()
        .to_string()
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
    fn direct_endpoint_validation_rejects_secret_bearing_values() {
        assert!(validate_direct_endpoint("quic://127.0.0.1:9443").is_ok());
        assert!(validate_direct_endpoint("udp://127.0.0.1:9443").is_ok());
        assert!(validate_direct_endpoint("quic://token@127.0.0.1:9443").is_err());
        assert!(validate_direct_endpoint("quic://127.0.0.1:9443/path").is_err());
        assert!(validate_direct_endpoint("quic://127.0.0.1:9443?token=value").is_err());
    }

    #[test]
    fn direct_probe_fails_closed_when_peer_is_unavailable() {
        let alice_home = test_home("probe-unavailable-alice");
        let bob_home = test_home("probe-unavailable-bob");
        let bob_card = trust::export_peer_card(Some(bob_home.clone())).expect("bob card exports");
        let peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");
        let paths = StatePaths::from_home(alice_home.clone());
        let alice_node = state::read_state(Some(alice_home))
            .expect("state reads")
            .node
            .expect("node exists")
            .node_id;

        let error = probe_direct_quic_from_paths(
            &paths,
            &alice_node,
            &peer,
            "quic://127.0.0.1:9",
            Duration::from_millis(150),
        )
        .expect_err("unavailable peer fails closed");

        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn direct_quic_probe_authenticates_trusted_peer() {
        let alice_home = test_home("probe-alice");
        let bob_home = test_home("probe-bob");
        let bob_endpoint = free_loopback_endpoint();
        state::init_state(Some(bob_home.clone())).expect("bob state initializes");
        fs::write(
            StatePaths::from_home(bob_home.clone()).config,
            format!("version = \"1\"\ndirect_quic_endpoint = \"{bob_endpoint}\"\n"),
        )
        .expect("bob config writes");
        let alice_card =
            trust::export_peer_card(Some(alice_home.clone())).expect("alice card exports");
        let bob_card = trust::export_peer_card(Some(bob_home.clone())).expect("bob card exports");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");
        trust::trust_peer_card(Some(bob_home.clone()), alice_card).expect("bob trusts alice");

        let bob_paths = StatePaths::from_home(bob_home.clone());
        let bob_node = state::read_state(Some(bob_home))
            .expect("bob state")
            .node
            .expect("bob node")
            .node_id;
        let mut server = DirectRuntimeServer::new().expect("server starts");
        let handle = std::thread::spawn(move || {
            server
                .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(900))
                .expect("server tick")
        });
        std::thread::sleep(Duration::from_millis(100));

        let alice_paths = StatePaths::from_home(alice_home.clone());
        let alice_node = state::read_state(Some(alice_home))
            .expect("alice state")
            .node
            .expect("alice node")
            .node_id;
        let report = probe_direct_quic_from_paths(
            &alice_paths,
            &alice_node,
            &bob_peer,
            &bob_endpoint,
            Duration::from_millis(900),
        )
        .expect("direct probe succeeds");
        let server_report = handle.join().expect("server joins");

        assert!(report.authenticated);
        assert!(server_report.listening);
        assert_eq!(server_report.received, 1);
    }

    #[test]
    fn direct_stream_chunk_delivers_to_peer_inbox_without_payload_logs() {
        let alice_home = test_home("stream-alice");
        let bob_home = test_home("stream-bob");
        let bob_endpoint = free_loopback_endpoint();
        state::init_state(Some(bob_home.clone())).expect("bob state initializes");
        fs::write(
            StatePaths::from_home(bob_home.clone()).config,
            format!("version = \"1\"\ndirect_quic_endpoint = \"{bob_endpoint}\"\n"),
        )
        .expect("bob config writes");
        let alice_card =
            trust::export_peer_card(Some(alice_home.clone())).expect("alice card exports");
        let bob_card = trust::export_peer_card(Some(bob_home.clone())).expect("bob card exports");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");
        let alice_peer =
            trust::trust_peer_card(Some(bob_home.clone()), alice_card).expect("bob trusts alice");
        grant_peer_policy(&alice_home, &bob_peer.peer_node_id, false, true);
        grant_peer_policy(&bob_home, &alice_peer.peer_node_id, false, true);
        register_stream_agent(&alice_home, "agent.alice");
        register_stream_agent(&bob_home, "agent.bob");

        let bob_paths = StatePaths::from_home(bob_home.clone());
        let bob_node = state::read_state(Some(bob_home.clone()))
            .expect("bob state")
            .node
            .expect("bob node")
            .node_id;
        let mut server = DirectRuntimeServer::new().expect("server starts");
        let handle = std::thread::spawn(move || {
            server
                .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(900))
                .expect("server tick")
        });
        std::thread::sleep(Duration::from_millis(100));

        let alice_paths = StatePaths::from_home(alice_home.clone());
        let alice_node = state::read_state(Some(alice_home))
            .expect("alice state")
            .node
            .expect("alice node")
            .node_id;
        let chunk = RemoteStreamChunk::new(
            "stream.1",
            "agent.alice",
            "agent.bob",
            &bob_peer.peer_node_id,
            OpaquePayload::from_bytes(b"private stream chunk".to_vec()),
        )
        .expect("chunk valid");
        let sent = send_direct_stream_chunk_from_paths(&alice_paths, &alice_node, chunk)
            .expect("direct stream sends");
        let server_report = handle.join().expect("server joins");
        let inbox = messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob")
            .expect("bob inbox reads");
        let log = fs::read_to_string(StatePaths::from_home(bob_home).logs_dir.join("direct.log"))
            .expect("direct log reads");

        assert_eq!(sent.route, "direct-quic");
        assert_eq!(server_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].kind, "stream_chunk");
        assert!(log.contains("payload=not_observed"));
        assert!(!log.contains("private stream chunk"));
    }

    #[test]
    fn direct_message_delivers_to_peer_inbox_without_payload_logs() {
        let alice_home = test_home("message-alice");
        let bob_home = test_home("message-bob");
        let bob_endpoint = free_loopback_endpoint();
        state::init_state(Some(bob_home.clone())).expect("bob state initializes");
        fs::write(
            StatePaths::from_home(bob_home.clone()).config,
            format!("version = \"1\"\ndirect_quic_endpoint = \"{bob_endpoint}\"\n"),
        )
        .expect("bob config writes");
        let alice_card =
            trust::export_peer_card(Some(alice_home.clone())).expect("alice card exports");
        let bob_card = trust::export_peer_card(Some(bob_home.clone())).expect("bob card exports");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");
        let alice_peer =
            trust::trust_peer_card(Some(bob_home.clone()), alice_card).expect("bob trusts alice");
        grant_peer_policy(&alice_home, &bob_peer.peer_node_id, true, false);
        grant_peer_policy(&bob_home, &alice_peer.peer_node_id, true, false);
        register_stream_agent(&alice_home, "agent.alice");
        register_stream_agent(&bob_home, "agent.bob");

        let bob_paths = StatePaths::from_home(bob_home.clone());
        let bob_node = state::read_state(Some(bob_home.clone()))
            .expect("bob state")
            .node
            .expect("bob node")
            .node_id;
        let mut server = DirectRuntimeServer::new().expect("server starts");
        let handle = std::thread::spawn(move || {
            server
                .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(900))
                .expect("server tick")
        });
        std::thread::sleep(Duration::from_millis(100));

        let alice_paths = StatePaths::from_home(alice_home.clone());
        let alice_node = state::read_state(Some(alice_home))
            .expect("alice state")
            .node
            .expect("alice node")
            .node_id;
        let message = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            &bob_peer.peer_node_id,
            OpaquePayload::from_bytes(b"private direct message".to_vec()),
        )
        .expect("message valid");
        let sent = send_direct_message_from_paths(&alice_paths, &alice_node, message)
            .expect("message sends");
        let server_report = handle.join().expect("server joins");
        let inbox = messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob")
            .expect("bob inbox reads");
        let log = fs::read_to_string(StatePaths::from_home(bob_home).logs_dir.join("direct.log"))
            .expect("direct log reads");

        assert_eq!(sent.route, "direct-quic");
        assert_eq!(server_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].kind, "message");
        assert!(log.contains("payload=not_observed"));
        assert!(!log.contains("private direct message"));
    }

    fn register_stream_agent(home: &Path, agent_id: &str) {
        let mut registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        registration.capabilities.streams = true;
        agents::submit_registration(Some(home.to_path_buf()), registration).expect("submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("processes");
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
        .expect("policy grants");
    }

    fn free_loopback_endpoint() -> String {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("free UDP port binds");
        let port = socket.local_addr().expect("local addr").port();
        drop(socket);
        format!("quic://127.0.0.1:{port}")
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-direct-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
