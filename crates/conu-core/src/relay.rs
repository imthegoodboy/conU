//! Relay frame contract shared by runtimes and the relay service.
//!
//! The relay can carry peer-encrypted envelope bodies, but it must never expose
//! plaintext payload fields. Frame rendering keeps ciphertext in a dedicated
//! opaque body field and all user-facing surfaces should summarize only
//! metadata.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use native_tls::{HandshakeError, TlsConnector, TlsStream};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_BYTES: usize = 8192;
const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Error produced while parsing or rendering relay frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrameError {
    reason: String,
}

impl RelayFrameError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn io(action: &'static str, source: io::Error) -> Self {
        Self::new(format!("{action}: {source}"))
    }
}

impl fmt::Display for RelayFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid relay frame: {}", self.reason)
    }
}

impl std::error::Error for RelayFrameError {}

/// Runtime-to-relay hello frame.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayHello {
    pub node_id: String,
    pub auth_token: String,
    pub resume_session_id: Option<String>,
}

impl RelayHello {
    pub fn new(
        node_id: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            node_id: validate_identifier(node_id.into(), "node id")?,
            auth_token: validate_token(auth_token.into())?,
            resume_session_id: None,
        })
    }

    pub fn with_resume_session_id(
        mut self,
        resume_session_id: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        self.resume_session_id = Some(validate_session_id(resume_session_id.into())?);
        Ok(self)
    }
}

impl fmt::Debug for RelayHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let resume_session_id = self.resume_session_id.as_ref().map(|_| "<redacted>");
        formatter
            .debug_struct("RelayHello")
            .field("node_id", &self.node_id)
            .field("auth_token", &"<redacted>")
            .field("resume_session_id", &resume_session_id)
            .finish()
    }
}

/// Runtime-to-relay opaque forwarding request.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayForward {
    pub to_node_id: String,
    pub envelope_id: String,
    pub kind: RelayEnvelopeKind,
    pub stream_id: Option<String>,
    pub payload_bytes: usize,
    pub from_agent_id: Option<String>,
    pub to_agent_id: Option<String>,
    pub body: Option<RelayOpaqueBody>,
}

impl RelayForward {
    pub fn new(
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        payload_bytes: usize,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            kind: RelayEnvelopeKind::Message,
            stream_id: None,
            payload_bytes,
            from_agent_id: None,
            to_agent_id: None,
            body: None,
        })
    }

    pub fn with_body(
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload_bytes: usize,
        body: RelayOpaqueBody,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            kind: RelayEnvelopeKind::Message,
            stream_id: None,
            from_agent_id: Some(validate_identifier(from_agent_id.into(), "from agent id")?),
            to_agent_id: Some(validate_identifier(to_agent_id.into(), "to agent id")?),
            payload_bytes,
            body: Some(body),
        })
    }

    pub fn with_stream_body(
        stream_id: impl Into<String>,
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload_bytes: usize,
        body: RelayOpaqueBody,
    ) -> Result<Self, RelayFrameError> {
        let stream_id = validate_identifier(stream_id.into(), "stream id")?;

        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            kind: RelayEnvelopeKind::StreamChunk,
            stream_id: Some(stream_id),
            from_agent_id: Some(validate_identifier(from_agent_id.into(), "from agent id")?),
            to_agent_id: Some(validate_identifier(to_agent_id.into(), "to agent id")?),
            payload_bytes,
            body: Some(body),
        })
    }

    pub fn with_agent_card_body(
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        payload_bytes: usize,
        body: RelayOpaqueBody,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            kind: RelayEnvelopeKind::AgentCard,
            stream_id: None,
            from_agent_id: Some(validate_identifier(from_agent_id.into(), "from agent id")?),
            to_agent_id: Some("conu.discovery".to_string()),
            payload_bytes,
            body: Some(body),
        })
    }

    pub fn with_room_event_body(
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload_bytes: usize,
        body: RelayOpaqueBody,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            kind: RelayEnvelopeKind::RoomEvent,
            stream_id: None,
            from_agent_id: Some(validate_identifier(from_agent_id.into(), "from agent id")?),
            to_agent_id: Some(validate_identifier(to_agent_id.into(), "to agent id")?),
            payload_bytes,
            body: Some(body),
        })
    }
}

impl fmt::Debug for RelayForward {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayForward")
            .field("to_node_id", &self.to_node_id)
            .field("envelope_id", &self.envelope_id)
            .field("kind", &self.kind)
            .field("stream_id", &self.stream_id)
            .field("payload_bytes", &self.payload_bytes)
            .field("from_agent_id", &self.from_agent_id)
            .field("to_agent_id", &self.to_agent_id)
            .field("body", &self.body)
            .finish()
    }
}

/// Opaque envelope kind carried over the blind relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnvelopeKind {
    Message,
    StreamChunk,
    AgentCard,
    RoomEvent,
}

impl RelayEnvelopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::StreamChunk => "stream_chunk",
            Self::AgentCard => "agent_card",
            Self::RoomEvent => "room_event",
        }
    }

    fn from_str(value: &str) -> Result<Self, RelayFrameError> {
        match value {
            "message" => Ok(Self::Message),
            "stream_chunk" => Ok(Self::StreamChunk),
            "agent_card" => Ok(Self::AgentCard),
            "room_event" => Ok(Self::RoomEvent),
            _ => Err(RelayFrameError::new("unsupported relay envelope kind")),
        }
    }
}

/// Peer-encrypted body material carried by the blind relay.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayOpaqueBody {
    pub algorithm: String,
    pub key_id: String,
    pub sender_exchange_public_key_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl RelayOpaqueBody {
    pub fn new(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        sender_exchange_public_key_hex: impl Into<String>,
        nonce_hex: impl Into<String>,
        ciphertext_hex: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            algorithm: validate_algorithm(algorithm.into())?,
            key_id: validate_identifier(key_id.into(), "key id")?,
            sender_exchange_public_key_hex: validate_hex(
                sender_exchange_public_key_hex.into(),
                "sender exchange public key",
            )?,
            nonce_hex: validate_hex(nonce_hex.into(), "nonce")?,
            ciphertext_hex: validate_hex(ciphertext_hex.into(), "body")?,
        })
    }
}

impl fmt::Debug for RelayOpaqueBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayOpaqueBody")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("sender_exchange_public_key_hex", &"<public-key>")
            .field("nonce_hex", &"<nonce>")
            .field("ciphertext_len", &self.ciphertext_hex.len())
            .field("ciphertext", &"<encrypted>")
            .finish()
    }
}

/// Hosted relay admin lifecycle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAdminAction {
    Issue,
    Rotate,
    Revoke,
    Audit,
    Dashboard,
    TenantUpsert,
    TenantRevoke,
    TenantNodeUpsert,
    TenantNodeRevoke,
    TenantAudit,
    AccountSuspend,
    MailboxAudit,
    MailboxPurge,
}

impl RelayAdminAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
            Self::Audit => "audit",
            Self::Dashboard => "dashboard",
            Self::TenantUpsert => "tenant_upsert",
            Self::TenantRevoke => "tenant_revoke",
            Self::TenantNodeUpsert => "tenant_node_upsert",
            Self::TenantNodeRevoke => "tenant_node_revoke",
            Self::TenantAudit => "tenant_audit",
            Self::AccountSuspend => "account_suspend",
            Self::MailboxAudit => "mailbox_audit",
            Self::MailboxPurge => "mailbox_purge",
        }
    }

    fn from_str(value: &str) -> Result<Self, RelayFrameError> {
        match value {
            "issue" => Ok(Self::Issue),
            "rotate" => Ok(Self::Rotate),
            "revoke" => Ok(Self::Revoke),
            "audit" => Ok(Self::Audit),
            "dashboard" => Ok(Self::Dashboard),
            "tenant_upsert" => Ok(Self::TenantUpsert),
            "tenant_revoke" => Ok(Self::TenantRevoke),
            "tenant_node_upsert" => Ok(Self::TenantNodeUpsert),
            "tenant_node_revoke" => Ok(Self::TenantNodeRevoke),
            "tenant_audit" => Ok(Self::TenantAudit),
            "account_suspend" => Ok(Self::AccountSuspend),
            "mailbox_audit" => Ok(Self::MailboxAudit),
            "mailbox_purge" => Ok(Self::MailboxPurge),
            _ => Err(RelayFrameError::new("unsupported relay admin action")),
        }
    }
}

/// Authenticated hosted-relay admin request.
///
/// Issue and rotate requests carry only token hash metadata. The raw relay
/// credential token is generated and stored by the admin client, not sent to or
/// stored by the relay service.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayAdminRequest {
    pub action: RelayAdminAction,
    pub admin_token: String,
    pub account_id: Option<String>,
    pub node_id: Option<String>,
    pub token_sha256_hex: Option<String>,
    pub token_length: Option<usize>,
    pub expires_at_unix: Option<u64>,
    pub retention_ttl_seconds: Option<u64>,
    pub mailbox_purge_dry_run: Option<bool>,
    pub tenant_messages: Option<bool>,
    pub tenant_streams: Option<bool>,
    pub tenant_rooms: Option<bool>,
    pub tenant_files: Option<bool>,
    pub tenant_mailbox: Option<bool>,
    pub signing_key_id: Option<String>,
    pub exchange_key_id: Option<String>,
}

impl RelayAdminRequest {
    pub fn issue(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
        node_id: impl Into<String>,
        token_sha256_hex: impl Into<String>,
        token_length: usize,
        expires_at_unix: Option<u64>,
    ) -> Result<Self, RelayFrameError> {
        Self::credential_update(
            RelayAdminAction::Issue,
            admin_token,
            account_id,
            node_id,
            token_sha256_hex,
            token_length,
            expires_at_unix,
        )
    }

    pub fn rotate(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
        node_id: impl Into<String>,
        token_sha256_hex: impl Into<String>,
        token_length: usize,
        expires_at_unix: Option<u64>,
    ) -> Result<Self, RelayFrameError> {
        Self::credential_update(
            RelayAdminAction::Rotate,
            admin_token,
            account_id,
            node_id,
            token_sha256_hex,
            token_length,
            expires_at_unix,
        )
    }

    pub fn revoke(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::Revoke,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: Some(validate_identifier(node_id.into(), "node id")?),
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn audit(
        admin_token: impl Into<String>,
        account_id: Option<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::Audit,
            admin_token: validate_token(admin_token.into())?,
            account_id: account_id
                .map(|value| validate_identifier(value, "account id"))
                .transpose()?,
            node_id: None,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn dashboard(
        admin_token: impl Into<String>,
        account_id: Option<String>,
        node_id: Option<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::Dashboard,
            admin_token: validate_token(admin_token.into())?,
            account_id: account_id
                .map(|value| validate_identifier(value, "account id"))
                .transpose()?,
            node_id: node_id
                .map(|value| validate_identifier(value, "node id"))
                .transpose()?,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn mailbox_audit(
        admin_token: impl Into<String>,
        node_id: Option<String>,
        retention_ttl_seconds: Option<u64>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::MailboxAudit,
            admin_token: validate_token(admin_token.into())?,
            account_id: None,
            node_id: node_id
                .map(|value| validate_identifier(value, "node id"))
                .transpose()?,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: retention_ttl_seconds
                .map(validate_positive_seconds)
                .transpose()?,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn mailbox_purge(
        admin_token: impl Into<String>,
        node_id: Option<String>,
        retention_ttl_seconds: u64,
        dry_run: bool,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::MailboxPurge,
            admin_token: validate_token(admin_token.into())?,
            account_id: None,
            node_id: node_id
                .map(|value| validate_identifier(value, "node id"))
                .transpose()?,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: Some(validate_positive_seconds(retention_ttl_seconds)?),
            mailbox_purge_dry_run: Some(dry_run),
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn tenant_upsert(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::TenantUpsert,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: None,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn tenant_revoke(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::TenantRevoke,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: None,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tenant_node_upsert(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
        node_id: impl Into<String>,
        messages: bool,
        streams: bool,
        rooms: bool,
        files: bool,
        mailbox: bool,
        signing_key_id: Option<String>,
        exchange_key_id: Option<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::TenantNodeUpsert,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: Some(validate_identifier(node_id.into(), "node id")?),
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: Some(messages),
            tenant_streams: Some(streams),
            tenant_rooms: Some(rooms),
            tenant_files: Some(files),
            tenant_mailbox: Some(mailbox),
            signing_key_id: signing_key_id
                .map(|value| validate_identifier(value, "signing key id"))
                .transpose()?,
            exchange_key_id: exchange_key_id
                .map(|value| validate_identifier(value, "exchange key id"))
                .transpose()?,
        })
    }

    pub fn tenant_node_revoke(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::TenantNodeRevoke,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: Some(validate_identifier(node_id.into(), "node id")?),
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn tenant_audit(
        admin_token: impl Into<String>,
        account_id: Option<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::TenantAudit,
            admin_token: validate_token(admin_token.into())?,
            account_id: account_id
                .map(|value| validate_identifier(value, "account id"))
                .transpose()?,
            node_id: None,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    pub fn account_suspend(
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action: RelayAdminAction::AccountSuspend,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: None,
            token_sha256_hex: None,
            token_length: None,
            expires_at_unix: None,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }

    fn credential_update(
        action: RelayAdminAction,
        admin_token: impl Into<String>,
        account_id: impl Into<String>,
        node_id: impl Into<String>,
        token_sha256_hex: impl Into<String>,
        token_length: usize,
        expires_at_unix: Option<u64>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            action,
            admin_token: validate_token(admin_token.into())?,
            account_id: Some(validate_identifier(account_id.into(), "account id")?),
            node_id: Some(validate_identifier(node_id.into(), "node id")?),
            token_sha256_hex: Some(validate_fixed_hex(
                token_sha256_hex.into(),
                "token sha256",
                64,
            )?),
            token_length: Some(validate_token_length(token_length)?),
            expires_at_unix,
            retention_ttl_seconds: None,
            mailbox_purge_dry_run: None,
            tenant_messages: None,
            tenant_streams: None,
            tenant_rooms: None,
            tenant_files: None,
            tenant_mailbox: None,
            signing_key_id: None,
            exchange_key_id: None,
        })
    }
}

impl fmt::Debug for RelayAdminRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAdminRequest")
            .field("action", &self.action)
            .field("admin_token", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("node_id", &self.node_id)
            .field(
                "token_sha256_hex",
                &self.token_sha256_hex.as_ref().map(|_| "<redacted>"),
            )
            .field("token_length", &self.token_length)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("retention_ttl_seconds", &self.retention_ttl_seconds)
            .field("mailbox_purge_dry_run", &self.mailbox_purge_dry_run)
            .field("tenant_messages", &self.tenant_messages)
            .field("tenant_streams", &self.tenant_streams)
            .field("tenant_rooms", &self.tenant_rooms)
            .field("tenant_files", &self.tenant_files)
            .field("tenant_mailbox", &self.tenant_mailbox)
            .field("signing_key_id", &self.signing_key_id)
            .field("exchange_key_id", &self.exchange_key_id)
            .finish()
    }
}

/// Metadata-only hosted relay admin result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAdminResult {
    pub action: RelayAdminAction,
    pub status: String,
    pub account_id: Option<String>,
    pub node_id: Option<String>,
    pub credentials: usize,
    pub active: usize,
    pub revoked: usize,
    pub expired: usize,
    pub accounts: usize,
    pub token_length: Option<usize>,
    pub expires_at_unix: Option<u64>,
    pub tenants: usize,
    pub active_tenants: usize,
    pub revoked_tenants: usize,
    pub nodes: usize,
    pub active_nodes: usize,
    pub revoked_nodes: usize,
    pub tenant_policies: usize,
    pub accounting_records: usize,
    pub accounting_window_started_unix: Option<u64>,
    pub sessions_authenticated: u64,
    pub sessions_resumed: u64,
    pub envelopes_sent: u64,
    pub bytes_sent: u64,
    pub envelopes_received: u64,
    pub bytes_received: u64,
    pub envelopes_mailboxed: u64,
    pub bytes_mailboxed: u64,
    pub abuse_records: usize,
    pub abuse_window_started_unix: Option<u64>,
    pub admin_unauthorized: u64,
    pub admin_failed: u64,
    pub unauthorized_sessions: u64,
    pub credential_denied_sessions: u64,
    pub tenant_denied_sessions: u64,
    pub rate_limited_sessions: u64,
    pub session_expired: u64,
    pub quota_denied_forwards: u64,
    pub undelivered_forwards: u64,
    pub mailbox_rejected_forwards: u64,
    pub malformed_client_frames: u64,
    pub retention_ttl_seconds: Option<u64>,
    pub mailbox_nodes: usize,
    pub mailbox_records: usize,
    pub mailbox_invalid_records: usize,
    pub mailbox_bytes: u64,
    pub mailbox_oldest_queued_unix_millis: Option<u64>,
    pub mailbox_newest_queued_unix_millis: Option<u64>,
    pub mailbox_expired_records: Option<u64>,
    pub mailbox_expired_bytes: Option<u64>,
    pub mailbox_dry_run: Option<bool>,
    pub mailbox_confirmed: Option<bool>,
    pub mailbox_purged_records: Option<u64>,
    pub mailbox_purged_bytes: Option<u64>,
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

impl RelayAdminResult {
    pub fn new(action: RelayAdminAction, status: impl Into<String>) -> Self {
        Self {
            action,
            status: status.into(),
            account_id: None,
            node_id: None,
            credentials: 0,
            active: 0,
            revoked: 0,
            expired: 0,
            accounts: 0,
            token_length: None,
            expires_at_unix: None,
            tenants: 0,
            active_tenants: 0,
            revoked_tenants: 0,
            nodes: 0,
            active_nodes: 0,
            revoked_nodes: 0,
            tenant_policies: 0,
            accounting_records: 0,
            accounting_window_started_unix: None,
            sessions_authenticated: 0,
            sessions_resumed: 0,
            envelopes_sent: 0,
            bytes_sent: 0,
            envelopes_received: 0,
            bytes_received: 0,
            envelopes_mailboxed: 0,
            bytes_mailboxed: 0,
            abuse_records: 0,
            abuse_window_started_unix: None,
            admin_unauthorized: 0,
            admin_failed: 0,
            unauthorized_sessions: 0,
            credential_denied_sessions: 0,
            tenant_denied_sessions: 0,
            rate_limited_sessions: 0,
            session_expired: 0,
            quota_denied_forwards: 0,
            undelivered_forwards: 0,
            mailbox_rejected_forwards: 0,
            malformed_client_frames: 0,
            retention_ttl_seconds: None,
            mailbox_nodes: 0,
            mailbox_records: 0,
            mailbox_invalid_records: 0,
            mailbox_bytes: 0,
            mailbox_oldest_queued_unix_millis: None,
            mailbox_newest_queued_unix_millis: None,
            mailbox_expired_records: None,
            mailbox_expired_bytes: None,
            mailbox_dry_run: None,
            mailbox_confirmed: None,
            mailbox_purged_records: None,
            mailbox_purged_bytes: None,
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
        }
    }
}

/// Client frames a runtime can send to the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayClientFrame {
    Hello(RelayHello),
    Forward(Box<RelayForward>),
    Admin(Box<RelayAdminRequest>),
    Ping,
}

/// Relay-forwarded opaque envelope metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayForwarded {
    pub from_node_id: String,
    pub to_node_id: String,
    pub envelope_id: String,
    pub kind: RelayEnvelopeKind,
    pub stream_id: Option<String>,
    pub payload_bytes: usize,
    pub from_agent_id: Option<String>,
    pub to_agent_id: Option<String>,
    pub body: Option<RelayOpaqueBody>,
}

/// Relay frames sent back to runtimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayServerFrame {
    Welcome {
        session_id: String,
        resumed: bool,
    },
    Forwarded(Box<RelayForwarded>),
    Sent {
        to_node_id: String,
        envelope_id: String,
        payload_bytes: usize,
    },
    Undelivered {
        to_node_id: String,
        envelope_id: String,
        reason: String,
    },
    AdminResult(Box<RelayAdminResult>),
    Pong,
    Error {
        reason: String,
    },
}

/// Render a client frame as a compact metadata line.
pub fn render_client_frame(frame: &RelayClientFrame) -> String {
    match frame {
        RelayClientFrame::Hello(hello) => {
            let mut line = format!("HELLO node={} token={}", hello.node_id, hello.auth_token);
            if let Some(resume_session_id) = &hello.resume_session_id {
                line.push_str(&format!(" resume={resume_session_id}"));
            }
            line.push_str(" payload=not_observed");
            line
        }
        RelayClientFrame::Forward(forward) => {
            render_forward_line("FORWARD", None, forward.as_ref())
        }
        RelayClientFrame::Admin(request) => render_admin_request_line(request.as_ref()),
        RelayClientFrame::Ping => "PING payload=not_observed".to_string(),
    }
}

/// Parse a client frame line received by the relay.
pub fn parse_client_frame(line: &str) -> Result<RelayClientFrame, RelayFrameError> {
    let (kind, values) = parse_frame_values(line)?;
    if values.contains_key("payload_hex") || values.contains_key("payload_text") {
        return Err(RelayFrameError::new(
            "relay frame must not include plaintext payload fields",
        ));
    }

    match kind {
        "HELLO" => {
            let mut hello =
                RelayHello::new(required(&values, "node")?, required(&values, "token")?)?;
            if let Some(resume_session_id) = values.get("resume") {
                hello = hello.with_resume_session_id(resume_session_id.clone())?;
            }
            Ok(RelayClientFrame::Hello(hello))
        }
        "FORWARD" => Ok(RelayClientFrame::Forward(Box::new(
            RelayForward::new(
                required(&values, "to")?,
                required(&values, "envelope")?,
                parse_usize(&required(&values, "bytes")?)?,
            )?
            .with_kind_and_stream_from_values(&values)?
            .with_optional_body(&values)?,
        ))),
        "ADMIN" => Ok(RelayClientFrame::Admin(Box::new(parse_admin_request(
            &values,
        )?))),
        "PING" => Ok(RelayClientFrame::Ping),
        _ => Err(RelayFrameError::new("unsupported client frame type")),
    }
}

/// Render a relay server frame.
pub fn render_server_frame(frame: &RelayServerFrame) -> String {
    match frame {
        RelayServerFrame::Welcome {
            session_id,
            resumed,
        } => format!(
            "WELCOME session={} resumed={} payload=not_observed",
            session_id, resumed
        ),
        RelayServerFrame::Forwarded(forwarded) => render_forwarded_line(forwarded.as_ref()),
        RelayServerFrame::Sent {
            to_node_id,
            envelope_id,
            payload_bytes,
        } => format!(
            "SENT to={} envelope={} bytes={} payload=not_observed",
            to_node_id, envelope_id, payload_bytes
        ),
        RelayServerFrame::Undelivered {
            to_node_id,
            envelope_id,
            reason,
        } => format!(
            "UNDELIVERED to={} envelope={} reason={} payload=not_observed",
            to_node_id,
            envelope_id,
            sanitize_reason(reason)
        ),
        RelayServerFrame::AdminResult(result) => render_admin_result_line(result),
        RelayServerFrame::Pong => "PONG payload=not_observed".to_string(),
        RelayServerFrame::Error { reason } => {
            format!(
                "ERROR reason={} payload=not_observed",
                sanitize_reason(reason)
            )
        }
    }
}

/// Parse a relay server frame line received by a runtime.
pub fn parse_server_frame(line: &str) -> Result<RelayServerFrame, RelayFrameError> {
    let (kind, values) = parse_frame_values(line)?;
    if values.contains_key("payload_hex") || values.contains_key("payload_text") {
        return Err(RelayFrameError::new(
            "relay frame must not include plaintext payload fields",
        ));
    }

    match kind {
        "WELCOME" => Ok(RelayServerFrame::Welcome {
            session_id: validate_session_id(required(&values, "session")?)?,
            resumed: optional_bool(&values, "resumed")?.unwrap_or(false),
        }),
        "ENVELOPE" => {
            let body = optional_body(&values)?;
            let kind = relay_kind_from_values(&values)?;
            let stream_id = optional_identifier(&values, "stream", "stream id")?;
            validate_kind_stream(kind, stream_id.as_deref())?;
            Ok(RelayServerFrame::Forwarded(Box::new(RelayForwarded {
                from_node_id: validate_identifier(required(&values, "from")?, "from node id")?,
                to_node_id: validate_identifier(required(&values, "to")?, "to node id")?,
                envelope_id: validate_identifier(required(&values, "envelope")?, "envelope id")?,
                kind,
                stream_id,
                payload_bytes: parse_usize(&required(&values, "bytes")?)?,
                from_agent_id: optional_identifier(&values, "from_agent", "from agent id")?,
                to_agent_id: optional_identifier(&values, "to_agent", "to agent id")?,
                body,
            })))
        }
        "SENT" => Ok(RelayServerFrame::Sent {
            to_node_id: validate_identifier(required(&values, "to")?, "to node id")?,
            envelope_id: validate_identifier(required(&values, "envelope")?, "envelope id")?,
            payload_bytes: parse_usize(&required(&values, "bytes")?)?,
        }),
        "UNDELIVERED" => Ok(RelayServerFrame::Undelivered {
            to_node_id: validate_identifier(required(&values, "to")?, "to node id")?,
            envelope_id: validate_identifier(required(&values, "envelope")?, "envelope id")?,
            reason: required(&values, "reason")?,
        }),
        "ADMIN_RESULT" => Ok(RelayServerFrame::AdminResult(Box::new(parse_admin_result(
            &values,
        )?))),
        "PONG" => Ok(RelayServerFrame::Pong),
        "ERROR" => Ok(RelayServerFrame::Error {
            reason: required(&values, "reason")?,
        }),
        _ => Err(RelayFrameError::new("unsupported server frame type")),
    }
}

trait RelayStream: Read + Write {}

impl<T> RelayStream for T where T: Read + Write {}

/// Minimal WebSocket client for runtime-to-relay sync.
pub struct RelayWebSocketClient {
    stream: Box<dyn RelayStream>,
}

impl fmt::Debug for RelayWebSocketClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayWebSocketClient")
            .field("stream", &"<websocket>")
            .finish()
    }
}

impl RelayWebSocketClient {
    pub fn connect(endpoint: &str, timeout: Duration) -> Result<Self, RelayFrameError> {
        let parsed = ParsedEndpoint::parse(endpoint)?;
        let stream = TcpStream::connect((&parsed.host[..], parsed.port))
            .map_err(|error| RelayFrameError::io("connect relay endpoint", error))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| RelayFrameError::io("configure relay read timeout", error))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| RelayFrameError::io("configure relay write timeout", error))?;
        let mut stream: Box<dyn RelayStream> = match parsed.scheme {
            RelayScheme::Ws => Box::new(stream),
            RelayScheme::Wss => Box::new(connect_tls(&parsed.host, stream)?),
        };
        perform_client_handshake(stream.as_mut(), &parsed)?;

        Ok(Self { stream })
    }

    pub fn send(&mut self, frame: &RelayClientFrame) -> Result<(), RelayFrameError> {
        write_client_text_frame(self.stream.as_mut(), &render_client_frame(frame))
    }

    pub fn read(&mut self) -> Result<Option<RelayServerFrame>, RelayFrameError> {
        let Some(text) = read_server_text_frame(self.stream.as_mut())? else {
            return Ok(None);
        };
        parse_server_frame(&text).map(Some)
    }
}

impl RelayForward {
    fn with_kind_and_stream_from_values(
        mut self,
        values: &HashMap<String, String>,
    ) -> Result<Self, RelayFrameError> {
        self.kind = relay_kind_from_values(values)?;
        self.stream_id = optional_identifier(values, "stream", "stream id")?;
        validate_kind_stream(self.kind, self.stream_id.as_deref())?;
        Ok(self)
    }

    fn with_optional_body(
        mut self,
        values: &HashMap<String, String>,
    ) -> Result<Self, RelayFrameError> {
        self.body = optional_body(values)?;
        if self.body.is_some() {
            self.from_agent_id = Some(validate_identifier(
                required(values, "from_agent")?,
                "from agent id",
            )?);
            self.to_agent_id = Some(validate_identifier(
                required(values, "to_agent")?,
                "to agent id",
            )?);
        }
        Ok(self)
    }
}

fn render_forward_line(kind: &str, from_node: Option<&str>, forward: &RelayForward) -> String {
    let mut line = match from_node {
        Some(from_node) => format!(
            "{kind} from={} to={} envelope={} kind={} bytes={}",
            from_node,
            forward.to_node_id,
            forward.envelope_id,
            forward.kind.as_str(),
            forward.payload_bytes
        ),
        None => format!(
            "{kind} to={} envelope={} kind={} bytes={}",
            forward.to_node_id,
            forward.envelope_id,
            forward.kind.as_str(),
            forward.payload_bytes
        ),
    };

    append_forward_body(
        &mut line,
        forward.stream_id.as_deref(),
        forward.from_agent_id.as_deref(),
        forward.to_agent_id.as_deref(),
        forward.body.as_ref(),
    );
    line
}

fn render_forwarded_line(forwarded: &RelayForwarded) -> String {
    let mut line = format!(
        "ENVELOPE from={} to={} envelope={} kind={} bytes={}",
        forwarded.from_node_id,
        forwarded.to_node_id,
        forwarded.envelope_id,
        forwarded.kind.as_str(),
        forwarded.payload_bytes
    );
    append_forward_body(
        &mut line,
        forwarded.stream_id.as_deref(),
        forwarded.from_agent_id.as_deref(),
        forwarded.to_agent_id.as_deref(),
        forwarded.body.as_ref(),
    );
    line
}

fn append_forward_body(
    line: &mut String,
    stream_id: Option<&str>,
    from_agent_id: Option<&str>,
    to_agent_id: Option<&str>,
    body: Option<&RelayOpaqueBody>,
) {
    if let Some(stream_id) = stream_id {
        line.push_str(&format!(" stream={stream_id}"));
    }

    if let Some(body) = body {
        line.push_str(&format!(
            " from_agent={} to_agent={} cipher={} key={} sender_key={} nonce={} body={} payload=peer_encrypted",
            from_agent_id.unwrap_or("unknown"),
            to_agent_id.unwrap_or("unknown"),
            body.algorithm,
            body.key_id,
            body.sender_exchange_public_key_hex,
            body.nonce_hex,
            body.ciphertext_hex
        ));
    } else {
        line.push_str(" payload=opaque");
    }
}

fn render_admin_request_line(request: &RelayAdminRequest) -> String {
    let mut line = format!(
        "ADMIN action={} admin_token={}",
        request.action.as_str(),
        request.admin_token
    );
    if let Some(account_id) = &request.account_id {
        line.push_str(&format!(" account={account_id}"));
    }
    if let Some(node_id) = &request.node_id {
        line.push_str(&format!(" node={node_id}"));
    }
    if let Some(token_sha256_hex) = &request.token_sha256_hex {
        line.push_str(&format!(" token_sha256={token_sha256_hex}"));
    }
    if let Some(token_length) = request.token_length {
        line.push_str(&format!(" token_length={token_length}"));
    }
    if let Some(expires_at_unix) = request.expires_at_unix {
        line.push_str(&format!(" expires={expires_at_unix}"));
    }
    if let Some(retention_ttl_seconds) = request.retention_ttl_seconds {
        line.push_str(&format!(" ttl_seconds={retention_ttl_seconds}"));
    }
    if let Some(dry_run) = request.mailbox_purge_dry_run {
        line.push_str(&format!(" dry_run={dry_run}"));
    }
    if let Some(messages) = request.tenant_messages {
        line.push_str(&format!(" messages={messages}"));
    }
    if let Some(streams) = request.tenant_streams {
        line.push_str(&format!(" streams={streams}"));
    }
    if let Some(rooms) = request.tenant_rooms {
        line.push_str(&format!(" rooms={rooms}"));
    }
    if let Some(files) = request.tenant_files {
        line.push_str(&format!(" files={files}"));
    }
    if let Some(mailbox) = request.tenant_mailbox {
        line.push_str(&format!(" mailbox={mailbox}"));
    }
    if let Some(signing_key_id) = &request.signing_key_id {
        line.push_str(&format!(" signing_key_id={signing_key_id}"));
    }
    if let Some(exchange_key_id) = &request.exchange_key_id {
        line.push_str(&format!(" exchange_key_id={exchange_key_id}"));
    }
    line.push_str(" token_displayed=false payload=not_observed");
    line
}

fn parse_admin_request(
    values: &HashMap<String, String>,
) -> Result<RelayAdminRequest, RelayFrameError> {
    let action = RelayAdminAction::from_str(&required(values, "action")?)?;
    match action {
        RelayAdminAction::Issue => RelayAdminRequest::issue(
            required(values, "admin_token")?,
            required(values, "account")?,
            required(values, "node")?,
            required(values, "token_sha256")?,
            parse_usize(&required(values, "token_length")?)?,
            optional_u64(values, "expires")?,
        ),
        RelayAdminAction::Rotate => RelayAdminRequest::rotate(
            required(values, "admin_token")?,
            required(values, "account")?,
            required(values, "node")?,
            required(values, "token_sha256")?,
            parse_usize(&required(values, "token_length")?)?,
            optional_u64(values, "expires")?,
        ),
        RelayAdminAction::Revoke => RelayAdminRequest::revoke(
            required(values, "admin_token")?,
            required(values, "account")?,
            required(values, "node")?,
        ),
        RelayAdminAction::Audit => RelayAdminRequest::audit(
            required(values, "admin_token")?,
            values.get("account").cloned(),
        ),
        RelayAdminAction::Dashboard => RelayAdminRequest::dashboard(
            required(values, "admin_token")?,
            values.get("account").cloned(),
            values.get("node").cloned(),
        ),
        RelayAdminAction::TenantUpsert => RelayAdminRequest::tenant_upsert(
            required(values, "admin_token")?,
            required(values, "account")?,
        ),
        RelayAdminAction::TenantRevoke => RelayAdminRequest::tenant_revoke(
            required(values, "admin_token")?,
            required(values, "account")?,
        ),
        RelayAdminAction::TenantNodeUpsert => RelayAdminRequest::tenant_node_upsert(
            required(values, "admin_token")?,
            required(values, "account")?,
            required(values, "node")?,
            required_bool(values, "messages")?,
            required_bool(values, "streams")?,
            required_bool(values, "rooms")?,
            required_bool(values, "files")?,
            required_bool(values, "mailbox")?,
            values.get("signing_key_id").cloned(),
            values.get("exchange_key_id").cloned(),
        ),
        RelayAdminAction::TenantNodeRevoke => RelayAdminRequest::tenant_node_revoke(
            required(values, "admin_token")?,
            required(values, "account")?,
            required(values, "node")?,
        ),
        RelayAdminAction::TenantAudit => RelayAdminRequest::tenant_audit(
            required(values, "admin_token")?,
            values.get("account").cloned(),
        ),
        RelayAdminAction::AccountSuspend => RelayAdminRequest::account_suspend(
            required(values, "admin_token")?,
            required(values, "account")?,
        ),
        RelayAdminAction::MailboxAudit => RelayAdminRequest::mailbox_audit(
            required(values, "admin_token")?,
            values.get("node").cloned(),
            optional_u64(values, "ttl_seconds")?,
        ),
        RelayAdminAction::MailboxPurge => RelayAdminRequest::mailbox_purge(
            required(values, "admin_token")?,
            values.get("node").cloned(),
            optional_u64(values, "ttl_seconds")?
                .ok_or_else(|| RelayFrameError::new("ttl_seconds is required"))?,
            required_bool(values, "dry_run")?,
        ),
    }
}

fn render_admin_result_line(result: &RelayAdminResult) -> String {
    let mut line = format!(
        "ADMIN_RESULT action={} status={} credentials={} active={} revoked={} expired={} accounts={}",
        result.action.as_str(),
        sanitize_reason(&result.status),
        result.credentials,
        result.active,
        result.revoked,
        result.expired,
        result.accounts
    );
    if let Some(account_id) = &result.account_id {
        line.push_str(&format!(" account={account_id}"));
    }
    if let Some(node_id) = &result.node_id {
        line.push_str(&format!(" node={node_id}"));
    }
    if let Some(token_length) = result.token_length {
        line.push_str(&format!(" token_length={token_length}"));
    }
    if let Some(expires_at_unix) = result.expires_at_unix {
        line.push_str(&format!(" expires={expires_at_unix}"));
    }
    if matches!(
        result.action,
        RelayAdminAction::Dashboard
            | RelayAdminAction::TenantUpsert
            | RelayAdminAction::TenantRevoke
            | RelayAdminAction::TenantNodeUpsert
            | RelayAdminAction::TenantNodeRevoke
            | RelayAdminAction::TenantAudit
            | RelayAdminAction::AccountSuspend
    ) {
        line.push_str(&format!(
            " tenants={} active_tenants={} revoked_tenants={} nodes={} active_nodes={} revoked_nodes={} tenant_policies={}",
            result.tenants,
            result.active_tenants,
            result.revoked_tenants,
            result.nodes,
            result.active_nodes,
            result.revoked_nodes,
            result.tenant_policies
        ));
    }
    if result.action == RelayAdminAction::Dashboard {
        line.push_str(&format!(
            " accounting_records={} sessions_authenticated={} sessions_resumed={} envelopes_sent={} bytes_sent={} envelopes_received={} bytes_received={} envelopes_mailboxed={} bytes_mailboxed={}",
            result.accounting_records,
            result.sessions_authenticated,
            result.sessions_resumed,
            result.envelopes_sent,
            result.bytes_sent,
            result.envelopes_received,
            result.bytes_received,
            result.envelopes_mailboxed,
            result.bytes_mailboxed
        ));
        if let Some(window_started_unix) = result.accounting_window_started_unix {
            line.push_str(&format!(" accounting_window_started={window_started_unix}"));
        }
        line.push_str(&format!(
            " abuse_records={} admin_unauthorized={} admin_failed={} unauthorized_sessions={} credential_denied_sessions={} tenant_denied_sessions={} rate_limited_sessions={} session_expired={} quota_denied_forwards={} undelivered_forwards={} mailbox_rejected_forwards={} malformed_client_frames={}",
            result.abuse_records,
            result.admin_unauthorized,
            result.admin_failed,
            result.unauthorized_sessions,
            result.credential_denied_sessions,
            result.tenant_denied_sessions,
            result.rate_limited_sessions,
            result.session_expired,
            result.quota_denied_forwards,
            result.undelivered_forwards,
            result.mailbox_rejected_forwards,
            result.malformed_client_frames
        ));
        if let Some(window_started_unix) = result.abuse_window_started_unix {
            line.push_str(&format!(" abuse_window_started={window_started_unix}"));
        }
    }
    if matches!(
        result.action,
        RelayAdminAction::MailboxAudit | RelayAdminAction::MailboxPurge
    ) {
        line.push_str(&format!(
            " mailbox_nodes={} mailbox_records={} mailbox_invalid_records={} mailbox_bytes={}",
            result.mailbox_nodes,
            result.mailbox_records,
            result.mailbox_invalid_records,
            result.mailbox_bytes
        ));
        if let Some(retention_ttl_seconds) = result.retention_ttl_seconds {
            line.push_str(&format!(" ttl_seconds={retention_ttl_seconds}"));
        }
        if let Some(oldest_queued_unix_millis) = result.mailbox_oldest_queued_unix_millis {
            line.push_str(&format!(
                " mailbox_oldest_queued_unix_millis={oldest_queued_unix_millis}"
            ));
        }
        if let Some(newest_queued_unix_millis) = result.mailbox_newest_queued_unix_millis {
            line.push_str(&format!(
                " mailbox_newest_queued_unix_millis={newest_queued_unix_millis}"
            ));
        }
        if let Some(expired_records) = result.mailbox_expired_records {
            line.push_str(&format!(" mailbox_expired_records={expired_records}"));
        }
        if let Some(expired_bytes) = result.mailbox_expired_bytes {
            line.push_str(&format!(" mailbox_expired_bytes={expired_bytes}"));
        }
        if let Some(dry_run) = result.mailbox_dry_run {
            line.push_str(&format!(" dry_run={dry_run}"));
        }
        if let Some(confirmed) = result.mailbox_confirmed {
            line.push_str(&format!(" confirmed={confirmed}"));
        }
        if let Some(purged_records) = result.mailbox_purged_records {
            line.push_str(&format!(" mailbox_purged_records={purged_records}"));
        }
        if let Some(purged_bytes) = result.mailbox_purged_bytes {
            line.push_str(&format!(" mailbox_purged_bytes={purged_bytes}"));
        }
    }
    line.push_str(&format!(
        " payload_displayed={} token_displayed={} token_hash_displayed={} key_material_displayed={} session_id_displayed={} ciphertext_displayed={} contents_displayed={} payload=not_observed",
        result.payload_displayed,
        result.token_displayed,
        result.token_hash_displayed,
        result.key_material_displayed,
        result.session_id_displayed,
        result.ciphertext_displayed,
        result.contents_displayed
    ));
    line
}

fn parse_admin_result(
    values: &HashMap<String, String>,
) -> Result<RelayAdminResult, RelayFrameError> {
    Ok(RelayAdminResult {
        action: RelayAdminAction::from_str(&required(values, "action")?)?,
        status: required(values, "status")?,
        account_id: optional_identifier(values, "account", "account id")?,
        node_id: optional_identifier(values, "node", "node id")?,
        credentials: parse_usize(&required(values, "credentials")?)?,
        active: parse_usize(&required(values, "active")?)?,
        revoked: parse_usize(&required(values, "revoked")?)?,
        expired: parse_usize(&required(values, "expired")?)?,
        accounts: parse_usize(&required(values, "accounts")?)?,
        token_length: optional_usize(values, "token_length")?,
        expires_at_unix: optional_u64(values, "expires")?,
        tenants: optional_count(values, "tenants")?,
        active_tenants: optional_count(values, "active_tenants")?,
        revoked_tenants: optional_count(values, "revoked_tenants")?,
        nodes: optional_count(values, "nodes")?,
        active_nodes: optional_count(values, "active_nodes")?,
        revoked_nodes: optional_count(values, "revoked_nodes")?,
        tenant_policies: optional_count(values, "tenant_policies")?,
        accounting_records: optional_count(values, "accounting_records")?,
        accounting_window_started_unix: optional_u64(values, "accounting_window_started")?,
        sessions_authenticated: optional_u64(values, "sessions_authenticated")?.unwrap_or(0),
        sessions_resumed: optional_u64(values, "sessions_resumed")?.unwrap_or(0),
        envelopes_sent: optional_u64(values, "envelopes_sent")?.unwrap_or(0),
        bytes_sent: optional_u64(values, "bytes_sent")?.unwrap_or(0),
        envelopes_received: optional_u64(values, "envelopes_received")?.unwrap_or(0),
        bytes_received: optional_u64(values, "bytes_received")?.unwrap_or(0),
        envelopes_mailboxed: optional_u64(values, "envelopes_mailboxed")?.unwrap_or(0),
        bytes_mailboxed: optional_u64(values, "bytes_mailboxed")?.unwrap_or(0),
        abuse_records: optional_count(values, "abuse_records")?,
        abuse_window_started_unix: optional_u64(values, "abuse_window_started")?,
        admin_unauthorized: optional_u64(values, "admin_unauthorized")?.unwrap_or(0),
        admin_failed: optional_u64(values, "admin_failed")?.unwrap_or(0),
        unauthorized_sessions: optional_u64(values, "unauthorized_sessions")?.unwrap_or(0),
        credential_denied_sessions: optional_u64(values, "credential_denied_sessions")?
            .unwrap_or(0),
        tenant_denied_sessions: optional_u64(values, "tenant_denied_sessions")?.unwrap_or(0),
        rate_limited_sessions: optional_u64(values, "rate_limited_sessions")?.unwrap_or(0),
        session_expired: optional_u64(values, "session_expired")?.unwrap_or(0),
        quota_denied_forwards: optional_u64(values, "quota_denied_forwards")?.unwrap_or(0),
        undelivered_forwards: optional_u64(values, "undelivered_forwards")?.unwrap_or(0),
        mailbox_rejected_forwards: optional_u64(values, "mailbox_rejected_forwards")?.unwrap_or(0),
        malformed_client_frames: optional_u64(values, "malformed_client_frames")?.unwrap_or(0),
        retention_ttl_seconds: optional_u64(values, "ttl_seconds")?,
        mailbox_nodes: optional_count(values, "mailbox_nodes")?,
        mailbox_records: optional_count(values, "mailbox_records")?,
        mailbox_invalid_records: optional_count(values, "mailbox_invalid_records")?,
        mailbox_bytes: optional_u64(values, "mailbox_bytes")?.unwrap_or(0),
        mailbox_oldest_queued_unix_millis: optional_u64(
            values,
            "mailbox_oldest_queued_unix_millis",
        )?,
        mailbox_newest_queued_unix_millis: optional_u64(
            values,
            "mailbox_newest_queued_unix_millis",
        )?,
        mailbox_expired_records: optional_u64(values, "mailbox_expired_records")?,
        mailbox_expired_bytes: optional_u64(values, "mailbox_expired_bytes")?,
        mailbox_dry_run: optional_bool(values, "dry_run")?,
        mailbox_confirmed: optional_bool(values, "confirmed")?,
        mailbox_purged_records: optional_u64(values, "mailbox_purged_records")?,
        mailbox_purged_bytes: optional_u64(values, "mailbox_purged_bytes")?,
        payload_displayed: optional_bool(values, "payload_displayed")?.unwrap_or(false),
        token_displayed: optional_bool(values, "token_displayed")?.unwrap_or(false),
        token_hash_displayed: optional_bool(values, "token_hash_displayed")?.unwrap_or(false),
        key_material_displayed: optional_bool(values, "key_material_displayed")?.unwrap_or(false),
        session_id_displayed: optional_bool(values, "session_id_displayed")?.unwrap_or(false),
        ciphertext_displayed: optional_bool(values, "ciphertext_displayed")?.unwrap_or(false),
        contents_displayed: optional_bool(values, "contents_displayed")?.unwrap_or(false),
    })
}

fn relay_kind_from_values(
    values: &HashMap<String, String>,
) -> Result<RelayEnvelopeKind, RelayFrameError> {
    values
        .get("kind")
        .map(String::as_str)
        .map(RelayEnvelopeKind::from_str)
        .unwrap_or(Ok(RelayEnvelopeKind::Message))
}

fn validate_kind_stream(
    kind: RelayEnvelopeKind,
    stream_id: Option<&str>,
) -> Result<(), RelayFrameError> {
    match (kind, stream_id) {
        (RelayEnvelopeKind::StreamChunk, None) => Err(RelayFrameError::new(
            "stream chunk frames require stream id",
        )),
        (RelayEnvelopeKind::Message, Some(_)) => Err(RelayFrameError::new(
            "message frames must not include stream id",
        )),
        (RelayEnvelopeKind::AgentCard, Some(_)) => Err(RelayFrameError::new(
            "agent card frames must not include stream id",
        )),
        (RelayEnvelopeKind::RoomEvent, Some(_)) => Err(RelayFrameError::new(
            "room event frames must not include stream id",
        )),
        _ => Ok(()),
    }
}

fn optional_body(
    values: &HashMap<String, String>,
) -> Result<Option<RelayOpaqueBody>, RelayFrameError> {
    if !values.contains_key("body") {
        return Ok(None);
    }

    Ok(Some(RelayOpaqueBody::new(
        required(values, "cipher")?,
        required(values, "key")?,
        required(values, "sender_key")?,
        required(values, "nonce")?,
        required(values, "body")?,
    )?))
}

fn optional_identifier(
    values: &HashMap<String, String>,
    key: &'static str,
    field: &'static str,
) -> Result<Option<String>, RelayFrameError> {
    values
        .get(key)
        .map(|value| validate_identifier(value.clone(), field))
        .transpose()
}

fn optional_bool(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<Option<bool>, RelayFrameError> {
    match values.get(key).map(String::as_str) {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(_) => Err(RelayFrameError::new(format!("{key} must be true or false"))),
    }
}

fn required_bool(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<bool, RelayFrameError> {
    optional_bool(values, key)?.ok_or_else(|| RelayFrameError::new(format!("{key} is required")))
}

fn parse_frame_values(line: &str) -> Result<(&str, HashMap<String, String>), RelayFrameError> {
    let mut parts = line.split_whitespace();
    let kind = parts
        .next()
        .ok_or_else(|| RelayFrameError::new("missing frame type"))?;
    let mut values = HashMap::new();

    for part in parts {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok((kind, values))
}

fn required(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<String, RelayFrameError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| RelayFrameError::new(format!("missing {key}")))
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new(format!("{field} cannot be empty")));
    }
    if value.len() > 120 {
        return Err(RelayFrameError::new(format!("{field} is too long")));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayFrameError::new(format!(
            "{field} must use ASCII letters, numbers, dash, underscore, or dot"
        )));
    }
    Ok(value)
}

fn validate_session_id(value: String) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new("session id cannot be empty"));
    }
    if value.len() > 180 {
        return Err(RelayFrameError::new("session id is too long"));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayFrameError::new(
            "session id must use ASCII letters, numbers, dash, underscore, or dot",
        ));
    }
    Ok(value)
}

fn validate_token(value: String) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new("token cannot be empty"));
    }
    if value.len() > 200 {
        return Err(RelayFrameError::new("token is too long"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(RelayFrameError::new("token cannot contain whitespace"));
    }
    Ok(value)
}

fn validate_algorithm(value: String) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new("cipher algorithm cannot be empty"));
    }
    if value.len() > 80 {
        return Err(RelayFrameError::new("cipher algorithm is too long"));
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '+' | '.')
    }) {
        return Err(RelayFrameError::new("cipher algorithm is invalid"));
    }
    Ok(value)
}

fn validate_hex(value: String, field: &'static str) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new(format!("{field} cannot be empty")));
    }
    if value.len() > MAX_FRAME_BYTES * 2 {
        return Err(RelayFrameError::new(format!("{field} is too large")));
    }
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RelayFrameError::new(format!("{field} must be hex")));
    }
    Ok(value)
}

fn validate_fixed_hex(
    value: String,
    field: &'static str,
    expected_len: usize,
) -> Result<String, RelayFrameError> {
    let value = validate_hex(value, field)?;
    if value.len() != expected_len {
        return Err(RelayFrameError::new(format!(
            "{field} must contain {expected_len} hex characters"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_token_length(value: usize) -> Result<usize, RelayFrameError> {
    if value == 0 {
        return Err(RelayFrameError::new(
            "token length must be greater than zero",
        ));
    }
    if value > 200 {
        return Err(RelayFrameError::new("token length is too large"));
    }
    Ok(value)
}

fn validate_positive_seconds(value: u64) -> Result<u64, RelayFrameError> {
    if value == 0 {
        return Err(RelayFrameError::new(
            "retention ttl seconds must be greater than zero",
        ));
    }
    Ok(value)
}

fn parse_usize(value: &str) -> Result<usize, RelayFrameError> {
    value
        .parse::<usize>()
        .map_err(|_| RelayFrameError::new("expected unsigned byte count"))
}

fn optional_usize(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<Option<usize>, RelayFrameError> {
    values
        .get(key)
        .map(|value| parse_usize(value).and_then(validate_token_length))
        .transpose()
}

fn optional_count(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<usize, RelayFrameError> {
    values
        .get(key)
        .map(|value| parse_usize(value))
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn optional_u64(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<Option<u64>, RelayFrameError> {
    values
        .get(key)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| RelayFrameError::new(format!("{key} must be an unsigned integer")))
        })
        .transpose()
}

fn sanitize_reason(reason: &str) -> String {
    let sanitized = reason
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEndpoint {
    scheme: RelayScheme,
    host: String,
    port: u16,
    path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayScheme {
    Ws,
    Wss,
}

impl ParsedEndpoint {
    fn parse(endpoint: &str) -> Result<Self, RelayFrameError> {
        let (scheme, rest, default_port) = if let Some(rest) = endpoint.strip_prefix("ws://") {
            (RelayScheme::Ws, rest, 80)
        } else if let Some(rest) = endpoint.strip_prefix("wss://") {
            (RelayScheme::Wss, rest, 443)
        } else {
            return Err(RelayFrameError::new(
                "relay endpoint must start with ws:// or wss://",
            ));
        };
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/relay".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.trim().to_string(),
                port.parse::<u16>()
                    .map_err(|_| RelayFrameError::new("relay endpoint port is invalid"))?,
            ),
            None => (authority.trim().to_string(), default_port),
        };

        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(RelayFrameError::new("relay endpoint host is invalid"));
        }
        if path.is_empty() || path.chars().any(char::is_whitespace) {
            return Err(RelayFrameError::new("relay endpoint path is invalid"));
        }

        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn connect_tls(host: &str, stream: TcpStream) -> Result<TlsStream<TcpStream>, RelayFrameError> {
    let connector = TlsConnector::new()
        .map_err(|error| RelayFrameError::new(format!("configure relay TLS: {error}")))?;
    match connector.connect(host, stream) {
        Ok(stream) => Ok(stream),
        Err(HandshakeError::Failure(error)) => {
            Err(RelayFrameError::new(format!("connect relay TLS: {error}")))
        }
        Err(HandshakeError::WouldBlock(_)) => Err(RelayFrameError::new(
            "connect relay TLS: handshake would block",
        )),
    }
}

fn perform_client_handshake(
    stream: &mut dyn RelayStream,
    endpoint: &ParsedEndpoint,
) -> Result<(), RelayFrameError> {
    let key = websocket_key();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        endpoint.path,
        endpoint.authority(),
        key
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| RelayFrameError::io("write websocket handshake", error))?;
    let response = read_http_response(stream)?;

    if !response.starts_with("HTTP/1.1 101") && !response.starts_with("HTTP/1.0 101") {
        return Err(RelayFrameError::new(
            "relay websocket upgrade was not accepted",
        ));
    }
    let accept = header_value(&response, "sec-websocket-accept")
        .ok_or_else(|| RelayFrameError::new("relay handshake missing accept header"))?;
    if accept != websocket_accept_key(&key) {
        return Err(RelayFrameError::new("relay websocket accept key mismatch"));
    }

    Ok(())
}

fn read_http_response(stream: &mut dyn RelayStream) -> Result<String, RelayFrameError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1];

    while bytes.len() < MAX_HTTP_HEADER_BYTES {
        stream
            .read_exact(&mut buffer)
            .map_err(|error| RelayFrameError::io("read websocket handshake", error))?;
        bytes.push(buffer[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| RelayFrameError::new("websocket handshake is not UTF-8"));
        }
    }

    Err(RelayFrameError::new(
        "websocket handshake headers are too large",
    ))
}

fn header_value(response: &str, header: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(header) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn write_client_text_frame(
    stream: &mut dyn RelayStream,
    text: &str,
) -> Result<(), RelayFrameError> {
    write_client_raw_frame(stream, 0x1, text.as_bytes())
}

fn write_client_raw_frame(
    stream: &mut dyn RelayStream,
    opcode: u8,
    payload: &[u8],
) -> Result<(), RelayFrameError> {
    let mask = websocket_mask();
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);

    if payload.len() <= 125 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }

    stream
        .write_all(&frame)
        .map_err(|error| RelayFrameError::io("write websocket frame", error))
}

fn read_server_text_frame(stream: &mut dyn RelayStream) -> Result<Option<String>, RelayFrameError> {
    let mut header = [0_u8; 2];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(RelayFrameError::io("read websocket frame", error)),
    }

    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = u64::from(header[1] & 0x7f);

    if len == 126 {
        let mut bytes = [0_u8; 2];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayFrameError::io("read websocket frame length", error))?;
        len = u64::from(u16::from_be_bytes(bytes));
    } else if len == 127 {
        let mut bytes = [0_u8; 8];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayFrameError::io("read websocket frame length", error))?;
        len = u64::from_be_bytes(bytes);
    }

    if len as usize > MAX_FRAME_BYTES {
        return Err(RelayFrameError::new("websocket frame is too large"));
    }

    let mut mask = [0_u8; 4];
    if masked {
        stream
            .read_exact(&mut mask)
            .map_err(|error| RelayFrameError::io("read websocket frame mask", error))?;
    }

    let mut payload = vec![0_u8; len as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|error| RelayFrameError::io("read websocket frame body", error))?;

    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    match opcode {
        0x1 => String::from_utf8(payload)
            .map(Some)
            .map_err(|_| RelayFrameError::new("text frame is not UTF-8")),
        0x8 => Ok(None),
        0x9 => {
            write_client_raw_frame(stream, 0xA, &payload)?;
            Ok(Some("PONG payload=not_observed".to_string()))
        }
        _ => Err(RelayFrameError::new(
            "unsupported websocket frame opcode from relay",
        )),
    }
}

fn websocket_key() -> String {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&process::id().to_be_bytes());
    bytes[4..12].copy_from_slice(&(current_unix_nanos() as u64).to_be_bytes());
    bytes[12..].copy_from_slice(&websocket_mask());
    base64_encode(&bytes)
}

fn websocket_mask() -> [u8; 4] {
    let now = current_unix_nanos();
    [
        (now & 0xff) as u8,
        ((now >> 8) & 0xff) as u8,
        ((now >> 16) & 0xff) as u8,
        ((now >> 24) & 0xff) as u8,
    ]
}

fn websocket_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key.trim());
    input.push_str(WEBSOCKET_GUID);
    base64_encode(&sha1(input.as_bytes()))
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;

        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }

    out
}

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;
    let bit_len = (bytes.len() as u64) * 8;
    let mut message = bytes.to_vec();

    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0_u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let offset = i * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0_u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
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
    fn hello_debug_redacts_token() {
        let hello = RelayHello::new("node.a", "secret-token").expect("valid hello");
        let debug = format!("{hello:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn hello_resume_round_trips_without_debug_leak() {
        let session_id = "relay_node.a_123";
        let frame = RelayClientFrame::Hello(
            RelayHello::new("node.a", "secret-token")
                .expect("valid hello")
                .with_resume_session_id(session_id)
                .expect("resume id"),
        );
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("hello parses");
        let debug = format!("{frame:?}");

        assert!(rendered.contains("resume=relay_node.a_123"));
        assert!(rendered.contains("payload=not_observed"));
        assert_eq!(parsed, frame);
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains(session_id));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn welcome_resume_round_trips_with_legacy_default() {
        let frame = RelayServerFrame::Welcome {
            session_id: "relay_node.a_123".to_string(),
            resumed: true,
        };
        let rendered = render_server_frame(&frame);
        let parsed = parse_server_frame(&rendered).expect("welcome parses");
        let legacy = parse_server_frame("WELCOME session=relay_node.a_456 payload=not_observed")
            .expect("legacy welcome parses");

        assert!(rendered.contains("resumed=true"));
        assert_eq!(parsed, frame);
        assert_eq!(
            legacy,
            RelayServerFrame::Welcome {
                session_id: "relay_node.a_456".to_string(),
                resumed: false,
            }
        );
    }

    #[test]
    fn forward_frame_is_metadata_only() {
        let frame = RelayClientFrame::Forward(Box::new(
            RelayForward::new("node.b", "env.1", 42).expect("valid forward"),
        ));
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("frame parses");

        assert!(rendered.contains("payload=opaque"));
        assert!(!rendered.contains("private message contents"));
        assert_eq!(parsed, frame);
    }

    #[test]
    fn stream_chunk_frame_carries_stream_metadata_only() {
        let body =
            RelayOpaqueBody::new("xchacha20poly1305", "key.1", "aa", "bb", "cc").expect("body");
        let frame = RelayClientFrame::Forward(Box::new(
            RelayForward::with_stream_body(
                "stream.1", "node.b", "env.1", "agent.a", "agent.b", 18, body,
            )
            .expect("stream frame"),
        ));
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("frame parses");

        assert!(rendered.contains("kind=stream_chunk"));
        assert!(rendered.contains("stream=stream.1"));
        assert!(rendered.contains("payload=peer_encrypted"));
        assert!(!rendered.contains("private stream chunk"));
        assert_eq!(parsed, frame);
    }

    #[test]
    fn agent_card_frame_carries_ciphertext_only() {
        let body =
            RelayOpaqueBody::new("xchacha20poly1305", "key.1", "aa", "bb", "cc").expect("body");
        let frame = RelayClientFrame::Forward(Box::new(
            RelayForward::with_agent_card_body("node.b", "env.card.1", "agent.a", 128, body)
                .expect("agent card frame"),
        ));
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("frame parses");

        assert!(rendered.contains("kind=agent_card"));
        assert!(rendered.contains("to_agent=conu.discovery"));
        assert!(rendered.contains("payload=peer_encrypted"));
        assert!(!rendered.contains("conu-agent-card-v1"));
        assert!(!rendered.contains("signature_hex"));
        assert_eq!(parsed, frame);
    }

    #[test]
    fn room_event_frame_carries_ciphertext_only() {
        let body =
            RelayOpaqueBody::new("xchacha20poly1305", "key.1", "aa", "bb", "cc").expect("body");
        let frame = RelayClientFrame::Forward(Box::new(
            RelayForward::with_room_event_body(
                "node.b",
                "room.env.1",
                "agent.a",
                "agent.b",
                128,
                body,
            )
            .expect("room event frame"),
        ));
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("frame parses");

        assert!(rendered.contains("kind=room_event"));
        assert!(rendered.contains("payload=peer_encrypted"));
        assert!(!rendered.contains("room.dev"));
        assert!(!rendered.contains("build"));
        assert!(!rendered.contains("private room event"));
        assert_eq!(parsed, frame);
    }

    #[test]
    fn admin_frames_round_trip_with_debug_redaction() {
        let token_hash = "a".repeat(64);
        let request = RelayAdminRequest::issue(
            "admin-secret-token-1234567890",
            "account.prod",
            "node.hosted",
            token_hash.clone(),
            64,
            Some(4_000),
        )
        .expect("admin request parses");
        let frame = RelayClientFrame::Admin(Box::new(request.clone()));
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("admin request parses");
        let debug = format!("{frame:?}");
        let result = RelayServerFrame::AdminResult(Box::new(RelayAdminResult {
            action: RelayAdminAction::Issue,
            status: "issued".to_string(),
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            credentials: 1,
            active: 1,
            revoked: 0,
            expired: 0,
            accounts: 1,
            token_length: Some(64),
            expires_at_unix: Some(4_000),
            token_displayed: false,
            contents_displayed: false,
            ..RelayAdminResult::new(RelayAdminAction::Issue, "issued")
        }));
        let rendered_result = render_server_frame(&result);
        let parsed_result = parse_server_frame(&rendered_result).expect("admin result parses");

        assert_eq!(parsed, frame);
        assert!(rendered.contains("ADMIN action=issue"));
        assert!(rendered.contains("token_displayed=false"));
        assert!(rendered.contains("payload=not_observed"));
        assert!(!debug.contains("admin-secret-token-1234567890"));
        assert!(!debug.contains(&token_hash));
        assert!(debug.contains("<redacted>"));
        assert_eq!(parsed_result, result);
        assert!(rendered_result.contains("ADMIN_RESULT action=issue status=issued"));
        assert!(rendered_result.contains("contents_displayed=false"));
        assert!(!rendered_result.contains("admin-secret-token-1234567890"));
        assert!(!rendered_result.contains(&token_hash));

        let dashboard_request = RelayAdminRequest::dashboard(
            "admin-secret-token-1234567890",
            Some("account.prod".to_string()),
            Some("node.hosted".to_string()),
        )
        .expect("dashboard request parses");
        let dashboard_frame = RelayClientFrame::Admin(Box::new(dashboard_request));
        let rendered_dashboard = render_client_frame(&dashboard_frame);
        let parsed_dashboard =
            parse_client_frame(&rendered_dashboard).expect("dashboard request parses");
        let dashboard_debug = format!("{dashboard_frame:?}");
        let dashboard_result = RelayServerFrame::AdminResult(Box::new(RelayAdminResult {
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            credentials: 1,
            active: 1,
            accounts: 1,
            tenants: 1,
            active_tenants: 1,
            nodes: 1,
            active_nodes: 1,
            tenant_policies: 1,
            accounting_records: 1,
            sessions_authenticated: 1,
            abuse_records: 1,
            admin_unauthorized: 1,
            ..RelayAdminResult::new(RelayAdminAction::Dashboard, "snapshotted")
        }));
        let rendered_dashboard_result = render_server_frame(&dashboard_result);
        let parsed_dashboard_result =
            parse_server_frame(&rendered_dashboard_result).expect("dashboard result parses");

        assert_eq!(parsed_dashboard, dashboard_frame);
        assert!(rendered_dashboard.contains("ADMIN action=dashboard"));
        assert!(rendered_dashboard.contains("account=account.prod"));
        assert!(rendered_dashboard.contains("node=node.hosted"));
        assert!(!dashboard_debug.contains("admin-secret-token-1234567890"));
        assert_eq!(parsed_dashboard_result, dashboard_result);
        assert!(rendered_dashboard_result.contains("ADMIN_RESULT action=dashboard"));
        assert!(rendered_dashboard_result.contains("tenants=1"));
        assert!(rendered_dashboard_result.contains("accounting_records=1"));
        assert!(rendered_dashboard_result.contains("admin_unauthorized=1"));
        assert!(rendered_dashboard_result.contains("payload_displayed=false"));
        assert!(!rendered_dashboard_result.contains("admin-secret-token-1234567890"));
        assert!(!rendered_dashboard_result.contains(&token_hash));

        let tenant_request = RelayAdminRequest::tenant_node_upsert(
            "admin-secret-token-1234567890",
            "account.prod",
            "node.hosted",
            true,
            true,
            false,
            false,
            true,
            Some("signing.key.1".to_string()),
            Some("exchange.key.1".to_string()),
        )
        .expect("tenant node request parses");
        let tenant_frame = RelayClientFrame::Admin(Box::new(tenant_request));
        let rendered_tenant = render_client_frame(&tenant_frame);
        let parsed_tenant =
            parse_client_frame(&rendered_tenant).expect("tenant node request parses");
        let tenant_debug = format!("{tenant_frame:?}");
        let tenant_result = RelayServerFrame::AdminResult(Box::new(RelayAdminResult {
            action: RelayAdminAction::TenantNodeUpsert,
            status: "upserted".to_string(),
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            tenants: 1,
            active_tenants: 1,
            revoked_tenants: 0,
            nodes: 1,
            active_nodes: 1,
            revoked_nodes: 0,
            tenant_policies: 1,
            ..RelayAdminResult::new(RelayAdminAction::TenantNodeUpsert, "upserted")
        }));
        let rendered_tenant_result = render_server_frame(&tenant_result);
        let parsed_tenant_result =
            parse_server_frame(&rendered_tenant_result).expect("tenant node result parses");

        assert_eq!(parsed_tenant, tenant_frame);
        assert!(rendered_tenant.contains("ADMIN action=tenant_node_upsert"));
        assert!(rendered_tenant.contains("account=account.prod"));
        assert!(rendered_tenant.contains("node=node.hosted"));
        assert!(rendered_tenant.contains("messages=true"));
        assert!(rendered_tenant.contains("mailbox=true"));
        assert!(rendered_tenant.contains("signing_key_id=signing.key.1"));
        assert!(!tenant_debug.contains("admin-secret-token-1234567890"));
        assert_eq!(parsed_tenant_result, tenant_result);
        assert!(rendered_tenant_result.contains("ADMIN_RESULT action=tenant_node_upsert"));
        assert!(rendered_tenant_result.contains("tenants=1"));
        assert!(rendered_tenant_result.contains("tenant_policies=1"));
        assert!(rendered_tenant_result.contains("payload_displayed=false"));
        assert!(!rendered_tenant_result.contains("admin-secret-token-1234567890"));
        assert!(!rendered_tenant_result.contains(&token_hash));
        assert!(!rendered_tenant_result.contains("signing.key.1"));
        assert!(!rendered_tenant_result.contains("exchange.key.1"));

        let suspend_request =
            RelayAdminRequest::account_suspend("admin-secret-token-1234567890", "account.prod")
                .expect("account suspend request parses");
        let suspend_frame = RelayClientFrame::Admin(Box::new(suspend_request));
        let rendered_suspend = render_client_frame(&suspend_frame);
        let parsed_suspend =
            parse_client_frame(&rendered_suspend).expect("account suspend request parses");
        let suspend_debug = format!("{suspend_frame:?}");
        let suspend_result = RelayServerFrame::AdminResult(Box::new(RelayAdminResult {
            action: RelayAdminAction::AccountSuspend,
            status: "suspended".to_string(),
            account_id: Some("account.prod".to_string()),
            credentials: 2,
            active: 0,
            revoked: 2,
            accounts: 1,
            tenants: 1,
            active_tenants: 0,
            revoked_tenants: 1,
            nodes: 1,
            active_nodes: 1,
            tenant_policies: 1,
            ..RelayAdminResult::new(RelayAdminAction::AccountSuspend, "suspended")
        }));
        let rendered_suspend_result = render_server_frame(&suspend_result);
        let parsed_suspend_result =
            parse_server_frame(&rendered_suspend_result).expect("account suspend result parses");

        assert_eq!(parsed_suspend, suspend_frame);
        assert!(rendered_suspend.contains("ADMIN action=account_suspend"));
        assert!(rendered_suspend.contains("account=account.prod"));
        assert!(!suspend_debug.contains("admin-secret-token-1234567890"));
        assert_eq!(parsed_suspend_result, suspend_result);
        assert!(rendered_suspend_result.contains("ADMIN_RESULT action=account_suspend"));
        assert!(rendered_suspend_result.contains("credentials=2 active=0 revoked=2"));
        assert!(rendered_suspend_result.contains("tenants=1 active_tenants=0"));
        assert!(rendered_suspend_result.contains("payload_displayed=false"));
        assert!(!rendered_suspend_result.contains("admin-secret-token-1234567890"));
        assert!(!rendered_suspend_result.contains(&token_hash));

        let mailbox_request = RelayAdminRequest::mailbox_audit(
            "admin-secret-token-1234567890",
            Some("node.hosted".to_string()),
            Some(3600),
        )
        .expect("mailbox audit request parses");
        let mailbox_frame = RelayClientFrame::Admin(Box::new(mailbox_request));
        let rendered_mailbox = render_client_frame(&mailbox_frame);
        let parsed_mailbox =
            parse_client_frame(&rendered_mailbox).expect("mailbox audit request parses");
        let mailbox_debug = format!("{mailbox_frame:?}");
        let mailbox_result = RelayServerFrame::AdminResult(Box::new(RelayAdminResult {
            node_id: Some("node.hosted".to_string()),
            retention_ttl_seconds: Some(3600),
            mailbox_nodes: 1,
            mailbox_records: 2,
            mailbox_invalid_records: 1,
            mailbox_bytes: 512,
            mailbox_oldest_queued_unix_millis: Some(1_763_596_800_000),
            mailbox_newest_queued_unix_millis: Some(1_763_596_900_000),
            mailbox_expired_records: Some(1),
            mailbox_expired_bytes: Some(256),
            ..RelayAdminResult::new(RelayAdminAction::MailboxAudit, "audited")
        }));
        let rendered_mailbox_result = render_server_frame(&mailbox_result);
        let parsed_mailbox_result =
            parse_server_frame(&rendered_mailbox_result).expect("mailbox audit result parses");

        assert_eq!(parsed_mailbox, mailbox_frame);
        assert!(rendered_mailbox.contains("ADMIN action=mailbox_audit"));
        assert!(rendered_mailbox.contains("node=node.hosted"));
        assert!(rendered_mailbox.contains("ttl_seconds=3600"));
        assert!(!mailbox_debug.contains("admin-secret-token-1234567890"));
        assert_eq!(parsed_mailbox_result, mailbox_result);
        assert!(rendered_mailbox_result.contains("ADMIN_RESULT action=mailbox_audit"));
        assert!(rendered_mailbox_result.contains("mailbox_records=2"));
        assert!(rendered_mailbox_result.contains("mailbox_invalid_records=1"));
        assert!(rendered_mailbox_result.contains("mailbox_expired_records=1"));
        assert!(rendered_mailbox_result.contains("payload_displayed=false"));
        assert!(!rendered_mailbox_result.contains("admin-secret-token-1234567890"));
        assert!(!rendered_mailbox_result.contains(&token_hash));

        let purge_request = RelayAdminRequest::mailbox_purge(
            "admin-secret-token-1234567890",
            Some("node.hosted".to_string()),
            3600,
            false,
        )
        .expect("mailbox purge request parses");
        let purge_frame = RelayClientFrame::Admin(Box::new(purge_request));
        let rendered_purge = render_client_frame(&purge_frame);
        let parsed_purge =
            parse_client_frame(&rendered_purge).expect("mailbox purge request parses");
        let purge_debug = format!("{purge_frame:?}");
        let purge_result = RelayServerFrame::AdminResult(Box::new(RelayAdminResult {
            node_id: Some("node.hosted".to_string()),
            retention_ttl_seconds: Some(3600),
            mailbox_nodes: 1,
            mailbox_records: 2,
            mailbox_invalid_records: 1,
            mailbox_bytes: 512,
            mailbox_expired_records: Some(1),
            mailbox_expired_bytes: Some(256),
            mailbox_dry_run: Some(false),
            mailbox_confirmed: Some(true),
            mailbox_purged_records: Some(1),
            mailbox_purged_bytes: Some(256),
            ..RelayAdminResult::new(RelayAdminAction::MailboxPurge, "purged")
        }));
        let rendered_purge_result = render_server_frame(&purge_result);
        let parsed_purge_result =
            parse_server_frame(&rendered_purge_result).expect("mailbox purge result parses");

        assert_eq!(parsed_purge, purge_frame);
        assert!(rendered_purge.contains("ADMIN action=mailbox_purge"));
        assert!(rendered_purge.contains("node=node.hosted"));
        assert!(rendered_purge.contains("ttl_seconds=3600"));
        assert!(rendered_purge.contains("dry_run=false"));
        assert!(!purge_debug.contains("admin-secret-token-1234567890"));
        assert_eq!(parsed_purge_result, purge_result);
        assert!(rendered_purge_result.contains("ADMIN_RESULT action=mailbox_purge"));
        assert!(rendered_purge_result.contains("mailbox_purged_records=1"));
        assert!(rendered_purge_result.contains("confirmed=true"));
        assert!(rendered_purge_result.contains("payload_displayed=false"));
        assert!(!rendered_purge_result.contains("admin-secret-token-1234567890"));
        assert!(!rendered_purge_result.contains(&token_hash));
    }

    #[test]
    fn rejects_plaintext_payload_fields() {
        let error = parse_client_frame("HELLO node=node.b token=test-token payload_text=secret")
            .expect_err("plaintext payload should fail");

        assert!(error.to_string().contains("must not include"));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn endpoint_parser_accepts_wss_with_default_port() {
        let endpoint =
            ParsedEndpoint::parse("wss://relay.example.com/conu").expect("wss endpoint parses");

        assert_eq!(endpoint.scheme, RelayScheme::Wss);
        assert_eq!(endpoint.host, "relay.example.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/conu");
        assert_eq!(endpoint.authority(), "relay.example.com:443");
    }

    #[test]
    fn endpoint_parser_accepts_ws_with_default_port() {
        let endpoint = ParsedEndpoint::parse("ws://relay.example.com").expect("ws endpoint parses");

        assert_eq!(endpoint.scheme, RelayScheme::Ws);
        assert_eq!(endpoint.host, "relay.example.com");
        assert_eq!(endpoint.port, 80);
        assert_eq!(endpoint.path, "/relay");
    }

    #[test]
    fn endpoint_parser_rejects_non_websocket_schemes() {
        let error = ParsedEndpoint::parse("https://relay.example.com")
            .expect_err("non websocket endpoint fails");

        assert!(error.to_string().contains("ws:// or wss://"));
    }
}
