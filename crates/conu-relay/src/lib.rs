//! WebSocket relay MVP for conU.
//!
//! Phase 8 implements a small plain WebSocket relay that authenticates
//! runtime sessions and forwards opaque envelope metadata between connected
//! nodes. It deliberately has no API for plaintext payload contents.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conu_core::relay::{
    RelayAdminAction, RelayAdminRequest, RelayAdminResult, RelayClientFrame, RelayForwarded,
    RelayServerFrame, parse_client_frame, parse_server_frame, render_server_frame,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_BYTES: usize = 8192;
const MAX_FRAME_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 512;
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 64;
const DEFAULT_MAX_FRAMES_PER_MINUTE: usize = 600;
const DEFAULT_SESSION_IDLE_TIMEOUT_SECS: u64 = 120;
const DEFAULT_SESSION_TTL_SECS: u64 = 60 * 60;
const DEFAULT_MAX_OFFLINE_ENVELOPES_PER_NODE: usize = 128;
const DEFAULT_OFFLINE_ENVELOPE_TTL_SECS: u64 = 60 * 60;
const DEFAULT_ACCOUNTING_WINDOW_SECS: u64 = 24 * 60 * 60;
const RELAY_MAILBOX_FILE_VERSION: &str = "1";
const RELAY_SESSION_FILE_VERSION: &str = "1";
const RELAY_CREDENTIALS_FILE_VERSION: &str = "1";
const RELAY_ADMIN_TOKENS_FILE_VERSION: &str = "1";
const RELAY_ACCOUNTING_FILE_VERSION: &str = "1";
const RELAY_ABUSE_FILE_VERSION: &str = "1";
const HOSTED_TENANT_FILE_VERSION: &str = "1";
const RELAY_SESSION_STATE_LOAD_ATTEMPTS: usize = 6;
const RELAY_SESSION_STATE_LOAD_RETRY_DELAY: Duration = Duration::from_millis(20);
const RELAY_METADATA_REPLACE_ATTEMPTS: usize = 6;
const RELAY_METADATA_REPLACE_RETRY_DELAY: Duration = Duration::from_millis(20);
const LOCAL_DEV_TOKEN: &str = "local-dev-token";
const MIN_PUBLIC_BIND_TOKEN_LEN: usize = 24;
const MAX_TOKEN_LEN: usize = 200;
const ISSUED_RELAY_TOKEN_BYTES: usize = 32;
const MAX_RELAY_MANIFEST_FILE_BYTES: u64 = 1024 * 1024;

/// Configuration for the relay server.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub bind_addr: String,
    pub auth: RelayAuth,
    pub limits: RelayLimits,
    pub session_policy: RelaySessionPolicy,
    pub session_storage: RelaySessionStorage,
    pub mailbox_policy: RelayMailboxPolicy,
    pub mailbox_storage: RelayMailboxStorage,
    pub mailbox_maintenance: RelayMailboxMaintenancePolicy,
    pub accounting_policy: RelayAccountingPolicy,
    pub accounting_storage: RelayAccountingStorage,
    pub abuse_policy: RelayAbusePolicy,
    pub abuse_storage: RelayAbuseStorage,
    pub admin: RelayAdminConfig,
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConfig")
            .field("bind_addr", &self.bind_addr)
            .field("auth", &self.auth)
            .field("limits", &self.limits)
            .field("session_policy", &self.session_policy)
            .field("session_storage", &self.session_storage)
            .field("mailbox_policy", &self.mailbox_policy)
            .field("mailbox_storage", &self.mailbox_storage)
            .field("mailbox_maintenance", &self.mailbox_maintenance)
            .field("accounting_policy", &self.accounting_policy)
            .field("accounting_storage", &self.accounting_storage)
            .field("abuse_policy", &self.abuse_policy)
            .field("abuse_storage", &self.abuse_storage)
            .field("admin", &self.admin)
            .finish()
    }
}

/// Relay authentication mode.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayAuth {
    SharedToken(String),
    ScopedCredentials(Vec<RelayCredential>),
    ScopedCredentialsFile { path: PathBuf, bind_addr: String },
}

impl RelayAuth {
    fn authorize(&self, node_id: &str, token: &str) -> bool {
        self.authorize_at(node_id, token, current_unix_seconds())
    }

    fn authorize_at(&self, node_id: &str, token: &str, now_unix: u64) -> bool {
        match self {
            Self::SharedToken(expected) => constant_time_eq(expected.as_bytes(), token.as_bytes()),
            Self::ScopedCredentials(credentials) => {
                authorize_scoped_credentials(credentials, node_id, token, now_unix)
            }
            Self::ScopedCredentialsFile { path, bind_addr } => {
                let Ok(credentials) = load_scoped_credentials_file(path) else {
                    return false;
                };
                if validate_scoped_credentials_for_bind(bind_addr, &credentials).is_err() {
                    return false;
                }
                authorize_scoped_credentials(&credentials, node_id, token, now_unix)
            }
        }
    }
}

impl fmt::Debug for RelayAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedToken(_) => formatter
                .debug_struct("RelayAuth::SharedToken")
                .field("token", &"<redacted>")
                .finish(),
            Self::ScopedCredentials(credentials) => formatter
                .debug_struct("RelayAuth::ScopedCredentials")
                .field("credentials", &credentials.len())
                .finish(),
            Self::ScopedCredentialsFile { path, .. } => formatter
                .debug_struct("RelayAuth::ScopedCredentialsFile")
                .field("path", path)
                .field("reload", &"per-hello")
                .finish(),
        }
    }
}

/// Optional hosted relay admin control plane.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayAdminConfig {
    Disabled,
    Enabled {
        bind_addr: String,
        primary_token: Option<String>,
        credentials_file: PathBuf,
        tenants_file: Option<PathBuf>,
        tokens_file: Option<PathBuf>,
    },
}

impl RelayAdminConfig {
    fn disabled() -> Self {
        Self::Disabled
    }

    fn with_token(
        bind_addr: &str,
        token: impl Into<String>,
        credentials_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        let token = token.into();
        validate_admin_token(bind_addr, &token)?;
        let credentials_file = credentials_file.into();
        if credentials_file.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay admin credentials file cannot be empty",
            ));
        }
        Ok(Self::Enabled {
            bind_addr: bind_addr.to_string(),
            primary_token: Some(token),
            credentials_file,
            tenants_file: None,
            tokens_file: None,
        })
    }

    fn with_tokens_file(
        bind_addr: &str,
        tokens_file: impl Into<PathBuf>,
        credentials_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        let credentials_file = credentials_file.into();
        if credentials_file.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay admin credentials file cannot be empty",
            ));
        }
        let tokens_file = tokens_file.into();
        if tokens_file.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay admin tokens file cannot be empty",
            ));
        }
        Ok(Self::Enabled {
            bind_addr: bind_addr.to_string(),
            primary_token: None,
            credentials_file,
            tenants_file: None,
            tokens_file: Some(tokens_file),
        })
    }

    fn with_tenants_file(mut self, tenants_file: impl Into<PathBuf>) -> Result<Self, RelayError> {
        let tenants_file = tenants_file.into();
        if tenants_file.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay admin tenants file cannot be empty",
            ));
        }
        match &mut self {
            Self::Disabled => Err(RelayError::InvalidConfig(
                "relay admin tenants file requires admin token configuration",
            )),
            Self::Enabled {
                tenants_file: slot, ..
            } => {
                *slot = Some(tenants_file);
                Ok(self)
            }
        }
    }

    fn with_admin_tokens_file(
        mut self,
        tokens_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        let tokens_file = tokens_file.into();
        if tokens_file.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay admin tokens file cannot be empty",
            ));
        }
        match &mut self {
            Self::Disabled => Err(RelayError::InvalidConfig(
                "relay admin tokens file requires admin configuration",
            )),
            Self::Enabled {
                tokens_file: slot, ..
            } => {
                *slot = Some(tokens_file);
                Ok(self)
            }
        }
    }

    fn authorize_action(
        &self,
        token: &str,
        action: RelayAdminAction,
    ) -> Result<RelayAdminAuthorization, RelayError> {
        match self {
            Self::Disabled => Err(RelayError::Protocol("admin_unauthorized".to_string())),
            Self::Enabled {
                bind_addr,
                primary_token,
                tokens_file,
                ..
            } => {
                if primary_token
                    .as_deref()
                    .is_some_and(|expected| constant_time_eq(expected.as_bytes(), token.as_bytes()))
                {
                    return Ok(RelayAdminAuthorization::full());
                }
                let Some(tokens_file) = tokens_file else {
                    return Err(RelayError::Protocol("admin_unauthorized".to_string()));
                };
                let tokens = load_admin_tokens_file(tokens_file, bind_addr)?;
                tokens.authorize(token, action)
            }
        }
    }

    fn credentials_file(&self) -> Option<&Path> {
        match self {
            Self::Disabled => None,
            Self::Enabled {
                credentials_file, ..
            } => Some(credentials_file.as_path()),
        }
    }

    fn tenants_file(&self) -> Option<&Path> {
        match self {
            Self::Disabled => None,
            Self::Enabled { tenants_file, .. } => tenants_file.as_deref(),
        }
    }
}

impl fmt::Debug for RelayAdminConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("RelayAdminConfig::Disabled"),
            Self::Enabled {
                credentials_file,
                primary_token,
                tokens_file,
                ..
            } => formatter
                .debug_struct("RelayAdminConfig::Enabled")
                .field(
                    "primary_token",
                    &primary_token.as_ref().map(|_| "<redacted>"),
                )
                .field("credentials_file", credentials_file)
                .field("tenants_file", &self.tenants_file())
                .field("tokens_file", tokens_file)
                .finish(),
        }
    }
}

/// Action scopes for manifest-backed hosted relay admin tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayAdminTokenScopes {
    pub credentials: bool,
    pub tenants: bool,
    pub dashboard: bool,
    pub sessions: bool,
    pub mailbox_audit: bool,
    pub mailbox_purge: bool,
}

impl RelayAdminTokenScopes {
    pub const fn full() -> Self {
        Self {
            credentials: true,
            tenants: true,
            dashboard: true,
            sessions: true,
            mailbox_audit: true,
            mailbox_purge: true,
        }
    }

    fn allows(self, action: RelayAdminAction) -> bool {
        match action {
            RelayAdminAction::Issue
            | RelayAdminAction::Rotate
            | RelayAdminAction::Revoke
            | RelayAdminAction::Audit => self.credentials,
            RelayAdminAction::TenantUpsert
            | RelayAdminAction::TenantRevoke
            | RelayAdminAction::TenantNodeUpsert
            | RelayAdminAction::TenantNodeRevoke
            | RelayAdminAction::TenantAudit => self.tenants,
            RelayAdminAction::AccountSuspend => self.credentials && self.tenants,
            RelayAdminAction::Dashboard => self.dashboard,
            RelayAdminAction::SessionAudit => self.sessions,
            RelayAdminAction::MailboxAudit => self.mailbox_audit,
            RelayAdminAction::MailboxPurge => self.mailbox_purge,
        }
    }

    fn any(self) -> bool {
        self.credentials
            || self.tenants
            || self.dashboard
            || self.sessions
            || self.mailbox_audit
            || self.mailbox_purge
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayAdminAuthorization {
    account_id: Option<String>,
}

impl RelayAdminAuthorization {
    fn full() -> Self {
        Self { account_id: None }
    }
}

/// Lifecycle state for a scoped relay credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCredentialStatus {
    Active,
    Revoked,
}

impl RelayCredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, RelayError> {
        match value.trim() {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(RelayError::InvalidConfig(
                "relay credential status must be active or revoked",
            )),
        }
    }
}

/// Per-node relay credential for hosted relay deployments.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayCredential {
    pub account_id: Option<String>,
    pub node_id: String,
    secret: RelayCredentialSecret,
    status: RelayCredentialStatus,
    expires_at_unix: Option<u64>,
}

impl RelayCredential {
    pub fn new(node_id: impl Into<String>, token: impl Into<String>) -> Result<Self, RelayError> {
        let node_id = validate_node_id(node_id.into())?;
        let token = token.into();
        validate_token(&token)?;
        if token.contains([',', ':']) {
            return Err(RelayError::InvalidConfig(
                "relay scoped credential tokens cannot contain separators",
            ));
        }

        Ok(Self {
            account_id: None,
            node_id,
            secret: RelayCredentialSecret::PlainToken(token),
            status: RelayCredentialStatus::Active,
            expires_at_unix: None,
        })
    }

    pub fn from_sha256_hex(
        node_id: impl Into<String>,
        token_sha256_hex: impl Into<String>,
        token_length: usize,
    ) -> Result<Self, RelayError> {
        let node_id = validate_node_id(node_id.into())?;
        let token_sha256_hex = validate_token_sha256_hex(token_sha256_hex.into())?;
        validate_token_length_metadata(token_length)?;

        Ok(Self {
            account_id: None,
            node_id,
            secret: RelayCredentialSecret::Sha256Hex {
                token_sha256_hex,
                token_length,
            },
            status: RelayCredentialStatus::Active,
            expires_at_unix: None,
        })
    }

    pub fn with_status(mut self, status: RelayCredentialStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_account_id(mut self, account_id: impl Into<String>) -> Result<Self, RelayError> {
        self.account_id = Some(validate_account_id(account_id.into())?);
        Ok(self)
    }

    pub fn with_expires_at_unix(mut self, expires_at_unix: Option<u64>) -> Self {
        self.expires_at_unix = expires_at_unix;
        self
    }

    fn authorize_at(&self, node_id: &str, token: &str, now_unix: u64) -> bool {
        let node_matches = self.node_id == node_id;
        let token_matches = self.secret.matches(token);
        let active = self.status == RelayCredentialStatus::Active
            && self
                .expires_at_unix
                .is_none_or(|expires_at| expires_at > now_unix);
        node_matches && token_matches && active
    }

    fn validate_for_bind(&self, bind_addr: &str) -> Result<(), RelayError> {
        self.secret.validate_for_bind(bind_addr)
    }
}

/// A newly issued scoped relay credential.
///
/// The raw token is available only for writing to a client secret file. Debug
/// output redacts both token and hash material.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedRelayCredential {
    account_id: Option<String>,
    node_id: String,
    token: String,
    token_sha256_hex: String,
    token_length: usize,
    expires_at_unix: Option<u64>,
    created_at_unix: u64,
}

/// Payload-safe result of updating a scoped credential manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialManifestUpdate {
    pub path: PathBuf,
    pub node_id: String,
    pub status: RelayCredentialStatus,
    pub credentials: usize,
    pub replaced: bool,
    pub token_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only summary of hosted relay account credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedCredentialAudit {
    pub account_id: Option<String>,
    pub credentials: usize,
    pub active: usize,
    pub revoked: usize,
    pub expired: usize,
    pub accounts: usize,
    pub token_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only summary of hosted relay scoped admin-token records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedAdminTokenAudit {
    pub account_id: Option<String>,
    pub records: usize,
    pub active: usize,
    pub revoked: usize,
    pub expired: usize,
    pub account_scoped_records: usize,
    pub global_records: usize,
    pub accounts: usize,
    pub expiring_records: usize,
    pub next_expires_at_unix: Option<u64>,
    pub last_expires_at_unix: Option<u64>,
    pub scope_credentials: usize,
    pub scope_tenants: usize,
    pub scope_dashboard: usize,
    pub scope_sessions: usize,
    pub scope_mailbox_audit: usize,
    pub scope_mailbox_purge: usize,
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

/// Hosted tenant/account lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedTenantStatus {
    Active,
    Revoked,
}

impl HostedTenantStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, RelayError> {
        match value.trim() {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(RelayError::InvalidConfig(
                "hosted tenant status must be active or revoked",
            )),
        }
    }
}

/// Hosted permission metadata for a node inside an account.
///
/// These flags are an operator-side hosted boundary. They do not grant local
/// peer permissions; conUD still enforces local peer policy before delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostedTenantPermissions {
    pub messages: bool,
    pub streams: bool,
    pub rooms: bool,
    pub files: bool,
    pub mailbox: bool,
}

impl HostedTenantPermissions {
    pub const fn any(self) -> bool {
        self.messages || self.streams || self.rooms || self.files || self.mailbox
    }
}

/// Payload-safe result of updating hosted tenant metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedTenantManifestUpdate {
    pub path: PathBuf,
    pub account_id: String,
    pub node_id: Option<String>,
    pub status: HostedTenantStatus,
    pub tenants: usize,
    pub nodes: usize,
    pub token_displayed: bool,
    pub key_material_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only hosted tenant audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedTenantAudit {
    pub account_id: Option<String>,
    pub tenants: usize,
    pub active_tenants: usize,
    pub revoked_tenants: usize,
    pub nodes: usize,
    pub active_nodes: usize,
    pub revoked_nodes: usize,
    pub policies: usize,
    pub token_displayed: bool,
    pub key_material_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only result of suspending one hosted account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedAccountSuspension {
    pub account_id: String,
    pub credentials_file: PathBuf,
    pub tenants_file: PathBuf,
    pub credentials: usize,
    pub active: usize,
    pub revoked: usize,
    pub expired: usize,
    pub accounts: usize,
    pub tenants: usize,
    pub active_tenants: usize,
    pub revoked_tenants: usize,
    pub nodes: usize,
    pub active_nodes: usize,
    pub revoked_nodes: usize,
    pub tenant_policies: usize,
    pub token_displayed: bool,
    pub key_material_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only result of suspending one hosted account node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedAccountNodeSuspension {
    pub account_id: String,
    pub node_id: String,
    pub credentials_file: PathBuf,
    pub tenants_file: PathBuf,
    pub credentials: usize,
    pub active: usize,
    pub revoked: usize,
    pub expired: usize,
    pub accounts: usize,
    pub tenants: usize,
    pub active_tenants: usize,
    pub revoked_tenants: usize,
    pub nodes: usize,
    pub active_nodes: usize,
    pub revoked_nodes: usize,
    pub tenant_policies: usize,
    pub token_displayed: bool,
    pub key_material_displayed: bool,
    pub contents_displayed: bool,
}

impl IssuedRelayCredential {
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn token_sha256_hex(&self) -> &str {
        &self.token_sha256_hex
    }

    pub fn token_length(&self) -> usize {
        self.token_length
    }

    pub fn expires_at_unix(&self) -> Option<u64> {
        self.expires_at_unix
    }

    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    pub fn manifest_entry(&self) -> String {
        render_issued_credential_manifest_entry(self)
    }

    pub fn with_account_id(mut self, account_id: impl Into<String>) -> Result<Self, RelayError> {
        self.account_id = Some(validate_account_id(account_id.into())?);
        Ok(self)
    }
}

impl fmt::Debug for IssuedRelayCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedRelayCredential")
            .field("account_id", &self.account_id)
            .field("node_id", &self.node_id)
            .field("token", &"<redacted>")
            .field("token_sha256_hex", &"<redacted>")
            .field("token_length", &self.token_length)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
enum RelayCredentialSecret {
    PlainToken(String),
    Sha256Hex {
        token_sha256_hex: String,
        token_length: usize,
    },
}

impl RelayCredentialSecret {
    fn matches(&self, token: &str) -> bool {
        match self {
            Self::PlainToken(expected) => constant_time_eq(expected.as_bytes(), token.as_bytes()),
            Self::Sha256Hex {
                token_sha256_hex, ..
            } => match relay_token_sha256_hex(token) {
                Ok(actual) => constant_time_eq(token_sha256_hex.as_bytes(), actual.as_bytes()),
                Err(_) => false,
            },
        }
    }

    fn validate_for_bind(&self, bind_addr: &str) -> Result<(), RelayError> {
        match self {
            Self::PlainToken(token) => validate_token_for_bind(bind_addr, token),
            Self::Sha256Hex {
                token_sha256_hex,
                token_length,
            } => validate_hashed_token_for_bind(bind_addr, token_sha256_hex, *token_length),
        }
    }
}

impl fmt::Debug for RelayCredentialSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Debug for RelayCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayCredential")
            .field("account_id", &self.account_id)
            .field("node_id", &self.node_id)
            .field("secret", &self.secret)
            .field("status", &self.status)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// Abuse-control limits enforced by the relay before it forwards frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    max_connections: usize,
    max_connections_per_ip: usize,
    max_frames_per_minute: usize,
}

impl RelayLimits {
    pub fn new(
        max_connections: usize,
        max_connections_per_ip: usize,
        max_frames_per_minute: usize,
    ) -> Result<Self, RelayError> {
        if max_connections == 0 {
            return Err(RelayError::InvalidConfig(
                "max relay connections must be greater than zero",
            ));
        }
        if max_connections_per_ip == 0 {
            return Err(RelayError::InvalidConfig(
                "max relay connections per IP must be greater than zero",
            ));
        }
        if max_frames_per_minute == 0 {
            return Err(RelayError::InvalidConfig(
                "max relay frames per minute must be greater than zero",
            ));
        }

        Ok(Self {
            max_connections,
            max_connections_per_ip,
            max_frames_per_minute,
        })
    }
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            max_frames_per_minute: DEFAULT_MAX_FRAMES_PER_MINUTE,
        }
    }
}

/// Bounded offline mailbox policy for peer-encrypted envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayMailboxPolicy {
    max_envelopes_per_node: usize,
    envelope_ttl: Duration,
}

impl RelayMailboxPolicy {
    pub fn new(max_envelopes_per_node: usize, envelope_ttl: Duration) -> Result<Self, RelayError> {
        if max_envelopes_per_node == 0 {
            return Err(RelayError::InvalidConfig(
                "relay offline mailbox size must be greater than zero",
            ));
        }
        if envelope_ttl.is_zero() {
            return Err(RelayError::InvalidConfig(
                "relay offline mailbox TTL must be greater than zero",
            ));
        }

        Ok(Self {
            max_envelopes_per_node,
            envelope_ttl,
        })
    }
}

impl Default for RelayMailboxPolicy {
    fn default() -> Self {
        Self {
            max_envelopes_per_node: DEFAULT_MAX_OFFLINE_ENVELOPES_PER_NODE,
            envelope_ttl: Duration::from_secs(DEFAULT_OFFLINE_ENVELOPE_TTL_SECS),
        }
    }
}

/// Optional relay-local durable mailbox maintenance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayMailboxMaintenancePolicy {
    purge_interval: Option<Duration>,
}

impl RelayMailboxMaintenancePolicy {
    pub const fn disabled() -> Self {
        Self {
            purge_interval: None,
        }
    }

    pub fn every(purge_interval: Duration) -> Result<Self, RelayError> {
        if purge_interval.is_zero() {
            return Err(RelayError::InvalidConfig(
                "relay mailbox purge interval must be greater than zero",
            ));
        }
        Ok(Self {
            purge_interval: Some(purge_interval),
        })
    }

    pub const fn purge_interval(self) -> Option<Duration> {
        self.purge_interval
    }

    pub const fn is_enabled(self) -> bool {
        self.purge_interval.is_some()
    }
}

impl Default for RelayMailboxMaintenancePolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Optional persistence mode for relay mailbox envelopes.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RelayMailboxStorage {
    #[default]
    MemoryOnly,
    FileBacked(PathBuf),
}

impl RelayMailboxStorage {
    pub fn memory_only() -> Self {
        Self::MemoryOnly
    }

    pub fn file_backed(path: impl Into<PathBuf>) -> Result<Self, RelayError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay mailbox directory cannot be empty",
            ));
        }

        Ok(Self::FileBacked(path))
    }
}

impl fmt::Debug for RelayMailboxStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryOnly => formatter.write_str("RelayMailboxStorage::MemoryOnly"),
            Self::FileBacked(path) => formatter
                .debug_struct("RelayMailboxStorage::FileBacked")
                .field("path", path)
                .finish(),
        }
    }
}

/// Metadata-only usage accounting and quota policy for relay nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAccountingPolicy {
    window: Duration,
    max_envelopes_sent_per_node: Option<u64>,
    max_bytes_sent_per_node: Option<u64>,
}

impl RelayAccountingPolicy {
    pub fn new(
        window: Duration,
        max_envelopes_sent_per_node: Option<u64>,
        max_bytes_sent_per_node: Option<u64>,
    ) -> Result<Self, RelayError> {
        if window.is_zero() {
            return Err(RelayError::InvalidConfig(
                "relay accounting window must be greater than zero",
            ));
        }
        if max_envelopes_sent_per_node == Some(0) {
            return Err(RelayError::InvalidConfig(
                "relay envelope quota must be greater than zero when configured",
            ));
        }
        if max_bytes_sent_per_node == Some(0) {
            return Err(RelayError::InvalidConfig(
                "relay byte quota must be greater than zero when configured",
            ));
        }

        Ok(Self {
            window,
            max_envelopes_sent_per_node,
            max_bytes_sent_per_node,
        })
    }

    fn window_start_unix(&self, now_unix: u64) -> u64 {
        let window_secs = self.window.as_secs().max(1);
        now_unix - (now_unix % window_secs)
    }
}

impl Default for RelayAccountingPolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(DEFAULT_ACCOUNTING_WINDOW_SECS),
            max_envelopes_sent_per_node: None,
            max_bytes_sent_per_node: None,
        }
    }
}

/// Optional persistence mode for metadata-only relay accounting counters.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RelayAccountingStorage {
    #[default]
    MemoryOnly,
    FileBacked(PathBuf),
}

impl RelayAccountingStorage {
    pub fn memory_only() -> Self {
        Self::MemoryOnly
    }

    pub fn file_backed(path: impl Into<PathBuf>) -> Result<Self, RelayError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay accounting directory cannot be empty",
            ));
        }

        Ok(Self::FileBacked(path))
    }
}

impl fmt::Debug for RelayAccountingStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryOnly => formatter.write_str("RelayAccountingStorage::MemoryOnly"),
            Self::FileBacked(path) => formatter
                .debug_struct("RelayAccountingStorage::FileBacked")
                .field("path", path)
                .finish(),
        }
    }
}

/// Metadata-only relay accounting audit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAccountingAudit {
    pub node_id: Option<String>,
    pub records: usize,
    pub window_started_unix: Option<u64>,
    pub sessions_authenticated: u64,
    pub sessions_resumed: u64,
    pub envelopes_sent: u64,
    pub bytes_sent: u64,
    pub envelopes_received: u64,
    pub bytes_received: u64,
    pub envelopes_mailboxed: u64,
    pub bytes_mailboxed: u64,
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only relay session-state audit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionAudit {
    pub node_id: Option<String>,
    pub records: usize,
    pub active_records: usize,
    pub expired_records: usize,
    pub invalid_records: usize,
    pub oldest_created_unix_millis: Option<u64>,
    pub newest_last_seen_unix_millis: Option<u64>,
    pub next_expires_unix_millis: Option<u64>,
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only durable relay mailbox audit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMailboxAudit {
    pub node_id: Option<String>,
    pub retention_ttl_seconds: Option<u64>,
    pub nodes: usize,
    pub records: usize,
    pub invalid_records: usize,
    pub bytes: u64,
    pub oldest_queued_unix_millis: Option<u64>,
    pub newest_queued_unix_millis: Option<u64>,
    pub expired_records: Option<u64>,
    pub expired_bytes: Option<u64>,
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only durable relay mailbox retention purge result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMailboxPurgeReport {
    pub node_id: Option<String>,
    pub retention_ttl_seconds: u64,
    pub dry_run: bool,
    pub confirmed: bool,
    pub nodes: usize,
    pub records: usize,
    pub invalid_records: usize,
    pub bytes: u64,
    pub expired_records: u64,
    pub expired_bytes: u64,
    pub purged_records: u64,
    pub purged_bytes: u64,
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

/// Metadata-only abuse/dashboard counter window for relay enforcement events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayAbusePolicy {
    window: Duration,
}

impl RelayAbusePolicy {
    pub fn new(window: Duration) -> Result<Self, RelayError> {
        if window.is_zero() {
            return Err(RelayError::InvalidConfig(
                "relay abuse window must be greater than zero",
            ));
        }

        Ok(Self { window })
    }

    fn window_start_unix(&self, now_unix: u64) -> u64 {
        let window_secs = self.window.as_secs().max(1);
        now_unix - (now_unix % window_secs)
    }
}

impl Default for RelayAbusePolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(DEFAULT_ACCOUNTING_WINDOW_SECS),
        }
    }
}

/// Optional persistence mode for metadata-only relay abuse/dashboard counters.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RelayAbuseStorage {
    #[default]
    MemoryOnly,
    FileBacked(PathBuf),
}

impl RelayAbuseStorage {
    pub fn memory_only() -> Self {
        Self::MemoryOnly
    }

    pub fn file_backed(path: impl Into<PathBuf>) -> Result<Self, RelayError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay abuse directory cannot be empty",
            ));
        }

        Ok(Self::FileBacked(path))
    }
}

impl fmt::Debug for RelayAbuseStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryOnly => formatter.write_str("RelayAbuseStorage::MemoryOnly"),
            Self::FileBacked(path) => formatter
                .debug_struct("RelayAbuseStorage::FileBacked")
                .field("path", path)
                .finish(),
        }
    }
}

/// Metadata-only relay abuse/dashboard audit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAbuseAudit {
    pub node_id: Option<String>,
    pub records: usize,
    pub window_started_unix: Option<u64>,
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
    pub payload_displayed: bool,
    pub token_displayed: bool,
    pub token_hash_displayed: bool,
    pub key_material_displayed: bool,
    pub session_id_displayed: bool,
    pub ciphertext_displayed: bool,
    pub contents_displayed: bool,
}

/// Optional persistence mode for metadata-only authenticated relay session records.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RelaySessionStorage {
    #[default]
    MemoryOnly,
    FileBacked(PathBuf),
}

impl RelaySessionStorage {
    pub fn memory_only() -> Self {
        Self::MemoryOnly
    }

    pub fn file_backed(path: impl Into<PathBuf>) -> Result<Self, RelayError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay session state directory cannot be empty",
            ));
        }

        Ok(Self::FileBacked(path))
    }
}

impl fmt::Debug for RelaySessionStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryOnly => formatter.write_str("RelaySessionStorage::MemoryOnly"),
            Self::FileBacked(path) => formatter
                .debug_struct("RelaySessionStorage::FileBacked")
                .field("path", path)
                .finish(),
        }
    }
}

/// Session lifetime policy for authenticated relay clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaySessionPolicy {
    idle_timeout: Duration,
    max_session_ttl: Duration,
}

impl RelaySessionPolicy {
    pub fn new(idle_timeout: Duration, max_session_ttl: Duration) -> Result<Self, RelayError> {
        if idle_timeout.is_zero() {
            return Err(RelayError::InvalidConfig(
                "relay session idle timeout must be greater than zero",
            ));
        }
        if max_session_ttl.is_zero() {
            return Err(RelayError::InvalidConfig(
                "relay session TTL must be greater than zero",
            ));
        }

        Ok(Self {
            idle_timeout,
            max_session_ttl,
        })
    }
}

impl Default for RelaySessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(DEFAULT_SESSION_IDLE_TIMEOUT_SECS),
            max_session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
        }
    }
}

impl RelayConfig {
    pub fn new(
        bind_addr: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, RelayError> {
        let bind_addr = bind_addr.into();
        let auth_token = auth_token.into();

        if bind_addr.trim().is_empty() {
            return Err(RelayError::InvalidConfig("bind address cannot be empty"));
        }
        validate_token_for_bind(&bind_addr, &auth_token)?;

        Ok(Self {
            bind_addr,
            auth: RelayAuth::SharedToken(auth_token),
            limits: RelayLimits::default(),
            session_policy: RelaySessionPolicy::default(),
            session_storage: RelaySessionStorage::default(),
            mailbox_policy: RelayMailboxPolicy::default(),
            mailbox_storage: RelayMailboxStorage::default(),
            mailbox_maintenance: RelayMailboxMaintenancePolicy::default(),
            accounting_policy: RelayAccountingPolicy::default(),
            accounting_storage: RelayAccountingStorage::default(),
            abuse_policy: RelayAbusePolicy::default(),
            abuse_storage: RelayAbuseStorage::default(),
            admin: RelayAdminConfig::disabled(),
        })
    }

    pub fn with_scoped_credentials(
        bind_addr: impl Into<String>,
        credentials: Vec<RelayCredential>,
    ) -> Result<Self, RelayError> {
        let bind_addr = bind_addr.into();
        if bind_addr.trim().is_empty() {
            return Err(RelayError::InvalidConfig("bind address cannot be empty"));
        }
        validate_scoped_credentials_for_bind(&bind_addr, &credentials)?;

        Ok(Self {
            bind_addr,
            auth: RelayAuth::ScopedCredentials(credentials),
            limits: RelayLimits::default(),
            session_policy: RelaySessionPolicy::default(),
            session_storage: RelaySessionStorage::default(),
            mailbox_policy: RelayMailboxPolicy::default(),
            mailbox_storage: RelayMailboxStorage::default(),
            mailbox_maintenance: RelayMailboxMaintenancePolicy::default(),
            accounting_policy: RelayAccountingPolicy::default(),
            accounting_storage: RelayAccountingStorage::default(),
            abuse_policy: RelayAbusePolicy::default(),
            abuse_storage: RelayAbuseStorage::default(),
            admin: RelayAdminConfig::disabled(),
        })
    }

    pub fn with_scoped_credentials_file(
        bind_addr: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        let bind_addr = bind_addr.into();
        if bind_addr.trim().is_empty() {
            return Err(RelayError::InvalidConfig("bind address cannot be empty"));
        }
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(RelayError::InvalidConfig(
                "relay credential file path cannot be empty",
            ));
        }

        Ok(Self {
            bind_addr: bind_addr.clone(),
            auth: RelayAuth::ScopedCredentialsFile { path, bind_addr },
            limits: RelayLimits::default(),
            session_policy: RelaySessionPolicy::default(),
            session_storage: RelaySessionStorage::default(),
            mailbox_policy: RelayMailboxPolicy::default(),
            mailbox_storage: RelayMailboxStorage::default(),
            mailbox_maintenance: RelayMailboxMaintenancePolicy::default(),
            accounting_policy: RelayAccountingPolicy::default(),
            accounting_storage: RelayAccountingStorage::default(),
            abuse_policy: RelayAbusePolicy::default(),
            abuse_storage: RelayAbuseStorage::default(),
            admin: RelayAdminConfig::disabled(),
        })
    }

    pub fn with_limits(mut self, limits: RelayLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_session_policy(mut self, session_policy: RelaySessionPolicy) -> Self {
        self.session_policy = session_policy;
        self
    }

    pub fn with_session_storage(mut self, session_storage: RelaySessionStorage) -> Self {
        self.session_storage = session_storage;
        self
    }

    pub fn with_mailbox_policy(mut self, mailbox_policy: RelayMailboxPolicy) -> Self {
        self.mailbox_policy = mailbox_policy;
        self
    }

    pub fn with_mailbox_storage(mut self, mailbox_storage: RelayMailboxStorage) -> Self {
        self.mailbox_storage = mailbox_storage;
        self
    }

    pub fn with_mailbox_maintenance(
        mut self,
        mailbox_maintenance: RelayMailboxMaintenancePolicy,
    ) -> Self {
        self.mailbox_maintenance = mailbox_maintenance;
        self
    }

    pub fn with_accounting_policy(mut self, accounting_policy: RelayAccountingPolicy) -> Self {
        self.accounting_policy = accounting_policy;
        self
    }

    pub fn with_accounting_storage(mut self, accounting_storage: RelayAccountingStorage) -> Self {
        self.accounting_storage = accounting_storage;
        self
    }

    pub fn with_abuse_policy(mut self, abuse_policy: RelayAbusePolicy) -> Self {
        self.abuse_policy = abuse_policy;
        self
    }

    pub fn with_abuse_storage(mut self, abuse_storage: RelayAbuseStorage) -> Self {
        self.abuse_storage = abuse_storage;
        self
    }

    pub fn with_admin_token(
        mut self,
        token: impl Into<String>,
        credentials_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        self.admin = RelayAdminConfig::with_token(&self.bind_addr, token, credentials_file)?;
        Ok(self)
    }

    pub fn with_admin_tokens_file(
        mut self,
        tokens_file: impl Into<PathBuf>,
        credentials_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        self.admin =
            RelayAdminConfig::with_tokens_file(&self.bind_addr, tokens_file, credentials_file)?;
        Ok(self)
    }

    pub fn with_additional_admin_tokens_file(
        mut self,
        tokens_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        self.admin = self.admin.with_admin_tokens_file(tokens_file)?;
        Ok(self)
    }

    pub fn with_admin_tenants_file(
        mut self,
        tenants_file: impl Into<PathBuf>,
    ) -> Result<Self, RelayError> {
        self.admin = self.admin.with_tenants_file(tenants_file)?;
        Ok(self)
    }
}

/// Read a scoped relay credential manifest from disk.
///
/// The manifest stores token hashes, lifecycle status, and expiry metadata; it
/// must not contain raw relay tokens.
pub fn load_scoped_credentials_file(
    path: impl AsRef<Path>,
) -> Result<Vec<RelayCredential>, RelayError> {
    let path = path.as_ref();
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )?;
    parse_scoped_credentials_file(&contents)
}

/// Parse a scoped relay credential manifest.
pub fn parse_scoped_credentials_file(contents: &str) -> Result<Vec<RelayCredential>, RelayError> {
    let records = parse_credential_file_records(contents)?;
    if records.is_empty() {
        return Err(RelayError::InvalidConfig(
            "relay credential file must contain at least one credential",
        ));
    }

    records
        .into_iter()
        .map(CredentialFileRecord::into_credential)
        .collect()
}

fn parse_credential_file_records(contents: &str) -> Result<Vec<CredentialFileRecord>, RelayError> {
    let mut version = None::<String>;
    let mut current = None::<CredentialFileRecord>;
    let mut top_level_keys = ConfigKeyTracker::default();
    let mut records = Vec::new();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[credential]]" {
            if let Some(record) = current.take() {
                records.push(record);
            }
            current = Some(CredentialFileRecord::default());
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            RelayError::InvalidConfigValue(format!(
                "relay credential file line {line_number} must use key = value"
            ))
        })?;
        let key = key.trim();
        let value = clean_config_value(value);
        if key.is_empty() {
            return Err(RelayError::InvalidConfigValue(format!(
                "relay credential file line {line_number} must include a key"
            )));
        }

        if let Some(record) = current.as_mut() {
            record.set(key, &value, line_number)?;
            continue;
        }

        top_level_keys.record(key, "relay credential file", line_number)?;
        match key {
            "version" => version = Some(value),
            _ => {
                return Err(RelayError::InvalidConfigValue(format!(
                    "relay credential file line {line_number} has key before [[credential]]"
                )));
            }
        }
    }

    if let Some(record) = current.take() {
        records.push(record);
    }

    match version.as_deref() {
        Some(RELAY_CREDENTIALS_FILE_VERSION) => {}
        Some(_) => {
            return Err(RelayError::InvalidConfig(
                "relay credential file version is unsupported",
            ));
        }
        None => {
            return Err(RelayError::InvalidConfig(
                "relay credential file version is required",
            ));
        }
    }

    Ok(records)
}

fn load_admin_tokens_file(
    path: impl AsRef<Path>,
    bind_addr: &str,
) -> Result<RelayAdminTokenManifest, RelayError> {
    let path = path.as_ref();
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay admin tokens file",
        "read relay admin tokens file",
    )?;
    parse_admin_tokens_file(&contents, bind_addr)
}

fn parse_admin_tokens_file(
    contents: &str,
    bind_addr: &str,
) -> Result<RelayAdminTokenManifest, RelayError> {
    let mut version = None::<String>;
    let mut current = None::<AdminTokenFileRecord>;
    let mut top_level_keys = ConfigKeyTracker::default();
    let mut records = Vec::new();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[admin_token]]" {
            if let Some(record) = current.take() {
                records.push(record.into_token(bind_addr)?);
            }
            current = Some(AdminTokenFileRecord::default());
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            RelayError::InvalidConfigValue(format!(
                "relay admin tokens file line {line_number} must use key = value"
            ))
        })?;
        let key = key.trim();
        let value = clean_config_value(value);
        if key.is_empty() {
            return Err(RelayError::InvalidConfigValue(format!(
                "relay admin tokens file line {line_number} must include a key"
            )));
        }

        if let Some(record) = current.as_mut() {
            record.set(key, &value, line_number)?;
            continue;
        }

        top_level_keys.record(key, "relay admin tokens file", line_number)?;
        match key {
            "version" => version = Some(value),
            _ => {
                return Err(RelayError::InvalidConfigValue(format!(
                    "relay admin tokens file line {line_number} has key before [[admin_token]]"
                )));
            }
        }
    }

    if let Some(record) = current.take() {
        records.push(record.into_token(bind_addr)?);
    }

    match version.as_deref() {
        Some(RELAY_ADMIN_TOKENS_FILE_VERSION) => {}
        Some(_) => {
            return Err(RelayError::InvalidConfig(
                "relay admin tokens file version is unsupported",
            ));
        }
        None => {
            return Err(RelayError::InvalidConfig(
                "relay admin tokens file version is required",
            ));
        }
    }
    if records.is_empty() {
        return Err(RelayError::InvalidConfig(
            "relay admin tokens file must contain at least one admin token",
        ));
    }

    Ok(RelayAdminTokenManifest { records })
}

/// Add or rotate a newly issued relay credential in a live-reload manifest.
///
/// The manifest receives only token hashes and lifecycle metadata. Raw tokens
/// stay in the caller-controlled token file.
pub fn upsert_issued_relay_credential_in_file(
    path: impl AsRef<Path>,
    credential: &IssuedRelayCredential,
    replace_existing: bool,
) -> Result<CredentialManifestUpdate, RelayError> {
    let path = path.as_ref();
    let mut records = match read_optional_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )? {
        Some(contents) => parse_credential_file_records(&contents)?,
        None => Vec::new(),
    };
    let mut existing_index = None;
    for (index, record) in records.iter().enumerate() {
        if record.node_id()? == credential.node_id() {
            existing_index = Some(index);
            break;
        }
    }

    let updated_at_unix = current_unix_seconds();
    let record = CredentialFileRecord::from_issued(credential, updated_at_unix);
    let replaced = match existing_index {
        Some(index) if replace_existing => {
            records[index] = record;
            true
        }
        Some(_) => {
            return Err(RelayError::InvalidConfig(
                "relay credential already exists; use --replace to rotate it",
            ));
        }
        None => {
            records.push(record);
            false
        }
    };

    write_credential_manifest_records(path, &records)?;
    Ok(CredentialManifestUpdate {
        path: path.to_path_buf(),
        node_id: credential.node_id().to_string(),
        status: RelayCredentialStatus::Active,
        credentials: records.len(),
        replaced,
        token_displayed: false,
        contents_displayed: false,
    })
}

/// Add or rotate a hosted account relay credential from hash metadata.
///
/// The raw token is generated and stored by the admin client. The relay stores
/// only account/node metadata, token hash, token length, lifecycle state, and
/// display guards.
pub fn upsert_hosted_relay_credential_hash_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
    node_id: impl Into<String>,
    token_sha256_hex: impl Into<String>,
    token_length: usize,
    expires_at_unix: Option<u64>,
    replace_existing: bool,
) -> Result<CredentialManifestUpdate, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let node_id = validate_node_id(node_id.into())?;
    validate_token_length_metadata(token_length)?;
    let mut records = match read_optional_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )? {
        Some(contents) => parse_credential_file_records(&contents)?,
        None => Vec::new(),
    };
    let mut existing_index = None;
    for (index, record) in records.iter().enumerate() {
        if record.node_id()? == node_id {
            existing_index = Some(index);
            break;
        }
    }

    let now_unix = current_unix_seconds();
    let record = CredentialFileRecord::from_hosted_hash(
        account_id.clone(),
        node_id.clone(),
        token_sha256_hex,
        token_length,
        expires_at_unix,
        now_unix,
    )?;
    let replaced = match existing_index {
        Some(index) if replace_existing => {
            let existing_account = records[index].account_id()?;
            if existing_account != Some(account_id.as_str()) {
                return Err(RelayError::InvalidConfig(
                    "relay hosted credential belongs to a different account",
                ));
            }
            records[index] = record;
            true
        }
        Some(_) => {
            return Err(RelayError::InvalidConfig(
                "relay credential already exists; rotate is required",
            ));
        }
        None if replace_existing => {
            return Err(RelayError::InvalidConfig(
                "relay credential rotation target was not found",
            ));
        }
        None => {
            records.push(record);
            false
        }
    };

    write_credential_manifest_records(path, &records)?;
    Ok(CredentialManifestUpdate {
        path: path.to_path_buf(),
        node_id,
        status: RelayCredentialStatus::Active,
        credentials: records.len(),
        replaced,
        token_displayed: false,
        contents_displayed: false,
    })
}

/// Mark a credential as revoked in a live-reload manifest.
pub fn revoke_relay_credential_in_file(
    path: impl AsRef<Path>,
    node_id: impl Into<String>,
) -> Result<CredentialManifestUpdate, RelayError> {
    let path = path.as_ref();
    let node_id = validate_node_id(node_id.into())?;
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )?;
    let mut records = parse_credential_file_records(&contents)?;
    let updated_at_unix = current_unix_seconds();
    let mut revoked = false;

    for record in &mut records {
        if record.node_id()? == node_id {
            *record = record
                .clone()
                .with_status(RelayCredentialStatus::Revoked, updated_at_unix);
            revoked = true;
            break;
        }
    }

    if !revoked {
        return Err(RelayError::InvalidConfig(
            "relay credential node id was not found",
        ));
    }

    write_credential_manifest_records(path, &records)?;
    Ok(CredentialManifestUpdate {
        path: path.to_path_buf(),
        node_id,
        status: RelayCredentialStatus::Revoked,
        credentials: records.len(),
        replaced: false,
        token_displayed: false,
        contents_displayed: false,
    })
}

/// Mark a hosted account credential as revoked in a live-reload manifest.
pub fn revoke_hosted_relay_credential_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
    node_id: impl Into<String>,
) -> Result<CredentialManifestUpdate, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let node_id = validate_node_id(node_id.into())?;
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )?;
    let mut records = parse_credential_file_records(&contents)?;
    let updated_at_unix = current_unix_seconds();
    let mut revoked = false;

    for record in &mut records {
        if record.node_id()? == node_id && record.account_id()? == Some(account_id.as_str()) {
            *record = record
                .clone()
                .with_status(RelayCredentialStatus::Revoked, updated_at_unix);
            revoked = true;
            break;
        }
    }

    if !revoked {
        return Err(RelayError::InvalidConfig(
            "relay hosted credential was not found",
        ));
    }

    write_credential_manifest_records(path, &records)?;
    Ok(CredentialManifestUpdate {
        path: path.to_path_buf(),
        node_id,
        status: RelayCredentialStatus::Revoked,
        credentials: records.len(),
        replaced: false,
        token_displayed: false,
        contents_displayed: false,
    })
}

/// Revoke every credential for one hosted account without exposing hashes.
pub fn revoke_hosted_relay_credentials_for_account_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
) -> Result<HostedCredentialAudit, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let contents = match read_optional_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )? {
        Some(contents) => contents,
        None => return audit_hosted_relay_credentials_file(path, Some(&account_id)),
    };
    let mut records = parse_credential_file_records(&contents)?;
    let updated_at_unix = current_unix_seconds();
    let mut changed = false;

    for record in &mut records {
        if record.account_id()? == Some(account_id.as_str())
            && record.status.unwrap_or(RelayCredentialStatus::Active)
                != RelayCredentialStatus::Revoked
        {
            *record = record
                .clone()
                .with_status(RelayCredentialStatus::Revoked, updated_at_unix);
            changed = true;
        }
    }

    if changed {
        write_credential_manifest_records(path, &records)?;
    }
    audit_hosted_relay_credentials_file(path, Some(&account_id))
}

/// Revoke every credential for one hosted account node without exposing hashes.
pub fn revoke_hosted_relay_credentials_for_account_node_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
    node_id: impl Into<String>,
) -> Result<HostedCredentialAudit, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let node_id = validate_node_id(node_id.into())?;
    let contents = match read_optional_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )? {
        Some(contents) => contents,
        None => {
            return audit_hosted_relay_credentials_file_with_node(
                path,
                Some(&account_id),
                Some(&node_id),
            );
        }
    };
    let mut records = parse_credential_file_records(&contents)?;
    let updated_at_unix = current_unix_seconds();
    let mut changed = false;

    for record in &mut records {
        if record.account_id()? == Some(account_id.as_str())
            && record.node_id()? == node_id.as_str()
            && record.status.unwrap_or(RelayCredentialStatus::Active)
                != RelayCredentialStatus::Revoked
        {
            *record = record
                .clone()
                .with_status(RelayCredentialStatus::Revoked, updated_at_unix);
            changed = true;
        }
    }

    if changed {
        write_credential_manifest_records(path, &records)?;
    }
    audit_hosted_relay_credentials_file_with_node(path, Some(&account_id), Some(&node_id))
}

/// Suspend one hosted account by revoking tenant access and account credentials.
///
/// The tenant registry is revoked first so new sessions fail closed even if a
/// later credential-file update fails.
pub fn suspend_hosted_account_in_files(
    credentials_file: impl AsRef<Path>,
    tenants_file: impl AsRef<Path>,
    account_id: impl Into<String>,
) -> Result<HostedAccountSuspension, RelayError> {
    let credentials_file = credentials_file.as_ref();
    let tenants_file = tenants_file.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let tenant_update = revoke_hosted_tenant_in_file(tenants_file, account_id.clone())?;
    let credentials =
        revoke_hosted_relay_credentials_for_account_in_file(credentials_file, account_id.clone())?;
    let tenants = audit_hosted_tenants_file(tenants_file, Some(&account_id))?;

    Ok(HostedAccountSuspension {
        account_id,
        credentials_file: credentials_file.to_path_buf(),
        tenants_file: tenants_file.to_path_buf(),
        credentials: credentials.credentials,
        active: credentials.active,
        revoked: credentials.revoked,
        expired: credentials.expired,
        accounts: credentials.accounts,
        tenants: tenants.tenants,
        active_tenants: tenants.active_tenants,
        revoked_tenants: tenants.revoked_tenants,
        nodes: tenants.nodes,
        active_nodes: tenants.active_nodes,
        revoked_nodes: tenants.revoked_nodes,
        tenant_policies: tenants.policies,
        token_displayed: credentials.token_displayed
            || tenants.token_displayed
            || tenant_update.token_displayed,
        key_material_displayed: tenants.key_material_displayed
            || tenant_update.key_material_displayed,
        contents_displayed: credentials.contents_displayed
            || tenants.contents_displayed
            || tenant_update.contents_displayed,
    })
}

/// Suspend one hosted account node by revoking tenant-node access and node
/// credentials.
///
/// The tenant-node registry is revoked first so new sessions fail closed even
/// if a later credential-file update fails.
pub fn suspend_hosted_account_node_in_files(
    credentials_file: impl AsRef<Path>,
    tenants_file: impl AsRef<Path>,
    account_id: impl Into<String>,
    node_id: impl Into<String>,
) -> Result<HostedAccountNodeSuspension, RelayError> {
    let credentials_file = credentials_file.as_ref();
    let tenants_file = tenants_file.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let node_id = validate_node_id(node_id.into())?;
    let tenant_update =
        revoke_hosted_tenant_node_in_file(tenants_file, account_id.clone(), node_id.clone())?;
    let credentials = revoke_hosted_relay_credentials_for_account_node_in_file(
        credentials_file,
        account_id.clone(),
        node_id.clone(),
    )?;
    let tenants =
        audit_hosted_tenants_file_with_node(tenants_file, Some(&account_id), Some(&node_id))?;

    Ok(HostedAccountNodeSuspension {
        account_id,
        node_id,
        credentials_file: credentials_file.to_path_buf(),
        tenants_file: tenants_file.to_path_buf(),
        credentials: credentials.credentials,
        active: credentials.active,
        revoked: credentials.revoked,
        expired: credentials.expired,
        accounts: credentials.accounts,
        tenants: tenants.tenants,
        active_tenants: tenants.active_tenants,
        revoked_tenants: tenants.revoked_tenants,
        nodes: tenants.nodes,
        active_nodes: tenants.active_nodes,
        revoked_nodes: tenants.revoked_nodes,
        tenant_policies: tenants.policies,
        token_displayed: credentials.token_displayed
            || tenants.token_displayed
            || tenant_update.token_displayed,
        key_material_displayed: tenants.key_material_displayed
            || tenant_update.key_material_displayed,
        contents_displayed: credentials.contents_displayed
            || tenants.contents_displayed
            || tenant_update.contents_displayed,
    })
}

/// Return whether a live-reload credential manifest already has a node entry.
pub fn relay_credential_manifest_contains_node(
    path: impl AsRef<Path>,
    node_id: impl Into<String>,
) -> Result<bool, RelayError> {
    let path = path.as_ref();
    let node_id = validate_node_id(node_id.into())?;
    let contents = match read_optional_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )? {
        Some(contents) => contents,
        None => return Ok(false),
    };
    for record in parse_credential_file_records(&contents)? {
        if record.node_id()? == node_id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Summarize hosted relay credentials without exposing token hashes or contents.
pub fn audit_hosted_relay_credentials_file(
    path: impl AsRef<Path>,
    account_id: Option<&str>,
) -> Result<HostedCredentialAudit, RelayError> {
    audit_hosted_relay_credentials_file_with_node(path, account_id, None)
}

/// Summarize hosted relay credentials for an optional account/node filter
/// without exposing token hashes or contents.
pub fn audit_hosted_relay_credentials_file_with_node(
    path: impl AsRef<Path>,
    account_id: Option<&str>,
    node_id: Option<&str>,
) -> Result<HostedCredentialAudit, RelayError> {
    let path = path.as_ref();
    let account_id = account_id
        .map(|value| validate_account_id(value.to_string()))
        .transpose()?;
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    let records = match read_optional_regular_relay_file(
        path,
        "inspect relay credential file",
        "read relay credential file",
    )? {
        Some(contents) => parse_credential_file_records(&contents)?,
        None => Vec::new(),
    };
    let now_unix = current_unix_seconds();
    let mut accounts = HashSet::new();
    let mut credentials = 0_usize;
    let mut active = 0_usize;
    let mut revoked = 0_usize;
    let mut expired = 0_usize;

    for record in records {
        let record_account = record.account_id()?;
        let record_node = record.node_id()?;
        let account_mismatch = account_id
            .as_deref()
            .is_some_and(|target| record_account != Some(target));
        let node_mismatch = node_id
            .as_deref()
            .is_some_and(|target| record_node != target);
        if node_id.is_none() {
            if let Some(account) = record_account {
                accounts.insert(account.to_string());
            }
        }
        if node_id.is_some() && !account_mismatch && !node_mismatch {
            if let Some(account) = record_account {
                accounts.insert(account.to_string());
            }
        }
        if account_mismatch || node_mismatch {
            continue;
        }
        let status = record.status.unwrap_or(RelayCredentialStatus::Active);
        let is_expired = record
            .expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix);
        credentials += 1;
        if status == RelayCredentialStatus::Revoked {
            revoked += 1;
        } else if is_expired {
            expired += 1;
        } else {
            active += 1;
        }
    }

    Ok(HostedCredentialAudit {
        account_id,
        credentials,
        active,
        revoked,
        expired,
        accounts: accounts.len(),
        token_displayed: false,
        contents_displayed: false,
    })
}

/// Summarize hosted relay scoped admin-token records without exposing tokens,
/// token hashes, or manifest contents.
pub fn audit_hosted_admin_tokens_file(
    path: impl AsRef<Path>,
    account_id: Option<&str>,
    bind_addr: &str,
) -> Result<HostedAdminTokenAudit, RelayError> {
    let path = path.as_ref();
    let account_id = account_id
        .map(|value| validate_account_id(value.to_string()))
        .transpose()?;
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay admin tokens file",
        "read relay admin tokens file",
    )?;
    let manifest = parse_admin_tokens_file(&contents, bind_addr)?;
    let now_unix = current_unix_seconds();
    let mut accounts = HashSet::new();
    let mut records = 0_usize;
    let mut active = 0_usize;
    let mut revoked = 0_usize;
    let mut expired = 0_usize;
    let mut account_scoped_records = 0_usize;
    let mut global_records = 0_usize;
    let mut expiring_records = 0_usize;
    let mut next_expires_at_unix = None::<u64>;
    let mut last_expires_at_unix = None::<u64>;
    let mut scope_credentials = 0_usize;
    let mut scope_tenants = 0_usize;
    let mut scope_dashboard = 0_usize;
    let mut scope_sessions = 0_usize;
    let mut scope_mailbox_audit = 0_usize;
    let mut scope_mailbox_purge = 0_usize;

    for record in manifest.records {
        if account_id
            .as_deref()
            .is_some_and(|target| record.account_id.as_deref() != Some(target))
        {
            continue;
        }

        if let Some(record_account) = record.account_id.as_deref() {
            accounts.insert(record_account.to_string());
        }
        records += 1;
        if record.account_id.is_some() {
            account_scoped_records += 1;
        } else {
            global_records += 1;
        }

        let is_expired = record
            .expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix);
        if record.status == RelayCredentialStatus::Revoked {
            revoked += 1;
        } else if is_expired {
            expired += 1;
        } else {
            active += 1;
        }

        if let Some(expires_at_unix) = record.expires_at_unix {
            expiring_records += 1;
            last_expires_at_unix = Some(
                last_expires_at_unix
                    .map(|current| current.max(expires_at_unix))
                    .unwrap_or(expires_at_unix),
            );
            if record.status == RelayCredentialStatus::Active && expires_at_unix > now_unix {
                next_expires_at_unix = Some(
                    next_expires_at_unix
                        .map(|current| current.min(expires_at_unix))
                        .unwrap_or(expires_at_unix),
                );
            }
        }

        if record.scopes.credentials {
            scope_credentials += 1;
        }
        if record.scopes.tenants {
            scope_tenants += 1;
        }
        if record.scopes.dashboard {
            scope_dashboard += 1;
        }
        if record.scopes.sessions {
            scope_sessions += 1;
        }
        if record.scopes.mailbox_audit {
            scope_mailbox_audit += 1;
        }
        if record.scopes.mailbox_purge {
            scope_mailbox_purge += 1;
        }
    }

    Ok(HostedAdminTokenAudit {
        account_id,
        records,
        active,
        revoked,
        expired,
        account_scoped_records,
        global_records,
        accounts: accounts.len(),
        expiring_records,
        next_expires_at_unix,
        last_expires_at_unix,
        scope_credentials,
        scope_tenants,
        scope_dashboard,
        scope_sessions,
        scope_mailbox_audit,
        scope_mailbox_purge,
        payload_displayed: false,
        token_displayed: false,
        token_hash_displayed: false,
        key_material_displayed: false,
        session_id_displayed: false,
        ciphertext_displayed: false,
        contents_displayed: false,
    })
}

/// Add or reactivate a hosted tenant account in a metadata-only registry.
pub fn upsert_hosted_tenant_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
) -> Result<HostedTenantManifestUpdate, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let mut manifest = load_hosted_tenant_manifest_or_empty(path)?;
    let now_unix = current_unix_seconds();

    match manifest
        .tenants
        .iter_mut()
        .find(|tenant| tenant.account_id == account_id)
    {
        Some(tenant) => {
            tenant.status = HostedTenantStatus::Active;
            tenant.updated_at_unix = Some(now_unix);
        }
        None => manifest.tenants.push(HostedTenantRecord {
            account_id: account_id.clone(),
            status: HostedTenantStatus::Active,
            created_at_unix: Some(now_unix),
            updated_at_unix: Some(now_unix),
        }),
    }

    write_hosted_tenant_manifest(path, &manifest)?;
    Ok(hosted_tenant_update(
        path,
        account_id,
        None,
        HostedTenantStatus::Active,
        &manifest,
    ))
}

/// Mark a hosted tenant account revoked without deleting its metadata.
pub fn revoke_hosted_tenant_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
) -> Result<HostedTenantManifestUpdate, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let mut manifest = load_hosted_tenant_manifest_or_empty(path)?;
    let now_unix = current_unix_seconds();
    let Some(tenant) = manifest
        .tenants
        .iter_mut()
        .find(|tenant| tenant.account_id == account_id)
    else {
        return Err(RelayError::InvalidConfig(
            "hosted tenant account was not found",
        ));
    };
    tenant.status = HostedTenantStatus::Revoked;
    tenant.updated_at_unix = Some(now_unix);

    write_hosted_tenant_manifest(path, &manifest)?;
    Ok(hosted_tenant_update(
        path,
        account_id,
        None,
        HostedTenantStatus::Revoked,
        &manifest,
    ))
}

/// Add or reactivate one node's hosted policy metadata.
///
/// Hosted permissions are operator metadata only. They do not grant local peer
/// policy inside a user's runtime.
pub fn upsert_hosted_tenant_node_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
    node_id: impl Into<String>,
    permissions: HostedTenantPermissions,
    signing_key_id: Option<String>,
    exchange_key_id: Option<String>,
) -> Result<HostedTenantManifestUpdate, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let node_id = validate_node_id(node_id.into())?;
    let signing_key_id = signing_key_id
        .map(|value| validate_key_id(value, "signing key id"))
        .transpose()?;
    let exchange_key_id = exchange_key_id
        .map(|value| validate_key_id(value, "exchange key id"))
        .transpose()?;
    let mut manifest = load_hosted_tenant_manifest_or_empty(path)?;
    ensure_tenant_active(&manifest, &account_id)?;
    let now_unix = current_unix_seconds();

    match manifest
        .nodes
        .iter_mut()
        .find(|node| node.node_id == node_id)
    {
        Some(node) if node.account_id != account_id => {
            return Err(RelayError::InvalidConfig(
                "hosted tenant node belongs to a different account",
            ));
        }
        Some(node) => {
            node.status = HostedTenantStatus::Active;
            node.permissions = permissions;
            node.signing_key_id = signing_key_id;
            node.exchange_key_id = exchange_key_id;
            node.updated_at_unix = Some(now_unix);
        }
        None => manifest.nodes.push(HostedTenantNodeRecord {
            account_id: account_id.clone(),
            node_id: node_id.clone(),
            status: HostedTenantStatus::Active,
            permissions,
            signing_key_id,
            exchange_key_id,
            created_at_unix: Some(now_unix),
            updated_at_unix: Some(now_unix),
        }),
    }

    write_hosted_tenant_manifest(path, &manifest)?;
    Ok(hosted_tenant_update(
        path,
        account_id,
        Some(node_id),
        HostedTenantStatus::Active,
        &manifest,
    ))
}

/// Revoke one hosted node without deleting its policy metadata.
pub fn revoke_hosted_tenant_node_in_file(
    path: impl AsRef<Path>,
    account_id: impl Into<String>,
    node_id: impl Into<String>,
) -> Result<HostedTenantManifestUpdate, RelayError> {
    let path = path.as_ref();
    let account_id = validate_account_id(account_id.into())?;
    let node_id = validate_node_id(node_id.into())?;
    let mut manifest = load_hosted_tenant_manifest_or_empty(path)?;
    ensure_tenant_exists(&manifest, &account_id)?;
    let now_unix = current_unix_seconds();
    let Some(node) = manifest
        .nodes
        .iter_mut()
        .find(|node| node.account_id == account_id && node.node_id == node_id)
    else {
        return Err(RelayError::InvalidConfig(
            "hosted tenant node was not found",
        ));
    };
    node.status = HostedTenantStatus::Revoked;
    node.updated_at_unix = Some(now_unix);

    write_hosted_tenant_manifest(path, &manifest)?;
    Ok(hosted_tenant_update(
        path,
        account_id,
        Some(node_id),
        HostedTenantStatus::Revoked,
        &manifest,
    ))
}

/// Summarize hosted tenant metadata without exposing payloads, tokens, hashes,
/// private keys, ciphertext bodies, or manifest contents.
pub fn audit_hosted_tenants_file(
    path: impl AsRef<Path>,
    account_id: Option<&str>,
) -> Result<HostedTenantAudit, RelayError> {
    audit_hosted_tenants_file_with_node(path, account_id, None)
}

/// Summarize hosted tenant metadata for an optional account/node filter without
/// exposing payloads, tokens, hashes, private keys, ciphertext bodies, or
/// manifest contents.
pub fn audit_hosted_tenants_file_with_node(
    path: impl AsRef<Path>,
    account_id: Option<&str>,
    node_id: Option<&str>,
) -> Result<HostedTenantAudit, RelayError> {
    let path = path.as_ref();
    let account_id = account_id
        .map(|value| validate_account_id(value.to_string()))
        .transpose()?;
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    let manifest = match read_optional_regular_relay_file(
        path,
        "inspect hosted tenant file",
        "read hosted tenant file",
    )? {
        Some(contents) => parse_hosted_tenant_manifest(&contents)?,
        None => HostedTenantManifest::default(),
    };
    let mut tenants = 0_usize;
    let mut active_tenants = 0_usize;
    let mut revoked_tenants = 0_usize;
    let mut nodes = 0_usize;
    let mut active_nodes = 0_usize;
    let mut revoked_nodes = 0_usize;
    let mut policies = 0_usize;

    for tenant in &manifest.tenants {
        if account_id
            .as_deref()
            .is_some_and(|target| target != tenant.account_id)
        {
            continue;
        }
        tenants += 1;
        match tenant.status {
            HostedTenantStatus::Active => active_tenants += 1,
            HostedTenantStatus::Revoked => revoked_tenants += 1,
        }
    }
    for node in &manifest.nodes {
        if account_id
            .as_deref()
            .is_some_and(|target| target != node.account_id)
            || node_id
                .as_deref()
                .is_some_and(|target| target != node.node_id)
        {
            continue;
        }
        nodes += 1;
        match node.status {
            HostedTenantStatus::Active => active_nodes += 1,
            HostedTenantStatus::Revoked => revoked_nodes += 1,
        }
        if node.permissions.any() {
            policies += 1;
        }
    }

    Ok(HostedTenantAudit {
        account_id,
        tenants,
        active_tenants,
        revoked_tenants,
        nodes,
        active_nodes,
        revoked_nodes,
        policies,
        token_displayed: false,
        key_material_displayed: false,
        contents_displayed: false,
    })
}

/// Summarize relay session-state records without exposing session ids, tokens,
/// token hashes, payloads, ciphertext bodies, or private key material.
pub fn audit_relay_session_state_dir(
    root: impl AsRef<Path>,
    node_id: Option<&str>,
) -> Result<RelaySessionAudit, RelayError> {
    let root = root.as_ref();
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    let mut audit = RelaySessionAudit {
        node_id,
        records: 0,
        active_records: 0,
        expired_records: 0,
        invalid_records: 0,
        oldest_created_unix_millis: None,
        newest_last_seen_unix_millis: None,
        next_expires_unix_millis: None,
        payload_displayed: false,
        token_displayed: false,
        token_hash_displayed: false,
        key_material_displayed: false,
        session_id_displayed: false,
        ciphertext_displayed: false,
        contents_displayed: false,
    };

    if !relay_directory_exists(root, "inspect relay session state directory")? {
        return Ok(audit);
    }

    let now = current_unix_millis_u64();
    if let Some(node_id) = audit.node_id.as_deref() {
        let path = relay_session_record_path(root, node_id);
        if path.exists() {
            audit_session_state_file(&mut audit, &path, now)?;
        }
        return Ok(audit);
    }

    for entry in fs::read_dir(root)
        .map_err(|error| RelayError::io("read relay session state directory", error))?
    {
        let entry =
            entry.map_err(|error| RelayError::io("read relay session state entry", error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("session") {
            continue;
        }
        audit_session_state_file(&mut audit, &path, now)?;
    }

    Ok(audit)
}

fn audit_session_state_file(
    audit: &mut RelaySessionAudit,
    path: &Path,
    now_unix_millis: u64,
) -> Result<(), RelayError> {
    let record = match read_session_file(path) {
        Ok(Some(record)) => record,
        Ok(None) | Err(_) => {
            audit.invalid_records += 1;
            return Ok(());
        }
    };
    if audit
        .node_id
        .as_deref()
        .is_some_and(|node_id| record.node_id != node_id)
    {
        return Ok(());
    }

    audit.records += 1;
    audit.oldest_created_unix_millis = Some(
        audit
            .oldest_created_unix_millis
            .map_or(record.created_at_unix_millis, |existing| {
                existing.min(record.created_at_unix_millis)
            }),
    );
    audit.newest_last_seen_unix_millis = Some(
        audit
            .newest_last_seen_unix_millis
            .map_or(record.last_seen_unix_millis, |existing| {
                existing.max(record.last_seen_unix_millis)
            }),
    );

    if record.is_expired(now_unix_millis) {
        audit.expired_records += 1;
    } else {
        audit.active_records += 1;
        audit.next_expires_unix_millis = Some(
            audit
                .next_expires_unix_millis
                .map_or(record.expires_at_unix_millis, |existing| {
                    existing.min(record.expires_at_unix_millis)
                }),
        );
    }

    Ok(())
}

/// Summarize relay accounting counters without exposing tokens, token hashes,
/// session ids, payloads, ciphertext bodies, or private key material.
pub fn audit_relay_accounting_dir(
    root: impl AsRef<Path>,
    node_id: Option<&str>,
) -> Result<RelayAccountingAudit, RelayError> {
    let root = root.as_ref();
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    let mut audit = RelayAccountingAudit {
        node_id,
        records: 0,
        window_started_unix: None,
        sessions_authenticated: 0,
        sessions_resumed: 0,
        envelopes_sent: 0,
        bytes_sent: 0,
        envelopes_received: 0,
        bytes_received: 0,
        envelopes_mailboxed: 0,
        bytes_mailboxed: 0,
        payload_displayed: false,
        token_displayed: false,
        token_hash_displayed: false,
        key_material_displayed: false,
        session_id_displayed: false,
        ciphertext_displayed: false,
        contents_displayed: false,
    };

    if !relay_directory_exists(root, "inspect relay accounting directory")? {
        return Ok(audit);
    }

    let mut mixed_windows = false;
    for entry in fs::read_dir(root)
        .map_err(|error| RelayError::io("read relay accounting directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay accounting entry", error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("accounting") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }

        let Some(record) = read_accounting_file(&path)? else {
            continue;
        };
        if audit
            .node_id
            .as_deref()
            .is_some_and(|node_id| record.node_id != node_id)
        {
            continue;
        }

        audit.records += 1;
        if !mixed_windows {
            audit.window_started_unix = match audit.window_started_unix {
                None => Some(record.window_started_unix),
                Some(existing) if existing == record.window_started_unix => Some(existing),
                Some(_) => {
                    mixed_windows = true;
                    None
                }
            };
        }
        audit.sessions_authenticated = audit
            .sessions_authenticated
            .saturating_add(record.sessions_authenticated);
        audit.sessions_resumed = audit
            .sessions_resumed
            .saturating_add(record.sessions_resumed);
        audit.envelopes_sent = audit.envelopes_sent.saturating_add(record.envelopes_sent);
        audit.bytes_sent = audit.bytes_sent.saturating_add(record.bytes_sent);
        audit.envelopes_received = audit
            .envelopes_received
            .saturating_add(record.envelopes_received);
        audit.bytes_received = audit.bytes_received.saturating_add(record.bytes_received);
        audit.envelopes_mailboxed = audit
            .envelopes_mailboxed
            .saturating_add(record.envelopes_mailboxed);
        audit.bytes_mailboxed = audit.bytes_mailboxed.saturating_add(record.bytes_mailboxed);
    }

    Ok(audit)
}

/// Summarize durable relay mailbox files without exposing frame contents,
/// ciphertext bodies, plaintext payloads, tokens, hashes, or session ids.
pub fn audit_relay_mailbox_dir(
    root: impl AsRef<Path>,
    node_id: Option<&str>,
    retention_ttl: Option<Duration>,
) -> Result<RelayMailboxAudit, RelayError> {
    let root = root.as_ref();
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    if retention_ttl.is_some_and(|ttl| ttl.is_zero()) {
        return Err(RelayError::InvalidConfig(
            "relay mailbox audit TTL must be greater than zero",
        ));
    }
    let retention_ttl_seconds = retention_ttl.map(|ttl| ttl.as_secs());
    let retention_ttl_millis = retention_ttl.map(|ttl| ttl.as_millis());
    let mut audit = RelayMailboxAudit {
        node_id,
        retention_ttl_seconds,
        nodes: 0,
        records: 0,
        invalid_records: 0,
        bytes: 0,
        oldest_queued_unix_millis: None,
        newest_queued_unix_millis: None,
        expired_records: retention_ttl.map(|_| 0),
        expired_bytes: retention_ttl.map(|_| 0),
        payload_displayed: false,
        token_displayed: false,
        token_hash_displayed: false,
        key_material_displayed: false,
        session_id_displayed: false,
        ciphertext_displayed: false,
        contents_displayed: false,
    };

    if !relay_directory_exists(root, "inspect relay mailbox directory")? {
        return Ok(audit);
    }

    let now_millis = current_unix_millis();
    if let Some(node_id) = audit.node_id.as_deref() {
        let node_dir = root.join(sanitize_identifier(node_id));
        if relay_directory_exists(&node_dir, "inspect relay mailbox node directory")? {
            audit_mailbox_node_dir(&mut audit, &node_dir, now_millis, retention_ttl_millis)?;
        }
        return Ok(audit);
    }

    for entry in
        fs::read_dir(root).map_err(|error| RelayError::io("read relay mailbox directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay mailbox entry", error))?;
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        audit_mailbox_node_dir(&mut audit, &entry.path(), now_millis, retention_ttl_millis)?;
    }

    Ok(audit)
}

/// Delete expired durable relay mailbox files after an explicit operator
/// confirmation, or report the same retention set in dry-run mode.
///
/// The report is aggregate-only and does not expose stored frames, ciphertext
/// bodies, plaintext payloads, tokens, hashes, private keys, or session ids.
pub fn purge_relay_mailbox_dir(
    root: impl AsRef<Path>,
    node_id: Option<&str>,
    retention_ttl: Duration,
    dry_run: bool,
) -> Result<RelayMailboxPurgeReport, RelayError> {
    let root = root.as_ref();
    if retention_ttl.is_zero() {
        return Err(RelayError::InvalidConfig(
            "relay mailbox purge TTL must be greater than zero",
        ));
    }
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    let mut report = RelayMailboxPurgeReport {
        node_id,
        retention_ttl_seconds: retention_ttl.as_secs(),
        dry_run,
        confirmed: !dry_run,
        nodes: 0,
        records: 0,
        invalid_records: 0,
        bytes: 0,
        expired_records: 0,
        expired_bytes: 0,
        purged_records: 0,
        purged_bytes: 0,
        payload_displayed: false,
        token_displayed: false,
        token_hash_displayed: false,
        key_material_displayed: false,
        session_id_displayed: false,
        ciphertext_displayed: false,
        contents_displayed: false,
    };

    if !relay_directory_exists(root, "inspect relay mailbox directory")? {
        return Ok(report);
    }

    let now_millis = current_unix_millis();
    let retention_ttl_millis = retention_ttl.as_millis();
    if let Some(node_id) = report.node_id.as_deref() {
        let node_dir = root.join(sanitize_identifier(node_id));
        if relay_directory_exists(&node_dir, "inspect relay mailbox node directory")? {
            purge_mailbox_node_dir(&mut report, &node_dir, now_millis, retention_ttl_millis)?;
        }
        return Ok(report);
    }

    for entry in
        fs::read_dir(root).map_err(|error| RelayError::io("read relay mailbox directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay mailbox entry", error))?;
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        purge_mailbox_node_dir(&mut report, &entry.path(), now_millis, retention_ttl_millis)?;
    }

    Ok(report)
}

/// Summarize relay abuse/dashboard counters without exposing secrets, payloads,
/// ciphertext bodies, token hashes, frame contents, or session ids.
pub fn audit_relay_abuse_dir(
    root: impl AsRef<Path>,
    node_id: Option<&str>,
) -> Result<RelayAbuseAudit, RelayError> {
    let root = root.as_ref();
    let node_id = node_id
        .map(|value| validate_node_id(value.to_string()))
        .transpose()?;
    let mut audit = RelayAbuseAudit {
        node_id,
        records: 0,
        window_started_unix: None,
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
        payload_displayed: false,
        token_displayed: false,
        token_hash_displayed: false,
        key_material_displayed: false,
        session_id_displayed: false,
        ciphertext_displayed: false,
        contents_displayed: false,
    };

    if !relay_directory_exists(root, "inspect relay abuse directory")? {
        return Ok(audit);
    }

    let mut mixed_windows = false;
    for entry in
        fs::read_dir(root).map_err(|error| RelayError::io("read relay abuse directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay abuse entry", error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("abuse") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }

        let Some(record) = read_abuse_file(&path)? else {
            continue;
        };
        if audit
            .node_id
            .as_deref()
            .is_some_and(|node_id| record.node_id.as_deref() != Some(node_id))
        {
            continue;
        }

        audit.records += 1;
        if !mixed_windows {
            audit.window_started_unix = match audit.window_started_unix {
                None => Some(record.window_started_unix),
                Some(existing) if existing == record.window_started_unix => Some(existing),
                Some(_) => {
                    mixed_windows = true;
                    None
                }
            };
        }
        audit.admin_unauthorized = audit
            .admin_unauthorized
            .saturating_add(record.admin_unauthorized);
        audit.admin_failed = audit.admin_failed.saturating_add(record.admin_failed);
        audit.unauthorized_sessions = audit
            .unauthorized_sessions
            .saturating_add(record.unauthorized_sessions);
        audit.credential_denied_sessions = audit
            .credential_denied_sessions
            .saturating_add(record.credential_denied_sessions);
        audit.tenant_denied_sessions = audit
            .tenant_denied_sessions
            .saturating_add(record.tenant_denied_sessions);
        audit.rate_limited_sessions = audit
            .rate_limited_sessions
            .saturating_add(record.rate_limited_sessions);
        audit.session_expired = audit.session_expired.saturating_add(record.session_expired);
        audit.quota_denied_forwards = audit
            .quota_denied_forwards
            .saturating_add(record.quota_denied_forwards);
        audit.undelivered_forwards = audit
            .undelivered_forwards
            .saturating_add(record.undelivered_forwards);
        audit.mailbox_rejected_forwards = audit
            .mailbox_rejected_forwards
            .saturating_add(record.mailbox_rejected_forwards);
        audit.malformed_client_frames = audit
            .malformed_client_frames
            .saturating_add(record.malformed_client_frames);
    }

    Ok(audit)
}

fn hosted_tenant_registry_authorizes_node(
    path: impl AsRef<Path>,
    node_id: &str,
) -> Result<(), RelayError> {
    let node_id = validate_node_id(node_id.to_string())?;
    let manifest = load_hosted_tenant_manifest_or_empty(path.as_ref())?;
    let Some(node) = manifest.nodes.iter().find(|node| node.node_id == node_id) else {
        return Err(RelayError::InvalidConfig(
            "hosted tenant node was not found",
        ));
    };
    ensure_account_node_active(&manifest, &node.account_id, &node.node_id)
}

fn hosted_tenant_registry_authorizes_account_node(
    path: impl AsRef<Path>,
    account_id: &str,
    node_id: &str,
) -> Result<(), RelayError> {
    let account_id = validate_account_id(account_id.to_string())?;
    let node_id = validate_node_id(node_id.to_string())?;
    let manifest = load_hosted_tenant_manifest_or_empty(path.as_ref())?;
    ensure_account_node_active(&manifest, &account_id, &node_id)
}

/// Return the SHA-256 hash used by relay credential manifest entries.
pub fn relay_token_sha256_hex(token: &str) -> Result<String, RelayError> {
    validate_token(token)?;
    Ok(sha256_hex(token.as_bytes()))
}

/// Issue a new scoped relay credential for a node.
///
/// The returned value contains the raw token so callers can write it to the
/// intended client's secret store, but the rendered manifest entry contains
/// only the token hash and metadata.
pub fn issue_relay_credential(
    node_id: impl Into<String>,
    expires_at_unix: Option<u64>,
) -> Result<IssuedRelayCredential, RelayError> {
    let mut token_bytes = [0_u8; ISSUED_RELAY_TOKEN_BYTES];
    OsRng.fill_bytes(&mut token_bytes);
    issue_relay_credential_from_token_bytes(
        node_id,
        &token_bytes,
        expires_at_unix,
        current_unix_seconds(),
    )
}

/// Issue a scoped relay credential from caller-provided entropy.
///
/// This is public for deterministic tests and offline admin tooling. Callers
/// should pass at least 32 random bytes for production use.
pub fn issue_relay_credential_from_token_bytes(
    node_id: impl Into<String>,
    token_bytes: &[u8],
    expires_at_unix: Option<u64>,
    created_at_unix: u64,
) -> Result<IssuedRelayCredential, RelayError> {
    if token_bytes.len() < ISSUED_RELAY_TOKEN_BYTES {
        return Err(RelayError::InvalidConfig(
            "issued relay credentials require at least 32 bytes of entropy",
        ));
    }

    let node_id = validate_node_id(node_id.into())?;
    let token = hex_encode(token_bytes);
    validate_token(&token)?;
    let token_sha256_hex = relay_token_sha256_hex(&token)?;
    let token_length = token.len();
    validate_token_length_metadata(token_length)?;
    let _credential =
        RelayCredential::from_sha256_hex(node_id.clone(), token_sha256_hex.clone(), token_length)?
            .with_expires_at_unix(expires_at_unix);

    Ok(IssuedRelayCredential {
        account_id: None,
        node_id,
        token,
        token_sha256_hex,
        token_length,
        expires_at_unix,
        created_at_unix,
    })
}

/// Render the manifest entry for a newly issued credential.
pub fn render_issued_credential_manifest_entry(credential: &IssuedRelayCredential) -> String {
    let account_id = credential
        .account_id
        .as_ref()
        .map(|account_id| format!("account_id = \"{account_id}\"\n"))
        .unwrap_or_default();
    let expires_at = credential
        .expires_at_unix
        .map(|expires_at| format!("expires_at_unix = {expires_at}\n"))
        .unwrap_or_default();

    format!(
        "[[credential]]\n\
{}\
node_id = \"{}\"\n\
token_sha256_hex = \"{}\"\n\
token_length = {}\n\
status = \"active\"\n\
{}\
created_at_unix = {}\n\
updated_at_unix = {}\n\
payload_displayed = false\n\
token_displayed = false\n",
        account_id,
        credential.node_id,
        credential.token_sha256_hex,
        credential.token_length,
        expires_at,
        credential.created_at_unix,
        credential.created_at_unix
    )
}

/// Write the issued raw token to a new file for delivery to the intended node.
///
/// The file is created with owner-only permissions on Unix and is never
/// overwritten.
pub fn write_issued_relay_token_file(
    credential: &IssuedRelayCredential,
    path: impl AsRef<Path>,
) -> Result<(), RelayError> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_relay_directory(parent, "create issued relay token directory")?;
    }
    if regular_relay_file_exists(path, "inspect issued relay token file")? {
        return Err(RelayError::io(
            "create issued relay token file",
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "issued relay token file already exists",
            ),
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| RelayError::io("create issued relay token file", error))?;
    file.write_all(credential.token.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|error| RelayError::io("write issued relay token file", error))
}

fn write_credential_manifest_records(
    path: &Path,
    records: &[CredentialFileRecord],
) -> Result<(), RelayError> {
    let contents = render_credential_manifest_records(records)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_relay_directory(parent, "create relay credential file directory")?;
    }
    write_relay_metadata_file(
        path,
        &contents,
        "inspect relay credential file replacement",
        "create temporary relay credential file",
        "write temporary relay credential file",
        "replace relay credential file",
    )
}

fn render_credential_manifest_records(
    records: &[CredentialFileRecord],
) -> Result<String, RelayError> {
    if records.is_empty() {
        return Err(RelayError::InvalidConfig(
            "relay credential file must contain at least one credential",
        ));
    }

    let mut seen_nodes = HashSet::new();
    let mut output = format!("version = \"{}\"\n\n", RELAY_CREDENTIALS_FILE_VERSION);
    for (index, record) in records.iter().enumerate() {
        let node_id = record.node_id()?.to_string();
        if !seen_nodes.insert(node_id) {
            return Err(RelayError::InvalidConfig(
                "relay scoped credentials must have unique node ids",
            ));
        }
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&record.render()?);
    }
    Ok(output)
}

fn ensure_relay_directory(path: &Path, action: &'static str) -> Result<(), RelayError> {
    if relay_directory_exists(path, action)? {
        return Ok(());
    }

    fs::create_dir_all(path).map_err(|error| RelayError::io(action, error))?;
    if relay_directory_exists(path, "inspect relay directory")? {
        return Ok(());
    }

    Err(RelayError::io(
        "inspect relay directory",
        io::Error::new(
            io::ErrorKind::NotFound,
            "relay directory path was not created",
        ),
    ))
}

fn relay_directory_exists(path: &Path, action: &'static str) -> Result<bool, RelayError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RelayError::io(
                    action,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "relay directory path is not a directory",
                    ),
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(RelayError::io(action, error)),
    }
}

fn write_relay_metadata_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    create_temp_action: &'static str,
    write_temp_action: &'static str,
    replace_action: &'static str,
) -> Result<(), RelayError> {
    for attempt in 0..RELAY_METADATA_REPLACE_ATTEMPTS {
        match write_relay_metadata_file_once(
            path,
            contents,
            inspect_action,
            create_temp_action,
            write_temp_action,
            replace_action,
        ) {
            Ok(()) => return Ok(()),
            Err(error)
                if relay_metadata_replace_should_retry(&error)
                    && attempt + 1 < RELAY_METADATA_REPLACE_ATTEMPTS =>
            {
                thread::sleep(RELAY_METADATA_REPLACE_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("relay metadata replacement loop always returns")
}

fn write_relay_metadata_file_once(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    create_temp_action: &'static str,
    write_temp_action: &'static str,
    replace_action: &'static str,
) -> Result<(), RelayError> {
    let expected_metadata = inspect_optional_regular_relay_file(path, inspect_action)?;
    let temp_path = relay_metadata_temp_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|error| RelayError::io(create_temp_action, error))?;
    if let Err(error) = file
        .write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&temp_path);
        return Err(RelayError::io(write_temp_action, error));
    }
    drop(file);

    let result = replace_regular_relay_file_with_temp(
        path,
        &temp_path,
        expected_metadata.as_ref(),
        inspect_action,
        replace_action,
    );
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn relay_metadata_replace_should_retry(error: &RelayError) -> bool {
    match error {
        RelayError::Io { source, .. } => {
            matches!(
                source.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::AlreadyExists
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
            ) || relay_metadata_replace_invalid_input_should_retry(source)
        }
        RelayError::InvalidConfig(_)
        | RelayError::InvalidConfigValue(_)
        | RelayError::Protocol(_) => false,
    }
}

fn relay_metadata_replace_invalid_input_should_retry(source: &io::Error) -> bool {
    if source.kind() != io::ErrorKind::InvalidInput {
        return false;
    }

    let message = source.to_string();
    message.contains("relay file path changed before replacement")
        || message.contains("relay file path appeared before replacement")
}

fn replace_regular_relay_file_with_temp(
    path: &Path,
    temp_path: &Path,
    expected_metadata: Option<&fs::Metadata>,
    inspect_action: &'static str,
    replace_action: &'static str,
) -> Result<(), RelayError> {
    match expected_metadata {
        Some(expected_metadata) => {
            let current_metadata = inspect_existing_regular_relay_file(path, inspect_action)?;
            if !relay_manifest_file_metadata_matches(expected_metadata, &current_metadata) {
                return Err(RelayError::io(
                    inspect_action,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "relay file path changed before replacement",
                    ),
                ));
            }
        }
        None => {
            if inspect_optional_regular_relay_file(path, inspect_action)?.is_some() {
                return Err(RelayError::io(
                    inspect_action,
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "relay file path appeared before replacement",
                    ),
                ));
            }
        }
    }

    replace_regular_relay_file_after_validation(path, temp_path, expected_metadata, replace_action)
}

#[cfg(not(windows))]
fn replace_regular_relay_file_after_validation(
    path: &Path,
    temp_path: &Path,
    _expected_metadata: Option<&fs::Metadata>,
    replace_action: &'static str,
) -> Result<(), RelayError> {
    fs::rename(temp_path, path).map_err(|error| RelayError::io(replace_action, error))
}

#[cfg(windows)]
fn replace_regular_relay_file_after_validation(
    path: &Path,
    temp_path: &Path,
    expected_metadata: Option<&fs::Metadata>,
    replace_action: &'static str,
) -> Result<(), RelayError> {
    if expected_metadata.is_none() {
        return fs::rename(temp_path, path).map_err(|error| RelayError::io(replace_action, error));
    }

    let backup_path = relay_metadata_backup_path(path)?;
    fs::rename(path, &backup_path).map_err(|error| RelayError::io(replace_action, error))?;

    if let Err(error) = fs::rename(temp_path, path) {
        let restore_result = fs::rename(&backup_path, path);
        let _ = fs::remove_file(temp_path);
        if let Err(restore_error) = restore_result {
            return Err(RelayError::io(
                "restore relay file after failed replacement",
                restore_error,
            ));
        }
        return Err(RelayError::io(replace_action, error));
    }

    let _ = fs::remove_file(&backup_path);
    Ok(())
}

fn relay_metadata_temp_path(path: &Path) -> Result<PathBuf, RelayError> {
    relay_metadata_sidecar_path(path, "tmp")
}

#[cfg(windows)]
fn relay_metadata_backup_path(path: &Path) -> Result<PathBuf, RelayError> {
    relay_metadata_sidecar_path(path, "backup")
}

fn relay_metadata_sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, RelayError> {
    let file_name = path.file_name().ok_or(RelayError::InvalidConfig(
        "relay metadata file path must include a file name",
    ))?;
    Ok(path.with_file_name(format!(
        ".{}.{}-{}-{}",
        file_name.to_string_lossy(),
        suffix,
        std::process::id(),
        current_unix_nanos()
    )))
}

fn read_required_regular_relay_file(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
) -> Result<String, RelayError> {
    read_optional_regular_relay_file(path, inspect_action, read_action)?.ok_or_else(|| {
        RelayError::io(
            inspect_action,
            io::Error::new(io::ErrorKind::NotFound, "relay file path is missing"),
        )
    })
}

fn read_optional_regular_relay_file(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
) -> Result<Option<String>, RelayError> {
    let Some(metadata) = inspect_optional_regular_relay_file(path, inspect_action)? else {
        return Ok(None);
    };

    read_existing_regular_relay_file_with_metadata(path, inspect_action, read_action, &metadata)
        .map(Some)
}

fn read_existing_regular_relay_file_with_metadata(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
    metadata: &fs::Metadata,
) -> Result<String, RelayError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| RelayError::io(read_action, error))?;
    let path_metadata = inspect_existing_regular_relay_file(path, inspect_action)?;
    if !relay_manifest_file_metadata_matches(metadata, &path_metadata) {
        return Err(RelayError::io(
            inspect_action,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay file path changed while reading",
            ),
        ));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| RelayError::io(inspect_action, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_RELAY_MANIFEST_FILE_BYTES
        || !relay_manifest_file_metadata_matches(metadata, &opened_metadata)
    {
        return Err(RelayError::io(
            read_action,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay file path changed while reading",
            ),
        ));
    }

    let mut contents = String::new();
    let limit = MAX_RELAY_MANIFEST_FILE_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_string(&mut contents)
        .map_err(|error| RelayError::io(read_action, error))?;
    if contents.len() as u64 > MAX_RELAY_MANIFEST_FILE_BYTES {
        return Err(RelayError::io(
            read_action,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("relay file exceeds {MAX_RELAY_MANIFEST_FILE_BYTES} bytes"),
            ),
        ));
    }
    Ok(contents)
}

fn regular_relay_file_exists(
    path: &Path,
    inspect_action: &'static str,
) -> Result<bool, RelayError> {
    inspect_optional_regular_relay_file(path, inspect_action).map(|metadata| metadata.is_some())
}

fn inspect_optional_regular_relay_file(
    path: &Path,
    inspect_action: &'static str,
) -> Result<Option<fs::Metadata>, RelayError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => inspect_regular_relay_file_metadata(metadata, inspect_action).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(RelayError::io(inspect_action, error)),
    }
}

fn inspect_existing_regular_relay_file(
    path: &Path,
    inspect_action: &'static str,
) -> Result<fs::Metadata, RelayError> {
    fs::symlink_metadata(path)
        .map_err(|error| RelayError::io(inspect_action, error))
        .and_then(|metadata| inspect_regular_relay_file_metadata(metadata, inspect_action))
}

fn inspect_regular_relay_file_metadata(
    metadata: fs::Metadata,
    inspect_action: &'static str,
) -> Result<fs::Metadata, RelayError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(RelayError::io(
            inspect_action,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay file path is not a regular file",
            ),
        ));
    }
    if metadata.len() > MAX_RELAY_MANIFEST_FILE_BYTES {
        return Err(RelayError::io(
            inspect_action,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("relay file exceeds {MAX_RELAY_MANIFEST_FILE_BYTES} bytes"),
            ),
        ));
    }
    Ok(metadata)
}

fn relay_manifest_file_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && relay_manifest_file_identity_matches(expected, current)
}

#[cfg(unix)]
fn relay_manifest_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn relay_manifest_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(not(any(unix, windows)))]
fn relay_manifest_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

fn load_hosted_tenant_manifest_or_empty(path: &Path) -> Result<HostedTenantManifest, RelayError> {
    match read_optional_regular_relay_file(
        path,
        "inspect hosted tenant file",
        "read hosted tenant file",
    )? {
        Some(contents) => parse_hosted_tenant_manifest(&contents),
        None => Ok(HostedTenantManifest::default()),
    }
}

fn parse_hosted_tenant_manifest(contents: &str) -> Result<HostedTenantManifest, RelayError> {
    let mut version = None::<String>;
    let mut top_level_keys = ConfigKeyTracker::default();
    let mut section = None::<HostedTenantManifestSection>;
    let mut tenants = Vec::new();
    let mut nodes = Vec::new();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[tenant]]" || line == "[[tenant_node]]" {
            if let Some(previous) = section.take() {
                push_hosted_tenant_section(previous, &mut tenants, &mut nodes)?;
            }
            section = if line == "[[tenant]]" {
                Some(HostedTenantManifestSection::Tenant(
                    HostedTenantFileRecord::default(),
                ))
            } else {
                Some(HostedTenantManifestSection::Node(
                    HostedTenantNodeFileRecord::default(),
                ))
            };
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            RelayError::InvalidConfigValue(format!(
                "hosted tenant file line {line_number} must use key = value"
            ))
        })?;
        let key = key.trim();
        let value = clean_config_value(value);
        if key.is_empty() {
            return Err(RelayError::InvalidConfigValue(format!(
                "hosted tenant file line {line_number} must include a key"
            )));
        }

        match section.as_mut() {
            Some(HostedTenantManifestSection::Tenant(record)) => {
                record.set(key, &value, line_number)?;
            }
            Some(HostedTenantManifestSection::Node(record)) => {
                record.set(key, &value, line_number)?;
            }
            None => match key {
                "version" => {
                    top_level_keys.record(key, "hosted tenant file", line_number)?;
                    version = Some(value);
                }
                _ => {
                    top_level_keys.record(key, "hosted tenant file", line_number)?;
                    return Err(RelayError::InvalidConfigValue(format!(
                        "hosted tenant file line {line_number} has key before a section"
                    )));
                }
            },
        }
    }

    if let Some(previous) = section.take() {
        push_hosted_tenant_section(previous, &mut tenants, &mut nodes)?;
    }

    match version.as_deref() {
        Some(HOSTED_TENANT_FILE_VERSION) => {}
        Some(_) => {
            return Err(RelayError::InvalidConfig(
                "hosted tenant file version is unsupported",
            ));
        }
        None => {
            return Err(RelayError::InvalidConfig(
                "hosted tenant file version is required",
            ));
        }
    }

    validate_hosted_tenant_manifest(&tenants, &nodes)?;
    Ok(HostedTenantManifest { tenants, nodes })
}

enum HostedTenantManifestSection {
    Tenant(HostedTenantFileRecord),
    Node(HostedTenantNodeFileRecord),
}

fn push_hosted_tenant_section(
    section: HostedTenantManifestSection,
    tenants: &mut Vec<HostedTenantRecord>,
    nodes: &mut Vec<HostedTenantNodeRecord>,
) -> Result<(), RelayError> {
    match section {
        HostedTenantManifestSection::Tenant(record) => tenants.push(record.into_record()?),
        HostedTenantManifestSection::Node(record) => nodes.push(record.into_record()?),
    }
    Ok(())
}

fn validate_hosted_tenant_manifest(
    tenants: &[HostedTenantRecord],
    nodes: &[HostedTenantNodeRecord],
) -> Result<(), RelayError> {
    let mut account_ids = HashSet::new();
    for tenant in tenants {
        if !account_ids.insert(tenant.account_id.clone()) {
            return Err(RelayError::InvalidConfig(
                "hosted tenant accounts must be unique",
            ));
        }
    }
    let mut node_ids = HashSet::new();
    for node in nodes {
        if !account_ids.contains(&node.account_id) {
            return Err(RelayError::InvalidConfig(
                "hosted tenant node references an unknown account",
            ));
        }
        if !node_ids.insert(node.node_id.clone()) {
            return Err(RelayError::InvalidConfig(
                "hosted tenant nodes must be unique",
            ));
        }
    }
    Ok(())
}

fn write_hosted_tenant_manifest(
    path: &Path,
    manifest: &HostedTenantManifest,
) -> Result<(), RelayError> {
    validate_hosted_tenant_manifest(&manifest.tenants, &manifest.nodes)?;
    let mut tenants = manifest.tenants.clone();
    tenants.sort_by(|left, right| left.account_id.cmp(&right.account_id));
    let mut nodes = manifest.nodes.clone();
    nodes.sort_by(|left, right| {
        left.account_id
            .cmp(&right.account_id)
            .then(left.node_id.cmp(&right.node_id))
    });

    let mut contents = format!("version = \"{}\"\n", HOSTED_TENANT_FILE_VERSION);
    for tenant in &tenants {
        contents.push_str("\n[[tenant]]\n");
        contents.push_str(&format!(
            "account_id = \"{}\"\nstatus = \"{}\"\n",
            tenant.account_id,
            tenant.status.as_str()
        ));
        if let Some(created_at_unix) = tenant.created_at_unix {
            contents.push_str(&format!("created_at_unix = {created_at_unix}\n"));
        }
        if let Some(updated_at_unix) = tenant.updated_at_unix {
            contents.push_str(&format!("updated_at_unix = {updated_at_unix}\n"));
        }
        contents.push_str(
            "payload_displayed = false\ntoken_displayed = false\nkey_material_displayed = false\ncontents_displayed = false\n",
        );
    }
    for node in &nodes {
        contents.push_str("\n[[tenant_node]]\n");
        contents.push_str(&format!(
            "account_id = \"{}\"\nnode_id = \"{}\"\nstatus = \"{}\"\nmessages = {}\nstreams = {}\nrooms = {}\nfiles = {}\nmailbox = {}\n",
            node.account_id,
            node.node_id,
            node.status.as_str(),
            node.permissions.messages,
            node.permissions.streams,
            node.permissions.rooms,
            node.permissions.files,
            node.permissions.mailbox
        ));
        if let Some(signing_key_id) = &node.signing_key_id {
            contents.push_str(&format!("signing_key_id = \"{signing_key_id}\"\n"));
        }
        if let Some(exchange_key_id) = &node.exchange_key_id {
            contents.push_str(&format!("exchange_key_id = \"{exchange_key_id}\"\n"));
        }
        if let Some(created_at_unix) = node.created_at_unix {
            contents.push_str(&format!("created_at_unix = {created_at_unix}\n"));
        }
        if let Some(updated_at_unix) = node.updated_at_unix {
            contents.push_str(&format!("updated_at_unix = {updated_at_unix}\n"));
        }
        contents.push_str(
            "payload_displayed = false\ntoken_displayed = false\nkey_material_displayed = false\ncontents_displayed = false\n",
        );
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_relay_directory(parent, "create hosted tenant file directory")?;
    }
    write_relay_metadata_file(
        path,
        &contents,
        "inspect hosted tenant file replacement",
        "create temporary hosted tenant file",
        "write temporary hosted tenant file",
        "replace hosted tenant file",
    )
}

fn hosted_tenant_update(
    path: &Path,
    account_id: String,
    node_id: Option<String>,
    status: HostedTenantStatus,
    manifest: &HostedTenantManifest,
) -> HostedTenantManifestUpdate {
    HostedTenantManifestUpdate {
        path: path.to_path_buf(),
        account_id,
        node_id,
        status,
        tenants: manifest.tenants.len(),
        nodes: manifest.nodes.len(),
        token_displayed: false,
        key_material_displayed: false,
        contents_displayed: false,
    }
}

fn ensure_tenant_exists(
    manifest: &HostedTenantManifest,
    account_id: &str,
) -> Result<(), RelayError> {
    manifest
        .tenants
        .iter()
        .find(|tenant| tenant.account_id == account_id)
        .map(|_| ())
        .ok_or(RelayError::InvalidConfig(
            "hosted tenant account was not found",
        ))
}

fn ensure_tenant_active(
    manifest: &HostedTenantManifest,
    account_id: &str,
) -> Result<(), RelayError> {
    let tenant = manifest
        .tenants
        .iter()
        .find(|tenant| tenant.account_id == account_id)
        .ok_or(RelayError::InvalidConfig(
            "hosted tenant account was not found",
        ))?;
    if tenant.status != HostedTenantStatus::Active {
        return Err(RelayError::InvalidConfig(
            "hosted tenant account is revoked",
        ));
    }
    Ok(())
}

fn ensure_account_node_active(
    manifest: &HostedTenantManifest,
    account_id: &str,
    node_id: &str,
) -> Result<(), RelayError> {
    ensure_tenant_active(manifest, account_id)?;
    let node = manifest
        .nodes
        .iter()
        .find(|node| node.account_id == account_id && node.node_id == node_id)
        .ok_or(RelayError::InvalidConfig(
            "hosted tenant node was not found",
        ))?;
    if node.status != HostedTenantStatus::Active {
        return Err(RelayError::InvalidConfig("hosted tenant node is revoked"));
    }
    Ok(())
}

fn parse_manifest_bool(value: &str, key: &str, line_number: usize) -> Result<bool, RelayError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(RelayError::InvalidConfigValue(format!(
            "hosted tenant file line {line_number} {key} must be true or false"
        ))),
    }
}

fn parse_manifest_u64(value: &str, key: &str, line_number: usize) -> Result<u64, RelayError> {
    value.parse::<u64>().map_err(|_| {
        RelayError::InvalidConfigValue(format!(
            "hosted tenant file line {line_number} {key} must be an unsigned integer"
        ))
    })
}

fn authorize_scoped_credentials(
    credentials: &[RelayCredential],
    node_id: &str,
    token: &str,
    now_unix: u64,
) -> bool {
    let mut authorized = false;
    for credential in credentials {
        authorized |= credential.authorize_at(node_id, token, now_unix);
    }
    authorized
}

fn validate_scoped_credentials_for_bind(
    bind_addr: &str,
    credentials: &[RelayCredential],
) -> Result<(), RelayError> {
    if credentials.is_empty() {
        return Err(RelayError::InvalidConfig(
            "relay scoped credentials cannot be empty",
        ));
    }

    let mut nodes = HashSet::new();
    for credential in credentials {
        credential.validate_for_bind(bind_addr)?;
        if !nodes.insert(credential.node_id.clone()) {
            return Err(RelayError::InvalidConfig(
                "relay scoped credentials must have unique node ids",
            ));
        }
    }

    Ok(())
}

/// Running relay handle used by tests and local smoke checks.
pub struct RelayHandle {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    maintenance_join: Option<JoinHandle<()>>,
}

impl RelayHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        if let Some(join) = self.maintenance_join.take() {
            let _ = join.join();
        }
    }
}

/// Errors produced by the relay server.
#[derive(Debug)]
pub enum RelayError {
    InvalidConfig(&'static str),
    InvalidConfigValue(String),
    Io {
        action: &'static str,
        source: io::Error,
    },
    Protocol(String),
}

impl RelayError {
    fn io(action: &'static str, source: io::Error) -> Self {
        Self::Io { action, source }
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid relay config: {reason}"),
            Self::InvalidConfigValue(reason) => {
                write!(formatter, "invalid relay config: {reason}")
            }
            Self::Io { action, source } => write!(formatter, "{action}: {source}"),
            Self::Protocol(reason) => write!(formatter, "relay protocol error: {reason}"),
        }
    }
}

impl std::error::Error for RelayError {}

#[derive(Clone, PartialEq, Eq)]
struct RelayAdminTokenManifest {
    records: Vec<RelayAdminTokenRecord>,
}

impl RelayAdminTokenManifest {
    fn authorize(
        &self,
        token: &str,
        action: RelayAdminAction,
    ) -> Result<RelayAdminAuthorization, RelayError> {
        let now_unix = current_unix_seconds();
        for record in &self.records {
            if record.matches(token, now_unix) {
                if !record.scopes.allows(action) {
                    return Err(RelayError::Protocol("admin_scope_denied".to_string()));
                }
                return Ok(RelayAdminAuthorization {
                    account_id: record.account_id.clone(),
                });
            }
        }
        Err(RelayError::Protocol("admin_unauthorized".to_string()))
    }
}

impl fmt::Debug for RelayAdminTokenManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAdminTokenManifest")
            .field("records", &self.records.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RelayAdminTokenRecord {
    account_id: Option<String>,
    token_sha256_hex: String,
    token_length: usize,
    status: RelayCredentialStatus,
    expires_at_unix: Option<u64>,
    scopes: RelayAdminTokenScopes,
}

impl RelayAdminTokenRecord {
    fn matches(&self, token: &str, now_unix: u64) -> bool {
        self.status == RelayCredentialStatus::Active
            && self
                .expires_at_unix
                .is_none_or(|expires_at| expires_at > now_unix)
            && token.len() == self.token_length
            && relay_token_sha256_hex(token).is_ok_and(|actual| {
                constant_time_eq(actual.as_bytes(), self.token_sha256_hex.as_bytes())
            })
    }
}

impl fmt::Debug for RelayAdminTokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAdminTokenRecord")
            .field("account_id", &self.account_id)
            .field("token_sha256_hex", &"<redacted>")
            .field("token_length", &self.token_length)
            .field("status", &self.status)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[derive(Clone, Default)]
struct ConfigKeyTracker {
    seen: HashSet<String>,
}

impl ConfigKeyTracker {
    fn record(&mut self, key: &str, label: &str, line_number: usize) -> Result<(), RelayError> {
        if !self.seen.insert(key.to_string()) {
            return Err(RelayError::InvalidConfigValue(format!(
                "{label} line {line_number} contains duplicate key {key}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct AdminTokenFileRecord {
    account_id: Option<String>,
    token_sha256_hex: Option<String>,
    token_length: Option<usize>,
    status: Option<RelayCredentialStatus>,
    expires_at_unix: Option<u64>,
    scopes: RelayAdminTokenScopes,
    keys: ConfigKeyTracker,
}

impl AdminTokenFileRecord {
    fn set(&mut self, key: &str, value: &str, line_number: usize) -> Result<(), RelayError> {
        self.keys
            .record(key, "relay admin tokens file", line_number)?;
        match key {
            "account_id" => self.account_id = Some(validate_account_id(value.to_string())?),
            "token_sha256_hex" => self.token_sha256_hex = Some(value.to_string()),
            "token_length" => {
                self.token_length = Some(value.parse::<usize>().map_err(|_| {
                    RelayError::InvalidConfigValue(format!(
                        "relay admin tokens file line {line_number} token_length must be an unsigned integer"
                    ))
                })?);
            }
            "status" => self.status = Some(RelayCredentialStatus::parse(value)?),
            "expires_at_unix" => {
                self.expires_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    RelayError::InvalidConfigValue(format!(
                        "relay admin tokens file line {line_number} expires_at_unix must be an unsigned integer"
                    ))
                })?);
            }
            "scope_credentials" => {
                self.scopes.credentials = parse_config_bool(value, line_number, key)?
            }
            "scope_tenants" => self.scopes.tenants = parse_config_bool(value, line_number, key)?,
            "scope_dashboard" => {
                self.scopes.dashboard = parse_config_bool(value, line_number, key)?
            }
            "scope_sessions" => self.scopes.sessions = parse_config_bool(value, line_number, key)?,
            "scope_mailbox_audit" => {
                self.scopes.mailbox_audit = parse_config_bool(value, line_number, key)?
            }
            "scope_mailbox_purge" => {
                self.scopes.mailbox_purge = parse_config_bool(value, line_number, key)?
            }
            "payload_displayed"
            | "token_displayed"
            | "token_hash_displayed"
            | "key_material_displayed"
            | "session_id_displayed"
            | "ciphertext_displayed"
            | "contents_displayed" => {
                if value != "false" {
                    return Err(RelayError::InvalidConfigValue(format!(
                        "relay admin tokens file line {line_number} {key} must be false"
                    )));
                }
            }
            "label" | "created_at_unix" | "updated_at_unix" => {}
            _ => {
                return Err(RelayError::InvalidConfigValue(format!(
                    "relay admin tokens file line {line_number} uses unsupported key {key}"
                )));
            }
        }
        Ok(())
    }

    fn into_token(self, bind_addr: &str) -> Result<RelayAdminTokenRecord, RelayError> {
        let token_sha256_hex = self.token_sha256_hex.ok_or(RelayError::InvalidConfig(
            "relay admin tokens file entry is missing token_sha256_hex",
        ))?;
        let token_length = self.token_length.ok_or(RelayError::InvalidConfig(
            "relay admin tokens file entry is missing token_length",
        ))?;
        let token_sha256_hex = validate_token_sha256_hex(token_sha256_hex)?;
        validate_hashed_token_for_bind(bind_addr, &token_sha256_hex, token_length)?;
        if !self.scopes.any() {
            return Err(RelayError::InvalidConfig(
                "relay admin tokens file entry must grant at least one scope",
            ));
        }

        Ok(RelayAdminTokenRecord {
            account_id: self.account_id,
            token_sha256_hex,
            token_length,
            status: self.status.unwrap_or(RelayCredentialStatus::Active),
            expires_at_unix: self.expires_at_unix,
            scopes: self.scopes,
        })
    }
}

#[derive(Clone, Default)]
struct CredentialFileRecord {
    account_id: Option<String>,
    node_id: Option<String>,
    token_sha256_hex: Option<String>,
    token_length: Option<usize>,
    status: Option<RelayCredentialStatus>,
    expires_at_unix: Option<u64>,
    created_at_unix: Option<u64>,
    updated_at_unix: Option<u64>,
    keys: ConfigKeyTracker,
}

impl CredentialFileRecord {
    fn set(&mut self, key: &str, value: &str, line_number: usize) -> Result<(), RelayError> {
        self.keys
            .record(key, "relay credential file", line_number)?;
        match key {
            "account_id" => self.account_id = Some(validate_account_id(value.to_string())?),
            "node_id" => self.node_id = Some(value.to_string()),
            "token_sha256_hex" => self.token_sha256_hex = Some(value.to_string()),
            "token_length" => {
                self.token_length = Some(value.parse::<usize>().map_err(|_| {
                    RelayError::InvalidConfigValue(format!(
                        "relay credential file line {line_number} token_length must be an unsigned integer"
                    ))
                })?);
            }
            "status" => self.status = Some(RelayCredentialStatus::parse(value)?),
            "expires_at_unix" => {
                self.expires_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    RelayError::InvalidConfigValue(format!(
                        "relay credential file line {line_number} expires_at_unix must be an unsigned integer"
                    ))
                })?);
            }
            "created_at_unix" => {
                self.created_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    RelayError::InvalidConfigValue(format!(
                        "relay credential file line {line_number} created_at_unix must be an unsigned integer"
                    ))
                })?);
            }
            "updated_at_unix" => {
                self.updated_at_unix = Some(value.parse::<u64>().map_err(|_| {
                    RelayError::InvalidConfigValue(format!(
                        "relay credential file line {line_number} updated_at_unix must be an unsigned integer"
                    ))
                })?);
            }
            "payload_displayed" | "token_displayed" => {
                if value != "false" {
                    return Err(RelayError::InvalidConfigValue(format!(
                        "relay credential file line {line_number} {key} must be false"
                    )));
                }
            }
            "label" => {}
            _ => {
                return Err(RelayError::InvalidConfigValue(format!(
                    "relay credential file line {line_number} uses unsupported key {key}"
                )));
            }
        }
        Ok(())
    }

    fn from_issued(credential: &IssuedRelayCredential, updated_at_unix: u64) -> Self {
        Self {
            account_id: credential.account_id.clone(),
            node_id: Some(credential.node_id.clone()),
            token_sha256_hex: Some(credential.token_sha256_hex.clone()),
            token_length: Some(credential.token_length),
            status: Some(RelayCredentialStatus::Active),
            expires_at_unix: credential.expires_at_unix,
            created_at_unix: Some(credential.created_at_unix),
            updated_at_unix: Some(updated_at_unix),
            keys: ConfigKeyTracker::default(),
        }
    }

    fn from_hosted_hash(
        account_id: impl Into<String>,
        node_id: impl Into<String>,
        token_sha256_hex: impl Into<String>,
        token_length: usize,
        expires_at_unix: Option<u64>,
        created_at_unix: u64,
    ) -> Result<Self, RelayError> {
        Ok(Self {
            account_id: Some(validate_account_id(account_id.into())?),
            node_id: Some(validate_node_id(node_id.into())?),
            token_sha256_hex: Some(validate_token_sha256_hex(token_sha256_hex.into())?),
            token_length: Some(token_length),
            status: Some(RelayCredentialStatus::Active),
            expires_at_unix,
            created_at_unix: Some(created_at_unix),
            updated_at_unix: Some(created_at_unix),
            keys: ConfigKeyTracker::default(),
        })
    }

    fn account_id(&self) -> Result<Option<&str>, RelayError> {
        self.account_id
            .as_deref()
            .map(validate_account_id_ref)
            .transpose()
    }

    fn node_id(&self) -> Result<&str, RelayError> {
        self.node_id
            .as_deref()
            .ok_or(RelayError::InvalidConfig(
                "relay credential file entry is missing node_id",
            ))
            .and_then(validate_node_id_ref)
    }

    fn with_status(mut self, status: RelayCredentialStatus, updated_at_unix: u64) -> Self {
        self.status = Some(status);
        self.updated_at_unix = Some(updated_at_unix);
        self
    }

    fn render(&self) -> Result<String, RelayError> {
        let node_id = self.node_id()?;
        let token_sha256_hex = self
            .token_sha256_hex
            .as_ref()
            .ok_or(RelayError::InvalidConfig(
                "relay credential file entry is missing token_sha256_hex",
            ))?;
        let token_length = self.token_length.ok_or(RelayError::InvalidConfig(
            "relay credential file entry is missing token_length",
        ))?;
        validate_token_sha256_hex(token_sha256_hex.clone())?;
        validate_token_length_metadata(token_length)?;

        let mut output = "[[credential]]\n".to_string();
        if let Some(account_id) = self.account_id()? {
            output.push_str(&format!("account_id = \"{account_id}\"\n"));
        }
        output.push_str(&format!(
            "node_id = \"{node_id}\"\n\
token_sha256_hex = \"{token_sha256_hex}\"\n\
token_length = {token_length}\n\
status = \"{}\"\n",
            self.status
                .unwrap_or(RelayCredentialStatus::Active)
                .as_str()
        ));
        if let Some(expires_at_unix) = self.expires_at_unix {
            output.push_str(&format!("expires_at_unix = {expires_at_unix}\n"));
        }
        if let Some(created_at_unix) = self.created_at_unix {
            output.push_str(&format!("created_at_unix = {created_at_unix}\n"));
        }
        if let Some(updated_at_unix) = self.updated_at_unix {
            output.push_str(&format!("updated_at_unix = {updated_at_unix}\n"));
        }
        output.push_str("payload_displayed = false\ntoken_displayed = false\n");
        Ok(output)
    }

    fn into_credential(self) -> Result<RelayCredential, RelayError> {
        let node_id = self.node_id.ok_or(RelayError::InvalidConfig(
            "relay credential file entry is missing node_id",
        ))?;
        let token_sha256_hex = self.token_sha256_hex.ok_or(RelayError::InvalidConfig(
            "relay credential file entry is missing token_sha256_hex",
        ))?;
        let token_length = self.token_length.ok_or(RelayError::InvalidConfig(
            "relay credential file entry is missing token_length",
        ))?;

        let mut credential =
            RelayCredential::from_sha256_hex(node_id, token_sha256_hex, token_length)?;
        if let Some(account_id) = self.account_id {
            credential = credential.with_account_id(account_id)?;
        }
        Ok(credential
            .with_status(self.status.unwrap_or(RelayCredentialStatus::Active))
            .with_expires_at_unix(self.expires_at_unix))
    }
}

#[derive(Debug, Clone, Default)]
struct HostedTenantManifest {
    tenants: Vec<HostedTenantRecord>,
    nodes: Vec<HostedTenantNodeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedTenantRecord {
    account_id: String,
    status: HostedTenantStatus,
    created_at_unix: Option<u64>,
    updated_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedTenantNodeRecord {
    account_id: String,
    node_id: String,
    status: HostedTenantStatus,
    permissions: HostedTenantPermissions,
    signing_key_id: Option<String>,
    exchange_key_id: Option<String>,
    created_at_unix: Option<u64>,
    updated_at_unix: Option<u64>,
}

#[derive(Clone, Default)]
struct HostedTenantFileRecord {
    account_id: Option<String>,
    status: Option<HostedTenantStatus>,
    created_at_unix: Option<u64>,
    updated_at_unix: Option<u64>,
    keys: ConfigKeyTracker,
}

#[derive(Clone, Default)]
struct HostedTenantNodeFileRecord {
    account_id: Option<String>,
    node_id: Option<String>,
    status: Option<HostedTenantStatus>,
    messages: Option<bool>,
    streams: Option<bool>,
    rooms: Option<bool>,
    files: Option<bool>,
    mailbox: Option<bool>,
    signing_key_id: Option<String>,
    exchange_key_id: Option<String>,
    created_at_unix: Option<u64>,
    updated_at_unix: Option<u64>,
    keys: ConfigKeyTracker,
}

impl HostedTenantFileRecord {
    fn set(&mut self, key: &str, value: &str, line_number: usize) -> Result<(), RelayError> {
        self.keys.record(key, "hosted tenant file", line_number)?;
        match key {
            "account_id" => self.account_id = Some(validate_account_id(value.to_string())?),
            "status" => self.status = Some(HostedTenantStatus::parse(value)?),
            "created_at_unix" => {
                self.created_at_unix = Some(parse_manifest_u64(value, key, line_number)?);
            }
            "updated_at_unix" => {
                self.updated_at_unix = Some(parse_manifest_u64(value, key, line_number)?);
            }
            "payload_displayed"
            | "token_displayed"
            | "key_material_displayed"
            | "contents_displayed" => {
                if value != "false" {
                    return Err(RelayError::InvalidConfigValue(format!(
                        "hosted tenant file line {line_number} {key} must be false"
                    )));
                }
            }
            _ => {
                return Err(RelayError::InvalidConfigValue(format!(
                    "hosted tenant file line {line_number} uses unsupported tenant key {key}"
                )));
            }
        }
        Ok(())
    }

    fn into_record(self) -> Result<HostedTenantRecord, RelayError> {
        Ok(HostedTenantRecord {
            account_id: self.account_id.ok_or(RelayError::InvalidConfig(
                "hosted tenant entry is missing account_id",
            ))?,
            status: self.status.unwrap_or(HostedTenantStatus::Active),
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
        })
    }
}

impl HostedTenantNodeFileRecord {
    fn set(&mut self, key: &str, value: &str, line_number: usize) -> Result<(), RelayError> {
        self.keys.record(key, "hosted tenant file", line_number)?;
        match key {
            "account_id" => self.account_id = Some(validate_account_id(value.to_string())?),
            "node_id" => self.node_id = Some(validate_node_id(value.to_string())?),
            "status" => self.status = Some(HostedTenantStatus::parse(value)?),
            "messages" => self.messages = Some(parse_manifest_bool(value, key, line_number)?),
            "streams" => self.streams = Some(parse_manifest_bool(value, key, line_number)?),
            "rooms" => self.rooms = Some(parse_manifest_bool(value, key, line_number)?),
            "files" => self.files = Some(parse_manifest_bool(value, key, line_number)?),
            "mailbox" => self.mailbox = Some(parse_manifest_bool(value, key, line_number)?),
            "signing_key_id" => {
                self.signing_key_id = Some(validate_key_id(value.to_string(), "signing key id")?);
            }
            "exchange_key_id" => {
                self.exchange_key_id = Some(validate_key_id(value.to_string(), "exchange key id")?);
            }
            "created_at_unix" => {
                self.created_at_unix = Some(parse_manifest_u64(value, key, line_number)?);
            }
            "updated_at_unix" => {
                self.updated_at_unix = Some(parse_manifest_u64(value, key, line_number)?);
            }
            "payload_displayed"
            | "token_displayed"
            | "key_material_displayed"
            | "contents_displayed" => {
                if value != "false" {
                    return Err(RelayError::InvalidConfigValue(format!(
                        "hosted tenant file line {line_number} {key} must be false"
                    )));
                }
            }
            _ => {
                return Err(RelayError::InvalidConfigValue(format!(
                    "hosted tenant file line {line_number} uses unsupported node key {key}"
                )));
            }
        }
        Ok(())
    }

    fn into_record(self) -> Result<HostedTenantNodeRecord, RelayError> {
        Ok(HostedTenantNodeRecord {
            account_id: self.account_id.ok_or(RelayError::InvalidConfig(
                "hosted tenant node entry is missing account_id",
            ))?,
            node_id: self.node_id.ok_or(RelayError::InvalidConfig(
                "hosted tenant node entry is missing node_id",
            ))?,
            status: self.status.unwrap_or(HostedTenantStatus::Active),
            permissions: HostedTenantPermissions {
                messages: self.messages.unwrap_or(false),
                streams: self.streams.unwrap_or(false),
                rooms: self.rooms.unwrap_or(false),
                files: self.files.unwrap_or(false),
                mailbox: self.mailbox.unwrap_or(false),
            },
            signing_key_id: self.signing_key_id,
            exchange_key_id: self.exchange_key_id,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
        })
    }
}

/// Run a relay server until the process exits.
pub fn run_blocking(config: RelayConfig) -> Result<(), RelayError> {
    let listener = TcpListener::bind(&config.bind_addr)
        .map_err(|error| RelayError::io("bind relay listener", error))?;
    let bind_addr = config.bind_addr.clone();
    let mailbox_policy = config.mailbox_policy;
    let mailbox_storage_for_maintenance = config.mailbox_storage.clone();
    let mailbox_maintenance = config.mailbox_maintenance;
    let hub = Arc::new(RelayHub::new(RelayHubConfig {
        auth: config.auth,
        limits: config.limits,
        session_policy: config.session_policy,
        session_storage: config.session_storage,
        mailbox_policy,
        mailbox_storage: config.mailbox_storage,
        accounting_policy: config.accounting_policy,
        accounting_storage: config.accounting_storage,
        abuse_policy: config.abuse_policy,
        abuse_storage: config.abuse_storage,
        admin: config.admin,
    })?);
    let _maintenance_join = spawn_mailbox_maintenance_worker(
        mailbox_storage_for_maintenance,
        mailbox_policy,
        mailbox_maintenance,
        None,
    );

    println!(
        "conU relay listening on {}; payloads not observed",
        listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or(bind_addr)
    );

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let hub = hub.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, hub);
                });
            }
            Err(error) => return Err(RelayError::io("accept relay connection", error)),
        }
    }

    Ok(())
}

/// Spawn a relay server in the background for tests and local validation.
pub fn spawn_relay(config: RelayConfig) -> Result<RelayHandle, RelayError> {
    let listener = TcpListener::bind(&config.bind_addr)
        .map_err(|error| RelayError::io("bind relay listener", error))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| RelayError::io("configure relay listener", error))?;
    let local_addr = listener
        .local_addr()
        .map_err(|error| RelayError::io("read relay listener address", error))?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let mailbox_policy = config.mailbox_policy;
    let mailbox_storage_for_maintenance = config.mailbox_storage.clone();
    let mailbox_maintenance = config.mailbox_maintenance;
    let hub = Arc::new(RelayHub::new(RelayHubConfig {
        auth: config.auth,
        limits: config.limits,
        session_policy: config.session_policy,
        session_storage: config.session_storage,
        mailbox_policy,
        mailbox_storage: config.mailbox_storage,
        accounting_policy: config.accounting_policy,
        accounting_storage: config.accounting_storage,
        abuse_policy: config.abuse_policy,
        abuse_storage: config.abuse_storage,
        admin: config.admin,
    })?);

    let join = thread::spawn(move || {
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let hub = hub.clone();
                    thread::spawn(move || {
                        #[cfg(not(test))]
                        let _ = handle_connection(stream, hub);

                        #[cfg(test)]
                        if let Err(error) = handle_connection(stream, hub) {
                            eprintln!("relay test connection ended: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    let maintenance_join = spawn_mailbox_maintenance_worker(
        mailbox_storage_for_maintenance,
        mailbox_policy,
        mailbox_maintenance,
        Some(stop.clone()),
    );

    Ok(RelayHandle {
        local_addr,
        stop,
        join: Some(join),
        maintenance_join,
    })
}

fn spawn_mailbox_maintenance_worker(
    storage: RelayMailboxStorage,
    policy: RelayMailboxPolicy,
    maintenance: RelayMailboxMaintenancePolicy,
    stop: Option<Arc<AtomicBool>>,
) -> Option<JoinHandle<()>> {
    let interval = maintenance.purge_interval()?;
    let RelayMailboxStorage::FileBacked(root) = storage else {
        return None;
    };

    Some(thread::spawn(move || {
        loop {
            if stop
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::SeqCst))
            {
                break;
            }
            let _ = purge_relay_mailbox_dir(&root, None, policy.envelope_ttl, false);

            let started = Instant::now();
            while started.elapsed() < interval {
                if stop
                    .as_ref()
                    .is_some_and(|stop| stop.load(Ordering::SeqCst))
                {
                    return;
                }
                let remaining = interval.saturating_sub(started.elapsed());
                thread::sleep(remaining.min(Duration::from_millis(50)));
            }
        }
    }))
}

/// Compute the RFC 6455 Sec-WebSocket-Accept value.
pub fn websocket_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key.trim());
    input.push_str(WEBSOCKET_GUID);
    base64_encode(&sha1(input.as_bytes()))
}

struct RelayHubConfig {
    auth: RelayAuth,
    limits: RelayLimits,
    session_policy: RelaySessionPolicy,
    session_storage: RelaySessionStorage,
    mailbox_policy: RelayMailboxPolicy,
    mailbox_storage: RelayMailboxStorage,
    accounting_policy: RelayAccountingPolicy,
    accounting_storage: RelayAccountingStorage,
    abuse_policy: RelayAbusePolicy,
    abuse_storage: RelayAbuseStorage,
    admin: RelayAdminConfig,
}

struct RelayHub {
    auth: RelayAuth,
    limits: RelayLimits,
    session_policy: RelaySessionPolicy,
    session_storage: RelaySessionStorage,
    mailbox_policy: RelayMailboxPolicy,
    mailbox_storage: RelayMailboxStorage,
    accounting_policy: RelayAccountingPolicy,
    accounting_storage: RelayAccountingStorage,
    abuse_policy: RelayAbusePolicy,
    abuse_storage: RelayAbuseStorage,
    admin: RelayAdminConfig,
    connections: Mutex<ConnectionCounts>,
    state: Mutex<RelayHubState>,
    sessions: Mutex<RelaySessionState>,
    accounting: Mutex<RelayAccountingState>,
    abuse: Mutex<RelayAbuseState>,
    admin_manifest: Mutex<()>,
}

impl fmt::Debug for RelayHub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayHub")
            .field("auth", &self.auth)
            .field("limits", &self.limits)
            .field("session_policy", &self.session_policy)
            .field("session_storage", &self.session_storage)
            .field("mailbox_policy", &self.mailbox_policy)
            .field("mailbox_storage", &self.mailbox_storage)
            .field("accounting_policy", &self.accounting_policy)
            .field("accounting_storage", &self.accounting_storage)
            .field("abuse_policy", &self.abuse_policy)
            .field("abuse_storage", &self.abuse_storage)
            .field("admin", &self.admin)
            .field("connections", &"<connection-counts>")
            .field("state", &"<relay-hub-state>")
            .field("sessions", &"<relay-session-state>")
            .field("accounting", &"<relay-accounting-state>")
            .field("abuse", &"<relay-abuse-state>")
            .field("admin_manifest", &"<admin-manifest-lock>")
            .finish()
    }
}

impl RelayHub {
    fn new(config: RelayHubConfig) -> Result<Self, RelayError> {
        let state = RelayHubState::load(&config.mailbox_storage, config.mailbox_policy)?;
        let sessions = RelaySessionState::load(&config.session_storage, config.session_policy)?;
        let accounting =
            RelayAccountingState::load(&config.accounting_storage, config.accounting_policy)?;
        let abuse = RelayAbuseState::load(&config.abuse_storage, config.abuse_policy)?;
        Ok(Self {
            auth: config.auth,
            limits: config.limits,
            session_policy: config.session_policy,
            session_storage: config.session_storage,
            mailbox_policy: config.mailbox_policy,
            mailbox_storage: config.mailbox_storage,
            accounting_policy: config.accounting_policy,
            accounting_storage: config.accounting_storage,
            abuse_policy: config.abuse_policy,
            abuse_storage: config.abuse_storage,
            admin: config.admin,
            connections: Mutex::new(ConnectionCounts::default()),
            state: Mutex::new(state),
            sessions: Mutex::new(sessions),
            accounting: Mutex::new(accounting),
            abuse: Mutex::new(abuse),
            admin_manifest: Mutex::new(()),
        })
    }

    fn open_connection(&self, peer_ip: IpAddr) -> Result<ConnectionGuard<'_>, RelayError> {
        let mut connections = self.connections.lock().map_err(|_| {
            RelayError::Protocol("relay connection counter lock failed".to_string())
        })?;
        let peer_count = *connections.by_ip.get(&peer_ip).unwrap_or(&0);

        if connections.total >= self.limits.max_connections {
            return Err(RelayError::Protocol(
                "relay connection limit exceeded".to_string(),
            ));
        }
        if peer_count >= self.limits.max_connections_per_ip {
            return Err(RelayError::Protocol(
                "relay per-ip connection limit exceeded".to_string(),
            ));
        }

        connections.total += 1;
        connections.by_ip.insert(peer_ip, peer_count + 1);

        Ok(ConnectionGuard { hub: self, peer_ip })
    }

    fn close_connection(&self, peer_ip: IpAddr) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.total = connections.total.saturating_sub(1);
            if let Some(count) = connections.by_ip.get_mut(&peer_ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    connections.by_ip.remove(&peer_ip);
                }
            }
        }
    }

    fn add_client(
        &self,
        node_id: String,
        resume_session_id: Option<&str>,
        stream: TcpStream,
    ) -> Result<(String, bool, Vec<RelayForwarded>), RelayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RelayError::Protocol("relay hub state lock failed".to_string()))?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| RelayError::Protocol("relay session state lock failed".to_string()))?;
        let resumed = match resume_session_id {
            Some(candidate) if !state.clients.contains_key(&node_id) => {
                sessions.can_resume(&node_id, candidate, &self.session_storage)?
            }
            _ => false,
        };
        let session_id = if resumed {
            resume_session_id.unwrap_or_default().to_string()
        } else {
            session_id(&node_id)
        };
        sessions.record_authenticated(
            &node_id,
            &session_id,
            resumed,
            self.session_policy,
            &self.session_storage,
        )?;
        state.clients.insert(
            node_id.clone(),
            RelayClientConnection {
                session_id,
                stream: Arc::new(Mutex::new(stream)),
            },
        );
        let queued = state.drain_mailbox(&node_id, self.mailbox_policy, &self.mailbox_storage)?;
        let session_id = state
            .clients
            .get(&node_id)
            .map(|connection| connection.session_id.clone())
            .ok_or_else(|| RelayError::Protocol("relay session was not registered".to_string()))?;
        Ok((session_id, resumed, queued))
    }

    fn record_authenticated_session(&self, node_id: &str, resumed: bool) -> Result<(), RelayError> {
        let mut accounting = self
            .accounting
            .lock()
            .map_err(|_| RelayError::Protocol("relay accounting lock failed".to_string()))?;
        accounting.record_session(
            node_id,
            resumed,
            self.accounting_policy,
            &self.accounting_storage,
        )
    }

    fn remove_client(&self, node_id: &str, session_id: &str) {
        let mut removed = false;
        if let Ok(mut state) = self.state.lock() {
            if state
                .clients
                .get(node_id)
                .is_some_and(|connection| connection.session_id == session_id)
            {
                state.clients.remove(node_id);
                removed = true;
            }
        }
        if removed {
            if let Ok(mut sessions) = self.sessions.lock() {
                let _ = sessions.touch_session(node_id, session_id, &self.session_storage);
            }
        }
    }

    fn target_or_mailbox(
        &self,
        node_id: &str,
        forwarded: RelayForwarded,
    ) -> Result<RelayForwardDelivery, RelayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RelayError::Protocol("relay hub state lock failed".to_string()))?;
        if let Some(client) = state.clients.get(node_id) {
            return Ok(RelayForwardDelivery::Online(client.stream.clone()));
        }
        if forwarded.body.is_none() {
            return Ok(RelayForwardDelivery::Undelivered("peer_offline"));
        }
        match state.enqueue_mailbox(
            node_id,
            forwarded,
            self.mailbox_policy,
            &self.mailbox_storage,
        ) {
            Ok(()) => Ok(RelayForwardDelivery::Mailboxed),
            Err(reason) => Ok(RelayForwardDelivery::Undelivered(reason)),
        }
    }

    fn quota_allows_forward(&self, from_node_id: &str, payload_bytes: u64) -> bool {
        let Ok(mut accounting) = self.accounting.lock() else {
            return false;
        };
        accounting.quota_allows(from_node_id, payload_bytes, self.accounting_policy)
    }

    fn record_forward(
        &self,
        from_node_id: &str,
        to_node_id: &str,
        payload_bytes: u64,
        mailboxed: bool,
    ) -> Result<(), RelayError> {
        let mut accounting = self
            .accounting
            .lock()
            .map_err(|_| RelayError::Protocol("relay accounting lock failed".to_string()))?;
        accounting.record_forward(
            from_node_id,
            to_node_id,
            payload_bytes,
            mailboxed,
            self.accounting_policy,
            &self.accounting_storage,
        )
    }

    fn record_abuse(&self, node_id: Option<&str>, kind: RelayAbuseKind) -> Result<(), RelayError> {
        let mut abuse = self
            .abuse
            .lock()
            .map_err(|_| RelayError::Protocol("relay abuse counter lock failed".to_string()))?;
        abuse.record_event(node_id, kind, self.abuse_policy, &self.abuse_storage)
    }

    fn handle_admin_request(
        &self,
        request: &RelayAdminRequest,
    ) -> Result<RelayAdminResult, RelayError> {
        let authorization = match self
            .admin
            .authorize_action(&request.admin_token, request.action)
        {
            Ok(authorization) => authorization,
            Err(error) => {
                let _ = self.record_abuse(None, RelayAbuseKind::AdminUnauthorized);
                return Err(error);
            }
        };
        let credentials_file = self
            .admin
            .credentials_file()
            .ok_or_else(|| RelayError::Protocol("admin_unavailable".to_string()))?
            .to_path_buf();
        let _manifest_guard = self
            .admin_manifest
            .lock()
            .map_err(|_| RelayError::Protocol("relay admin manifest lock failed".to_string()))?;

        match request.action {
            RelayAdminAction::Issue | RelayAdminAction::Rotate => {
                let account_id = request.account_id.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin account is required".to_string())
                })?;
                self.ensure_admin_account_allowed(&authorization, account_id)?;
                let node_id = request.node_id.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin node is required".to_string())
                })?;
                let token_sha256_hex = request.token_sha256_hex.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin token hash is required".to_string())
                })?;
                let token_length = request.token_length.ok_or_else(|| {
                    RelayError::Protocol("relay admin token length is required".to_string())
                })?;
                let status = if request.action == RelayAdminAction::Issue {
                    "issued"
                } else {
                    "rotated"
                };
                if let Some(tenants_file) = self.admin.tenants_file() {
                    if let Err(error) = hosted_tenant_registry_authorizes_account_node(
                        tenants_file,
                        account_id,
                        node_id,
                    ) {
                        return self
                            .admin_result_for_update_error(request, account_id, node_id, error);
                    }
                }
                if let Err(error) = upsert_hosted_relay_credential_hash_in_file(
                    &credentials_file,
                    account_id,
                    node_id,
                    token_sha256_hex,
                    token_length,
                    request.expires_at_unix,
                    request.action == RelayAdminAction::Rotate,
                ) {
                    return self.admin_result_for_update_error(request, account_id, node_id, error);
                }
                let audit =
                    audit_hosted_relay_credentials_file(&credentials_file, Some(account_id))?;
                Ok(RelayAdminResult {
                    action: request.action,
                    status: status.to_string(),
                    account_id: Some(account_id.to_string()),
                    node_id: Some(node_id.to_string()),
                    credentials: audit.credentials,
                    active: audit.active,
                    revoked: audit.revoked,
                    expired: audit.expired,
                    accounts: audit.accounts,
                    token_length: Some(token_length),
                    expires_at_unix: request.expires_at_unix,
                    token_displayed: false,
                    contents_displayed: false,
                    ..RelayAdminResult::new(request.action, status)
                })
            }
            RelayAdminAction::Revoke => {
                let account_id = request.account_id.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin account is required".to_string())
                })?;
                self.ensure_admin_account_allowed(&authorization, account_id)?;
                let node_id = request.node_id.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin node is required".to_string())
                })?;
                if let Err(error) =
                    revoke_hosted_relay_credential_in_file(&credentials_file, account_id, node_id)
                {
                    return self.admin_result_for_update_error(request, account_id, node_id, error);
                }
                let audit =
                    audit_hosted_relay_credentials_file(&credentials_file, Some(account_id))?;
                Ok(RelayAdminResult {
                    action: request.action,
                    status: "revoked".to_string(),
                    account_id: Some(account_id.to_string()),
                    node_id: Some(node_id.to_string()),
                    credentials: audit.credentials,
                    active: audit.active,
                    revoked: audit.revoked,
                    expired: audit.expired,
                    accounts: audit.accounts,
                    token_length: None,
                    expires_at_unix: None,
                    token_displayed: false,
                    contents_displayed: false,
                    ..RelayAdminResult::new(request.action, "revoked")
                })
            }
            RelayAdminAction::Audit => {
                let account_id =
                    self.admin_account_filter(request.account_id.as_deref(), &authorization)?;
                let audit =
                    audit_hosted_relay_credentials_file(&credentials_file, account_id.as_deref())?;
                Ok(RelayAdminResult {
                    action: request.action,
                    status: "audited".to_string(),
                    account_id: audit.account_id,
                    node_id: None,
                    credentials: audit.credentials,
                    active: audit.active,
                    revoked: audit.revoked,
                    expired: audit.expired,
                    accounts: audit.accounts,
                    token_length: None,
                    expires_at_unix: None,
                    token_displayed: false,
                    contents_displayed: false,
                    ..RelayAdminResult::new(request.action, "audited")
                })
            }
            RelayAdminAction::Dashboard => {
                self.admin_dashboard_result(request, &credentials_file, &authorization)
            }
            RelayAdminAction::SessionAudit => {
                self.admin_session_audit_result(request, &authorization)
            }
            RelayAdminAction::TenantUpsert
            | RelayAdminAction::TenantRevoke
            | RelayAdminAction::TenantNodeUpsert
            | RelayAdminAction::TenantNodeRevoke => {
                self.admin_tenant_update_result(request, &authorization)
            }
            RelayAdminAction::TenantAudit => {
                self.admin_tenant_audit_result(request, &authorization)
            }
            RelayAdminAction::AccountSuspend => {
                self.admin_account_suspend_result(request, &credentials_file, &authorization)
            }
            RelayAdminAction::MailboxAudit => {
                self.admin_mailbox_audit_result(request, &authorization)
            }
            RelayAdminAction::MailboxPurge => {
                self.admin_mailbox_purge_result(request, &authorization)
            }
        }
    }

    fn admin_tenant_update_result(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        let Some(tenants_file) = self.admin.tenants_file() else {
            return Ok(RelayAdminResult {
                action: request.action,
                status: "tenant_unavailable".to_string(),
                account_id: request.account_id.clone(),
                node_id: request.node_id.clone(),
                ..RelayAdminResult::new(request.action, "tenant_unavailable")
            });
        };
        let account_id = request.account_id.as_deref().ok_or_else(|| {
            RelayError::Protocol("relay admin tenant account is required".to_string())
        })?;
        self.ensure_admin_account_allowed(authorization, account_id)?;
        let update = match request.action {
            RelayAdminAction::TenantUpsert => {
                upsert_hosted_tenant_in_file(tenants_file, account_id)
            }
            RelayAdminAction::TenantRevoke => {
                revoke_hosted_tenant_in_file(tenants_file, account_id)
            }
            RelayAdminAction::TenantNodeUpsert => {
                let node_id = request.node_id.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin tenant node is required".to_string())
                })?;
                upsert_hosted_tenant_node_in_file(
                    tenants_file,
                    account_id,
                    node_id,
                    HostedTenantPermissions {
                        messages: request.tenant_messages.unwrap_or(false),
                        streams: request.tenant_streams.unwrap_or(false),
                        rooms: request.tenant_rooms.unwrap_or(false),
                        files: request.tenant_files.unwrap_or(false),
                        mailbox: request.tenant_mailbox.unwrap_or(false),
                    },
                    request.signing_key_id.clone(),
                    request.exchange_key_id.clone(),
                )
            }
            RelayAdminAction::TenantNodeRevoke => {
                let node_id = request.node_id.as_deref().ok_or_else(|| {
                    RelayError::Protocol("relay admin tenant node is required".to_string())
                })?;
                revoke_hosted_tenant_node_in_file(tenants_file, account_id, node_id)
            }
            _ => unreachable!("tenant update result only handles tenant update actions"),
        };
        let update = match update {
            Ok(update) => update,
            Err(error) => {
                return self.admin_tenant_result_for_update_error(
                    request,
                    account_id,
                    request.node_id.as_deref(),
                    tenants_file,
                    error,
                );
            }
        };
        let audit = audit_hosted_tenants_file(tenants_file, Some(account_id))?;
        let status = match update.status {
            HostedTenantStatus::Active => "upserted",
            HostedTenantStatus::Revoked => "revoked",
        };

        Ok(RelayAdminResult {
            action: request.action,
            status: status.to_string(),
            account_id: Some(update.account_id),
            node_id: update.node_id,
            tenants: audit.tenants,
            active_tenants: audit.active_tenants,
            revoked_tenants: audit.revoked_tenants,
            nodes: audit.nodes,
            active_nodes: audit.active_nodes,
            revoked_nodes: audit.revoked_nodes,
            tenant_policies: audit.policies,
            token_displayed: update.token_displayed || audit.token_displayed,
            key_material_displayed: update.key_material_displayed || audit.key_material_displayed,
            contents_displayed: update.contents_displayed || audit.contents_displayed,
            ..RelayAdminResult::new(request.action, status)
        })
    }

    fn admin_tenant_audit_result(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        let Some(tenants_file) = self.admin.tenants_file() else {
            return Ok(RelayAdminResult {
                action: request.action,
                status: "tenant_unavailable".to_string(),
                account_id: request.account_id.clone(),
                ..RelayAdminResult::new(request.action, "tenant_unavailable")
            });
        };
        let account_id = self.admin_account_filter(request.account_id.as_deref(), authorization)?;
        let audit = audit_hosted_tenants_file(tenants_file, account_id.as_deref())?;

        Ok(RelayAdminResult {
            action: request.action,
            status: "audited".to_string(),
            account_id: audit.account_id,
            tenants: audit.tenants,
            active_tenants: audit.active_tenants,
            revoked_tenants: audit.revoked_tenants,
            nodes: audit.nodes,
            active_nodes: audit.active_nodes,
            revoked_nodes: audit.revoked_nodes,
            tenant_policies: audit.policies,
            token_displayed: audit.token_displayed,
            key_material_displayed: audit.key_material_displayed,
            contents_displayed: audit.contents_displayed,
            ..RelayAdminResult::new(request.action, "audited")
        })
    }

    fn admin_account_suspend_result(
        &self,
        request: &RelayAdminRequest,
        credentials_file: &Path,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        let Some(tenants_file) = self.admin.tenants_file() else {
            return Ok(RelayAdminResult {
                action: request.action,
                status: "tenant_unavailable".to_string(),
                account_id: request.account_id.clone(),
                ..RelayAdminResult::new(request.action, "tenant_unavailable")
            });
        };
        let account_id = request.account_id.as_deref().ok_or_else(|| {
            RelayError::Protocol("relay admin account suspension account is required".to_string())
        })?;
        self.ensure_admin_account_allowed(authorization, account_id)?;
        let suspension =
            match suspend_hosted_account_in_files(credentials_file, tenants_file, account_id) {
                Ok(suspension) => suspension,
                Err(error) => {
                    return self.admin_tenant_result_for_update_error(
                        request,
                        account_id,
                        None,
                        tenants_file,
                        error,
                    );
                }
            };

        Ok(RelayAdminResult {
            action: request.action,
            status: "suspended".to_string(),
            account_id: Some(suspension.account_id),
            credentials: suspension.credentials,
            active: suspension.active,
            revoked: suspension.revoked,
            expired: suspension.expired,
            accounts: suspension.accounts,
            tenants: suspension.tenants,
            active_tenants: suspension.active_tenants,
            revoked_tenants: suspension.revoked_tenants,
            nodes: suspension.nodes,
            active_nodes: suspension.active_nodes,
            revoked_nodes: suspension.revoked_nodes,
            tenant_policies: suspension.tenant_policies,
            token_displayed: suspension.token_displayed,
            key_material_displayed: suspension.key_material_displayed,
            contents_displayed: suspension.contents_displayed,
            ..RelayAdminResult::new(request.action, "suspended")
        })
    }

    fn admin_mailbox_purge_result(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        let RelayMailboxStorage::FileBacked(mailbox_dir) = &self.mailbox_storage else {
            return Ok(RelayAdminResult {
                action: request.action,
                status: "mailbox_unavailable".to_string(),
                node_id: request.node_id.clone(),
                retention_ttl_seconds: request.retention_ttl_seconds,
                mailbox_dry_run: request.mailbox_purge_dry_run,
                ..RelayAdminResult::new(request.action, "mailbox_unavailable")
            });
        };
        let retention_ttl_seconds = request.retention_ttl_seconds.ok_or_else(|| {
            RelayError::Protocol("relay admin mailbox purge ttl is required".to_string())
        })?;
        let dry_run = request.mailbox_purge_dry_run.ok_or_else(|| {
            RelayError::Protocol("relay admin mailbox purge mode is required".to_string())
        })?;
        self.ensure_admin_mailbox_node_allowed(request, authorization)?;
        let report = purge_relay_mailbox_dir(
            mailbox_dir,
            request.node_id.as_deref(),
            Duration::from_secs(retention_ttl_seconds),
            dry_run,
        )?;
        let status = if report.dry_run { "dry_run" } else { "purged" };

        Ok(RelayAdminResult {
            action: request.action,
            status: status.to_string(),
            node_id: report.node_id,
            retention_ttl_seconds: Some(report.retention_ttl_seconds),
            mailbox_nodes: report.nodes,
            mailbox_records: report.records,
            mailbox_invalid_records: report.invalid_records,
            mailbox_bytes: report.bytes,
            mailbox_expired_records: Some(report.expired_records),
            mailbox_expired_bytes: Some(report.expired_bytes),
            mailbox_dry_run: Some(report.dry_run),
            mailbox_confirmed: Some(report.confirmed),
            mailbox_purged_records: Some(report.purged_records),
            mailbox_purged_bytes: Some(report.purged_bytes),
            payload_displayed: report.payload_displayed,
            token_displayed: report.token_displayed,
            token_hash_displayed: report.token_hash_displayed,
            key_material_displayed: report.key_material_displayed,
            session_id_displayed: report.session_id_displayed,
            ciphertext_displayed: report.ciphertext_displayed,
            contents_displayed: report.contents_displayed,
            ..RelayAdminResult::new(request.action, status)
        })
    }

    fn admin_mailbox_audit_result(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        let RelayMailboxStorage::FileBacked(mailbox_dir) = &self.mailbox_storage else {
            return Ok(RelayAdminResult {
                action: request.action,
                status: "mailbox_unavailable".to_string(),
                node_id: request.node_id.clone(),
                retention_ttl_seconds: request.retention_ttl_seconds,
                ..RelayAdminResult::new(request.action, "mailbox_unavailable")
            });
        };
        self.ensure_admin_mailbox_node_allowed(request, authorization)?;
        let retention_ttl = request.retention_ttl_seconds.map(Duration::from_secs);
        let audit =
            audit_relay_mailbox_dir(mailbox_dir, request.node_id.as_deref(), retention_ttl)?;

        Ok(RelayAdminResult {
            action: request.action,
            status: "audited".to_string(),
            node_id: audit.node_id,
            retention_ttl_seconds: audit.retention_ttl_seconds,
            mailbox_nodes: audit.nodes,
            mailbox_records: audit.records,
            mailbox_invalid_records: audit.invalid_records,
            mailbox_bytes: audit.bytes,
            mailbox_oldest_queued_unix_millis: audit.oldest_queued_unix_millis,
            mailbox_newest_queued_unix_millis: audit.newest_queued_unix_millis,
            mailbox_expired_records: audit.expired_records,
            mailbox_expired_bytes: audit.expired_bytes,
            payload_displayed: audit.payload_displayed,
            token_displayed: audit.token_displayed,
            token_hash_displayed: audit.token_hash_displayed,
            key_material_displayed: audit.key_material_displayed,
            session_id_displayed: audit.session_id_displayed,
            ciphertext_displayed: audit.ciphertext_displayed,
            contents_displayed: audit.contents_displayed,
            ..RelayAdminResult::new(request.action, "audited")
        })
    }

    fn ensure_admin_account_allowed(
        &self,
        authorization: &RelayAdminAuthorization,
        account_id: &str,
    ) -> Result<(), RelayError> {
        if authorization
            .account_id
            .as_deref()
            .is_some_and(|allowed| allowed != account_id)
        {
            return Err(RelayError::Protocol("admin_scope_denied".to_string()));
        }
        Ok(())
    }

    fn admin_account_filter(
        &self,
        request_account_id: Option<&str>,
        authorization: &RelayAdminAuthorization,
    ) -> Result<Option<String>, RelayError> {
        let request_account_id = request_account_id
            .map(|value| validate_account_id(value.to_string()))
            .transpose()?;
        match (authorization.account_id.as_deref(), request_account_id) {
            (Some(allowed), Some(requested)) if allowed != requested => {
                Err(RelayError::Protocol("admin_scope_denied".to_string()))
            }
            (Some(allowed), _) => Ok(Some(allowed.to_string())),
            (None, requested) => Ok(requested),
        }
    }

    fn ensure_admin_dashboard_node_allowed(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<(), RelayError> {
        let Some(account_id) = authorization.account_id.as_deref() else {
            return Ok(());
        };
        let Some(node_id) = request.node_id.as_deref() else {
            return Ok(());
        };
        let Some(tenants_file) = self.admin.tenants_file() else {
            return Err(RelayError::Protocol("admin_scope_denied".to_string()));
        };
        hosted_tenant_registry_authorizes_account_node(tenants_file, account_id, node_id)
            .map_err(|_| RelayError::Protocol("admin_scope_denied".to_string()))
    }

    fn ensure_admin_mailbox_node_allowed(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<(), RelayError> {
        let Some(account_id) = authorization.account_id.as_deref() else {
            return Ok(());
        };
        let Some(node_id) = request.node_id.as_deref() else {
            return Err(RelayError::Protocol("admin_scope_denied".to_string()));
        };
        let Some(tenants_file) = self.admin.tenants_file() else {
            return Err(RelayError::Protocol("admin_scope_denied".to_string()));
        };
        hosted_tenant_registry_authorizes_account_node(tenants_file, account_id, node_id)
            .map_err(|_| RelayError::Protocol("admin_scope_denied".to_string()))
    }

    fn ensure_admin_session_node_allowed(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<(), RelayError> {
        let Some(account_id) = authorization.account_id.as_deref() else {
            return Ok(());
        };
        let Some(node_id) = request.node_id.as_deref() else {
            return Err(RelayError::Protocol("admin_scope_denied".to_string()));
        };
        let Some(tenants_file) = self.admin.tenants_file() else {
            return Err(RelayError::Protocol("admin_scope_denied".to_string()));
        };
        hosted_tenant_registry_authorizes_account_node(tenants_file, account_id, node_id)
            .map_err(|_| RelayError::Protocol("admin_scope_denied".to_string()))
    }

    fn admin_session_audit_result(
        &self,
        request: &RelayAdminRequest,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        self.ensure_admin_session_node_allowed(request, authorization)?;
        let RelaySessionStorage::FileBacked(session_state_dir) = &self.session_storage else {
            return Ok(RelayAdminResult {
                action: request.action,
                status: "session_state_unavailable".to_string(),
                node_id: request.node_id.clone(),
                ..RelayAdminResult::new(request.action, "session_state_unavailable")
            });
        };
        let audit = audit_relay_session_state_dir(session_state_dir, request.node_id.as_deref())?;

        Ok(RelayAdminResult {
            action: request.action,
            status: "audited".to_string(),
            node_id: audit.node_id,
            session_state_records: audit.records,
            session_state_active_records: audit.active_records,
            session_state_expired_records: audit.expired_records,
            session_state_invalid_records: audit.invalid_records,
            session_state_oldest_created_unix_millis: audit.oldest_created_unix_millis,
            session_state_newest_last_seen_unix_millis: audit.newest_last_seen_unix_millis,
            session_state_next_expires_unix_millis: audit.next_expires_unix_millis,
            payload_displayed: audit.payload_displayed,
            token_displayed: audit.token_displayed,
            token_hash_displayed: audit.token_hash_displayed,
            key_material_displayed: audit.key_material_displayed,
            session_id_displayed: audit.session_id_displayed,
            ciphertext_displayed: audit.ciphertext_displayed,
            contents_displayed: audit.contents_displayed,
            ..RelayAdminResult::new(request.action, "audited")
        })
    }

    fn admin_dashboard_result(
        &self,
        request: &RelayAdminRequest,
        credentials_file: &Path,
        authorization: &RelayAdminAuthorization,
    ) -> Result<RelayAdminResult, RelayError> {
        let account_id = self.admin_account_filter(request.account_id.as_deref(), authorization)?;
        self.ensure_admin_dashboard_node_allowed(request, authorization)?;
        let scoped_without_node = authorization.account_id.is_some() && request.node_id.is_none();
        let node_filter = request.node_id.as_deref();
        let credentials =
            audit_hosted_relay_credentials_file(credentials_file, account_id.as_deref())?;
        let tenants = self
            .admin
            .tenants_file()
            .map(|path| audit_hosted_tenants_file(path, account_id.as_deref()))
            .transpose()?;
        let accounting = match &self.accounting_storage {
            _ if scoped_without_node => None,
            RelayAccountingStorage::MemoryOnly => None,
            RelayAccountingStorage::FileBacked(path) => {
                Some(audit_relay_accounting_dir(path, node_filter)?)
            }
        };
        let abuse = match &self.abuse_storage {
            _ if scoped_without_node => None,
            RelayAbuseStorage::MemoryOnly => None,
            RelayAbuseStorage::FileBacked(path) => Some(audit_relay_abuse_dir(path, node_filter)?),
        };

        Ok(RelayAdminResult {
            action: request.action,
            status: "snapshotted".to_string(),
            account_id: credentials.account_id,
            node_id: request.node_id.clone(),
            credentials: credentials.credentials,
            active: credentials.active,
            revoked: credentials.revoked,
            expired: credentials.expired,
            accounts: credentials.accounts,
            tenants: tenants.as_ref().map(|audit| audit.tenants).unwrap_or(0),
            active_tenants: tenants
                .as_ref()
                .map(|audit| audit.active_tenants)
                .unwrap_or(0),
            revoked_tenants: tenants
                .as_ref()
                .map(|audit| audit.revoked_tenants)
                .unwrap_or(0),
            nodes: tenants.as_ref().map(|audit| audit.nodes).unwrap_or(0),
            active_nodes: tenants
                .as_ref()
                .map(|audit| audit.active_nodes)
                .unwrap_or(0),
            revoked_nodes: tenants
                .as_ref()
                .map(|audit| audit.revoked_nodes)
                .unwrap_or(0),
            tenant_policies: tenants.as_ref().map(|audit| audit.policies).unwrap_or(0),
            accounting_records: accounting.as_ref().map(|audit| audit.records).unwrap_or(0),
            accounting_window_started_unix: accounting
                .as_ref()
                .and_then(|audit| audit.window_started_unix),
            sessions_authenticated: accounting
                .as_ref()
                .map(|audit| audit.sessions_authenticated)
                .unwrap_or(0),
            sessions_resumed: accounting
                .as_ref()
                .map(|audit| audit.sessions_resumed)
                .unwrap_or(0),
            envelopes_sent: accounting
                .as_ref()
                .map(|audit| audit.envelopes_sent)
                .unwrap_or(0),
            bytes_sent: accounting
                .as_ref()
                .map(|audit| audit.bytes_sent)
                .unwrap_or(0),
            envelopes_received: accounting
                .as_ref()
                .map(|audit| audit.envelopes_received)
                .unwrap_or(0),
            bytes_received: accounting
                .as_ref()
                .map(|audit| audit.bytes_received)
                .unwrap_or(0),
            envelopes_mailboxed: accounting
                .as_ref()
                .map(|audit| audit.envelopes_mailboxed)
                .unwrap_or(0),
            bytes_mailboxed: accounting
                .as_ref()
                .map(|audit| audit.bytes_mailboxed)
                .unwrap_or(0),
            abuse_records: abuse.as_ref().map(|audit| audit.records).unwrap_or(0),
            abuse_window_started_unix: abuse.as_ref().and_then(|audit| audit.window_started_unix),
            admin_unauthorized: abuse
                .as_ref()
                .map(|audit| audit.admin_unauthorized)
                .unwrap_or(0),
            admin_failed: abuse.as_ref().map(|audit| audit.admin_failed).unwrap_or(0),
            unauthorized_sessions: abuse
                .as_ref()
                .map(|audit| audit.unauthorized_sessions)
                .unwrap_or(0),
            credential_denied_sessions: abuse
                .as_ref()
                .map(|audit| audit.credential_denied_sessions)
                .unwrap_or(0),
            tenant_denied_sessions: abuse
                .as_ref()
                .map(|audit| audit.tenant_denied_sessions)
                .unwrap_or(0),
            rate_limited_sessions: abuse
                .as_ref()
                .map(|audit| audit.rate_limited_sessions)
                .unwrap_or(0),
            session_expired: abuse
                .as_ref()
                .map(|audit| audit.session_expired)
                .unwrap_or(0),
            quota_denied_forwards: abuse
                .as_ref()
                .map(|audit| audit.quota_denied_forwards)
                .unwrap_or(0),
            undelivered_forwards: abuse
                .as_ref()
                .map(|audit| audit.undelivered_forwards)
                .unwrap_or(0),
            mailbox_rejected_forwards: abuse
                .as_ref()
                .map(|audit| audit.mailbox_rejected_forwards)
                .unwrap_or(0),
            malformed_client_frames: abuse
                .as_ref()
                .map(|audit| audit.malformed_client_frames)
                .unwrap_or(0),
            payload_displayed: accounting
                .as_ref()
                .is_some_and(|audit| audit.payload_displayed)
                || abuse.as_ref().is_some_and(|audit| audit.payload_displayed),
            token_displayed: credentials.token_displayed
                || tenants.as_ref().is_some_and(|audit| audit.token_displayed)
                || accounting
                    .as_ref()
                    .is_some_and(|audit| audit.token_displayed)
                || abuse.as_ref().is_some_and(|audit| audit.token_displayed),
            token_hash_displayed: accounting
                .as_ref()
                .is_some_and(|audit| audit.token_hash_displayed)
                || abuse
                    .as_ref()
                    .is_some_and(|audit| audit.token_hash_displayed),
            key_material_displayed: tenants
                .as_ref()
                .is_some_and(|audit| audit.key_material_displayed)
                || accounting
                    .as_ref()
                    .is_some_and(|audit| audit.key_material_displayed)
                || abuse
                    .as_ref()
                    .is_some_and(|audit| audit.key_material_displayed),
            session_id_displayed: accounting
                .as_ref()
                .is_some_and(|audit| audit.session_id_displayed)
                || abuse
                    .as_ref()
                    .is_some_and(|audit| audit.session_id_displayed),
            ciphertext_displayed: accounting
                .as_ref()
                .is_some_and(|audit| audit.ciphertext_displayed)
                || abuse
                    .as_ref()
                    .is_some_and(|audit| audit.ciphertext_displayed),
            contents_displayed: credentials.contents_displayed
                || tenants
                    .as_ref()
                    .is_some_and(|audit| audit.contents_displayed)
                || accounting
                    .as_ref()
                    .is_some_and(|audit| audit.contents_displayed)
                || abuse.as_ref().is_some_and(|audit| audit.contents_displayed),
            ..RelayAdminResult::new(request.action, "snapshotted")
        })
    }

    fn admin_result_for_update_error(
        &self,
        request: &RelayAdminRequest,
        account_id: &str,
        node_id: &str,
        error: RelayError,
    ) -> Result<RelayAdminResult, RelayError> {
        let status = hosted_admin_error_status(&error).ok_or(error)?;
        let credentials_file = self
            .admin
            .credentials_file()
            .ok_or_else(|| RelayError::Protocol("admin_unavailable".to_string()))?;
        let audit = audit_hosted_relay_credentials_file(credentials_file, Some(account_id))?;
        Ok(RelayAdminResult {
            action: request.action,
            status: status.to_string(),
            account_id: Some(account_id.to_string()),
            node_id: Some(node_id.to_string()),
            credentials: audit.credentials,
            active: audit.active,
            revoked: audit.revoked,
            expired: audit.expired,
            accounts: audit.accounts,
            token_length: request.token_length,
            expires_at_unix: request.expires_at_unix,
            token_displayed: false,
            contents_displayed: false,
            ..RelayAdminResult::new(request.action, status)
        })
    }

    fn admin_tenant_result_for_update_error(
        &self,
        request: &RelayAdminRequest,
        account_id: &str,
        node_id: Option<&str>,
        tenants_file: &Path,
        error: RelayError,
    ) -> Result<RelayAdminResult, RelayError> {
        let status = hosted_admin_error_status(&error).ok_or(error)?;
        let audit = audit_hosted_tenants_file(tenants_file, Some(account_id))?;
        Ok(RelayAdminResult {
            action: request.action,
            status: status.to_string(),
            account_id: Some(account_id.to_string()),
            node_id: node_id.map(str::to_string),
            tenants: audit.tenants,
            active_tenants: audit.active_tenants,
            revoked_tenants: audit.revoked_tenants,
            nodes: audit.nodes,
            active_nodes: audit.active_nodes,
            revoked_nodes: audit.revoked_nodes,
            tenant_policies: audit.policies,
            token_displayed: audit.token_displayed,
            key_material_displayed: audit.key_material_displayed,
            contents_displayed: audit.contents_displayed,
            ..RelayAdminResult::new(request.action, status)
        })
    }
}

fn handle_connection(mut stream: TcpStream, hub: Arc<RelayHub>) -> Result<(), RelayError> {
    let peer_ip = stream
        .peer_addr()
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let _connection_guard = hub.open_connection(peer_ip)?;
    stream
        .set_nonblocking(false)
        .map_err(|error| RelayError::io("configure relay connection mode", error))?;
    stream
        .set_read_timeout(Some(hub.session_policy.idle_timeout))
        .map_err(|error| RelayError::io("configure relay connection", error))?;
    if matches!(
        perform_relay_handshake(&mut stream)?,
        RelayHandshake::HealthCheck
    ) {
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }

    let mut session_node = None::<(String, String)>;
    let mut authenticated_at = None::<Instant>;
    let mut rate_limiter = FrameRateLimiter::new(hub.limits.max_frames_per_minute);

    while let Some(text) = read_text_frame(&mut stream)? {
        if authenticated_at
            .is_some_and(|started| started.elapsed() >= hub.session_policy.max_session_ttl)
        {
            let _ = hub.record_abuse(
                session_node.as_ref().map(|(node_id, _)| node_id.as_str()),
                RelayAbuseKind::SessionExpired,
            );
            write_text_frame(
                &mut stream,
                &render_server_frame(&RelayServerFrame::Error {
                    reason: "session_expired".to_string(),
                }),
            )?;
            break;
        }

        if !rate_limiter.allow() {
            let _ = hub.record_abuse(
                session_node.as_ref().map(|(node_id, _)| node_id.as_str()),
                RelayAbuseKind::RateLimitedSession,
            );
            write_text_frame(
                &mut stream,
                &render_server_frame(&RelayServerFrame::Error {
                    reason: "rate_limited".to_string(),
                }),
            )?;
            break;
        }

        match parse_client_frame(&text) {
            Ok(RelayClientFrame::Admin(request)) => {
                if session_node.is_some() {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "admin_requires_fresh_connection".to_string(),
                        }),
                    )?;
                    break;
                }
                match hub.handle_admin_request(&request) {
                    Ok(result) => {
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::AdminResult(Box::new(result))),
                        )?;
                    }
                    Err(RelayError::Protocol(reason))
                        if reason == "admin_unauthorized" || reason == "admin_scope_denied" =>
                    {
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::Error { reason }),
                        )?;
                        break;
                    }
                    Err(_) => {
                        let _ = hub.record_abuse(None, RelayAbuseKind::AdminFailed);
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::Error {
                                reason: "admin_failed".to_string(),
                            }),
                        )?;
                        break;
                    }
                }
            }
            Ok(RelayClientFrame::Hello(hello)) => {
                if session_node.is_some() {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "already_authenticated".to_string(),
                        }),
                    )?;
                    break;
                }
                if !hub.auth.authorize(&hello.node_id, &hello.auth_token) {
                    let _ = hub.record_abuse(
                        Some(&hello.node_id),
                        RelayAbuseKind::CredentialDeniedSession,
                    );
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "unauthorized".to_string(),
                        }),
                    )?;
                    break;
                }
                if let Some(tenants_file) = hub.admin.tenants_file() {
                    if hosted_tenant_registry_authorizes_node(tenants_file, &hello.node_id).is_err()
                    {
                        let _ = hub.record_abuse(
                            Some(&hello.node_id),
                            RelayAbuseKind::TenantDeniedSession,
                        );
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::Error {
                                reason: "unauthorized".to_string(),
                            }),
                        )?;
                        break;
                    }
                }
                let (session_id, resumed, queued) = hub.add_client(
                    hello.node_id.clone(),
                    hello.resume_session_id.as_deref(),
                    stream
                        .try_clone()
                        .map_err(|error| RelayError::io("clone relay stream", error))?,
                )?;
                hub.record_authenticated_session(&hello.node_id, resumed)?;
                session_node = Some((hello.node_id, session_id.clone()));
                authenticated_at = Some(Instant::now());
                write_text_frame(
                    &mut stream,
                    &render_server_frame(&RelayServerFrame::Welcome {
                        session_id,
                        resumed,
                    }),
                )?;
                for forwarded in queued {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Forwarded(Box::new(forwarded))),
                    )?;
                }
            }
            Ok(RelayClientFrame::Forward(forward)) => {
                let forward = *forward;
                let Some((from_node_id, _)) = session_node.clone() else {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "hello_required".to_string(),
                        }),
                    )?;
                    continue;
                };

                let forwarded = RelayForwarded {
                    from_node_id,
                    to_node_id: forward.to_node_id.clone(),
                    envelope_id: forward.envelope_id.clone(),
                    kind: forward.kind,
                    stream_id: forward.stream_id.clone(),
                    payload_bytes: forward.payload_bytes,
                    from_agent_id: forward.from_agent_id.clone(),
                    to_agent_id: forward.to_agent_id.clone(),
                    body: forward.body.clone(),
                };
                let accounted_payload_bytes = forwarded.payload_bytes as u64;
                if !hub.quota_allows_forward(&forwarded.from_node_id, accounted_payload_bytes) {
                    let _ = hub.record_abuse(
                        Some(&forwarded.from_node_id),
                        RelayAbuseKind::QuotaDeniedForward,
                    );
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Undelivered {
                            to_node_id: forward.to_node_id,
                            envelope_id: forward.envelope_id,
                            reason: "quota_exceeded".to_string(),
                        }),
                    )?;
                    continue;
                }
                match hub.target_or_mailbox(&forward.to_node_id, forwarded.clone())? {
                    RelayForwardDelivery::Online(target) => {
                        hub.record_forward(
                            &forwarded.from_node_id,
                            &forward.to_node_id,
                            accounted_payload_bytes,
                            false,
                        )?;
                        let target_frame =
                            render_server_frame(&RelayServerFrame::Forwarded(Box::new(forwarded)));
                        let mut target = target.lock().map_err(|_| {
                            RelayError::Protocol("relay target lock failed".to_string())
                        })?;
                        write_text_frame(&mut target, &target_frame)?;
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::Sent {
                                to_node_id: forward.to_node_id,
                                envelope_id: forward.envelope_id,
                                payload_bytes: forward.payload_bytes,
                            }),
                        )?;
                    }
                    RelayForwardDelivery::Mailboxed => {
                        hub.record_forward(
                            &forwarded.from_node_id,
                            &forward.to_node_id,
                            accounted_payload_bytes,
                            true,
                        )?;
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::Sent {
                                to_node_id: forward.to_node_id,
                                envelope_id: forward.envelope_id,
                                payload_bytes: forward.payload_bytes,
                            }),
                        )?;
                    }
                    RelayForwardDelivery::Undelivered(reason) => {
                        let _ = hub.record_abuse(
                            Some(&forwarded.from_node_id),
                            RelayAbuseKind::UndeliveredForward,
                        );
                        if reason.starts_with("mailbox_") {
                            let _ = hub.record_abuse(
                                Some(&forwarded.from_node_id),
                                RelayAbuseKind::MailboxRejectedForward,
                            );
                        }
                        write_text_frame(
                            &mut stream,
                            &render_server_frame(&RelayServerFrame::Undelivered {
                                to_node_id: forward.to_node_id,
                                envelope_id: forward.envelope_id,
                                reason: reason.to_string(),
                            }),
                        )?;
                    }
                }
            }
            Ok(RelayClientFrame::Ping) => {
                write_text_frame(&mut stream, &render_server_frame(&RelayServerFrame::Pong))?;
            }
            Err(error) => {
                let _ = hub.record_abuse(None, RelayAbuseKind::MalformedClientFrame);
                write_text_frame(
                    &mut stream,
                    &render_server_frame(&RelayServerFrame::Error {
                        reason: error.to_string(),
                    }),
                )?;
            }
        }
    }

    if let Some((node_id, session_id)) = session_node {
        hub.remove_client(&node_id, &session_id);
    }
    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
}

#[derive(Debug, Default)]
struct RelayHubState {
    clients: HashMap<String, RelayClientConnection>,
    mailbox: HashMap<String, VecDeque<QueuedRelayEnvelope>>,
}

impl RelayHubState {
    fn load(storage: &RelayMailboxStorage, policy: RelayMailboxPolicy) -> Result<Self, RelayError> {
        let mut state = Self::default();
        let RelayMailboxStorage::FileBacked(root) = storage else {
            return Ok(state);
        };

        ensure_relay_directory(root, "create relay mailbox directory")?;
        let mut loaded: HashMap<String, Vec<QueuedRelayEnvelope>> = HashMap::new();
        for node_entry in fs::read_dir(root)
            .map_err(|error| RelayError::io("read relay mailbox directory", error))?
        {
            let node_entry =
                node_entry.map_err(|error| RelayError::io("read relay mailbox entry", error))?;
            let Ok(file_type) = node_entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }

            let node_dir = node_entry.path();
            for entry in fs::read_dir(&node_dir)
                .map_err(|error| RelayError::io("read relay mailbox node directory", error))?
            {
                let entry =
                    entry.map_err(|error| RelayError::io("read relay mailbox envelope", error))?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("mailbox") {
                    continue;
                }
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if !file_type.is_file() {
                    remove_mailbox_file(&path).map_err(|error| {
                        RelayError::io("remove invalid relay mailbox envelope", error)
                    })?;
                    continue;
                }

                let Some(envelope) = (match read_mailbox_file(&path) {
                    Ok(envelope) => envelope,
                    Err(_) => {
                        remove_mailbox_file(&path).map_err(|error| {
                            RelayError::io("remove invalid relay mailbox envelope", error)
                        })?;
                        continue;
                    }
                }) else {
                    remove_mailbox_file(&path).map_err(|error| {
                        RelayError::io("remove invalid relay mailbox envelope", error)
                    })?;
                    continue;
                };
                if envelope.is_expired(policy) {
                    remove_mailbox_file(&path).map_err(|error| {
                        RelayError::io("remove expired relay mailbox envelope", error)
                    })?;
                    continue;
                }
                loaded
                    .entry(envelope.forwarded.to_node_id.clone())
                    .or_default()
                    .push(envelope);
            }
        }

        for (node_id, mut envelopes) in loaded {
            envelopes.sort_by(|left, right| {
                left.queued_at_nanos
                    .cmp(&right.queued_at_nanos)
                    .then_with(|| left.forwarded.envelope_id.cmp(&right.forwarded.envelope_id))
            });
            while envelopes.len() > policy.max_envelopes_per_node {
                if let Some(entry) = envelopes.pop() {
                    remove_entry_storage(&entry).map_err(|error| {
                        RelayError::io("remove capped relay mailbox envelope", error)
                    })?;
                }
            }
            state.mailbox.insert(node_id, envelopes.into());
        }

        Ok(state)
    }

    fn drain_mailbox(
        &mut self,
        node_id: &str,
        policy: RelayMailboxPolicy,
        storage: &RelayMailboxStorage,
    ) -> Result<Vec<RelayForwarded>, RelayError> {
        let Some(queue) = self.mailbox.get_mut(node_id) else {
            return Ok(Vec::new());
        };
        Self::prune_queue(queue, policy, storage);
        let drained_entries: Vec<_> = queue.drain(..).collect();
        if queue.is_empty() {
            self.mailbox.remove(node_id);
        }

        let mut drained = Vec::with_capacity(drained_entries.len());
        for entry in drained_entries {
            remove_entry_storage(&entry)
                .map_err(|error| RelayError::io("remove relay mailbox envelope", error))?;
            drained.push(entry.forwarded);
        }

        Ok(drained)
    }

    fn enqueue_mailbox(
        &mut self,
        node_id: &str,
        forwarded: RelayForwarded,
        policy: RelayMailboxPolicy,
        storage: &RelayMailboxStorage,
    ) -> Result<(), &'static str> {
        let queue = self.mailbox.entry(node_id.to_string()).or_default();
        Self::prune_queue(queue, policy, storage);
        if queue.len() >= policy.max_envelopes_per_node {
            return Err("mailbox_full");
        }

        let queued_at_nanos = current_unix_nanos();
        let mut envelope = QueuedRelayEnvelope {
            queued_at_millis: queued_at_nanos / 1_000_000,
            queued_at_nanos,
            storage_path: None,
            forwarded,
        };
        persist_mailbox_entry(storage, node_id, &mut envelope)?;
        queue.push_back(envelope);
        Ok(())
    }

    fn prune_queue(
        queue: &mut VecDeque<QueuedRelayEnvelope>,
        policy: RelayMailboxPolicy,
        storage: &RelayMailboxStorage,
    ) {
        let _ = storage;
        while queue.front().is_some_and(|entry| entry.is_expired(policy)) {
            if let Some(entry) = queue.pop_front() {
                let _ = remove_entry_storage(&entry);
            }
        }
    }
}

#[derive(Default)]
struct RelaySessionState {
    records: HashMap<String, RelaySessionRecord>,
}

impl fmt::Debug for RelaySessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelaySessionState")
            .field("records", &self.records.len())
            .finish()
    }
}

impl RelaySessionState {
    fn load(
        storage: &RelaySessionStorage,
        _policy: RelaySessionPolicy,
    ) -> Result<Self, RelayError> {
        let RelaySessionStorage::FileBacked(root) = storage else {
            return Ok(Self::default());
        };

        ensure_relay_directory(root, "create relay session state directory")?;
        for attempt in 0..RELAY_SESSION_STATE_LOAD_ATTEMPTS {
            let (state, retry) = Self::load_from_directory(root)?;
            if !retry || attempt + 1 == RELAY_SESSION_STATE_LOAD_ATTEMPTS {
                return Ok(state);
            }
            thread::sleep(RELAY_SESSION_STATE_LOAD_RETRY_DELAY);
        }

        Ok(Self::default())
    }

    fn load_from_directory(root: &Path) -> Result<(Self, bool), RelayError> {
        let mut state = Self::default();
        let mut retry = false;
        let now = current_unix_millis_u64();
        for entry in fs::read_dir(root)
            .map_err(|error| RelayError::io("read relay session state directory", error))?
        {
            let entry =
                entry.map_err(|error| RelayError::io("read relay session state entry", error))?;
            let path = entry.path();
            if is_relay_session_temp_file(&path) {
                retry = true;
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("session") {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    retry = true;
                    continue;
                }
            };
            if !file_type.is_file() {
                let _ = remove_mailbox_file(&path);
                continue;
            }

            let record = match read_session_file(&path) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    let _ = remove_mailbox_file(&path);
                    continue;
                }
                Err(error) if relay_session_load_should_retry(&error) => {
                    retry = true;
                    continue;
                }
                Err(_) => {
                    let _ = remove_mailbox_file(&path);
                    continue;
                }
            };
            if record.is_expired(now) {
                let _ = remove_mailbox_file(&path);
                continue;
            }
            state.records.insert(record.node_id.clone(), record);
        }

        Ok((state, retry))
    }

    fn can_resume(
        &mut self,
        node_id: &str,
        session_id: &str,
        storage: &RelaySessionStorage,
    ) -> Result<bool, RelayError> {
        if !session_id_belongs_to_node(session_id, node_id) {
            return Ok(false);
        }

        let now = current_unix_millis_u64();
        if !self.records.contains_key(node_id) {
            if let Some(record) = Self::load_record_from_storage(storage, node_id)? {
                self.records.insert(record.node_id.clone(), record);
            }
        }
        let Some(record) = self.records.get(node_id) else {
            return Ok(false);
        };
        if record.is_expired(now) {
            self.records.remove(node_id);
            remove_session_record(storage, node_id)?;
            return Ok(false);
        }

        Ok(record.session_id == session_id)
    }

    fn load_record_from_storage(
        storage: &RelaySessionStorage,
        node_id: &str,
    ) -> Result<Option<RelaySessionRecord>, RelayError> {
        let RelaySessionStorage::FileBacked(root) = storage else {
            return Ok(None);
        };
        let path = relay_session_record_path(root, node_id);

        for attempt in 0..RELAY_SESSION_STATE_LOAD_ATTEMPTS {
            match read_session_file(&path) {
                Ok(record) => return Ok(record),
                Err(error)
                    if relay_session_load_should_retry(&error)
                        && attempt + 1 < RELAY_SESSION_STATE_LOAD_ATTEMPTS =>
                {
                    thread::sleep(RELAY_SESSION_STATE_LOAD_RETRY_DELAY);
                }
                Err(RelayError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(_) => return Ok(None),
            }
        }

        Ok(None)
    }

    fn record_authenticated(
        &mut self,
        node_id: &str,
        session_id: &str,
        resumed: bool,
        policy: RelaySessionPolicy,
        storage: &RelaySessionStorage,
    ) -> Result<(), RelayError> {
        let now = current_unix_millis_u64();
        let record = if resumed {
            let mut record =
                self.records.get(node_id).cloned().ok_or_else(|| {
                    RelayError::Protocol("relay session state missing".to_string())
                })?;
            record.last_seen_unix_millis = now;
            record
        } else {
            RelaySessionRecord::new(node_id, session_id, now, policy)
        };
        persist_session_record(storage, &record)?;
        self.records.insert(node_id.to_string(), record);
        Ok(())
    }

    fn touch_session(
        &mut self,
        node_id: &str,
        session_id: &str,
        storage: &RelaySessionStorage,
    ) -> Result<(), RelayError> {
        let Some(record) = self.records.get_mut(node_id) else {
            return Ok(());
        };
        if record.session_id != session_id {
            return Ok(());
        }
        record.last_seen_unix_millis = current_unix_millis_u64();
        persist_session_record(storage, record)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RelaySessionRecord {
    node_id: String,
    session_id: String,
    created_at_unix_millis: u64,
    last_seen_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl fmt::Debug for RelaySessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelaySessionRecord")
            .field("node_id", &self.node_id)
            .field("session_id", &"<redacted>")
            .field("created_at_unix_millis", &self.created_at_unix_millis)
            .field("last_seen_unix_millis", &self.last_seen_unix_millis)
            .field("expires_at_unix_millis", &self.expires_at_unix_millis)
            .finish()
    }
}

impl RelaySessionRecord {
    fn new(
        node_id: &str,
        session_id: &str,
        now_unix_millis: u64,
        policy: RelaySessionPolicy,
    ) -> Self {
        let ttl_millis = policy
            .max_session_ttl
            .as_millis()
            .max(1)
            .min(u64::MAX as u128) as u64;
        Self {
            node_id: node_id.to_string(),
            session_id: session_id.to_string(),
            created_at_unix_millis: now_unix_millis,
            last_seen_unix_millis: now_unix_millis,
            expires_at_unix_millis: now_unix_millis.saturating_add(ttl_millis),
        }
    }

    fn is_expired(&self, now_unix_millis: u64) -> bool {
        now_unix_millis >= self.expires_at_unix_millis
    }
}

#[derive(Debug)]
struct RelayAccountingState {
    window_started_unix: u64,
    records: HashMap<String, RelayAccountingRecord>,
}

impl RelayAccountingState {
    fn load(
        storage: &RelayAccountingStorage,
        policy: RelayAccountingPolicy,
    ) -> Result<Self, RelayError> {
        let window_started_unix = policy.window_start_unix(current_unix_seconds());
        let mut state = Self {
            window_started_unix,
            records: HashMap::new(),
        };
        let RelayAccountingStorage::FileBacked(root) = storage else {
            return Ok(state);
        };

        ensure_relay_directory(root, "create relay accounting directory")?;
        for entry in fs::read_dir(root)
            .map_err(|error| RelayError::io("read relay accounting directory", error))?
        {
            let entry =
                entry.map_err(|error| RelayError::io("read relay accounting entry", error))?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("accounting") {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                let _ = remove_mailbox_file(&path);
                continue;
            }
            let Some(record) = read_accounting_file(&path)? else {
                let _ = remove_mailbox_file(&path);
                continue;
            };
            if record.window_started_unix != window_started_unix {
                let _ = remove_mailbox_file(&path);
                continue;
            }
            state.records.insert(record.node_id.clone(), record);
        }

        Ok(state)
    }

    fn reset_window_if_needed(&mut self, policy: RelayAccountingPolicy) {
        let window_started_unix = policy.window_start_unix(current_unix_seconds());
        if self.window_started_unix != window_started_unix {
            self.window_started_unix = window_started_unix;
            self.records.clear();
        }
    }

    fn quota_allows(
        &mut self,
        node_id: &str,
        payload_bytes: u64,
        policy: RelayAccountingPolicy,
    ) -> bool {
        self.reset_window_if_needed(policy);
        let Some(record) = self.records.get(node_id) else {
            return true;
        };
        if policy
            .max_envelopes_sent_per_node
            .is_some_and(|limit| record.envelopes_sent.saturating_add(1) > limit)
        {
            return false;
        }
        if policy
            .max_bytes_sent_per_node
            .is_some_and(|limit| record.bytes_sent.saturating_add(payload_bytes) > limit)
        {
            return false;
        }

        true
    }

    fn record_session(
        &mut self,
        node_id: &str,
        resumed: bool,
        policy: RelayAccountingPolicy,
        storage: &RelayAccountingStorage,
    ) -> Result<(), RelayError> {
        self.reset_window_if_needed(policy);
        let window_started_unix = self.window_started_unix;
        let record = self
            .records
            .entry(node_id.to_string())
            .or_insert_with(|| RelayAccountingRecord::new(node_id, window_started_unix));
        record.sessions_authenticated = record.sessions_authenticated.saturating_add(1);
        if resumed {
            record.sessions_resumed = record.sessions_resumed.saturating_add(1);
        }
        persist_accounting_record(storage, record)
    }

    fn record_forward(
        &mut self,
        from_node_id: &str,
        to_node_id: &str,
        payload_bytes: u64,
        mailboxed: bool,
        policy: RelayAccountingPolicy,
        storage: &RelayAccountingStorage,
    ) -> Result<(), RelayError> {
        self.reset_window_if_needed(policy);
        let window_started_unix = self.window_started_unix;

        {
            let sender = self
                .records
                .entry(from_node_id.to_string())
                .or_insert_with(|| RelayAccountingRecord::new(from_node_id, window_started_unix));
            sender.envelopes_sent = sender.envelopes_sent.saturating_add(1);
            sender.bytes_sent = sender.bytes_sent.saturating_add(payload_bytes);
        }

        {
            let receiver = self
                .records
                .entry(to_node_id.to_string())
                .or_insert_with(|| RelayAccountingRecord::new(to_node_id, window_started_unix));
            receiver.envelopes_received = receiver.envelopes_received.saturating_add(1);
            receiver.bytes_received = receiver.bytes_received.saturating_add(payload_bytes);
            if mailboxed {
                receiver.envelopes_mailboxed = receiver.envelopes_mailboxed.saturating_add(1);
                receiver.bytes_mailboxed = receiver.bytes_mailboxed.saturating_add(payload_bytes);
            }
        }

        if let Some(sender) = self.records.get(from_node_id) {
            persist_accounting_record(storage, sender)?;
        }
        if from_node_id != to_node_id {
            if let Some(receiver) = self.records.get(to_node_id) {
                persist_accounting_record(storage, receiver)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayAccountingRecord {
    node_id: String,
    window_started_unix: u64,
    sessions_authenticated: u64,
    sessions_resumed: u64,
    envelopes_sent: u64,
    bytes_sent: u64,
    envelopes_received: u64,
    bytes_received: u64,
    envelopes_mailboxed: u64,
    bytes_mailboxed: u64,
}

impl RelayAccountingRecord {
    fn new(node_id: &str, window_started_unix: u64) -> Self {
        Self {
            node_id: node_id.to_string(),
            window_started_unix,
            sessions_authenticated: 0,
            sessions_resumed: 0,
            envelopes_sent: 0,
            bytes_sent: 0,
            envelopes_received: 0,
            bytes_received: 0,
            envelopes_mailboxed: 0,
            bytes_mailboxed: 0,
        }
    }
}

#[derive(Debug)]
struct RelayAbuseState {
    window_started_unix: u64,
    records: HashMap<String, RelayAbuseRecord>,
}

impl RelayAbuseState {
    fn load(storage: &RelayAbuseStorage, policy: RelayAbusePolicy) -> Result<Self, RelayError> {
        let window_started_unix = policy.window_start_unix(current_unix_seconds());
        let mut state = Self {
            window_started_unix,
            records: HashMap::new(),
        };
        let RelayAbuseStorage::FileBacked(root) = storage else {
            return Ok(state);
        };

        ensure_relay_directory(root, "create relay abuse directory")?;
        for entry in fs::read_dir(root)
            .map_err(|error| RelayError::io("read relay abuse directory", error))?
        {
            let entry = entry.map_err(|error| RelayError::io("read relay abuse entry", error))?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("abuse") {
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                let _ = remove_mailbox_file(&path);
                continue;
            }
            let Some(record) = read_abuse_file(&path)? else {
                let _ = remove_mailbox_file(&path);
                continue;
            };
            if record.window_started_unix != window_started_unix {
                let _ = remove_mailbox_file(&path);
                continue;
            }
            state
                .records
                .insert(abuse_record_key(record.node_id.as_deref()), record);
        }

        Ok(state)
    }

    fn reset_window_if_needed(
        &mut self,
        policy: RelayAbusePolicy,
        storage: &RelayAbuseStorage,
    ) -> Result<(), RelayError> {
        let window_started_unix = policy.window_start_unix(current_unix_seconds());
        if self.window_started_unix != window_started_unix {
            self.window_started_unix = window_started_unix;
            self.records.clear();
            purge_abuse_storage(storage)?;
        }
        Ok(())
    }

    fn record_event(
        &mut self,
        node_id: Option<&str>,
        kind: RelayAbuseKind,
        policy: RelayAbusePolicy,
        storage: &RelayAbuseStorage,
    ) -> Result<(), RelayError> {
        self.reset_window_if_needed(policy, storage)?;
        let node_id = node_id.and_then(|value| validate_node_id(value.to_string()).ok());
        let key = abuse_record_key(node_id.as_deref());
        let record = self
            .records
            .entry(key)
            .or_insert_with(|| RelayAbuseRecord::new(node_id, self.window_started_unix));
        record.record(kind);
        persist_abuse_record(storage, record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayAbuseRecord {
    node_id: Option<String>,
    window_started_unix: u64,
    admin_unauthorized: u64,
    admin_failed: u64,
    unauthorized_sessions: u64,
    credential_denied_sessions: u64,
    tenant_denied_sessions: u64,
    rate_limited_sessions: u64,
    session_expired: u64,
    quota_denied_forwards: u64,
    undelivered_forwards: u64,
    mailbox_rejected_forwards: u64,
    malformed_client_frames: u64,
}

impl RelayAbuseRecord {
    fn new(node_id: Option<String>, window_started_unix: u64) -> Self {
        Self {
            node_id,
            window_started_unix,
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
        }
    }

    fn record(&mut self, kind: RelayAbuseKind) {
        match kind {
            RelayAbuseKind::AdminUnauthorized => {
                self.admin_unauthorized = self.admin_unauthorized.saturating_add(1);
            }
            RelayAbuseKind::AdminFailed => {
                self.admin_failed = self.admin_failed.saturating_add(1);
            }
            RelayAbuseKind::CredentialDeniedSession => {
                self.unauthorized_sessions = self.unauthorized_sessions.saturating_add(1);
                self.credential_denied_sessions = self.credential_denied_sessions.saturating_add(1);
            }
            RelayAbuseKind::TenantDeniedSession => {
                self.unauthorized_sessions = self.unauthorized_sessions.saturating_add(1);
                self.tenant_denied_sessions = self.tenant_denied_sessions.saturating_add(1);
            }
            RelayAbuseKind::RateLimitedSession => {
                self.rate_limited_sessions = self.rate_limited_sessions.saturating_add(1);
            }
            RelayAbuseKind::SessionExpired => {
                self.session_expired = self.session_expired.saturating_add(1);
            }
            RelayAbuseKind::QuotaDeniedForward => {
                self.quota_denied_forwards = self.quota_denied_forwards.saturating_add(1);
            }
            RelayAbuseKind::UndeliveredForward => {
                self.undelivered_forwards = self.undelivered_forwards.saturating_add(1);
            }
            RelayAbuseKind::MailboxRejectedForward => {
                self.mailbox_rejected_forwards = self.mailbox_rejected_forwards.saturating_add(1);
            }
            RelayAbuseKind::MalformedClientFrame => {
                self.malformed_client_frames = self.malformed_client_frames.saturating_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RelayAbuseKind {
    AdminUnauthorized,
    AdminFailed,
    CredentialDeniedSession,
    TenantDeniedSession,
    RateLimitedSession,
    SessionExpired,
    QuotaDeniedForward,
    UndeliveredForward,
    MailboxRejectedForward,
    MalformedClientFrame,
}

#[derive(Debug)]
struct QueuedRelayEnvelope {
    queued_at_millis: u128,
    queued_at_nanos: u128,
    storage_path: Option<PathBuf>,
    forwarded: RelayForwarded,
}

impl QueuedRelayEnvelope {
    fn is_expired(&self, policy: RelayMailboxPolicy) -> bool {
        let elapsed_millis = current_unix_millis().saturating_sub(self.queued_at_millis);
        elapsed_millis >= policy.envelope_ttl.as_millis()
    }
}

#[derive(Debug)]
enum RelayForwardDelivery {
    Online(Arc<Mutex<TcpStream>>),
    Mailboxed,
    Undelivered(&'static str),
}

#[derive(Debug, Default)]
struct ConnectionCounts {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

struct ConnectionGuard<'a> {
    hub: &'a RelayHub,
    peer_ip: IpAddr,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.hub.close_connection(self.peer_ip);
    }
}

#[derive(Debug)]
struct RelayClientConnection {
    session_id: String,
    stream: Arc<Mutex<TcpStream>>,
}

#[derive(Debug)]
struct FrameRateLimiter {
    max_frames: usize,
    window_start: Instant,
    frames: usize,
}

impl FrameRateLimiter {
    fn new(max_frames: usize) -> Self {
        Self {
            max_frames,
            window_start: Instant::now(),
            frames: 0,
        }
    }

    fn allow(&mut self) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(60) {
            self.window_start = Instant::now();
            self.frames = 0;
        }

        if self.frames >= self.max_frames {
            return false;
        }

        self.frames += 1;
        true
    }
}

enum RelayHandshake {
    WebSocket,
    HealthCheck,
}

fn perform_relay_handshake(stream: &mut TcpStream) -> Result<RelayHandshake, RelayError> {
    let request = read_http_request(stream)?;
    if is_http_health_check(&request) {
        write_http_health_check(stream)?;
        return Ok(RelayHandshake::HealthCheck);
    }
    let key = header_value(&request, "sec-websocket-key")
        .ok_or_else(|| RelayError::Protocol("missing Sec-WebSocket-Key header".to_string()))?;
    let accept = websocket_accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| RelayError::io("write websocket handshake", error))?;
    Ok(RelayHandshake::WebSocket)
}

fn is_http_health_check(request: &str) -> bool {
    let Some(request_line) = request.lines().next() else {
        return false;
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    method == "GET"
        && matches!(path, "/" | "/healthz")
        && header_value(request, "sec-websocket-key").is_none()
}

fn write_http_health_check(stream: &mut TcpStream) -> Result<(), RelayError> {
    const BODY: &str = "conu-relay ok payload=not_observed\n";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        BODY.len(),
        BODY
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| RelayError::io("write relay health check", error))
}

fn read_http_request(stream: &mut TcpStream) -> Result<String, RelayError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1];

    while bytes.len() < MAX_HTTP_HEADER_BYTES {
        stream
            .read_exact(&mut buffer)
            .map_err(|error| RelayError::io("read websocket handshake", error))?;
        bytes.push(buffer[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| RelayError::Protocol("handshake is not UTF-8".to_string()));
        }
    }

    Err(RelayError::Protocol(
        "websocket handshake headers are too large".to_string(),
    ))
}

fn header_value(request: &str, header: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(header) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn read_text_frame(stream: &mut TcpStream) -> Result<Option<String>, RelayError> {
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
        Err(error) => return Err(RelayError::io("read websocket frame", error)),
    }

    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = u64::from(header[1] & 0x7f);

    if len == 126 {
        let mut bytes = [0_u8; 2];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayError::io("read websocket frame length", error))?;
        len = u64::from(u16::from_be_bytes(bytes));
    } else if len == 127 {
        let mut bytes = [0_u8; 8];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayError::io("read websocket frame length", error))?;
        len = u64::from_be_bytes(bytes);
    }

    if len as usize > MAX_FRAME_BYTES {
        return Err(RelayError::Protocol(
            "websocket frame is too large".to_string(),
        ));
    }

    let mut mask = [0_u8; 4];
    if masked {
        stream
            .read_exact(&mut mask)
            .map_err(|error| RelayError::io("read websocket frame mask", error))?;
    }

    let mut payload = vec![0_u8; len as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|error| RelayError::io("read websocket frame payload", error))?;

    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    match opcode {
        0x1 => String::from_utf8(payload)
            .map(Some)
            .map_err(|_| RelayError::Protocol("text frame is not UTF-8".to_string())),
        0x8 => Ok(None),
        0x9 => {
            write_raw_frame(stream, 0xA, &payload)?;
            Ok(Some("PING payload=not_observed".to_string()))
        }
        _ => Err(RelayError::Protocol(
            "unsupported websocket frame opcode".to_string(),
        )),
    }
}

fn write_text_frame(stream: &mut TcpStream, text: &str) -> Result<(), RelayError> {
    write_raw_frame(stream, 0x1, text.as_bytes())
}

fn write_raw_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> Result<(), RelayError> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);

    if payload.len() <= 125 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    frame.extend_from_slice(payload);
    stream
        .write_all(&frame)
        .map_err(|error| RelayError::io("write websocket frame", error))
}

fn session_id(node_id: &str) -> String {
    format!(
        "relay_{}_{}",
        sanitize_identifier(node_id),
        current_unix_nanos()
    )
}

fn session_id_belongs_to_node(session_id: &str, node_id: &str) -> bool {
    let prefix = format!("relay_{}_", sanitize_identifier(node_id));
    session_id.starts_with(&prefix)
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect()
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn current_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn current_unix_millis_u64() -> u64 {
    current_unix_millis().min(u64::MAX as u128) as u64
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn persist_mailbox_entry(
    storage: &RelayMailboxStorage,
    node_id: &str,
    entry: &mut QueuedRelayEnvelope,
) -> Result<(), &'static str> {
    let RelayMailboxStorage::FileBacked(root) = storage else {
        return Ok(());
    };

    ensure_relay_directory(root, "create relay mailbox directory")
        .map_err(|_| "mailbox_unavailable")?;
    let node_dir = root.join(sanitize_identifier(node_id));
    ensure_relay_directory(&node_dir, "create relay mailbox node directory")
        .map_err(|_| "mailbox_unavailable")?;
    let path = node_dir.join(format!(
        "{}-{}.mailbox",
        entry.queued_at_nanos,
        sanitize_identifier(&entry.forwarded.envelope_id)
    ));
    let contents = render_mailbox_file(entry);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| "mailbox_unavailable")?;
    file.write_all(contents.as_bytes())
        .map_err(|_| "mailbox_unavailable")?;
    entry.storage_path = Some(path);
    Ok(())
}

fn render_mailbox_file(entry: &QueuedRelayEnvelope) -> String {
    let frame = render_server_frame(&RelayServerFrame::Forwarded(Box::new(
        entry.forwarded.clone(),
    )));
    format!(
        "version = \"{}\"\nqueued_at_millis = {}\nqueued_at_nanos = {}\nframe = {}\npayload_displayed = false\n",
        RELAY_MAILBOX_FILE_VERSION, entry.queued_at_millis, entry.queued_at_nanos, frame
    )
}

fn read_mailbox_file(path: &Path) -> Result<Option<QueuedRelayEnvelope>, RelayError> {
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay mailbox file",
        "read relay mailbox file",
    )?;
    let version = relay_metadata_value(&contents, "version", "relay mailbox entry is invalid")?
        .unwrap_or_default();
    if version != RELAY_MAILBOX_FILE_VERSION {
        return Ok(None);
    }
    if !relay_metadata_false_guard(
        &contents,
        "payload_displayed",
        "relay mailbox entry is invalid",
    )? {
        return Ok(None);
    }
    let queued_at_millis = relay_metadata_value(
        &contents,
        "queued_at_millis",
        "relay mailbox entry is invalid",
    )?
    .and_then(|value| value.parse::<u128>().ok())
    .ok_or_else(|| RelayError::Protocol("relay mailbox entry is invalid".to_string()))?;
    let queued_at_nanos = relay_metadata_value(
        &contents,
        "queued_at_nanos",
        "relay mailbox entry is invalid",
    )?
    .and_then(|value| value.parse::<u128>().ok())
    .or_else(|| mailbox_file_sequence(path))
    .unwrap_or_else(|| queued_at_millis.saturating_mul(1_000_000));
    let frame = relay_metadata_value(&contents, "frame", "relay mailbox entry is invalid")?
        .ok_or_else(|| RelayError::Protocol("relay mailbox entry is invalid".to_string()))?;
    let forwarded = match parse_server_frame(&frame) {
        Ok(RelayServerFrame::Forwarded(forwarded)) => *forwarded,
        _ => return Ok(None),
    };
    if forwarded.body.is_none() {
        return Ok(None);
    }

    Ok(Some(QueuedRelayEnvelope {
        queued_at_millis,
        queued_at_nanos,
        storage_path: Some(path.to_path_buf()),
        forwarded,
    }))
}

fn audit_mailbox_node_dir(
    audit: &mut RelayMailboxAudit,
    node_dir: &Path,
    now_millis: u128,
    retention_ttl_millis: Option<u128>,
) -> Result<(), RelayError> {
    let mut node_records = 0usize;
    for entry in fs::read_dir(node_dir)
        .map_err(|error| RelayError::io("read relay mailbox node directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay mailbox envelope", error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("mailbox") {
            continue;
        }

        node_records = node_records.saturating_add(1);
        audit.records = audit.records.saturating_add(1);
        let Ok(file_type) = entry.file_type() else {
            audit.invalid_records = audit.invalid_records.saturating_add(1);
            continue;
        };
        if !file_type.is_file() {
            audit.invalid_records = audit.invalid_records.saturating_add(1);
            continue;
        }
        let byte_len = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        audit.bytes = audit.bytes.saturating_add(byte_len);

        let queued_at_millis = match read_mailbox_audit_timestamp(&path) {
            Ok(Some(queued_at_millis)) => queued_at_millis,
            Ok(None) | Err(RelayError::Protocol(_)) => {
                audit.invalid_records = audit.invalid_records.saturating_add(1);
                continue;
            }
            Err(error) => return Err(error),
        };

        let queued_at_u64 = queued_at_millis.min(u64::MAX as u128) as u64;
        audit.oldest_queued_unix_millis = Some(
            audit
                .oldest_queued_unix_millis
                .map(|existing| existing.min(queued_at_u64))
                .unwrap_or(queued_at_u64),
        );
        audit.newest_queued_unix_millis = Some(
            audit
                .newest_queued_unix_millis
                .map(|existing| existing.max(queued_at_u64))
                .unwrap_or(queued_at_u64),
        );

        if let Some(ttl_millis) = retention_ttl_millis {
            let expired = now_millis.saturating_sub(queued_at_millis) >= ttl_millis;
            if expired {
                audit.expired_records = audit
                    .expired_records
                    .map(|records| records.saturating_add(1));
                audit.expired_bytes = audit
                    .expired_bytes
                    .map(|bytes| bytes.saturating_add(byte_len));
            }
        }
    }

    if node_records > 0 {
        audit.nodes = audit.nodes.saturating_add(1);
    }
    Ok(())
}

fn read_mailbox_audit_timestamp(path: &Path) -> Result<Option<u128>, RelayError> {
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay mailbox file",
        "read relay mailbox file",
    )?;
    let version = relay_metadata_value(&contents, "version", "relay mailbox entry is invalid")?
        .unwrap_or_default();
    if version != RELAY_MAILBOX_FILE_VERSION {
        return Ok(None);
    }
    if !relay_metadata_false_guard(
        &contents,
        "payload_displayed",
        "relay mailbox entry is invalid",
    )? {
        return Ok(None);
    }
    let Some(queued_at_millis) = relay_metadata_value(
        &contents,
        "queued_at_millis",
        "relay mailbox entry is invalid",
    )?
    .and_then(|value| value.parse::<u128>().ok()) else {
        return Ok(None);
    };
    Ok(Some(queued_at_millis))
}

fn purge_mailbox_node_dir(
    report: &mut RelayMailboxPurgeReport,
    node_dir: &Path,
    now_millis: u128,
    retention_ttl_millis: u128,
) -> Result<(), RelayError> {
    let mut node_records = 0usize;
    for entry in fs::read_dir(node_dir)
        .map_err(|error| RelayError::io("read relay mailbox node directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay mailbox envelope", error))?;
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("mailbox") {
            continue;
        }

        node_records = node_records.saturating_add(1);
        report.records = report.records.saturating_add(1);
        let byte_len = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        report.bytes = report.bytes.saturating_add(byte_len);

        let Some(queued_at_millis) = read_mailbox_purge_timestamp(&path)? else {
            report.invalid_records = report.invalid_records.saturating_add(1);
            continue;
        };
        let expired = now_millis.saturating_sub(queued_at_millis) >= retention_ttl_millis;
        if !expired {
            continue;
        }

        report.expired_records = report.expired_records.saturating_add(1);
        report.expired_bytes = report.expired_bytes.saturating_add(byte_len);
        if !report.dry_run {
            remove_mailbox_file(&path)
                .map_err(|error| RelayError::io("remove expired relay mailbox file", error))?;
            report.purged_records = report.purged_records.saturating_add(1);
            report.purged_bytes = report.purged_bytes.saturating_add(byte_len);
        }
    }

    if node_records > 0 {
        report.nodes = report.nodes.saturating_add(1);
    }
    Ok(())
}

fn read_mailbox_purge_timestamp(path: &Path) -> Result<Option<u128>, RelayError> {
    match read_mailbox_file(path) {
        Ok(Some(entry)) => Ok(Some(entry.queued_at_millis)),
        Ok(None) | Err(RelayError::Protocol(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn mailbox_file_sequence(path: &Path) -> Option<u128> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .and_then(|value| value.split_once('-').map(|(sequence, _)| sequence))
        .and_then(|value| value.parse::<u128>().ok())
}

fn persist_session_record(
    storage: &RelaySessionStorage,
    record: &RelaySessionRecord,
) -> Result<(), RelayError> {
    let RelaySessionStorage::FileBacked(root) = storage else {
        return Ok(());
    };

    ensure_relay_directory(root, "create relay session state directory")?;
    let path = relay_session_record_path(root, &record.node_id);
    let contents = render_session_file(record);
    write_relay_metadata_file(
        &path,
        &contents,
        "inspect relay session state file replacement",
        "create temporary relay session state file",
        "write temporary relay session state file",
        "replace relay session state file",
    )
}

fn remove_session_record(storage: &RelaySessionStorage, node_id: &str) -> Result<(), RelayError> {
    let RelaySessionStorage::FileBacked(root) = storage else {
        return Ok(());
    };

    remove_mailbox_file(&relay_session_record_path(root, node_id))
        .map_err(|error| RelayError::io("remove relay session state file", error))
}

fn relay_session_record_path(root: &Path, node_id: &str) -> PathBuf {
    root.join(format!("{}.session", sanitize_identifier(node_id)))
}

fn is_relay_session_temp_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with('.') && name.contains(".session.") && name.ends_with(".tmp")
        })
}

fn relay_session_load_should_retry(error: &RelayError) -> bool {
    match error {
        RelayError::Io { source, .. } => matches!(
            source.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::Interrupted
        ),
        RelayError::InvalidConfig(_)
        | RelayError::InvalidConfigValue(_)
        | RelayError::Protocol(_) => false,
    }
}

fn render_session_file(record: &RelaySessionRecord) -> String {
    format!(
        "version = \"{}\"\nnode_id = \"{}\"\nsession_id = \"{}\"\ncreated_at_unix_millis = {}\nlast_seen_unix_millis = {}\nexpires_at_unix_millis = {}\npayload_displayed = false\ntoken_displayed = false\ncontents_displayed = false\n",
        RELAY_SESSION_FILE_VERSION,
        record.node_id,
        record.session_id,
        record.created_at_unix_millis,
        record.last_seen_unix_millis,
        record.expires_at_unix_millis
    )
}

fn read_session_file(path: &Path) -> Result<Option<RelaySessionRecord>, RelayError> {
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay session state file",
        "read relay session state file",
    )?;
    let version =
        relay_metadata_value(&contents, "version", "relay session state entry is invalid")?
            .unwrap_or_default();
    if version != RELAY_SESSION_FILE_VERSION {
        return Ok(None);
    }
    if !relay_metadata_false_guard(
        &contents,
        "payload_displayed",
        "relay session state entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "token_displayed",
        "relay session state entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "contents_displayed",
        "relay session state entry is invalid",
    )? {
        return Ok(None);
    }
    let Some(node_id) =
        relay_metadata_value(&contents, "node_id", "relay session state entry is invalid")?
    else {
        return Ok(None);
    };
    let Ok(node_id) = validate_node_id(node_id) else {
        return Ok(None);
    };
    let Some(session_id) = relay_metadata_value(
        &contents,
        "session_id",
        "relay session state entry is invalid",
    )?
    else {
        return Ok(None);
    };
    if !session_id_belongs_to_node(&session_id, &node_id) {
        return Ok(None);
    }

    Ok(Some(RelaySessionRecord {
        node_id,
        session_id,
        created_at_unix_millis: parse_session_u64(&contents, "created_at_unix_millis")?,
        last_seen_unix_millis: parse_session_u64(&contents, "last_seen_unix_millis")?,
        expires_at_unix_millis: parse_session_u64(&contents, "expires_at_unix_millis")?,
    }))
}

fn parse_session_u64(contents: &str, key: &str) -> Result<u64, RelayError> {
    relay_metadata_value(contents, key, "relay session state entry is invalid")?
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| RelayError::Protocol("relay session state entry is invalid".to_string()))
}

fn persist_accounting_record(
    storage: &RelayAccountingStorage,
    record: &RelayAccountingRecord,
) -> Result<(), RelayError> {
    let RelayAccountingStorage::FileBacked(root) = storage else {
        return Ok(());
    };

    ensure_relay_directory(root, "create relay accounting directory")?;
    let path = root.join(format!(
        "{}.accounting",
        sanitize_identifier(&record.node_id)
    ));
    let contents = render_accounting_file(record);
    write_relay_metadata_file(
        &path,
        &contents,
        "inspect relay accounting file replacement",
        "create temporary relay accounting file",
        "write temporary relay accounting file",
        "replace relay accounting file",
    )
}

fn render_accounting_file(record: &RelayAccountingRecord) -> String {
    format!(
        "version = \"{}\"\nnode_id = \"{}\"\nwindow_started_unix = {}\nsessions_authenticated = {}\nsessions_resumed = {}\nenvelopes_sent = {}\nbytes_sent = {}\nenvelopes_received = {}\nbytes_received = {}\nenvelopes_mailboxed = {}\nbytes_mailboxed = {}\npayload_displayed = false\ntoken_displayed = false\n",
        RELAY_ACCOUNTING_FILE_VERSION,
        record.node_id,
        record.window_started_unix,
        record.sessions_authenticated,
        record.sessions_resumed,
        record.envelopes_sent,
        record.bytes_sent,
        record.envelopes_received,
        record.bytes_received,
        record.envelopes_mailboxed,
        record.bytes_mailboxed
    )
}

fn read_accounting_file(path: &Path) -> Result<Option<RelayAccountingRecord>, RelayError> {
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay accounting file",
        "read relay accounting file",
    )?;
    let version = relay_metadata_value(&contents, "version", "relay accounting entry is invalid")?
        .unwrap_or_default();
    if version != RELAY_ACCOUNTING_FILE_VERSION {
        return Ok(None);
    }
    if !relay_metadata_false_guard(
        &contents,
        "payload_displayed",
        "relay accounting entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "token_displayed",
        "relay accounting entry is invalid",
    )? {
        return Ok(None);
    }
    let Some(node_id) =
        relay_metadata_value(&contents, "node_id", "relay accounting entry is invalid")?
    else {
        return Ok(None);
    };
    let Ok(node_id) = validate_node_id(node_id) else {
        return Ok(None);
    };

    Ok(Some(RelayAccountingRecord {
        node_id,
        window_started_unix: parse_accounting_u64(&contents, "window_started_unix")?,
        sessions_authenticated: parse_accounting_u64(&contents, "sessions_authenticated")?,
        sessions_resumed: parse_optional_accounting_u64(&contents, "sessions_resumed")?
            .unwrap_or(0),
        envelopes_sent: parse_accounting_u64(&contents, "envelopes_sent")?,
        bytes_sent: parse_accounting_u64(&contents, "bytes_sent")?,
        envelopes_received: parse_accounting_u64(&contents, "envelopes_received")?,
        bytes_received: parse_accounting_u64(&contents, "bytes_received")?,
        envelopes_mailboxed: parse_accounting_u64(&contents, "envelopes_mailboxed")?,
        bytes_mailboxed: parse_accounting_u64(&contents, "bytes_mailboxed")?,
    }))
}

fn parse_accounting_u64(contents: &str, key: &str) -> Result<u64, RelayError> {
    relay_metadata_value(contents, key, "relay accounting entry is invalid")?
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| RelayError::Protocol("relay accounting entry is invalid".to_string()))
}

fn parse_optional_accounting_u64(contents: &str, key: &str) -> Result<Option<u64>, RelayError> {
    relay_metadata_value(contents, key, "relay accounting entry is invalid")?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| RelayError::Protocol("relay accounting entry is invalid".to_string()))
        })
        .transpose()
}

fn persist_abuse_record(
    storage: &RelayAbuseStorage,
    record: &RelayAbuseRecord,
) -> Result<(), RelayError> {
    let RelayAbuseStorage::FileBacked(root) = storage else {
        return Ok(());
    };

    ensure_relay_directory(root, "create relay abuse directory")?;
    let path = abuse_record_path(root, record.node_id.as_deref());
    let contents = render_abuse_file(record);
    write_relay_metadata_file(
        &path,
        &contents,
        "inspect relay abuse file replacement",
        "create temporary relay abuse file",
        "write temporary relay abuse file",
        "replace relay abuse file",
    )
}

fn purge_abuse_storage(storage: &RelayAbuseStorage) -> Result<(), RelayError> {
    let RelayAbuseStorage::FileBacked(root) = storage else {
        return Ok(());
    };
    if !relay_directory_exists(root, "inspect relay abuse directory")? {
        return Ok(());
    }
    for entry in
        fs::read_dir(root).map_err(|error| RelayError::io("read relay abuse directory", error))?
    {
        let entry = entry.map_err(|error| RelayError::io("read relay abuse entry", error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("abuse") {
            remove_mailbox_file(&path)
                .map_err(|error| RelayError::io("remove relay abuse file", error))?;
        }
    }
    Ok(())
}

fn abuse_record_key(node_id: Option<&str>) -> String {
    match node_id {
        Some(node_id) => format!("node:{node_id}"),
        None => "global".to_string(),
    }
}

fn abuse_record_path(root: &Path, node_id: Option<&str>) -> PathBuf {
    match node_id {
        Some(node_id) => root.join(format!("node-{}.abuse", sanitize_identifier(node_id))),
        None => root.join("global.abuse"),
    }
}

fn render_abuse_file(record: &RelayAbuseRecord) -> String {
    let mut contents = format!(
        "version = \"{}\"\nscope = \"{}\"\n",
        RELAY_ABUSE_FILE_VERSION,
        if record.node_id.is_some() {
            "node"
        } else {
            "global"
        }
    );
    if let Some(node_id) = record.node_id.as_deref() {
        contents.push_str(&format!("node_id = \"{}\"\n", node_id));
    }
    contents.push_str(&format!(
        "window_started_unix = {}\nadmin_unauthorized = {}\nadmin_failed = {}\nunauthorized_sessions = {}\ncredential_denied_sessions = {}\ntenant_denied_sessions = {}\nrate_limited_sessions = {}\nsession_expired = {}\nquota_denied_forwards = {}\nundelivered_forwards = {}\nmailbox_rejected_forwards = {}\nmalformed_client_frames = {}\npayload_displayed = false\ntoken_displayed = false\ntoken_hash_displayed = false\nkey_material_displayed = false\nsession_id_displayed = false\nciphertext_displayed = false\ncontents_displayed = false\n",
        record.window_started_unix,
        record.admin_unauthorized,
        record.admin_failed,
        record.unauthorized_sessions,
        record.credential_denied_sessions,
        record.tenant_denied_sessions,
        record.rate_limited_sessions,
        record.session_expired,
        record.quota_denied_forwards,
        record.undelivered_forwards,
        record.mailbox_rejected_forwards,
        record.malformed_client_frames
    ));
    contents
}

fn read_abuse_file(path: &Path) -> Result<Option<RelayAbuseRecord>, RelayError> {
    let contents = read_required_regular_relay_file(
        path,
        "inspect relay abuse file",
        "read relay abuse file",
    )?;
    let version = relay_metadata_value(&contents, "version", "relay abuse entry is invalid")?
        .unwrap_or_default();
    if version != RELAY_ABUSE_FILE_VERSION {
        return Ok(None);
    }
    if !relay_metadata_false_guard(
        &contents,
        "payload_displayed",
        "relay abuse entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "token_displayed",
        "relay abuse entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "token_hash_displayed",
        "relay abuse entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "key_material_displayed",
        "relay abuse entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "session_id_displayed",
        "relay abuse entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "ciphertext_displayed",
        "relay abuse entry is invalid",
    )? || !relay_metadata_false_guard(
        &contents,
        "contents_displayed",
        "relay abuse entry is invalid",
    )? {
        return Ok(None);
    }
    let scope = relay_metadata_value(&contents, "scope", "relay abuse entry is invalid")?
        .unwrap_or_else(|| "node".to_string());
    let node_id = match scope.as_str() {
        "global" => None,
        "node" => {
            let Some(node_id) =
                relay_metadata_value(&contents, "node_id", "relay abuse entry is invalid")?
            else {
                return Ok(None);
            };
            let Ok(node_id) = validate_node_id(node_id) else {
                return Ok(None);
            };
            Some(node_id)
        }
        _ => return Ok(None),
    };

    Ok(Some(RelayAbuseRecord {
        node_id,
        window_started_unix: parse_abuse_u64(&contents, "window_started_unix")?,
        admin_unauthorized: parse_abuse_u64(&contents, "admin_unauthorized")?,
        admin_failed: parse_abuse_u64(&contents, "admin_failed")?,
        unauthorized_sessions: parse_abuse_u64(&contents, "unauthorized_sessions")?,
        credential_denied_sessions: parse_abuse_u64(&contents, "credential_denied_sessions")?,
        tenant_denied_sessions: parse_abuse_u64(&contents, "tenant_denied_sessions")?,
        rate_limited_sessions: parse_abuse_u64(&contents, "rate_limited_sessions")?,
        session_expired: parse_abuse_u64(&contents, "session_expired")?,
        quota_denied_forwards: parse_abuse_u64(&contents, "quota_denied_forwards")?,
        undelivered_forwards: parse_optional_abuse_u64(&contents, "undelivered_forwards")?
            .unwrap_or(0),
        mailbox_rejected_forwards: parse_abuse_u64(&contents, "mailbox_rejected_forwards")?,
        malformed_client_frames: parse_abuse_u64(&contents, "malformed_client_frames")?,
    }))
}

fn parse_abuse_u64(contents: &str, key: &str) -> Result<u64, RelayError> {
    relay_metadata_value(contents, key, "relay abuse entry is invalid")?
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| RelayError::Protocol("relay abuse entry is invalid".to_string()))
}

fn parse_optional_abuse_u64(contents: &str, key: &str) -> Result<Option<u64>, RelayError> {
    relay_metadata_value(contents, key, "relay abuse entry is invalid")?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| RelayError::Protocol("relay abuse entry is invalid".to_string()))
        })
        .transpose()
}

fn relay_metadata_value(
    contents: &str,
    key: &str,
    invalid_reason: &'static str,
) -> Result<Option<String>, RelayError> {
    let prefix = format!("{key} = ");
    let mut found = None;
    for line in contents.lines() {
        let Some(value) = line.trim().strip_prefix(&prefix) else {
            continue;
        };
        if found.is_some() {
            return Err(RelayError::Protocol(invalid_reason.to_string()));
        }
        found = Some(value.trim().trim_matches('"').to_string());
    }
    Ok(found)
}

fn relay_metadata_false_guard(
    contents: &str,
    key: &str,
    invalid_reason: &'static str,
) -> Result<bool, RelayError> {
    Ok(relay_metadata_value(contents, key, invalid_reason)?.as_deref() == Some("false"))
}

fn strip_config_comment(line: &str) -> &str {
    line.split_once('#')
        .map(|(before, _)| before)
        .unwrap_or(line)
}

fn clean_config_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn parse_config_bool(value: &str, line_number: usize, key: &str) -> Result<bool, RelayError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(RelayError::InvalidConfigValue(format!(
            "relay config file line {line_number} {key} must be true or false"
        ))),
    }
}

fn remove_entry_storage(entry: &QueuedRelayEnvelope) -> io::Result<()> {
    let Some(path) = entry.storage_path.as_deref() else {
        return Ok(());
    };
    remove_mailbox_file(path)
}

fn remove_mailbox_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn bind_addr_is_public(bind_addr: &str) -> bool {
    let host = bind_host(bind_addr);
    if host.is_empty() || host == "*" {
        return true;
    }
    if host.eq_ignore_ascii_case("localhost") || host.eq_ignore_ascii_case("localhost.localdomain")
    {
        return false;
    }

    host.parse::<IpAddr>()
        .map(|ip| !ip.is_loopback())
        .unwrap_or(true)
}

fn bind_host(bind_addr: &str) -> String {
    let bind_addr = bind_addr.trim();
    if let Some(rest) = bind_addr.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host.trim().to_string();
        }
    }

    bind_addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(bind_addr)
        .trim()
        .to_string()
}

fn validate_node_id(value: String) -> Result<String, RelayError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayError::InvalidConfig("relay node id cannot be empty"));
    }
    if value.len() > 120 {
        return Err(RelayError::InvalidConfig("relay node id is too long"));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayError::InvalidConfig(
            "relay node id must use ASCII letters, numbers, dash, underscore, or dot",
        ));
    }
    Ok(value)
}

fn validate_node_id_ref(value: &str) -> Result<&str, RelayError> {
    validate_node_id(value.to_string())?;
    Ok(value)
}

fn validate_account_id(value: String) -> Result<String, RelayError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayError::InvalidConfig(
            "relay account id cannot be empty",
        ));
    }
    if value.len() > 120 {
        return Err(RelayError::InvalidConfig("relay account id is too long"));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayError::InvalidConfig(
            "relay account id must use ASCII letters, numbers, dash, underscore, or dot",
        ));
    }
    Ok(value)
}

fn validate_account_id_ref(value: &str) -> Result<&str, RelayError> {
    validate_account_id(value.to_string())?;
    Ok(value)
}

fn validate_key_id(value: String, label: &'static str) -> Result<String, RelayError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayError::InvalidConfigValue(format!(
            "{label} cannot be empty"
        )));
    }
    if value.len() > 160 {
        return Err(RelayError::InvalidConfigValue(format!(
            "{label} is too long"
        )));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayError::InvalidConfigValue(format!(
            "{label} must use ASCII letters, numbers, dash, underscore, or dot"
        )));
    }
    Ok(value)
}

fn validate_token(value: &str) -> Result<(), RelayError> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(RelayError::InvalidConfig(
            "relay auth token must be non-empty and contain no whitespace",
        ));
    }
    if value.len() > MAX_TOKEN_LEN {
        return Err(RelayError::InvalidConfig("relay auth token is too long"));
    }
    Ok(())
}

fn validate_token_for_bind(bind_addr: &str, token: &str) -> Result<(), RelayError> {
    validate_token(token)?;
    if bind_addr_is_public(bind_addr) {
        if token == LOCAL_DEV_TOKEN {
            return Err(RelayError::InvalidConfig(
                "non-loopback relay binds require custom relay credentials; the dev token is loopback-only",
            ));
        }
        if token.len() < MIN_PUBLIC_BIND_TOKEN_LEN {
            return Err(RelayError::InvalidConfig(
                "non-loopback relay tokens must be at least 24 characters",
            ));
        }
    }
    Ok(())
}

fn validate_admin_token(bind_addr: &str, token: &str) -> Result<(), RelayError> {
    validate_token(token)?;
    if token == LOCAL_DEV_TOKEN || token.len() < MIN_PUBLIC_BIND_TOKEN_LEN {
        return Err(RelayError::InvalidConfig(
            "relay admin token must be custom and at least 24 characters",
        ));
    }
    validate_token_for_bind(bind_addr, token)
}

fn hosted_admin_error_status(error: &RelayError) -> Option<&'static str> {
    let message = error.to_string();
    if message.contains("already exists") {
        Some("already_exists")
    } else if message.contains("hosted tenant account was not found") {
        Some("tenant_not_found")
    } else if message.contains("hosted tenant account is revoked") {
        Some("tenant_revoked")
    } else if message.contains("hosted tenant node was not found") {
        Some("tenant_node_not_found")
    } else if message.contains("hosted tenant node is revoked") {
        Some("tenant_node_revoked")
    } else if message.contains("hosted tenant node belongs to a different account") {
        Some("account_mismatch")
    } else if message.contains("was not found") {
        Some("not_found")
    } else if message.contains("different account") {
        Some("account_mismatch")
    } else {
        None
    }
}

fn validate_hashed_token_for_bind(
    bind_addr: &str,
    token_sha256_hex: &str,
    token_length: usize,
) -> Result<(), RelayError> {
    validate_token_sha256_hex(token_sha256_hex.to_string())?;
    validate_token_length_metadata(token_length)?;
    if bind_addr_is_public(bind_addr) {
        if constant_time_eq(
            token_sha256_hex.as_bytes(),
            sha256_hex(LOCAL_DEV_TOKEN.as_bytes()).as_bytes(),
        ) {
            return Err(RelayError::InvalidConfig(
                "non-loopback relay binds require custom relay credentials; the dev token is loopback-only",
            ));
        }
        if token_length < MIN_PUBLIC_BIND_TOKEN_LEN {
            return Err(RelayError::InvalidConfig(
                "non-loopback relay tokens must be at least 24 characters",
            ));
        }
    }
    Ok(())
}

fn validate_token_sha256_hex(value: String) -> Result<String, RelayError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RelayError::InvalidConfig(
            "relay credential token_sha256_hex must contain 64 hex characters",
        ));
    }
    Ok(value)
}

fn validate_token_length_metadata(token_length: usize) -> Result<(), RelayError> {
    if token_length == 0 {
        return Err(RelayError::InvalidConfig(
            "relay credential token_length must be greater than zero",
        ));
    }
    if token_length > MAX_TOKEN_LEN {
        return Err(RelayError::InvalidConfig(
            "relay credential token_length is too large",
        ));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());

    for index in 0..max_len {
        let left = *left.get(index).unwrap_or(&0);
        let right = *right.get(index).unwrap_or(&0);
        diff |= usize::from(left ^ right);
    }

    diff == 0
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }

    encoded
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

#[cfg(test)]
mod tests {
    use super::*;
    use conu_core::agents::{self, AgentRegistration};
    use conu_core::messages;
    use conu_core::relay::{RelayForward, RelayHello, RelayOpaqueBody, render_client_frame};
    use conu_core::relay_delivery::{self, RelayRuntimePump, RemoteMessage};
    use conu_core::{policy, rooms, sessions, state, streams, trust};
    use conu_protocol::OpaquePayload;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process;

    const TEST_HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(3);
    const TEST_SERVER_FRAME_POLL: Duration = Duration::from_millis(500);
    const TEST_SERVER_FRAME_WAIT: Duration = Duration::from_secs(10);

    #[test]
    fn websocket_accept_key_matches_rfc_example() {
        let accept = websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ==");

        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn loopback_bind_allows_dev_token() {
        let config =
            RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("loopback dev token ok");

        assert!(config.auth.authorize("node.local", "local-dev-token"));
    }

    #[test]
    fn loopback_hostname_aliases_allow_dev_token() {
        for bind_addr in [
            "localhost:0",
            "LOCALHOST:0",
            "localhost.localdomain:0",
            "LOCALHOST.LOCALDOMAIN:0",
        ] {
            let config =
                RelayConfig::new(bind_addr, "local-dev-token").expect("loopback dev token ok");

            assert!(config.auth.authorize("node.local", "local-dev-token"));
        }
    }

    #[test]
    fn public_bind_rejects_dev_token() {
        let error = RelayConfig::new("0.0.0.0:8787", "local-dev-token")
            .expect_err("public dev token should be rejected");

        assert!(error.to_string().contains("loopback-only"));
        assert!(!error.to_string().contains("local-dev-token"));
    }

    #[test]
    fn public_bind_requires_long_token() {
        let error = RelayConfig::new("0.0.0.0:8787", "short-token")
            .expect_err("short public token should be rejected");

        assert!(error.to_string().contains("at least 24"));
        assert!(!error.to_string().contains("short-token"));
    }

    #[test]
    fn public_bind_accepts_long_custom_token() {
        let config = RelayConfig::new("0.0.0.0:8787", "replace-with-a-long-random-relay-token")
            .expect("long public token ok");

        assert!(
            config
                .auth
                .authorize("node.public", "replace-with-a-long-random-relay-token")
        );
    }

    #[test]
    fn public_bind_rejects_scoped_dev_token() {
        let credential =
            RelayCredential::new("node.a", "local-dev-token").expect("credential parses");
        let error = RelayConfig::with_scoped_credentials("0.0.0.0:8787", vec![credential])
            .expect_err("public dev scoped token should be rejected");

        assert!(error.to_string().contains("loopback-only"));
        assert!(!error.to_string().contains("local-dev-token"));
    }

    #[test]
    fn relay_config_debug_redacts_tokens() {
        let shared =
            RelayConfig::new("127.0.0.1:0", "shared-secret-token").expect("shared config parses");
        let credential =
            RelayCredential::new("node.a", "node-a-secret-token").expect("credential parses");
        let scoped = RelayConfig::with_scoped_credentials("127.0.0.1:0", vec![credential.clone()])
            .expect("scoped config parses");
        let shared_debug = format!("{shared:?}");
        let credential_debug = format!("{credential:?}");
        let scoped_debug = format!("{scoped:?}");

        assert!(!shared_debug.contains("shared-secret-token"));
        assert!(shared_debug.contains("<redacted>"));
        assert!(!credential_debug.contains("node-a-secret-token"));
        assert!(credential_debug.contains("<redacted>"));
        assert!(!scoped_debug.contains("node-a-secret-token"));
        assert!(scoped_debug.contains("ScopedCredentials"));
    }

    #[test]
    fn scoped_credentials_accept_only_matching_node_token() {
        let credentials = vec![
            RelayCredential::new("node.a", "node-a-token").expect("node a credential"),
            RelayCredential::new("node.b", "node-b-token").expect("node b credential"),
        ];
        let relay = spawn_relay(
            RelayConfig::with_scoped_credentials("127.0.0.1:0", credentials)
                .expect("valid scoped config"),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());
        let mut node_b_wrong_token = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "node-a-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));

        write_client_text(
            &mut node_b_wrong_token,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "node-a-token").expect("hello"),
            )),
        );
        let response = read_server_text(&mut node_b_wrong_token);

        assert!(response.contains("ERROR reason=unauthorized"));
        assert!(!response.contains("node-a-token"));
    }

    #[test]
    fn hashed_credentials_accept_matching_token_without_storing_token() {
        let token = "node-a-hashed-token-1234567890";
        let hash = relay_token_sha256_hex(token).expect("hash generated");
        let credential = RelayCredential::from_sha256_hex("node.a", hash.clone(), token.len())
            .expect("hashed credential parses");
        let config = RelayConfig::with_scoped_credentials("127.0.0.1:0", vec![credential.clone()])
            .expect("hashed scoped config parses");
        let config_debug = format!("{config:?}");
        let credential_debug = format!("{credential:?}");

        assert!(config.auth.authorize("node.a", token));
        assert!(!config.auth.authorize("node.a", "wrong-hashed-token"));
        assert!(!config.auth.authorize("node.b", token));
        assert!(!config_debug.contains(token));
        assert!(!config_debug.contains(&hash));
        assert!(!credential_debug.contains(token));
        assert!(!credential_debug.contains(&hash));
        assert!(credential_debug.contains("<redacted>"));
    }

    #[test]
    fn issued_relay_credential_renders_manifest_without_token() {
        let entropy = [7_u8; ISSUED_RELAY_TOKEN_BYTES];
        let credential =
            issue_relay_credential_from_token_bytes("node.issue", &entropy, Some(2_000), 1_000)
                .expect("credential issues");
        let manifest = format!("version = \"1\"\n\n{}", credential.manifest_entry());
        let credentials = parse_scoped_credentials_file(&manifest).expect("issued manifest parses");
        let auth = RelayAuth::ScopedCredentials(credentials);
        let debug = format!("{credential:?}");

        assert_eq!(credential.token_length(), ISSUED_RELAY_TOKEN_BYTES * 2);
        assert!(auth.authorize_at("node.issue", credential.token(), 1_500));
        assert!(!auth.authorize_at("node.issue", credential.token(), 2_000));
        assert!(manifest.contains("token_displayed = false"));
        assert!(manifest.contains("payload_displayed = false"));
        assert!(manifest.contains("expires_at_unix = 2000"));
        assert!(!manifest.contains(credential.token()));
        assert!(!debug.contains(credential.token()));
        assert!(!debug.contains(credential.token_sha256_hex()));
    }

    #[test]
    fn issued_relay_token_file_is_created_once_without_manifest_leak() {
        let home = test_home("issued-relay-token");
        let path = home.join("node.issue.token");
        let entropy = [11_u8; ISSUED_RELAY_TOKEN_BYTES];
        let credential =
            issue_relay_credential_from_token_bytes("node.issue", &entropy, None, 1_000)
                .expect("credential issues");

        write_issued_relay_token_file(&credential, &path).expect("token file writes");
        let contents = fs::read_to_string(&path).expect("token file reads");
        let overwrite = write_issued_relay_token_file(&credential, &path)
            .expect_err("token file should not overwrite");

        assert_eq!(contents.trim(), credential.token());
        assert!(
            overwrite
                .to_string()
                .contains("create issued relay token file")
        );
        assert!(!credential.manifest_entry().contains(credential.token()));
    }

    #[cfg(unix)]
    #[test]
    fn issued_relay_token_file_rejects_symlink_without_replacing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("issued-relay-token-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let token_path = home.join("node.issue.token");
        let target_path = home.join("outside-token.txt");
        let target_contents = "existing relay token\n";
        fs::write(&target_path, target_contents).expect("target token writes");
        symlink(&target_path, &token_path).expect("token symlink creates");
        let credential = issue_relay_credential_from_token_bytes(
            "node.issue",
            &[12_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            1_000,
        )
        .expect("credential issues");

        let error = write_issued_relay_token_file(&credential, &token_path)
            .expect_err("symlinked token output should fail closed");

        assert!(
            error
                .to_string()
                .contains("inspect issued relay token file")
        );
        assert_eq!(
            fs::read_to_string(&target_path).expect("target token reads"),
            target_contents
        );
        assert!(
            fs::symlink_metadata(&token_path)
                .expect("token symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn issued_relay_token_file_rejects_symlinked_output_directory() {
        use std::os::unix::fs::symlink;

        let home = test_home("issued-relay-token-dir-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let outside = home.join("outside");
        fs::create_dir_all(&outside).expect("outside dir creates");
        let token_dir = home.join("tokens");
        symlink(&outside, &token_dir).expect("token dir symlink creates");
        let token_path = token_dir.join("node.issue.token");
        let credential = issue_relay_credential_from_token_bytes(
            "node.issue",
            &[14_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            1_000,
        )
        .expect("credential issues");

        let error = write_issued_relay_token_file(&credential, &token_path)
            .expect_err("symlinked token output directory should fail closed");

        assert!(
            error
                .to_string()
                .contains("create issued relay token directory")
        );
        assert_eq!(
            fs::read_dir(&outside).expect("outside dir reads").count(),
            0
        );
        assert!(
            fs::symlink_metadata(&token_dir)
                .expect("token dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn relay_metadata_file_replacement_replaces_existing_contents() {
        let home = test_home("relay-metadata-replacement");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("metadata.toml");
        fs::write(&path, "version = \"1\"\nstatus = \"old\"\n").expect("metadata writes");

        write_relay_metadata_file(
            &path,
            "version = \"1\"\nstatus = \"new\"\n",
            "inspect relay metadata test",
            "create temporary relay metadata test",
            "write temporary relay metadata test",
            "replace relay metadata test",
        )
        .expect("metadata replaces");

        assert_eq!(
            fs::read_to_string(&path).expect("metadata reads"),
            "version = \"1\"\nstatus = \"new\"\n"
        );
    }

    #[test]
    fn relay_metadata_file_replacement_rejects_changed_target_without_replacing_file() {
        let home = test_home("relay-metadata-replacement-race");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("metadata.toml");
        let changed = "version = \"1\"\nstatus = \"changed-before-replace\"\n";
        fs::write(&path, "version = \"1\"\nstatus = \"old\"\n").expect("metadata writes");
        let expected = inspect_existing_regular_relay_file(&path, "inspect relay metadata test")
            .expect("metadata inspect");
        let temp_path = relay_metadata_temp_path(&path).expect("temp path");
        fs::write(&temp_path, "version = \"1\"\nstatus = \"new\"\n").expect("temp writes");
        fs::write(&path, changed).expect("metadata changes before replacement");

        let error = replace_regular_relay_file_with_temp(
            &path,
            &temp_path,
            Some(&expected),
            "inspect relay metadata test",
            "replace relay metadata test",
        )
        .expect_err("changed target should fail closed");

        let _ = fs::remove_file(&temp_path);
        assert!(error.to_string().contains("changed before replacement"));
        assert_eq!(
            fs::read_to_string(&path).expect("metadata reads"),
            changed,
            "changed live metadata must not be overwritten by stale replacement"
        );
    }

    #[test]
    fn relay_metadata_replacement_retries_transient_path_change_errors() {
        let changed = RelayError::io(
            "inspect relay metadata test",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay file path changed before replacement",
            ),
        );
        let appeared = RelayError::io(
            "inspect relay metadata test",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay file path appeared before replacement",
            ),
        );
        let unsafe_target = RelayError::io(
            "inspect relay metadata test",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay file path is not a regular file",
            ),
        );

        assert!(relay_metadata_replace_should_retry(&changed));
        assert!(relay_metadata_replace_should_retry(&appeared));
        assert!(!relay_metadata_replace_should_retry(&unsafe_target));
    }

    #[cfg(unix)]
    #[test]
    fn relay_metadata_file_replacement_rejects_unwritable_parent_without_truncating_existing_file()
    {
        use std::os::unix::fs::PermissionsExt;

        let home = test_home("relay-metadata-unwritable-parent");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("metadata.toml");
        let original = "version = \"1\"\nstatus = \"old\"\n";
        fs::write(&path, original).expect("metadata writes");
        let original_permissions = fs::metadata(&home)
            .expect("home metadata reads")
            .permissions();
        let mut locked_permissions = original_permissions.clone();
        locked_permissions.set_mode(0o500);
        fs::set_permissions(&home, locked_permissions).expect("home permissions lock");

        let result = write_relay_metadata_file(
            &path,
            "version = \"1\"\nstatus = \"new\"\n",
            "inspect unwritable relay metadata",
            "create temporary unwritable relay metadata",
            "write temporary unwritable relay metadata",
            "replace unwritable relay metadata",
        );

        fs::set_permissions(&home, original_permissions).expect("home permissions restore");
        let error = result.expect_err("unwritable parent should fail before replacement");

        assert!(
            error
                .to_string()
                .contains("create temporary unwritable relay metadata")
        );
        assert_eq!(
            fs::read_to_string(&path).expect("metadata reads"),
            original,
            "failed staged replacement must leave existing relay metadata unchanged"
        );
    }

    #[test]
    fn issued_relay_credential_upserts_and_replaces_manifest_without_token() {
        let home = test_home("issued-relay-manifest-upsert");
        let manifest_path = home.join("credentials.toml");
        let first_entropy = [13_u8; ISSUED_RELAY_TOKEN_BYTES];
        let second_entropy = [17_u8; ISSUED_RELAY_TOKEN_BYTES];
        let first =
            issue_relay_credential_from_token_bytes("node.issue", &first_entropy, None, 1_000)
                .expect("first credential issues");
        let first_update = upsert_issued_relay_credential_in_file(&manifest_path, &first, false)
            .expect("first credential upserts");
        let first_manifest = fs::read_to_string(&manifest_path).expect("manifest reads");
        let first_auth = RelayAuth::ScopedCredentials(
            parse_scoped_credentials_file(&first_manifest).expect("manifest parses"),
        );

        assert_eq!(first_update.credentials, 1);
        assert_eq!(first_update.status, RelayCredentialStatus::Active);
        assert!(!first_update.replaced);
        assert!(!first_update.token_displayed);
        assert!(!first_update.contents_displayed);
        assert!(
            relay_credential_manifest_contains_node(&manifest_path, "node.issue")
                .expect("manifest contains node")
        );
        assert!(
            !relay_credential_manifest_contains_node(&manifest_path, "node.missing")
                .expect("manifest does not contain missing node")
        );
        assert!(first_manifest.contains("version = \"1\""));
        assert!(first_manifest.contains(first.token_sha256_hex()));
        assert!(!first_manifest.contains(first.token()));
        assert!(first_auth.authorize_at("node.issue", first.token(), 1_500));

        let second = issue_relay_credential_from_token_bytes(
            "node.issue",
            &second_entropy,
            Some(3_000),
            2_000,
        )
        .expect("second credential issues");
        let duplicate_error =
            upsert_issued_relay_credential_in_file(&manifest_path, &second, false)
                .expect_err("rotation requires replace");
        let duplicate_message = duplicate_error.to_string();
        assert!(duplicate_message.contains("--replace"));
        assert!(!duplicate_message.contains(first.token()));
        assert!(!duplicate_message.contains(second.token()));
        assert!(!duplicate_message.contains(first.token_sha256_hex()));
        assert!(!duplicate_message.contains(second.token_sha256_hex()));

        let replacement_update =
            upsert_issued_relay_credential_in_file(&manifest_path, &second, true)
                .expect("credential replaces");
        let replaced_manifest = fs::read_to_string(&manifest_path).expect("manifest reads");
        let replaced_auth = RelayAuth::ScopedCredentials(
            parse_scoped_credentials_file(&replaced_manifest).expect("manifest parses"),
        );

        assert!(replacement_update.replaced);
        assert_eq!(replacement_update.credentials, 1);
        assert!(replaced_manifest.contains(second.token_sha256_hex()));
        assert!(!replaced_manifest.contains(first.token_sha256_hex()));
        assert!(!replaced_manifest.contains(first.token()));
        assert!(!replaced_manifest.contains(second.token()));
        assert!(replaced_manifest.contains("expires_at_unix = 3000"));
        assert!(!replaced_auth.authorize_at("node.issue", first.token(), 2_500));
        assert!(replaced_auth.authorize_at("node.issue", second.token(), 2_500));
        assert!(!replaced_auth.authorize_at("node.issue", second.token(), 3_000));
    }

    #[cfg(unix)]
    #[test]
    fn relay_credential_manifest_upsert_rejects_symlink_without_replacing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("credential-manifest-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let manifest_path = home.join("credentials.toml");
        let target_path = home.join("outside-credentials.toml");
        let target_token = "target-node-token-1234567890";
        let target_hash = relay_token_sha256_hex(target_token).expect("target hash");
        let target_contents =
            credential_manifest_text("node.target", &target_hash, target_token.len(), "active");
        fs::write(&target_path, &target_contents).expect("target manifest writes");
        symlink(&target_path, &manifest_path).expect("credential manifest symlink creates");
        let credential = issue_relay_credential_from_token_bytes(
            "node.issue",
            &[23_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            1_000,
        )
        .expect("credential issues");

        let error = upsert_issued_relay_credential_in_file(&manifest_path, &credential, false)
            .expect_err("symlinked credential manifest should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target_path).expect("target manifest reads"),
            target_contents
        );
        assert!(
            fs::symlink_metadata(&manifest_path)
                .expect("credential symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn relay_credential_manifest_revoke_marks_node_without_token_leak() {
        let home = test_home("relay-manifest-revoke");
        let manifest_path = home.join("credentials.toml");
        let entropy = [19_u8; ISSUED_RELAY_TOKEN_BYTES];
        let credential =
            issue_relay_credential_from_token_bytes("node.revoke", &entropy, None, 1_000)
                .expect("credential issues");

        upsert_issued_relay_credential_in_file(&manifest_path, &credential, false)
            .expect("credential upserts");
        let revoke_update = revoke_relay_credential_in_file(&manifest_path, "node.revoke")
            .expect("credential revokes");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest reads");
        let auth = RelayAuth::ScopedCredentials(
            parse_scoped_credentials_file(&manifest).expect("manifest parses"),
        );
        let missing_error = revoke_relay_credential_in_file(&manifest_path, "node.missing")
            .expect_err("missing node should fail");
        let missing_message = missing_error.to_string();

        assert_eq!(revoke_update.status, RelayCredentialStatus::Revoked);
        assert_eq!(revoke_update.credentials, 1);
        assert!(!revoke_update.token_displayed);
        assert!(!revoke_update.contents_displayed);
        assert!(manifest.contains("status = \"revoked\""));
        assert!(manifest.contains("updated_at_unix = "));
        assert!(!manifest.contains(credential.token()));
        assert!(!auth.authorize("node.revoke", credential.token()));
        assert!(missing_message.contains("node id was not found"));
        assert!(!missing_message.contains(credential.token()));
        assert!(!missing_message.contains(credential.token_sha256_hex()));
    }

    #[test]
    fn credential_manifest_enforces_status_and_expiry_without_tokens() {
        let active_token = "active-node-token-1234567890";
        let revoked_token = "revoked-node-token-1234567890";
        let expired_token = "expired-node-token-1234567890";
        let active_hash = relay_token_sha256_hex(active_token).expect("active hash");
        let revoked_hash = relay_token_sha256_hex(revoked_token).expect("revoked hash");
        let expired_hash = relay_token_sha256_hex(expired_token).expect("expired hash");
        let expired_at = current_unix_seconds().saturating_sub(1);
        let contents = format!(
            "version = \"1\"\n\n\
[[credential]]\n\
node_id = \"node.active\"\n\
token_sha256_hex = \"{active_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
payload_displayed = false\n\
token_displayed = false\n\n\
[[credential]]\n\
node_id = \"node.revoked\"\n\
token_sha256_hex = \"{revoked_hash}\"\n\
token_length = {}\n\
status = \"revoked\"\n\
payload_displayed = false\n\
token_displayed = false\n\n\
[[credential]]\n\
node_id = \"node.expired\"\n\
token_sha256_hex = \"{expired_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
expires_at_unix = {expired_at}\n\
payload_displayed = false\n\
token_displayed = false\n",
            active_token.len(),
            revoked_token.len(),
            expired_token.len()
        );
        let credentials =
            parse_scoped_credentials_file(&contents).expect("credential manifest parses");
        let auth = RelayAuth::ScopedCredentials(credentials);

        assert!(auth.authorize("node.active", active_token));
        assert!(!auth.authorize("node.revoked", revoked_token));
        assert!(!auth.authorize("node.expired", expired_token));
        assert!(!format!("{auth:?}").contains(active_token));
        assert!(!format!("{auth:?}").contains(&active_hash));
    }

    #[test]
    fn credential_manifest_live_reload_revokes_without_restart_or_token_leak() {
        let token = "live-node-token-1234567890";
        let hash = relay_token_sha256_hex(token).expect("hash");
        let manifest_path = test_home("live-credential-manifest").join("credentials.toml");
        fs::create_dir_all(manifest_path.parent().expect("manifest parent"))
            .expect("manifest parent creates");
        fs::write(
            &manifest_path,
            credential_manifest_text("node.live", &hash, token.len(), "active"),
        )
        .expect("active manifest writes");
        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("live credential config parses");
        let config_debug = format!("{config:?}");
        let relay = spawn_relay(config).expect("relay starts");
        let mut first = connect_client(relay.local_addr());

        write_client_text(
            &mut first,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.live", token).expect("hello"),
            )),
        );
        let accepted = read_server_text(&mut first);

        assert!(accepted.contains("WELCOME"));
        assert!(!accepted.contains(token));
        assert!(!config_debug.contains(token));
        assert!(!config_debug.contains(&hash));

        fs::write(
            &manifest_path,
            credential_manifest_text("node.live", &hash, token.len(), "revoked"),
        )
        .expect("revoked manifest writes");
        let mut second = connect_client(relay.local_addr());
        write_client_text(
            &mut second,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.live", token).expect("hello"),
            )),
        );
        let rejected = read_server_text(&mut second);

        assert!(rejected.contains("ERROR reason=unauthorized"));
        assert!(!rejected.contains(token));
        assert!(!rejected.contains(&hash));
    }

    #[test]
    fn credential_manifest_live_reload_denies_invalid_updates_without_token_leak() {
        let token = "live-deny-token-1234567890";
        let hash = relay_token_sha256_hex(token).expect("hash");
        let manifest_path = test_home("live-invalid-credential-manifest").join("credentials.toml");
        fs::create_dir_all(manifest_path.parent().expect("manifest parent"))
            .expect("manifest parent creates");
        fs::write(
            &manifest_path,
            credential_manifest_text("node.live", &hash, token.len(), "active"),
        )
        .expect("active manifest writes");
        let relay = spawn_relay(
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("live credential config parses"),
        )
        .expect("relay starts");
        let mut first = connect_client(relay.local_addr());

        write_client_text(
            &mut first,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.live", token).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut first).contains("WELCOME"));

        fs::write(
            &manifest_path,
            "version = \"1\"\n\n[[credential]]\nnode_id = \"node.live\"\ntoken_displayed = false\n",
        )
        .expect("invalid manifest writes");
        let mut second = connect_client(relay.local_addr());
        write_client_text(
            &mut second,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.live", token).expect("hello"),
            )),
        );
        let rejected = read_server_text(&mut second);

        assert!(rejected.contains("ERROR reason=unauthorized"));
        assert!(!rejected.contains(token));
        assert!(!rejected.contains(&hash));
    }

    #[test]
    fn hosted_admin_online_lifecycle_updates_manifest_without_secret_leak() {
        let home = test_home("hosted-admin-online-lifecycle");
        let manifest_path = home.join("credentials.toml");
        let admin_token = "hosted-admin-control-token-1234567890";
        let first = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[23_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            1_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("first credential issues");
        let second = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[29_u8; ISSUED_RELAY_TOKEN_BYTES],
            Some(current_unix_seconds() + 3_600),
            2_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("second credential issues");
        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_admin_token(admin_token, manifest_path.clone())
                .expect("admin token configures");

        assert!(!config.auth.authorize("node.hosted", first.token()));
        let relay = spawn_relay(config).expect("relay starts");

        let issued = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                admin_token,
                "account.prod",
                first.node_id(),
                first.token_sha256_hex().to_string(),
                first.token_length(),
                first.expires_at_unix(),
            )
            .expect("issue request"),
        );
        let manifest = fs::read_to_string(&manifest_path).expect("manifest reads");

        assert!(issued.contains("ADMIN_RESULT action=issue status=issued"));
        assert!(issued.contains("credentials=1 active=1 revoked=0"));
        assert!(!issued.contains(admin_token));
        assert!(!issued.contains(first.token()));
        assert!(!issued.contains(first.token_sha256_hex()));
        assert!(manifest.contains("account_id = \"account.prod\""));
        assert!(manifest.contains(first.token_sha256_hex()));
        assert!(!manifest.contains(first.token()));

        let mut first_client = connect_client(relay.local_addr());
        write_client_text(
            &mut first_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.hosted", first.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut first_client).contains("WELCOME"));

        let rotated = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::rotate(
                admin_token,
                "account.prod",
                second.node_id(),
                second.token_sha256_hex().to_string(),
                second.token_length(),
                second.expires_at_unix(),
            )
            .expect("rotate request"),
        );
        let rotated_manifest = fs::read_to_string(&manifest_path).expect("manifest reads");

        assert!(rotated.contains("ADMIN_RESULT action=rotate status=rotated"));
        assert!(!rotated.contains(admin_token));
        assert!(!rotated.contains(first.token()));
        assert!(!rotated.contains(second.token()));
        assert!(!rotated.contains(second.token_sha256_hex()));
        assert!(!rotated_manifest.contains(first.token_sha256_hex()));
        assert!(rotated_manifest.contains(second.token_sha256_hex()));
        assert!(!rotated_manifest.contains(first.token()));
        assert!(!rotated_manifest.contains(second.token()));

        let mut old_token_client = connect_client(relay.local_addr());
        write_client_text(
            &mut old_token_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.hosted", first.token()).expect("hello"),
            )),
        );
        let old_rejected = read_server_text(&mut old_token_client);
        assert!(old_rejected.contains("ERROR reason=unauthorized"));
        assert!(!old_rejected.contains(first.token()));

        let mut rotated_client = connect_client(relay.local_addr());
        write_client_text(
            &mut rotated_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.hosted", second.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut rotated_client).contains("WELCOME"));

        let revoked = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::revoke(admin_token, "account.prod", "node.hosted")
                .expect("revoke request"),
        );
        assert!(revoked.contains("ADMIN_RESULT action=revoke status=revoked"));
        assert!(revoked.contains("credentials=1 active=0 revoked=1"));
        assert!(!revoked.contains(admin_token));
        assert!(!revoked.contains(second.token()));
        assert!(!revoked.contains(second.token_sha256_hex()));

        let mut revoked_client = connect_client(relay.local_addr());
        write_client_text(
            &mut revoked_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.hosted", second.token()).expect("hello"),
            )),
        );
        let revoked_rejected = read_server_text(&mut revoked_client);
        assert!(revoked_rejected.contains("ERROR reason=unauthorized"));
        assert!(!revoked_rejected.contains(second.token()));

        let audit = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::audit(admin_token, None).expect("audit request"),
        );
        assert!(audit.contains("ADMIN_RESULT action=audit status=audited"));
        assert!(audit.contains("credentials=1 active=0 revoked=1"));
        assert!(audit.contains("accounts=1"));
        assert!(!audit.contains(admin_token));
        assert!(!audit.contains(second.token()));
        assert!(!audit.contains(second.token_sha256_hex()));
    }

    #[test]
    fn hosted_admin_rejects_wrong_token_without_echoing_secrets() {
        let home = test_home("hosted-admin-wrong-token");
        let manifest_path = home.join("credentials.toml");
        let admin_token = "hosted-admin-control-token-abcdef";
        let wrong_admin_token = "wrong-admin-control-token-abcdef";
        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_admin_token(admin_token, manifest_path)
                .expect("admin token configures");
        let relay = spawn_relay(config).expect("relay starts");

        let response = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::audit(wrong_admin_token, Some("account.prod".to_string()))
                .expect("audit request"),
        );

        assert!(response.contains("ERROR reason=admin_unauthorized"));
        assert!(!response.contains(admin_token));
        assert!(!response.contains(wrong_admin_token));
    }

    #[test]
    fn hosted_admin_token_manifest_enforces_scopes_and_accounts_without_secret_leak() {
        let home = test_home("hosted-admin-token-rbac");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let admin_tokens_path = home.join("admin-tokens.toml");
        let credential_token = "credential-admin-token-1234567890";
        let tenant_token = "tenant-admin-token-1234567890";
        let dashboard_token = "dashboard-admin-token-1234567890";
        let credential_hash = relay_token_sha256_hex(credential_token).expect("credential hash");
        let tenant_hash = relay_token_sha256_hex(tenant_token).expect("tenant hash");
        let dashboard_hash = relay_token_sha256_hex(dashboard_token).expect("dashboard hash");
        fs::create_dir_all(&home).expect("test home creates");
        let credential = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[47_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            3_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("credential issues");
        let admin_manifest = format!(
            "version = \"1\"\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{credential_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_credentials = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{tenant_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_tenants = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{dashboard_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_dashboard = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n",
            credential_token.len(),
            tenant_token.len(),
            dashboard_token.len()
        );
        fs::write(&admin_tokens_path, admin_manifest).expect("admin token manifest writes");
        let manifest_contents = fs::read_to_string(&admin_tokens_path).expect("manifest reads");
        assert!(manifest_contents.contains(&credential_hash));
        assert!(manifest_contents.contains(&tenant_hash));
        assert!(manifest_contents.contains(&dashboard_hash));
        assert!(!manifest_contents.contains(credential_token));
        assert!(!manifest_contents.contains(tenant_token));
        assert!(!manifest_contents.contains(dashboard_token));

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_admin_tokens_file(admin_tokens_path.clone(), manifest_path.clone())
                .expect("admin token manifest configures")
                .with_admin_tenants_file(tenants_path)
                .expect("tenant registry configures");
        let config_debug = format!("{config:?}");
        assert!(!config_debug.contains(credential_token));
        assert!(!config_debug.contains(&credential_hash));
        let relay = spawn_relay(config).expect("relay starts");

        let scope_denied = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                tenant_token,
                "account.prod",
                credential.node_id(),
                credential.token_sha256_hex().to_string(),
                credential.token_length(),
                credential.expires_at_unix(),
            )
            .expect("issue request"),
        );
        assert!(
            scope_denied.contains("ERROR reason=admin_scope_denied"),
            "{scope_denied}"
        );
        assert!(!scope_denied.contains(tenant_token));
        assert!(!scope_denied.contains(credential.token()));
        assert!(!scope_denied.contains(credential.token_sha256_hex()));

        let other_account_denied = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::audit(credential_token, Some("account.other".to_string()))
                .expect("audit request"),
        );
        assert!(other_account_denied.contains("ERROR reason=admin_scope_denied"));
        assert!(!other_account_denied.contains(credential_token));

        let suspend_scope_denied = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::account_suspend(tenant_token, "account.prod")
                .expect("account suspend request"),
        );
        assert!(suspend_scope_denied.contains("ERROR reason=admin_scope_denied"));
        assert!(!suspend_scope_denied.contains(tenant_token));
        assert!(!suspend_scope_denied.contains(credential.token()));
        assert!(!suspend_scope_denied.contains(credential.token_sha256_hex()));

        let tenant = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_upsert(tenant_token, "account.prod")
                .expect("tenant upsert request"),
        );
        assert!(tenant.contains("ADMIN_RESULT action=tenant_upsert status=upserted"));
        assert!(tenant.contains("account=account.prod"));
        assert!(!tenant.contains(tenant_token));

        let node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_node_upsert(
                tenant_token,
                "account.prod",
                credential.node_id(),
                true,
                true,
                false,
                false,
                true,
                Some("signing.key.1".to_string()),
                Some("exchange.key.1".to_string()),
            )
            .expect("tenant node upsert request"),
        );
        assert!(node.contains("ADMIN_RESULT action=tenant_node_upsert status=upserted"));
        assert!(!node.contains(tenant_token));
        assert!(!node.contains("signing.key.1"));
        assert!(!node.contains("exchange.key.1"));

        let issued = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                credential_token,
                "account.prod",
                credential.node_id(),
                credential.token_sha256_hex().to_string(),
                credential.token_length(),
                credential.expires_at_unix(),
            )
            .expect("issue request"),
        );
        assert!(issued.contains("ADMIN_RESULT action=issue status=issued"));
        assert!(issued.contains("account=account.prod"));
        assert!(!issued.contains(credential_token));
        assert!(!issued.contains(credential.token()));
        assert!(!issued.contains(credential.token_sha256_hex()));

        let audit = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::audit(credential_token, None).expect("audit request"),
        );
        assert!(audit.contains("ADMIN_RESULT action=audit status=audited"));
        assert!(audit.contains("account=account.prod"));
        assert!(audit.contains("credentials=1 active=1 revoked=0"));
        assert!(!audit.contains(credential_token));
        assert!(!audit.contains(credential.token_sha256_hex()));

        let dashboard = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::dashboard(dashboard_token, None, None).expect("dashboard request"),
        );
        assert!(dashboard.contains("ADMIN_RESULT action=dashboard status=snapshotted"));
        assert!(dashboard.contains("account=account.prod"));
        assert!(dashboard.contains("credentials=1 active=1 revoked=0"));
        assert!(dashboard.contains("tenants=1 active_tenants=1 revoked_tenants=0"));
        assert!(dashboard.contains("accounting_records=0"));
        assert!(dashboard.contains("abuse_records=0"));
        assert!(!dashboard.contains(dashboard_token));
        assert!(!dashboard.contains(credential.token()));
        assert!(!dashboard.contains(credential.token_sha256_hex()));
        assert!(!dashboard.contains("signing.key.1"));
        assert!(!dashboard.contains("exchange.key.1"));
    }

    #[test]
    fn hosted_admin_token_manifest_scopes_mailbox_actions_to_account_nodes_without_secret_leak() {
        let home = test_home("hosted-admin-token-mailbox-rbac");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let admin_tokens_path = home.join("admin-tokens.toml");
        let mailbox_dir = home.join("relay-mailbox");
        let node_id = "node.hosted";
        let audit_token = "mailbox-audit-admin-token-1234567890";
        let purge_token = "mailbox-purge-admin-token-1234567890";
        let audit_hash = relay_token_sha256_hex(audit_token).expect("audit hash");
        let purge_hash = relay_token_sha256_hex(purge_token).expect("purge hash");
        fs::create_dir_all(mailbox_dir.join(node_id)).expect("mailbox node dir");
        upsert_hosted_tenant_in_file(&tenants_path, "account.prod").expect("tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            node_id,
            HostedTenantPermissions {
                messages: false,
                streams: false,
                rooms: false,
                files: false,
                mailbox: true,
            },
            None,
            None,
        )
        .expect("tenant node upserts");
        fs::write(
            &admin_tokens_path,
            format!(
                "version = \"1\"\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{audit_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_mailbox_audit = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{purge_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_mailbox_purge = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n",
                audit_token.len(),
                purge_token.len()
            ),
        )
        .expect("admin token manifest writes");

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_mailbox_storage(
                    RelayMailboxStorage::file_backed(mailbox_dir).expect("mailbox storage"),
                )
                .with_admin_tokens_file(admin_tokens_path, manifest_path)
                .expect("admin token manifest configures")
                .with_admin_tenants_file(tenants_path)
                .expect("tenant registry configures");
        let relay = spawn_relay(config).expect("relay starts");

        let missing_node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_audit(audit_token, None, Some(1))
                .expect("mailbox audit request"),
        );
        assert!(missing_node.contains("ERROR reason=admin_scope_denied"));
        assert!(!missing_node.contains(audit_token));
        assert!(!missing_node.contains(&audit_hash));

        let wrong_scope = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_purge(audit_token, Some(node_id.to_string()), 1, true)
                .expect("mailbox purge request"),
        );
        assert!(wrong_scope.contains("ERROR reason=admin_scope_denied"));
        assert!(!wrong_scope.contains(audit_token));
        assert!(!wrong_scope.contains(&audit_hash));

        let wrong_node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_audit(audit_token, Some("node.other".to_string()), Some(1))
                .expect("mailbox audit request"),
        );
        assert!(wrong_node.contains("ERROR reason=admin_scope_denied"));
        assert!(!wrong_node.contains(audit_token));
        assert!(!wrong_node.contains(&audit_hash));

        let audit = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_audit(audit_token, Some(node_id.to_string()), Some(1))
                .expect("mailbox audit request"),
        );
        assert!(audit.contains("ADMIN_RESULT action=mailbox_audit status=audited"));
        assert!(audit.contains("node=node.hosted"));
        assert!(audit.contains("payload_displayed=false"));
        assert!(audit.contains("token_displayed=false"));
        assert!(audit.contains("token_hash_displayed=false"));
        assert!(!audit.contains(audit_token));
        assert!(!audit.contains(&audit_hash));
        assert!(!audit.contains(purge_token));
        assert!(!audit.contains(&purge_hash));

        let purge = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_purge(purge_token, Some(node_id.to_string()), 1, true)
                .expect("mailbox purge request"),
        );
        assert!(purge.contains("ADMIN_RESULT action=mailbox_purge status=dry_run"));
        assert!(purge.contains("node=node.hosted"));
        assert!(purge.contains("confirmed=false"));
        assert!(purge.contains("token_hash_displayed=false"));
        assert!(!purge.contains(audit_token));
        assert!(!purge.contains(&audit_hash));
        assert!(!purge.contains(purge_token));
        assert!(!purge.contains(&purge_hash));
    }

    #[test]
    fn hosted_admin_token_manifest_scopes_session_audit_to_account_nodes_without_secret_leak() {
        let home = test_home("hosted-admin-token-session-rbac");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let admin_tokens_path = home.join("admin-tokens.toml");
        let session_dir = home.join("sessions");
        let node_id = "node.hosted";
        let session_token = "session-audit-admin-token-1234567890";
        let dashboard_token = "session-dashboard-admin-token-1234567890";
        let session_hash = relay_token_sha256_hex(session_token).expect("session hash");
        let dashboard_hash = relay_token_sha256_hex(dashboard_token).expect("dashboard hash");
        fs::create_dir_all(&session_dir).expect("session dir");
        upsert_hosted_tenant_in_file(&tenants_path, "account.prod").expect("tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            node_id,
            HostedTenantPermissions {
                messages: false,
                streams: false,
                rooms: false,
                files: false,
                mailbox: false,
            },
            None,
            None,
        )
        .expect("tenant node upserts");
        let now = current_unix_millis_u64();
        let session = RelaySessionRecord {
            node_id: node_id.to_string(),
            session_id: session_id(node_id),
            created_at_unix_millis: now.saturating_sub(1_000),
            last_seen_unix_millis: now.saturating_sub(100),
            expires_at_unix_millis: now.saturating_add(60_000),
        };
        fs::write(
            relay_session_record_path(&session_dir, node_id),
            render_session_file(&session),
        )
        .expect("session state writes");
        fs::write(
            &admin_tokens_path,
            format!(
                "version = \"1\"\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{session_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_sessions = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{dashboard_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_dashboard = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n",
                session_token.len(),
                dashboard_token.len()
            ),
        )
        .expect("admin token manifest writes");

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_session_storage(
                    RelaySessionStorage::file_backed(session_dir).expect("session storage"),
                )
                .with_admin_tokens_file(admin_tokens_path, manifest_path)
                .expect("admin token manifest configures")
                .with_admin_tenants_file(tenants_path)
                .expect("tenant registry configures");
        let relay = spawn_relay(config).expect("relay starts");

        let missing_node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::session_audit(session_token, None).expect("session audit request"),
        );
        assert!(missing_node.contains("ERROR reason=admin_scope_denied"));
        assert!(!missing_node.contains(session_token));
        assert!(!missing_node.contains(&session_hash));

        let wrong_scope = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::session_audit(dashboard_token, Some(node_id.to_string()))
                .expect("session audit request"),
        );
        assert!(wrong_scope.contains("ERROR reason=admin_scope_denied"));
        assert!(!wrong_scope.contains(dashboard_token));
        assert!(!wrong_scope.contains(&dashboard_hash));

        let wrong_node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::session_audit(session_token, Some("node.other".to_string()))
                .expect("session audit request"),
        );
        assert!(wrong_node.contains("ERROR reason=admin_scope_denied"));
        assert!(!wrong_node.contains(session_token));
        assert!(!wrong_node.contains(&session_hash));

        let audit = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::session_audit(session_token, Some(node_id.to_string()))
                .expect("session audit request"),
        );
        assert!(audit.contains("ADMIN_RESULT action=session_audit status=audited"));
        assert!(audit.contains("node=node.hosted"));
        assert!(audit.contains("session_state_records=1"));
        assert!(audit.contains("session_state_active_records=1"));
        assert!(audit.contains("session_state_invalid_records=0"));
        assert!(audit.contains("payload_displayed=false"));
        assert!(audit.contains("session_id_displayed=false"));
        assert!(!audit.contains(session_token));
        assert!(!audit.contains(&session_hash));
        assert!(!audit.contains(&session.session_id));
    }

    #[test]
    fn admin_token_manifest_rejects_display_flags_and_empty_scopes() {
        let token = "manifest-admin-token-1234567890";
        let hash = relay_token_sha256_hex(token).expect("hash");
        let displayed = format!(
            "version = \"1\"\n\n\
[[admin_token]]\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
scope_dashboard = true\n\
token_hash_displayed = true\n",
            token.len()
        );
        let displayed_error = parse_admin_tokens_file(&displayed, "127.0.0.1:0")
            .expect_err("token_hash_displayed true should be rejected");
        assert!(
            displayed_error
                .to_string()
                .contains("token_hash_displayed must be false")
        );
        assert!(!displayed_error.to_string().contains(token));
        assert!(!displayed_error.to_string().contains(&hash));

        let empty_scope = format!(
            "version = \"1\"\n\n\
[[admin_token]]\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
token_displayed = false\n\
token_hash_displayed = false\n",
            token.len()
        );
        let empty_scope_error = parse_admin_tokens_file(&empty_scope, "127.0.0.1:0")
            .expect_err("empty scope should be rejected");
        assert!(empty_scope_error.to_string().contains("at least one scope"));
        assert!(!empty_scope_error.to_string().contains(token));
        assert!(!empty_scope_error.to_string().contains(&hash));

        let key_material_displayed = format!(
            "version = \"1\"\n\n\
[[admin_token]]\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
scope_dashboard = true\n\
key_material_displayed = true\n",
            token.len()
        );
        let key_material_error = parse_admin_tokens_file(&key_material_displayed, "127.0.0.1:0")
            .expect_err("key material display guard should be rejected");
        assert!(
            key_material_error
                .to_string()
                .contains("key_material_displayed must be false")
        );
        assert!(!key_material_error.to_string().contains(token));
        assert!(!key_material_error.to_string().contains(&hash));
    }

    #[test]
    fn hosted_admin_token_audit_summarizes_scopes_without_secret_leak() {
        let home = test_home("hosted-admin-token-audit");
        let manifest_path = home.join("admin-tokens.toml");
        let credential_token = "credential-admin-token-1234567890";
        let tenant_token = "tenant-admin-token-1234567890";
        let mailbox_token = "mailbox-admin-token-1234567890";
        let session_token = "session-admin-token-1234567890";
        let credential_hash = relay_token_sha256_hex(credential_token).expect("credential hash");
        let tenant_hash = relay_token_sha256_hex(tenant_token).expect("tenant hash");
        let mailbox_hash = relay_token_sha256_hex(mailbox_token).expect("mailbox hash");
        let session_hash = relay_token_sha256_hex(session_token).expect("session hash");
        let now_unix = current_unix_seconds();
        fs::create_dir_all(&home).expect("home creates");
        fs::write(
            &manifest_path,
            format!(
                "version = \"1\"\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{credential_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
expires_at_unix = {}\n\
scope_credentials = true\n\
scope_dashboard = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
key_material_displayed = false\n\
session_id_displayed = false\n\
ciphertext_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
account_id = \"account.prod\"\n\
token_sha256_hex = \"{tenant_hash}\"\n\
token_length = {}\n\
status = \"revoked\"\n\
scope_tenants = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
account_id = \"account.other\"\n\
token_sha256_hex = \"{mailbox_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
expires_at_unix = {}\n\
scope_mailbox_audit = true\n\
scope_mailbox_purge = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n\n\
[[admin_token]]\n\
token_sha256_hex = \"{session_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
scope_sessions = true\n\
payload_displayed = false\n\
token_displayed = false\n\
token_hash_displayed = false\n\
contents_displayed = false\n",
                credential_token.len(),
                now_unix + 3_600,
                tenant_token.len(),
                mailbox_token.len(),
                now_unix.saturating_sub(1),
                session_token.len()
            ),
        )
        .expect("manifest writes");

        let audit = audit_hosted_admin_tokens_file(&manifest_path, None, "0.0.0.0:8787")
            .expect("admin token audit succeeds");
        assert_eq!(audit.records, 4);
        assert_eq!(audit.active, 2);
        assert_eq!(audit.revoked, 1);
        assert_eq!(audit.expired, 1);
        assert_eq!(audit.account_scoped_records, 3);
        assert_eq!(audit.global_records, 1);
        assert_eq!(audit.accounts, 2);
        assert_eq!(audit.expiring_records, 2);
        assert_eq!(audit.next_expires_at_unix, Some(now_unix + 3_600));
        assert_eq!(audit.last_expires_at_unix, Some(now_unix + 3_600));
        assert_eq!(audit.scope_credentials, 1);
        assert_eq!(audit.scope_tenants, 1);
        assert_eq!(audit.scope_dashboard, 1);
        assert_eq!(audit.scope_sessions, 1);
        assert_eq!(audit.scope_mailbox_audit, 1);
        assert_eq!(audit.scope_mailbox_purge, 1);
        assert!(!audit.payload_displayed);
        assert!(!audit.token_displayed);
        assert!(!audit.token_hash_displayed);
        assert!(!audit.key_material_displayed);
        assert!(!audit.session_id_displayed);
        assert!(!audit.ciphertext_displayed);
        assert!(!audit.contents_displayed);

        let account_audit =
            audit_hosted_admin_tokens_file(&manifest_path, Some("account.prod"), "0.0.0.0:8787")
                .expect("account admin token audit succeeds");
        assert_eq!(account_audit.account_id.as_deref(), Some("account.prod"));
        assert_eq!(account_audit.records, 2);
        assert_eq!(account_audit.active, 1);
        assert_eq!(account_audit.revoked, 1);
        assert_eq!(account_audit.expired, 0);
        assert_eq!(account_audit.account_scoped_records, 2);
        assert_eq!(account_audit.global_records, 0);
        assert_eq!(account_audit.accounts, 1);

        let debug = format!("{audit:?}");
        for secret in [
            credential_token,
            tenant_token,
            mailbox_token,
            session_token,
            &credential_hash,
            &tenant_hash,
            &mailbox_hash,
            &session_hash,
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[cfg(unix)]
    #[test]
    fn admin_token_manifest_audit_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("admin-token-manifest-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let manifest_path = home.join("admin-tokens.toml");
        let target_path = home.join("outside-admin-tokens.toml");
        let target_contents = "version = \"1\"\n";
        fs::write(&target_path, target_contents).expect("target admin manifest writes");
        symlink(&target_path, &manifest_path).expect("admin token manifest symlink creates");

        let error = audit_hosted_admin_tokens_file(&manifest_path, None, "127.0.0.1:0")
            .expect_err("symlinked admin token manifest should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target_path).expect("target admin manifest reads"),
            target_contents
        );
        assert!(
            fs::symlink_metadata(&manifest_path)
                .expect("admin token symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn relay_manifest_reads_reject_oversized_files_without_reading_contents() {
        let home = test_home("relay-manifest-oversized");
        fs::create_dir_all(&home).expect("home creates");
        let credential_secret = "relay-secret-token-credential-oversized";
        let credential_path = home.join("credentials.toml");
        write_oversized_relay_manifest(&credential_path, credential_secret);

        let credential_error = load_scoped_credentials_file(&credential_path)
            .expect_err("oversized credential manifest should fail closed");
        let credential_message = credential_error.to_string();
        assert!(credential_message.contains("relay credential file"));
        assert!(credential_message.contains("exceeds"));
        assert!(!credential_message.contains(credential_secret));

        let admin_secret = "relay-secret-token-admin-oversized";
        let admin_path = home.join("admin-tokens.toml");
        write_oversized_relay_manifest(&admin_path, admin_secret);

        let admin_error = audit_hosted_admin_tokens_file(&admin_path, None, "127.0.0.1:0")
            .expect_err("oversized admin-token manifest should fail closed");
        let admin_message = admin_error.to_string();
        assert!(admin_message.contains("relay admin tokens file"));
        assert!(admin_message.contains("exceeds"));
        assert!(!admin_message.contains(admin_secret));

        let tenant_secret = "relay-secret-token-tenant-oversized";
        let tenant_path = home.join("tenants.toml");
        write_oversized_relay_manifest(&tenant_path, tenant_secret);

        let tenant_error = audit_hosted_tenants_file(&tenant_path, None)
            .expect_err("oversized tenant manifest should fail closed");
        let tenant_message = tenant_error.to_string();
        assert!(tenant_message.contains("hosted tenant file"));
        assert!(tenant_message.contains("exceeds"));
        assert!(!tenant_message.contains(tenant_secret));
    }

    #[test]
    fn hosted_admin_dashboard_snapshots_metadata_with_admin_token() {
        let home = test_home("hosted-admin-dashboard");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let accounting_storage =
            RelayAccountingStorage::file_backed(home.join("accounting")).expect("accounting dir");
        let abuse_storage = RelayAbuseStorage::file_backed(home.join("abuse")).expect("abuse dir");
        let admin_token = "hosted-admin-dashboard-token-123456";
        let wrong_admin_token = "wrong-hosted-dashboard-token-123456";
        let credential = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[41_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            1_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("credential issues");

        upsert_hosted_tenant_in_file(&tenants_path, "account.prod").expect("tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            credential.node_id(),
            HostedTenantPermissions {
                messages: true,
                streams: false,
                rooms: false,
                files: false,
                mailbox: true,
            },
            Some("signing.key.1".to_string()),
            Some("exchange.key.1".to_string()),
        )
        .expect("tenant node upserts");

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_accounting_storage(accounting_storage)
                .with_abuse_storage(abuse_storage)
                .with_admin_token(admin_token, manifest_path.clone())
                .expect("admin token configures")
                .with_admin_tenants_file(tenants_path)
                .expect("tenant registry configures");
        let relay = spawn_relay(config).expect("relay starts");

        let issued = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                admin_token,
                "account.prod",
                credential.node_id(),
                credential.token_sha256_hex().to_string(),
                credential.token_length(),
                credential.expires_at_unix(),
            )
            .expect("issue request"),
        );
        assert!(issued.contains("ADMIN_RESULT action=issue status=issued"));

        let mut active_client = connect_client(relay.local_addr());
        write_client_text(
            &mut active_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(credential.node_id(), credential.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut active_client).contains("WELCOME"));

        let rejected_dashboard = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::dashboard(
                wrong_admin_token,
                Some("account.prod".to_string()),
                Some(credential.node_id().to_string()),
            )
            .expect("dashboard request"),
        );
        assert!(rejected_dashboard.contains("ERROR reason=admin_unauthorized"));
        assert!(!rejected_dashboard.contains(admin_token));
        assert!(!rejected_dashboard.contains(wrong_admin_token));
        assert!(!rejected_dashboard.contains(credential.token()));
        assert!(!rejected_dashboard.contains(credential.token_sha256_hex()));

        let dashboard = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::dashboard(admin_token, Some("account.prod".to_string()), None)
                .expect("dashboard request"),
        );

        assert!(dashboard.contains("ADMIN_RESULT action=dashboard status=snapshotted"));
        assert!(dashboard.contains("credentials=1 active=1 revoked=0 expired=0 accounts=1"));
        assert!(dashboard.contains("tenants=1 active_tenants=1 revoked_tenants=0"));
        assert!(dashboard.contains("nodes=1 active_nodes=1 revoked_nodes=0 tenant_policies=1"));
        assert!(dashboard.contains("accounting_records=1 sessions_authenticated=1"));
        assert!(dashboard.contains("abuse_records=1 admin_unauthorized=1"));
        assert!(dashboard.contains("payload_displayed=false"));
        assert!(dashboard.contains("token_displayed=false"));
        assert!(dashboard.contains("token_hash_displayed=false"));
        assert!(dashboard.contains("key_material_displayed=false"));
        assert!(dashboard.contains("session_id_displayed=false"));
        assert!(dashboard.contains("ciphertext_displayed=false"));
        assert!(dashboard.contains("contents_displayed=false"));
        assert!(!dashboard.contains(admin_token));
        assert!(!dashboard.contains(wrong_admin_token));
        assert!(!dashboard.contains(credential.token()));
        assert!(!dashboard.contains(credential.token_sha256_hex()));
        assert!(!dashboard.contains("signing.key.1"));
        assert!(!dashboard.contains("exchange.key.1"));
    }

    #[test]
    fn hosted_admin_tenant_lifecycle_updates_registry_with_admin_token() {
        let home = test_home("hosted-admin-tenant-lifecycle");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let admin_token = "hosted-admin-tenant-lifecycle-token-123456";
        let wrong_admin_token = "wrong-hosted-tenant-lifecycle-token-123456";
        let credential = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[43_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            2_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("credential issues");

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_admin_token(admin_token, manifest_path.clone())
                .expect("admin token configures")
                .with_admin_tenants_file(tenants_path.clone())
                .expect("tenant registry configures");
        let relay = spawn_relay(config).expect("relay starts");

        let rejected = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_upsert(wrong_admin_token, "account.prod")
                .expect("tenant upsert request"),
        );
        assert!(rejected.contains("ERROR reason=admin_unauthorized"));
        assert!(!rejected.contains(admin_token));
        assert!(!rejected.contains(wrong_admin_token));

        let missing_tenant = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_node_upsert(
                admin_token,
                "account.prod",
                credential.node_id(),
                true,
                true,
                false,
                false,
                true,
                Some("signing.key.1".to_string()),
                Some("exchange.key.1".to_string()),
            )
            .expect("tenant node upsert request"),
        );
        assert!(missing_tenant.contains("ADMIN_RESULT action=tenant_node_upsert"));
        assert!(missing_tenant.contains("status=tenant_not_found"));
        assert!(!missing_tenant.contains(admin_token));
        assert!(!missing_tenant.contains(credential.token()));
        assert!(!missing_tenant.contains(credential.token_sha256_hex()));
        assert!(!missing_tenant.contains("signing.key.1"));
        assert!(!missing_tenant.contains("exchange.key.1"));

        let tenant = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_upsert(admin_token, "account.prod")
                .expect("tenant upsert request"),
        );
        assert!(tenant.contains("ADMIN_RESULT action=tenant_upsert status=upserted"));
        assert!(tenant.contains("account=account.prod"));
        assert!(tenant.contains("tenants=1 active_tenants=1 revoked_tenants=0"));
        assert!(tenant.contains("nodes=0 active_nodes=0 revoked_nodes=0 tenant_policies=0"));
        assert!(tenant.contains("payload_displayed=false"));
        assert!(tenant.contains("token_displayed=false"));
        assert!(tenant.contains("key_material_displayed=false"));
        assert!(tenant.contains("contents_displayed=false"));
        assert!(!tenant.contains(admin_token));
        assert!(!tenant.contains(wrong_admin_token));
        assert!(!tenant.contains(credential.token()));
        assert!(!tenant.contains(credential.token_sha256_hex()));

        let node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_node_upsert(
                admin_token,
                "account.prod",
                credential.node_id(),
                true,
                true,
                false,
                false,
                true,
                Some("signing.key.1".to_string()),
                Some("exchange.key.1".to_string()),
            )
            .expect("tenant node upsert request"),
        );
        assert!(node.contains("ADMIN_RESULT action=tenant_node_upsert status=upserted"));
        assert!(node.contains("node=node.hosted"));
        assert!(node.contains("nodes=1 active_nodes=1 revoked_nodes=0 tenant_policies=1"));
        assert!(node.contains("token_displayed=false"));
        assert!(node.contains("key_material_displayed=false"));
        assert!(node.contains("contents_displayed=false"));
        assert!(!node.contains(admin_token));
        assert!(!node.contains(credential.token()));
        assert!(!node.contains(credential.token_sha256_hex()));
        assert!(!node.contains("signing.key.1"));
        assert!(!node.contains("exchange.key.1"));

        let issued = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                admin_token,
                "account.prod",
                credential.node_id(),
                credential.token_sha256_hex().to_string(),
                credential.token_length(),
                credential.expires_at_unix(),
            )
            .expect("issue request"),
        );
        assert!(issued.contains("ADMIN_RESULT action=issue status=issued"));
        assert!(!issued.contains(credential.token()));
        assert!(!issued.contains(credential.token_sha256_hex()));

        let mut active_client = connect_client(relay.local_addr());
        write_client_text(
            &mut active_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(credential.node_id(), credential.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut active_client).contains("WELCOME"));

        let audit = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_audit(admin_token, Some("account.prod".to_string()))
                .expect("tenant audit request"),
        );
        assert!(audit.contains("ADMIN_RESULT action=tenant_audit status=audited"));
        assert!(audit.contains("tenants=1 active_tenants=1 revoked_tenants=0"));
        assert!(audit.contains("nodes=1 active_nodes=1 revoked_nodes=0 tenant_policies=1"));
        assert!(!audit.contains(admin_token));
        assert!(!audit.contains(credential.token()));
        assert!(!audit.contains(credential.token_sha256_hex()));
        assert!(!audit.contains("signing.key.1"));
        assert!(!audit.contains("exchange.key.1"));

        let revoked_node = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_node_revoke(
                admin_token,
                "account.prod",
                credential.node_id(),
            )
            .expect("tenant node revoke request"),
        );
        assert!(revoked_node.contains("ADMIN_RESULT action=tenant_node_revoke status=revoked"));
        assert!(revoked_node.contains("nodes=1 active_nodes=0 revoked_nodes=1"));
        assert!(!revoked_node.contains(admin_token));
        assert!(!revoked_node.contains(credential.token()));
        assert!(!revoked_node.contains(credential.token_sha256_hex()));

        let mut revoked_tenant_client = connect_client(relay.local_addr());
        write_client_text(
            &mut revoked_tenant_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(credential.node_id(), credential.token()).expect("hello"),
            )),
        );
        let revoked_response = read_server_text(&mut revoked_tenant_client);
        assert!(revoked_response.contains("ERROR reason=unauthorized"));
        assert!(!revoked_response.contains(credential.token()));
        assert!(!revoked_response.contains(credential.token_sha256_hex()));

        let revoked_tenant = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::tenant_revoke(admin_token, "account.prod")
                .expect("tenant revoke request"),
        );
        assert!(revoked_tenant.contains("ADMIN_RESULT action=tenant_revoke status=revoked"));
        assert!(revoked_tenant.contains("tenants=1 active_tenants=0 revoked_tenants=1"));
        assert!(!revoked_tenant.contains(admin_token));
        assert!(!revoked_tenant.contains(credential.token()));
        assert!(!revoked_tenant.contains(credential.token_sha256_hex()));

        let manifest = fs::read_to_string(&tenants_path).expect("tenant manifest reads");
        assert!(manifest.contains("signing_key_id = \"signing.key.1\""));
        assert!(manifest.contains("exchange_key_id = \"exchange.key.1\""));
        assert!(!manifest.contains(admin_token));
        assert!(!manifest.contains(wrong_admin_token));
        assert!(!manifest.contains(credential.token()));
        assert!(!manifest.contains(credential.token_sha256_hex()));
        assert!(!manifest.contains("payload-body"));
        assert!(!manifest.contains("ciphertext_body"));
    }

    #[cfg(unix)]
    #[test]
    fn hosted_tenant_manifest_upsert_rejects_symlink_without_replacing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("hosted-tenant-manifest-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let tenants_path = home.join("tenants.toml");
        let target_path = home.join("outside-tenants.toml");
        let target_contents = "version = \"1\"\n";
        fs::write(&target_path, target_contents).expect("target tenant manifest writes");
        symlink(&target_path, &tenants_path).expect("tenant manifest symlink creates");

        let error = upsert_hosted_tenant_in_file(&tenants_path, "account.prod")
            .expect_err("symlinked tenant manifest should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target_path).expect("target tenant manifest reads"),
            target_contents
        );
        assert!(
            fs::symlink_metadata(&tenants_path)
                .expect("tenant symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn hosted_admin_account_suspend_revokes_tenant_and_account_credentials_without_secret_leak() {
        let home = test_home("hosted-account-suspend");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let admin_token = "hosted-admin-account-suspend-token-123456";
        let wrong_admin_token = "wrong-hosted-account-suspend-token-123456";
        let first = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[49_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            4_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("first credential issues");
        let second = issue_relay_credential_from_token_bytes(
            "node.second",
            &[50_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            4_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("second credential issues");
        let other = issue_relay_credential_from_token_bytes(
            "node.other",
            &[51_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            4_000,
        )
        .and_then(|credential| credential.with_account_id("account.other"))
        .expect("other credential issues");

        upsert_hosted_tenant_in_file(&tenants_path, "account.prod").expect("tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            first.node_id(),
            HostedTenantPermissions {
                messages: true,
                streams: false,
                rooms: false,
                files: false,
                mailbox: true,
            },
            Some("signing.key.1".to_string()),
            Some("exchange.key.1".to_string()),
        )
        .expect("first tenant node upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            second.node_id(),
            HostedTenantPermissions {
                messages: true,
                streams: true,
                rooms: false,
                files: false,
                mailbox: false,
            },
            None,
            None,
        )
        .expect("second tenant node upserts");
        upsert_hosted_tenant_in_file(&tenants_path, "account.other").expect("other tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.other",
            other.node_id(),
            HostedTenantPermissions {
                messages: true,
                streams: false,
                rooms: false,
                files: false,
                mailbox: false,
            },
            None,
            None,
        )
        .expect("other tenant node upserts");
        upsert_hosted_relay_credential_hash_in_file(
            &manifest_path,
            "account.prod",
            first.node_id(),
            first.token_sha256_hex(),
            first.token_length(),
            first.expires_at_unix(),
            false,
        )
        .expect("first credential upserts");
        upsert_hosted_relay_credential_hash_in_file(
            &manifest_path,
            "account.prod",
            second.node_id(),
            second.token_sha256_hex(),
            second.token_length(),
            second.expires_at_unix(),
            false,
        )
        .expect("second credential upserts");
        upsert_hosted_relay_credential_hash_in_file(
            &manifest_path,
            "account.other",
            other.node_id(),
            other.token_sha256_hex(),
            other.token_length(),
            other.expires_at_unix(),
            false,
        )
        .expect("other credential upserts");

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("credential manifest configures")
                .with_admin_token(admin_token, manifest_path.clone())
                .expect("admin token configures")
                .with_admin_tenants_file(tenants_path.clone())
                .expect("tenant registry configures");
        let relay = spawn_relay(config).expect("relay starts");

        let mut active_client = connect_client(relay.local_addr());
        write_client_text(
            &mut active_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(first.node_id(), first.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut active_client).contains("WELCOME"));

        let rejected = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::account_suspend(wrong_admin_token, "account.prod")
                .expect("account suspend request"),
        );
        assert!(rejected.contains("ERROR reason=admin_unauthorized"));
        assert!(!rejected.contains(admin_token));
        assert!(!rejected.contains(wrong_admin_token));

        let suspended = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::account_suspend(admin_token, "account.prod")
                .expect("account suspend request"),
        );
        assert!(suspended.contains("ADMIN_RESULT action=account_suspend status=suspended"));
        assert!(suspended.contains("account=account.prod"));
        assert!(suspended.contains("credentials=2 active=0 revoked=2 expired=0 accounts=2"));
        assert!(suspended.contains("tenants=1 active_tenants=0 revoked_tenants=1"));
        assert!(suspended.contains("nodes=2 active_nodes=2 revoked_nodes=0 tenant_policies=2"));
        assert!(suspended.contains("payload_displayed=false"));
        assert!(suspended.contains("token_displayed=false"));
        assert!(suspended.contains("token_hash_displayed=false"));
        assert!(suspended.contains("key_material_displayed=false"));
        assert!(suspended.contains("contents_displayed=false"));
        assert!(!suspended.contains(admin_token));
        assert!(!suspended.contains(wrong_admin_token));
        assert!(!suspended.contains(first.token()));
        assert!(!suspended.contains(first.token_sha256_hex()));
        assert!(!suspended.contains(second.token()));
        assert!(!suspended.contains(second.token_sha256_hex()));
        assert!(!suspended.contains(other.token()));
        assert!(!suspended.contains(other.token_sha256_hex()));
        assert!(!suspended.contains("signing.key.1"));
        assert!(!suspended.contains("exchange.key.1"));

        let mut suspended_client = connect_client(relay.local_addr());
        write_client_text(
            &mut suspended_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(first.node_id(), first.token()).expect("hello"),
            )),
        );
        let suspended_response = read_server_text(&mut suspended_client);
        assert!(suspended_response.contains("ERROR reason=unauthorized"));
        assert!(!suspended_response.contains(first.token()));
        assert!(!suspended_response.contains(first.token_sha256_hex()));

        let mut other_client = connect_client(relay.local_addr());
        write_client_text(
            &mut other_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(other.node_id(), other.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut other_client).contains("WELCOME"));

        let credential_manifest =
            fs::read_to_string(&manifest_path).expect("credential manifest reads");
        assert!(credential_manifest.contains("node_id = \"node.hosted\""));
        assert!(credential_manifest.contains("node_id = \"node.second\""));
        assert!(credential_manifest.contains("node_id = \"node.other\""));
        assert_eq!(
            credential_manifest.matches("status = \"revoked\"").count(),
            2
        );
        assert_eq!(
            credential_manifest.matches("status = \"active\"").count(),
            1
        );
        assert!(!credential_manifest.contains(admin_token));
        assert!(!credential_manifest.contains(first.token()));
        assert!(!credential_manifest.contains(second.token()));
        assert!(!credential_manifest.contains(other.token()));

        let tenant_manifest = fs::read_to_string(&tenants_path).expect("tenant manifest reads");
        assert!(tenant_manifest.contains("account_id = \"account.prod\""));
        assert!(tenant_manifest.contains("account_id = \"account.other\""));
        assert!(!tenant_manifest.contains(admin_token));
        assert!(!tenant_manifest.contains(first.token()));
        assert!(!tenant_manifest.contains(first.token_sha256_hex()));
        assert!(!tenant_manifest.contains("payload-body"));
        assert!(!tenant_manifest.contains("ciphertext_body"));
    }

    #[test]
    fn hosted_admin_mailbox_audit_snapshots_retention_metadata_with_admin_token() {
        let home = test_home("hosted-admin-mailbox-audit");
        let manifest_path = home.join("credentials.toml");
        let mailbox_dir = home.join("relay-mailbox");
        let node_dir = mailbox_dir.join("node.hosted");
        let admin_token = "hosted-admin-mailbox-audit-token-123456";
        let wrong_admin_token = "wrong-hosted-mailbox-audit-token-123456";

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_mailbox_storage(
                    RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("mailbox storage"),
                )
                .with_admin_token(admin_token, manifest_path)
                .expect("admin token configures");
        let relay = spawn_relay(config).expect("relay starts");
        fs::create_dir_all(&node_dir).expect("mailbox node dir");
        let now = current_unix_millis();
        let expired_queued_at = now.saturating_sub(10_000);
        let fresh_queued_at = now.saturating_add(60_000);

        let expired = QueuedRelayEnvelope {
            queued_at_millis: expired_queued_at,
            queued_at_nanos: expired_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.hosted", "env.admin.mailbox.expired"),
            ),
        };
        let fresh = QueuedRelayEnvelope {
            queued_at_millis: fresh_queued_at,
            queued_at_nanos: fresh_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.hosted", "env.admin.mailbox.fresh"),
            ),
        };
        fs::write(
            node_dir.join("expired.mailbox"),
            render_mailbox_file(&expired),
        )
        .expect("expired mailbox file");
        fs::write(node_dir.join("fresh.mailbox"), render_mailbox_file(&fresh))
            .expect("fresh mailbox file");
        fs::write(
            node_dir.join("invalid.mailbox"),
            "version = \"1\"\nqueued_at_millis = invalid\nframe = ENVELOPE from=node.a body_ciphertext=ciphertext_body\npayload_displayed = false\n",
        )
        .expect("invalid mailbox file");
        fs::write(
            node_dir.join("display-guard.mailbox"),
            render_mailbox_file(&expired)
                .replace("payload_displayed = false", "payload_displayed = true"),
        )
        .expect("display guard mailbox file");

        let rejected = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_audit(
                wrong_admin_token,
                Some("node.hosted".to_string()),
                Some(1),
            )
            .expect("mailbox audit request"),
        );
        assert!(rejected.contains("ERROR reason=admin_unauthorized"));
        assert!(!rejected.contains(admin_token));
        assert!(!rejected.contains(wrong_admin_token));

        let audit = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_audit(admin_token, Some("node.hosted".to_string()), Some(1))
                .expect("mailbox audit request"),
        );

        assert!(audit.contains("ADMIN_RESULT action=mailbox_audit status=audited"));
        assert!(audit.contains("node=node.hosted"));
        assert!(audit.contains("ttl_seconds=1"));
        assert!(audit.contains("mailbox_nodes=1"));
        assert!(audit.contains("mailbox_records=4"));
        assert!(audit.contains("mailbox_invalid_records=2"));
        assert!(audit.contains("mailbox_expired_records=1"));
        assert!(audit.contains("payload_displayed=false"));
        assert!(audit.contains("token_displayed=false"));
        assert!(audit.contains("token_hash_displayed=false"));
        assert!(audit.contains("key_material_displayed=false"));
        assert!(audit.contains("session_id_displayed=false"));
        assert!(audit.contains("ciphertext_displayed=false"));
        assert!(audit.contains("contents_displayed=false"));
        assert!(!audit.contains(admin_token));
        assert!(!audit.contains(wrong_admin_token));
        assert!(!audit.contains("ENVELOPE from=node.a"));
        assert!(!audit.contains("ciphertext_body"));
        assert!(!audit.contains("env.admin.mailbox"));
    }

    #[test]
    fn hosted_admin_mailbox_purge_dry_run_and_confirm_with_admin_token() {
        let home = test_home("hosted-admin-mailbox-purge");
        let manifest_path = home.join("credentials.toml");
        let mailbox_dir = home.join("relay-mailbox");
        let node_dir = mailbox_dir.join("node.hosted");
        let admin_token = "hosted-admin-mailbox-purge-token-123456";
        let wrong_admin_token = "wrong-hosted-mailbox-purge-token-123456";

        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_mailbox_storage(
                    RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("mailbox storage"),
                )
                .with_admin_token(admin_token, manifest_path)
                .expect("admin token configures");
        let relay = spawn_relay(config).expect("relay starts");
        fs::create_dir_all(&node_dir).expect("mailbox node dir");
        let now = current_unix_millis();
        let expired_queued_at = now.saturating_sub(10_000);
        let fresh_queued_at = now.saturating_add(60_000);

        let expired = QueuedRelayEnvelope {
            queued_at_millis: expired_queued_at,
            queued_at_nanos: expired_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.hosted", "env.admin.mailbox.purge.expired"),
            ),
        };
        let fresh = QueuedRelayEnvelope {
            queued_at_millis: fresh_queued_at,
            queued_at_nanos: fresh_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.hosted", "env.admin.mailbox.purge.fresh"),
            ),
        };
        let expired_path = node_dir.join("expired.mailbox");
        let fresh_path = node_dir.join("fresh.mailbox");
        let invalid_path = node_dir.join("invalid.mailbox");
        let display_guard_path = node_dir.join("display-guard.mailbox");
        fs::write(&expired_path, render_mailbox_file(&expired)).expect("expired mailbox file");
        fs::write(&fresh_path, render_mailbox_file(&fresh)).expect("fresh mailbox file");
        fs::write(
            &invalid_path,
            "version = \"1\"\nqueued_at_millis = invalid\nframe = ENVELOPE from=node.a body_ciphertext=ciphertext_body\npayload_displayed = false\n",
        )
        .expect("invalid mailbox file");
        fs::write(
            &display_guard_path,
            render_mailbox_file(&expired)
                .replace("payload_displayed = false", "payload_displayed = true"),
        )
        .expect("display guard mailbox file");

        let rejected = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_purge(
                wrong_admin_token,
                Some("node.hosted".to_string()),
                1,
                true,
            )
            .expect("mailbox purge request"),
        );
        assert!(rejected.contains("ERROR reason=admin_unauthorized"));
        assert!(!rejected.contains(admin_token));
        assert!(!rejected.contains(wrong_admin_token));
        assert!(expired_path.exists());

        let dry_run = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_purge(admin_token, Some("node.hosted".to_string()), 1, true)
                .expect("mailbox purge request"),
        );

        assert!(dry_run.contains("ADMIN_RESULT action=mailbox_purge status=dry_run"));
        assert!(dry_run.contains("node=node.hosted"));
        assert!(dry_run.contains("ttl_seconds=1"));
        assert!(dry_run.contains("mailbox_nodes=1"));
        assert!(dry_run.contains("mailbox_records=4"));
        assert!(dry_run.contains("mailbox_invalid_records=2"));
        assert!(dry_run.contains("mailbox_expired_records=1"));
        assert!(dry_run.contains("mailbox_purged_records=0"));
        assert!(dry_run.contains("dry_run=true"));
        assert!(dry_run.contains("confirmed=false"));
        assert!(dry_run.contains("payload_displayed=false"));
        assert!(dry_run.contains("token_displayed=false"));
        assert!(dry_run.contains("ciphertext_displayed=false"));
        assert!(dry_run.contains("contents_displayed=false"));
        assert!(!dry_run.contains(admin_token));
        assert!(!dry_run.contains(wrong_admin_token));
        assert!(!dry_run.contains("ENVELOPE from=node.a"));
        assert!(!dry_run.contains("ciphertext_body"));
        assert!(!dry_run.contains("env.admin.mailbox"));
        assert!(expired_path.exists());

        let confirmed = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::mailbox_purge(
                admin_token,
                Some("node.hosted".to_string()),
                1,
                false,
            )
            .expect("mailbox purge request"),
        );

        assert!(confirmed.contains("ADMIN_RESULT action=mailbox_purge status=purged"));
        assert!(confirmed.contains("mailbox_expired_records=1"));
        assert!(confirmed.contains("mailbox_purged_records=1"));
        assert!(confirmed.contains("dry_run=false"));
        assert!(confirmed.contains("confirmed=true"));
        assert!(confirmed.contains("payload_displayed=false"));
        assert!(confirmed.contains("token_displayed=false"));
        assert!(confirmed.contains("ciphertext_displayed=false"));
        assert!(confirmed.contains("contents_displayed=false"));
        assert!(!confirmed.contains(admin_token));
        assert!(!confirmed.contains(wrong_admin_token));
        assert!(!confirmed.contains("ENVELOPE from=node.a"));
        assert!(!confirmed.contains("ciphertext_body"));
        assert!(!confirmed.contains("env.admin.mailbox"));
        assert!(!expired_path.exists());
        assert!(fresh_path.exists());
        assert!(invalid_path.exists());
        assert!(display_guard_path.exists());
    }

    #[test]
    fn hosted_tenant_registry_updates_and_audits_without_secret_material() {
        let home = test_home("hosted-tenant-registry-safe");
        let tenants_path = home.join("tenants.toml");
        let token = "hosted-node-token-that-must-not-appear";
        let token_hash = relay_token_sha256_hex(token).expect("hash generated");
        let permissions = HostedTenantPermissions {
            messages: true,
            streams: true,
            rooms: false,
            files: false,
            mailbox: true,
        };

        let tenant_update =
            upsert_hosted_tenant_in_file(&tenants_path, "account.prod").expect("tenant upserts");
        let node_update = upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            "node.hosted",
            permissions,
            Some("signing.key.1".to_string()),
            Some("exchange.key.1".to_string()),
        )
        .expect("tenant node upserts");
        let audit =
            audit_hosted_tenants_file(&tenants_path, Some("account.prod")).expect("tenant audit");
        let manifest = fs::read_to_string(&tenants_path).expect("tenant manifest reads");

        assert_eq!(tenant_update.tenants, 1);
        assert_eq!(node_update.nodes, 1);
        assert_eq!(audit.tenants, 1);
        assert_eq!(audit.active_tenants, 1);
        assert_eq!(audit.nodes, 1);
        assert_eq!(audit.active_nodes, 1);
        assert_eq!(audit.policies, 1);
        assert!(!tenant_update.token_displayed);
        assert!(!tenant_update.key_material_displayed);
        assert!(!tenant_update.contents_displayed);
        assert!(!node_update.token_displayed);
        assert!(!node_update.key_material_displayed);
        assert!(!node_update.contents_displayed);
        assert!(!audit.token_displayed);
        assert!(!audit.key_material_displayed);
        assert!(!audit.contents_displayed);
        assert!(manifest.contains("payload_displayed = false"));
        assert!(manifest.contains("token_displayed = false"));
        assert!(manifest.contains("key_material_displayed = false"));
        assert!(manifest.contains("contents_displayed = false"));
        assert!(manifest.contains("signing_key_id = \"signing.key.1\""));
        assert!(manifest.contains("exchange_key_id = \"exchange.key.1\""));
        assert!(!manifest.contains(token));
        assert!(!manifest.contains(&token_hash));
        assert!(!manifest.contains("BEGIN PRIVATE KEY"));
        assert!(!manifest.contains("payload-body"));
        assert!(!manifest.contains("ciphertext_body"));
    }

    #[test]
    fn hosted_tenant_registry_gates_admin_and_runtime_fail_closed() {
        let home = test_home("hosted-tenant-admin-runtime-gate");
        let manifest_path = home.join("credentials.toml");
        let tenants_path = home.join("tenants.toml");
        let admin_token = "hosted-admin-control-token-with-tenants";
        let first = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[31_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            1_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("first credential issues");
        let second = issue_relay_credential_from_token_bytes(
            "node.hosted",
            &[37_u8; ISSUED_RELAY_TOKEN_BYTES],
            None,
            2_000,
        )
        .and_then(|credential| credential.with_account_id("account.prod"))
        .expect("second credential issues");
        let config =
            RelayConfig::with_scoped_credentials_file("127.0.0.1:0", manifest_path.clone())
                .expect("missing manifest starts fail-closed")
                .with_admin_token(admin_token, manifest_path.clone())
                .expect("admin token configures")
                .with_admin_tenants_file(tenants_path.clone())
                .expect("tenant registry configures");
        let relay = spawn_relay(config).expect("relay starts");

        let missing_tenant = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                admin_token,
                "account.prod",
                first.node_id(),
                first.token_sha256_hex().to_string(),
                first.token_length(),
                first.expires_at_unix(),
            )
            .expect("issue request"),
        );
        assert!(missing_tenant.contains("ADMIN_RESULT action=issue status=tenant_not_found"));
        assert!(!missing_tenant.contains(admin_token));
        assert!(!missing_tenant.contains(first.token()));
        assert!(!missing_tenant.contains(first.token_sha256_hex()));
        assert!(!manifest_path.exists());

        upsert_hosted_tenant_in_file(&tenants_path, "account.prod").expect("tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_path,
            "account.prod",
            first.node_id(),
            HostedTenantPermissions {
                messages: true,
                streams: true,
                rooms: true,
                files: false,
                mailbox: true,
            },
            Some("signing.key.1".to_string()),
            Some("exchange.key.1".to_string()),
        )
        .expect("tenant node upserts");

        let issued = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::issue(
                admin_token,
                "account.prod",
                first.node_id(),
                first.token_sha256_hex().to_string(),
                first.token_length(),
                first.expires_at_unix(),
            )
            .expect("issue request"),
        );
        assert!(issued.contains("ADMIN_RESULT action=issue status=issued"));
        assert!(!issued.contains(admin_token));
        assert!(!issued.contains(first.token()));
        assert!(!issued.contains(first.token_sha256_hex()));

        let mut active_client = connect_client(relay.local_addr());
        write_client_text(
            &mut active_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(first.node_id(), first.token()).expect("hello"),
            )),
        );
        assert!(read_server_text(&mut active_client).contains("WELCOME"));

        revoke_hosted_tenant_node_in_file(&tenants_path, "account.prod", first.node_id())
            .expect("tenant node revokes");

        let mut revoked_tenant_client = connect_client(relay.local_addr());
        write_client_text(
            &mut revoked_tenant_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new(first.node_id(), first.token()).expect("hello"),
            )),
        );
        let revoked_tenant_response = read_server_text(&mut revoked_tenant_client);
        assert!(revoked_tenant_response.contains("ERROR reason=unauthorized"));
        assert!(!revoked_tenant_response.contains(first.token()));
        assert!(!revoked_tenant_response.contains(first.token_sha256_hex()));

        let denied_rotate = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::rotate(
                admin_token,
                "account.prod",
                second.node_id(),
                second.token_sha256_hex().to_string(),
                second.token_length(),
                second.expires_at_unix(),
            )
            .expect("rotate request"),
        );
        assert!(denied_rotate.contains("ADMIN_RESULT action=rotate status=tenant_node_revoked"));
        assert!(!denied_rotate.contains(admin_token));
        assert!(!denied_rotate.contains(first.token()));
        assert!(!denied_rotate.contains(second.token()));
        assert!(!denied_rotate.contains(second.token_sha256_hex()));

        let revoked_credential = send_admin_text(
            relay.local_addr(),
            RelayAdminRequest::revoke(admin_token, "account.prod", first.node_id())
                .expect("revoke request"),
        );
        assert!(revoked_credential.contains("ADMIN_RESULT action=revoke status=revoked"));
        assert!(!revoked_credential.contains(admin_token));
        assert!(!revoked_credential.contains(first.token()));
        assert!(!revoked_credential.contains(first.token_sha256_hex()));
    }

    #[test]
    fn public_bind_rejects_hashed_dev_or_short_tokens_without_echoing_hash() {
        let dev_hash = relay_token_sha256_hex("local-dev-token").expect("dev hash");
        let dev_credential =
            RelayCredential::from_sha256_hex("node.dev", dev_hash.clone(), "local-dev-token".len())
                .expect("dev hashed credential parses");
        let dev_error = RelayConfig::with_scoped_credentials("0.0.0.0:8787", vec![dev_credential])
            .expect_err("public dev hash should be rejected");
        let short_hash = relay_token_sha256_hex("short-token").expect("short hash");
        let short_credential =
            RelayCredential::from_sha256_hex("node.short", short_hash.clone(), "short-token".len())
                .expect("short hashed credential parses");
        let short_error =
            RelayConfig::with_scoped_credentials("0.0.0.0:8787", vec![short_credential])
                .expect_err("public short hash should be rejected");

        assert!(dev_error.to_string().contains("loopback-only"));
        assert!(!dev_error.to_string().contains(&dev_hash));
        assert!(short_error.to_string().contains("at least 24"));
        assert!(!short_error.to_string().contains(&short_hash));
    }

    #[test]
    fn credential_manifest_rejects_token_displayed_true() {
        let token = "manifest-token-1234567890";
        let hash = relay_token_sha256_hex(token).expect("hash");
        let contents = format!(
            "version = \"1\"\n\n\
[[credential]]\n\
node_id = \"node.a\"\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
token_displayed = true\n",
            token.len()
        );
        let error = parse_scoped_credentials_file(&contents)
            .expect_err("token_displayed true should be rejected");

        assert!(error.to_string().contains("token_displayed must be false"));
        assert!(!error.to_string().contains(token));
        assert!(!error.to_string().contains(&hash));
    }

    #[test]
    fn relay_manifest_parsers_reject_duplicate_keys_without_secret_values() {
        let secret = "relay-duplicate-secret";
        let token = "duplicate-manifest-token-1234567890";
        let hash = relay_token_sha256_hex(token).expect("hash");
        let duplicate_message = |error: RelayError, key: &str| {
            let message = error.to_string();
            assert!(message.contains(&format!("duplicate key {key}")));
            assert!(!message.contains(secret));
            assert!(!message.contains(&hash));
        };

        let credential_top_level = format!(
            "version = \"1\"\nversion = \"{secret}\"\n\n\
[[credential]]\n\
node_id = \"node.a\"\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
payload_displayed = false\n\
token_displayed = false\n",
            token.len()
        );
        duplicate_message(
            parse_scoped_credentials_file(&credential_top_level)
                .expect_err("duplicate credential version should fail closed"),
            "version",
        );

        let credential_entry = format!(
            "version = \"1\"\n\n\
[[credential]]\n\
node_id = \"node.a\"\n\
node_id = \"{secret}\"\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
payload_displayed = false\n\
token_displayed = false\n",
            token.len()
        );
        duplicate_message(
            parse_scoped_credentials_file(&credential_entry)
                .expect_err("duplicate credential entry key should fail closed"),
            "node_id",
        );

        let admin_top_level = format!(
            "version = \"1\"\nversion = \"{secret}\"\n\n\
[[admin_token]]\n\
token_sha256_hex = \"{hash}\"\n\
token_length = {}\n\
scope_dashboard = true\n\
token_hash_displayed = false\n",
            token.len()
        );
        duplicate_message(
            parse_admin_tokens_file(&admin_top_level, "127.0.0.1:0")
                .expect_err("duplicate admin-token version should fail closed"),
            "version",
        );

        let admin_entry = format!(
            "version = \"1\"\n\n\
[[admin_token]]\n\
token_sha256_hex = \"{hash}\"\n\
token_sha256_hex = \"{secret}\"\n\
token_length = {}\n\
scope_dashboard = true\n\
token_hash_displayed = false\n",
            token.len()
        );
        duplicate_message(
            parse_admin_tokens_file(&admin_entry, "127.0.0.1:0")
                .expect_err("duplicate admin-token entry key should fail closed"),
            "token_sha256_hex",
        );

        let tenant_top_level = format!(
            "version = \"1\"\nversion = \"{secret}\"\n\n\
[[tenant]]\n\
account_id = \"account.prod\"\n\
payload_displayed = false\n\
token_displayed = false\n\
key_material_displayed = false\n\
contents_displayed = false\n"
        );
        duplicate_message(
            parse_hosted_tenant_manifest(&tenant_top_level)
                .expect_err("duplicate hosted-tenant version should fail closed"),
            "version",
        );

        let tenant_entry = format!(
            "version = \"1\"\n\n\
[[tenant]]\n\
account_id = \"account.prod\"\n\
account_id = \"{secret}\"\n\
payload_displayed = false\n\
token_displayed = false\n\
key_material_displayed = false\n\
contents_displayed = false\n"
        );
        duplicate_message(
            parse_hosted_tenant_manifest(&tenant_entry)
                .expect_err("duplicate hosted-tenant entry key should fail closed"),
            "account_id",
        );

        let tenant_node_entry = format!(
            "version = \"1\"\n\n\
[[tenant]]\n\
account_id = \"account.prod\"\n\
payload_displayed = false\n\
token_displayed = false\n\
key_material_displayed = false\n\
contents_displayed = false\n\n\
[[tenant_node]]\n\
account_id = \"account.prod\"\n\
node_id = \"node.a\"\n\
node_id = \"{secret}\"\n\
payload_displayed = false\n\
token_displayed = false\n\
key_material_displayed = false\n\
contents_displayed = false\n"
        );
        duplicate_message(
            parse_hosted_tenant_manifest(&tenant_node_entry)
                .expect_err("duplicate hosted-tenant node key should fail closed"),
            "node_id",
        );
    }

    #[test]
    fn relay_accounting_quota_rejects_sender_without_payloads() {
        let accounting_policy = RelayAccountingPolicy::new(stable_counter_window(), Some(1), None)
            .expect("accounting policy");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_accounting_policy(accounting_policy),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());
        let mut node_b = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));
        assert!(read_server_text(&mut node_b).contains("WELCOME"));

        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.quota.1")),
        );
        assert!(read_server_text(&mut node_b).contains("ENVELOPE"));
        assert!(read_server_text(&mut node_a).contains("SENT"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.quota.2")),
        );
        let rejected = read_server_text(&mut node_a);

        assert!(rejected.contains("UNDELIVERED to=node.b envelope=env.quota.2"));
        assert!(rejected.contains("reason=quota_exceeded"));
        assert!(!rejected.contains("private message contents"));
        assert!(!rejected.contains("test-token"));
    }

    #[test]
    fn relay_file_backed_accounting_records_metadata_without_payloads() {
        let accounting_dir = test_home("relay-accounting").join("accounting");
        let accounting_storage =
            RelayAccountingStorage::file_backed(accounting_dir.clone()).expect("storage config");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_accounting_storage(accounting_storage),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());
        let mut node_b = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));
        assert!(read_server_text(&mut node_b).contains("WELCOME"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.accounting.1")),
        );
        assert!(read_server_text(&mut node_b).contains("ENVELOPE"));
        assert!(read_server_text(&mut node_a).contains("SENT"));

        let stored = read_accounting_texts(&accounting_dir);
        let joined = stored.join("\n");

        assert_eq!(stored.len(), 2);
        assert!(joined.contains("node_id = \"node.a\""));
        assert!(joined.contains("node_id = \"node.b\""));
        assert!(joined.contains("sessions_authenticated = 1"));
        assert!(joined.contains("sessions_resumed = 0"));
        assert!(joined.contains("envelopes_sent = 1"));
        assert!(joined.contains("bytes_sent = 22"));
        assert!(joined.contains("envelopes_received = 1"));
        assert!(joined.contains("bytes_received = 22"));
        assert!(joined.contains("payload_displayed = false"));
        assert!(joined.contains("token_displayed = false"));
        assert!(!joined.contains("private message contents"));
        assert!(!joined.contains("test-token"));
    }

    #[test]
    fn relay_accounting_audit_summarizes_metadata_without_payloads() {
        let accounting_dir = test_home("relay-accounting-audit").join("accounting");
        let accounting_storage =
            RelayAccountingStorage::file_backed(accounting_dir.clone()).expect("storage config");
        let record_a = RelayAccountingRecord {
            node_id: "node.a".to_string(),
            window_started_unix: 1_763_596_800,
            sessions_authenticated: 2,
            sessions_resumed: 1,
            envelopes_sent: 3,
            bytes_sent: 33,
            envelopes_received: 4,
            bytes_received: 44,
            envelopes_mailboxed: 1,
            bytes_mailboxed: 11,
        };
        let record_b = RelayAccountingRecord {
            node_id: "node.b".to_string(),
            window_started_unix: 1_763_596_800,
            sessions_authenticated: 1,
            sessions_resumed: 0,
            envelopes_sent: 5,
            bytes_sent: 55,
            envelopes_received: 6,
            bytes_received: 66,
            envelopes_mailboxed: 2,
            bytes_mailboxed: 22,
        };
        persist_accounting_record(&accounting_storage, &record_a).expect("record a writes");
        persist_accounting_record(&accounting_storage, &record_b).expect("record b writes");

        let audit = audit_relay_accounting_dir(&accounting_dir, None).expect("accounting audit");
        assert_eq!(audit.records, 2);
        assert_eq!(audit.window_started_unix, Some(1_763_596_800));
        assert_eq!(audit.sessions_authenticated, 3);
        assert_eq!(audit.sessions_resumed, 1);
        assert_eq!(audit.envelopes_sent, 8);
        assert_eq!(audit.bytes_sent, 88);
        assert_eq!(audit.envelopes_received, 10);
        assert_eq!(audit.bytes_received, 110);
        assert_eq!(audit.envelopes_mailboxed, 3);
        assert_eq!(audit.bytes_mailboxed, 33);
        assert!(!audit.payload_displayed);
        assert!(!audit.token_displayed);
        assert!(!audit.token_hash_displayed);
        assert!(!audit.key_material_displayed);
        assert!(!audit.session_id_displayed);
        assert!(!audit.ciphertext_displayed);
        assert!(!audit.contents_displayed);

        let filtered =
            audit_relay_accounting_dir(&accounting_dir, Some("node.a")).expect("filtered audit");
        assert_eq!(filtered.records, 1);
        assert_eq!(filtered.node_id.as_deref(), Some("node.a"));
        assert_eq!(filtered.bytes_sent, 33);
        assert_eq!(filtered.bytes_received, 44);

        let missing = audit_relay_accounting_dir(accounting_dir.join("missing"), None)
            .expect("missing audit is empty");
        assert_eq!(missing.records, 0);
        assert_eq!(missing.window_started_unix, None);

        let stored = read_accounting_texts(&accounting_dir).join("\n");
        assert!(!stored.contains("test-token"));
        assert!(!stored.contains("token_sha256_hex"));
        assert!(!stored.contains("relay_node.a_123456789"));
        assert!(!stored.contains("private message contents"));
        assert!(!stored.contains("ciphertext_body"));
    }

    #[test]
    fn relay_accounting_loads_existing_window_for_quota() {
        let accounting_dir = test_home("relay-accounting-quota").join("accounting");
        let accounting_storage =
            RelayAccountingStorage::file_backed(accounting_dir).expect("storage config");
        let accounting_policy = RelayAccountingPolicy::new(stable_counter_window(), Some(1), None)
            .expect("accounting policy");
        let mut state = RelayAccountingState::load(&accounting_storage, accounting_policy)
            .expect("accounting loads");

        state
            .record_forward(
                "node.a",
                "node.b",
                22,
                true,
                accounting_policy,
                &accounting_storage,
            )
            .expect("accounting records");
        let mut loaded = RelayAccountingState::load(&accounting_storage, accounting_policy)
            .expect("accounting reloads");

        assert!(!loaded.quota_allows("node.a", 1, accounting_policy));
        assert!(loaded.quota_allows("node.b", 1, accounting_policy));
    }

    #[test]
    fn relay_file_backed_abuse_records_denials_without_secret_material() {
        let abuse_dir = test_home("relay-abuse-dashboard").join("abuse");
        let abuse_storage =
            RelayAbuseStorage::file_backed(abuse_dir.clone()).expect("abuse storage config");
        let counter_window = stable_counter_window();
        let abuse_policy = RelayAbusePolicy::new(counter_window).expect("abuse policy");
        let accounting_policy =
            RelayAccountingPolicy::new(counter_window, Some(2), None).expect("accounting policy");
        let mailbox_policy =
            RelayMailboxPolicy::new(1, Duration::from_secs(60)).expect("mailbox policy");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_abuse_policy(abuse_policy)
                .with_abuse_storage(abuse_storage.clone())
                .with_accounting_policy(accounting_policy)
                .with_mailbox_policy(mailbox_policy),
        )
        .expect("relay starts");

        let mut denied = connect_client(relay.local_addr());
        write_client_text(
            &mut denied,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.denied", "wrong-secret-token").expect("hello"),
            )),
        );
        let denied_response = read_server_text(&mut denied);
        assert!(denied_response.contains("ERROR reason=unauthorized"));
        assert!(!denied_response.contains("wrong-secret-token"));

        let mut node_a = connect_client(relay.local_addr());
        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));

        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.offline", "env.abuse.1")),
        );
        assert!(read_server_text(&mut node_a).contains("SENT"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.offline", "env.abuse.2")),
        );
        let mailbox_rejected = read_server_text(&mut node_a);
        assert!(mailbox_rejected.contains("reason=mailbox_full"));

        let mut node_b = connect_client(relay.local_addr());
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_b).contains("WELCOME"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.quota.audit.1")),
        );
        assert!(read_server_text(&mut node_b).contains("ENVELOPE"));
        assert!(read_server_text(&mut node_a).contains("SENT"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.quota.audit.2")),
        );
        let quota_rejected = read_server_text(&mut node_a);
        assert!(quota_rejected.contains("reason=quota_exceeded"));
        drop(node_a);
        drop(node_b);
        drop(denied);
        drop(relay);

        let rate_relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_abuse_policy(abuse_policy)
                .with_abuse_storage(abuse_storage.clone())
                .with_limits(RelayLimits::new(8, 8, 1).expect("limits")),
        )
        .expect("rate relay starts");
        let mut rate_client = connect_client(rate_relay.local_addr());
        write_client_text(
            &mut rate_client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.rate", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut rate_client).contains("WELCOME"));
        write_client_text(
            &mut rate_client,
            "PING payload_text=private-message-contents",
        );
        let rate_limited = read_server_text(&mut rate_client);
        assert!(rate_limited.contains("ERROR reason=rate_limited"));
        drop(rate_client);
        drop(rate_relay);

        let session_policy =
            RelaySessionPolicy::new(Duration::from_secs(5), Duration::from_millis(10))
                .expect("session policy");
        let expiring_relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_abuse_policy(abuse_policy)
                .with_abuse_storage(abuse_storage.clone())
                .with_session_policy(session_policy),
        )
        .expect("expiring relay starts");
        let mut expiring = connect_client(expiring_relay.local_addr());
        write_client_text(
            &mut expiring,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.expiring", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut expiring).contains("WELCOME"));
        thread::sleep(Duration::from_millis(50));
        write_client_text(&mut expiring, "PING payload_text=private-message-contents");
        assert!(read_server_text(&mut expiring).contains("ERROR reason=session_expired"));
        drop(expiring);
        drop(expiring_relay);

        let audit = audit_relay_abuse_dir(&abuse_dir, None).expect("abuse audit reads");
        assert_eq!(audit.unauthorized_sessions, 1);
        assert_eq!(audit.credential_denied_sessions, 1);
        assert_eq!(audit.mailbox_rejected_forwards, 1);
        assert_eq!(audit.undelivered_forwards, 1);
        assert_eq!(audit.quota_denied_forwards, 1);
        assert_eq!(audit.rate_limited_sessions, 1);
        assert_eq!(audit.session_expired, 1);
        assert!(!audit.payload_displayed);
        assert!(!audit.token_displayed);
        assert!(!audit.token_hash_displayed);
        assert!(!audit.key_material_displayed);
        assert!(!audit.session_id_displayed);
        assert!(!audit.ciphertext_displayed);
        assert!(!audit.contents_displayed);

        let node_a_audit =
            audit_relay_abuse_dir(&abuse_dir, Some("node.a")).expect("node audit reads");
        assert_eq!(node_a_audit.quota_denied_forwards, 1);
        assert_eq!(node_a_audit.mailbox_rejected_forwards, 1);
        assert_eq!(node_a_audit.credential_denied_sessions, 0);

        let joined = read_abuse_texts(&abuse_dir).join("\n");
        assert!(joined.contains("payload_displayed = false"));
        assert!(joined.contains("token_displayed = false"));
        assert!(joined.contains("token_hash_displayed = false"));
        assert!(joined.contains("key_material_displayed = false"));
        assert!(joined.contains("session_id_displayed = false"));
        assert!(joined.contains("ciphertext_displayed = false"));
        assert!(joined.contains("contents_displayed = false"));
        assert!(!joined.contains("wrong-secret-token"));
        assert!(!joined.contains("test-token"));
        assert!(!joined.contains("private-message-contents"));
        assert!(!joined.contains("ciphertext_body"));
        assert!(!joined.contains("token_sha256_hex"));
    }

    #[test]
    fn relay_resumes_same_node_session_and_accounts_metadata_only() {
        let accounting_dir = test_home("relay-resume-accounting").join("accounting");
        let accounting_storage =
            RelayAccountingStorage::file_backed(accounting_dir.clone()).expect("storage config");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_accounting_storage(accounting_storage),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        let first = read_server_text(&mut node_a);
        let first_session = match parse_server_frame(&first).expect("welcome parses") {
            RelayServerFrame::Welcome {
                session_id,
                resumed,
            } => {
                assert!(!resumed);
                session_id
            }
            other => panic!("unexpected frame: {other:?}"),
        };
        drop(node_a);
        thread::sleep(Duration::from_millis(100));

        let mut node_a_again = connect_client(relay.local_addr());
        write_client_text(
            &mut node_a_again,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token")
                    .expect("hello")
                    .with_resume_session_id(first_session.clone())
                    .expect("resume id"),
            )),
        );
        let resumed = read_server_text(&mut node_a_again);
        match parse_server_frame(&resumed).expect("resumed welcome parses") {
            RelayServerFrame::Welcome {
                session_id,
                resumed,
            } => {
                assert_eq!(session_id, first_session);
                assert!(resumed);
            }
            other => panic!("unexpected frame: {other:?}"),
        };

        let mut node_b = connect_client(relay.local_addr());
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token")
                    .expect("hello")
                    .with_resume_session_id(first_session.clone())
                    .expect("resume id"),
            )),
        );
        let rejected_cross_node_resume = read_server_text(&mut node_b);
        match parse_server_frame(&rejected_cross_node_resume).expect("node b welcome parses") {
            RelayServerFrame::Welcome {
                session_id,
                resumed,
            } => {
                assert_ne!(session_id, first_session);
                assert!(!resumed);
            }
            other => panic!("unexpected frame: {other:?}"),
        };

        let joined = read_accounting_texts(&accounting_dir).join("\n");
        assert!(joined.contains("node_id = \"node.a\""));
        assert!(joined.contains("sessions_authenticated = 2"));
        assert!(joined.contains("sessions_resumed = 1"));
        assert!(joined.contains("node_id = \"node.b\""));
        assert!(joined.contains("sessions_authenticated = 1"));
        assert!(!joined.contains("private message contents"));
        assert!(!joined.contains("test-token"));
        assert!(!resumed.contains("test-token"));
        assert!(!rejected_cross_node_resume.contains("test-token"));
    }

    #[test]
    fn relay_file_backed_session_state_survives_restart_without_payloads() {
        let session_dir = test_home("relay-session-state").join("sessions");
        let session_storage =
            RelaySessionStorage::file_backed(session_dir.clone()).expect("storage config");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_session_storage(session_storage.clone()),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        let first = read_server_text(&mut node_a);
        let first_session = match parse_server_frame(&first).expect("welcome parses") {
            RelayServerFrame::Welcome {
                session_id,
                resumed,
            } => {
                assert!(!resumed);
                session_id
            }
            other => panic!("unexpected frame: {other:?}"),
        };
        drop(node_a);
        drop(relay);

        let restarted = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_session_storage(session_storage),
        )
        .expect("relay restarts");
        let mut node_a_again = connect_client(restarted.local_addr());
        write_client_text(
            &mut node_a_again,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token")
                    .expect("hello")
                    .with_resume_session_id(first_session.clone())
                    .expect("resume id"),
            )),
        );
        let resumed = read_server_text(&mut node_a_again);
        match parse_server_frame(&resumed).expect("resumed welcome parses") {
            RelayServerFrame::Welcome {
                session_id,
                resumed,
            } => {
                assert_eq!(session_id, first_session);
                assert!(resumed);
            }
            other => panic!("unexpected frame: {other:?}"),
        };

        let mut node_b = connect_client(restarted.local_addr());
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token")
                    .expect("hello")
                    .with_resume_session_id(first_session.clone())
                    .expect("resume id"),
            )),
        );
        match parse_server_frame(&read_server_text(&mut node_b)).expect("node b welcome parses") {
            RelayServerFrame::Welcome {
                session_id,
                resumed,
            } => {
                assert_ne!(session_id, first_session);
                assert!(!resumed);
            }
            other => panic!("unexpected frame: {other:?}"),
        };

        let joined = read_session_texts(&session_dir).join("\n");
        assert!(joined.contains("node_id = \"node.a\""));
        assert!(joined.contains("payload_displayed = false"));
        assert!(joined.contains("token_displayed = false"));
        assert!(joined.contains("contents_displayed = false"));
        assert!(!joined.contains("private message contents"));
        assert!(!joined.contains("test-token"));
        assert!(!joined.contains("token_sha256_hex"));
        assert!(!resumed.contains("test-token"));

        let loaded_state = RelaySessionState::load(
            &RelaySessionStorage::file_backed(session_dir).expect("storage config"),
            RelaySessionPolicy::default(),
        )
        .expect("session state reloads");
        let debug = format!("{loaded_state:?}");
        assert!(!debug.contains(&first_session));
        assert!(!debug.contains("test-token"));
    }

    #[test]
    fn relay_session_resume_reloads_file_backed_record_on_demand() {
        let session_dir = test_home("relay-session-on-demand").join("sessions");
        let session_storage =
            RelaySessionStorage::file_backed(session_dir).expect("storage config");
        let session_id = "relay_node.a_on_demand".to_string();
        let record = RelaySessionRecord::new(
            "node.a",
            &session_id,
            current_unix_millis_u64(),
            RelaySessionPolicy::default(),
        );
        persist_session_record(&session_storage, &record).expect("session record persists");

        let mut sessions = RelaySessionState::default();

        assert!(
            sessions
                .can_resume("node.a", &session_id, &session_storage)
                .expect("session resume checks")
        );
        assert!(
            !sessions
                .can_resume("node.b", &session_id, &session_storage)
                .expect("cross-node resume checks")
        );
    }

    #[test]
    fn relay_session_state_load_skips_invalid_records_without_payloads() {
        let session_dir = test_home("relay-session-state-invalid-load").join("sessions");
        fs::create_dir_all(&session_dir).expect("session dir exists");
        let invalid_path = relay_session_record_path(&session_dir, "node.invalid");
        fs::write(
            &invalid_path,
            "version = \"1\"\nnode_id = \"node.invalid\"\nsession_id = \"relay_node.invalid_1\"\ncreated_at_unix_millis = not-a-number\nlast_seen_unix_millis = 1\nexpires_at_unix_millis = 2\npayload_displayed = false\ntoken_displayed = false\ncontents_displayed = false\n",
        )
        .expect("invalid session state writes");
        let now = current_unix_millis_u64();
        let valid = RelaySessionRecord {
            node_id: "node.valid".to_string(),
            session_id: session_id("node.valid"),
            created_at_unix_millis: now,
            last_seen_unix_millis: now,
            expires_at_unix_millis: now.saturating_add(5_000),
        };
        fs::write(
            relay_session_record_path(&session_dir, "node.valid"),
            render_session_file(&valid),
        )
        .expect("valid session state writes");

        let loaded_state = RelaySessionState::load(
            &RelaySessionStorage::file_backed(session_dir).expect("storage config"),
            RelaySessionPolicy::default(),
        )
        .expect("session state loads around invalid records");

        assert_eq!(loaded_state.records.len(), 1);
        assert!(loaded_state.records.contains_key("node.valid"));
        assert!(!invalid_path.exists());
        let debug = format!("{loaded_state:?}");
        assert!(!debug.contains("relay_node.invalid_1"));
        assert!(!debug.contains("not-a-number"));
    }

    #[test]
    fn relay_session_state_audit_reports_metadata_only() {
        let session_dir = test_home("relay-session-state-audit").join("sessions");
        fs::create_dir_all(&session_dir).expect("session dir exists");
        let now = current_unix_millis_u64();
        let active_session = session_id("node.a");
        let expired_session = session_id("node.b");
        let active = RelaySessionRecord {
            node_id: "node.a".to_string(),
            session_id: active_session.clone(),
            created_at_unix_millis: now.saturating_sub(1_000),
            last_seen_unix_millis: now.saturating_sub(500),
            expires_at_unix_millis: now.saturating_add(5_000),
        };
        let expired = RelaySessionRecord {
            node_id: "node.b".to_string(),
            session_id: expired_session.clone(),
            created_at_unix_millis: now.saturating_sub(2_000),
            last_seen_unix_millis: now.saturating_sub(1_500),
            expires_at_unix_millis: now.saturating_sub(1),
        };
        fs::write(
            relay_session_record_path(&session_dir, "node.a"),
            render_session_file(&active),
        )
        .expect("active session writes");
        fs::write(
            relay_session_record_path(&session_dir, "node.b"),
            render_session_file(&expired),
        )
        .expect("expired session writes");
        fs::write(
            session_dir.join("invalid.session"),
            "version = \"1\"\nnode_id = \"node.invalid\"\nsession_id = \"relay_node.invalid_1\"\npayload_displayed = true\n",
        )
        .expect("invalid session writes");

        let audit = audit_relay_session_state_dir(&session_dir, None).expect("session audit reads");
        assert_eq!(audit.records, 2);
        assert_eq!(audit.active_records, 1);
        assert_eq!(audit.expired_records, 1);
        assert_eq!(audit.invalid_records, 1);
        assert_eq!(
            audit.oldest_created_unix_millis,
            Some(expired.created_at_unix_millis)
        );
        assert_eq!(
            audit.newest_last_seen_unix_millis,
            Some(active.last_seen_unix_millis)
        );
        assert_eq!(
            audit.next_expires_unix_millis,
            Some(active.expires_at_unix_millis)
        );
        assert!(!audit.payload_displayed);
        assert!(!audit.token_displayed);
        assert!(!audit.token_hash_displayed);
        assert!(!audit.key_material_displayed);
        assert!(!audit.session_id_displayed);
        assert!(!audit.ciphertext_displayed);
        assert!(!audit.contents_displayed);

        let node_a_audit =
            audit_relay_session_state_dir(&session_dir, Some("node.a")).expect("node audit reads");
        assert_eq!(node_a_audit.records, 1);
        assert_eq!(node_a_audit.active_records, 1);
        assert_eq!(node_a_audit.expired_records, 0);
        assert_eq!(node_a_audit.invalid_records, 0);

        let debug = format!("{audit:?}");
        assert!(!debug.contains(&active_session));
        assert!(!debug.contains(&expired_session));
        assert!(!debug.contains("test-token"));
    }

    #[test]
    fn relay_session_ttl_expires_without_echoing_payloads() {
        let session_policy =
            RelaySessionPolicy::new(Duration::from_secs(5), Duration::from_millis(10))
                .expect("valid session policy");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_session_policy(session_policy),
        )
        .expect("relay starts");
        let mut client = connect_client(relay.local_addr());

        write_client_text(
            &mut client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.expiring", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut client).contains("WELCOME"));

        thread::sleep(Duration::from_millis(50));
        write_client_text(&mut client, "PING payload_text=private-message-contents");
        let response = read_server_text(&mut client);

        assert!(response.contains("ERROR reason=session_expired"));
        assert!(!response.contains("private-message-contents"));
        assert!(response.contains("payload=not_observed"));
    }

    #[test]
    fn relay_forwards_metadata_between_two_runtime_sessions() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "test-token").expect("valid config"))
                .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());
        let mut node_b = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));
        assert!(read_server_text(&mut node_b).contains("WELCOME"));

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Forward(Box::new(
                RelayForward::new("node.b", "env.1", 42).expect("forward"),
            ))),
        );
        let delivered = read_server_text(&mut node_b);
        let sent = read_server_text(&mut node_a);

        assert!(
            delivered
                .contains("ENVELOPE from=node.a to=node.b envelope=env.1 kind=message bytes=42")
        );
        assert!(delivered.contains("payload=opaque"));
        assert!(sent.contains("SENT to=node.b envelope=env.1 bytes=42"));
        assert!(!delivered.contains("private message contents"));
        assert!(!sent.contains("private message contents"));
    }

    #[test]
    fn relay_mailboxes_peer_encrypted_envelope_until_target_connects() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "test-token").expect("valid config"))
                .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));

        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.offline.1")),
        );
        let accepted = read_server_text(&mut node_a);

        assert!(accepted.contains("SENT to=node.b envelope=env.offline.1 bytes=22"));
        assert!(!accepted.contains("private message contents"));

        let mut node_b = connect_client(relay.local_addr());
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_b).contains("WELCOME"));
        let delivered = read_server_text(&mut node_b);

        assert!(delivered.contains(
            "ENVELOPE from=node.a to=node.b envelope=env.offline.1 kind=message bytes=22"
        ));
        assert!(delivered.contains("from_agent=agent.a"));
        assert!(delivered.contains("to_agent=agent.b"));
        assert!(delivered.contains("payload=peer_encrypted"));
        assert!(!delivered.contains("private message contents"));
    }

    #[test]
    fn relay_offline_mailbox_is_bounded_without_echoing_payloads() {
        let mailbox_policy =
            RelayMailboxPolicy::new(1, Duration::from_secs(60)).expect("valid mailbox policy");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_mailbox_policy(mailbox_policy),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));

        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.offline.1")),
        );
        assert!(read_server_text(&mut node_a).contains("SENT"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.offline.2")),
        );
        let rejected = read_server_text(&mut node_a);

        assert!(rejected.contains("UNDELIVERED to=node.b envelope=env.offline.2"));
        assert!(rejected.contains("reason=mailbox_full"));
        assert!(!rejected.contains("private message contents"));
    }

    #[test]
    fn relay_offline_mailbox_prunes_expired_envelopes_without_payloads() {
        let mailbox_policy =
            RelayMailboxPolicy::new(4, Duration::from_millis(10)).expect("valid mailbox policy");
        let mut state = RelayHubState::default();
        let forwarded = forwarded_from_client_frame(
            "node.a",
            encrypted_forward_frame("node.b", "env.expired.1"),
        );
        let storage = RelayMailboxStorage::memory_only();

        state
            .enqueue_mailbox("node.b", forwarded, mailbox_policy, &storage)
            .expect("mailbox accepts encrypted envelope");
        thread::sleep(Duration::from_millis(30));
        let drained = state
            .drain_mailbox("node.b", mailbox_policy, &storage)
            .expect("mailbox drains");

        assert!(drained.is_empty());
        assert!(!format!("{state:?}").contains("private message contents"));
    }

    #[test]
    fn relay_file_backed_mailbox_survives_relay_restart_without_payloads() {
        let mailbox_dir = test_home("durable-mailbox").join("relay-mailbox");
        let storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("storage config");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_mailbox_storage(storage.clone()),
        )
        .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));
        write_client_text(
            &mut node_a,
            &render_client_frame(&encrypted_forward_frame("node.b", "env.durable.1")),
        );
        let accepted = read_server_text(&mut node_a);
        let stored = read_mailbox_texts(&mailbox_dir);

        assert!(accepted.contains("SENT to=node.b envelope=env.durable.1 bytes=22"));
        assert!(
            stored
                .iter()
                .any(|contents| contents.contains("payload=peer_encrypted"))
        );
        assert!(!stored.join("\n").contains("private message contents"));

        drop(node_a);
        drop(relay);

        let restarted = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_mailbox_storage(storage),
        )
        .expect("relay restarts");
        let mut node_b = connect_client(restarted.local_addr());
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_b).contains("WELCOME"));
        let delivered = read_server_text(&mut node_b);

        assert!(delivered.contains(
            "ENVELOPE from=node.a to=node.b envelope=env.durable.1 kind=message bytes=22"
        ));
        assert!(read_mailbox_texts(&mailbox_dir).is_empty());
        assert!(!delivered.contains("private message contents"));
    }

    #[test]
    fn relay_file_backed_mailbox_load_respects_current_cap_without_payloads() {
        let mailbox_dir = test_home("durable-mailbox-cap").join("relay-mailbox");
        let storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("storage config");
        let original_policy =
            RelayMailboxPolicy::new(3, Duration::from_secs(60)).expect("valid mailbox policy");
        let current_policy =
            RelayMailboxPolicy::new(1, Duration::from_secs(60)).expect("valid mailbox policy");
        let mut state = RelayHubState::default();

        for envelope_id in ["env.cap.1", "env.cap.2", "env.cap.3"] {
            let forwarded = forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", envelope_id),
            );
            state
                .enqueue_mailbox("node.b", forwarded, original_policy, &storage)
                .expect("mailbox accepts encrypted envelope");
        }
        assert_eq!(read_mailbox_texts(&mailbox_dir).len(), 3);

        let mut loaded =
            RelayHubState::load(&storage, current_policy).expect("file mailbox loads with cap");
        assert_eq!(read_mailbox_texts(&mailbox_dir).len(), 1);

        let drained = loaded
            .drain_mailbox("node.b", current_policy, &storage)
            .expect("mailbox drains");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].envelope_id, "env.cap.1");
        assert!(read_mailbox_texts(&mailbox_dir).is_empty());
        assert!(!format!("{loaded:?}").contains("private message contents"));
    }

    #[test]
    fn relay_file_backed_mailbox_audit_reports_retention_metadata_only() {
        let mailbox_dir = test_home("durable-mailbox-audit").join("relay-mailbox");
        let storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("storage config");
        let mailbox_policy =
            RelayMailboxPolicy::new(4, Duration::from_secs(60)).expect("valid mailbox policy");
        let mut state = RelayHubState::default();

        for (node_id, envelope_id) in [
            ("node.b", "env.mailbox.audit.1"),
            ("node.c", "env.mailbox.audit.2"),
        ] {
            let forwarded = forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame(node_id, envelope_id),
            );
            state
                .enqueue_mailbox(node_id, forwarded, mailbox_policy, &storage)
                .expect("mailbox accepts encrypted envelope");
        }

        let invalid_dir = mailbox_dir.join("node.invalid");
        fs::create_dir_all(&invalid_dir).expect("invalid mailbox dir");
        fs::write(
            invalid_dir.join("invalid.mailbox"),
            "version = \"1\"\nqueued_at_millis = invalid\nframe = ENVELOPE from=node.a body_ciphertext=ciphertext_body\npayload_displayed = false\n",
        )
        .expect("invalid mailbox fixture");
        thread::sleep(Duration::from_millis(10));

        let audit = audit_relay_mailbox_dir(&mailbox_dir, None, Some(Duration::from_millis(1)))
            .expect("mailbox audit reads");
        assert_eq!(audit.nodes, 3);
        assert_eq!(audit.records, 3);
        assert_eq!(audit.invalid_records, 1);
        assert!(audit.bytes > 0);
        assert!(audit.oldest_queued_unix_millis.is_some());
        assert!(audit.newest_queued_unix_millis.is_some());
        assert_eq!(audit.expired_records, Some(2));
        assert!(audit.expired_bytes.unwrap_or_default() > 0);
        assert!(!audit.payload_displayed);
        assert!(!audit.token_displayed);
        assert!(!audit.token_hash_displayed);
        assert!(!audit.key_material_displayed);
        assert!(!audit.session_id_displayed);
        assert!(!audit.ciphertext_displayed);
        assert!(!audit.contents_displayed);

        let node_audit =
            audit_relay_mailbox_dir(&mailbox_dir, Some("node.b"), Some(Duration::from_millis(1)))
                .expect("node mailbox audit reads");
        assert_eq!(node_audit.nodes, 1);
        assert_eq!(node_audit.records, 1);
        assert_eq!(node_audit.invalid_records, 0);

        let debug = format!("{audit:?}");
        assert!(!debug.contains("private message contents"));
        assert!(!debug.contains("ciphertext_body"));
        assert!(!debug.contains("ENVELOPE from=node.a"));
        assert!(!debug.contains("relay_node.hosted_123456789"));
        assert!(!debug.contains("token_sha256_hex"));
    }

    #[test]
    fn relay_metadata_duplicate_keys_fail_closed_without_payloads() {
        let home = test_home("relay-metadata-duplicate-keys");
        let now_millis = current_unix_millis();
        let now_unix = current_unix_seconds();
        let secret_marker = "private message contents";

        let mailbox_dir = home.join("relay-mailbox");
        let mailbox_node_dir = mailbox_dir.join("node.b");
        fs::create_dir_all(&mailbox_node_dir).expect("mailbox node dir");
        let mailbox_entry = QueuedRelayEnvelope {
            queued_at_millis: now_millis,
            queued_at_nanos: now_millis.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", "env.duplicate.mailbox"),
            ),
        };
        let mailbox_path = mailbox_node_dir.join("duplicate.mailbox");
        fs::write(
            &mailbox_path,
            render_mailbox_file(&mailbox_entry)
                + "payload_displayed = true\nsecret_payload = \"private message contents\"\n",
        )
        .expect("duplicate mailbox writes");

        let mailbox_audit =
            audit_relay_mailbox_dir(&mailbox_dir, None, None).expect("mailbox audit reads");
        assert_eq!(mailbox_audit.records, 1);
        assert_eq!(mailbox_audit.invalid_records, 1);
        assert!(mailbox_audit.oldest_queued_unix_millis.is_none());
        assert!(!format!("{mailbox_audit:?}").contains(secret_marker));

        let mailbox_storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("mailbox storage");
        let mailbox_policy =
            RelayMailboxPolicy::new(4, Duration::from_secs(60)).expect("mailbox policy");
        let mut loaded_mailbox =
            RelayHubState::load(&mailbox_storage, mailbox_policy).expect("mailbox loads");
        let drained = loaded_mailbox
            .drain_mailbox("node.b", mailbox_policy, &mailbox_storage)
            .expect("mailbox drains");
        assert!(drained.is_empty());
        assert!(!mailbox_path.exists());

        let session_dir = home.join("sessions");
        fs::create_dir_all(&session_dir).expect("session dir");
        let session_record = RelaySessionRecord::new(
            "node.a",
            &session_id("node.a"),
            now_millis.min(u64::MAX as u128) as u64,
            RelaySessionPolicy::default(),
        );
        let session_path = relay_session_record_path(&session_dir, "node.a");
        fs::write(
            &session_path,
            render_session_file(&session_record)
                + "contents_displayed = true\nsecret_payload = \"private session\"\n",
        )
        .expect("duplicate session writes");

        let session_audit =
            audit_relay_session_state_dir(&session_dir, None).expect("session audit reads");
        assert_eq!(session_audit.records, 0);
        assert_eq!(session_audit.invalid_records, 1);
        assert!(!format!("{session_audit:?}").contains(secret_marker));
        let loaded_sessions = RelaySessionState::load(
            &RelaySessionStorage::file_backed(session_dir).expect("session storage"),
            RelaySessionPolicy::default(),
        )
        .expect("session state loads around duplicate record");
        assert!(loaded_sessions.records.is_empty());
        assert!(!session_path.exists());

        let accounting_dir = home.join("accounting");
        fs::create_dir_all(&accounting_dir).expect("accounting dir");
        let mut accounting_record = RelayAccountingRecord::new("node.a", now_unix);
        accounting_record.sessions_authenticated = 1;
        fs::write(
            accounting_dir.join("node.a.accounting"),
            render_accounting_file(&accounting_record)
                + "sessions_authenticated = 2\nsecret_payload = \"private accounting\"\n",
        )
        .expect("duplicate accounting writes");
        let accounting_error = audit_relay_accounting_dir(&accounting_dir, None)
            .expect_err("duplicate accounting key fails closed");
        assert!(
            accounting_error
                .to_string()
                .contains("relay accounting entry is invalid")
        );
        assert!(!accounting_error.to_string().contains(secret_marker));
        assert!(!accounting_error.to_string().contains("private accounting"));

        let abuse_dir = home.join("abuse");
        fs::create_dir_all(&abuse_dir).expect("abuse dir");
        let mut abuse_record = RelayAbuseRecord::new(Some("node.a".to_string()), now_unix);
        abuse_record.record(RelayAbuseKind::RateLimitedSession);
        fs::write(
            abuse_dir.join("node-node.a.abuse"),
            render_abuse_file(&abuse_record)
                + "rate_limited_sessions = 2\nsecret_payload = \"private abuse\"\n",
        )
        .expect("duplicate abuse writes");
        let abuse_error =
            audit_relay_abuse_dir(&abuse_dir, None).expect_err("duplicate abuse key fails closed");
        assert!(
            abuse_error
                .to_string()
                .contains("relay abuse entry is invalid")
        );
        assert!(!abuse_error.to_string().contains(secret_marker));
        assert!(!abuse_error.to_string().contains("private abuse"));
    }

    #[cfg(unix)]
    #[test]
    fn relay_metadata_reads_reject_symlinks_without_reading_targets() {
        use std::os::unix::fs::symlink;

        let home = test_home("relay-metadata-read-symlink");
        let now_millis = current_unix_millis();
        let now_unix = current_unix_seconds();

        let mailbox_dir = home.join("relay-mailbox");
        let mailbox_node_dir = mailbox_dir.join("node.b");
        fs::create_dir_all(&mailbox_node_dir).expect("mailbox node dir");
        let mailbox_entry = QueuedRelayEnvelope {
            queued_at_millis: now_millis,
            queued_at_nanos: now_millis.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", "env.symlink.mailbox"),
            ),
        };
        let mailbox_target = home.join("outside.mailbox");
        let mailbox_target_contents =
            render_mailbox_file(&mailbox_entry) + "secret_payload = \"private message contents\"\n";
        fs::write(&mailbox_target, &mailbox_target_contents).expect("mailbox target writes");
        let mailbox_link = mailbox_node_dir.join("linked.mailbox");
        symlink(&mailbox_target, &mailbox_link).expect("mailbox symlink creates");

        let mailbox_audit =
            audit_relay_mailbox_dir(&mailbox_dir, None, None).expect("mailbox audit reads");
        assert_eq!(mailbox_audit.records, 1);
        assert_eq!(mailbox_audit.invalid_records, 1);
        assert!(mailbox_audit.oldest_queued_unix_millis.is_none());
        assert!(mailbox_audit.newest_queued_unix_millis.is_none());

        let storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("mailbox storage");
        let mailbox_policy =
            RelayMailboxPolicy::new(4, Duration::from_secs(60)).expect("mailbox policy");
        let mut loaded = RelayHubState::load(&storage, mailbox_policy).expect("mailbox loads");
        let drained = loaded
            .drain_mailbox("node.b", mailbox_policy, &storage)
            .expect("mailbox drains");
        assert!(drained.is_empty());
        assert!(fs::symlink_metadata(&mailbox_link).is_err());
        assert_eq!(
            fs::read_to_string(&mailbox_target).expect("mailbox target reads"),
            mailbox_target_contents
        );

        let session_dir = home.join("sessions");
        fs::create_dir_all(&session_dir).expect("session dir");
        let session_record = RelaySessionRecord::new(
            "node.a",
            &session_id("node.a"),
            now_millis.min(u64::MAX as u128) as u64,
            RelaySessionPolicy::default(),
        );
        let session_target = home.join("outside.session");
        let session_target_contents =
            render_session_file(&session_record) + "secret_payload = \"private session\"\n";
        fs::write(&session_target, &session_target_contents).expect("session target writes");
        let session_link = session_dir.join("node.a.session");
        symlink(&session_target, &session_link).expect("session symlink creates");
        let session_audit =
            audit_relay_session_state_dir(&session_dir, None).expect("session audit reads");
        assert_eq!(session_audit.records, 0);
        assert_eq!(session_audit.invalid_records, 1);
        assert_eq!(
            fs::read_to_string(&session_target).expect("session target reads"),
            session_target_contents
        );
        assert!(
            fs::symlink_metadata(&session_link)
                .expect("session symlink metadata")
                .file_type()
                .is_symlink()
        );

        let accounting_dir = home.join("accounting");
        fs::create_dir_all(&accounting_dir).expect("accounting dir");
        let mut accounting_record = RelayAccountingRecord::new("node.a", now_unix);
        accounting_record.sessions_authenticated = 7;
        let accounting_target = home.join("outside.accounting");
        let accounting_target_contents = render_accounting_file(&accounting_record)
            + "secret_payload = \"private accounting\"\n";
        fs::write(&accounting_target, &accounting_target_contents)
            .expect("accounting target writes");
        let accounting_link = accounting_dir.join("node.a.accounting");
        symlink(&accounting_target, &accounting_link).expect("accounting symlink creates");
        let accounting_audit =
            audit_relay_accounting_dir(&accounting_dir, None).expect("accounting audit reads");
        assert_eq!(accounting_audit.records, 0);
        assert_eq!(accounting_audit.sessions_authenticated, 0);
        assert_eq!(
            fs::read_to_string(&accounting_target).expect("accounting target reads"),
            accounting_target_contents
        );

        let abuse_dir = home.join("abuse");
        fs::create_dir_all(&abuse_dir).expect("abuse dir");
        let mut abuse_record = RelayAbuseRecord::new(Some("node.a".to_string()), now_unix);
        abuse_record.record(RelayAbuseKind::RateLimitedSession);
        let abuse_target = home.join("outside.abuse");
        let abuse_target_contents =
            render_abuse_file(&abuse_record) + "secret_payload = \"private abuse\"\n";
        fs::write(&abuse_target, &abuse_target_contents).expect("abuse target writes");
        let abuse_link = abuse_dir.join("node-node.a.abuse");
        symlink(&abuse_target, &abuse_link).expect("abuse symlink creates");
        let abuse_audit = audit_relay_abuse_dir(&abuse_dir, None).expect("abuse audit reads");
        assert_eq!(abuse_audit.records, 0);
        assert_eq!(abuse_audit.rate_limited_sessions, 0);
        assert_eq!(
            fs::read_to_string(&abuse_target).expect("abuse target reads"),
            abuse_target_contents
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_metadata_writes_reject_symlinks_without_replacing_targets() {
        use std::os::unix::fs::symlink;

        let home = test_home("relay-metadata-write-symlink");
        let now_millis = current_unix_millis();
        let now_unix = current_unix_seconds();

        let session_dir = home.join("sessions");
        fs::create_dir_all(&session_dir).expect("session dir creates");
        let session_record = RelaySessionRecord::new(
            "node.a",
            &session_id("node.a"),
            now_millis.min(u64::MAX as u128) as u64,
            RelaySessionPolicy::default(),
        );
        let session_target = home.join("outside.session");
        let session_target_contents = "existing session target\n";
        fs::write(&session_target, session_target_contents).expect("session target writes");
        let session_link = session_dir.join("node.a.session");
        symlink(&session_target, &session_link).expect("session symlink creates");
        let session_storage =
            RelaySessionStorage::file_backed(session_dir).expect("session storage");

        let session_error = persist_session_record(&session_storage, &session_record)
            .expect_err("symlinked session write fails closed");

        assert!(session_error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&session_target).expect("session target reads"),
            session_target_contents
        );
        assert!(
            fs::symlink_metadata(&session_link)
                .expect("session link metadata")
                .file_type()
                .is_symlink()
        );

        let accounting_dir = home.join("accounting");
        fs::create_dir_all(&accounting_dir).expect("accounting dir creates");
        let mut accounting_record = RelayAccountingRecord::new("node.a", now_unix);
        accounting_record.sessions_authenticated = 3;
        let accounting_target = home.join("outside.accounting");
        let accounting_target_contents = "existing accounting target\n";
        fs::write(&accounting_target, accounting_target_contents)
            .expect("accounting target writes");
        let accounting_link = accounting_dir.join("node.a.accounting");
        symlink(&accounting_target, &accounting_link).expect("accounting symlink creates");
        let accounting_storage =
            RelayAccountingStorage::file_backed(accounting_dir).expect("accounting storage");

        let accounting_error = persist_accounting_record(&accounting_storage, &accounting_record)
            .expect_err("symlinked accounting write fails closed");

        assert!(accounting_error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&accounting_target).expect("accounting target reads"),
            accounting_target_contents
        );
        assert!(
            fs::symlink_metadata(&accounting_link)
                .expect("accounting link metadata")
                .file_type()
                .is_symlink()
        );

        let abuse_dir = home.join("abuse");
        fs::create_dir_all(&abuse_dir).expect("abuse dir creates");
        let mut abuse_record = RelayAbuseRecord::new(Some("node.a".to_string()), now_unix);
        abuse_record.record(RelayAbuseKind::RateLimitedSession);
        let abuse_target = home.join("outside.abuse");
        let abuse_target_contents = "existing abuse target\n";
        fs::write(&abuse_target, abuse_target_contents).expect("abuse target writes");
        let abuse_link = abuse_dir.join("node-node.a.abuse");
        symlink(&abuse_target, &abuse_link).expect("abuse symlink creates");
        let abuse_storage = RelayAbuseStorage::file_backed(abuse_dir).expect("abuse storage");

        let abuse_error = persist_abuse_record(&abuse_storage, &abuse_record)
            .expect_err("symlinked abuse write fails closed");

        assert!(abuse_error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&abuse_target).expect("abuse target reads"),
            abuse_target_contents
        );
        assert!(
            fs::symlink_metadata(&abuse_link)
                .expect("abuse link metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_metadata_writes_reject_symlinked_storage_directory() {
        use std::os::unix::fs::symlink;

        let home = test_home("relay-metadata-write-dir-symlink");
        let outside = home.join("outside-sessions");
        let session_dir = home.join("sessions");
        fs::create_dir_all(&outside).expect("outside dir creates");
        symlink(&outside, &session_dir).expect("session dir symlink creates");
        let session_record = RelaySessionRecord::new(
            "node.a",
            &session_id("node.a"),
            current_unix_millis().min(u64::MAX as u128) as u64,
            RelaySessionPolicy::default(),
        );
        let session_storage =
            RelaySessionStorage::file_backed(session_dir.clone()).expect("session storage");

        let error = persist_session_record(&session_storage, &session_record)
            .expect_err("symlinked storage directory fails closed");

        assert!(error.to_string().contains("not a directory"));
        assert_eq!(
            fs::read_dir(&outside).expect("outside dir reads").count(),
            0
        );
        assert!(
            fs::symlink_metadata(&session_dir)
                .expect("session dir link metadata")
                .file_type()
                .is_symlink()
        );

        let session_audit_error = audit_relay_session_state_dir(&session_dir, None)
            .expect_err("symlinked session audit directory fails closed");
        assert!(session_audit_error.to_string().contains("not a directory"));

        let accounting_outside = home.join("outside-accounting");
        let accounting_dir = home.join("accounting");
        fs::create_dir_all(&accounting_outside).expect("outside accounting dir creates");
        symlink(&accounting_outside, &accounting_dir).expect("accounting dir symlink creates");
        let accounting_storage = RelayAccountingStorage::file_backed(accounting_dir.clone())
            .expect("accounting storage");

        let accounting_load_error =
            RelayAccountingState::load(&accounting_storage, RelayAccountingPolicy::default())
                .expect_err("symlinked accounting load directory fails closed");
        let accounting_audit_error = audit_relay_accounting_dir(&accounting_dir, None)
            .expect_err("symlinked accounting audit directory fails closed");

        assert!(
            accounting_load_error
                .to_string()
                .contains("not a directory")
        );
        assert!(
            accounting_audit_error
                .to_string()
                .contains("not a directory")
        );
        assert_eq!(
            fs::read_dir(&accounting_outside)
                .expect("outside accounting dir reads")
                .count(),
            0
        );

        let abuse_outside = home.join("outside-abuse");
        let abuse_dir = home.join("abuse");
        fs::create_dir_all(&abuse_outside).expect("outside abuse dir creates");
        symlink(&abuse_outside, &abuse_dir).expect("abuse dir symlink creates");
        let abuse_storage =
            RelayAbuseStorage::file_backed(abuse_dir.clone()).expect("abuse storage");

        let abuse_load_error = RelayAbuseState::load(&abuse_storage, RelayAbusePolicy::default())
            .expect_err("symlinked abuse load directory fails closed");
        let abuse_audit_error = audit_relay_abuse_dir(&abuse_dir, None)
            .expect_err("symlinked abuse audit directory fails closed");
        let abuse_purge_error =
            purge_abuse_storage(&abuse_storage).expect_err("symlinked abuse purge fails closed");

        assert!(abuse_load_error.to_string().contains("not a directory"));
        assert!(abuse_audit_error.to_string().contains("not a directory"));
        assert!(abuse_purge_error.to_string().contains("not a directory"));
        assert_eq!(
            fs::read_dir(&abuse_outside)
                .expect("outside abuse dir reads")
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_mailbox_writes_reject_symlinked_storage_directories() {
        use std::os::unix::fs::symlink;

        let home = test_home("relay-mailbox-write-dir-symlink");
        let mailbox_policy =
            RelayMailboxPolicy::new(4, Duration::from_secs(60)).expect("mailbox policy");

        let outside_root = home.join("outside-root");
        let mailbox_root = home.join("relay-mailbox-root");
        fs::create_dir_all(&outside_root).expect("outside root creates");
        symlink(&outside_root, &mailbox_root).expect("mailbox root symlink creates");
        let root_storage =
            RelayMailboxStorage::file_backed(mailbox_root.clone()).expect("mailbox storage");

        let load_error = RelayHubState::load(&root_storage, mailbox_policy)
            .expect_err("symlinked mailbox root fails closed");

        assert!(load_error.to_string().contains("not a directory"));
        assert_eq!(
            fs::read_dir(&outside_root)
                .expect("outside root reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&mailbox_root)
                .expect("mailbox root link metadata")
                .file_type()
                .is_symlink()
        );

        let mailbox_dir = home.join("relay-mailbox");
        let outside_node = home.join("outside-node");
        let mailbox_node_dir = mailbox_dir.join("node.b");
        fs::create_dir_all(&mailbox_dir).expect("mailbox dir creates");
        fs::create_dir_all(&outside_node).expect("outside node creates");
        symlink(&outside_node, &mailbox_node_dir).expect("mailbox node symlink creates");
        let node_storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("mailbox storage");
        let forwarded =
            forwarded_from_client_frame("node.a", encrypted_forward_frame("node.b", "env.node"));
        let mut state = RelayHubState::default();

        let enqueue_error = state
            .enqueue_mailbox("node.b", forwarded, mailbox_policy, &node_storage)
            .expect_err("symlinked mailbox node dir fails closed");

        assert_eq!(enqueue_error, "mailbox_unavailable");
        assert_eq!(
            fs::read_dir(&outside_node)
                .expect("outside node reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&mailbox_node_dir)
                .expect("mailbox node link metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_mailbox_admin_paths_reject_symlinked_node_directory() {
        use std::os::unix::fs::symlink;

        let home = test_home("relay-mailbox-admin-dir-symlink");
        let mailbox_dir = home.join("relay-mailbox");
        let outside_node = home.join("outside-node");
        let mailbox_node_dir = mailbox_dir.join("node.b");
        fs::create_dir_all(&mailbox_dir).expect("mailbox dir creates");
        fs::create_dir_all(&outside_node).expect("outside node creates");
        symlink(&outside_node, &mailbox_node_dir).expect("mailbox node symlink creates");

        let audit_error = audit_relay_mailbox_dir(&mailbox_dir, Some("node.b"), None)
            .expect_err("symlinked mailbox audit node dir fails closed");
        let purge_error =
            purge_relay_mailbox_dir(&mailbox_dir, Some("node.b"), Duration::from_secs(1), true)
                .expect_err("symlinked mailbox purge node dir fails closed");

        assert!(audit_error.to_string().contains("not a directory"));
        assert!(purge_error.to_string().contains("not a directory"));
        assert_eq!(
            fs::read_dir(&outside_node)
                .expect("outside node reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&mailbox_node_dir)
                .expect("mailbox node link metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn relay_mailbox_purge_requires_confirm_and_keeps_output_metadata_only() {
        let mailbox_dir = test_home("durable-mailbox-purge").join("relay-mailbox");
        let node_dir = mailbox_dir.join("node.b");
        fs::create_dir_all(&node_dir).expect("mailbox node dir");
        let now = current_unix_millis();
        let expired_queued_at = now.saturating_sub(10_000);
        let fresh_queued_at = now.saturating_add(60_000);

        let expired = QueuedRelayEnvelope {
            queued_at_millis: expired_queued_at,
            queued_at_nanos: expired_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", "env.purge.expired"),
            ),
        };
        let fresh = QueuedRelayEnvelope {
            queued_at_millis: fresh_queued_at,
            queued_at_nanos: fresh_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", "env.purge.fresh"),
            ),
        };
        let expired_path = node_dir.join("expired.mailbox");
        let fresh_path = node_dir.join("fresh.mailbox");
        let invalid_path = node_dir.join("invalid.mailbox");
        let display_guard_path = node_dir.join("display-guard.mailbox");
        fs::write(&expired_path, render_mailbox_file(&expired)).expect("expired mailbox file");
        fs::write(&fresh_path, render_mailbox_file(&fresh)).expect("fresh mailbox file");
        fs::write(
            &invalid_path,
            "version = \"1\"\nqueued_at_millis = invalid\nframe = ENVELOPE from=node.a body_ciphertext=ciphertext_body\npayload_displayed = false\n",
        )
        .expect("invalid mailbox file");
        fs::write(
            &display_guard_path,
            render_mailbox_file(&expired)
                .replace("payload_displayed = false", "payload_displayed = true"),
        )
        .expect("display guard mailbox file");

        let dry_run =
            purge_relay_mailbox_dir(&mailbox_dir, Some("node.b"), Duration::from_secs(1), true)
                .expect("dry-run purge reports");
        assert!(dry_run.dry_run);
        assert!(!dry_run.confirmed);
        assert_eq!(dry_run.nodes, 1);
        assert_eq!(dry_run.records, 4);
        assert_eq!(dry_run.invalid_records, 2);
        assert_eq!(dry_run.expired_records, 1);
        assert_eq!(dry_run.purged_records, 0);
        assert!(expired_path.exists());
        assert!(fresh_path.exists());
        assert!(invalid_path.exists());
        assert!(display_guard_path.exists());

        let confirmed =
            purge_relay_mailbox_dir(&mailbox_dir, Some("node.b"), Duration::from_secs(1), false)
                .expect("confirmed purge removes expired mailbox");
        assert!(!confirmed.dry_run);
        assert!(confirmed.confirmed);
        assert_eq!(confirmed.records, 4);
        assert_eq!(confirmed.invalid_records, 2);
        assert_eq!(confirmed.expired_records, 1);
        assert_eq!(confirmed.purged_records, 1);
        assert!(confirmed.purged_bytes > 0);
        assert!(!expired_path.exists());
        assert!(fresh_path.exists());
        assert!(invalid_path.exists());
        assert!(display_guard_path.exists());
        assert!(!confirmed.payload_displayed);
        assert!(!confirmed.token_displayed);
        assert!(!confirmed.token_hash_displayed);
        assert!(!confirmed.key_material_displayed);
        assert!(!confirmed.session_id_displayed);
        assert!(!confirmed.ciphertext_displayed);
        assert!(!confirmed.contents_displayed);

        let debug = format!("{confirmed:?}");
        assert!(!debug.contains("private message contents"));
        assert!(!debug.contains("ciphertext_body"));
        assert!(!debug.contains("ENVELOPE from=node.a"));
        assert!(!debug.contains("relay_node.hosted_123456789"));
        assert!(!debug.contains("token_sha256_hex"));
    }

    #[test]
    fn relay_mailbox_scheduled_purge_removes_expired_valid_files_only() {
        let mailbox_dir = test_home("durable-mailbox-scheduled-purge").join("relay-mailbox");
        let storage =
            RelayMailboxStorage::file_backed(mailbox_dir.clone()).expect("mailbox storage");
        let mailbox_policy =
            RelayMailboxPolicy::new(8, Duration::from_secs(60)).expect("mailbox policy");
        let maintenance = RelayMailboxMaintenancePolicy::every(Duration::from_millis(50))
            .expect("maintenance policy");
        let _relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_mailbox_policy(mailbox_policy)
                .with_mailbox_storage(storage)
                .with_mailbox_maintenance(maintenance),
        )
        .expect("relay starts");

        let node_dir = mailbox_dir.join("node.b");
        fs::create_dir_all(&node_dir).expect("mailbox node dir");
        let now = current_unix_millis();
        let expired_queued_at = now.saturating_sub(120_000);
        let fresh_queued_at = now.saturating_add(60_000);
        let expired = QueuedRelayEnvelope {
            queued_at_millis: expired_queued_at,
            queued_at_nanos: expired_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", "env.scheduled.expired"),
            ),
        };
        let fresh = QueuedRelayEnvelope {
            queued_at_millis: fresh_queued_at,
            queued_at_nanos: fresh_queued_at.saturating_mul(1_000_000),
            storage_path: None,
            forwarded: forwarded_from_client_frame(
                "node.a",
                encrypted_forward_frame("node.b", "env.scheduled.fresh"),
            ),
        };
        let expired_path = node_dir.join("expired.mailbox");
        let fresh_path = node_dir.join("fresh.mailbox");
        let invalid_path = node_dir.join("invalid.mailbox");
        let display_guard_path = node_dir.join("display-guard.mailbox");
        fs::write(&expired_path, render_mailbox_file(&expired)).expect("expired mailbox file");
        fs::write(&fresh_path, render_mailbox_file(&fresh)).expect("fresh mailbox file");
        fs::write(
            &invalid_path,
            "version = \"1\"\nqueued_at_millis = invalid\nframe = ENVELOPE from=node.a body_ciphertext=ciphertext_body\npayload_displayed = false\n",
        )
        .expect("invalid mailbox file");
        fs::write(
            &display_guard_path,
            render_mailbox_file(&expired)
                .replace("payload_displayed = false", "payload_displayed = true"),
        )
        .expect("display guard mailbox file");

        let deadline = Instant::now() + Duration::from_secs(2);
        while expired_path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }

        assert!(!expired_path.exists());
        assert!(fresh_path.exists());
        assert!(invalid_path.exists());
        assert!(display_guard_path.exists());

        let audit =
            audit_relay_mailbox_dir(&mailbox_dir, Some("node.b"), Some(Duration::from_secs(60)))
                .expect("mailbox audit reads");
        assert_eq!(audit.records, 3);
        assert_eq!(audit.invalid_records, 2);
        assert_eq!(audit.expired_records, Some(0));
        assert!(!audit.payload_displayed);
        assert!(!audit.ciphertext_displayed);
        assert!(!audit.contents_displayed);
    }

    #[test]
    fn relay_rejects_bad_token_without_echoing_token() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "test-token").expect("valid config"))
                .expect("relay starts");
        let mut client = connect_client(relay.local_addr());

        write_client_text(
            &mut client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.bad", "secret-bad-token").expect("hello"),
            )),
        );
        let response = read_server_text(&mut client);

        assert!(response.contains("ERROR reason=unauthorized"));
        assert!(!response.contains("secret-bad-token"));
    }

    #[test]
    fn relay_rate_limits_frames_without_echoing_payloads() {
        let limits = RelayLimits::new(10, 10, 2).expect("valid limits");
        let relay = spawn_relay(
            RelayConfig::new("127.0.0.1:0", "test-token")
                .expect("valid config")
                .with_limits(limits),
        )
        .expect("relay starts");
        let mut client = connect_client(relay.local_addr());

        write_client_text(
            &mut client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.limited", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut client).contains("WELCOME"));

        write_client_text(&mut client, &render_client_frame(&RelayClientFrame::Ping));
        assert!(read_server_text(&mut client).contains("PONG"));

        write_client_text(&mut client, "PING payload_text=private-message-contents");
        let response = read_server_text(&mut client);

        assert!(response.contains("ERROR reason=rate_limited"));
        assert!(!response.contains("private-message-contents"));
        assert!(response.contains("payload=not_observed"));
    }

    #[test]
    fn relay_delivers_peer_encrypted_message_between_two_state_homes() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("alice");
        let bob_home = test_home("bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let bob_node = node_id(&bob_home);
        let remote = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            bob_node,
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("remote message valid");
        relay_delivery::submit_remote_message(Some(alice_home.clone()), remote)
            .expect("remote message queues");

        let bob_home_for_thread = bob_home.clone();
        let bob_sync = thread::spawn(move || {
            relay_delivery::sync_relay_once(Some(bob_home_for_thread), Duration::from_millis(2_000))
                .expect("bob relay sync")
        });
        thread::sleep(Duration::from_millis(100));
        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home), Duration::from_millis(1_000))
                .expect("alice relay sync");
        let bob_report = bob_sync.join().expect("bob thread joins");
        let inbox = messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob")
            .expect("bob inbox reads");
        let received =
            messages::read_message_payload(Some(bob_home), "agent.bob", &inbox[0].envelope_id)
                .expect("bob payload reads");

        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(received.as_bytes(), b"private message contents");
    }

    #[test]
    fn relay_mailboxes_peer_encrypted_message_until_receiver_connects() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("mailbox-alice");
        let bob_home = test_home("mailbox-bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let bob_node = node_id(&bob_home);
        let remote = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            bob_node,
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("remote message valid");
        relay_delivery::submit_remote_message(Some(alice_home.clone()), remote)
            .expect("remote message queues");

        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home), Duration::from_millis(200))
                .expect("alice relay sync queues offline");
        let bob_report =
            relay_delivery::sync_relay_once(Some(bob_home.clone()), Duration::from_millis(1_000))
                .expect("bob relay sync receives mailbox");
        let inbox = messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob")
            .expect("bob inbox reads");
        let received =
            messages::read_message_payload(Some(bob_home), "agent.bob", &inbox[0].envelope_id)
                .expect("bob payload reads");

        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(received.as_bytes(), b"private message contents");
    }

    #[test]
    fn relay_delivers_peer_encrypted_stream_chunk_between_two_state_homes() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("stream-alice");
        let bob_home = test_home("stream-bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let bob_node = node_id(&bob_home);
        write_remote_agent(&alice_home, "agent.bob", &bob_node);

        let opened = streams::open_stream(
            Some(alice_home.clone()),
            "agent.alice",
            "agent.bob",
            "message",
        )
        .expect("remote stream opens");
        streams::write_stream(
            Some(alice_home.clone()),
            &opened.stream.stream_id,
            OpaquePayload::from_bytes(b"private stream chunk".to_vec()),
        )
        .expect("remote stream chunk queues");

        let bob_home_for_thread = bob_home.clone();
        let bob_sync = thread::spawn(move || {
            relay_delivery::sync_relay_once(Some(bob_home_for_thread), Duration::from_millis(2_000))
                .expect("bob relay sync")
        });
        thread::sleep(Duration::from_millis(100));
        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home), Duration::from_millis(1_000))
                .expect("alice relay sync");
        let bob_report = bob_sync.join().expect("bob thread joins");
        let inbox =
            wait_for_agent_inbox_count(bob_home.clone(), "agent.bob", 1, Duration::from_secs(2));
        let receipts = messages::list_receipts(Some(bob_home.clone())).expect("receipts read");
        let received =
            messages::read_message_payload(Some(bob_home), "agent.bob", &inbox[0].envelope_id)
                .expect("stream payload reads");

        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].kind, "stream_chunk");
        assert_eq!(
            inbox[0].stream_id.as_deref(),
            Some(opened.stream.stream_id.as_str())
        );
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].kind, "stream_chunk");
        assert_eq!(
            receipts[0].stream_id.as_deref(),
            Some(opened.stream.stream_id.as_str())
        );
        assert_eq!(received.as_bytes(), b"private stream chunk");
    }

    #[test]
    fn relay_delivers_peer_encrypted_room_event_between_two_state_homes() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("room-alice");
        let bob_home = test_home("room-bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let alice_node = node_id(&alice_home);
        let bob_node = node_id(&bob_home);
        write_remote_agent(&alice_home, "agent.bob", &bob_node);
        write_remote_agent(&bob_home, "agent.alice", &alice_node);

        rooms::create_room(
            Some(alice_home.clone()),
            "room.dev",
            "Dev Room",
            "agent.alice",
        )
        .expect("room creates");
        rooms::join_room(Some(alice_home.clone()), "room.dev", "agent.bob")
            .expect("remote agent joins");
        let published = rooms::publish_room_event(
            Some(alice_home.clone()),
            "room.dev",
            "agent.alice",
            "build",
            OpaquePayload::from_bytes(b"private room event".to_vec()),
        )
        .expect("room event publishes");

        let bob_home_for_thread = bob_home.clone();
        let bob_sync = thread::spawn(move || {
            relay_delivery::sync_relay_once(Some(bob_home_for_thread), Duration::from_millis(2_000))
                .expect("bob relay sync")
        });
        thread::sleep(Duration::from_millis(100));
        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home.clone()), Duration::from_millis(1_000))
                .expect("alice relay sync");
        let bob_report = bob_sync.join().expect("bob thread joins");
        let inbox =
            wait_for_agent_inbox_count(bob_home.clone(), "agent.bob", 1, Duration::from_secs(2));
        let room_events = rooms::list_room_events(Some(bob_home.clone())).expect("events read");
        let received = messages::read_message_payload(
            Some(bob_home.clone()),
            "agent.bob",
            &inbox[0].envelope_id,
        )
        .expect("room payload reads");
        let event_file =
            fs::read_to_string(state::StatePaths::from_home(bob_home).room_events).expect("events");

        assert_eq!(published.local_deliveries, 0);
        assert_eq!(published.remote_deliveries, 1);
        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].kind, "event");
        assert_eq!(room_events.len(), 1);
        assert_eq!(room_events[0].room_id, "room.dev");
        assert_eq!(room_events[0].topic, "build");
        assert_eq!(room_events[0].route, "room-relay");
        assert_eq!(received.as_bytes(), b"private room event");
        assert!(event_file.contains("payload_displayed = false"));
        assert!(!event_file.contains("private room event"));
    }

    #[test]
    fn relay_rejects_room_event_when_inbound_topic_policy_denies_sender() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("room-policy-alice");
        let bob_home = test_home("room-policy-bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let alice_node = node_id(&alice_home);
        let bob_node = node_id(&bob_home);
        write_remote_agent(&alice_home, "agent.bob", &bob_node);
        write_remote_agent(&bob_home, "agent.alice", &alice_node);

        rooms::create_room(
            Some(alice_home.clone()),
            "room.dev",
            "Dev Room",
            "agent.alice",
        )
        .expect("alice room creates");
        rooms::join_room(Some(alice_home.clone()), "room.dev", "agent.bob")
            .expect("bob remote joins alice room");
        rooms::create_room(Some(bob_home.clone()), "room.dev", "Dev Room", "agent.bob")
            .expect("bob room creates");
        rooms::join_room(Some(bob_home.clone()), "room.dev", "agent.alice")
            .expect("alice remote joins bob room");
        rooms::set_room_topic_policy(
            Some(bob_home.clone()),
            "room.dev",
            "agent.bob",
            "build",
            rooms::RoomTopicPolicyUpdate {
                publish: Some(false),
                subscribe: Some(true),
            },
        )
        .expect("bob subscribes to build but does not grant alice publish");
        rooms::publish_room_event(
            Some(alice_home.clone()),
            "room.dev",
            "agent.alice",
            "build",
            OpaquePayload::from_bytes(b"private room event".to_vec()),
        )
        .expect("alice room event queues");

        let bob_home_for_thread = bob_home.clone();
        let bob_sync = thread::spawn(move || {
            relay_delivery::sync_relay_once(Some(bob_home_for_thread), Duration::from_millis(2_000))
        });
        thread::sleep(Duration::from_millis(100));
        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home), Duration::from_millis(1_000))
                .expect("alice relay sync");
        let bob_result = bob_sync.join().expect("bob thread joins");
        let error = bob_result.expect_err("bob rejects denied room event");
        let inbox =
            messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob").expect("inbox reads");
        let events = rooms::list_room_events(Some(bob_home)).expect("room events read");
        let error_text = error.to_string();

        assert_eq!(alice_report.sent, 1);
        assert!(error_text.contains("not allowed to publish"));
        assert!(inbox.is_empty());
        assert!(events.is_empty());
        assert!(!error_text.contains("private room event"));
    }

    #[test]
    fn relay_exchanges_signed_agent_cards_during_session_sync() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("cards-alice");
        let bob_home = test_home("cards-bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");

        sessions::sync_remote_sessions(Some(alice_home.clone())).expect("alice sessions sync");
        sessions::sync_remote_sessions(Some(bob_home.clone())).expect("bob sessions sync");

        let bob_home_for_thread = bob_home.clone();
        let bob_sync = thread::spawn(move || {
            relay_delivery::sync_relay_once(Some(bob_home_for_thread), Duration::from_millis(2_000))
                .expect("bob relay sync")
        });
        thread::sleep(Duration::from_millis(100));
        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home.clone()), Duration::from_millis(1_000))
                .expect("alice relay sync");
        let bob_report = bob_sync.join().expect("bob thread joins");
        let alice_remote =
            sessions::list_remote_agents(Some(alice_home)).expect("alice remote agents read");
        let bob_remote =
            sessions::list_remote_agents(Some(bob_home)).expect("bob remote agents read");
        let debug = format!("{alice_remote:?}\n{bob_remote:?}");

        assert!(alice_report.received >= 1);
        assert!(bob_report.received >= 1);
        assert_eq!(
            alice_remote.len(),
            1,
            "alice_report={alice_report:?} bob_report={bob_report:?} remote={debug}"
        );
        assert_eq!(
            bob_remote.len(),
            1,
            "alice_report={alice_report:?} bob_report={bob_report:?} remote={debug}"
        );
        assert_eq!(
            alice_remote[0].agent_id, "agent.bob",
            "alice_report={alice_report:?} bob_report={bob_report:?} remote={debug}"
        );
        assert_eq!(
            bob_remote[0].agent_id, "agent.alice",
            "alice_report={alice_report:?} bob_report={bob_report:?} remote={debug}"
        );
        assert!(alice_remote[0].agent_card_signed());
        assert!(bob_remote[0].agent_card_signed());
        assert!(alice_remote[0].capabilities.streams);
        assert!(bob_remote[0].capabilities.streams);
        assert!(!debug.contains("private message contents"));
    }

    #[test]
    fn relay_runtime_pump_reuses_session_across_ticks() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("persistent-alice");
        let bob_home = test_home("persistent-bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");

        let alice_paths = state::StatePaths::from_home(alice_home.clone());
        let bob_paths = state::StatePaths::from_home(bob_home.clone());
        let alice_node = node_id(&alice_home);
        let bob_node = node_id(&bob_home);
        let mut alice_pump = RelayRuntimePump::new();
        let mut bob_pump = RelayRuntimePump::new();

        let idle = bob_pump
            .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(50))
            .expect("bob relay session opens");
        let first_session = bob_pump
            .session_id()
            .expect("bob session id exists")
            .to_string();

        assert!(idle.connected);
        assert_eq!(bob_pump.connected_endpoint(), Some(endpoint.as_str()));

        queue_remote_message(&alice_home, &bob_node, b"first private message");
        let alice_report = alice_pump
            .tick_from_paths(&alice_paths, &alice_node, Duration::from_millis(500))
            .expect("alice relay tick sends first");
        let bob_report = bob_pump
            .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(1_000))
            .expect("bob relay tick receives first");

        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(bob_pump.session_id(), Some(first_session.as_str()));

        queue_remote_message(&alice_home, &bob_node, b"second private message");
        let alice_report = alice_pump
            .tick_from_paths(&alice_paths, &alice_node, Duration::from_millis(500))
            .expect("alice relay tick sends second");
        let bob_report = bob_pump
            .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(1_000))
            .expect("bob relay tick receives second");
        let inbox =
            messages::list_agent_inbox(Some(bob_home), "agent.bob").expect("bob inbox reads");

        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(bob_pump.session_id(), Some(first_session.as_str()));
        assert_eq!(inbox.len(), 2);
    }

    #[test]
    fn relay_runtime_pump_resumes_session_after_disconnect() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let bob_home = test_home("persistent-resume-bob");
        prepare_home(&bob_home, &endpoint);
        register_agent(&bob_home, "agent.bob");

        let bob_paths = state::StatePaths::from_home(bob_home.clone());
        let bob_node = node_id(&bob_home);
        let mut bob_pump = RelayRuntimePump::new();

        let opened = bob_pump
            .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(50))
            .expect("bob relay session opens");
        let first_session = bob_pump
            .session_id()
            .expect("bob session id exists")
            .to_string();

        assert!(opened.connected);
        bob_pump.disconnect();
        assert_eq!(bob_pump.session_id(), None);
        thread::sleep(Duration::from_millis(100));

        let resumed = bob_pump
            .tick_from_paths(&bob_paths, &bob_node, Duration::from_millis(50))
            .expect("bob relay session resumes");
        let debug = format!("{bob_pump:?}");

        assert!(resumed.connected);
        assert_eq!(bob_pump.session_id(), Some(first_session.as_str()));
        assert!(!debug.contains(&first_session));
    }

    fn encrypted_forward_frame(to_node_id: &str, envelope_id: &str) -> RelayClientFrame {
        RelayClientFrame::Forward(Box::new(
            RelayForward::with_body(
                to_node_id,
                envelope_id,
                "agent.a",
                "agent.b",
                22,
                RelayOpaqueBody::new("xchacha20poly1305", "key.1", "aa", "bb", "cc").expect("body"),
            )
            .expect("forward"),
        ))
    }

    fn forwarded_from_client_frame(from_node_id: &str, frame: RelayClientFrame) -> RelayForwarded {
        let RelayClientFrame::Forward(forward) = frame else {
            unreachable!("test helper only accepts forward frames");
        };
        let forward = *forward;
        RelayForwarded {
            from_node_id: from_node_id.to_string(),
            to_node_id: forward.to_node_id,
            envelope_id: forward.envelope_id,
            kind: forward.kind,
            stream_id: forward.stream_id,
            payload_bytes: forward.payload_bytes,
            from_agent_id: forward.from_agent_id,
            to_agent_id: forward.to_agent_id,
            body: forward.body,
        }
    }

    fn read_mailbox_texts(root: &Path) -> Vec<String> {
        let mut contents = Vec::new();
        if !root.exists() {
            return contents;
        }
        for node_entry in fs::read_dir(root).expect("mailbox root reads") {
            let node_entry = node_entry.expect("node entry reads");
            if !node_entry.file_type().expect("node type reads").is_dir() {
                continue;
            }
            for entry in fs::read_dir(node_entry.path()).expect("node mailbox reads") {
                let path = entry.expect("mailbox entry reads").path();
                if path.extension().and_then(|value| value.to_str()) == Some("mailbox") {
                    contents.push(fs::read_to_string(path).expect("mailbox file reads"));
                }
            }
        }
        contents
    }

    fn read_accounting_texts(root: &Path) -> Vec<String> {
        let mut contents = Vec::new();
        if !root.exists() {
            return contents;
        }
        for entry in fs::read_dir(root).expect("accounting root reads") {
            let path = entry.expect("accounting entry reads").path();
            if path.extension().and_then(|value| value.to_str()) == Some("accounting") {
                contents.push(fs::read_to_string(path).expect("accounting file reads"));
            }
        }
        contents
    }

    fn read_session_texts(root: &Path) -> Vec<String> {
        let mut contents = Vec::new();
        if !root.exists() {
            return contents;
        }
        for entry in fs::read_dir(root).expect("session root reads") {
            let path = entry.expect("session entry reads").path();
            if path.extension().and_then(|value| value.to_str()) == Some("session") {
                contents.push(fs::read_to_string(path).expect("session file reads"));
            }
        }
        contents
    }

    fn read_abuse_texts(root: &Path) -> Vec<String> {
        let mut contents = Vec::new();
        if !root.exists() {
            return contents;
        }
        for entry in fs::read_dir(root).expect("abuse root reads") {
            let path = entry.expect("abuse entry reads").path();
            if path.extension().and_then(|value| value.to_str()) == Some("abuse") {
                contents.push(fs::read_to_string(path).expect("abuse file reads"));
            }
        }
        contents
    }

    fn credential_manifest_text(
        node_id: &str,
        token_sha256_hex: &str,
        token_length: usize,
        status: &str,
    ) -> String {
        format!(
            "version = \"1\"\n\n\
[[credential]]\n\
node_id = \"{node_id}\"\n\
token_sha256_hex = \"{token_sha256_hex}\"\n\
token_length = {token_length}\n\
status = \"{status}\"\n\
payload_displayed = false\n\
token_displayed = false\n"
        )
    }

    fn connect_client(addr: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(addr).expect("client connects");
        stream
            .set_read_timeout(Some(TEST_HANDSHAKE_READ_TIMEOUT))
            .expect("timeout set");
        let request = "GET /relay HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("handshake writes");
        let mut response = Vec::new();
        let mut buf = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut buf).expect("handshake reads");
            response.push(buf[0]);
        }
        let response = String::from_utf8(response).expect("handshake utf8");
        assert!(response.contains("101 Switching Protocols"));
        stream
            .set_read_timeout(Some(TEST_SERVER_FRAME_POLL))
            .expect("frame timeout set");
        stream
    }

    #[test]
    fn relay_health_check_returns_payload_safe_http_ok() {
        let relay = spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").unwrap())
            .expect("relay starts");
        let mut stream = TcpStream::connect(relay.local_addr()).expect("health client connects");
        stream
            .set_read_timeout(Some(TEST_HANDSHAKE_READ_TIMEOUT))
            .expect("timeout set");
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("health request writes");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("health response reads");
        let response = String::from_utf8(response).expect("health response utf8");
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("conu-relay ok payload=not_observed"));
        assert!(!response.contains("local-dev-token"));
        assert!(!response.contains("ciphertext"));
    }

    fn write_client_text(stream: &mut TcpStream, text: &str) {
        let mask = [1_u8, 2, 3, 4];
        let payload = text.as_bytes();
        let mut frame = Vec::new();
        frame.push(0x81);
        if payload.len() <= 125 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        stream.write_all(&frame).expect("client frame writes");
    }

    fn read_server_text(stream: &mut TcpStream) -> String {
        let deadline = Instant::now() + TEST_SERVER_FRAME_WAIT;
        loop {
            if let Some(frame) = read_text_frame(stream).expect("server frame reads") {
                return frame;
            }
            if Instant::now() >= deadline {
                panic!("server frame exists");
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn send_admin_text(addr: SocketAddr, request: RelayAdminRequest) -> String {
        let mut stream = connect_client(addr);
        write_client_text(
            &mut stream,
            &render_client_frame(&RelayClientFrame::Admin(Box::new(request))),
        );
        read_server_text(&mut stream)
    }

    fn prepare_home(home: &Path, endpoint: &str) {
        state::init_state(Some(home.to_path_buf())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.to_path_buf());
        fs::write(
            paths.config,
            format!("version = \"1\"\ndefault_relay = \"{endpoint}\"\n"),
        )
        .expect("config writes");
    }

    fn trust_each_other(alice_home: &Path, bob_home: &Path) {
        let alice = trust::export_peer_card(Some(alice_home.to_path_buf())).expect("alice card");
        let bob = trust::export_peer_card(Some(bob_home.to_path_buf())).expect("bob card");
        let alice_node = alice.node_id.clone();
        let bob_node = bob.node_id.clone();
        trust::trust_peer_card(Some(alice_home.to_path_buf()), bob).expect("alice trusts bob");
        trust::trust_peer_card(Some(bob_home.to_path_buf()), alice).expect("bob trusts alice");
        let relay_policy = policy::PeerPolicyUpdate {
            messages: Some(true),
            streams: Some(true),
            rooms: Some(true),
            files: Some(false),
            mailbox: Some(false),
        };
        policy::set_peer_policy(
            Some(alice_home.to_path_buf()),
            &bob_node,
            relay_policy.clone(),
        )
        .expect("alice grants relay policy");
        policy::set_peer_policy(Some(bob_home.to_path_buf()), &alice_node, relay_policy)
            .expect("bob grants relay policy");
    }

    fn register_agent(home: &Path, agent_id: &str) {
        let mut registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        registration.capabilities.streams = true;
        registration.capabilities.rooms = true;
        agents::submit_registration(Some(home.to_path_buf()), registration)
            .expect("registration submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("registration processes");
    }

    fn queue_remote_message(alice_home: &Path, bob_node: &str, bytes: &[u8]) {
        let remote = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            bob_node,
            OpaquePayload::from_bytes(bytes.to_vec()),
        )
        .expect("remote message valid");
        relay_delivery::submit_remote_message(Some(alice_home.to_path_buf()), remote)
            .expect("remote message queues");
    }

    fn wait_for_agent_inbox_count(
        home: PathBuf,
        agent_id: &str,
        count: usize,
        timeout: Duration,
    ) -> Vec<messages::InboxEntry> {
        let deadline = Instant::now() + timeout;
        loop {
            let inbox =
                messages::list_agent_inbox(Some(home.clone()), agent_id).expect("inbox reads");
            if inbox.len() >= count {
                return inbox;
            }
            if Instant::now() >= deadline {
                panic!(
                    "agent inbox did not reach expected metadata count: expected={count} actual={}",
                    inbox.len()
                );
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn write_remote_agent(home: &Path, agent_id: &str, peer_node_id: &str) {
        let paths = state::StatePaths::from_home(home.to_path_buf());
        fs::create_dir_all(&paths.agents_dir).expect("agents dir");
        fs::write(
            &paths.remote_agent_registry,
            format!(
                "# conU remote agent registry\nversion = \"1\"\n\n[[remote_agent]]\nagent_id = \"{agent_id}\"\ndisplay_name = \"Remote Agent\"\npeer_node_id = \"{peer_node_id}\"\nnode_id = \"{peer_node_id}\"\nkind = \"remote-agent\"\npresence = \"ready\"\nlast_seen_unix = {}\ncap_messages = true\ncap_streams = true\ncap_rooms = true\ncap_files = false\ncap_presence = true\npayload_displayed = false\n",
                current_unix_nanos()
            ),
        )
        .expect("remote agent writes");
    }

    fn node_id(home: &Path) -> String {
        state::read_state(Some(home.to_path_buf()))
            .expect("state reads")
            .node
            .expect("node exists")
            .node_id
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-relay-e2e-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }

    fn write_oversized_relay_manifest(path: &Path, secret: &str) {
        let mut contents = format!("# {secret}\n");
        contents.push_str(&"a".repeat((MAX_RELAY_MANIFEST_FILE_BYTES + 1) as usize));
        fs::write(path, contents).expect("oversized relay manifest writes");
    }

    fn stable_counter_window() -> Duration {
        Duration::from_secs(10 * 365 * 24 * 60 * 60)
    }
}
