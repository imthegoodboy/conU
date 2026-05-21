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
    RelayClientFrame, RelayForwarded, RelayServerFrame, parse_client_frame, parse_server_frame,
    render_server_frame,
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
const RELAY_CREDENTIALS_FILE_VERSION: &str = "1";
const RELAY_ACCOUNTING_FILE_VERSION: &str = "1";
const LOCAL_DEV_TOKEN: &str = "local-dev-token";
const MIN_PUBLIC_BIND_TOKEN_LEN: usize = 24;
const MAX_TOKEN_LEN: usize = 200;
const ISSUED_RELAY_TOKEN_BYTES: usize = 32;

/// Configuration for the relay server.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub bind_addr: String,
    pub auth: RelayAuth,
    pub limits: RelayLimits,
    pub session_policy: RelaySessionPolicy,
    pub mailbox_policy: RelayMailboxPolicy,
    pub mailbox_storage: RelayMailboxStorage,
    pub accounting_policy: RelayAccountingPolicy,
    pub accounting_storage: RelayAccountingStorage,
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConfig")
            .field("bind_addr", &self.bind_addr)
            .field("auth", &self.auth)
            .field("limits", &self.limits)
            .field("session_policy", &self.session_policy)
            .field("mailbox_policy", &self.mailbox_policy)
            .field("mailbox_storage", &self.mailbox_storage)
            .field("accounting_policy", &self.accounting_policy)
            .field("accounting_storage", &self.accounting_storage)
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

impl IssuedRelayCredential {
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
}

impl fmt::Debug for IssuedRelayCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedRelayCredential")
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
            mailbox_policy: RelayMailboxPolicy::default(),
            mailbox_storage: RelayMailboxStorage::default(),
            accounting_policy: RelayAccountingPolicy::default(),
            accounting_storage: RelayAccountingStorage::default(),
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
            mailbox_policy: RelayMailboxPolicy::default(),
            mailbox_storage: RelayMailboxStorage::default(),
            accounting_policy: RelayAccountingPolicy::default(),
            accounting_storage: RelayAccountingStorage::default(),
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
        let credentials = load_scoped_credentials_file(&path)?;
        validate_scoped_credentials_for_bind(&bind_addr, &credentials)?;

        Ok(Self {
            bind_addr: bind_addr.clone(),
            auth: RelayAuth::ScopedCredentialsFile { path, bind_addr },
            limits: RelayLimits::default(),
            session_policy: RelaySessionPolicy::default(),
            mailbox_policy: RelayMailboxPolicy::default(),
            mailbox_storage: RelayMailboxStorage::default(),
            accounting_policy: RelayAccountingPolicy::default(),
            accounting_storage: RelayAccountingStorage::default(),
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

    pub fn with_mailbox_policy(mut self, mailbox_policy: RelayMailboxPolicy) -> Self {
        self.mailbox_policy = mailbox_policy;
        self
    }

    pub fn with_mailbox_storage(mut self, mailbox_storage: RelayMailboxStorage) -> Self {
        self.mailbox_storage = mailbox_storage;
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
}

/// Read a scoped relay credential manifest from disk.
///
/// The manifest stores token hashes, lifecycle status, and expiry metadata; it
/// must not contain raw relay tokens.
pub fn load_scoped_credentials_file(
    path: impl AsRef<Path>,
) -> Result<Vec<RelayCredential>, RelayError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .map_err(|error| RelayError::io("read relay credential file", error))?;
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

        if let Some(record) = current.as_mut() {
            record.set(key, &value, line_number)?;
            continue;
        }

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
    let mut records = match fs::read_to_string(path) {
        Ok(contents) => parse_credential_file_records(&contents)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(RelayError::io("read relay credential file", error)),
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

/// Mark a credential as revoked in a live-reload manifest.
pub fn revoke_relay_credential_in_file(
    path: impl AsRef<Path>,
    node_id: impl Into<String>,
) -> Result<CredentialManifestUpdate, RelayError> {
    let path = path.as_ref();
    let node_id = validate_node_id(node_id.into())?;
    let contents = fs::read_to_string(path)
        .map_err(|error| RelayError::io("read relay credential file", error))?;
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

/// Return whether a live-reload credential manifest already has a node entry.
pub fn relay_credential_manifest_contains_node(
    path: impl AsRef<Path>,
    node_id: impl Into<String>,
) -> Result<bool, RelayError> {
    let path = path.as_ref();
    let node_id = validate_node_id(node_id.into())?;
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(RelayError::io("read relay credential file", error)),
    };
    for record in parse_credential_file_records(&contents)? {
        if record.node_id()? == node_id {
            return Ok(true);
        }
    }
    Ok(false)
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
    let expires_at = credential
        .expires_at_unix
        .map(|expires_at| format!("expires_at_unix = {expires_at}\n"))
        .unwrap_or_default();

    format!(
        "[[credential]]\n\
node_id = \"{}\"\n\
token_sha256_hex = \"{}\"\n\
token_length = {}\n\
status = \"active\"\n\
{}\
created_at_unix = {}\n\
updated_at_unix = {}\n\
payload_displayed = false\n\
token_displayed = false\n",
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
        fs::create_dir_all(parent)
            .map_err(|error| RelayError::io("create issued relay token directory", error))?;
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
        fs::create_dir_all(parent)
            .map_err(|error| RelayError::io("create relay credential file directory", error))?;
    }

    let temp_path = credential_manifest_temp_path(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temp_path)
        .map_err(|error| RelayError::io("create temporary relay credential file", error))?;
    if let Err(error) = file
        .write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&temp_path);
        return Err(RelayError::io(
            "write temporary relay credential file",
            error,
        ));
    }
    drop(file);

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| RelayError::io("replace relay credential file", error))?;
    }

    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(RelayError::io("replace relay credential file", error));
    }
    Ok(())
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

fn credential_manifest_temp_path(path: &Path) -> Result<PathBuf, RelayError> {
    let file_name = path.file_name().ok_or(RelayError::InvalidConfig(
        "relay credential file path must include a file name",
    ))?;
    Ok(path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        current_unix_nanos()
    )))
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

#[derive(Clone, Default)]
struct CredentialFileRecord {
    node_id: Option<String>,
    token_sha256_hex: Option<String>,
    token_length: Option<usize>,
    status: Option<RelayCredentialStatus>,
    expires_at_unix: Option<u64>,
    created_at_unix: Option<u64>,
    updated_at_unix: Option<u64>,
}

impl CredentialFileRecord {
    fn set(&mut self, key: &str, value: &str, line_number: usize) -> Result<(), RelayError> {
        match key {
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
            node_id: Some(credential.node_id.clone()),
            token_sha256_hex: Some(credential.token_sha256_hex.clone()),
            token_length: Some(credential.token_length),
            status: Some(RelayCredentialStatus::Active),
            expires_at_unix: credential.expires_at_unix,
            created_at_unix: Some(credential.created_at_unix),
            updated_at_unix: Some(updated_at_unix),
        }
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

        let mut output = format!(
            "[[credential]]\n\
node_id = \"{node_id}\"\n\
token_sha256_hex = \"{token_sha256_hex}\"\n\
token_length = {token_length}\n\
status = \"{}\"\n",
            self.status
                .unwrap_or(RelayCredentialStatus::Active)
                .as_str()
        );
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

        let credential = RelayCredential::from_sha256_hex(node_id, token_sha256_hex, token_length)?;
        Ok(credential
            .with_status(self.status.unwrap_or(RelayCredentialStatus::Active))
            .with_expires_at_unix(self.expires_at_unix))
    }
}

/// Run a relay server until the process exits.
pub fn run_blocking(config: RelayConfig) -> Result<(), RelayError> {
    let listener = TcpListener::bind(&config.bind_addr)
        .map_err(|error| RelayError::io("bind relay listener", error))?;
    let bind_addr = config.bind_addr.clone();
    let hub = Arc::new(RelayHub::new(
        config.auth,
        config.limits,
        config.session_policy,
        config.mailbox_policy,
        config.mailbox_storage,
        config.accounting_policy,
        config.accounting_storage,
    )?);

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
    let hub = Arc::new(RelayHub::new(
        config.auth,
        config.limits,
        config.session_policy,
        config.mailbox_policy,
        config.mailbox_storage,
        config.accounting_policy,
        config.accounting_storage,
    )?);

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

    Ok(RelayHandle {
        local_addr,
        stop,
        join: Some(join),
    })
}

/// Compute the RFC 6455 Sec-WebSocket-Accept value.
pub fn websocket_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key.trim());
    input.push_str(WEBSOCKET_GUID);
    base64_encode(&sha1(input.as_bytes()))
}

struct RelayHub {
    auth: RelayAuth,
    limits: RelayLimits,
    session_policy: RelaySessionPolicy,
    mailbox_policy: RelayMailboxPolicy,
    mailbox_storage: RelayMailboxStorage,
    accounting_policy: RelayAccountingPolicy,
    accounting_storage: RelayAccountingStorage,
    connections: Mutex<ConnectionCounts>,
    state: Mutex<RelayHubState>,
    accounting: Mutex<RelayAccountingState>,
}

impl fmt::Debug for RelayHub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayHub")
            .field("auth", &self.auth)
            .field("limits", &self.limits)
            .field("session_policy", &self.session_policy)
            .field("mailbox_policy", &self.mailbox_policy)
            .field("mailbox_storage", &self.mailbox_storage)
            .field("accounting_policy", &self.accounting_policy)
            .field("accounting_storage", &self.accounting_storage)
            .field("connections", &"<connection-counts>")
            .field("state", &"<relay-hub-state>")
            .field("accounting", &"<relay-accounting-state>")
            .finish()
    }
}

impl RelayHub {
    fn new(
        auth: RelayAuth,
        limits: RelayLimits,
        session_policy: RelaySessionPolicy,
        mailbox_policy: RelayMailboxPolicy,
        mailbox_storage: RelayMailboxStorage,
        accounting_policy: RelayAccountingPolicy,
        accounting_storage: RelayAccountingStorage,
    ) -> Result<Self, RelayError> {
        let state = RelayHubState::load(&mailbox_storage, mailbox_policy)?;
        let accounting = RelayAccountingState::load(&accounting_storage, accounting_policy)?;
        Ok(Self {
            auth,
            limits,
            session_policy,
            mailbox_policy,
            mailbox_storage,
            accounting_policy,
            accounting_storage,
            connections: Mutex::new(ConnectionCounts::default()),
            state: Mutex::new(state),
            accounting: Mutex::new(accounting),
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
        let resumed = resume_session_id.is_some_and(|candidate| {
            !state.clients.contains_key(&node_id) && session_id_belongs_to_node(candidate, &node_id)
        });
        let session_id = if resumed {
            resume_session_id.unwrap_or_default().to_string()
        } else {
            session_id(&node_id)
        };
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
        if let Ok(mut state) = self.state.lock() {
            if state
                .clients
                .get(node_id)
                .is_some_and(|connection| connection.session_id == session_id)
            {
                state.clients.remove(node_id);
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
    perform_websocket_handshake(&mut stream)?;

    let mut session_node = None::<(String, String)>;
    let mut authenticated_at = None::<Instant>;
    let mut rate_limiter = FrameRateLimiter::new(hub.limits.max_frames_per_minute);

    while let Some(text) = read_text_frame(&mut stream)? {
        if authenticated_at
            .is_some_and(|started| started.elapsed() >= hub.session_policy.max_session_ttl)
        {
            write_text_frame(
                &mut stream,
                &render_server_frame(&RelayServerFrame::Error {
                    reason: "session_expired".to_string(),
                }),
            )?;
            break;
        }

        if !rate_limiter.allow() {
            write_text_frame(
                &mut stream,
                &render_server_frame(&RelayServerFrame::Error {
                    reason: "rate_limited".to_string(),
                }),
            )?;
            break;
        }

        match parse_client_frame(&text) {
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
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "unauthorized".to_string(),
                        }),
                    )?;
                    break;
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

        fs::create_dir_all(root)
            .map_err(|error| RelayError::io("create relay mailbox directory", error))?;
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
            envelopes.sort_by_key(|envelope| envelope.queued_at_millis);
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

        let mut envelope = QueuedRelayEnvelope {
            queued_at_millis: current_unix_millis(),
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

        fs::create_dir_all(root)
            .map_err(|error| RelayError::io("create relay accounting directory", error))?;
        for entry in fs::read_dir(root)
            .map_err(|error| RelayError::io("read relay accounting directory", error))?
        {
            let entry =
                entry.map_err(|error| RelayError::io("read relay accounting entry", error))?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("accounting") {
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
struct QueuedRelayEnvelope {
    queued_at_millis: u128,
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

fn perform_websocket_handshake(stream: &mut TcpStream) -> Result<(), RelayError> {
    let request = read_http_request(stream)?;
    let key = header_value(&request, "sec-websocket-key")
        .ok_or_else(|| RelayError::Protocol("missing Sec-WebSocket-Key header".to_string()))?;
    let accept = websocket_accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| RelayError::io("write websocket handshake", error))
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

    let node_dir = root.join(sanitize_identifier(node_id));
    fs::create_dir_all(&node_dir).map_err(|_| "mailbox_unavailable")?;
    let path = node_dir.join(format!(
        "{}-{}.mailbox",
        current_unix_nanos(),
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
        "version = \"{}\"\nqueued_at_millis = {}\nframe = {}\npayload_displayed = false\n",
        RELAY_MAILBOX_FILE_VERSION, entry.queued_at_millis, frame
    )
}

fn read_mailbox_file(path: &Path) -> Result<Option<QueuedRelayEnvelope>, RelayError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| RelayError::io("read relay mailbox file", error))?;
    let version = mailbox_value(&contents, "version").unwrap_or_default();
    if version != RELAY_MAILBOX_FILE_VERSION {
        return Ok(None);
    }
    let queued_at_millis = mailbox_value(&contents, "queued_at_millis")
        .and_then(|value| value.parse::<u128>().ok())
        .ok_or_else(|| RelayError::Protocol("relay mailbox entry is invalid".to_string()))?;
    let frame = mailbox_value(&contents, "frame")
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
        storage_path: Some(path.to_path_buf()),
        forwarded,
    }))
}

fn persist_accounting_record(
    storage: &RelayAccountingStorage,
    record: &RelayAccountingRecord,
) -> Result<(), RelayError> {
    let RelayAccountingStorage::FileBacked(root) = storage else {
        return Ok(());
    };

    fs::create_dir_all(root)
        .map_err(|error| RelayError::io("create relay accounting directory", error))?;
    let path = root.join(format!(
        "{}.accounting",
        sanitize_identifier(&record.node_id)
    ));
    let contents = render_accounting_file(record);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| RelayError::io("write relay accounting file", error))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| RelayError::io("write relay accounting file", error))
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
    let contents = fs::read_to_string(path)
        .map_err(|error| RelayError::io("read relay accounting file", error))?;
    let version = mailbox_value(&contents, "version").unwrap_or_default();
    if version != RELAY_ACCOUNTING_FILE_VERSION {
        return Ok(None);
    }
    if mailbox_value(&contents, "payload_displayed").as_deref() != Some("false")
        || mailbox_value(&contents, "token_displayed").as_deref() != Some("false")
    {
        return Ok(None);
    }
    let Some(node_id) = mailbox_value(&contents, "node_id") else {
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
    mailbox_value(contents, key)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| RelayError::Protocol("relay accounting entry is invalid".to_string()))
}

fn parse_optional_accounting_u64(contents: &str, key: &str) -> Result<Option<u64>, RelayError> {
    mailbox_value(contents, key)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| RelayError::Protocol("relay accounting entry is invalid".to_string()))
        })
        .transpose()
}

fn mailbox_value(contents: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = ");
    contents.lines().find_map(|line| {
        let value = line.trim().strip_prefix(&prefix)?;
        Some(value.trim().trim_matches('"').to_string())
    })
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
    if host.eq_ignore_ascii_case("localhost") {
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
    fn relay_accounting_quota_rejects_sender_without_payloads() {
        let accounting_policy = RelayAccountingPolicy::new(Duration::from_secs(60), Some(1), None)
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
    fn relay_accounting_loads_existing_window_for_quota() {
        let accounting_dir = test_home("relay-accounting-quota").join("accounting");
        let accounting_storage =
            RelayAccountingStorage::file_backed(accounting_dir).expect("storage config");
        let accounting_policy = RelayAccountingPolicy::new(Duration::from_secs(60), Some(1), None)
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
            messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob").expect("inbox reads");
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
            messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob").expect("inbox reads");
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
            .set_read_timeout(Some(Duration::from_secs(3)))
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
        read_text_frame(stream)
            .expect("server frame reads")
            .expect("server frame exists")
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
}
