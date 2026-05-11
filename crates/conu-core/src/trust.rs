//! Local pairing invitations and trust store records.
//!
//! Phase 7 creates the trust-store mechanics before relay rendezvous exists.
//! Pairing codes are local invitations; joining one creates a local trusted peer
//! record without exposing payload contents.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::security;
use crate::state::{self, StateError, StatePaths};

const TRUST_VERSION: &str = "1";
const PAIRING_VERSION: &str = "1";
const PAIRING_TTL_SECS: u64 = 10 * 60;
const DEFAULT_RELAY_ENDPOINT: &str = "ws://127.0.0.1:8787";

/// Lifecycle state for a local pairing invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStatus {
    Pending,
    Used,
    Expired,
}

impl PairingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Used => "used",
            Self::Expired => "expired",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "pending" => Self::Pending,
            "used" => Self::Used,
            "expired" => Self::Expired,
            _ => Self::Expired,
        }
    }
}

/// Trust state for a known peer runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    Trusted,
    Revoked,
}

impl TrustStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Revoked => "revoked",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "trusted" => Self::Trusted,
            "revoked" => Self::Revoked,
            _ => Self::Revoked,
        }
    }
}

/// Local pairing invitation created by `conu pair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInvite {
    pub code: String,
    pub local_node_id: String,
    pub peer_node_id: String,
    pub display_name: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: PairingStatus,
}

/// Trusted or revoked peer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeer {
    pub peer_node_id: String,
    pub display_name: String,
    pub status: TrustStatus,
    pub source: String,
    pub pairing_code_hash: String,
    pub exchange_public_key_hex: Option<String>,
    pub relay_endpoint: Option<String>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

/// Public card a user can exchange with another conU node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCard {
    pub node_id: String,
    pub display_name: String,
    pub exchange_public_key_hex: String,
    pub relay_endpoint: String,
}

/// Result of joining a local pairing invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinReport {
    pub peer: TrustedPeer,
    pub invite: PairingInvite,
}

/// Result of revoking a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeReport {
    pub peer: TrustedPeer,
    pub changed: bool,
}

/// Errors produced by pairing and trust operations.
#[derive(Debug)]
pub enum TrustError {
    State(StateError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRequest {
        reason: String,
    },
    Security(security::SecurityError),
}

impl TrustError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRequest { reason } => write!(formatter, "invalid trust request: {reason}"),
            Self::Security(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<StateError> for TrustError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<security::SecurityError> for TrustError {
    fn from(error: security::SecurityError) -> Self {
        Self::Security(error)
    }
}

/// Create a local pairing invitation.
pub fn create_pairing_invite(home_override: Option<PathBuf>) -> Result<PairingInvite, TrustError> {
    let init = state::init_state(home_override)?;
    let now = current_unix_seconds();
    let code = unique_pairing_code(&init.paths, &init.node.node_id, now)?;
    let peer_suffix = pairing_code_suffix(&code);
    let invite = PairingInvite {
        peer_node_id: format!("peer_{peer_suffix}"),
        display_name: format!("paired-peer-{peer_suffix}"),
        code,
        local_node_id: init.node.node_id,
        created_at_unix: now,
        expires_at_unix: now + PAIRING_TTL_SECS,
        status: PairingStatus::Pending,
    };
    write_pairing_invite(&init.paths, &invite)?;

    Ok(invite)
}

/// Join a local pairing invitation and create a trusted peer record.
pub fn join_pairing_code(
    home_override: Option<PathBuf>,
    code: &str,
) -> Result<JoinReport, TrustError> {
    let code = validate_pairing_code(code)?;
    let init = state::init_state(home_override)?;
    let mut invite = read_pairing_invite(&init.paths, &code)?;
    let now = current_unix_seconds();

    if invite.expires_at_unix < now {
        invite.status = PairingStatus::Expired;
        write_pairing_invite(&init.paths, &invite)?;
        return Err(TrustError::InvalidRequest {
            reason: "pairing code expired".to_string(),
        });
    }
    if invite.status != PairingStatus::Pending {
        return Err(TrustError::InvalidRequest {
            reason: "pairing code has already been used".to_string(),
        });
    }

    let peer = upsert_trusted_peer(&init.paths, &invite, now)?;
    invite.status = PairingStatus::Used;
    write_pairing_invite(&init.paths, &invite)?;
    move_used_invite(&init.paths, &invite)?;

    Ok(JoinReport { peer, invite })
}

/// List trusted and revoked peers from the local trust store.
pub fn list_peers(home_override: Option<PathBuf>) -> Result<Vec<TrustedPeer>, TrustError> {
    let paths = StatePaths::resolve(home_override)?;
    read_trust_store(&paths)
}

/// Export this node's public card for manual cross-machine trust.
pub fn export_peer_card(home_override: Option<PathBuf>) -> Result<PeerCard, TrustError> {
    let init = state::init_state(home_override)?;
    let material = security::local_peer_key_material(&init.paths)?;

    Ok(PeerCard {
        node_id: init.node.node_id,
        display_name: init.node.display_name,
        exchange_public_key_hex: material.local_exchange_public_key_hex,
        relay_endpoint: configured_relay_endpoint(&init.paths)?,
    })
}

/// Trust a peer from an explicitly exchanged public card.
pub fn trust_peer_card(
    home_override: Option<PathBuf>,
    card: PeerCard,
) -> Result<TrustedPeer, TrustError> {
    let init = state::init_state(home_override)?;
    let now = current_unix_seconds();
    let card = validate_peer_card(card)?;

    if card.node_id == init.node.node_id {
        return Err(TrustError::InvalidRequest {
            reason: "cannot trust the local node as a remote peer".to_string(),
        });
    }

    security::derive_peer_key_agreement_from_paths(
        &init.paths,
        &card.exchange_public_key_hex,
        b"conu manual peer trust v1",
    )?;

    upsert_manual_trusted_peer(&init.paths, card, now)
}

/// Revoke a peer by node id.
pub fn revoke_peer(
    home_override: Option<PathBuf>,
    peer_node_id: &str,
) -> Result<RevokeReport, TrustError> {
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    let init = state::init_state(home_override)?;
    let mut peers = read_trust_store(&init.paths)?;
    let now = current_unix_seconds();

    for peer in &mut peers {
        if peer.peer_node_id == peer_node_id {
            let changed = peer.status != TrustStatus::Revoked;
            peer.status = TrustStatus::Revoked;
            peer.updated_at_unix = now;
            let result = peer.clone();
            write_trust_store(&init.paths, &peers)?;
            return Ok(RevokeReport {
                peer: result,
                changed,
            });
        }
    }

    Err(TrustError::InvalidRequest {
        reason: "peer is not trusted locally".to_string(),
    })
}

fn upsert_trusted_peer(
    paths: &StatePaths,
    invite: &PairingInvite,
    now: u64,
) -> Result<TrustedPeer, TrustError> {
    let mut peers = read_trust_store(paths)?;
    let mut result = None;

    for peer in &mut peers {
        if peer.peer_node_id == invite.peer_node_id {
            peer.display_name = invite.display_name.clone();
            peer.status = TrustStatus::Trusted;
            peer.source = "local_pair_code".to_string();
            peer.pairing_code_hash = pairing_code_hash(&invite.code);
            peer.updated_at_unix = now;
            result = Some(peer.clone());
            break;
        }
    }

    let peer = result.unwrap_or_else(|| TrustedPeer {
        peer_node_id: invite.peer_node_id.clone(),
        display_name: invite.display_name.clone(),
        status: TrustStatus::Trusted,
        source: "local_pair_code".to_string(),
        pairing_code_hash: pairing_code_hash(&invite.code),
        exchange_public_key_hex: None,
        relay_endpoint: None,
        created_at_unix: now,
        updated_at_unix: now,
    });

    if !peers
        .iter()
        .any(|entry| entry.peer_node_id == peer.peer_node_id)
    {
        peers.push(peer.clone());
    }

    write_trust_store(paths, &peers)?;
    Ok(peer)
}

fn upsert_manual_trusted_peer(
    paths: &StatePaths,
    card: PeerCard,
    now: u64,
) -> Result<TrustedPeer, TrustError> {
    let mut peers = read_trust_store(paths)?;
    let fingerprint = manual_peer_hash(&card.node_id, &card.exchange_public_key_hex);
    let mut result = None;

    for peer in &mut peers {
        if peer.peer_node_id == card.node_id {
            peer.display_name = card.display_name.clone();
            peer.status = TrustStatus::Trusted;
            peer.source = "manual_peer_card".to_string();
            peer.pairing_code_hash = fingerprint.clone();
            peer.exchange_public_key_hex = Some(card.exchange_public_key_hex.clone());
            peer.relay_endpoint = Some(card.relay_endpoint.clone());
            peer.updated_at_unix = now;
            result = Some(peer.clone());
            break;
        }
    }

    let peer = result.unwrap_or_else(|| TrustedPeer {
        peer_node_id: card.node_id,
        display_name: card.display_name,
        status: TrustStatus::Trusted,
        source: "manual_peer_card".to_string(),
        pairing_code_hash: fingerprint,
        exchange_public_key_hex: Some(card.exchange_public_key_hex),
        relay_endpoint: Some(card.relay_endpoint),
        created_at_unix: now,
        updated_at_unix: now,
    });

    if !peers
        .iter()
        .any(|entry| entry.peer_node_id == peer.peer_node_id)
    {
        peers.push(peer.clone());
    }

    write_trust_store(paths, &peers)?;
    Ok(peer)
}

fn read_pairing_invite(paths: &StatePaths, code: &str) -> Result<PairingInvite, TrustError> {
    let path = paths.pairing_invites_dir.join(format!("{code}.pair"));
    if !path.exists() {
        return Err(TrustError::InvalidRequest {
            reason: "pairing code is not available locally until relay pairing arrives".to_string(),
        });
    }

    let contents = fs::read_to_string(&path)
        .map_err(|error| TrustError::io("read pairing invitation", &path, error))?;
    let values = parse_key_values(&contents);

    Ok(PairingInvite {
        code: validate_pairing_code(&required(&values, "code")?)?,
        local_node_id: validate_identifier(required(&values, "local_node_id")?, "local node id")?,
        peer_node_id: validate_identifier(required(&values, "peer_node_id")?, "peer node id")?,
        display_name: validate_display_name(required(&values, "display_name")?)?,
        created_at_unix: parse_u64(&required(&values, "created_at_unix")?)?,
        expires_at_unix: parse_u64(&required(&values, "expires_at_unix")?)?,
        status: PairingStatus::from_str(&required(&values, "status")?),
    })
}

fn write_pairing_invite(paths: &StatePaths, invite: &PairingInvite) -> Result<(), TrustError> {
    fs::create_dir_all(&paths.pairing_invites_dir).map_err(|error| {
        TrustError::io(
            "create pairing invitation directory",
            &paths.pairing_invites_dir,
            error,
        )
    })?;
    let path = paths
        .pairing_invites_dir
        .join(format!("{}.pair", invite.code));
    let contents = format!(
        "version = \"{}\"\ncode = \"{}\"\nlocal_node_id = \"{}\"\npeer_node_id = \"{}\"\ndisplay_name = \"{}\"\ncreated_at_unix = {}\nexpires_at_unix = {}\nstatus = \"{}\"\npayload_displayed = false\n",
        PAIRING_VERSION,
        escape_file_value(&invite.code),
        escape_file_value(&invite.local_node_id),
        escape_file_value(&invite.peer_node_id),
        escape_file_value(&invite.display_name),
        invite.created_at_unix,
        invite.expires_at_unix,
        invite.status.as_str()
    );

    fs::write(&path, contents)
        .map_err(|error| TrustError::io("write pairing invitation", &path, error))
}

fn move_used_invite(paths: &StatePaths, invite: &PairingInvite) -> Result<(), TrustError> {
    fs::create_dir_all(&paths.pairing_used_dir).map_err(|error| {
        TrustError::io(
            "create used pairing invitation directory",
            &paths.pairing_used_dir,
            error,
        )
    })?;
    let source = paths
        .pairing_invites_dir
        .join(format!("{}.pair", invite.code));
    let target = paths.pairing_used_dir.join(format!("{}.pair", invite.code));
    fs::rename(&source, &target)
        .map_err(|error| TrustError::io("move used pairing invitation", &source, error))
}

fn read_trust_store(paths: &StatePaths) -> Result<Vec<TrustedPeer>, TrustError> {
    if !paths.trust_store.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(&paths.trust_store)
        .map_err(|error| TrustError::io("read trust store", &paths.trust_store, error))?;
    parse_trust_store(&contents)
}

fn write_trust_store(paths: &StatePaths, peers: &[TrustedPeer]) -> Result<(), TrustError> {
    let mut sorted = peers.to_vec();
    sorted.sort_by(|left, right| left.peer_node_id.cmp(&right.peer_node_id));
    let mut contents = format!("# conU trust store\nversion = \"{}\"\n", TRUST_VERSION);

    for peer in sorted {
        contents.push_str("\n[[peer]]\n");
        contents.push_str(&format!(
            "peer_node_id = \"{}\"\n",
            escape_file_value(&peer.peer_node_id)
        ));
        contents.push_str(&format!(
            "display_name = \"{}\"\n",
            escape_file_value(&peer.display_name)
        ));
        contents.push_str(&format!("status = \"{}\"\n", peer.status.as_str()));
        contents.push_str(&format!(
            "source = \"{}\"\n",
            escape_file_value(&peer.source)
        ));
        contents.push_str(&format!(
            "pairing_code_hash = \"{}\"\n",
            escape_file_value(&peer.pairing_code_hash)
        ));
        contents.push_str(&format!(
            "exchange_public_key_hex = \"{}\"\n",
            escape_file_value(peer.exchange_public_key_hex.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!(
            "relay_endpoint = \"{}\"\n",
            escape_file_value(peer.relay_endpoint.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!("created_at_unix = {}\n", peer.created_at_unix));
        contents.push_str(&format!("updated_at_unix = {}\n", peer.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    fs::write(&paths.trust_store, contents)
        .map_err(|error| TrustError::io("write trust store", &paths.trust_store, error))
}

fn parse_trust_store(contents: &str) -> Result<Vec<TrustedPeer>, TrustError> {
    let mut peers = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with('#')
            || line == "trusted_peers = []"
            || line == "revoked_peers = []"
            || line == "version = \"1\""
        {
            continue;
        }

        if line == "[[peer]]" {
            if !current.is_empty() {
                peers.push(peer_from_values(&current)?);
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
        peers.push(peer_from_values(&current)?);
    }

    Ok(peers)
}

fn peer_from_values(values: &HashMap<String, String>) -> Result<TrustedPeer, TrustError> {
    Ok(TrustedPeer {
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        status: TrustStatus::from_str(&required(values, "status")?),
        source: validate_identifier(required(values, "source")?, "source")?,
        pairing_code_hash: validate_identifier(
            required(values, "pairing_code_hash")?,
            "pairing code hash",
        )?,
        exchange_public_key_hex: optional_hex(values.get("exchange_public_key_hex"))?,
        relay_endpoint: optional_endpoint(values.get("relay_endpoint"))?,
        created_at_unix: parse_u64(&required(values, "created_at_unix")?)?,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn unique_pairing_code(paths: &StatePaths, node_id: &str, now: u64) -> Result<String, TrustError> {
    for attempt in 0..10_u64 {
        let code = generate_pairing_code(node_id, now, attempt);
        let path = paths.pairing_invites_dir.join(format!("{code}.pair"));
        if !path.exists() {
            return Ok(code);
        }
    }

    Err(TrustError::InvalidRequest {
        reason: "could not allocate a unique pairing code".to_string(),
    })
}

fn generate_pairing_code(node_id: &str, now: u64, attempt: u64) -> String {
    let mut hasher = DefaultHasher::new();
    node_id.hash(&mut hasher);
    now.hash(&mut hasher);
    attempt.hash(&mut hasher);
    process::id().hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);

    format!("{:06}", hasher.finish() % 1_000_000)
}

fn pairing_code_hash(code: &str) -> String {
    let mut hasher = DefaultHasher::new();
    code.hash(&mut hasher);
    format!("pair_{:016x}", hasher.finish())
}

fn manual_peer_hash(node_id: &str, exchange_public_key_hex: &str) -> String {
    let mut hasher = DefaultHasher::new();
    node_id.hash(&mut hasher);
    exchange_public_key_hex.hash(&mut hasher);
    format!("manual_{:016x}", hasher.finish())
}

fn pairing_code_suffix(code: &str) -> String {
    pairing_code_hash(code)
        .trim_start_matches("pair_")
        .chars()
        .take(12)
        .collect()
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, TrustError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| TrustError::InvalidRequest {
            reason: format!("missing {key}"),
        })
}

fn validate_pairing_code(code: &str) -> Result<String, TrustError> {
    let code = code.trim().to_string();
    if code.len() != 6 || !code.chars().all(|character| character.is_ascii_digit()) {
        return Err(TrustError::InvalidRequest {
            reason: "pairing code must be six digits".to_string(),
        });
    }
    Ok(code)
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, TrustError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(TrustError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 100 {
        return Err(TrustError::InvalidRequest {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(TrustError::InvalidRequest {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_display_name(value: String) -> Result<String, TrustError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(TrustError::InvalidRequest {
            reason: "display name cannot be empty".to_string(),
        });
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(TrustError::InvalidRequest {
            reason: "display name cannot contain control characters".to_string(),
        });
    }
    Ok(value)
}

fn validate_endpoint(value: String) -> Result<String, TrustError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(TrustError::InvalidRequest {
            reason: "relay endpoint cannot be empty".to_string(),
        });
    }
    if !value.starts_with("ws://") {
        return Err(TrustError::InvalidRequest {
            reason: "relay endpoint must start with ws:// for the current relay client".to_string(),
        });
    }
    if value.len() > 220 || value.chars().any(char::is_whitespace) {
        return Err(TrustError::InvalidRequest {
            reason: "relay endpoint is invalid".to_string(),
        });
    }
    Ok(value)
}

fn validate_hex(value: String, field: &'static str) -> Result<String, TrustError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(TrustError::InvalidRequest {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(TrustError::InvalidRequest {
            reason: format!("{field} must be hex"),
        });
    }
    Ok(value)
}

fn validate_peer_card(card: PeerCard) -> Result<PeerCard, TrustError> {
    Ok(PeerCard {
        node_id: validate_identifier(card.node_id, "peer node id")?,
        display_name: validate_display_name(card.display_name)?,
        exchange_public_key_hex: validate_hex(card.exchange_public_key_hex, "exchange public key")?,
        relay_endpoint: validate_endpoint(card.relay_endpoint)?,
    })
}

fn optional_hex(value: Option<&String>) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| validate_hex(value, "exchange public key"))
        .transpose()
}

fn optional_endpoint(value: Option<&String>) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(validate_endpoint)
        .transpose()
}

fn configured_relay_endpoint(paths: &StatePaths) -> Result<String, TrustError> {
    let contents = match fs::read_to_string(&paths.config) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DEFAULT_RELAY_ENDPOINT.to_string());
        }
        Err(error) => return Err(TrustError::io("read conU config", &paths.config, error)),
    };
    let values = parse_key_values(&contents);
    let endpoint = values
        .get("default_relay")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_RELAY_ENDPOINT.to_string());
    validate_endpoint(endpoint)
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

fn parse_u64(value: &str) -> Result<u64, TrustError> {
    value
        .parse::<u64>()
        .map_err(|_| TrustError::InvalidRequest {
            reason: "expected unsigned integer".to_string(),
        })
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

    #[test]
    fn pairing_invite_persists_without_payload() {
        let home = test_home("invite");

        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let invite_file = fs::read_to_string(
            StatePaths::from_home(home)
                .pairing_invites_dir
                .join(format!("{}.pair", invite.code)),
        )
        .expect("invite reads");

        assert_eq!(invite.status, PairingStatus::Pending);
        assert_eq!(invite.code.len(), 6);
        assert!(invite_file.contains("payload_displayed = false"));
        assert!(!invite_file.contains("private message contents"));
    }

    #[test]
    fn join_pairing_code_creates_trusted_peer() {
        let home = test_home("join");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");

        let report = join_pairing_code(Some(home.clone()), &invite.code).expect("join succeeds");
        let peers = list_peers(Some(home)).expect("peers read");

        assert_eq!(report.peer.status, TrustStatus::Trusted);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_node_id, invite.peer_node_id);
        assert_ne!(peers[0].pairing_code_hash, invite.code);
        assert!(peers[0].pairing_code_hash.starts_with("pair_"));
    }

    #[test]
    fn used_pairing_code_cannot_be_joined_twice() {
        let home = test_home("used");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        join_pairing_code(Some(home.clone()), &invite.code).expect("first join succeeds");

        let error = join_pairing_code(Some(home), &invite.code).expect_err("second join fails");

        assert!(error.to_string().contains("not available locally"));
    }

    #[test]
    fn revoke_peer_marks_record_revoked() {
        let home = test_home("revoke");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = join_pairing_code(Some(home.clone()), &invite.code).expect("join succeeds");

        let report =
            revoke_peer(Some(home.clone()), &joined.peer.peer_node_id).expect("revoke succeeds");
        let peers = list_peers(Some(home)).expect("peers read");

        assert!(report.changed);
        assert_eq!(report.peer.status, TrustStatus::Revoked);
        assert_eq!(peers[0].status, TrustStatus::Revoked);
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-trust-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
