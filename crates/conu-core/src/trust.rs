//! Local pairing invitations and trust store records.
//!
//! Phase 7 creates the trust-store mechanics before relay rendezvous exists.
//! Pairing codes are local invitations; joining one creates a local trusted peer
//! record without exposing payload contents.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::relay_endpoint::{self, RelayEndpointError};
use crate::state::{self, StateError, StatePaths};
use crate::{direct_transport, security};

const TRUST_VERSION: &str = "1";
const PAIRING_VERSION: &str = "1";
const PAIRING_TTL_SECS: u64 = 10 * 60;
const DEFAULT_RELAY_ENDPOINT: &str = "ws://127.0.0.1:8787";
const MAX_TRUST_FILE_BYTES: u64 = 1024 * 1024;

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
    pub direct_quic_endpoint: Option<String>,
    pub signing_public_key_hex: Option<String>,
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub signature_hex: Option<String>,
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
    pub direct_quic_endpoint: Option<String>,
    pub signing_public_key_hex: Option<String>,
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub signature_hex: Option<String>,
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
    write_new_pairing_invite(&init.paths, &invite)?;

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

    ensure_used_invite_target_available(&init.paths, &invite)?;
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
    let mut card = PeerCard {
        node_id: init.node.node_id,
        display_name: init.node.display_name,
        exchange_public_key_hex: material.local_exchange_public_key_hex,
        relay_endpoint: configured_relay_endpoint(&init.paths)?,
        direct_quic_endpoint: configured_direct_quic_endpoint(&init.paths)?,
        signing_public_key_hex: None,
        signature_algorithm: None,
        signature_key_id: None,
        signature_hex: None,
    };
    let signature = security::sign_agent_card_from_paths(&init.paths, &canonical_peer_card(&card))?;
    card.signing_public_key_hex = Some(signature.public_key_hex);
    card.signature_algorithm = Some(signature.algorithm);
    card.signature_key_id = Some(signature.key_id);
    card.signature_hex = Some(signature.signature_hex);

    Ok(card)
}

/// Trust a peer from an explicitly exchanged public card.
pub fn trust_peer_card(
    home_override: Option<PathBuf>,
    card: PeerCard,
) -> Result<TrustedPeer, TrustError> {
    let init = state::init_state(home_override)?;
    let now = current_unix_seconds();
    let card = validate_peer_card(card)?;
    verify_peer_card_signature(&card)?;

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
        direct_quic_endpoint: None,
        signing_public_key_hex: None,
        signature_algorithm: None,
        signature_key_id: None,
        signature_hex: None,
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
            peer.source = if card.signature_hex.is_some() {
                "manual_signed_peer_card".to_string()
            } else {
                "manual_peer_card".to_string()
            };
            peer.pairing_code_hash = fingerprint.clone();
            peer.exchange_public_key_hex = Some(card.exchange_public_key_hex.clone());
            peer.relay_endpoint = Some(card.relay_endpoint.clone());
            peer.direct_quic_endpoint = card.direct_quic_endpoint.clone();
            peer.signing_public_key_hex = card.signing_public_key_hex.clone();
            peer.signature_algorithm = card.signature_algorithm.clone();
            peer.signature_key_id = card.signature_key_id.clone();
            peer.signature_hex = card.signature_hex.clone();
            peer.updated_at_unix = now;
            result = Some(peer.clone());
            break;
        }
    }

    let peer = result.unwrap_or_else(|| TrustedPeer {
        peer_node_id: card.node_id,
        display_name: card.display_name,
        status: TrustStatus::Trusted,
        source: if card.signature_hex.is_some() {
            "manual_signed_peer_card".to_string()
        } else {
            "manual_peer_card".to_string()
        },
        pairing_code_hash: fingerprint,
        exchange_public_key_hex: Some(card.exchange_public_key_hex),
        relay_endpoint: Some(card.relay_endpoint),
        direct_quic_endpoint: card.direct_quic_endpoint,
        signing_public_key_hex: card.signing_public_key_hex,
        signature_algorithm: card.signature_algorithm,
        signature_key_id: card.signature_key_id,
        signature_hex: card.signature_hex,
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
    if !pairing_invite_directory_exists(paths)? {
        return Err(TrustError::InvalidRequest {
            reason: "pairing code is not available locally until relay pairing arrives".to_string(),
        });
    }
    let path = paths.pairing_invites_dir.join(format!("{code}.pair"));
    let Some(contents) = read_trust_file(
        &path,
        "inspect pairing invitation",
        "read pairing invitation",
    )?
    else {
        return Err(TrustError::InvalidRequest {
            reason: "pairing code is not available locally until relay pairing arrives".to_string(),
        });
    };
    let values = parse_key_values(&contents)?;

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
    write_pairing_invite_with_mode(paths, invite, false)
}

fn write_new_pairing_invite(paths: &StatePaths, invite: &PairingInvite) -> Result<(), TrustError> {
    write_pairing_invite_with_mode(paths, invite, true)
}

fn write_pairing_invite_with_mode(
    paths: &StatePaths,
    invite: &PairingInvite,
    create_new: bool,
) -> Result<(), TrustError> {
    ensure_pairing_invite_directory(paths)?;
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

    if create_new {
        write_new_file(
            &path,
            &contents,
            "create pairing invitation",
            "write pairing invitation",
        )
    } else {
        write_trust_file(
            &path,
            &contents,
            "create pairing invitation",
            "open pairing invitation",
            "write pairing invitation",
        )
    }
}

fn move_used_invite(paths: &StatePaths, invite: &PairingInvite) -> Result<(), TrustError> {
    ensure_pairing_invite_directory(paths)?;
    ensure_pairing_used_directory(paths)?;
    let source = paths
        .pairing_invites_dir
        .join(format!("{}.pair", invite.code));
    let target = paths.pairing_used_dir.join(format!("{}.pair", invite.code));
    state::archive_regular_state_file_no_replace(
        &source,
        &target,
        "inspect used pairing invitation before archive",
        "reserve used pairing invitation",
        "move used pairing invitation",
    )
    .map_err(TrustError::from)
}

fn ensure_used_invite_target_available(
    paths: &StatePaths,
    invite: &PairingInvite,
) -> Result<(), TrustError> {
    ensure_pairing_used_directory(paths)?;
    let target = paths.pairing_used_dir.join(format!("{}.pair", invite.code));
    ensure_path_available(&target, "reserve used pairing invitation")
}

fn ensure_pairing_invite_directory(paths: &StatePaths) -> Result<(), TrustError> {
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.pairing_dir)?;
    state::ensure_state_directory(&paths.pairing_invites_dir)?;
    Ok(())
}

fn ensure_pairing_used_directory(paths: &StatePaths) -> Result<(), TrustError> {
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.pairing_dir)?;
    state::ensure_state_directory(&paths.pairing_used_dir)?;
    Ok(())
}

fn pairing_invite_directory_exists(paths: &StatePaths) -> Result<bool, TrustError> {
    if !state::state_directory_exists(&paths.home, "inspect state directory")? {
        return Ok(false);
    }
    if !state::state_directory_exists(&paths.pairing_dir, "inspect pairing directory")? {
        return Ok(false);
    }
    state::state_directory_exists(
        &paths.pairing_invites_dir,
        "inspect pairing invitation directory",
    )
    .map_err(TrustError::from)
}

fn ensure_path_available(path: &Path, action: &'static str) -> Result<(), TrustError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(TrustError::io(
            action,
            path,
            io::Error::new(io::ErrorKind::AlreadyExists, "target already exists"),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TrustError::io("inspect trust target", path, error)),
    }
}

fn write_new_file(
    path: &Path,
    contents: &str,
    create_action: &'static str,
    write_action: &'static str,
) -> Result<(), TrustError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| TrustError::io(create_action, path, error))?;

    file.write_all(contents.as_bytes())
        .map_err(|error| TrustError::io(write_action, path, error))
}

fn read_trust_store(paths: &StatePaths) -> Result<Vec<TrustedPeer>, TrustError> {
    if !state::state_directory_exists(&paths.home, "inspect state directory")? {
        return Ok(Vec::new());
    }
    match read_trust_file(
        &paths.trust_store,
        "inspect trust store",
        "read trust store",
    )? {
        Some(contents) => parse_trust_store(&contents),
        None => Ok(Vec::new()),
    }
}

fn write_trust_store(paths: &StatePaths, peers: &[TrustedPeer]) -> Result<(), TrustError> {
    state::ensure_state_directory(&paths.home)?;
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
        contents.push_str(&format!(
            "direct_quic_endpoint = \"{}\"\n",
            escape_file_value(peer.direct_quic_endpoint.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!(
            "signing_public_key_hex = \"{}\"\n",
            escape_file_value(peer.signing_public_key_hex.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!(
            "signature_algorithm = \"{}\"\n",
            escape_file_value(peer.signature_algorithm.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!(
            "signature_key_id = \"{}\"\n",
            escape_file_value(peer.signature_key_id.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!(
            "signature_hex = \"{}\"\n",
            escape_file_value(peer.signature_hex.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!("created_at_unix = {}\n", peer.created_at_unix));
        contents.push_str(&format!("updated_at_unix = {}\n", peer.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    write_trust_file(
        &paths.trust_store,
        &contents,
        "create trust store",
        "open trust store",
        "write trust store",
    )
}

fn read_trust_file(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
) -> Result<Option<String>, TrustError> {
    let Some(metadata) = regular_trust_file_metadata(path, inspect_action)? else {
        return Ok(None);
    };

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| TrustError::io(read_action, path, error))?;
    let Some(path_metadata) = regular_trust_file_metadata(path, inspect_action)? else {
        return Err(TrustError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "trust file path is missing"),
        ));
    };
    if !trust_file_metadata_matches(&metadata, &path_metadata) {
        return Err(TrustError::io(
            inspect_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trust file path changed while reading",
            ),
        ));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| TrustError::io(inspect_action, path, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_TRUST_FILE_BYTES
        || !trust_file_metadata_matches(&metadata, &opened_metadata)
    {
        return Err(TrustError::io(
            read_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trust file path changed while reading",
            ),
        ));
    }

    let mut contents = String::new();
    let limit = MAX_TRUST_FILE_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_string(&mut contents)
        .map_err(|error| TrustError::io(read_action, path, error))?;
    if contents.len() as u64 > MAX_TRUST_FILE_BYTES {
        return Err(TrustError::io(
            read_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("trust file exceeds {MAX_TRUST_FILE_BYTES} bytes"),
            ),
        ));
    }

    Ok(Some(contents))
}

fn write_trust_file(
    path: &Path,
    contents: &str,
    create_action: &'static str,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), TrustError> {
    ensure_trust_file_contents_within_limit(path, contents.len(), write_action)?;

    if regular_trust_file_metadata(path, open_action)?.is_some() {
        replace_existing_trust_file(path, contents, open_action, write_action)
    } else {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| TrustError::io(create_action, path, error))?;

        file.write_all(contents.as_bytes())
            .map_err(|error| TrustError::io(write_action, path, error))
    }
}

fn replace_existing_trust_file(
    path: &Path,
    contents: &str,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), TrustError> {
    let Some(metadata) = regular_trust_file_metadata(path, open_action)? else {
        return Err(TrustError::io(
            open_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "trust file path is missing"),
        ));
    };
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| TrustError::io(open_action, path, error))?;
    validate_opened_regular_trust_file(path, open_action, &metadata, &file)?;
    drop(file);

    let temp_path = write_replacement_trust_temp_file(path, contents, write_action)?;
    let result =
        replace_trust_file_with_temp(path, &temp_path, &metadata, open_action, write_action);
    if result.is_err() {
        remove_temp_trust_file(&temp_path);
    }
    result
}

fn write_replacement_trust_temp_file(
    path: &Path,
    contents: &str,
    write_action: &'static str,
) -> Result<PathBuf, TrustError> {
    let parent = trust_file_parent(path);
    if !state::state_directory_exists(parent, "inspect trust directory")? {
        return Err(TrustError::io(
            write_action,
            parent,
            io::Error::new(io::ErrorKind::NotFound, "trust directory path is missing"),
        ));
    }

    for attempt in 0..16 {
        let temp_path = replacement_trust_temp_path(path, attempt);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(TrustError::io(write_action, &temp_path, error)),
        };

        let write_result = file
            .write_all(contents.as_bytes())
            .and_then(|_| file.sync_all());
        drop(file);

        if let Err(error) = write_result {
            remove_temp_trust_file(&temp_path);
            return Err(TrustError::io(write_action, &temp_path, error));
        }

        return Ok(temp_path);
    }

    Err(TrustError::io(
        write_action,
        path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique trust replacement file",
        ),
    ))
}

fn replace_trust_file_with_temp(
    path: &Path,
    temp_path: &Path,
    expected_metadata: &fs::Metadata,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), TrustError> {
    let Some(current_metadata) = regular_trust_file_metadata(path, open_action)? else {
        return Err(TrustError::io(
            open_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "trust file path is missing"),
        ));
    };
    if !trust_file_write_target_matches(expected_metadata, &current_metadata) {
        return Err(TrustError::io(
            open_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trust file path changed before replacement",
            ),
        ));
    }

    fs::rename(temp_path, path).map_err(|error| TrustError::io(write_action, path, error))
}

fn ensure_trust_file_contents_within_limit(
    path: &Path,
    contents_len: usize,
    action: &'static str,
) -> Result<(), TrustError> {
    if contents_len as u64 > MAX_TRUST_FILE_BYTES {
        return Err(TrustError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("trust file exceeds {MAX_TRUST_FILE_BYTES} bytes"),
            ),
        ));
    }
    Ok(())
}

fn trust_file_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn replacement_trust_temp_path(path: &Path, attempt: u8) -> PathBuf {
    let parent = trust_file_parent(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("trust");
    parent.join(format!(
        ".{file_name}.tmp-{}-{}-{attempt}",
        process::id(),
        current_unix_nanos()
    ))
}

fn remove_temp_trust_file(path: &Path) {
    let _ = fs::remove_file(path);
}

fn validate_opened_regular_trust_file(
    path: &Path,
    action: &'static str,
    expected_metadata: &fs::Metadata,
    file: &fs::File,
) -> Result<(), TrustError> {
    let Some(path_metadata) = regular_trust_file_metadata(path, action)? else {
        return Err(TrustError::io(
            action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "trust file path is missing"),
        ));
    };
    if !trust_file_metadata_matches(expected_metadata, &path_metadata) {
        return Err(TrustError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trust file path changed while opening",
            ),
        ));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| TrustError::io(action, path, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_TRUST_FILE_BYTES
        || !trust_file_metadata_matches(expected_metadata, &opened_metadata)
    {
        return Err(TrustError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "opened trust file does not match inspected path",
            ),
        ));
    }

    Ok(())
}

fn regular_trust_file_metadata(
    path: &Path,
    action: &'static str,
) -> Result<Option<fs::Metadata>, TrustError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(TrustError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "trust file path is not a regular file",
                    ),
                ));
            }
            if metadata.len() > MAX_TRUST_FILE_BYTES {
                return Err(TrustError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("trust file exceeds {MAX_TRUST_FILE_BYTES} bytes"),
                    ),
                ));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(TrustError::io(action, path, error)),
    }
}

fn trust_file_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && trust_file_identity_matches(expected, current)
}

fn trust_file_write_target_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    trust_file_stable_identity_matches(expected, current)
}

#[cfg(unix)]
fn trust_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    trust_file_stable_identity_matches(expected, current)
}

#[cfg(unix)]
fn trust_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn trust_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    trust_file_stable_identity_matches(expected, current)
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(windows)]
fn trust_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
}

#[cfg(not(any(unix, windows)))]
fn trust_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

#[cfg(not(any(unix, windows)))]
fn trust_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    trust_file_identity_matches(expected, current)
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
        insert_trust_value(&mut current, key, value)?;
    }

    if !current.is_empty() {
        peers.push(peer_from_values(&current)?);
    }

    Ok(peers)
}

fn insert_trust_value(
    values: &mut HashMap<String, String>,
    key: &str,
    value: &str,
) -> Result<(), TrustError> {
    let key = key.trim();
    if values.contains_key(key) {
        let reason = if key.is_empty() {
            "duplicate empty trust key".to_string()
        } else {
            format!("duplicate trust key {key}")
        };
        return Err(TrustError::InvalidRequest { reason });
    }
    values.insert(key.to_string(), clean_value(value));
    Ok(())
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
        direct_quic_endpoint: optional_direct_endpoint(values.get("direct_quic_endpoint"))?,
        signing_public_key_hex: optional_hex_field(
            values.get("signing_public_key_hex"),
            "signing public key",
        )?,
        signature_algorithm: optional_identifier(
            values.get("signature_algorithm"),
            "signature algorithm",
        )?,
        signature_key_id: optional_identifier(values.get("signature_key_id"), "signature key id")?,
        signature_hex: optional_hex_field(values.get("signature_hex"), "signature")?,
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
    relay_endpoint::validate_relay_endpoint(value).map_err(|error| {
        let reason = match error {
            RelayEndpointError::Empty => "relay endpoint cannot be empty",
            RelayEndpointError::Scheme => "relay endpoint must start with ws:// or wss://",
            RelayEndpointError::Invalid => "relay endpoint is invalid",
        };
        TrustError::InvalidRequest {
            reason: reason.to_string(),
        }
    })
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
        direct_quic_endpoint: card
            .direct_quic_endpoint
            .map(validate_direct_endpoint)
            .transpose()?,
        signing_public_key_hex: card
            .signing_public_key_hex
            .map(|value| validate_hex(value, "signing public key"))
            .transpose()?,
        signature_algorithm: card
            .signature_algorithm
            .map(|value| validate_identifier(value, "signature algorithm"))
            .transpose()?,
        signature_key_id: card
            .signature_key_id
            .map(|value| validate_identifier(value, "signature key id"))
            .transpose()?,
        signature_hex: card
            .signature_hex
            .map(|value| validate_hex(value, "signature"))
            .transpose()?,
    })
}

fn verify_peer_card_signature(card: &PeerCard) -> Result<(), TrustError> {
    let signature_fields = [
        card.signing_public_key_hex.as_ref(),
        card.signature_algorithm.as_ref(),
        card.signature_key_id.as_ref(),
        card.signature_hex.as_ref(),
    ];
    let present = signature_fields
        .iter()
        .filter(|value| value.is_some())
        .count();
    if present == 0 {
        return Ok(());
    }
    if present != signature_fields.len() {
        return Err(TrustError::InvalidRequest {
            reason: "signed peer card is missing signature fields".to_string(),
        });
    }
    if card.signature_algorithm.as_deref() != Some(security::AGENT_CARD_SIGNATURE_ALGORITHM) {
        return Err(TrustError::InvalidRequest {
            reason: "unsupported peer card signature algorithm".to_string(),
        });
    }

    let public_key_hex = card.signing_public_key_hex.as_deref().unwrap_or_default();
    let signature_hex = card.signature_hex.as_deref().unwrap_or_default();
    let current_signature_valid = security::verify_agent_card_signature(
        &canonical_peer_card(card),
        public_key_hex,
        signature_hex,
    )?;
    let legacy_signature_valid = card.direct_quic_endpoint.is_none()
        && security::verify_agent_card_signature(
            &legacy_canonical_peer_card(card),
            public_key_hex,
            signature_hex,
        )?;
    if !current_signature_valid && !legacy_signature_valid {
        return Err(TrustError::InvalidRequest {
            reason: "peer card signature verification failed".to_string(),
        });
    }

    Ok(())
}

fn canonical_peer_card(card: &PeerCard) -> String {
    format!(
        "conu-peer-card-v1\nnode_id={}\ndisplay_name={}\nexchange_public_key_hex={}\nrelay_endpoint={}\ndirect_quic_endpoint={}\n",
        card.node_id,
        card.display_name,
        card.exchange_public_key_hex,
        card.relay_endpoint,
        card.direct_quic_endpoint.as_deref().unwrap_or("")
    )
}

fn legacy_canonical_peer_card(card: &PeerCard) -> String {
    format!(
        "conu-peer-card-v1\nnode_id={}\ndisplay_name={}\nexchange_public_key_hex={}\nrelay_endpoint={}\n",
        card.node_id, card.display_name, card.exchange_public_key_hex, card.relay_endpoint
    )
}

fn optional_hex(value: Option<&String>) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| validate_hex(value, "exchange public key"))
        .transpose()
}

fn optional_hex_field(
    value: Option<&String>,
    field: &'static str,
) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| validate_hex(value, field))
        .transpose()
}

fn optional_identifier(
    value: Option<&String>,
    field: &'static str,
) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| validate_identifier(value, field))
        .transpose()
}

fn optional_endpoint(value: Option<&String>) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(validate_endpoint)
        .transpose()
}

fn optional_direct_endpoint(value: Option<&String>) -> Result<Option<String>, TrustError> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(validate_direct_endpoint)
        .transpose()
}

fn validate_direct_endpoint(value: String) -> Result<String, TrustError> {
    let value = value.trim().to_string();
    direct_transport::validate_direct_peer_endpoint(&value).map_err(|error| {
        TrustError::InvalidRequest {
            reason: error.to_string(),
        }
    })?;
    Ok(value)
}

fn configured_relay_endpoint(paths: &StatePaths) -> Result<String, TrustError> {
    let contents = match state::read_optional_regular_state_file(
        &paths.config,
        "inspect trust config",
        "read trust config",
    )? {
        Some(contents) => contents,
        None => return Ok(DEFAULT_RELAY_ENDPOINT.to_string()),
    };
    let values = parse_key_values(&contents)?;
    let endpoint = values
        .get("default_relay")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_RELAY_ENDPOINT.to_string());
    validate_endpoint(endpoint)
}

fn configured_direct_quic_endpoint(paths: &StatePaths) -> Result<Option<String>, TrustError> {
    direct_transport::configured_direct_quic_advertised_endpoint_from_paths(paths).map_err(
        |error| TrustError::InvalidRequest {
            reason: error.to_string(),
        },
    )
}

fn parse_key_values(contents: &str) -> Result<HashMap<String, String>, TrustError> {
    let mut values = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        insert_trust_value(&mut values, key, value)?;
    }

    Ok(values)
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
    fn new_pairing_invite_refuses_existing_file_without_overwrite() {
        let home = test_home("invite-create-collision");
        let paths = StatePaths::from_home(home);
        let invite = PairingInvite {
            code: "123456".to_string(),
            local_node_id: "node_local".to_string(),
            peer_node_id: "peer_existing".to_string(),
            display_name: "paired-peer-existing".to_string(),
            created_at_unix: 10,
            expires_at_unix: 20,
            status: PairingStatus::Pending,
        };
        write_new_pairing_invite(&paths, &invite).expect("first invite writes");
        let path = paths.pairing_invites_dir.join("123456.pair");
        let original = fs::read_to_string(&path).expect("original invite reads");
        let mut replacement = invite.clone();
        replacement.display_name = "paired-peer-replacement".to_string();

        let error = write_new_pairing_invite(&paths, &replacement)
            .expect_err("existing invite should fail closed");

        assert!(error.to_string().contains("create pairing invitation"));
        assert_eq!(
            fs::read_to_string(&path).expect("invite still reads"),
            original
        );
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
    fn used_pairing_archive_collision_fails_before_trust_mutation() {
        let home = test_home("used-collision");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.pairing_used_dir).expect("used dir creates");
        let used_path = paths.pairing_used_dir.join(format!("{}.pair", invite.code));
        fs::write(&used_path, "existing used invite").expect("existing used invite writes");
        let pending_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));

        let error = join_pairing_code(Some(home.clone()), &invite.code)
            .expect_err("used invite collision should fail closed");

        assert!(
            error
                .to_string()
                .contains("reserve used pairing invitation")
        );
        assert_eq!(
            fs::read_to_string(&used_path).expect("used invite reads"),
            "existing used invite"
        );
        assert!(
            fs::read_to_string(&pending_path)
                .expect("pending invite reads")
                .contains("status = \"pending\"")
        );
        assert!(list_peers(Some(home)).expect("peers read").is_empty());
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

    #[test]
    fn trust_store_duplicate_key_fails_closed_without_payloads() {
        let home = test_home("trust-duplicate-key");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        fs::write(
            &init.paths.trust_store,
            "# conU trust store\nversion = \"1\"\n\n[[peer]]\npeer_node_id = \"peer.safe\"\npeer_node_id = \"private.message.contents\"\ndisplay_name = \"Peer Safe\"\nstatus = \"trusted\"\nsource = \"test\"\npairing_code_hash = \"pair_test\"\nexchange_public_key_hex = \"\"\nrelay_endpoint = \"\"\ndirect_quic_endpoint = \"\"\nsigning_public_key_hex = \"\"\nsignature_algorithm = \"\"\nsignature_key_id = \"\"\nsignature_hex = \"\"\ncreated_at_unix = 1\nupdated_at_unix = 1\npayload_displayed = false\n",
        )
        .expect("trust store writes");

        let error = list_peers(Some(home)).expect_err("duplicate trust key fails closed");

        assert!(
            error
                .to_string()
                .contains("duplicate trust key peer_node_id")
        );
        assert!(!error.to_string().contains("private.message.contents"));
    }

    #[test]
    fn pairing_invite_duplicate_key_fails_closed_without_payloads() {
        let home = test_home("invite-duplicate-key");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home.clone());
        let invite_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));
        fs::write(
            invite_path,
            format!(
                "version = \"1\"\ncode = \"{}\"\nlocal_node_id = \"node_local\"\npeer_node_id = \"peer_safe\"\ndisplay_name = \"paired-peer-safe\"\ncreated_at_unix = 1\nexpires_at_unix = 601\nstatus = \"pending\"\nstatus = \"private message contents\"\npayload_displayed = false\n",
                invite.code
            ),
        )
        .expect("invite writes");

        let error = join_pairing_code(Some(home.clone()), &invite.code)
            .expect_err("duplicate invite key fails closed");
        let peers = list_peers(Some(home)).expect("peers read");

        assert!(error.to_string().contains("duplicate trust key status"));
        assert!(!error.to_string().contains("private message contents"));
        assert!(peers.is_empty());
    }

    #[test]
    fn trust_store_read_rejects_oversized_file_without_printing_contents() {
        let home = test_home("trust-store-read-oversized");
        let init = state::init_state(Some(home)).expect("state initializes");
        let paths = init.paths;
        let private_marker = "private-trust-marker";
        let mut contents = format!("# {private_marker}\n");
        contents.push_str(&"a".repeat((MAX_TRUST_FILE_BYTES + 1) as usize));
        fs::write(&paths.trust_store, contents).expect("oversized trust store writes");

        let error = read_trust_store(&paths).expect_err("oversized trust store should fail closed");
        let error = error.to_string();

        assert!(error.contains("trust file exceeds"));
        assert!(!error.contains(private_marker));
    }

    #[test]
    fn pairing_invite_read_rejects_oversized_file_without_printing_contents() {
        let home = test_home("pairing-invite-read-oversized");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home);
        let invite_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));
        let private_marker = "private-invite-marker";
        let mut contents = format!("# {private_marker}\n");
        contents.push_str(&"a".repeat((MAX_TRUST_FILE_BYTES + 1) as usize));
        fs::write(invite_path, contents).expect("oversized pairing invite writes");

        let error = read_pairing_invite(&paths, &invite.code)
            .expect_err("oversized pairing invite should fail closed");
        let error = error.to_string();

        assert!(error.contains("trust file exceeds"));
        assert!(!error.contains(private_marker));
    }

    #[test]
    fn opened_trust_write_guard_rejects_mismatched_handle() {
        let home = test_home("opened-trust-write-guard");
        fs::create_dir_all(&home).expect("home creates");
        let target = home.join("trust-target.toml");
        let replacement = home.join("trust-replacement.toml");
        fs::write(&target, "version = \"1\"\n").expect("target writes");
        std::thread::sleep(std::time::Duration::from_millis(2));
        fs::write(&replacement, "version = \"1\"\nchanged = true\n").expect("replacement writes");

        let expected = regular_trust_file_metadata(&target, "inspect trust write target")
            .expect("target metadata reads")
            .expect("target exists");
        let opened = OpenOptions::new()
            .write(true)
            .open(&replacement)
            .expect("replacement opens");

        let error = validate_opened_regular_trust_file(
            &target,
            "inspect trust write target",
            &expected,
            &opened,
        )
        .expect_err("mismatched opened handle should fail closed");

        assert!(
            error
                .to_string()
                .contains("opened trust file does not match inspected path")
        );
        assert_eq!(
            fs::read_to_string(&target).expect("target reads"),
            "version = \"1\"\n"
        );
        assert_eq!(
            fs::read_to_string(&replacement).expect("replacement reads"),
            "version = \"1\"\nchanged = true\n"
        );
    }

    #[test]
    fn write_trust_file_replaces_existing_contents() {
        let home = test_home("trust-atomic-rewrite");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("trust.toml");
        fs::write(&path, "version = \"1\"\n").expect("trust writes");

        write_trust_file(
            &path,
            "version = \"1\"\nupdated = true\n",
            "create trust store",
            "open trust store",
            "write trust store",
        )
        .expect("trust rewrites");

        assert_eq!(
            fs::read_to_string(&path).expect("trust reads"),
            "version = \"1\"\nupdated = true\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_trust_file_rejects_unwritable_parent_without_truncating_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let home = test_home("trust-atomic-rewrite-unwritable-parent");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("trust.toml");
        let original = test_trust_store_contents();
        fs::write(&path, original).expect("trust writes");
        let original_permissions = fs::metadata(&home)
            .expect("home metadata reads")
            .permissions();
        let mut locked_permissions = original_permissions.clone();
        locked_permissions.set_mode(0o500);
        fs::set_permissions(&home, locked_permissions).expect("home permissions lock");

        let result = write_trust_file(
            &path,
            "version = \"1\"\nchanged = true\n",
            "create unwritable trust store",
            "open unwritable trust store",
            "write unwritable trust store",
        );

        fs::set_permissions(&home, original_permissions).expect("home permissions restore");
        let error = result.expect_err("unwritable parent should fail before replacement");

        assert!(error.to_string().contains("write unwritable trust store"));
        assert_eq!(
            fs::read_to_string(&path).expect("trust reads"),
            original,
            "failed staged rewrite must leave existing trust store unchanged"
        );
    }

    #[test]
    fn manual_peer_card_accepts_wss_relay_endpoint() {
        let alice_home = test_home("wss-alice");
        let bob_home = test_home("wss-bob");
        let bob = state::init_state(Some(bob_home.clone())).expect("bob state initializes");
        fs::write(
            &bob.paths.config,
            "version = \"1\"\ndefault_relay = \"wss://relay.example.com/conu\"\n",
        )
        .expect("bob config writes");
        let bob_card = export_peer_card(Some(bob_home)).expect("bob card exports");

        let peer = trust_peer_card(Some(alice_home), bob_card).expect("wss peer is trusted");

        assert_eq!(peer.source, "manual_signed_peer_card");
        assert!(peer.signing_public_key_hex.is_some());
        assert!(peer.signature_hex.is_some());
        assert_eq!(
            peer.relay_endpoint.as_deref(),
            Some("wss://relay.example.com/conu")
        );
    }

    #[test]
    fn relay_endpoint_rejects_secret_bearing_config_without_echoing_value() {
        let home = test_home("secret-relay-config");
        let init = state::init_state(Some(home)).expect("state initializes");
        let secret_endpoint = "wss://user:secret@relay.example.com/conu?token=private#fragment";
        fs::write(
            &init.paths.config,
            format!("version = \"1\"\ndefault_relay = \"{secret_endpoint}\"\n"),
        )
        .expect("config writes");

        let error = configured_relay_endpoint(&init.paths)
            .expect_err("secret-bearing relay endpoint should fail");
        let rendered = error.to_string();

        assert!(rendered.contains("relay endpoint is invalid"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("token=private"));
    }

    #[test]
    fn legacy_peer_card_rejects_secret_bearing_relay_endpoint_without_echoing_value() {
        let alice_home = test_home("secret-card-alice");
        let bob_home = test_home("secret-card-bob");
        let mut bob_card = export_peer_card(Some(bob_home)).expect("bob card exports");
        bob_card.relay_endpoint =
            "wss://user:secret@relay.example.com/conu?token=private#fragment".to_string();
        bob_card.signing_public_key_hex = None;
        bob_card.signature_algorithm = None;
        bob_card.signature_key_id = None;
        bob_card.signature_hex = None;

        let error = trust_peer_card(Some(alice_home), bob_card)
            .expect_err("secret-bearing relay endpoint should fail");
        let rendered = error.to_string();

        assert!(rendered.contains("relay endpoint is invalid"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("token=private"));
    }

    #[test]
    fn signed_peer_card_rejects_tampering_without_echoing_secrets() {
        let alice_home = test_home("signed-alice");
        let bob_home = test_home("signed-bob");
        let mut bob_card = export_peer_card(Some(bob_home)).expect("bob card exports");

        bob_card.relay_endpoint = "wss://relay.example.com/tampered".to_string();
        let error =
            trust_peer_card(Some(alice_home), bob_card).expect_err("tampered card is rejected");

        assert!(error.to_string().contains("signature verification failed"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn unsigned_legacy_peer_card_still_imports_with_unsigned_source() {
        let alice_home = test_home("legacy-alice");
        let bob_home = test_home("legacy-bob");
        let mut bob_card = export_peer_card(Some(bob_home)).expect("bob card exports");
        bob_card.signing_public_key_hex = None;
        bob_card.signature_algorithm = None;
        bob_card.signature_key_id = None;
        bob_card.signature_hex = None;

        let peer = trust_peer_card(Some(alice_home), bob_card).expect("legacy card imports");

        assert_eq!(peer.source, "manual_peer_card");
        assert!(peer.signing_public_key_hex.is_none());
        assert!(peer.signature_hex.is_none());
    }

    #[test]
    fn signed_legacy_peer_card_without_direct_endpoint_still_imports() {
        let alice_home = test_home("legacy-signed-alice");
        let bob_home = test_home("legacy-signed-bob");
        let bob = state::init_state(Some(bob_home)).expect("bob state initializes");
        let material = security::local_peer_key_material(&bob.paths).expect("bob keys");
        let mut bob_card = PeerCard {
            node_id: bob.node.node_id,
            display_name: bob.node.display_name,
            exchange_public_key_hex: material.local_exchange_public_key_hex,
            relay_endpoint: "ws://127.0.0.1:8787".to_string(),
            direct_quic_endpoint: None,
            signing_public_key_hex: None,
            signature_algorithm: None,
            signature_key_id: None,
            signature_hex: None,
        };
        let signature = security::sign_agent_card_from_paths(
            &bob.paths,
            &legacy_canonical_peer_card(&bob_card),
        )
        .expect("legacy peer card signs");
        bob_card.signing_public_key_hex = Some(signature.public_key_hex);
        bob_card.signature_algorithm = Some(signature.algorithm);
        bob_card.signature_key_id = Some(signature.key_id);
        bob_card.signature_hex = Some(signature.signature_hex);

        let peer = trust_peer_card(Some(alice_home), bob_card).expect("legacy signed card imports");

        assert_eq!(peer.source, "manual_signed_peer_card");
        assert!(peer.direct_quic_endpoint.is_none());
    }

    #[test]
    fn peer_card_rejects_unusable_direct_endpoint_literal() {
        let card = PeerCard {
            node_id: "node_peer".to_string(),
            display_name: "Peer".to_string(),
            exchange_public_key_hex: "aa".to_string(),
            relay_endpoint: "ws://127.0.0.1:8787".to_string(),
            direct_quic_endpoint: Some("quic://0.0.0.0:9443".to_string()),
            signing_public_key_hex: None,
            signature_algorithm: None,
            signature_key_id: None,
            signature_hex: None,
        };

        let error = validate_peer_card(card)
            .expect_err("unusable direct endpoint literal should fail closed");

        assert!(error.to_string().contains("unspecified address"));
    }

    #[cfg(unix)]
    #[test]
    fn trust_config_read_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("trust-config-read-symlink");
        let init = state::init_state(Some(home)).expect("state initializes");
        let outside = init.paths.home.join("outside-config.toml");
        fs::write(
            &outside,
            "version = \"1\"\ndefault_relay = \"wss://relay.example.com/conu\"\n",
        )
        .expect("outside config writes");
        fs::remove_file(&init.paths.config).expect("config removes");
        symlink(&outside, &init.paths.config).expect("config symlink creates");

        let error = configured_relay_endpoint(&init.paths)
            .expect_err("trust config symlink should fail closed");

        assert!(error.to_string().contains("inspect trust config"));
        assert!(
            fs::symlink_metadata(&init.paths.config)
                .expect("config symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_write_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("trust-store-write-symlink");
        let init = state::init_state(Some(home)).expect("state initializes");
        let paths = init.paths;
        let outside = paths.home.join("outside-trust-store.toml");
        fs::write(&outside, "outside trust store\n").expect("outside writes");
        fs::remove_file(&paths.trust_store).expect("trust store removes");
        symlink(&outside, &paths.trust_store).expect("trust store symlink creates");

        let error = write_trust_store(&paths, &[test_peer("peer_symlink")])
            .expect_err("trust store symlink should fail closed");

        assert!(error.to_string().contains("open trust store"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "outside trust store\n"
        );
        assert!(
            fs::symlink_metadata(&paths.trust_store)
                .expect("trust store symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_read_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("trust-store-read-symlink");
        let init = state::init_state(Some(home)).expect("state initializes");
        let paths = init.paths;
        let outside = paths.home.join("outside-trust-store.toml");
        let outside_contents =
            "# conU trust store\nversion = \"1\"\n\n[[peer]]\npeer_node_id = \"peer_outside\"\n";
        fs::write(&outside, outside_contents).expect("outside writes");
        fs::remove_file(&paths.trust_store).expect("trust store removes");
        symlink(&outside, &paths.trust_store).expect("trust store symlink creates");

        let error = read_trust_store(&paths).expect_err("trust store symlink should fail closed");

        assert!(error.to_string().contains("inspect trust store"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            outside_contents
        );
    }

    #[cfg(unix)]
    #[test]
    fn pairing_invite_write_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-invite-write-symlink");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home);
        let invite_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));
        let outside = paths.home.join("outside-pairing-invite.toml");
        fs::write(&outside, "outside invite\n").expect("outside writes");
        fs::remove_file(&invite_path).expect("invite removes");
        symlink(&outside, &invite_path).expect("invite symlink creates");
        let mut replacement = invite.clone();
        replacement.status = PairingStatus::Used;

        let error = write_pairing_invite(&paths, &replacement)
            .expect_err("pairing invite symlink should fail closed");

        assert!(error.to_string().contains("open pairing invitation"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "outside invite\n"
        );
        assert!(
            fs::symlink_metadata(&invite_path)
                .expect("invite symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pairing_invite_read_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-invite-read-symlink");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home);
        let invite_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));
        let outside = paths.home.join("outside-pairing-invite.toml");
        fs::write(
            &outside,
            "version = \"1\"\ncode = \"123456\"\nlocal_node_id = \"node_outside\"\n",
        )
        .expect("outside writes");
        fs::remove_file(&invite_path).expect("invite removes");
        symlink(&outside, &invite_path).expect("invite symlink creates");

        let error = read_pairing_invite(&paths, &invite.code)
            .expect_err("pairing invite symlink should fail closed");

        assert!(error.to_string().contains("inspect pairing invitation"));
        assert!(
            fs::read_to_string(&outside)
                .expect("outside reads")
                .contains("node_outside")
        );
    }

    #[cfg(unix)]
    #[test]
    fn trust_home_symlink_is_rejected_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("trust-home-read-symlink");
        let outside = home.with_extension("outside-trust-home-read");
        fs::create_dir_all(&outside).expect("outside home creates");
        fs::write(outside.join("trust.toml"), test_trust_store_contents())
            .expect("outside trust store writes");
        symlink(&outside, &home).expect("home symlink creates");
        let paths = StatePaths::from_home(home.clone());

        let error = read_trust_store(&paths).expect_err("symlinked home should fail closed");

        assert!(error.to_string().contains("inspect state directory"));
        assert_eq!(
            fs::read_to_string(outside.join("trust.toml")).expect("outside trust reads"),
            test_trust_store_contents()
        );
        assert!(
            fs::symlink_metadata(&home)
                .expect("home symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn trust_home_symlink_is_rejected_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("trust-home-write-symlink");
        let outside = home.with_extension("outside-trust-home-write");
        fs::create_dir_all(&outside).expect("outside home creates");
        symlink(&outside, &home).expect("home symlink creates");
        let paths = StatePaths::from_home(home.clone());

        let error = write_trust_store(&paths, &[test_peer("peer_symlink_home")])
            .expect_err("symlinked home should fail closed");

        assert!(error.to_string().contains("state directory"));
        assert!(!outside.join("trust.toml").exists());
        assert!(
            fs::symlink_metadata(&home)
                .expect("home symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pairing_directory_symlink_is_rejected_without_writing_invite() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-dir-write-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let outside = home.with_extension("outside-pairing-dir-write");
        fs::remove_dir_all(&init.paths.pairing_dir).expect("pairing dir removes");
        fs::create_dir_all(&outside).expect("outside pairing dir creates");
        symlink(&outside, &init.paths.pairing_dir).expect("pairing dir symlink creates");

        let error = write_new_pairing_invite(&init.paths, &test_invite())
            .expect_err("symlinked pairing directory should fail closed");

        assert!(error.to_string().contains("state directory"));
        assert!(!outside.join("invites").exists());
        assert!(
            fs::symlink_metadata(&init.paths.pairing_dir)
                .expect("pairing dir metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pairing_directory_symlink_is_rejected_without_reading_invite() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-dir-read-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let outside = home.with_extension("outside-pairing-dir-read");
        fs::remove_dir_all(&init.paths.pairing_dir).expect("pairing dir removes");
        fs::create_dir_all(outside.join("invites")).expect("outside invites creates");
        fs::write(
            outside.join("invites").join("123456.pair"),
            test_pairing_invite_contents(),
        )
        .expect("outside invite writes");
        symlink(&outside, &init.paths.pairing_dir).expect("pairing dir symlink creates");

        let error = read_pairing_invite(&init.paths, "123456")
            .expect_err("symlinked pairing directory should fail closed");

        assert!(error.to_string().contains("inspect pairing directory"));
        assert_eq!(
            fs::read_to_string(outside.join("invites").join("123456.pair"))
                .expect("outside invite reads"),
            test_pairing_invite_contents()
        );
    }

    #[cfg(unix)]
    #[test]
    fn used_pairing_invite_symlink_is_rejected_without_moving_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-used-source-symlink");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home.clone());
        let pending_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));
        let used_path = paths.pairing_used_dir.join(format!("{}.pair", invite.code));
        let outside = home.with_extension("outside-pairing-used-source");
        fs::write(&outside, test_pairing_invite_contents()).expect("outside invite writes");
        fs::remove_file(&pending_path).expect("pending invite removes");
        symlink(&outside, &pending_path).expect("pending invite symlink creates");

        let error = move_used_invite(&paths, &invite)
            .expect_err("symlinked pending invite should fail closed");

        assert!(
            error
                .to_string()
                .contains("inspect used pairing invitation before archive")
        );
        assert!(!used_path.exists());
        assert_eq!(
            fs::read_to_string(&outside).expect("outside invite reads"),
            test_pairing_invite_contents()
        );
        assert!(
            fs::symlink_metadata(&pending_path)
                .expect("pending invite metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pairing_invites_directory_symlink_is_rejected_without_moving_invite() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-invites-dir-move-symlink");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-pairing-invites-dir-move");
        let outside_invite = outside.join(format!("{}.pair", invite.code));
        fs::remove_dir_all(&paths.pairing_invites_dir).expect("invites dir removes");
        fs::create_dir_all(&outside).expect("outside invites dir creates");
        fs::write(&outside_invite, test_pairing_invite_contents()).expect("outside invite writes");
        symlink(&outside, &paths.pairing_invites_dir).expect("invites dir symlink creates");

        let error = move_used_invite(&paths, &invite)
            .expect_err("symlinked invites directory should fail closed");

        assert!(error.to_string().contains("state directory"));
        assert_eq!(
            fs::read_to_string(&outside_invite).expect("outside invite reads"),
            test_pairing_invite_contents()
        );
        assert!(
            !paths
                .pairing_used_dir
                .join(format!("{}.pair", invite.code))
                .exists()
        );
        assert!(
            fs::symlink_metadata(&paths.pairing_invites_dir)
                .expect("invites dir metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn used_pairing_directory_symlink_is_rejected_without_moving_invite() {
        use std::os::unix::fs::symlink;

        let home = test_home("pairing-used-dir-symlink");
        let invite = create_pairing_invite(Some(home.clone())).expect("invite creates");
        let paths = StatePaths::from_home(home.clone());
        let pending_path = paths
            .pairing_invites_dir
            .join(format!("{}.pair", invite.code));
        let outside = home.with_extension("outside-pairing-used-dir");
        fs::remove_dir_all(&paths.pairing_used_dir).expect("used dir removes");
        fs::create_dir_all(&outside).expect("outside used dir creates");
        symlink(&outside, &paths.pairing_used_dir).expect("used dir symlink creates");

        let error = move_used_invite(&paths, &invite)
            .expect_err("symlinked used directory should fail closed");

        assert!(error.to_string().contains("state directory"));
        assert!(pending_path.exists());
        assert!(!outside.join(format!("{}.pair", invite.code)).exists());
        assert!(
            fs::symlink_metadata(&paths.pairing_used_dir)
                .expect("used dir metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    fn test_peer(peer_node_id: &str) -> TrustedPeer {
        TrustedPeer {
            peer_node_id: peer_node_id.to_string(),
            display_name: peer_node_id.to_string(),
            status: TrustStatus::Trusted,
            source: "test".to_string(),
            pairing_code_hash: "pair_test".to_string(),
            exchange_public_key_hex: None,
            relay_endpoint: None,
            direct_quic_endpoint: None,
            signing_public_key_hex: None,
            signature_algorithm: None,
            signature_key_id: None,
            signature_hex: None,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    #[cfg(unix)]
    fn test_invite() -> PairingInvite {
        PairingInvite {
            code: "123456".to_string(),
            local_node_id: "node_local".to_string(),
            peer_node_id: "peer_test".to_string(),
            display_name: "paired-peer-test".to_string(),
            created_at_unix: 1,
            expires_at_unix: 601,
            status: PairingStatus::Pending,
        }
    }

    #[cfg(unix)]
    fn test_pairing_invite_contents() -> &'static str {
        "version = \"1\"\ncode = \"123456\"\nlocal_node_id = \"node_local\"\npeer_node_id = \"peer_test\"\ndisplay_name = \"paired-peer-test\"\ncreated_at_unix = 1\nexpires_at_unix = 601\nstatus = \"pending\"\npayload_displayed = false\n"
    }

    #[cfg(unix)]
    fn test_trust_store_contents() -> &'static str {
        "# conU trust store\nversion = \"1\"\n\n[[peer]]\npeer_node_id = \"peer_test\"\ndisplay_name = \"Peer Test\"\nstatus = \"trusted\"\nsource = \"test\"\npairing_code_hash = \"pair_test\"\nexchange_public_key_hex = \"\"\nrelay_endpoint = \"\"\ndirect_quic_endpoint = \"\"\nsigning_public_key_hex = \"\"\nsignature_algorithm = \"\"\nsignature_key_id = \"\"\nsignature_hex = \"\"\ncreated_at_unix = 1\nupdated_at_unix = 1\npayload_displayed = false\n"
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-trust-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
