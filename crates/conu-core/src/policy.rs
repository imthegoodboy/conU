//! Peer-scoped communication policy.
//!
//! Trust says which nodes are known. Policy says which communication surfaces a
//! trusted peer may use with this local runtime. Policy records are metadata
//! only and never contain payload bytes.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus};

const POLICY_VERSION: &str = "1";

/// One permission surface controlled per trusted peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPermission {
    Messages,
    Streams,
    Rooms,
    Files,
    Mailbox,
}

impl PeerPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::Streams => "streams",
            Self::Rooms => "rooms",
            Self::Files => "files",
            Self::Mailbox => "mailbox",
        }
    }
}

/// Persisted peer-scoped communication grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicyRecord {
    pub peer_node_id: String,
    pub messages: bool,
    pub streams: bool,
    pub rooms: bool,
    pub files: bool,
    pub mailbox: bool,
    pub updated_at_unix: u64,
}

impl PeerPolicyRecord {
    pub fn denied(peer_node_id: impl Into<String>) -> Self {
        Self {
            peer_node_id: peer_node_id.into(),
            messages: false,
            streams: false,
            rooms: false,
            files: false,
            mailbox: false,
            updated_at_unix: 0,
        }
    }

    pub const fn allows(&self, permission: PeerPermission) -> bool {
        match permission {
            PeerPermission::Messages => self.messages,
            PeerPermission::Streams => self.streams,
            PeerPermission::Rooms => self.rooms,
            PeerPermission::Files => self.files,
            PeerPermission::Mailbox => self.mailbox,
        }
    }

    pub const fn has_any_grant(&self) -> bool {
        self.messages || self.streams || self.rooms || self.files || self.mailbox
    }
}

/// Partial policy update. Unset fields preserve existing values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerPolicyUpdate {
    pub messages: Option<bool>,
    pub streams: Option<bool>,
    pub rooms: Option<bool>,
    pub files: Option<bool>,
    pub mailbox: Option<bool>,
}

impl PeerPolicyUpdate {
    pub const fn empty() -> Self {
        Self {
            messages: None,
            streams: None,
            rooms: None,
            files: None,
            mailbox: None,
        }
    }

    pub const fn has_changes(&self) -> bool {
        self.messages.is_some()
            || self.streams.is_some()
            || self.rooms.is_some()
            || self.files.is_some()
            || self.mailbox.is_some()
    }
}

/// Errors produced by peer policy operations.
#[derive(Debug)]
pub enum PolicyError {
    State(StateError),
    Trust(trust::TrustError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRecord {
        reason: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRecord { reason } => write!(formatter, "invalid peer policy: {reason}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<StateError> for PolicyError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<trust::TrustError> for PolicyError {
    fn from(error: trust::TrustError) -> Self {
        Self::Trust(error)
    }
}

/// List explicit peer policy records.
pub fn list_peer_policies(
    home_override: Option<PathBuf>,
) -> Result<Vec<PeerPolicyRecord>, PolicyError> {
    let paths = StatePaths::resolve(home_override)?;
    read_policies(&paths)
}

/// Read one peer's effective policy. Missing records deny all permissions.
pub fn peer_policy(
    home_override: Option<PathBuf>,
    peer_node_id: &str,
) -> Result<PeerPolicyRecord, PolicyError> {
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    let paths = StatePaths::resolve(home_override)?;
    effective_policy_from_paths(&paths, &peer_node_id)
}

/// Set one trusted peer's communication policy.
pub fn set_peer_policy(
    home_override: Option<PathBuf>,
    peer_node_id: &str,
    update: PeerPolicyUpdate,
) -> Result<PeerPolicyRecord, PolicyError> {
    if !update.has_changes() {
        return Err(PolicyError::InvalidRecord {
            reason: "at least one policy field must be set".to_string(),
        });
    }

    let init = state::init_state(home_override)?;
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    ensure_peer_is_trusted(&init.paths, &peer_node_id)?;

    let mut policies = read_policies(&init.paths)?;
    let mut record = policies
        .iter()
        .find(|policy| policy.peer_node_id == peer_node_id)
        .cloned()
        .unwrap_or_else(|| PeerPolicyRecord::denied(peer_node_id.clone()));

    if let Some(value) = update.messages {
        record.messages = value;
    }
    if let Some(value) = update.streams {
        record.streams = value;
    }
    if let Some(value) = update.rooms {
        record.rooms = value;
    }
    if let Some(value) = update.files {
        record.files = value;
    }
    if let Some(value) = update.mailbox {
        record.mailbox = value;
    }
    record.updated_at_unix = current_unix_seconds();

    policies.retain(|policy| policy.peer_node_id != record.peer_node_id);
    policies.push(record.clone());
    write_policies(&init.paths, &policies)?;

    Ok(record)
}

/// Enforce one peer permission from already resolved state paths.
pub fn ensure_peer_allowed_from_paths(
    paths: &StatePaths,
    peer_node_id: &str,
    permission: PeerPermission,
) -> Result<(), PolicyError> {
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    ensure_peer_is_trusted(paths, &peer_node_id)?;
    let record = effective_policy_from_paths(paths, &peer_node_id)?;
    if !record.allows(permission) {
        return Err(PolicyError::InvalidRecord {
            reason: format!("peer is not allowed to use {}", permission.as_str()),
        });
    }
    Ok(())
}

fn effective_policy_from_paths(
    paths: &StatePaths,
    peer_node_id: &str,
) -> Result<PeerPolicyRecord, PolicyError> {
    Ok(read_policies(paths)?
        .into_iter()
        .find(|policy| policy.peer_node_id == peer_node_id)
        .unwrap_or_else(|| PeerPolicyRecord::denied(peer_node_id.to_string())))
}

fn ensure_peer_is_trusted(paths: &StatePaths, peer_node_id: &str) -> Result<(), PolicyError> {
    let trusted = trust::list_peers(Some(paths.home.clone()))?
        .into_iter()
        .any(|peer| peer.peer_node_id == peer_node_id && peer.status == TrustStatus::Trusted);
    if !trusted {
        return Err(PolicyError::InvalidRecord {
            reason: "peer is not trusted locally".to_string(),
        });
    }
    Ok(())
}

fn read_policies(paths: &StatePaths) -> Result<Vec<PeerPolicyRecord>, PolicyError> {
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.policy_store,
        "inspect peer policy store",
        "read peer policy store",
    )?
    else {
        return Ok(Vec::new());
    };
    let mut policies = Vec::new();
    let mut current = HashMap::new();
    let version_line = format!("version = \"{POLICY_VERSION}\"");

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == version_line {
            continue;
        }
        if line == "[[peer_policy]]" {
            if !current.is_empty() {
                policies.push(policy_from_values(&current)?);
                current.clear();
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        insert_record_value(&mut current, key, value)?;
    }

    if !current.is_empty() {
        policies.push(policy_from_values(&current)?);
    }

    Ok(policies)
}

fn insert_record_value(
    values: &mut HashMap<String, String>,
    key: &str,
    value: &str,
) -> Result<(), PolicyError> {
    let key = key.trim();
    if values.contains_key(key) {
        let reason = if key.is_empty() {
            "duplicate empty key".to_string()
        } else {
            format!("duplicate {key}")
        };
        return Err(PolicyError::InvalidRecord { reason });
    }
    values.insert(key.to_string(), clean_value(value));
    Ok(())
}

fn write_policies(paths: &StatePaths, policies: &[PeerPolicyRecord]) -> Result<(), PolicyError> {
    let mut sorted = policies.to_vec();
    sorted.sort_by(|left, right| left.peer_node_id.cmp(&right.peer_node_id));

    let mut contents = format!("# conU peer policy store\nversion = \"{POLICY_VERSION}\"\n");
    for policy in sorted {
        contents.push_str("\n[[peer_policy]]\n");
        contents.push_str(&format!(
            "peer_node_id = \"{}\"\n",
            escape_file_value(&policy.peer_node_id)
        ));
        contents.push_str(&format!("messages = {}\n", policy.messages));
        contents.push_str(&format!("streams = {}\n", policy.streams));
        contents.push_str(&format!("rooms = {}\n", policy.rooms));
        contents.push_str(&format!("files = {}\n", policy.files));
        contents.push_str(&format!("mailbox = {}\n", policy.mailbox));
        contents.push_str(&format!("updated_at_unix = {}\n", policy.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.policy_store,
        &contents,
        "inspect peer policy store",
        "create peer policy store",
        "open peer policy store",
        "write peer policy store",
    )?;
    Ok(())
}

fn policy_from_values(values: &HashMap<String, String>) -> Result<PeerPolicyRecord, PolicyError> {
    Ok(PeerPolicyRecord {
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        messages: parse_bool(values, "messages")?,
        streams: parse_bool(values, "streams")?,
        rooms: parse_bool(values, "rooms")?,
        files: parse_bool(values, "files")?,
        mailbox: parse_bool(values, "mailbox")?,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, PolicyError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| PolicyError::InvalidRecord {
            reason: format!("missing {key}"),
        })
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, PolicyError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(PolicyError::InvalidRecord {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 140 {
        return Err(PolicyError::InvalidRecord {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(PolicyError::InvalidRecord {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn parse_bool(values: &HashMap<String, String>, key: &'static str) -> Result<bool, PolicyError> {
    match values.get(key).map(String::as_str) {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(_) => Err(PolicyError::InvalidRecord {
            reason: format!("{key} must be true or false"),
        }),
    }
}

fn parse_u64(value: &str) -> Result<u64, PolicyError> {
    value
        .parse::<u64>()
        .map_err(|_| PolicyError::InvalidRecord {
            reason: "expected unsigned integer".to_string(),
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

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust;
    use std::env;
    use std::fs;
    use std::process;

    #[test]
    fn missing_peer_policy_denies_by_default() {
        let home = test_home("default-deny");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home), &invite.code).expect("joins");

        let error = ensure_peer_allowed_from_paths(
            &init.paths,
            &joined.peer.peer_node_id,
            PeerPermission::Messages,
        )
        .expect_err("missing policy denies");

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("private message contents"));
    }

    #[test]
    fn set_peer_policy_updates_grants_without_payloads() {
        let home = test_home("set");
        state::init_state(Some(home.clone())).expect("state initializes");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("joins");
        let update = PeerPolicyUpdate {
            messages: Some(true),
            streams: Some(false),
            rooms: Some(true),
            files: None,
            mailbox: None,
        };

        let record = set_peer_policy(Some(home.clone()), &joined.peer.peer_node_id, update)
            .expect("policy updates");
        let policies = list_peer_policies(Some(home.clone())).expect("policies list");
        let contents = fs::read_to_string(home.join("policy.toml")).expect("policy reads");

        assert!(record.messages);
        assert!(!record.streams);
        assert!(record.rooms);
        assert_eq!(policies.len(), 1);
        assert!(contents.contains("payload_displayed = false"));
        assert!(!contents.contains("private message contents"));
    }

    #[test]
    fn peer_policy_duplicate_permission_key_fails_closed_without_payloads() {
        let home = test_home("duplicate-key");
        state::init_state(Some(home.clone())).expect("state initializes");
        fs::write(
            home.join("policy.toml"),
            "# conU peer policy store\nversion = \"1\"\n\n[[peer_policy]]\npeer_node_id = \"peer.codex\"\nmessages = false\nmessages = true\nstreams = false\nrooms = false\nfiles = false\nmailbox = false\nupdated_at_unix = 1\npayload_displayed = false\nsecret_payload = \"private message contents\"\n",
        )
        .expect("policy writes");

        let error = list_peer_policies(Some(home)).expect_err("duplicate key fails closed");

        assert!(error.to_string().contains("duplicate messages"));
        assert!(!error.to_string().contains("private message contents"));
    }

    fn test_home(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "conu-policy-test-{label}-{}-{}",
            process::id(),
            current_unix_seconds()
        ))
    }
}
