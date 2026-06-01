//! Local persistent state for conU.
//!
//! Phase 11 keeps this local-first: a locally generated node id, security key
//! material, config, trust store, pairing invitations, agent registry, runtime
//! metadata, gateway inboxes, encrypted local message inboxes, and streams.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::PROTOCOL_VERSION;

const NODE_FILE: &str = "node.toml";
const CONFIG_FILE: &str = "config.toml";
const TRUST_FILE: &str = "trust.toml";
const POLICY_FILE: &str = "policy.toml";
const AGENTS_DIR: &str = "agents";
const AGENT_REGISTRY_FILE: &str = "registry.toml";
const REMOTE_AGENT_REGISTRY_FILE: &str = "remote.toml";
const RUNTIME_DIR: &str = "runtime";
const IPC_DIR: &str = "ipc";
const IPC_INBOX_DIR: &str = "inbox";
const IPC_PROCESSED_DIR: &str = "processed";
const IPC_REJECTED_DIR: &str = "rejected";
const MESSAGES_DIR: &str = "messages";
const MESSAGE_INBOX_DIR: &str = "inbox";
const MESSAGE_RECEIPTS_DIR: &str = "receipts";
const STREAMS_DIR: &str = "streams";
const STREAM_REGISTRY_FILE: &str = "registry.toml";
const STREAM_EVENTS_FILE: &str = "events.toml";
const ROOMS_DIR: &str = "rooms";
const ROOM_REGISTRY_FILE: &str = "registry.toml";
const ROOM_EVENTS_FILE: &str = "events.toml";
const ROOM_POLICY_FILE: &str = "policy.toml";
const ROUTES_DIR: &str = "routes";
const ROUTE_REGISTRY_FILE: &str = "registry.toml";
const ROUTE_PROBES_FILE: &str = "probes.toml";
const PAIRING_DIR: &str = "pairing";
const PAIRING_INVITES_DIR: &str = "invites";
const PAIRING_USED_DIR: &str = "used";
const SESSIONS_DIR: &str = "sessions";
const SESSION_REGISTRY_FILE: &str = "registry.toml";
const MAILBOX_DIR: &str = "mailbox";
const RELAY_DIR: &str = "relay";
const RELAY_OUTBOX_DIR: &str = "outbox";
const RELAY_SENT_DIR: &str = "sent";
const RELAY_REJECTED_DIR: &str = "rejected";
const LOGS_DIR: &str = "logs";
const SECURITY_DIR: &str = "security";
const IDENTITY_SIGNING_KEY_FILE: &str = "identity-signing.key";
const IDENTITY_EXCHANGE_KEY_FILE: &str = "identity-exchange.key";
const STORAGE_KEY_FILE: &str = "storage.key";
const STORAGE_KEY_ARCHIVE_DIR: &str = "storage-keys";
const RELAY_CREDENTIAL_FILE: &str = "relay-credential.key";
const REPLAY_CACHE_FILE: &str = "replay.toml";
const KEY_ROTATION_PLAN_FILE: &str = "key-rotation.md";
const MAX_STATE_FILE_BYTES: u64 = 1024 * 1024;

/// Files and folders used by the local conU state store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    pub home: PathBuf,
    pub node_identity: PathBuf,
    pub config: PathBuf,
    pub trust_store: PathBuf,
    pub policy_store: PathBuf,
    pub agents_dir: PathBuf,
    pub agent_registry: PathBuf,
    pub remote_agent_registry: PathBuf,
    pub runtime_dir: PathBuf,
    pub runtime_status: PathBuf,
    pub runtime_lock: PathBuf,
    pub runtime_stop_request: PathBuf,
    pub ipc_dir: PathBuf,
    pub ipc_inbox_dir: PathBuf,
    pub ipc_processed_dir: PathBuf,
    pub ipc_rejected_dir: PathBuf,
    pub message_ipc_dir: PathBuf,
    pub message_ipc_inbox_dir: PathBuf,
    pub message_ipc_processed_dir: PathBuf,
    pub message_ipc_rejected_dir: PathBuf,
    pub messages_dir: PathBuf,
    pub message_inbox_dir: PathBuf,
    pub message_receipts_dir: PathBuf,
    pub streams_dir: PathBuf,
    pub stream_registry: PathBuf,
    pub stream_events: PathBuf,
    pub rooms_dir: PathBuf,
    pub room_registry: PathBuf,
    pub room_events: PathBuf,
    pub room_policy: PathBuf,
    pub routes_dir: PathBuf,
    pub route_registry: PathBuf,
    pub route_probes: PathBuf,
    pub pairing_dir: PathBuf,
    pub pairing_invites_dir: PathBuf,
    pub pairing_used_dir: PathBuf,
    pub sessions_dir: PathBuf,
    pub session_registry: PathBuf,
    pub mailbox_dir: PathBuf,
    pub relay_dir: PathBuf,
    pub relay_outbox_dir: PathBuf,
    pub relay_sent_dir: PathBuf,
    pub relay_rejected_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub security_dir: PathBuf,
    pub identity_signing_key: PathBuf,
    pub identity_exchange_key: PathBuf,
    pub storage_key: PathBuf,
    pub storage_key_archive_dir: PathBuf,
    pub relay_credential: PathBuf,
    pub replay_cache: PathBuf,
    pub key_rotation_plan: PathBuf,
}

impl StatePaths {
    /// Resolve conU's local state paths.
    pub fn resolve(home_override: Option<PathBuf>) -> Result<Self, StateError> {
        let home = match home_override {
            Some(path) => path,
            None => default_home()?,
        };

        Ok(Self::from_home(home))
    }

    /// Build state paths from an already resolved home directory.
    pub fn from_home(home: PathBuf) -> Self {
        let agents_dir = home.join(AGENTS_DIR);
        let runtime_dir = home.join(RUNTIME_DIR);
        let ipc_dir = runtime_dir.join(IPC_DIR);
        let message_ipc_dir = ipc_dir.join(MESSAGES_DIR);
        let messages_dir = home.join(MESSAGES_DIR);
        let streams_dir = home.join(STREAMS_DIR);
        let rooms_dir = home.join(ROOMS_DIR);
        let routes_dir = home.join(ROUTES_DIR);
        let pairing_dir = home.join(PAIRING_DIR);
        let security_dir = home.join(SECURITY_DIR);
        let mailbox_dir = home.join(MAILBOX_DIR);
        let relay_dir = mailbox_dir.join(RELAY_DIR);

        Self {
            node_identity: home.join(NODE_FILE),
            config: home.join(CONFIG_FILE),
            trust_store: home.join(TRUST_FILE),
            policy_store: home.join(POLICY_FILE),
            agent_registry: agents_dir.join(AGENT_REGISTRY_FILE),
            remote_agent_registry: agents_dir.join(REMOTE_AGENT_REGISTRY_FILE),
            agents_dir,
            runtime_status: runtime_dir.join("status.toml"),
            runtime_lock: runtime_dir.join("conud.lock"),
            runtime_stop_request: runtime_dir.join("stop.request"),
            runtime_dir,
            ipc_inbox_dir: ipc_dir.join(IPC_INBOX_DIR),
            ipc_processed_dir: ipc_dir.join(IPC_PROCESSED_DIR),
            ipc_rejected_dir: ipc_dir.join(IPC_REJECTED_DIR),
            message_ipc_inbox_dir: message_ipc_dir.join(IPC_INBOX_DIR),
            message_ipc_processed_dir: message_ipc_dir.join(IPC_PROCESSED_DIR),
            message_ipc_rejected_dir: message_ipc_dir.join(IPC_REJECTED_DIR),
            message_ipc_dir,
            ipc_dir,
            message_inbox_dir: messages_dir.join(MESSAGE_INBOX_DIR),
            message_receipts_dir: messages_dir.join(MESSAGE_RECEIPTS_DIR),
            messages_dir,
            stream_registry: streams_dir.join(STREAM_REGISTRY_FILE),
            stream_events: streams_dir.join(STREAM_EVENTS_FILE),
            streams_dir,
            room_registry: rooms_dir.join(ROOM_REGISTRY_FILE),
            room_events: rooms_dir.join(ROOM_EVENTS_FILE),
            room_policy: rooms_dir.join(ROOM_POLICY_FILE),
            rooms_dir,
            route_registry: routes_dir.join(ROUTE_REGISTRY_FILE),
            route_probes: routes_dir.join(ROUTE_PROBES_FILE),
            routes_dir,
            pairing_invites_dir: pairing_dir.join(PAIRING_INVITES_DIR),
            pairing_used_dir: pairing_dir.join(PAIRING_USED_DIR),
            pairing_dir,
            sessions_dir: home.join(SESSIONS_DIR),
            session_registry: home.join(SESSIONS_DIR).join(SESSION_REGISTRY_FILE),
            relay_outbox_dir: relay_dir.join(RELAY_OUTBOX_DIR),
            relay_sent_dir: relay_dir.join(RELAY_SENT_DIR),
            relay_rejected_dir: relay_dir.join(RELAY_REJECTED_DIR),
            relay_dir,
            mailbox_dir,
            logs_dir: home.join(LOGS_DIR),
            identity_signing_key: security_dir.join(IDENTITY_SIGNING_KEY_FILE),
            identity_exchange_key: security_dir.join(IDENTITY_EXCHANGE_KEY_FILE),
            storage_key: security_dir.join(STORAGE_KEY_FILE),
            storage_key_archive_dir: security_dir.join(STORAGE_KEY_ARCHIVE_DIR),
            relay_credential: security_dir.join(RELAY_CREDENTIAL_FILE),
            replay_cache: security_dir.join(REPLAY_CACHE_FILE),
            key_rotation_plan: security_dir.join(KEY_ROTATION_PLAN_FILE),
            security_dir,
            home,
        }
    }
}

/// Local identity for this conUD runtime node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: String,
    pub display_name: String,
    pub created_at_unix: u64,
    pub protocol_version: String,
}

/// Result of creating or reusing local state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    pub paths: StatePaths,
    pub node: NodeIdentity,
    pub node_created: bool,
    pub config_created: bool,
    pub trust_store_created: bool,
    pub agent_registry_created: bool,
}

/// Read-only view of the local state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub paths: StatePaths,
    pub node: Option<NodeIdentity>,
    pub config_exists: bool,
    pub trust_store_exists: bool,
    pub agent_registry_exists: bool,
}

impl StateSnapshot {
    /// True once the required Phase 3 state files exist and the node identity parses.
    pub fn is_initialized(&self) -> bool {
        self.node.is_some()
            && self.config_exists
            && self.trust_store_exists
            && self.agent_registry_exists
    }
}

/// Errors produced while reading or creating local state.
#[derive(Debug)]
pub enum StateError {
    MissingHome,
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidNodeIdentity {
        path: PathBuf,
        reason: String,
    },
}

impl StateError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHome => write!(
                formatter,
                "could not resolve a conU state directory; set CONU_HOME"
            ),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidNodeIdentity { path, reason } => {
                write!(
                    formatter,
                    "invalid node identity at {}: {reason}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for StateError {}

/// Create the local state directory and required Phase 3 files.
pub fn init_state(home_override: Option<PathBuf>) -> Result<InitReport, StateError> {
    let paths = StatePaths::resolve(home_override)?;
    create_layout(&paths)?;

    let node_identity_exists = state_file_exists(&paths.node_identity, "inspect node identity")?;
    let (node, node_created) = if node_identity_exists {
        (read_node_identity(&paths.node_identity)?, false)
    } else {
        let node = NodeIdentity::new(default_display_name(), current_unix_seconds());
        match write_new_file(&paths.node_identity, &render_node_identity(&node)) {
            Ok(()) => (node, true),
            Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
                (read_node_identity(&paths.node_identity)?, false)
            }
            Err(error) => return Err(error),
        }
    };

    let config_created =
        write_if_missing(&paths.config, &render_config(&node), "inspect config file")?;
    let trust_store_created = write_if_missing(
        &paths.trust_store,
        &render_trust_store(),
        "inspect trust store",
    )?;
    write_if_missing(
        &paths.policy_store,
        &render_policy_store(),
        "inspect policy store",
    )?;
    let agent_registry_created = write_if_missing(
        &paths.agent_registry,
        &render_agent_registry(),
        "inspect agent registry",
    )?;

    Ok(InitReport {
        paths,
        node,
        node_created,
        config_created,
        trust_store_created,
        agent_registry_created,
    })
}

/// Read the current local state without creating missing files.
pub fn read_state(home_override: Option<PathBuf>) -> Result<StateSnapshot, StateError> {
    let paths = StatePaths::resolve(home_override)?;
    let node = match state_file_exists(&paths.node_identity, "inspect node identity")? {
        true => Some(read_node_identity(&paths.node_identity)?),
        false => None,
    };

    let config_exists = state_file_exists(&paths.config, "inspect config file")?;
    let trust_store_exists = state_file_exists(&paths.trust_store, "inspect trust store")?;
    let agent_registry_exists = state_file_exists(&paths.agent_registry, "inspect agent registry")?;

    Ok(StateSnapshot {
        config_exists,
        trust_store_exists,
        agent_registry_exists,
        paths,
        node,
    })
}

impl NodeIdentity {
    fn new(display_name: String, created_at_unix: u64) -> Self {
        Self {
            node_id: generate_node_id(&display_name, created_at_unix),
            display_name,
            created_at_unix,
            protocol_version: PROTOCOL_VERSION.to_string(),
        }
    }
}

fn create_layout(paths: &StatePaths) -> Result<(), StateError> {
    fs::create_dir_all(&paths.home)
        .map_err(|error| StateError::io("create state directory", &paths.home, error))?;

    for directory in [
        &paths.agents_dir,
        &paths.runtime_dir,
        &paths.ipc_dir,
        &paths.ipc_inbox_dir,
        &paths.ipc_processed_dir,
        &paths.ipc_rejected_dir,
        &paths.message_ipc_dir,
        &paths.message_ipc_inbox_dir,
        &paths.message_ipc_processed_dir,
        &paths.message_ipc_rejected_dir,
        &paths.messages_dir,
        &paths.message_inbox_dir,
        &paths.message_receipts_dir,
        &paths.streams_dir,
        &paths.rooms_dir,
        &paths.routes_dir,
        &paths.pairing_dir,
        &paths.pairing_invites_dir,
        &paths.pairing_used_dir,
        &paths.sessions_dir,
        &paths.mailbox_dir,
        &paths.relay_dir,
        &paths.relay_outbox_dir,
        &paths.relay_sent_dir,
        &paths.relay_rejected_dir,
        &paths.logs_dir,
        &paths.security_dir,
        &paths.storage_key_archive_dir,
    ] {
        ensure_state_directory(directory)?;
    }

    Ok(())
}

pub(crate) fn ensure_state_directory(path: &Path) -> Result<(), StateError> {
    if regular_state_directory_metadata(path, "inspect state directory")?.is_some() {
        return Ok(());
    }

    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            match regular_state_directory_metadata(path, "inspect state directory")? {
                Some(_) => Ok(()),
                None => Err(StateError::io(
                    "inspect state directory",
                    path,
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "state directory disappeared after create collision",
                    ),
                )),
            }
        }
        Err(error) => Err(StateError::io("create state directory", path, error)),
    }
}

pub(crate) fn state_directory_exists(
    path: &Path,
    action: &'static str,
) -> Result<bool, StateError> {
    regular_state_directory_metadata(path, action).map(|metadata| metadata.is_some())
}

fn write_if_missing(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
) -> Result<bool, StateError> {
    if regular_state_file_metadata(path, inspect_action)?.is_some() {
        return Ok(false);
    }

    match write_new_file(path, contents) {
        Ok(()) => Ok(true),
        Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            match regular_state_file_metadata(path, inspect_action)? {
                Some(_) => Ok(false),
                None => Err(StateError::io(
                    inspect_action,
                    path,
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "state file disappeared after create collision",
                    ),
                )),
            }
        }
        Err(error) => Err(error),
    }
}

fn write_new_file(path: &Path, contents: &str) -> Result<(), StateError> {
    write_new_file_with_actions(path, contents, "create state file", "write state file")
}

fn write_new_file_with_actions(
    path: &Path,
    contents: &str,
    create_action: &'static str,
    write_action: &'static str,
) -> Result<(), StateError> {
    ensure_state_contents_within_limit(path, contents.len(), write_action)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| StateError::io(create_action, path, error))?;

    file.write_all(contents.as_bytes())
        .map_err(|error| StateError::io(write_action, path, error))
}

fn read_node_identity(path: &Path) -> Result<NodeIdentity, StateError> {
    let contents = read_existing_state_file(path, "inspect node identity", "read node identity")?;
    let values = parse_key_values(&contents);

    let node_id = required_field(path, &values, "node_id")?;
    let display_name = required_field(path, &values, "display_name")?;
    let protocol_version = required_field(path, &values, "protocol_version")?;
    let created_at_unix = required_field(path, &values, "created_at_unix")?
        .parse::<u64>()
        .map_err(|_| StateError::InvalidNodeIdentity {
            path: path.to_path_buf(),
            reason: "created_at_unix must be an unsigned integer".to_string(),
        })?;

    if !node_id.starts_with("node_") {
        return Err(StateError::InvalidNodeIdentity {
            path: path.to_path_buf(),
            reason: "node_id must start with node_".to_string(),
        });
    }

    Ok(NodeIdentity {
        node_id,
        display_name,
        created_at_unix,
        protocol_version,
    })
}

fn read_existing_state_file(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
) -> Result<String, StateError> {
    let Some(metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    read_existing_state_file_with_metadata(path, inspect_action, read_action, &metadata)
}

fn read_existing_state_file_with_metadata(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
    metadata: &fs::Metadata,
) -> Result<String, StateError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| StateError::io(read_action, path, error))?;
    let Some(path_metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    if !state_file_metadata_matches(metadata, &path_metadata) {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file path changed while reading",
            ),
        ));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| StateError::io(inspect_action, path, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_STATE_FILE_BYTES
        || !state_file_metadata_matches(metadata, &opened_metadata)
    {
        return Err(StateError::io(
            read_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file path changed while reading",
            ),
        ));
    }

    let mut contents = String::new();
    let limit = MAX_STATE_FILE_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_string(&mut contents)
        .map_err(|error| StateError::io(read_action, path, error))?;
    if contents.len() as u64 > MAX_STATE_FILE_BYTES {
        return Err(StateError::io(
            read_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("state file exceeds {MAX_STATE_FILE_BYTES} bytes"),
            ),
        ));
    }
    Ok(contents)
}

pub(crate) fn read_optional_regular_state_file(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
) -> Result<Option<String>, StateError> {
    let Some(metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Ok(None);
    };

    read_existing_state_file_with_metadata(path, inspect_action, read_action, &metadata).map(Some)
}

pub(crate) fn read_required_regular_state_file(
    path: &Path,
    inspect_action: &'static str,
    read_action: &'static str,
) -> Result<String, StateError> {
    let Some(metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };

    read_existing_state_file_with_metadata(path, inspect_action, read_action, &metadata)
}

pub(crate) fn write_regular_state_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    create_action: &'static str,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), StateError> {
    if regular_state_file_metadata(path, inspect_action)?.is_none() {
        match write_new_file_with_actions(path, contents, create_action, write_action) {
            Ok(()) => return Ok(()),
            Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            }
            Err(error) => return Err(error),
        }
    }

    replace_existing_regular_state_file(path, contents, inspect_action, open_action, write_action)
}

pub(crate) fn rewrite_existing_regular_state_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), StateError> {
    if regular_state_file_metadata(path, inspect_action)?.is_none() {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    }

    replace_existing_regular_state_file(path, contents, inspect_action, open_action, write_action)
}

pub(crate) fn remove_existing_regular_state_file(
    path: &Path,
    inspect_action: &'static str,
    remove_action: &'static str,
) -> Result<(), StateError> {
    if regular_state_file_metadata(path, inspect_action)?.is_none() {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    }

    fs::remove_file(path).map_err(|error| StateError::io(remove_action, path, error))
}

pub(crate) fn archive_regular_state_file_no_replace(
    source: &Path,
    target: &Path,
    inspect_source_action: &'static str,
    inspect_target_action: &'static str,
    archive_action: &'static str,
) -> Result<(), StateError> {
    let Some(source_metadata) = regular_state_file_metadata(source, inspect_source_action)? else {
        return Err(StateError::io(
            inspect_source_action,
            source,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    let target_parent = state_file_parent(target);
    if regular_state_directory_metadata(target_parent, inspect_target_action)?.is_none() {
        return Err(StateError::io(
            inspect_target_action,
            target_parent,
            io::Error::new(io::ErrorKind::NotFound, "state directory path is missing"),
        ));
    }
    if regular_state_file_metadata(target, inspect_target_action)?.is_some() {
        return Err(StateError::io(
            inspect_target_action,
            target,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "archive target already exists",
            ),
        ));
    }

    if let Err(error) = fs::hard_link(source, target) {
        return Err(StateError::io(archive_action, source, error));
    }

    let target_metadata = match regular_state_file_metadata(target, inspect_target_action) {
        Ok(Some(metadata)) => metadata,
        Ok(None) => {
            return Err(StateError::io(
                inspect_target_action,
                target,
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "archive target disappeared after reservation",
                ),
            ));
        }
        Err(error) => {
            let _ = fs::remove_file(target);
            return Err(error);
        }
    };
    if !state_file_metadata_matches(&source_metadata, &target_metadata) {
        let _ = fs::remove_file(target);
        return Err(StateError::io(
            inspect_target_action,
            target,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "archive target does not match source file",
            ),
        ));
    }

    match regular_state_file_metadata(source, inspect_source_action)? {
        Some(current_metadata)
            if state_file_metadata_matches(&source_metadata, &current_metadata) => {}
        Some(_) => {
            let _ = fs::remove_file(target);
            return Err(StateError::io(
                inspect_source_action,
                source,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "state file path changed before archive removal",
                ),
            ));
        }
        None => return Ok(()),
    }

    match fs::remove_file(source) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(target);
            Err(StateError::io(archive_action, source, error))
        }
    }
}

pub(crate) fn append_regular_state_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    create_action: &'static str,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), StateError> {
    if regular_state_file_metadata(path, inspect_action)?.is_none() {
        match write_new_file_with_actions(path, contents, create_action, write_action) {
            Ok(()) => return Ok(()),
            Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            }
            Err(error) => return Err(error),
        }
    }

    let mut file = open_existing_regular_state_file_for_append(path, inspect_action, open_action)?;
    let metadata = file
        .metadata()
        .map_err(|error| StateError::io(open_action, path, error))?;
    ensure_state_append_within_limit(path, metadata.len(), contents.len(), write_action)?;
    file.write_all(contents.as_bytes())
        .map_err(|error| StateError::io(write_action, path, error))
}

pub(crate) fn ensure_regular_state_file_appendable(
    path: &Path,
    additional_bytes: usize,
    inspect_action: &'static str,
    open_action: &'static str,
) -> Result<(), StateError> {
    let file = open_existing_regular_state_file_for_append(path, inspect_action, open_action)?;
    let metadata = file
        .metadata()
        .map_err(|error| StateError::io(open_action, path, error))?;
    ensure_state_append_within_limit(path, metadata.len(), additional_bytes, open_action)
}

fn ensure_state_contents_within_limit(
    path: &Path,
    contents_len: usize,
    action: &'static str,
) -> Result<(), StateError> {
    if contents_len as u64 > MAX_STATE_FILE_BYTES {
        return Err(StateError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("state file exceeds {MAX_STATE_FILE_BYTES} bytes"),
            ),
        ));
    }
    Ok(())
}

fn ensure_state_append_within_limit(
    path: &Path,
    current_len: u64,
    additional_bytes: usize,
    action: &'static str,
) -> Result<(), StateError> {
    let Some(new_len) = current_len.checked_add(additional_bytes as u64) else {
        return Err(StateError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("state file exceeds {MAX_STATE_FILE_BYTES} bytes"),
            ),
        ));
    };
    if new_len > MAX_STATE_FILE_BYTES {
        return Err(StateError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("state file exceeds {MAX_STATE_FILE_BYTES} bytes"),
            ),
        ));
    }
    Ok(())
}

fn replace_existing_regular_state_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    open_action: &'static str,
    write_action: &'static str,
) -> Result<(), StateError> {
    ensure_state_contents_within_limit(path, contents.len(), write_action)?;
    let file = open_existing_regular_state_file_for_write(path, inspect_action, open_action)?;
    let metadata = file
        .metadata()
        .map_err(|error| StateError::io(open_action, path, error))?;
    drop(file);

    let temp_path = write_replacement_state_temp_file(path, contents, write_action)?;
    let result = replace_regular_state_file_with_temp(
        path,
        &temp_path,
        &metadata,
        inspect_action,
        write_action,
    );
    if result.is_err() {
        remove_temp_state_file(&temp_path);
    }
    result
}

fn write_replacement_state_temp_file(
    path: &Path,
    contents: &str,
    write_action: &'static str,
) -> Result<PathBuf, StateError> {
    let parent = state_file_parent(path);
    if regular_state_directory_metadata(parent, write_action)?.is_none() {
        return Err(StateError::io(
            write_action,
            parent,
            io::Error::new(io::ErrorKind::NotFound, "state directory path is missing"),
        ));
    }

    for attempt in 0..16 {
        let temp_path = replacement_state_temp_path(path, attempt);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StateError::io(write_action, &temp_path, error)),
        };

        let write_result = file
            .write_all(contents.as_bytes())
            .and_then(|_| file.sync_all());
        drop(file);

        if let Err(error) = write_result {
            remove_temp_state_file(&temp_path);
            return Err(StateError::io(write_action, &temp_path, error));
        }

        return Ok(temp_path);
    }

    Err(StateError::io(
        write_action,
        path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique state replacement file",
        ),
    ))
}

fn replace_regular_state_file_with_temp(
    path: &Path,
    temp_path: &Path,
    expected_metadata: &fs::Metadata,
    inspect_action: &'static str,
    write_action: &'static str,
) -> Result<(), StateError> {
    let Some(current_metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    if !state_file_write_target_matches(expected_metadata, &current_metadata) {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file path changed before replacement",
            ),
        ));
    }

    fs::rename(temp_path, path).map_err(|error| StateError::io(write_action, path, error))
}

fn state_file_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn replacement_state_temp_path(path: &Path, attempt: u8) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    parent.join(format!(
        ".{file_name}.tmp-{}-{}-{attempt}",
        process::id(),
        current_unix_nanos()
    ))
}

fn remove_temp_state_file(path: &Path) {
    let _ = fs::remove_file(path);
}

fn open_existing_regular_state_file_for_write(
    path: &Path,
    inspect_action: &'static str,
    open_action: &'static str,
) -> Result<File, StateError> {
    let Some(metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| StateError::io(open_action, path, error))?;
    validate_opened_regular_state_file(path, inspect_action, open_action, &metadata, &file)?;
    Ok(file)
}

fn open_existing_regular_state_file_for_append(
    path: &Path,
    inspect_action: &'static str,
    open_action: &'static str,
) -> Result<File, StateError> {
    let Some(metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    let file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| StateError::io(open_action, path, error))?;
    validate_opened_regular_state_file(path, inspect_action, open_action, &metadata, &file)?;
    Ok(file)
}

fn validate_opened_regular_state_file(
    path: &Path,
    inspect_action: &'static str,
    open_action: &'static str,
    expected_metadata: &fs::Metadata,
    file: &File,
) -> Result<(), StateError> {
    let Some(path_metadata) = regular_state_file_metadata(path, inspect_action)? else {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "state file path is missing"),
        ));
    };
    if !state_file_write_target_matches(expected_metadata, &path_metadata) {
        return Err(StateError::io(
            inspect_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file path changed while opening",
            ),
        ));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| StateError::io(open_action, path, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_STATE_FILE_BYTES
        || !state_file_write_target_matches(expected_metadata, &opened_metadata)
    {
        return Err(StateError::io(
            open_action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "opened state file does not match inspected path",
            ),
        ));
    }

    Ok(())
}

fn state_file_exists(path: &Path, inspect_action: &'static str) -> Result<bool, StateError> {
    regular_state_file_metadata(path, inspect_action).map(|metadata| metadata.is_some())
}

fn regular_state_file_metadata(
    path: &Path,
    action: &'static str,
) -> Result<Option<fs::Metadata>, StateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(StateError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "state file path is not a regular file",
                    ),
                ));
            }
            if metadata.len() > MAX_STATE_FILE_BYTES {
                return Err(StateError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("state file exceeds {MAX_STATE_FILE_BYTES} bytes"),
                    ),
                ));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StateError::io(action, path, error)),
    }
}

fn state_file_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && state_file_identity_matches(expected, current)
}

fn state_file_write_target_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    state_file_stable_identity_matches(expected, current)
}

#[cfg(unix)]
fn state_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    state_file_stable_identity_matches(expected, current)
}

#[cfg(unix)]
fn state_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn state_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    state_file_stable_identity_matches(expected, current)
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(windows)]
fn state_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
}

#[cfg(not(any(unix, windows)))]
fn state_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

#[cfg(not(any(unix, windows)))]
fn state_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    state_file_identity_matches(expected, current)
}

fn regular_state_directory_metadata(
    path: &Path,
    action: &'static str,
) -> Result<Option<fs::Metadata>, StateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(StateError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "state directory path is not a directory",
                    ),
                ));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StateError::io(action, path, error)),
    }
}

fn required_field(
    path: &Path,
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<String, StateError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| StateError::InvalidNodeIdentity {
            path: path.to_path_buf(),
            reason: format!("missing {key}"),
        })
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

fn render_node_identity(node: &NodeIdentity) -> String {
    format!(
        "# conU node identity\n# Local node id only. Secret keys are introduced in later phases.\nversion = \"1\"\nnode_id = \"{}\"\ndisplay_name = \"{}\"\ncreated_at_unix = {}\nprotocol_version = \"{}\"\n",
        escape_file_value(&node.node_id),
        escape_file_value(&node.display_name),
        node.created_at_unix,
        escape_file_value(&node.protocol_version)
    )
}

fn render_config(node: &NodeIdentity) -> String {
    format!(
        "# conU local config\nversion = \"1\"\nruntime_name = \"{}\"\ndefault_relay = \"\"\nrelay_auto_sync = true\n",
        escape_file_value(&node.display_name)
    )
}

fn render_trust_store() -> String {
    "# conU trust store skeleton\nversion = \"1\"\ntrusted_peers = []\nrevoked_peers = []\n"
        .to_string()
}

fn render_policy_store() -> String {
    "# conU peer policy store\nversion = \"1\"\n".to_string()
}

fn render_agent_registry() -> String {
    "# conU local agent registry\nversion = \"1\"\n".to_string()
}

fn escape_file_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn generate_node_id(display_name: &str, created_at_unix: u64) -> String {
    let mut hasher = DefaultHasher::new();
    display_name.hash(&mut hasher);
    created_at_unix.hash(&mut hasher);
    process::id().hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);

    format!("node_{:016x}", hasher.finish())
}

fn default_display_name() -> String {
    let raw = env::var("CONU_NODE_NAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "local-node".to_string());

    sanitize_display_name(&raw)
}

fn sanitize_display_name(value: &str) -> String {
    let cleaned = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();

    if cleaned.is_empty() {
        "local-node".to_string()
    } else {
        cleaned
    }
}

fn default_home() -> Result<PathBuf, StateError> {
    if let Ok(value) = env::var("CONU_HOME") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }

    #[cfg(windows)]
    if let Ok(value) = env::var("APPDATA") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value).join("conU"));
        }
    }

    if let Ok(value) = env::var("HOME") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value).join(".conu"));
        }
    }

    if let Ok(value) = env::var("USERPROFILE") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value).join(".conu"));
        }
    }

    Err(StateError::MissingHome)
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
    fn init_creates_required_state_files() {
        let home = test_home("creates");
        let report = init_state(Some(home.clone())).expect("state initializes");

        assert!(report.node_created);
        assert!(report.config_created);
        assert!(report.trust_store_created);
        assert!(report.agent_registry_created);
        assert!(report.node.node_id.starts_with("node_"));
        assert!(home.join(NODE_FILE).exists());
        assert!(home.join(CONFIG_FILE).exists());
        assert!(home.join(TRUST_FILE).exists());
        assert!(home.join(POLICY_FILE).exists());
        assert!(home.join(AGENTS_DIR).join(AGENT_REGISTRY_FILE).exists());
        assert!(home.join(RUNTIME_DIR).exists());
        assert!(
            home.join(RUNTIME_DIR)
                .join(IPC_DIR)
                .join(IPC_INBOX_DIR)
                .exists()
        );
        assert!(home.join(MESSAGES_DIR).join(MESSAGE_INBOX_DIR).exists());
        assert!(home.join(ROOMS_DIR).exists());
        assert!(home.join(PAIRING_DIR).join(PAIRING_INVITES_DIR).exists());
        assert!(
            home.join(RUNTIME_DIR)
                .join(IPC_DIR)
                .join(MESSAGES_DIR)
                .join(IPC_INBOX_DIR)
                .exists()
        );
    }

    #[test]
    fn init_is_idempotent_and_preserves_node_id() {
        let home = test_home("idempotent");
        let first = init_state(Some(home.clone())).expect("first init succeeds");
        let second = init_state(Some(home)).expect("second init succeeds");

        assert!(first.node_created);
        assert!(!second.node_created);
        assert_eq!(first.node.node_id, second.node.node_id);
        assert!(!second.config_created);
        assert!(!second.trust_store_created);
        assert!(!second.agent_registry_created);
    }

    #[test]
    fn read_state_reports_initialized_after_init() {
        let home = test_home("snapshot");
        init_state(Some(home.clone())).expect("state initializes");

        let snapshot = read_state(Some(home)).expect("state reads");

        assert!(snapshot.is_initialized());
        assert!(snapshot.node.expect("node").node_id.starts_with("node_"));
    }

    #[test]
    fn read_state_does_not_create_missing_files() {
        let home = test_home("missing");
        let snapshot = read_state(Some(home.clone())).expect("state reads");

        assert!(!snapshot.is_initialized());
        assert!(snapshot.node.is_none());
        assert!(!home.exists());
    }

    #[test]
    fn remove_existing_regular_state_file_removes_regular_file() {
        let home = test_home("remove-regular-state-file");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.toml");
        fs::write(&path, "version = \"1\"\n").expect("state file writes");

        remove_existing_regular_state_file(&path, "inspect removable state", "remove state file")
            .expect("regular state file removes");

        assert!(!path.exists());
    }

    #[test]
    fn remove_existing_regular_state_file_rejects_missing_file() {
        let home = test_home("remove-missing-state-file");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("missing.toml");

        let error = remove_existing_regular_state_file(
            &path,
            "inspect removable missing state",
            "remove missing state file",
        )
        .expect_err("missing state file should fail closed");

        assert!(
            error
                .to_string()
                .contains("inspect removable missing state")
        );
    }

    #[test]
    fn archive_regular_state_file_no_replace_moves_source_to_empty_target() {
        let home = test_home("archive-state-file");
        fs::create_dir_all(&home).expect("home creates");
        let source = home.join("request.req");
        let target = home.join("processed.req");
        fs::write(&source, "version = \"1\"\nstatus = \"queued\"\n").expect("source writes");

        archive_regular_state_file_no_replace(
            &source,
            &target,
            "inspect archive source",
            "reserve archive target",
            "archive state file",
        )
        .expect("state file archives");

        assert!(!source.exists());
        assert_eq!(
            fs::read_to_string(&target).expect("target reads"),
            "version = \"1\"\nstatus = \"queued\"\n"
        );
    }

    #[test]
    fn archive_regular_state_file_no_replace_refuses_existing_target_without_clobber() {
        let home = test_home("archive-state-file-collision");
        fs::create_dir_all(&home).expect("home creates");
        let source = home.join("request.req");
        let target = home.join("processed.req");
        fs::write(&source, "version = \"1\"\nstatus = \"queued\"\n").expect("source writes");
        fs::write(&target, "version = \"1\"\nstatus = \"existing\"\n").expect("target writes");

        let error = archive_regular_state_file_no_replace(
            &source,
            &target,
            "inspect archive source",
            "reserve archive target",
            "archive state file",
        )
        .expect_err("existing archive target should fail closed");

        assert!(error.to_string().contains("reserve archive target"));
        assert_eq!(
            fs::read_to_string(&target).expect("target reads"),
            "version = \"1\"\nstatus = \"existing\"\n"
        );
        assert_eq!(
            fs::read_to_string(&source).expect("source reads"),
            "version = \"1\"\nstatus = \"queued\"\n"
        );
    }

    #[test]
    fn read_regular_state_file_rejects_oversized_file_without_printing_contents() {
        let home = test_home("oversized-state-read");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.toml");
        let private_marker = "private-state-marker";
        let mut contents = format!("# {private_marker}\n");
        contents.push_str(&"a".repeat((MAX_STATE_FILE_BYTES + 1) as usize));
        fs::write(&path, contents).expect("oversized state writes");

        let required_error = read_required_regular_state_file(
            &path,
            "inspect oversized required state",
            "read oversized required state",
        )
        .expect_err("oversized required state file should fail closed");
        let required_error = required_error.to_string();
        assert!(required_error.contains("state file exceeds"));
        assert!(!required_error.contains(private_marker));

        let optional_error = read_optional_regular_state_file(
            &path,
            "inspect oversized optional state",
            "read oversized optional state",
        )
        .expect_err("oversized optional state file should fail closed");
        let optional_error = optional_error.to_string();
        assert!(optional_error.contains("state file exceeds"));
        assert!(!optional_error.contains(private_marker));
    }

    #[test]
    fn write_regular_state_file_rejects_oversized_contents_without_truncating_existing_file() {
        let home = test_home("oversized-state-write");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.toml");
        let original = "version = \"1\"\nstatus = \"kept\"\n";
        fs::write(&path, original).expect("state writes");
        let oversized = "a".repeat((MAX_STATE_FILE_BYTES + 1) as usize);

        let error = write_regular_state_file(
            &path,
            &oversized,
            "inspect oversized state write",
            "create oversized state",
            "open oversized state",
            "write oversized state",
        )
        .expect_err("oversized state write fails before truncating");

        assert!(error.to_string().contains("state file exceeds"));
        assert_eq!(
            fs::read_to_string(&path).expect("state reads"),
            original,
            "oversized write must not truncate existing state"
        );
    }

    #[test]
    fn rewrite_existing_regular_state_file_replaces_existing_contents() {
        let home = test_home("atomic-state-rewrite");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.toml");
        fs::write(&path, "version = \"1\"\nstatus = \"old\"\n").expect("state writes");

        rewrite_existing_regular_state_file(
            &path,
            "version = \"1\"\nstatus = \"new\"\n",
            "inspect atomic state rewrite",
            "open atomic state rewrite",
            "write atomic state rewrite",
        )
        .expect("state rewrite succeeds");

        assert_eq!(
            fs::read_to_string(&path).expect("state reads"),
            "version = \"1\"\nstatus = \"new\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_regular_state_file_rejects_unwritable_parent_without_truncating_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let home = test_home("atomic-state-rewrite-unwritable-parent");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.toml");
        let original = "version = \"1\"\nstatus = \"kept\"\n";
        fs::write(&path, original).expect("state writes");
        let original_permissions = fs::metadata(&home)
            .expect("home metadata reads")
            .permissions();
        let mut locked_permissions = original_permissions.clone();
        locked_permissions.set_mode(0o500);
        fs::set_permissions(&home, locked_permissions).expect("home permissions lock");

        let result = write_regular_state_file(
            &path,
            "version = \"1\"\nstatus = \"replacement\"\n",
            "inspect unwritable parent state",
            "create unwritable parent state",
            "open unwritable parent state",
            "write unwritable parent state",
        );

        fs::set_permissions(&home, original_permissions).expect("home permissions restore");
        let error = result.expect_err("unwritable parent should fail before replacement");

        assert!(error.to_string().contains("write unwritable parent state"));
        assert_eq!(
            fs::read_to_string(&path).expect("state reads"),
            original,
            "failed staged rewrite must leave existing state unchanged"
        );
    }

    #[test]
    fn append_regular_state_file_rejects_oversized_new_file() {
        let home = test_home("oversized-state-append-new");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.log");
        let oversized = "a".repeat((MAX_STATE_FILE_BYTES + 1) as usize);

        let error = append_regular_state_file(
            &path,
            &oversized,
            "inspect oversized state append",
            "create oversized append state",
            "open oversized append state",
            "write oversized append state",
        )
        .expect_err("oversized append create fails");

        assert!(error.to_string().contains("state file exceeds"));
        assert!(!path.exists());
    }

    #[test]
    fn append_regular_state_file_rejects_growth_past_limit_without_modifying_file() {
        let home = test_home("oversized-state-append-existing");
        fs::create_dir_all(&home).expect("home creates");
        let path = home.join("state.log");
        let original = "a".repeat((MAX_STATE_FILE_BYTES - 2) as usize);
        fs::write(&path, &original).expect("state writes");

        let error = append_regular_state_file(
            &path,
            "bbb",
            "inspect bounded state append",
            "create bounded append state",
            "open bounded append state",
            "write bounded append state",
        )
        .expect_err("append beyond state limit fails");

        assert!(error.to_string().contains("state file exceeds"));
        assert_eq!(
            fs::read_to_string(&path).expect("state reads"),
            original,
            "oversized append must leave existing state unchanged"
        );
    }

    #[test]
    fn init_rejects_directory_required_state_file() {
        let home = test_home("directory-config");
        let report = init_state(Some(home.clone())).expect("state initializes");
        fs::remove_file(&report.paths.config).expect("config removes");
        fs::create_dir_all(&report.paths.config).expect("config directory creates");

        let error = init_state(Some(home)).expect_err("directory config should fail closed");

        assert!(error.to_string().contains("inspect config file"));
    }

    #[test]
    fn init_rejects_file_instead_of_state_directory() {
        let home = test_home("file-logs-dir");
        let report = init_state(Some(home.clone())).expect("state initializes");
        fs::remove_dir(&report.paths.logs_dir).expect("logs dir removes");
        fs::write(&report.paths.logs_dir, "not a directory").expect("logs file writes");

        let error = init_state(Some(home)).expect_err("file state directory should fail closed");

        assert!(error.to_string().contains("inspect state directory"));
    }

    #[test]
    fn opened_state_write_guard_rejects_mismatched_handle() {
        let home = test_home("opened-write-guard");
        fs::create_dir_all(&home).expect("home creates");
        let target = home.join("target.toml");
        let replacement = home.join("replacement.toml");
        fs::write(&target, "version = \"1\"\n").expect("target writes");
        std::thread::sleep(std::time::Duration::from_millis(2));
        fs::write(&replacement, "version = \"1\"\nchanged = true\n").expect("replacement writes");

        let expected = regular_state_file_metadata(&target, "inspect state write target")
            .expect("target metadata reads")
            .expect("target exists");
        let opened = OpenOptions::new()
            .write(true)
            .open(&replacement)
            .expect("replacement opens");

        let error = validate_opened_regular_state_file(
            &target,
            "inspect state write target",
            "open state write target",
            &expected,
            &opened,
        )
        .expect_err("mismatched opened handle should fail closed");

        assert!(
            error
                .to_string()
                .contains("opened state file does not match inspected path")
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

    #[cfg(unix)]
    #[test]
    fn write_regular_state_file_rejects_symlink_without_truncating_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("write-state-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let target = home.join("outside-state.toml");
        let link = home.join("linked-state.toml");
        fs::write(&target, "version = \"1\"\nsecret = \"kept\"\n").expect("outside writes");
        symlink(&target, &link).expect("state symlink creates");

        let error = write_regular_state_file(
            &link,
            "version = \"1\"\nsecret = \"changed\"\n",
            "inspect symlinked state write",
            "create symlinked state",
            "open symlinked state",
            "write symlinked state",
        )
        .expect_err("symlinked state write should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target).expect("outside reads"),
            "version = \"1\"\nsecret = \"kept\"\n"
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("state symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_rejects_symlinked_node_identity_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("node-symlink-init");
        fs::create_dir_all(&home).expect("home creates");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.join("outside-node.toml");
        let outside_contents = render_node_identity(&NodeIdentity {
            node_id: "node_outside".to_string(),
            display_name: "outside".to_string(),
            created_at_unix: 1,
            protocol_version: PROTOCOL_VERSION.to_string(),
        });
        fs::write(&outside, &outside_contents).expect("outside writes");
        symlink(&outside, &paths.node_identity).expect("node identity symlink creates");

        let error = init_state(Some(home)).expect_err("node identity symlink should fail closed");

        assert!(error.to_string().contains("inspect node identity"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.node_identity)
                .expect("node identity symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_state_rejects_symlinked_node_identity_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("node-symlink-read");
        fs::create_dir_all(&home).expect("home creates");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.join("outside-node.toml");
        let outside_contents = render_node_identity(&NodeIdentity {
            node_id: "node_outside".to_string(),
            display_name: "outside".to_string(),
            created_at_unix: 1,
            protocol_version: PROTOCOL_VERSION.to_string(),
        });
        fs::write(&outside, &outside_contents).expect("outside writes");
        symlink(&outside, &paths.node_identity).expect("node identity symlink creates");

        let error = read_state(Some(home)).expect_err("node identity symlink should fail closed");

        assert!(error.to_string().contains("inspect node identity"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            outside_contents
        );
    }

    #[cfg(unix)]
    #[test]
    fn remove_existing_regular_state_file_rejects_symlink_without_deleting_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("remove-state-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let target = home.join("outside-state.toml");
        let link = home.join("linked-state.toml");
        fs::write(&target, "version = \"1\"\n").expect("outside state writes");
        symlink(&target, &link).expect("state symlink creates");

        let error = remove_existing_regular_state_file(
            &link,
            "inspect symlinked state removal",
            "remove symlinked state",
        )
        .expect_err("symlinked state file should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target).expect("outside state reads"),
            "version = \"1\"\n"
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("state symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_rejects_symlinked_required_state_file_without_reusing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("config-symlink-init");
        let report = init_state(Some(home.clone())).expect("state initializes");
        let outside = home.join("outside-config.toml");
        fs::write(&outside, "version = \"1\"\nruntime_name = \"outside\"\n")
            .expect("outside writes");
        fs::remove_file(&report.paths.config).expect("config removes");
        symlink(&outside, &report.paths.config).expect("config symlink creates");

        let error = init_state(Some(home)).expect_err("config symlink should fail closed");

        assert!(error.to_string().contains("inspect config file"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "version = \"1\"\nruntime_name = \"outside\"\n"
        );
        assert!(
            fs::symlink_metadata(&report.paths.config)
                .expect("config symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_rejects_symlinked_state_directory_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("messages-dir-symlink");
        let report = init_state(Some(home.clone())).expect("state initializes");
        let outside = home.join("outside-messages");
        fs::create_dir_all(&outside).expect("outside directory creates");
        fs::remove_dir_all(&report.paths.messages_dir).expect("messages dir removes");
        symlink(&outside, &report.paths.messages_dir).expect("messages dir symlink creates");

        let error = init_state(Some(home)).expect_err("state dir symlink should fail closed");

        assert!(error.to_string().contains("inspect state directory"));
        assert!(!outside.join(MESSAGE_INBOX_DIR).exists());
        assert!(
            fs::symlink_metadata(&report.paths.messages_dir)
                .expect("messages dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    fn test_home(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "conu-state-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
