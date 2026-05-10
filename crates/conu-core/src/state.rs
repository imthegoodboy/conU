//! Local persistent state for conU.
//!
//! Phase 6 keeps this intentionally small and std-only: a locally generated
//! node id, config, trust store, pairing invitations, agent registry, runtime
//! metadata, local gateway inboxes, and local opaque message inboxes. Secret
//! keys and encrypted remote mailbox storage belong to later phases.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_protocol::PROTOCOL_VERSION;

const NODE_FILE: &str = "node.toml";
const CONFIG_FILE: &str = "config.toml";
const TRUST_FILE: &str = "trust.toml";
const AGENTS_DIR: &str = "agents";
const AGENT_REGISTRY_FILE: &str = "registry.toml";
const RUNTIME_DIR: &str = "runtime";
const IPC_DIR: &str = "ipc";
const IPC_INBOX_DIR: &str = "inbox";
const IPC_PROCESSED_DIR: &str = "processed";
const IPC_REJECTED_DIR: &str = "rejected";
const MESSAGES_DIR: &str = "messages";
const MESSAGE_INBOX_DIR: &str = "inbox";
const MESSAGE_RECEIPTS_DIR: &str = "receipts";
const PAIRING_DIR: &str = "pairing";
const PAIRING_INVITES_DIR: &str = "invites";
const PAIRING_USED_DIR: &str = "used";
const SESSIONS_DIR: &str = "sessions";
const MAILBOX_DIR: &str = "mailbox";
const LOGS_DIR: &str = "logs";

/// Files and folders used by the local conU state store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    pub home: PathBuf,
    pub node_identity: PathBuf,
    pub config: PathBuf,
    pub trust_store: PathBuf,
    pub agents_dir: PathBuf,
    pub agent_registry: PathBuf,
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
    pub pairing_dir: PathBuf,
    pub pairing_invites_dir: PathBuf,
    pub pairing_used_dir: PathBuf,
    pub sessions_dir: PathBuf,
    pub mailbox_dir: PathBuf,
    pub logs_dir: PathBuf,
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
        let pairing_dir = home.join(PAIRING_DIR);

        Self {
            node_identity: home.join(NODE_FILE),
            config: home.join(CONFIG_FILE),
            trust_store: home.join(TRUST_FILE),
            agent_registry: agents_dir.join(AGENT_REGISTRY_FILE),
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
            pairing_invites_dir: pairing_dir.join(PAIRING_INVITES_DIR),
            pairing_used_dir: pairing_dir.join(PAIRING_USED_DIR),
            pairing_dir,
            sessions_dir: home.join(SESSIONS_DIR),
            mailbox_dir: home.join(MAILBOX_DIR),
            logs_dir: home.join(LOGS_DIR),
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

    let (node, node_created) = if paths.node_identity.exists() {
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

    let config_created = write_if_missing(&paths.config, &render_config(&node))?;
    let trust_store_created = write_if_missing(&paths.trust_store, &render_trust_store())?;
    let agent_registry_created = write_if_missing(&paths.agent_registry, &render_agent_registry())?;

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
    let node = match paths.node_identity.exists() {
        true => Some(read_node_identity(&paths.node_identity)?),
        false => None,
    };

    Ok(StateSnapshot {
        config_exists: paths.config.exists(),
        trust_store_exists: paths.trust_store.exists(),
        agent_registry_exists: paths.agent_registry.exists(),
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
    for directory in [
        &paths.home,
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
        &paths.pairing_dir,
        &paths.pairing_invites_dir,
        &paths.pairing_used_dir,
        &paths.sessions_dir,
        &paths.mailbox_dir,
        &paths.logs_dir,
    ] {
        fs::create_dir_all(directory)
            .map_err(|error| StateError::io("create state directory", directory, error))?;
    }

    Ok(())
}

fn write_if_missing(path: &Path, contents: &str) -> Result<bool, StateError> {
    match write_new_file(path, contents) {
        Ok(()) => Ok(true),
        Err(StateError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn write_new_file(path: &Path, contents: &str) -> Result<(), StateError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| StateError::io("create state file", path, error))?;

    file.write_all(contents.as_bytes())
        .map_err(|error| StateError::io("write state file", path, error))
}

fn read_node_identity(path: &Path) -> Result<NodeIdentity, StateError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| StateError::io("read node identity", path, error))?;
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
        "# conU local config\nversion = \"1\"\nruntime_name = \"{}\"\ndefault_relay = \"\"\n",
        escape_file_value(&node.display_name)
    )
}

fn render_trust_store() -> String {
    "# conU trust store skeleton\nversion = \"1\"\ntrusted_peers = []\nrevoked_peers = []\n"
        .to_string()
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
        assert!(home.join(AGENTS_DIR).join(AGENT_REGISTRY_FILE).exists());
        assert!(home.join(RUNTIME_DIR).exists());
        assert!(
            home.join(RUNTIME_DIR)
                .join(IPC_DIR)
                .join(IPC_INBOX_DIR)
                .exists()
        );
        assert!(home.join(MESSAGES_DIR).join(MESSAGE_INBOX_DIR).exists());
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

    fn test_home(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "conu-state-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
