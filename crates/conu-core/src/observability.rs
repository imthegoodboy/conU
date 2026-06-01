//! Payload-safe observability maintenance.
//!
//! This module manages local conU metadata logs by file name, byte count, and
//! archive index only. It never reads or interprets log contents.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::state::{self, StateError, StatePaths};

/// Default maximum active log size before rotation.
pub const DEFAULT_LOG_ROTATE_MAX_BYTES: u64 = 1024 * 1024;
/// Default number of rotated archives to keep per active log.
pub const DEFAULT_LOG_ROTATE_KEEP_ARCHIVES: usize = 5;
/// Schema id for payload-safe local telemetry snapshots.
pub const TELEMETRY_SNAPSHOT_SCHEMA: &str = "conu.telemetry.snapshot.v1";
/// Explicit allowlist for the local telemetry snapshot exporter.
///
/// These fields are aggregate readiness/counter values only. They exclude node
/// ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, secret
/// material, and payload contents.
pub const TELEMETRY_FIELD_ALLOWLIST: &[&str] = &[
    "schema",
    "fieldAllowlist",
    "state.initialized",
    "state.configReady",
    "state.trustStoreReady",
    "state.agentRegistryReady",
    "runtime.state",
    "runtime.health",
    "runtime.heartbeatAgeSecs",
    "agents.local",
    "agents.remote",
    "agents.trustedPeers",
    "agents.sessions",
    "streams.total",
    "streams.open",
    "rooms.total",
    "rooms.events",
    "routes.selected",
    "routes.selectedDirect",
    "routes.selectedRelay",
    "routes.relayFallbacks",
    "relay.queued",
    "relay.sent",
    "relay.rejected",
    "logs.payloadSafe",
    "logs.scannedFiles",
    "logs.issues",
    "security.initialized",
    "security.localPayloadEncryption",
    "security.signedAgentCards",
    "security.peerKeyExchange",
    "security.replayCache",
    "security.keyRotationPlan",
    "security.secretsOsProtected",
    "privacy.fieldAllowlistOnly",
    "privacy.contentsDisplayed",
];

/// Log rotation policy for local metadata logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRotationPolicy {
    pub max_bytes: u64,
    pub keep_archives: usize,
}

impl LogRotationPolicy {
    pub fn new(max_bytes: u64, keep_archives: usize) -> Result<Self, ObservabilityError> {
        if max_bytes == 0 {
            return Err(ObservabilityError::InvalidPolicy {
                reason: "log rotation max bytes must be greater than zero".to_string(),
            });
        }
        if keep_archives == 0 {
            return Err(ObservabilityError::InvalidPolicy {
                reason: "log rotation keep count must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            max_bytes,
            keep_archives,
        })
    }
}

impl Default for LogRotationPolicy {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_LOG_ROTATE_MAX_BYTES,
            keep_archives: DEFAULT_LOG_ROTATE_KEEP_ARCHIVES,
        }
    }
}

/// One payload-safe log rotation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRotationEntry {
    pub log_name: String,
    pub size_bytes: u64,
    pub rotated: bool,
    pub archives_removed: usize,
}

/// Payload-safe summary of one rotation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRotationReport {
    pub max_bytes: u64,
    pub keep_archives: usize,
    pub files_scanned: usize,
    pub files_rotated: usize,
    pub archives_removed: usize,
    pub entries: Vec<LogRotationEntry>,
}

/// Errors produced by observability maintenance.
#[derive(Debug)]
pub enum ObservabilityError {
    State(StateError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidPolicy {
        reason: String,
    },
}

impl ObservabilityError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for ObservabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidPolicy { reason } => {
                write!(formatter, "invalid log rotation policy: {reason}")
            }
        }
    }
}

impl std::error::Error for ObservabilityError {}

impl From<StateError> for ObservabilityError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// Rotate local metadata logs according to the provided policy.
pub fn rotate_logs(
    home_override: Option<PathBuf>,
    policy: LogRotationPolicy,
) -> Result<LogRotationReport, ObservabilityError> {
    let paths = StatePaths::resolve(home_override)?;
    rotate_logs_from_paths(&paths, policy)
}

/// Rotate local metadata logs from already resolved paths.
pub fn rotate_logs_from_paths(
    paths: &StatePaths,
    policy: LogRotationPolicy,
) -> Result<LogRotationReport, ObservabilityError> {
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.logs_dir)?;

    let mut entries = Vec::new();
    for entry in fs::read_dir(&paths.logs_dir)
        .map_err(|error| ObservabilityError::io("read logs directory", &paths.logs_dir, error))?
    {
        let entry = entry.map_err(|error| {
            ObservabilityError::io("read logs directory entry", &paths.logs_dir, error)
        })?;
        let path = entry.path();
        if !is_active_log_file(&path) {
            continue;
        }

        let Some(metadata) = active_log_metadata(&path)? else {
            continue;
        };

        let size_bytes = metadata.len();
        let archives_removed = if size_bytes > policy.max_bytes {
            rotate_one_log(&path, policy.keep_archives)?
        } else {
            0
        };
        entries.push(LogRotationEntry {
            log_name: file_name(&path),
            size_bytes,
            rotated: size_bytes > policy.max_bytes,
            archives_removed,
        });
    }

    entries.sort_by(|left, right| left.log_name.cmp(&right.log_name));
    let files_rotated = entries.iter().filter(|entry| entry.rotated).count();
    let archives_removed = entries.iter().map(|entry| entry.archives_removed).sum();

    Ok(LogRotationReport {
        max_bytes: policy.max_bytes,
        keep_archives: policy.keep_archives,
        files_scanned: entries.len(),
        files_rotated,
        archives_removed,
        entries,
    })
}

fn rotate_one_log(path: &Path, keep_archives: usize) -> Result<usize, ObservabilityError> {
    ensure_regular_log_file(path, "inspect active log before rotation")?;
    let mut removed = 0;
    for index in (1..=keep_archives).rev() {
        let source = archive_path(path, index);
        if regular_log_metadata(&source, "inspect log archive")?.is_none() {
            continue;
        }
        if index == keep_archives {
            remove_existing_regular_log_file(
                &source,
                "inspect log archive",
                "remove old log archive",
            )?;
            removed += 1;
        } else {
            let target = archive_path(path, index + 1);
            archive_regular_log_file_no_replace(
                &source,
                &target,
                "inspect log archive",
                "reserve log archive target",
                "shift log archive",
            )?;
        }
    }

    let first_archive = archive_path(path, 1);
    archive_regular_log_file_no_replace(
        path,
        &first_archive,
        "inspect active log before rotation",
        "reserve log archive target",
        "rotate active log",
    )?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| ObservabilityError::io("create fresh active log", path, error))?;

    Ok(removed)
}

fn remove_existing_regular_log_file(
    path: &Path,
    inspect_action: &'static str,
    remove_action: &'static str,
) -> Result<(), ObservabilityError> {
    if regular_log_metadata(path, inspect_action)?.is_none() {
        return Err(ObservabilityError::io(
            inspect_action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "log path does not exist"),
        ));
    }

    fs::remove_file(path).map_err(|error| ObservabilityError::io(remove_action, path, error))
}

fn archive_regular_log_file_no_replace(
    source: &Path,
    target: &Path,
    inspect_source_action: &'static str,
    inspect_target_action: &'static str,
    archive_action: &'static str,
) -> Result<(), ObservabilityError> {
    let Some(source_metadata) = regular_log_metadata(source, inspect_source_action)? else {
        return Err(ObservabilityError::io(
            inspect_source_action,
            source,
            io::Error::new(io::ErrorKind::NotFound, "log path does not exist"),
        ));
    };

    let target_parent = path_parent(target);
    if !state::state_directory_exists(target_parent, inspect_target_action)? {
        return Err(ObservabilityError::io(
            inspect_target_action,
            target_parent,
            io::Error::new(io::ErrorKind::NotFound, "log archive directory is missing"),
        ));
    }
    if regular_log_metadata(target, inspect_target_action)?.is_some() {
        return Err(ObservabilityError::io(
            inspect_target_action,
            target,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "log archive target already exists",
            ),
        ));
    }

    fs::hard_link(source, target)
        .map_err(|error| ObservabilityError::io(archive_action, source, error))?;

    let target_metadata = match regular_log_metadata(target, inspect_target_action) {
        Ok(Some(metadata)) => metadata,
        Ok(None) => {
            return Err(ObservabilityError::io(
                inspect_target_action,
                target,
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "log archive target disappeared after reservation",
                ),
            ));
        }
        Err(error) => {
            let _ = fs::remove_file(target);
            return Err(error);
        }
    };
    if !log_file_metadata_matches(&source_metadata, &target_metadata) {
        let _ = fs::remove_file(target);
        return Err(ObservabilityError::io(
            inspect_target_action,
            target,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "log archive target does not match source file",
            ),
        ));
    }

    match regular_log_metadata(source, inspect_source_action)? {
        Some(current_metadata)
            if log_file_metadata_matches(&source_metadata, &current_metadata) => {}
        Some(_) => {
            let _ = fs::remove_file(target);
            return Err(ObservabilityError::io(
                inspect_source_action,
                source,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "log file path changed before archive removal",
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
            Err(ObservabilityError::io(archive_action, source, error))
        }
    }
}

fn regular_log_metadata(
    path: &Path,
    action: &'static str,
) -> Result<Option<fs::Metadata>, ObservabilityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ObservabilityError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "log path is not a regular file",
                    ),
                ));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ObservabilityError::io(action, path, error)),
    }
}

fn log_file_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && log_file_stable_identity_matches(expected, current)
}

#[cfg(unix)]
fn log_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn log_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(not(any(unix, windows)))]
fn log_file_stable_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

fn path_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn active_log_metadata(path: &Path) -> Result<Option<fs::Metadata>, ObservabilityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Ok(None);
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ObservabilityError::io("read log metadata", path, error)),
    }
}

fn ensure_regular_log_file(path: &Path, action: &'static str) -> Result<(), ObservabilityError> {
    match regular_log_metadata(path, action)? {
        Some(_) => Ok(()),
        None => Err(ObservabilityError::io(
            action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "log path does not exist"),
        )),
    }
}

fn is_active_log_file(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("log")
}

fn archive_path(path: &Path, index: usize) -> PathBuf {
    path.with_file_name(format!("{}.{}", file_name(path), index))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown.log")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rotates_large_logs_without_reading_or_reporting_contents() {
        let home = test_home("rotate-large");
        let paths = StatePaths::from_home(home);
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("small.log"),
            "event=small payload=not_observed\n",
        )
        .expect("small log writes");
        fs::write(
            paths.logs_dir.join("conud.log"),
            "event=large bytes=123 payload=not_observed\n",
        )
        .expect("large log writes");

        let report = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(8, 2).expect("policy validates"),
        )
        .expect("logs rotate");

        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.files_rotated, 2);
        assert_eq!(report.archives_removed, 0);
        assert!(paths.logs_dir.join("conud.log").exists());
        assert!(paths.logs_dir.join("conud.log.1").exists());
        assert_eq!(
            fs::read_to_string(paths.logs_dir.join("conud.log")).expect("fresh log reads"),
            ""
        );
        assert!(
            fs::read_to_string(paths.logs_dir.join("conud.log.1"))
                .expect("archive reads")
                .contains("payload=not_observed")
        );
        assert!(!format!("{report:?}").contains("event=large"));
    }

    #[test]
    fn keeps_bounded_archives_per_log() {
        let home = test_home("rotate-keep");
        let paths = StatePaths::from_home(home);
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(paths.logs_dir.join("conud.log"), "active active\n").expect("active writes");
        fs::write(paths.logs_dir.join("conud.log.1"), "archive one\n").expect("archive writes");
        fs::write(paths.logs_dir.join("conud.log.2"), "archive two\n").expect("archive writes");

        let report = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(4, 2).expect("policy validates"),
        )
        .expect("logs rotate");

        assert_eq!(report.files_rotated, 1);
        assert_eq!(report.archives_removed, 1);
        assert_eq!(
            fs::read_to_string(paths.logs_dir.join("conud.log.1")).expect("archive one reads"),
            "active active\n"
        );
        assert_eq!(
            fs::read_to_string(paths.logs_dir.join("conud.log.2")).expect("archive two reads"),
            "archive one\n"
        );
    }

    #[test]
    fn rotates_log_larger_than_state_file_limit() {
        let home = test_home("rotate-oversized-log");
        let paths = StatePaths::from_home(home);
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("conud.log"),
            vec![b'x'; 1024 * 1024 + 1],
        )
        .expect("oversized log writes");

        let report = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(1, 2).expect("policy validates"),
        )
        .expect("oversized log rotates");

        assert_eq!(report.files_rotated, 1);
        assert_eq!(
            fs::metadata(paths.logs_dir.join("conud.log.1"))
                .expect("oversized archive metadata")
                .len(),
            1024 * 1024 + 1
        );
        assert_eq!(
            fs::metadata(paths.logs_dir.join("conud.log"))
                .expect("fresh active metadata")
                .len(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinked_active_log_without_touching_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("active-symlink");
        let paths = StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        let outside = home.join("outside.log");
        let link = paths.logs_dir.join("conud.log");
        fs::write(&outside, "outside payload-safe log\n").expect("outside log writes");
        symlink(&outside, &link).expect("active log symlink creates");

        let report = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(1, 2).expect("policy validates"),
        )
        .expect("logs rotate");

        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.files_rotated, 0);
        assert_eq!(
            fs::read_to_string(&outside).expect("outside log reads"),
            "outside payload-safe log\n"
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("active link metadata")
                .file_type()
                .is_symlink()
        );
        assert!(!paths.logs_dir.join("conud.log.1").exists());
    }

    #[cfg(unix)]
    #[test]
    fn archive_symlink_fails_before_rotating_active_log() {
        use std::os::unix::fs::symlink;

        let home = test_home("archive-symlink");
        let paths = StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        let active = paths.logs_dir.join("conud.log");
        let outside = home.join("outside-archive");
        let archive_link = paths.logs_dir.join("conud.log.1");
        fs::write(&active, "active active\n").expect("active writes");
        fs::write(&outside, "outside archive\n").expect("outside archive writes");
        symlink(&outside, &archive_link).expect("archive symlink creates");

        let error = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(4, 2).expect("policy validates"),
        )
        .expect_err("archive symlink should fail closed");

        assert!(error.to_string().contains("inspect log archive"));
        assert_eq!(
            fs::read_to_string(&active).expect("active reads"),
            "active active\n"
        );
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "outside archive\n"
        );
        assert!(
            fs::symlink_metadata(&archive_link)
                .expect("archive link metadata")
                .file_type()
                .is_symlink()
        );
        assert!(!paths.logs_dir.join("conud.log.2").exists());
    }

    #[test]
    fn archive_directory_fails_before_rotating_active_log() {
        let home = test_home("archive-directory");
        let paths = StatePaths::from_home(home);
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        let active = paths.logs_dir.join("conud.log");
        let archive_dir = paths.logs_dir.join("conud.log.1");
        fs::write(&active, "active active\n").expect("active writes");
        fs::create_dir_all(&archive_dir).expect("archive directory creates");

        let error = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(4, 2).expect("policy validates"),
        )
        .expect_err("archive directory should fail closed");

        assert!(error.to_string().contains("inspect log archive"));
        assert_eq!(
            fs::read_to_string(&active).expect("active reads"),
            "active active\n"
        );
        assert!(archive_dir.is_dir());
        assert!(!paths.logs_dir.join("conud.log.2").exists());
    }

    #[cfg(unix)]
    #[test]
    fn home_symlink_fails_before_creating_logs_directory() {
        use std::os::unix::fs::symlink;

        let home = test_home("home-symlink");
        let outside = test_home("home-symlink-target");
        fs::create_dir_all(&outside).expect("outside directory creates");
        symlink(&outside, &home).expect("home symlink creates");
        let paths = StatePaths::from_home(home.clone());

        let error = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(1, 2).expect("policy validates"),
        )
        .expect_err("home symlink should fail closed");

        assert!(error.to_string().contains("inspect state directory"));
        assert!(!outside.join("logs").exists());
        assert!(
            fs::symlink_metadata(&home)
                .expect("home link metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn logs_directory_symlink_fails_before_rotating_target_logs() {
        use std::os::unix::fs::symlink;

        let home = test_home("logs-dir-symlink");
        let paths = StatePaths::from_home(home.clone());
        let outside = test_home("logs-dir-symlink-target");
        fs::create_dir_all(&home).expect("home directory creates");
        fs::create_dir_all(&outside).expect("outside directory creates");
        fs::write(outside.join("conud.log"), "outside active log\n").expect("outside log writes");
        symlink(&outside, &paths.logs_dir).expect("logs directory symlink creates");

        let error = rotate_logs_from_paths(
            &paths,
            LogRotationPolicy::new(1, 2).expect("policy validates"),
        )
        .expect_err("logs directory symlink should fail closed");

        assert!(error.to_string().contains("inspect state directory"));
        assert_eq!(
            fs::read_to_string(outside.join("conud.log")).expect("outside log reads"),
            "outside active log\n"
        );
        assert!(!outside.join("conud.log.1").exists());
        assert!(
            fs::symlink_metadata(&paths.logs_dir)
                .expect("logs link metadata")
                .file_type()
                .is_symlink()
        );
    }

    fn test_home(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "conu-observability-test-{}-{}-{name}",
            process::id(),
            current_unix_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn current_unix_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
