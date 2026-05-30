//! Payload-safe observability maintenance.
//!
//! This module manages local conU metadata logs by file name, byte count, and
//! archive index only. It never reads or interprets log contents.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::state::{StateError, StatePaths};

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
    fs::create_dir_all(&paths.logs_dir)
        .map_err(|error| ObservabilityError::io("create logs directory", &paths.logs_dir, error))?;

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
            fs::remove_file(&source).map_err(|error| {
                ObservabilityError::io("remove old log archive", &source, error)
            })?;
            removed += 1;
        } else {
            let target = archive_path(path, index + 1);
            ensure_log_archive_target_available(&target)?;
            fs::rename(&source, &target)
                .map_err(|error| ObservabilityError::io("shift log archive", &source, error))?;
        }
    }

    let first_archive = archive_path(path, 1);
    ensure_log_archive_target_available(&first_archive)?;
    fs::rename(path, &first_archive)
        .map_err(|error| ObservabilityError::io("rotate active log", path, error))?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| ObservabilityError::io("create fresh active log", path, error))?;

    Ok(removed)
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

fn ensure_log_archive_target_available(path: &Path) -> Result<(), ObservabilityError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ObservabilityError::io(
            "reserve log archive target",
            path,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "log archive target already exists",
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ObservabilityError::io(
            "inspect log archive target",
            path,
            error,
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
