//! Local conUD runtime state and heartbeat management.
//!
//! Phase 9 uses file-backed health, gateway state, local messages, and remote
//! session mirrors so the CLI can detect conUD-owned communication state.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::state::{self, NodeIdentity, StateError, StatePaths};
use crate::{agents, direct_transport, messages, relay_delivery, sessions};

const STATUS_VERSION: &str = "1";
const STALE_AFTER_SECS: u64 = 10;
const LOCAL_ENDPOINT: &str = "file-ipc:runtime/ipc/inbox";
const RELAY_PUMP_WAIT_MS: u64 = 850;
const RELAY_PUMP_ERROR_BACKOFF_SECS: u64 = 5;
const MAX_RUNTIME_CONTROL_FILE_BYTES: u64 = 1024 * 1024;

/// High-level state for the local conUD runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    Offline,
    Starting,
    Running,
    Stopping,
    Stopped,
    Stale,
}

impl RuntimeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Stale => "stale",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "starting" => Self::Starting,
            "running" => Self::Running,
            "stopping" => Self::Stopping,
            "stopped" => Self::Stopped,
            "stale" => Self::Stale,
            _ => Self::Offline,
        }
    }

    pub const fn is_live(self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Stopping)
    }
}

/// Runtime metadata visible to the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub state: RuntimeState,
    pub pid: Option<u32>,
    pub node_id: Option<String>,
    pub started_at_unix: Option<u64>,
    pub heartbeat_at_unix: Option<u64>,
    pub local_endpoint: String,
    pub status_path: PathBuf,
    pub lock_path: PathBuf,
}

impl RuntimeStatus {
    /// True when the runtime heartbeat is fresh enough to treat as alive.
    pub fn is_live(&self) -> bool {
        self.state.is_live()
    }

    /// Seconds since the latest heartbeat, if a heartbeat exists.
    pub fn heartbeat_age_secs(&self) -> Option<u64> {
        self.heartbeat_at_unix
            .map(|heartbeat| current_unix_seconds().saturating_sub(heartbeat))
    }
}

/// Result of asking conUD to stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    pub requested: bool,
    pub status: RuntimeStatus,
}

/// Metadata-only summary for one conUD processing tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProcessReport {
    pub agents_processed: usize,
    pub agents_rejected: usize,
    pub messages_delivered: usize,
    pub messages_rejected: usize,
    pub sessions_synced: usize,
    pub remote_agents_synced: usize,
    pub relay_attempted: bool,
    pub relay_connected: bool,
    pub relay_sent: usize,
    pub relay_received: usize,
    pub relay_undelivered: usize,
    pub relay_rejected: usize,
    pub relay_error: bool,
    pub direct_attempted: bool,
    pub direct_listening: bool,
    pub direct_received: usize,
    pub direct_rejected: usize,
    pub direct_error: bool,
}

/// An acquired local runtime slot.
#[derive(Debug)]
pub struct RuntimeLease {
    paths: StatePaths,
    node: NodeIdentity,
    pid: u32,
    started_at_unix: u64,
    stopped: bool,
}

impl RuntimeLease {
    /// Return the currently known status for this runtime lease.
    pub fn status(&self) -> RuntimeStatus {
        self.build_status(RuntimeState::Running, current_unix_seconds())
    }

    /// Refresh the heartbeat file.
    pub fn heartbeat(&self) -> Result<RuntimeStatus, RuntimeError> {
        let status = self.build_status(RuntimeState::Running, current_unix_seconds());
        write_status(&self.paths, &status)?;
        append_log(&self.paths, "heartbeat", self.pid, &self.node.node_id)?;
        Ok(status)
    }

    /// True when the CLI has requested a graceful shutdown.
    pub fn stop_requested(&self) -> bool {
        self.paths.runtime_stop_request.exists()
    }

    /// Process local IPC, route/session mirrors, and one bounded relay pump.
    pub fn process_once(&self, relay_wait: Duration) -> Result<RuntimeProcessReport, RuntimeError> {
        let agent_report =
            agents::process_gateway_requests_from_paths(&self.paths, &self.node.node_id)
                .map_err(RuntimeError::Agent)?;
        let message_report = messages::process_message_requests_from_paths(&self.paths)
            .map_err(RuntimeError::Message)?;
        let session_report = sessions::sync_remote_sessions_from_paths(&self.paths)
            .map_err(RuntimeError::Session)?;
        let mut report = RuntimeProcessReport {
            agents_processed: agent_report.processed,
            agents_rejected: agent_report.rejected,
            messages_delivered: message_report.delivered,
            messages_rejected: message_report.rejected,
            sessions_synced: session_report.sessions_synced,
            remote_agents_synced: session_report.remote_agents_synced,
            relay_attempted: false,
            relay_connected: false,
            relay_sent: 0,
            relay_received: 0,
            relay_undelivered: 0,
            relay_rejected: 0,
            relay_error: false,
            direct_attempted: false,
            direct_listening: false,
            direct_received: 0,
            direct_rejected: 0,
            direct_error: false,
        };

        self.pump_relay_once(&mut report, relay_wait)?;
        Ok(report)
    }

    /// Sleep and heartbeat until a stop request appears.
    pub fn serve_until_stop(&self, heartbeat_every: Duration) -> Result<(), RuntimeError> {
        let mut next_relay_attempt = Instant::now();
        let mut relay_pump = relay_delivery::RelayRuntimePump::new();
        let mut direct_server = direct_transport::DirectRuntimeServer::new().ok();

        while !self.stop_requested() {
            self.heartbeat()?;
            if Instant::now() >= next_relay_attempt {
                let report = self.process_once_with_relay_pump(
                    Duration::from_millis(RELAY_PUMP_WAIT_MS),
                    &mut relay_pump,
                    direct_server.as_mut(),
                )?;
                if report.relay_error {
                    next_relay_attempt =
                        Instant::now() + Duration::from_secs(RELAY_PUMP_ERROR_BACKOFF_SECS);
                }
            } else {
                self.process_local_once(direct_server.as_mut())?;
            }
            thread::sleep(heartbeat_every);
        }

        let status = self.build_status(RuntimeState::Stopping, current_unix_seconds());
        write_status(&self.paths, &status)?;
        append_log(&self.paths, "stop_requested", self.pid, &self.node.node_id)?;
        Ok(())
    }

    /// Stop this runtime and clean up the process lock.
    pub fn stop(mut self) -> Result<RuntimeStatus, RuntimeError> {
        self.finish()
    }

    fn build_status(&self, state: RuntimeState, heartbeat_at_unix: u64) -> RuntimeStatus {
        RuntimeStatus {
            state,
            pid: Some(self.pid),
            node_id: Some(self.node.node_id.clone()),
            started_at_unix: Some(self.started_at_unix),
            heartbeat_at_unix: Some(heartbeat_at_unix),
            local_endpoint: LOCAL_ENDPOINT.to_string(),
            status_path: self.paths.runtime_status.clone(),
            lock_path: self.paths.runtime_lock.clone(),
        }
    }

    fn finish(&mut self) -> Result<RuntimeStatus, RuntimeError> {
        if self.stopped {
            return read_runtime_from_paths(&self.paths);
        }

        let status = self.build_status(RuntimeState::Stopped, current_unix_seconds());
        write_status(&self.paths, &status)?;
        remove_file_if_exists(&self.paths.runtime_lock)?;
        remove_file_if_exists(&self.paths.runtime_stop_request)?;
        append_log(&self.paths, "stopped", self.pid, &self.node.node_id)?;
        self.stopped = true;

        Ok(status)
    }

    fn process_local_once(
        &self,
        direct_server: Option<&mut direct_transport::DirectRuntimeServer>,
    ) -> Result<(), RuntimeError> {
        agents::process_gateway_requests_from_paths(&self.paths, &self.node.node_id)
            .map_err(RuntimeError::Agent)?;
        messages::process_message_requests_from_paths(&self.paths)
            .map_err(RuntimeError::Message)?;
        sessions::sync_remote_sessions_from_paths(&self.paths).map_err(RuntimeError::Session)?;
        self.pump_direct_once(direct_server, Duration::from_millis(100))?;
        Ok(())
    }

    fn process_once_with_relay_pump(
        &self,
        relay_wait: Duration,
        relay_pump: &mut relay_delivery::RelayRuntimePump,
        direct_server: Option<&mut direct_transport::DirectRuntimeServer>,
    ) -> Result<RuntimeProcessReport, RuntimeError> {
        let agent_report =
            agents::process_gateway_requests_from_paths(&self.paths, &self.node.node_id)
                .map_err(RuntimeError::Agent)?;
        let message_report = messages::process_message_requests_from_paths(&self.paths)
            .map_err(RuntimeError::Message)?;
        let session_report = sessions::sync_remote_sessions_from_paths(&self.paths)
            .map_err(RuntimeError::Session)?;
        let mut report = RuntimeProcessReport {
            agents_processed: agent_report.processed,
            agents_rejected: agent_report.rejected,
            messages_delivered: message_report.delivered,
            messages_rejected: message_report.rejected,
            sessions_synced: session_report.sessions_synced,
            remote_agents_synced: session_report.remote_agents_synced,
            relay_attempted: false,
            relay_connected: false,
            relay_sent: 0,
            relay_received: 0,
            relay_undelivered: 0,
            relay_rejected: 0,
            relay_error: false,
            direct_attempted: false,
            direct_listening: false,
            direct_received: 0,
            direct_rejected: 0,
            direct_error: false,
        };

        self.pump_relay_persistent(&mut report, relay_pump, relay_wait)?;
        self.pump_direct_persistent(&mut report, direct_server, Duration::from_millis(100))?;
        Ok(report)
    }

    fn pump_relay_once(
        &self,
        report: &mut RuntimeProcessReport,
        wait: Duration,
    ) -> Result<(), RuntimeError> {
        match relay_delivery::relay_runtime_should_sync_from_paths(&self.paths) {
            Ok(true) => {
                report.relay_attempted = true;
                match relay_delivery::sync_relay_once_from_paths(
                    &self.paths,
                    &self.node.node_id,
                    wait,
                ) {
                    Ok(relay_report) => {
                        report.relay_connected = relay_report.connected;
                        report.relay_sent = relay_report.sent;
                        report.relay_received = relay_report.received;
                        report.relay_undelivered = relay_report.undelivered;
                        report.relay_rejected = relay_report.rejected;
                        if relay_report.sent > 0
                            || relay_report.received > 0
                            || relay_report.undelivered > 0
                            || relay_report.rejected > 0
                        {
                            append_log(
                                &self.paths,
                                "relay_pump_activity",
                                self.pid,
                                &self.node.node_id,
                            )?;
                        }
                    }
                    Err(_) => {
                        report.relay_error = true;
                        append_log(
                            &self.paths,
                            "relay_pump_retry",
                            self.pid,
                            &self.node.node_id,
                        )?;
                    }
                }
            }
            Ok(false) => {}
            Err(_) => {
                report.relay_error = true;
                append_log(
                    &self.paths,
                    "relay_pump_retry",
                    self.pid,
                    &self.node.node_id,
                )?;
            }
        }

        Ok(())
    }

    fn pump_relay_persistent(
        &self,
        report: &mut RuntimeProcessReport,
        relay_pump: &mut relay_delivery::RelayRuntimePump,
        wait: Duration,
    ) -> Result<(), RuntimeError> {
        match relay_delivery::relay_runtime_should_sync_from_paths(&self.paths) {
            Ok(true) => {
                report.relay_attempted = true;
                match relay_pump.tick_from_paths(&self.paths, &self.node.node_id, wait) {
                    Ok(relay_report) => {
                        report.relay_connected = relay_report.connected;
                        report.relay_sent = relay_report.sent;
                        report.relay_received = relay_report.received;
                        report.relay_undelivered = relay_report.undelivered;
                        report.relay_rejected = relay_report.rejected;
                        if relay_report.sent > 0
                            || relay_report.received > 0
                            || relay_report.undelivered > 0
                            || relay_report.rejected > 0
                        {
                            append_log(
                                &self.paths,
                                "relay_pump_activity",
                                self.pid,
                                &self.node.node_id,
                            )?;
                        }
                    }
                    Err(_) => {
                        report.relay_error = true;
                        append_log(
                            &self.paths,
                            "relay_pump_retry",
                            self.pid,
                            &self.node.node_id,
                        )?;
                    }
                }
            }
            Ok(false) => relay_pump.disconnect(),
            Err(_) => {
                report.relay_error = true;
                relay_pump.disconnect();
                append_log(
                    &self.paths,
                    "relay_pump_retry",
                    self.pid,
                    &self.node.node_id,
                )?;
            }
        }

        Ok(())
    }

    fn pump_direct_once(
        &self,
        direct_server: Option<&mut direct_transport::DirectRuntimeServer>,
        wait: Duration,
    ) -> Result<(), RuntimeError> {
        let Some(server) = direct_server else {
            return Ok(());
        };
        match server.tick_from_paths(&self.paths, &self.node.node_id, wait) {
            Ok(_) => Ok(()),
            Err(_) => {
                append_log(
                    &self.paths,
                    "direct_quic_retry",
                    self.pid,
                    &self.node.node_id,
                )?;
                Ok(())
            }
        }
    }

    fn pump_direct_persistent(
        &self,
        report: &mut RuntimeProcessReport,
        direct_server: Option<&mut direct_transport::DirectRuntimeServer>,
        wait: Duration,
    ) -> Result<(), RuntimeError> {
        let Some(server) = direct_server else {
            return Ok(());
        };
        match server.tick_from_paths(&self.paths, &self.node.node_id, wait) {
            Ok(direct_report) => {
                report.direct_attempted = direct_report.enabled;
                report.direct_listening = direct_report.listening;
                report.direct_received = direct_report.received;
                report.direct_rejected = direct_report.rejected;
                if direct_report.received > 0 || direct_report.rejected > 0 {
                    append_log(
                        &self.paths,
                        "direct_quic_activity",
                        self.pid,
                        &self.node.node_id,
                    )?;
                }
            }
            Err(_) => {
                report.direct_error = true;
                append_log(
                    &self.paths,
                    "direct_quic_retry",
                    self.pid,
                    &self.node.node_id,
                )?;
            }
        }
        Ok(())
    }
}

impl Drop for RuntimeLease {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Errors produced by the local runtime lifecycle.
#[derive(Debug)]
pub enum RuntimeError {
    State(StateError),
    Agent(agents::AgentError),
    Message(messages::MessageError),
    Session(sessions::SessionError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    AlreadyRunning(Box<RuntimeStatus>),
}

impl RuntimeError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::AlreadyRunning(status) => {
                let pid = status
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                write!(formatter, "conUD is already running with pid {pid}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<StateError> for RuntimeError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<agents::AgentError> for RuntimeError {
    fn from(error: agents::AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<messages::MessageError> for RuntimeError {
    fn from(error: messages::MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<sessions::SessionError> for RuntimeError {
    fn from(error: sessions::SessionError) -> Self {
        Self::Session(error)
    }
}

/// Read the local runtime status without changing it.
pub fn read_runtime(home_override: Option<PathBuf>) -> Result<RuntimeStatus, RuntimeError> {
    let paths = StatePaths::resolve(home_override)?;
    read_runtime_from_paths(&paths)
}

/// Acquire the local conUD runtime slot.
pub fn acquire_runtime(home_override: Option<PathBuf>) -> Result<RuntimeLease, RuntimeError> {
    let init = state::init_state(home_override)?;
    let paths = init.paths;
    let existing = read_runtime_from_paths(&paths)?;

    if existing.is_live() {
        return Err(RuntimeError::AlreadyRunning(Box::new(existing)));
    }

    if existing.state == RuntimeState::Stale || paths.runtime_lock.exists() {
        clear_runtime_files(&paths)?;
    }

    let pid = process::id();
    let started_at_unix = current_unix_seconds();
    write_lock(&paths, pid, started_at_unix)?;
    remove_file_if_exists(&paths.runtime_stop_request)?;

    let lease = RuntimeLease {
        paths,
        node: init.node,
        pid,
        started_at_unix,
        stopped: false,
    };

    let starting = lease.build_status(RuntimeState::Starting, started_at_unix);
    write_status(&lease.paths, &starting)?;
    append_log(&lease.paths, "started", lease.pid, &lease.node.node_id)?;
    lease.heartbeat()?;

    Ok(lease)
}

/// Ask a running local conUD process to shut down gracefully.
pub fn request_runtime_stop(home_override: Option<PathBuf>) -> Result<StopReport, RuntimeError> {
    let paths = StatePaths::resolve(home_override)?;
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.runtime_dir)?;

    let status = read_runtime_from_paths(&paths)?;
    if status.is_live() {
        let contents = format!("requested_at_unix = {}\n", current_unix_seconds());
        write_runtime_control_file(
            &paths.runtime_stop_request,
            &contents,
            "inspect runtime stop request",
            "create runtime stop request",
            "open runtime stop request",
            "truncate runtime stop request",
            "write runtime stop request",
        )?;
        append_log(
            &paths,
            "stop_requested_by_cli",
            process::id(),
            status.node_id.as_deref().unwrap_or("unknown"),
        )?;
        Ok(StopReport {
            requested: true,
            status,
        })
    } else if status.state == RuntimeState::Stale {
        let stopped = RuntimeStatus {
            state: RuntimeState::Stopped,
            heartbeat_at_unix: Some(current_unix_seconds()),
            ..status
        };
        clear_runtime_files(&paths)?;
        write_status(&paths, &stopped)?;
        Ok(StopReport {
            requested: false,
            status: stopped,
        })
    } else {
        Ok(StopReport {
            requested: false,
            status,
        })
    }
}

fn read_runtime_from_paths(paths: &StatePaths) -> Result<RuntimeStatus, RuntimeError> {
    if !state::state_directory_exists(&paths.home, "inspect state directory")? {
        return Ok(offline_status(paths));
    }
    if !state::state_directory_exists(&paths.runtime_dir, "inspect runtime directory")? {
        return Ok(offline_status(paths));
    }

    let Some(contents) = read_runtime_control_file(&paths.runtime_status, "read runtime status")?
    else {
        return Ok(offline_status(paths));
    };
    let values = parse_key_values(&contents);
    let mut status = RuntimeStatus {
        state: RuntimeState::from_str(value_or_empty(&values, "state")),
        pid: parse_u32(values.get("pid")),
        node_id: values
            .get("node_id")
            .cloned()
            .filter(|value| !value.is_empty()),
        started_at_unix: parse_u64(values.get("started_at_unix")),
        heartbeat_at_unix: parse_u64(values.get("heartbeat_at_unix")),
        local_endpoint: values
            .get("local_endpoint")
            .cloned()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| LOCAL_ENDPOINT.to_string()),
        status_path: paths.runtime_status.clone(),
        lock_path: paths.runtime_lock.clone(),
    };

    if status.state.is_live() && runtime_is_stale(&status) {
        status.state = RuntimeState::Stale;
    }

    Ok(status)
}

fn write_status(paths: &StatePaths, status: &RuntimeStatus) -> Result<(), RuntimeError> {
    let contents = format!(
        "version = \"{}\"\nstate = \"{}\"\npid = {}\nnode_id = \"{}\"\nstarted_at_unix = {}\nheartbeat_at_unix = {}\nlocal_endpoint = \"{}\"\n",
        STATUS_VERSION,
        status.state.as_str(),
        status.pid.unwrap_or_default(),
        escape_file_value(status.node_id.as_deref().unwrap_or("")),
        status.started_at_unix.unwrap_or_default(),
        status.heartbeat_at_unix.unwrap_or_default(),
        escape_file_value(&status.local_endpoint)
    );

    write_runtime_control_file(
        &paths.runtime_status,
        &contents,
        "inspect runtime status",
        "create runtime status",
        "open runtime status",
        "truncate runtime status",
        "write runtime status",
    )
}

fn write_lock(paths: &StatePaths, pid: u32, started_at_unix: u64) -> Result<(), RuntimeError> {
    let contents = format!("pid = {pid}\nstarted_at_unix = {started_at_unix}\n");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&paths.runtime_lock)
        .map_err(|error| RuntimeError::io("create runtime lock", &paths.runtime_lock, error))?;

    file.write_all(contents.as_bytes())
        .map_err(|error| RuntimeError::io("write runtime lock", &paths.runtime_lock, error))
}

fn read_runtime_control_file(
    path: &Path,
    action: &'static str,
) -> Result<Option<String>, RuntimeError> {
    let Some(metadata) = regular_runtime_control_metadata(path, action)? else {
        return Ok(None);
    };

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| RuntimeError::io(action, path, error))?;
    let Some(path_metadata) = regular_runtime_control_metadata(path, action)? else {
        return Err(RuntimeError::io(
            action,
            path,
            io::Error::new(io::ErrorKind::NotFound, "runtime control path is missing"),
        ));
    };
    if !runtime_control_metadata_matches(&metadata, &path_metadata) {
        return Err(RuntimeError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime control path changed while reading",
            ),
        ));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| RuntimeError::io(action, path, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_RUNTIME_CONTROL_FILE_BYTES
        || !runtime_control_metadata_matches(&metadata, &opened_metadata)
    {
        return Err(RuntimeError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime control path changed while reading",
            ),
        ));
    }

    let mut contents = String::new();
    let limit = MAX_RUNTIME_CONTROL_FILE_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_string(&mut contents)
        .map_err(|error| RuntimeError::io(action, path, error))?;
    if contents.len() as u64 > MAX_RUNTIME_CONTROL_FILE_BYTES {
        return Err(RuntimeError::io(
            action,
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("runtime control file exceeds {MAX_RUNTIME_CONTROL_FILE_BYTES} bytes"),
            ),
        ));
    }

    Ok(Some(contents))
}

fn write_runtime_control_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    create_action: &'static str,
    open_action: &'static str,
    truncate_action: &'static str,
    write_action: &'static str,
) -> Result<(), RuntimeError> {
    match regular_runtime_control_metadata(path, inspect_action)? {
        Some(_) => {
            let mut file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|error| RuntimeError::io(open_action, path, error))?;
            file.set_len(0)
                .map_err(|error| RuntimeError::io(truncate_action, path, error))?;
            file.write_all(contents.as_bytes())
                .map_err(|error| RuntimeError::io(write_action, path, error))
        }
        None => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| RuntimeError::io(create_action, path, error))?;
            file.write_all(contents.as_bytes())
                .map_err(|error| RuntimeError::io(write_action, path, error))
        }
    }
}

fn regular_runtime_control_metadata(
    path: &Path,
    action: &'static str,
) -> Result<Option<fs::Metadata>, RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(RuntimeError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "runtime control path is not a regular file",
                    ),
                ));
            }
            if metadata.len() > MAX_RUNTIME_CONTROL_FILE_BYTES {
                return Err(RuntimeError::io(
                    action,
                    path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "runtime control file exceeds {MAX_RUNTIME_CONTROL_FILE_BYTES} bytes"
                        ),
                    ),
                ));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(RuntimeError::io(action, path, error)),
    }
}

fn runtime_control_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && runtime_control_identity_matches(expected, current)
}

#[cfg(unix)]
fn runtime_control_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn runtime_control_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(not(any(unix, windows)))]
fn runtime_control_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

fn append_log(
    paths: &StatePaths,
    event: &str,
    pid: u32,
    node_id: &str,
) -> Result<(), RuntimeError> {
    state::ensure_state_directory(&paths.logs_dir)?;
    let log_path = paths.logs_dir.join("conud.log");
    let line = format!(
        "time={} event={} pid={} node={} payload=not_observed",
        current_unix_seconds(),
        event,
        pid,
        sanitize_log_value(node_id)
    );

    state::append_regular_state_file(
        &log_path,
        &(line + "\n"),
        "inspect runtime log",
        "create runtime log",
        "open runtime log",
        "write runtime log",
    )?;
    Ok(())
}

fn runtime_is_stale(status: &RuntimeStatus) -> bool {
    let Some(heartbeat_at_unix) = status.heartbeat_at_unix else {
        return true;
    };

    current_unix_seconds().saturating_sub(heartbeat_at_unix) > STALE_AFTER_SECS
}

fn offline_status(paths: &StatePaths) -> RuntimeStatus {
    RuntimeStatus {
        state: RuntimeState::Offline,
        pid: None,
        node_id: None,
        started_at_unix: None,
        heartbeat_at_unix: None,
        local_endpoint: LOCAL_ENDPOINT.to_string(),
        status_path: paths.runtime_status.clone(),
        lock_path: paths.runtime_lock.clone(),
    }
}

fn clear_runtime_files(paths: &StatePaths) -> Result<(), RuntimeError> {
    remove_file_if_exists(&paths.runtime_lock)?;
    remove_file_if_exists(&paths.runtime_stop_request)
}

fn remove_file_if_exists(path: &Path) -> Result<(), RuntimeError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RuntimeError::io("remove runtime file", path, error)),
    }
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

fn value_or_empty<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values.get(key).map(String::as_str).unwrap_or("")
}

fn parse_u32(value: Option<&String>) -> Option<u32> {
    value.and_then(|value| value.parse::<u32>().ok())
}

fn parse_u64(value: Option<&String>) -> Option<u64> {
    value.and_then(|value| value.parse::<u64>().ok())
}

fn escape_file_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect()
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
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
    fn acquire_runtime_writes_live_status() {
        let home = test_home("live");
        let lease = acquire_runtime(Some(home.clone())).expect("runtime starts");
        let status = read_runtime(Some(home)).expect("runtime reads");

        assert!(status.is_live());
        assert_eq!(status.state, RuntimeState::Running);
        assert_eq!(status.pid, Some(process::id()));
        assert_eq!(status.node_id, Some(lease.node.node_id.clone()));
    }

    #[test]
    fn second_runtime_cannot_start_while_heartbeat_is_fresh() {
        let home = test_home("already-running");
        let _lease = acquire_runtime(Some(home.clone())).expect("runtime starts");
        let error = acquire_runtime(Some(home)).expect_err("second runtime should fail");

        assert!(matches!(error, RuntimeError::AlreadyRunning(_)));
    }

    #[test]
    fn stop_request_creates_payload_safe_control_file() {
        let home = test_home("stop-request");
        let _lease = acquire_runtime(Some(home.clone())).expect("runtime starts");
        let report = request_runtime_stop(Some(home.clone())).expect("stop requested");
        let request = fs::read_to_string(StatePaths::from_home(home).runtime_stop_request)
            .expect("stop request exists");

        assert!(report.requested);
        assert!(request.contains("requested_at_unix"));
        assert!(!request.contains("private message contents"));
    }

    #[cfg(unix)]
    #[test]
    fn stop_request_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("stop-request-symlink");
        let _lease = acquire_runtime(Some(home.clone())).expect("runtime starts");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.join("outside-stop-request");
        fs::write(&outside, "outside control\n").expect("outside writes");
        symlink(&outside, &paths.runtime_stop_request).expect("stop request symlink creates");

        let error =
            request_runtime_stop(Some(home)).expect_err("symlink stop request should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "outside control\n"
        );
        assert!(
            fs::symlink_metadata(&paths.runtime_stop_request)
                .expect("stop request symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_status_write_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("status-write-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.join("outside-status");
        fs::write(&outside, "outside status\n").expect("outside writes");
        symlink(&outside, &paths.runtime_status).expect("status symlink creates");
        let status = RuntimeStatus {
            state: RuntimeState::Running,
            pid: Some(process::id()),
            node_id: Some(init.node.node_id),
            started_at_unix: Some(1),
            heartbeat_at_unix: Some(1),
            local_endpoint: LOCAL_ENDPOINT.to_string(),
            status_path: paths.runtime_status.clone(),
            lock_path: paths.runtime_lock.clone(),
        };

        let error = write_status(&paths, &status).expect_err("symlink status should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "outside status\n"
        );
        assert!(
            fs::symlink_metadata(&paths.runtime_status)
                .expect("status symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_status_read_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("status-read-symlink");
        let paths = StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.runtime_dir).expect("runtime dir creates");
        let outside = home.join("outside-status");
        fs::write(
            &outside,
            "version = \"1\"\nstate = \"running\"\npid = 123\nnode_id = \"node_outside\"\nstarted_at_unix = 1\nheartbeat_at_unix = 1\nlocal_endpoint = \"file-ipc:runtime/ipc/inbox\"\n",
        )
        .expect("outside writes");
        symlink(&outside, &paths.runtime_status).expect("status symlink creates");

        let error = read_runtime(Some(home)).expect_err("symlink status should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside reads"),
            "version = \"1\"\nstate = \"running\"\npid = 123\nnode_id = \"node_outside\"\nstarted_at_unix = 1\nheartbeat_at_unix = 1\nlocal_endpoint = \"file-ipc:runtime/ipc/inbox\"\n"
        );
        assert!(
            fs::symlink_metadata(&paths.runtime_status)
                .expect("status symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_directory_symlink_is_rejected_without_reading_target_status() {
        use std::os::unix::fs::symlink;

        let home = test_home("runtime-dir-read-symlink");
        let paths = StatePaths::from_home(home.clone());
        let outside = test_home("runtime-dir-read-target");
        fs::create_dir_all(&home).expect("home creates");
        fs::create_dir_all(&outside).expect("outside runtime creates");
        fs::write(
            outside.join("status.toml"),
            "version = \"1\"\nstate = \"running\"\npid = 123\nnode_id = \"node_outside\"\nstarted_at_unix = 1\nheartbeat_at_unix = 1\nlocal_endpoint = \"file-ipc:runtime/ipc/inbox\"\n",
        )
        .expect("outside status writes");
        symlink(&outside, &paths.runtime_dir).expect("runtime dir symlink creates");

        let error = read_runtime(Some(home)).expect_err("runtime dir symlink should fail closed");

        assert!(error.to_string().contains("inspect runtime directory"));
        assert_eq!(
            fs::read_to_string(outside.join("status.toml")).expect("outside status reads"),
            "version = \"1\"\nstate = \"running\"\npid = 123\nnode_id = \"node_outside\"\nstarted_at_unix = 1\nheartbeat_at_unix = 1\nlocal_endpoint = \"file-ipc:runtime/ipc/inbox\"\n"
        );
        assert!(
            fs::symlink_metadata(&paths.runtime_dir)
                .expect("runtime dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn stop_request_rejects_runtime_directory_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("runtime-dir-stop-symlink");
        let paths = StatePaths::from_home(home.clone());
        let outside = test_home("runtime-dir-stop-target");
        fs::create_dir_all(&home).expect("home creates");
        fs::create_dir_all(&outside).expect("outside runtime creates");
        fs::write(
            outside.join("status.toml"),
            "version = \"1\"\nstate = \"running\"\npid = 123\nnode_id = \"node_outside\"\nstarted_at_unix = 1\nheartbeat_at_unix = 1\nlocal_endpoint = \"file-ipc:runtime/ipc/inbox\"\n",
        )
        .expect("outside status writes");
        symlink(&outside, &paths.runtime_dir).expect("runtime dir symlink creates");

        let error =
            request_runtime_stop(Some(home)).expect_err("runtime dir symlink should fail closed");

        assert!(error.to_string().contains("inspect runtime directory"));
        assert!(!outside.join("stop.request").exists());
        assert_eq!(
            fs::read_to_string(outside.join("status.toml")).expect("outside status reads"),
            "version = \"1\"\nstate = \"running\"\npid = 123\nnode_id = \"node_outside\"\nstarted_at_unix = 1\nheartbeat_at_unix = 1\nlocal_endpoint = \"file-ipc:runtime/ipc/inbox\"\n"
        );
    }

    #[test]
    fn runtime_status_read_rejects_oversized_file_without_printing_contents() {
        let home = test_home("status-read-oversized");
        let paths = StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.runtime_dir).expect("runtime dir creates");
        let private_marker = "private-runtime-marker";
        let mut contents = format!("# {private_marker}\n");
        contents.push_str(&"a".repeat((MAX_RUNTIME_CONTROL_FILE_BYTES + 1) as usize));
        fs::write(&paths.runtime_status, contents).expect("oversized status writes");

        let error = read_runtime(Some(home)).expect_err("oversized status should fail closed");
        let error = error.to_string();

        assert!(error.contains("runtime control file exceeds"));
        assert!(!error.contains(private_marker));
    }

    #[test]
    fn runtime_log_is_payload_safe() {
        let home = test_home("payload-safe-log");
        let lease = acquire_runtime(Some(home.clone())).expect("runtime starts");
        lease.heartbeat().expect("heartbeat writes");
        let log = fs::read_to_string(StatePaths::from_home(home).logs_dir.join("conud.log"))
            .expect("runtime log exists");

        assert!(log.contains("payload=not_observed"));
        assert!(!log.contains("private message contents"));
        assert!(!log.contains("Review this code"));
    }

    #[test]
    fn process_once_keeps_relay_idle_without_relay_config() {
        let home = test_home("process-once-relay-idle");
        let lease = acquire_runtime(Some(home)).expect("runtime starts");

        let report = lease
            .process_once(Duration::from_millis(1))
            .expect("runtime tick succeeds");

        assert!(!report.relay_attempted);
        assert!(!report.relay_error);
    }

    #[test]
    fn stopped_runtime_removes_lock() {
        let home = test_home("stopped");
        let lease = acquire_runtime(Some(home.clone())).expect("runtime starts");
        let paths = StatePaths::from_home(home.clone());
        let status = lease.stop().expect("runtime stops");
        let read_back = read_runtime(Some(home)).expect("runtime reads");

        assert_eq!(status.state, RuntimeState::Stopped);
        assert_eq!(read_back.state, RuntimeState::Stopped);
        assert!(!paths.runtime_lock.exists());
    }

    #[test]
    fn stale_runtime_is_replaced_on_start() {
        let home = test_home("stale");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        fs::write(&paths.runtime_lock, "pid = 123\n").expect("stale lock writes");
        let stale_status = RuntimeStatus {
            state: RuntimeState::Running,
            pid: Some(123),
            node_id: Some(init.node.node_id),
            started_at_unix: Some(1),
            heartbeat_at_unix: Some(1),
            local_endpoint: LOCAL_ENDPOINT.to_string(),
            status_path: paths.runtime_status.clone(),
            lock_path: paths.runtime_lock.clone(),
        };
        write_status(&paths, &stale_status).expect("stale status writes");

        let lease = acquire_runtime(Some(home.clone())).expect("runtime replaces stale state");
        let status = read_runtime(Some(home)).expect("runtime reads");

        assert_eq!(status.state, RuntimeState::Running);
        assert_eq!(status.pid, Some(process::id()));
        assert_eq!(status.node_id, Some(lease.node.node_id.clone()));
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-runtime-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
