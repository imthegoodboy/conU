//! Route selection and direct-transport probing metadata.
//!
//! Phase 13 introduces a conUD-owned route manager. It records direct QUIC
//! candidates, relay fallback candidates, route scores, and probe metadata
//! without moving or observing payload bytes.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::direct_transport;
use crate::relay_endpoint::{self, RelayEndpointError};
use crate::state::{self, StateError, StatePaths};
use crate::trust::{self, TrustStatus, TrustedPeer};

const ROUTE_VERSION: &str = "1";
const DEFAULT_RELAY_ENDPOINT: &str = "ws://127.0.0.1:8787";
const RELAY_WEBSOCKET_LATENCY_MS: u64 = 80;
const DIRECT_QUIC_INVALID_ENDPOINT: &str = "quic://invalid";
const DIRECT_QUIC_UNCONFIGURED_ENDPOINT: &str = "quic://unconfigured";
const DIRECT_QUIC_PROBE_FAILED: &str = "direct_quic_probe_failed";
const NAT_TRAVERSAL_UNAVAILABLE: &str = "nat_traversal_unavailable";
const CANDIDATE_SOURCE_NONE: &str = "none";
const CANDIDATE_SOURCE_PEER_CONFIG: &str = "peer_config";
const CANDIDATE_SOURCE_PEER_CARD: &str = "peer_card";
const CANDIDATE_SOURCE_LOCAL_CONFIG: &str = "local_config";
const CANDIDATE_KIND_NONE: &str = "none";
const CANDIDATE_KIND_HOST: &str = "host";
const RENDEZVOUS_STATE_NOT_CONFIGURED: &str = "not_configured";
const RENDEZVOUS_STATE_CANDIDATE_EXCHANGED: &str = "candidate_exchanged";
const RENDEZVOUS_STATE_UNAVAILABLE: &str = "unavailable";
const RENDEZVOUS_STATE_DISABLED: &str = "disabled";

/// Transport class for a candidate route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTransport {
    DirectQuic,
    RelayWebSocket,
}

impl RouteTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectQuic => "direct-quic",
            Self::RelayWebSocket => "relay-websocket",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "direct-quic" => Self::DirectQuic,
            _ => Self::RelayWebSocket,
        }
    }
}

/// Current route candidate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    Selected,
    Candidate,
    Fallback,
    Unavailable,
}

impl RouteState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Candidate => "candidate",
            Self::Fallback => "fallback",
            Self::Unavailable => "unavailable",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "selected" => Self::Selected,
            "candidate" => Self::Candidate,
            "fallback" => Self::Fallback,
            _ => Self::Unavailable,
        }
    }
}

/// NAT posture inferred from local configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProfile {
    Unknown,
    Public,
    Cone,
    Symmetric,
    RelayOnly,
}

impl NatProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Public => "public",
            Self::Cone => "cone",
            Self::Symmetric => "symmetric",
            Self::RelayOnly => "relay-only",
        }
    }

    fn from_config(value: Option<&String>) -> Self {
        match value.map(String::as_str) {
            Some("public") => Self::Public,
            Some("cone") => Self::Cone,
            Some("symmetric") => Self::Symmetric,
            Some("relay-only") => Self::RelayOnly,
            _ => Self::Unknown,
        }
    }
}

/// Persisted route candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub route_id: String,
    pub peer_node_id: String,
    pub display_name: String,
    pub transport: RouteTransport,
    pub endpoint: String,
    pub state: RouteState,
    pub score: u16,
    pub latency_ms: Option<u64>,
    pub direct_attempted: bool,
    pub relay_fallback: bool,
    pub nat_profile: NatProfile,
    pub candidate_source: String,
    pub candidate_kind: String,
    pub rendezvous_state: String,
    pub failure_reason: Option<String>,
    pub updated_at_unix: u64,
}

impl RouteRecord {
    pub fn is_selected(&self) -> bool {
        self.state == RouteState::Selected
    }

    pub fn is_direct(&self) -> bool {
        self.transport == RouteTransport::DirectQuic
    }
}

/// One metadata-only route probe event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProbe {
    pub probe_id: String,
    pub route_id: String,
    pub peer_node_id: String,
    pub transport: RouteTransport,
    pub endpoint: String,
    pub outcome: String,
    pub score: u16,
    pub latency_ms: Option<u64>,
    pub candidate_source: String,
    pub candidate_kind: String,
    pub rendezvous_state: String,
    pub created_at_unix: u64,
}

/// Summary of a route sync/probe pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSyncReport {
    pub peers: usize,
    pub candidates: usize,
    pub direct_attempts: usize,
    pub direct_available: usize,
    pub selected_direct: usize,
    pub selected_relay: usize,
    pub relay_fallbacks: usize,
    pub nat_traversal_unavailable: usize,
    pub probes_recorded: usize,
}

/// Errors produced by route management.
#[derive(Debug)]
pub enum RouteError {
    State(StateError),
    Trust(trust::TrustError),
    Direct(direct_transport::DirectTransportError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRecord {
        reason: String,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Direct(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidRecord { reason } => write!(formatter, "invalid route record: {reason}"),
        }
    }
}

impl std::error::Error for RouteError {}

impl From<StateError> for RouteError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<trust::TrustError> for RouteError {
    fn from(error: trust::TrustError) -> Self {
        Self::Trust(error)
    }
}

impl From<direct_transport::DirectTransportError> for RouteError {
    fn from(error: direct_transport::DirectTransportError) -> Self {
        Self::Direct(error)
    }
}

/// Probe trusted-peer routes and write the selected route registry.
pub fn sync_routes(home_override: Option<PathBuf>) -> Result<RouteSyncReport, RouteError> {
    let init = state::init_state(home_override)?;
    sync_routes_from_paths(&init.paths)
}

/// Probe trusted-peer routes using already resolved state paths.
pub fn sync_routes_from_paths(paths: &StatePaths) -> Result<RouteSyncReport, RouteError> {
    ensure_route_files(paths)?;

    let peers = trust::list_peers(Some(paths.home.clone()))?;
    let local_node_id = state::read_state(Some(paths.home.clone()))?
        .node
        .map(|node| node.node_id)
        .unwrap_or_default();
    let config = read_config(paths)?;
    let relay_endpoint = relay_endpoint(&config)?;
    let nat_profile = NatProfile::from_config(config.get("nat_profile"));
    let now = current_unix_seconds();
    let mut routes = Vec::new();
    let mut probes = Vec::new();

    for peer in peers
        .iter()
        .filter(|peer| peer.status == TrustStatus::Trusted)
    {
        let direct =
            direct_route_candidate(paths, &local_node_id, peer, &config, nat_profile, now)?;
        let relay = relay_route_candidate(peer, &relay_endpoint, nat_profile, now)?;
        let direct_available = direct.state != RouteState::Unavailable;
        let direct_selected = direct_available && direct.score >= relay.score;

        let selected_direct = RouteRecord {
            state: if direct_selected {
                RouteState::Selected
            } else {
                direct.state
            },
            ..direct
        };
        let selected_relay = RouteRecord {
            state: if direct_selected {
                RouteState::Fallback
            } else {
                RouteState::Selected
            },
            relay_fallback: true,
            ..relay
        };

        probes.push(probe_from_route(&selected_direct, now));
        probes.push(probe_from_route(&selected_relay, now));
        routes.push(selected_direct);
        routes.push(selected_relay);
    }

    write_routes(paths, &routes)?;
    append_probes(paths, &probes)?;
    record_route_log(paths, &routes);

    Ok(report_from_routes(&routes, probes.len()))
}

/// Read route candidate records.
pub fn list_routes(home_override: Option<PathBuf>) -> Result<Vec<RouteRecord>, RouteError> {
    let paths = StatePaths::resolve(home_override)?;
    read_routes(&paths)
}

/// Read metadata-only route probe history.
pub fn list_route_probes(home_override: Option<PathBuf>) -> Result<Vec<RouteProbe>, RouteError> {
    let paths = StatePaths::resolve(home_override)?;
    read_probes(&paths)
}

/// Return the selected route for a peer, if one exists.
pub fn selected_route_for_peer(
    home_override: Option<PathBuf>,
    peer_node_id: &str,
) -> Result<Option<RouteRecord>, RouteError> {
    let paths = StatePaths::resolve(home_override)?;
    selected_route_for_peer_from_paths(&paths, peer_node_id)
}

/// Return the selected route for a peer from resolved paths.
pub fn selected_route_for_peer_from_paths(
    paths: &StatePaths,
    peer_node_id: &str,
) -> Result<Option<RouteRecord>, RouteError> {
    let peer_node_id = validate_identifier(peer_node_id.to_string(), "peer node id")?;
    Ok(read_routes(paths)?
        .into_iter()
        .find(|route| route.peer_node_id == peer_node_id && route.is_selected()))
}

fn direct_route_candidate(
    paths: &StatePaths,
    local_node_id: &str,
    peer: &TrustedPeer,
    config: &HashMap<String, String>,
    nat_profile: NatProfile,
    now: u64,
) -> Result<RouteRecord, RouteError> {
    let candidate = direct_candidate(config, peer, nat_profile);
    let display_endpoint = candidate.display_endpoint();
    let route_id = route_id(
        &peer.peer_node_id,
        RouteTransport::DirectQuic,
        Some(display_endpoint.as_str()),
    );
    let mut state = RouteState::Unavailable;
    let mut score = 0;
    let mut latency_ms = None;
    let mut failure_reason = Some(candidate.initial_failure_reason());
    let mut direct_attempted = false;

    if nat_profile == NatProfile::RelayOnly {
        failure_reason = Some("nat_profile_relay_only".to_string());
    } else if let Some(endpoint) = candidate.endpoint.as_deref() {
        direct_attempted = true;
        if valid_direct_endpoint(endpoint) {
            match direct_transport::probe_direct_quic_from_paths(
                paths,
                local_node_id,
                peer,
                endpoint,
                std::time::Duration::from_millis(direct_transport::DEFAULT_DIRECT_TIMEOUT_MS),
            ) {
                Ok(report) if report.authenticated => {
                    state = RouteState::Candidate;
                    score = direct_score(nat_profile);
                    latency_ms = Some(report.latency_ms.max(1));
                    failure_reason = None;
                }
                Ok(_) | Err(_) => {
                    score = direct_score(nat_profile);
                    failure_reason = Some(DIRECT_QUIC_PROBE_FAILED.to_string());
                }
            }
        } else {
            direct_attempted = false;
            failure_reason = Some("invalid_direct_quic_endpoint".to_string());
        }
    }

    Ok(RouteRecord {
        route_id,
        peer_node_id: peer.peer_node_id.clone(),
        display_name: peer.display_name.clone(),
        transport: RouteTransport::DirectQuic,
        endpoint: display_endpoint,
        state,
        score,
        latency_ms,
        direct_attempted,
        relay_fallback: false,
        nat_profile,
        candidate_source: candidate.source.to_string(),
        candidate_kind: candidate.kind.to_string(),
        rendezvous_state: candidate.rendezvous_state.to_string(),
        failure_reason,
        updated_at_unix: now,
    })
}

fn relay_route_candidate(
    peer: &TrustedPeer,
    endpoint: &str,
    nat_profile: NatProfile,
    now: u64,
) -> Result<RouteRecord, RouteError> {
    Ok(RouteRecord {
        route_id: route_id(
            &peer.peer_node_id,
            RouteTransport::RelayWebSocket,
            Some(endpoint),
        ),
        peer_node_id: peer.peer_node_id.clone(),
        display_name: peer.display_name.clone(),
        transport: RouteTransport::RelayWebSocket,
        endpoint: validate_endpoint(endpoint.to_string())?,
        state: RouteState::Candidate,
        score: 70,
        latency_ms: Some(RELAY_WEBSOCKET_LATENCY_MS),
        direct_attempted: false,
        relay_fallback: false,
        nat_profile,
        candidate_source: CANDIDATE_SOURCE_NONE.to_string(),
        candidate_kind: CANDIDATE_KIND_NONE.to_string(),
        rendezvous_state: RENDEZVOUS_STATE_NOT_CONFIGURED.to_string(),
        failure_reason: None,
        updated_at_unix: now,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectCandidate {
    endpoint: Option<String>,
    source: &'static str,
    kind: &'static str,
    rendezvous_state: &'static str,
}

impl DirectCandidate {
    fn initial_failure_reason(&self) -> String {
        match self.rendezvous_state {
            RENDEZVOUS_STATE_UNAVAILABLE => NAT_TRAVERSAL_UNAVAILABLE.to_string(),
            RENDEZVOUS_STATE_DISABLED => "nat_profile_relay_only".to_string(),
            _ => "no_direct_quic_candidate".to_string(),
        }
    }

    fn display_endpoint(&self) -> String {
        match self.endpoint.as_deref() {
            Some(endpoint) if valid_direct_endpoint(endpoint) => endpoint.to_string(),
            Some(_) => DIRECT_QUIC_INVALID_ENDPOINT.to_string(),
            None => DIRECT_QUIC_UNCONFIGURED_ENDPOINT.to_string(),
        }
    }
}

fn direct_candidate(
    config: &HashMap<String, String>,
    peer: &TrustedPeer,
    nat_profile: NatProfile,
) -> DirectCandidate {
    let keyed = format!("direct_quic_{}", config_key_suffix(&peer.peer_node_id));
    if let Some(endpoint) = config
        .get(&keyed)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return DirectCandidate {
            endpoint: Some(endpoint),
            source: CANDIDATE_SOURCE_PEER_CONFIG,
            kind: CANDIDATE_KIND_HOST,
            rendezvous_state: RENDEZVOUS_STATE_CANDIDATE_EXCHANGED,
        };
    }
    if let Some(endpoint) = peer
        .direct_quic_endpoint
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return DirectCandidate {
            endpoint: Some(endpoint),
            source: CANDIDATE_SOURCE_PEER_CARD,
            kind: CANDIDATE_KIND_HOST,
            rendezvous_state: RENDEZVOUS_STATE_CANDIDATE_EXCHANGED,
        };
    }
    if let Some(endpoint) = config
        .get("direct_quic_endpoint")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return DirectCandidate {
            endpoint: Some(endpoint),
            source: CANDIDATE_SOURCE_LOCAL_CONFIG,
            kind: CANDIDATE_KIND_HOST,
            rendezvous_state: RENDEZVOUS_STATE_CANDIDATE_EXCHANGED,
        };
    }

    DirectCandidate {
        endpoint: None,
        source: CANDIDATE_SOURCE_NONE,
        kind: CANDIDATE_KIND_NONE,
        rendezvous_state: rendezvous_state_without_candidate(nat_profile),
    }
}

fn rendezvous_state_without_candidate(nat_profile: NatProfile) -> &'static str {
    match nat_profile {
        NatProfile::RelayOnly => RENDEZVOUS_STATE_DISABLED,
        NatProfile::Public => RENDEZVOUS_STATE_NOT_CONFIGURED,
        NatProfile::Unknown | NatProfile::Cone | NatProfile::Symmetric => {
            RENDEZVOUS_STATE_UNAVAILABLE
        }
    }
}

fn direct_score(nat_profile: NatProfile) -> u16 {
    match nat_profile {
        NatProfile::Public => 98,
        NatProfile::Cone => 92,
        NatProfile::Unknown => 88,
        NatProfile::Symmetric => 72,
        NatProfile::RelayOnly => 0,
    }
}

fn probe_from_route(route: &RouteRecord, now: u64) -> RouteProbe {
    let outcome = match route.state {
        RouteState::Selected | RouteState::Candidate => "available",
        RouteState::Fallback => "fallback",
        RouteState::Unavailable => route.failure_reason.as_deref().unwrap_or("unavailable"),
    };

    RouteProbe {
        probe_id: probe_id(&route.route_id, now),
        route_id: route.route_id.clone(),
        peer_node_id: route.peer_node_id.clone(),
        transport: route.transport,
        endpoint: route.endpoint.clone(),
        outcome: outcome.to_string(),
        score: route.score,
        latency_ms: route.latency_ms,
        candidate_source: route.candidate_source.clone(),
        candidate_kind: route.candidate_kind.clone(),
        rendezvous_state: route.rendezvous_state.clone(),
        created_at_unix: now,
    }
}

fn report_from_routes(routes: &[RouteRecord], probes_recorded: usize) -> RouteSyncReport {
    let peers = routes
        .iter()
        .map(|route| route.peer_node_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    RouteSyncReport {
        peers,
        candidates: routes.len(),
        direct_attempts: routes
            .iter()
            .filter(|route| route.transport == RouteTransport::DirectQuic && route.direct_attempted)
            .count(),
        direct_available: routes
            .iter()
            .filter(|route| {
                route.transport == RouteTransport::DirectQuic
                    && route.state != RouteState::Unavailable
            })
            .count(),
        selected_direct: routes
            .iter()
            .filter(|route| route.is_selected() && route.is_direct())
            .count(),
        selected_relay: routes
            .iter()
            .filter(|route| {
                route.is_selected() && route.transport == RouteTransport::RelayWebSocket
            })
            .count(),
        relay_fallbacks: routes.iter().filter(|route| route.relay_fallback).count(),
        nat_traversal_unavailable: routes
            .iter()
            .filter(|route| {
                route.transport == RouteTransport::DirectQuic
                    && route.failure_reason.as_deref() == Some(NAT_TRAVERSAL_UNAVAILABLE)
            })
            .count(),
        probes_recorded,
    }
}

fn ensure_route_files(paths: &StatePaths) -> Result<(), RouteError> {
    ensure_routes_directory(paths)?;
    state::ensure_state_directory(&paths.logs_dir)?;
    Ok(())
}

fn read_config(paths: &StatePaths) -> Result<HashMap<String, String>, RouteError> {
    let contents = match state::read_optional_regular_state_file(
        &paths.config,
        "inspect route config",
        "read route config",
    )? {
        Some(contents) => contents,
        None => return Ok(HashMap::new()),
    };
    Ok(parse_key_values(&contents))
}

fn relay_endpoint(config: &HashMap<String, String>) -> Result<String, RouteError> {
    validate_endpoint(
        config
            .get("default_relay")
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_RELAY_ENDPOINT.to_string()),
    )
}

fn read_routes(paths: &StatePaths) -> Result<Vec<RouteRecord>, RouteError> {
    if !state::state_directory_exists(&paths.home, "inspect state directory")? {
        return Ok(Vec::new());
    }
    if !state::state_directory_exists(&paths.routes_dir, "inspect routes directory")? {
        return Ok(Vec::new());
    }
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.route_registry,
        "inspect route registry",
        "read route registry",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_routes(&contents)
}

fn write_routes(paths: &StatePaths, routes: &[RouteRecord]) -> Result<(), RouteError> {
    ensure_routes_directory(paths)?;
    let mut sorted = routes.to_vec();
    sorted.sort_by(|left, right| {
        left.peer_node_id
            .cmp(&right.peer_node_id)
            .then(left.transport.as_str().cmp(right.transport.as_str()))
    });
    let mut contents = format!("# conU route registry\nversion = \"{}\"\n", ROUTE_VERSION);

    for route in sorted {
        contents.push_str("\n[[route]]\n");
        contents.push_str(&format!(
            "route_id = \"{}\"\n",
            escape_file_value(&route.route_id)
        ));
        contents.push_str(&format!(
            "peer_node_id = \"{}\"\n",
            escape_file_value(&route.peer_node_id)
        ));
        contents.push_str(&format!(
            "display_name = \"{}\"\n",
            escape_file_value(&route.display_name)
        ));
        contents.push_str(&format!("transport = \"{}\"\n", route.transport.as_str()));
        contents.push_str(&format!(
            "endpoint = \"{}\"\n",
            escape_file_value(&route.endpoint)
        ));
        contents.push_str(&format!("state = \"{}\"\n", route.state.as_str()));
        contents.push_str(&format!("score = {}\n", route.score));
        contents.push_str(&format!("latency_ms = {}\n", route.latency_ms.unwrap_or(0)));
        contents.push_str(&format!("direct_attempted = {}\n", route.direct_attempted));
        contents.push_str(&format!("relay_fallback = {}\n", route.relay_fallback));
        contents.push_str(&format!(
            "nat_profile = \"{}\"\n",
            route.nat_profile.as_str()
        ));
        contents.push_str(&format!(
            "candidate_source = \"{}\"\n",
            escape_file_value(&route.candidate_source)
        ));
        contents.push_str(&format!(
            "candidate_kind = \"{}\"\n",
            escape_file_value(&route.candidate_kind)
        ));
        contents.push_str(&format!(
            "rendezvous_state = \"{}\"\n",
            escape_file_value(&route.rendezvous_state)
        ));
        contents.push_str(&format!(
            "failure_reason = \"{}\"\n",
            escape_file_value(route.failure_reason.as_deref().unwrap_or(""))
        ));
        contents.push_str(&format!("updated_at_unix = {}\n", route.updated_at_unix));
        contents.push_str("payload_displayed = false\n");
    }

    state::write_regular_state_file(
        &paths.route_registry,
        &contents,
        "inspect route registry",
        "create route registry",
        "open route registry",
        "write route registry",
    )?;
    Ok(())
}

fn append_probes(paths: &StatePaths, probes: &[RouteProbe]) -> Result<(), RouteError> {
    if probes.is_empty() {
        return Ok(());
    }

    ensure_routes_directory(paths)?;
    let mut contents = state::read_optional_regular_state_file(
        &paths.route_probes,
        "inspect route probes",
        "read route probes",
    )?
    .unwrap_or_else(|| format!("# conU route probes\nversion = \"{}\"\n", ROUTE_VERSION));

    for probe in probes {
        contents.push_str(&format!(
            "\n[[probe]]\nprobe_id = \"{}\"\nroute_id = \"{}\"\npeer_node_id = \"{}\"\ntransport = \"{}\"\nendpoint = \"{}\"\noutcome = \"{}\"\nscore = {}\nlatency_ms = {}\ncandidate_source = \"{}\"\ncandidate_kind = \"{}\"\nrendezvous_state = \"{}\"\ncreated_at_unix = {}\npayload_displayed = false\n",
            escape_file_value(&probe.probe_id),
            escape_file_value(&probe.route_id),
            escape_file_value(&probe.peer_node_id),
            probe.transport.as_str(),
            escape_file_value(&probe.endpoint),
            escape_file_value(&probe.outcome),
            probe.score,
            probe.latency_ms.unwrap_or(0),
            escape_file_value(&probe.candidate_source),
            escape_file_value(&probe.candidate_kind),
            escape_file_value(&probe.rendezvous_state),
            probe.created_at_unix
        ));
    }

    state::write_regular_state_file(
        &paths.route_probes,
        &contents,
        "inspect route probes",
        "create route probes",
        "open route probes",
        "write route probes",
    )?;
    Ok(())
}

fn read_probes(paths: &StatePaths) -> Result<Vec<RouteProbe>, RouteError> {
    if !state::state_directory_exists(&paths.home, "inspect state directory")? {
        return Ok(Vec::new());
    }
    if !state::state_directory_exists(&paths.routes_dir, "inspect routes directory")? {
        return Ok(Vec::new());
    }
    let Some(contents) = state::read_optional_regular_state_file(
        &paths.route_probes,
        "inspect route probes",
        "read route probes",
    )?
    else {
        return Ok(Vec::new());
    };
    parse_probes(&contents)
}

fn ensure_routes_directory(paths: &StatePaths) -> Result<(), RouteError> {
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.routes_dir)?;
    Ok(())
}

fn append_route_log(paths: &StatePaths, routes: &[RouteRecord]) -> Result<(), RouteError> {
    state::ensure_state_directory(&paths.logs_dir)?;
    let log_path = paths.logs_dir.join("routes.log");
    let report = report_from_routes(routes, 0);

    let line = format!(
        "event=route_sync peers={} candidates={} selected_direct={} selected_relay={} relay_fallbacks={} nat_traversal_unavailable={} payload=not_observed",
        report.peers,
        report.candidates,
        report.selected_direct,
        report.selected_relay,
        report.relay_fallbacks,
        report.nat_traversal_unavailable
    );

    state::append_regular_state_file(
        &log_path,
        &(line + "\n"),
        "inspect route log",
        "create route log",
        "open route log",
        "write route log",
    )?;
    Ok(())
}

fn record_route_log(paths: &StatePaths, routes: &[RouteRecord]) {
    let _ = append_route_log(paths, routes);
}

fn parse_routes(contents: &str) -> Result<Vec<RouteRecord>, RouteError> {
    let mut routes = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[route]]" {
            if !current.is_empty() {
                routes.push(route_from_values(&current)?);
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
        routes.push(route_from_values(&current)?);
    }

    Ok(routes)
}

fn parse_probes(contents: &str) -> Result<Vec<RouteProbe>, RouteError> {
    let mut probes = Vec::new();
    let mut current = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "version = \"1\"" {
            continue;
        }
        if line == "[[probe]]" {
            if !current.is_empty() {
                probes.push(probe_from_values(&current)?);
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
        probes.push(probe_from_values(&current)?);
    }

    Ok(probes)
}

fn route_from_values(values: &HashMap<String, String>) -> Result<RouteRecord, RouteError> {
    let latency_ms = parse_u64(&required(values, "latency_ms")?)?;
    let failure_reason = optional_clean(values.get("failure_reason"));
    let transport = RouteTransport::from_str(&required(values, "transport")?);
    let endpoint = validate_route_endpoint(required(values, "endpoint")?, transport)?;
    Ok(RouteRecord {
        route_id: validate_identifier(required(values, "route_id")?, "route id")?,
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        display_name: validate_display_name(required(values, "display_name")?)?,
        transport,
        endpoint,
        state: RouteState::from_str(&required(values, "state")?),
        score: parse_u16(&required(values, "score")?)?,
        latency_ms: if latency_ms == 0 {
            None
        } else {
            Some(latency_ms)
        },
        direct_attempted: parse_bool(values.get("direct_attempted")).unwrap_or(false),
        relay_fallback: parse_bool(values.get("relay_fallback")).unwrap_or(false),
        nat_profile: NatProfile::from_config(values.get("nat_profile")),
        candidate_source: optional_identifier(
            values.get("candidate_source"),
            CANDIDATE_SOURCE_NONE,
        )?,
        candidate_kind: optional_identifier(values.get("candidate_kind"), CANDIDATE_KIND_NONE)?,
        rendezvous_state: optional_identifier(
            values.get("rendezvous_state"),
            RENDEZVOUS_STATE_NOT_CONFIGURED,
        )?,
        failure_reason,
        updated_at_unix: parse_u64(&required(values, "updated_at_unix")?)?,
    })
}

fn probe_from_values(values: &HashMap<String, String>) -> Result<RouteProbe, RouteError> {
    let latency_ms = parse_u64(&required(values, "latency_ms")?)?;
    let transport = RouteTransport::from_str(&required(values, "transport")?);
    let endpoint = validate_route_endpoint(required(values, "endpoint")?, transport)?;
    Ok(RouteProbe {
        probe_id: validate_identifier(required(values, "probe_id")?, "probe id")?,
        route_id: validate_identifier(required(values, "route_id")?, "route id")?,
        peer_node_id: validate_identifier(required(values, "peer_node_id")?, "peer node id")?,
        transport,
        endpoint,
        outcome: validate_identifier(required(values, "outcome")?, "outcome")?,
        score: parse_u16(&required(values, "score")?)?,
        latency_ms: if latency_ms == 0 {
            None
        } else {
            Some(latency_ms)
        },
        candidate_source: optional_identifier(
            values.get("candidate_source"),
            CANDIDATE_SOURCE_NONE,
        )?,
        candidate_kind: optional_identifier(values.get("candidate_kind"), CANDIDATE_KIND_NONE)?,
        rendezvous_state: optional_identifier(
            values.get("rendezvous_state"),
            RENDEZVOUS_STATE_NOT_CONFIGURED,
        )?,
        created_at_unix: parse_u64(&required(values, "created_at_unix")?)?,
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

fn required(values: &HashMap<String, String>, key: &'static str) -> Result<String, RouteError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| RouteError::InvalidRecord {
            reason: format!("missing {key}"),
        })
}

fn optional_clean(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn optional_identifier(
    value: Option<&String>,
    default: &'static str,
) -> Result<String, RouteError> {
    match optional_clean(value) {
        Some(value) => validate_identifier(value, "route metadata"),
        None => Ok(default.to_string()),
    }
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, RouteError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RouteError::InvalidRecord {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 180 {
        return Err(RouteError::InvalidRecord {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RouteError::InvalidRecord {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(value)
}

fn validate_display_name(value: String) -> Result<String, RouteError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RouteError::InvalidRecord {
            reason: "display name cannot be empty".to_string(),
        });
    }
    if value.len() > 120 || value.contains('\n') || value.contains('\r') {
        return Err(RouteError::InvalidRecord {
            reason: "display name is invalid".to_string(),
        });
    }
    Ok(value)
}

fn validate_endpoint(value: String) -> Result<String, RouteError> {
    relay_endpoint::validate_relay_endpoint(value).map_err(|error| {
        let reason = match error {
            RelayEndpointError::Empty => "endpoint cannot be empty",
            RelayEndpointError::Scheme => "relay endpoint must start with ws:// or wss://",
            RelayEndpointError::Invalid => "relay endpoint is invalid",
        };
        RouteError::InvalidRecord {
            reason: reason.to_string(),
        }
    })
}

fn validate_route_endpoint(value: String, transport: RouteTransport) -> Result<String, RouteError> {
    let value = value.trim().to_string();
    match transport {
        RouteTransport::DirectQuic => {
            if !is_direct_route_placeholder(&value) {
                direct_transport::validate_direct_peer_endpoint(&value).map_err(|_| {
                    RouteError::InvalidRecord {
                        reason: "endpoint is invalid".to_string(),
                    }
                })?;
            }
            Ok(value)
        }
        RouteTransport::RelayWebSocket => validate_endpoint(value),
    }
}

fn is_direct_route_placeholder(value: &str) -> bool {
    matches!(
        value,
        DIRECT_QUIC_INVALID_ENDPOINT | DIRECT_QUIC_UNCONFIGURED_ENDPOINT
    )
}

fn valid_direct_endpoint(value: &str) -> bool {
    direct_transport::validate_direct_peer_endpoint(value).is_ok()
}

fn parse_bool(value: Option<&String>) -> Option<bool> {
    match value?.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_u16(value: &str) -> Result<u16, RouteError> {
    value.parse::<u16>().map_err(|_| RouteError::InvalidRecord {
        reason: "expected unsigned score".to_string(),
    })
}

fn parse_u64(value: &str) -> Result<u64, RouteError> {
    value.parse::<u64>().map_err(|_| RouteError::InvalidRecord {
        reason: "expected unsigned integer".to_string(),
    })
}

fn route_id(peer_node_id: &str, transport: RouteTransport, endpoint: Option<&str>) -> String {
    let mut hasher = DefaultHasher::new();
    peer_node_id.hash(&mut hasher);
    transport.as_str().hash(&mut hasher);
    endpoint.unwrap_or("").hash(&mut hasher);
    format!("route_{:016x}", hasher.finish())
}

fn probe_id(route_id: &str, now: u64) -> String {
    let mut hasher = DefaultHasher::new();
    route_id.hash(&mut hasher);
    now.hash(&mut hasher);
    current_unix_nanos().hash(&mut hasher);
    format!("probe_{:016x}", hasher.finish())
}

fn config_key_suffix(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
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
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process;

    #[test]
    fn sync_prefers_relay_when_no_direct_candidate_exists() {
        let home = test_home("relay-fallback");
        let peer = trusted_peer(&home);

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let routes = list_routes(Some(home)).expect("routes read");
        let selected = routes
            .iter()
            .find(|route| route.peer_node_id == peer.peer_node_id && route.is_selected())
            .expect("selected route");

        assert_eq!(report.relay_fallbacks, 1);
        assert_eq!(selected.transport, RouteTransport::RelayWebSocket);
        assert!(selected.relay_fallback);
    }

    #[test]
    fn sync_keeps_relay_selected_when_direct_quic_transport_is_inactive() {
        let home = test_home("direct-quic");
        let peer = trusted_peer(&home);
        let config_key = format!("direct_quic_{}", config_key_suffix(&peer.peer_node_id));
        fs::write(
            StatePaths::from_home(home.clone()).config,
            format!(
                "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"public\"\n{config_key} = \"quic://127.0.0.1:9443\"\n"
            ),
        )
        .expect("config writes");

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let routes = list_routes(Some(home.clone())).expect("routes read");
        let selected =
            selected_route_for_peer(Some(home.clone()), &peer.peer_node_id).expect("route lookup");
        let direct = routes
            .iter()
            .find(|route| route.peer_node_id == peer.peer_node_id && route.is_direct())
            .expect("direct route recorded");
        let probes = list_route_probes(Some(home)).expect("probes read");

        assert_eq!(report.direct_available, 0);
        assert_eq!(report.selected_direct, 0);
        assert_eq!(report.selected_relay, 1);
        assert_eq!(report.nat_traversal_unavailable, 0);
        assert_eq!(
            selected.expect("selected").transport,
            RouteTransport::RelayWebSocket
        );
        assert_eq!(direct.state, RouteState::Unavailable);
        assert_eq!(direct.score, direct_score(NatProfile::Public));
        assert_eq!(
            direct.failure_reason.as_deref(),
            Some(DIRECT_QUIC_PROBE_FAILED)
        );
        assert_eq!(direct.candidate_source, CANDIDATE_SOURCE_PEER_CONFIG);
        assert_eq!(direct.candidate_kind, CANDIDATE_KIND_HOST);
        assert_eq!(
            direct.rendezvous_state,
            RENDEZVOUS_STATE_CANDIDATE_EXCHANGED
        );
        let direct_probe = probes
            .iter()
            .find(|probe| {
                probe.peer_node_id == peer.peer_node_id
                    && probe.transport == RouteTransport::DirectQuic
            })
            .expect("direct probe recorded");
        assert_eq!(direct_probe.candidate_source, CANDIDATE_SOURCE_PEER_CONFIG);
        assert_eq!(direct_probe.candidate_kind, CANDIDATE_KIND_HOST);
        assert_eq!(
            direct_probe.rendezvous_state,
            RENDEZVOUS_STATE_CANDIDATE_EXCHANGED
        );
        assert!(
            probes
                .iter()
                .any(|probe| probe.outcome == DIRECT_QUIC_PROBE_FAILED)
        );
    }

    #[test]
    fn sync_marks_nat_traversal_unavailable_without_candidate() {
        let home = test_home("nat-unavailable");
        let peer = trusted_peer(&home);
        fs::write(
            StatePaths::from_home(home.clone()).config,
            "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"symmetric\"\n",
        )
        .expect("config writes");

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let routes = list_routes(Some(home.clone())).expect("routes read");
        let direct = routes
            .iter()
            .find(|route| route.peer_node_id == peer.peer_node_id && route.is_direct())
            .expect("direct route recorded");
        let selected =
            selected_route_for_peer(Some(home.clone()), &peer.peer_node_id).expect("route lookup");
        let probes = list_route_probes(Some(home)).expect("probes read");

        assert_eq!(report.direct_attempts, 0);
        assert_eq!(report.direct_available, 0);
        assert_eq!(report.selected_relay, 1);
        assert_eq!(report.nat_traversal_unavailable, 1);
        assert_eq!(
            selected.expect("selected").transport,
            RouteTransport::RelayWebSocket
        );
        assert_eq!(direct.state, RouteState::Unavailable);
        assert_eq!(direct.endpoint, DIRECT_QUIC_UNCONFIGURED_ENDPOINT);
        assert!(!direct.direct_attempted);
        assert_eq!(
            direct.failure_reason.as_deref(),
            Some(NAT_TRAVERSAL_UNAVAILABLE)
        );
        assert_eq!(direct.candidate_source, CANDIDATE_SOURCE_NONE);
        assert_eq!(direct.candidate_kind, CANDIDATE_KIND_NONE);
        assert_eq!(direct.rendezvous_state, RENDEZVOUS_STATE_UNAVAILABLE);
        assert!(
            probes
                .iter()
                .any(|probe| probe.outcome == NAT_TRAVERSAL_UNAVAILABLE)
        );
    }

    #[test]
    fn sync_records_peer_card_candidate_metadata_without_payloads() {
        let alice_home = test_home("peer-card-candidate-alice");
        let bob_home = test_home("peer-card-candidate-bob");
        let bob_endpoint = free_loopback_endpoint();
        state::init_state(Some(bob_home.clone())).expect("bob state initializes");
        fs::write(
            StatePaths::from_home(bob_home.clone()).config,
            format!("version = \"1\"\ndirect_quic_endpoint = \"{bob_endpoint}\"\n"),
        )
        .expect("bob config writes");

        let bob_card = trust::export_peer_card(Some(bob_home)).expect("bob card exports");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");

        let report = sync_routes(Some(alice_home.clone())).expect("routes sync");
        let routes = list_routes(Some(alice_home.clone())).expect("routes read");
        let direct = routes
            .iter()
            .find(|route| route.peer_node_id == bob_peer.peer_node_id && route.is_direct())
            .expect("direct route recorded");
        let paths = StatePaths::from_home(alice_home);
        let registry = fs::read_to_string(paths.route_registry).expect("routes read");
        let probes = fs::read_to_string(paths.route_probes).expect("probes read");

        assert_eq!(report.selected_relay, 1);
        assert!(direct.direct_attempted);
        assert_eq!(
            direct.failure_reason.as_deref(),
            Some(DIRECT_QUIC_PROBE_FAILED)
        );
        assert_eq!(direct.candidate_source, CANDIDATE_SOURCE_PEER_CARD);
        assert_eq!(direct.candidate_kind, CANDIDATE_KIND_HOST);
        assert_eq!(
            direct.rendezvous_state,
            RENDEZVOUS_STATE_CANDIDATE_EXCHANGED
        );
        assert!(registry.contains("candidate_source = \"peer_card\""));
        assert!(registry.contains("candidate_kind = \"host\""));
        assert!(registry.contains("rendezvous_state = \"candidate_exchanged\""));
        assert!(probes.contains("candidate_source = \"peer_card\""));
        assert!(probes.contains("candidate_kind = \"host\""));
        assert!(probes.contains("rendezvous_state = \"candidate_exchanged\""));
        assert!(probes.contains("payload_displayed = false"));
        assert!(!registry.contains("private message contents"));
        assert!(!probes.contains("private message contents"));
        assert!(!registry.contains("local-dev-token"));
        assert!(!probes.contains("local-dev-token"));
        assert!(!registry.contains("BEGIN PRIVATE KEY"));
        assert!(!probes.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn invalid_direct_candidate_sanitizes_endpoint_secret_metadata() {
        let home = test_home("invalid-endpoint-secret");
        let peer = trusted_peer(&home);
        let config_key = format!("direct_quic_{}", config_key_suffix(&peer.peer_node_id));
        let secret_endpoint = "quic://user:secret@127.0.0.1:9443";
        fs::write(
            StatePaths::from_home(home.clone()).config,
            format!(
                "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"public\"\n{config_key} = \"{secret_endpoint}\"\n"
            ),
        )
        .expect("config writes");

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let routes = list_routes(Some(home.clone())).expect("routes read");
        let direct = routes
            .iter()
            .find(|route| route.peer_node_id == peer.peer_node_id && route.is_direct())
            .expect("direct route recorded");
        let selected =
            selected_route_for_peer(Some(home.clone()), &peer.peer_node_id).expect("route lookup");
        let paths = StatePaths::from_home(home);
        let registry = fs::read_to_string(paths.route_registry).expect("routes read");
        let probes = fs::read_to_string(paths.route_probes).expect("probes read");
        let log = fs::read_to_string(paths.logs_dir.join("routes.log")).expect("log reads");

        assert_eq!(report.direct_attempts, 0);
        assert_eq!(report.selected_relay, 1);
        assert_eq!(
            selected.expect("selected").transport,
            RouteTransport::RelayWebSocket
        );
        assert_eq!(direct.endpoint, DIRECT_QUIC_INVALID_ENDPOINT);
        assert!(!direct.direct_attempted);
        assert_eq!(
            direct.failure_reason.as_deref(),
            Some("invalid_direct_quic_endpoint")
        );
        assert_eq!(direct.candidate_source, CANDIDATE_SOURCE_PEER_CONFIG);
        assert_eq!(direct.candidate_kind, CANDIDATE_KIND_HOST);
        assert_eq!(
            direct.rendezvous_state,
            RENDEZVOUS_STATE_CANDIDATE_EXCHANGED
        );
        assert_eq!(
            direct.route_id,
            route_id(
                &peer.peer_node_id,
                RouteTransport::DirectQuic,
                Some(DIRECT_QUIC_INVALID_ENDPOINT)
            )
        );
        assert_ne!(
            direct.route_id,
            route_id(
                &peer.peer_node_id,
                RouteTransport::DirectQuic,
                Some(secret_endpoint)
            )
        );
        for contents in [&registry, &probes, &log] {
            assert!(!contents.contains(secret_endpoint));
            assert!(!contents.contains("user:secret"));
            assert!(!contents.contains("@127.0.0.1"));
            assert!(!contents.contains("BEGIN PRIVATE KEY"));
            assert!(!contents.contains("private message contents"));
        }
    }

    #[test]
    fn relay_endpoint_config_rejects_secret_bearing_url_without_echoing_value() {
        let home = test_home("secret-relay-route-config");
        trusted_peer(&home);
        let secret_endpoint = "wss://user:secret@relay.example.com/conu?token=private#fragment";
        fs::write(
            StatePaths::from_home(home.clone()).config,
            format!(
                "version = \"1\"\ndefault_relay = \"{secret_endpoint}\"\nnat_profile = \"public\"\n"
            ),
        )
        .expect("config writes");

        let error = sync_routes(Some(home)).expect_err("secret-bearing relay endpoint should fail");
        let rendered = error.to_string();

        assert!(rendered.contains("endpoint is invalid"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("token=private"));
    }

    #[test]
    fn unusable_direct_ip_literal_is_not_probed() {
        let home = test_home("invalid-endpoint-unspecified");
        let peer = trusted_peer(&home);
        let config_key = format!("direct_quic_{}", config_key_suffix(&peer.peer_node_id));
        fs::write(
            StatePaths::from_home(home.clone()).config,
            format!(
                "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"public\"\n{config_key} = \"quic://0.0.0.0:9443\"\n"
            ),
        )
        .expect("config writes");

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let routes = list_routes(Some(home.clone())).expect("routes read");
        let selected =
            selected_route_for_peer(Some(home.clone()), &peer.peer_node_id).expect("route lookup");
        let direct = routes
            .iter()
            .find(|route| route.peer_node_id == peer.peer_node_id && route.is_direct())
            .expect("direct route recorded");
        let paths = StatePaths::from_home(home);
        let registry = fs::read_to_string(paths.route_registry).expect("routes read");
        let probes = fs::read_to_string(paths.route_probes).expect("probes read");

        assert_eq!(report.direct_attempts, 0);
        assert_eq!(report.selected_relay, 1);
        assert_eq!(
            selected.expect("selected").transport,
            RouteTransport::RelayWebSocket
        );
        assert_eq!(direct.endpoint, DIRECT_QUIC_INVALID_ENDPOINT);
        assert!(!direct.direct_attempted);
        assert_eq!(
            direct.failure_reason.as_deref(),
            Some("invalid_direct_quic_endpoint")
        );
        assert!(registry.contains("payload_displayed = false"));
        assert!(probes.contains("payload_displayed = false"));
        assert!(!registry.contains("0.0.0.0"));
        assert!(!probes.contains("0.0.0.0"));
    }

    #[test]
    fn sync_selects_direct_when_authenticated_quic_probe_succeeds() {
        let _direct_guard = crate::direct_transport::direct_quic_test_lock();
        let alice_home = test_home("direct-selected-alice");
        let bob_home = test_home("direct-selected-bob");
        let bob_endpoint = free_loopback_endpoint();
        state::init_state(Some(bob_home.clone())).expect("bob state initializes");
        fs::write(
            StatePaths::from_home(bob_home.clone()).config,
            format!("version = \"1\"\ndirect_quic_endpoint = \"{bob_endpoint}\"\n"),
        )
        .expect("bob config writes");

        let alice_card =
            trust::export_peer_card(Some(alice_home.clone())).expect("alice card exports");
        let bob_card = trust::export_peer_card(Some(bob_home.clone())).expect("bob card exports");
        let bob_peer =
            trust::trust_peer_card(Some(alice_home.clone()), bob_card).expect("alice trusts bob");
        trust::trust_peer_card(Some(bob_home.clone()), alice_card).expect("bob trusts alice");

        let bob_paths = StatePaths::from_home(bob_home.clone());
        let bob_node = state::read_state(Some(bob_home))
            .expect("bob state")
            .node
            .expect("bob node")
            .node_id;
        let mut server =
            crate::direct_transport::DirectRuntimeServer::new().expect("server starts");
        let handle = std::thread::spawn(move || {
            server
                .tick_from_paths(
                    &bob_paths,
                    &bob_node,
                    crate::direct_transport::direct_quic_test_timeout(),
                )
                .expect("server tick")
        });
        std::thread::sleep(crate::direct_transport::direct_quic_test_startup_delay());

        let report = sync_routes(Some(alice_home.clone())).expect("routes sync");
        let routes = list_routes(Some(alice_home.clone())).expect("routes read");
        let selected = selected_route_for_peer(Some(alice_home), &bob_peer.peer_node_id)
            .expect("route lookup");
        let relay = routes
            .iter()
            .find(|route| {
                route.peer_node_id == bob_peer.peer_node_id
                    && route.transport == RouteTransport::RelayWebSocket
            })
            .expect("relay route recorded");
        let server_report = handle.join().expect("server joins");

        assert_eq!(report.direct_available, 1);
        assert_eq!(report.selected_direct, 1);
        assert_eq!(report.selected_relay, 0);
        assert_eq!(report.relay_fallbacks, 1);
        assert_eq!(
            selected.expect("selected").transport,
            RouteTransport::DirectQuic
        );
        assert_eq!(relay.state, RouteState::Fallback);
        assert!(relay.relay_fallback);
        assert_eq!(server_report.received, 1);
    }

    #[test]
    fn route_logs_and_probes_are_payload_safe() {
        let home = test_home("payload-safe");
        trusted_peer(&home);

        sync_routes(Some(home.clone())).expect("routes sync");
        let paths = StatePaths::from_home(home.clone());
        let log = fs::read_to_string(paths.logs_dir.join("routes.log")).expect("log reads");
        let probes = fs::read_to_string(paths.route_probes).expect("probes read");

        assert!(log.contains("payload=not_observed"));
        assert!(probes.contains("payload_displayed = false"));
        assert!(!log.contains("private message contents"));
        assert!(!probes.contains("private message contents"));
        assert!(!log.contains("Review this code"));
    }

    #[test]
    fn route_sync_success_does_not_depend_on_route_log_write() {
        let home = test_home("route-log-collision");
        let peer = trusted_peer(&home);
        let route_log = StatePaths::from_home(home.clone())
            .logs_dir
            .join("routes.log");
        fs::create_dir(&route_log).expect("route log collision creates");

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let selected = selected_route_for_peer(Some(home), &peer.peer_node_id)
            .expect("selected route reads")
            .expect("selected route exists");

        assert_eq!(report.peers, 1);
        assert_eq!(selected.transport, RouteTransport::RelayWebSocket);
        assert!(route_log.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn route_registry_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("route-registry-symlink");
        trusted_peer(&home);
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-route-registry");
        let outside_contents = "outside route registry\n";
        fs::write(&outside, outside_contents).expect("outside registry writes");
        symlink(&outside, &paths.route_registry).expect("route registry symlink creates");

        let error = sync_routes(Some(home)).expect_err("symlinked route registry fails closed");

        assert!(error.to_string().contains("inspect route registry"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside registry reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.route_registry)
                .expect("route registry metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn route_probes_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("route-probes-symlink");
        trusted_peer(&home);
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-route-probes");
        let outside_contents = "outside route probes\n";
        fs::write(&outside, outside_contents).expect("outside probes write");
        symlink(&outside, &paths.route_probes).expect("route probes symlink creates");

        let error = sync_routes(Some(home)).expect_err("symlinked route probes fail closed");

        assert!(error.to_string().contains("inspect route probes"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside probes read"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.route_probes)
                .expect("route probes metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn route_directory_symlink_is_rejected_without_reading_registry() {
        use std::os::unix::fs::symlink;

        let home = test_home("routes-dir-registry-read-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-routes-dir-registry-read");
        let registry_name = paths
            .route_registry
            .file_name()
            .expect("route registry filename");
        fs::remove_dir_all(&paths.routes_dir).expect("routes dir removes");
        fs::create_dir_all(&outside).expect("outside routes dir creates");
        fs::write(outside.join(registry_name), test_route_registry_contents())
            .expect("outside registry writes");
        symlink(&outside, &paths.routes_dir).expect("routes dir symlink creates");

        let error = list_routes(Some(home)).expect_err("symlinked routes directory fails closed");

        assert!(error.to_string().contains("inspect routes directory"));
    }

    #[cfg(unix)]
    #[test]
    fn route_directory_symlink_is_rejected_without_writing_registry() {
        use std::os::unix::fs::symlink;

        let home = test_home("routes-dir-registry-write-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-routes-dir-registry-write");
        let registry_name = paths
            .route_registry
            .file_name()
            .expect("route registry filename");
        fs::remove_dir_all(&paths.routes_dir).expect("routes dir removes");
        fs::create_dir_all(&outside).expect("outside routes dir creates");
        symlink(&outside, &paths.routes_dir).expect("routes dir symlink creates");

        let error = write_routes(&paths, &[test_route_record()])
            .expect_err("symlinked routes directory fails closed");

        assert!(error.to_string().contains("state directory"));
        assert!(!outside.join(registry_name).exists());
        assert!(
            fs::symlink_metadata(&paths.routes_dir)
                .expect("routes dir metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn route_directory_symlink_is_rejected_without_reading_probes() {
        use std::os::unix::fs::symlink;

        let home = test_home("routes-dir-probes-read-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-routes-dir-probes-read");
        let probes_name = paths
            .route_probes
            .file_name()
            .expect("route probes filename");
        fs::remove_dir_all(&paths.routes_dir).expect("routes dir removes");
        fs::create_dir_all(&outside).expect("outside routes dir creates");
        fs::write(outside.join(probes_name), test_route_probe_contents())
            .expect("outside probes write");
        symlink(&outside, &paths.routes_dir).expect("routes dir symlink creates");

        let error =
            list_route_probes(Some(home)).expect_err("symlinked routes directory fails closed");

        assert!(error.to_string().contains("inspect routes directory"));
    }

    #[cfg(unix)]
    #[test]
    fn route_directory_symlink_is_rejected_without_appending_probe() {
        use std::os::unix::fs::symlink;

        let home = test_home("routes-dir-probes-write-symlink");
        let init = state::init_state(Some(home.clone())).expect("state initializes");
        let paths = init.paths;
        let outside = home.with_extension("outside-routes-dir-probes-write");
        let probes_name = paths
            .route_probes
            .file_name()
            .expect("route probes filename");
        fs::remove_dir_all(&paths.routes_dir).expect("routes dir removes");
        fs::create_dir_all(&outside).expect("outside routes dir creates");
        symlink(&outside, &paths.routes_dir).expect("routes dir symlink creates");

        let error = append_probes(&paths, &[test_route_probe()])
            .expect_err("symlinked routes directory fails closed");

        assert!(error.to_string().contains("state directory"));
        assert!(!outside.join(probes_name).exists());
        assert!(
            fs::symlink_metadata(&paths.routes_dir)
                .expect("routes dir metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn revoked_peer_is_not_routeable() {
        let home = test_home("revoked");
        let peer = trusted_peer(&home);
        trust::revoke_peer(Some(home.clone()), &peer.peer_node_id).expect("revokes");

        let report = sync_routes(Some(home.clone())).expect("routes sync");
        let routes = list_routes(Some(home)).expect("routes read");

        assert_eq!(report.peers, 0);
        assert!(routes.is_empty());
    }

    #[cfg(unix)]
    fn test_route_record() -> RouteRecord {
        RouteRecord {
            route_id: "route_test".to_string(),
            peer_node_id: "node_peer".to_string(),
            display_name: "Peer".to_string(),
            transport: RouteTransport::RelayWebSocket,
            endpoint: DEFAULT_RELAY_ENDPOINT.to_string(),
            state: RouteState::Selected,
            score: RELAY_WEBSOCKET_LATENCY_MS as u16,
            latency_ms: Some(RELAY_WEBSOCKET_LATENCY_MS),
            direct_attempted: false,
            relay_fallback: true,
            nat_profile: NatProfile::Unknown,
            candidate_source: CANDIDATE_SOURCE_NONE.to_string(),
            candidate_kind: CANDIDATE_KIND_NONE.to_string(),
            rendezvous_state: RENDEZVOUS_STATE_NOT_CONFIGURED.to_string(),
            failure_reason: None,
            updated_at_unix: 1,
        }
    }

    #[cfg(unix)]
    fn test_route_probe() -> RouteProbe {
        RouteProbe {
            probe_id: "probe_test".to_string(),
            route_id: "route_test".to_string(),
            peer_node_id: "node_peer".to_string(),
            transport: RouteTransport::RelayWebSocket,
            endpoint: DEFAULT_RELAY_ENDPOINT.to_string(),
            outcome: "selected".to_string(),
            score: RELAY_WEBSOCKET_LATENCY_MS as u16,
            latency_ms: Some(RELAY_WEBSOCKET_LATENCY_MS),
            candidate_source: CANDIDATE_SOURCE_NONE.to_string(),
            candidate_kind: CANDIDATE_KIND_NONE.to_string(),
            rendezvous_state: RENDEZVOUS_STATE_NOT_CONFIGURED.to_string(),
            created_at_unix: 1,
        }
    }

    #[cfg(unix)]
    fn test_route_registry_contents() -> &'static str {
        "# conU route registry\nversion = \"1\"\n\n[[route]]\nroute_id = \"route_test\"\npeer_node_id = \"node_peer\"\ndisplay_name = \"Peer\"\ntransport = \"relay-websocket\"\nendpoint = \"ws://127.0.0.1:8787\"\nstate = \"selected\"\nscore = 80\nlatency_ms = 80\ndirect_attempted = false\nrelay_fallback = true\nnat_profile = \"unknown\"\ncandidate_source = \"none\"\ncandidate_kind = \"none\"\nrendezvous_state = \"not_configured\"\nfailure_reason = \"\"\nupdated_at_unix = 1\npayload_displayed = false\n"
    }

    #[cfg(unix)]
    fn test_route_probe_contents() -> &'static str {
        "# conU route probes\nversion = \"1\"\n\n[[probe]]\nprobe_id = \"probe_test\"\nroute_id = \"route_test\"\npeer_node_id = \"node_peer\"\ntransport = \"relay-websocket\"\nendpoint = \"ws://127.0.0.1:8787\"\noutcome = \"selected\"\nscore = 80\nlatency_ms = 80\ncandidate_source = \"none\"\ncandidate_kind = \"none\"\nrendezvous_state = \"not_configured\"\ncreated_at_unix = 1\npayload_displayed = false\n"
    }

    fn trusted_peer(home: &Path) -> TrustedPeer {
        state::init_state(Some(home.to_path_buf())).expect("state initializes");
        let invite =
            trust::create_pairing_invite(Some(home.to_path_buf())).expect("invite creates");
        trust::join_pairing_code(Some(home.to_path_buf()), &invite.code)
            .expect("joins")
            .peer
    }

    fn test_home(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "conu-routes-test-{}-{}-{name}",
            process::id(),
            current_unix_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn free_loopback_endpoint() -> String {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("free UDP port binds");
        let port = socket.local_addr().expect("local addr").port();
        drop(socket);
        format!("quic://127.0.0.1:{port}")
    }
}
