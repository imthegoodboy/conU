//! Agent-facing SDK for conU.
//!
//! This crate gives agents a narrow, typed way to use conU as a connection
//! layer. It intentionally mirrors the core gateway surfaces and keeps list,
//! send, receipt, and stream operations metadata-only. Payload bytes are only
//! returned by explicit receive calls for the addressed local agent.

use std::fmt;
use std::path::PathBuf;

use conu_core::agents::{
    self, AgentPresence, AgentRegistration, GatewayProcessReport, GatewaySubmission,
    LocalAgentRecord, PresenceHeartbeat,
};
use conu_core::messages::{
    self, DeliveryReceipt, InboxEntry, LocalMessage, MessageProcessReport, MessageSubmission,
};
use conu_core::policy;
use conu_core::relay_delivery::{
    self, RelayQueueSummary, RelaySyncReport, RemoteMessage, RemoteMessageSubmission,
};
use conu_core::rooms::{
    self, RoomCreateReport, RoomEvent, RoomJoinReport, RoomPublishReport, RoomRecord,
    RoomTopicPolicyRecord, RoomTopicPolicyUpdate,
};
use conu_core::routes::{self, RouteProbe, RouteRecord, RouteSyncReport};
use conu_core::runtime::{self, RuntimeStatus};
use conu_core::security::{self, SecurityAudit};
use conu_core::sessions::{self, RemoteAgentRecord, RemoteSession, SessionSyncReport};
use conu_core::state::{self, InitReport, StateSnapshot};
use conu_core::streams::{
    self, StreamCloseReport, StreamEvent, StreamOpenReport, StreamRecord, StreamWriteReport,
};
use conu_core::trust::{self, JoinReport, PairingInvite, RevokeReport, TrustedPeer};
use conu_protocol::{AgentCapabilities, OpaquePayload};
use std::time::Duration;

pub use conu_core::agents::{AgentPresence as Presence, SignedAgentCard};
pub use conu_core::policy::{PeerPolicyRecord, PeerPolicyUpdate};
pub use conu_core::rooms::{
    RoomEvent as RoomBusEvent, RoomRecord as Room, RoomTopicPolicyRecord as TopicPolicy,
    RoomTopicPolicyUpdate as TopicPolicyUpdate,
};
pub use conu_core::routes::RouteRecord as Route;
pub use conu_core::streams::StreamRecord as Stream;
pub use conu_core::trust::PeerCard;
pub use conu_protocol::AgentCapabilities as Capabilities;

/// High-level SDK client bound to a conU state home.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConuClient {
    home: Option<PathBuf>,
}

impl ConuClient {
    /// Use the default conU state home for this user.
    pub fn new() -> Self {
        Self { home: None }
    }

    /// Use a specific conU state home. This is useful for agent sandboxes and tests.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
        }
    }

    /// Return the configured home override, if this client has one.
    pub fn home(&self) -> Option<&PathBuf> {
        self.home.as_ref()
    }

    /// Initialize local conU state and security material.
    pub fn init(&self) -> Result<InitReport, SdkError> {
        let report = state::init_state(self.home_override())?;
        security::ensure_security_state_from_paths(&report.paths)?;
        Ok(report)
    }

    /// Read local state without creating missing files.
    pub fn state_snapshot(&self) -> Result<StateSnapshot, SdkError> {
        Ok(state::read_state(self.home_override())?)
    }

    /// Read current conUD runtime metadata.
    pub fn runtime_status(&self) -> Result<RuntimeStatus, SdkError> {
        Ok(runtime::read_runtime(self.home_override())?)
    }

    /// Run the local security audit.
    pub fn security_audit(&self) -> Result<SecurityAudit, SdkError> {
        Ok(security::security_audit(self.home_override())?)
    }

    /// Register an agent with the default message/presence capabilities.
    pub fn register_agent(
        &self,
        agent_id: impl Into<String>,
        display_name: impl Into<String>,
        kind: impl Into<String>,
    ) -> Result<GatewaySubmission, SdkError> {
        let registration = AgentRegistration::new(agent_id, display_name, kind)?;
        Ok(agents::submit_registration(
            self.home_override(),
            registration,
        )?)
    }

    /// Register an agent with an explicit capability set.
    pub fn register_agent_with_capabilities(
        &self,
        agent_id: impl Into<String>,
        display_name: impl Into<String>,
        kind: impl Into<String>,
        capabilities: AgentCapabilities,
    ) -> Result<GatewaySubmission, SdkError> {
        let mut registration = AgentRegistration::new(agent_id, display_name, kind)?;
        registration.capabilities = capabilities;
        Ok(agents::submit_registration(
            self.home_override(),
            registration,
        )?)
    }

    /// Submit an agent presence heartbeat.
    pub fn set_presence(
        &self,
        agent_id: impl Into<String>,
        presence: AgentPresence,
    ) -> Result<GatewaySubmission, SdkError> {
        let heartbeat = PresenceHeartbeat::new(agent_id, presence)?;
        Ok(agents::submit_presence_heartbeat(
            self.home_override(),
            heartbeat,
        )?)
    }

    /// Process all queued local gateway work once.
    pub fn process_queued(&self) -> Result<ProcessReport, SdkError> {
        let agents = agents::process_gateway_requests(self.home_override())?;
        let messages = messages::process_message_requests(self.home_override())?;
        let sessions = sessions::sync_remote_sessions(self.home_override())?;

        Ok(ProcessReport {
            agents,
            messages,
            sessions,
        })
    }

    /// List local and mirrored remote agents.
    pub fn list_agents(&self) -> Result<AgentDirectory, SdkError> {
        Ok(AgentDirectory {
            local: agents::list_local_agents(self.home_override())?,
            remote: sessions::list_remote_agents(self.home_override())?,
        })
    }

    /// List trusted/revoked peers.
    pub fn list_peers(&self) -> Result<Vec<TrustedPeer>, SdkError> {
        Ok(trust::list_peers(self.home_override())?)
    }

    /// Probe and score direct/relay routes for trusted peers.
    pub fn sync_routes(&self) -> Result<RouteSyncReport, SdkError> {
        Ok(routes::sync_routes(self.home_override())?)
    }

    /// List direct/relay route candidates.
    pub fn list_routes(&self) -> Result<Vec<RouteRecord>, SdkError> {
        Ok(routes::list_routes(self.home_override())?)
    }

    /// List metadata-only route probe history.
    pub fn list_route_probes(&self) -> Result<Vec<RouteProbe>, SdkError> {
        Ok(routes::list_route_probes(self.home_override())?)
    }

    /// Create a local pairing invitation.
    pub fn create_pairing_invite(&self) -> Result<PairingInvite, SdkError> {
        Ok(trust::create_pairing_invite(self.home_override())?)
    }

    /// Export this node's public peer card for manual cross-machine trust.
    pub fn export_peer_card(&self) -> Result<PeerCard, SdkError> {
        Ok(trust::export_peer_card(self.home_override())?)
    }

    /// Export a signed public local agent card for a trusted peer.
    pub fn export_agent_card(&self, agent_id: &str) -> Result<SignedAgentCard, SdkError> {
        Ok(agents::export_agent_card(self.home_override(), agent_id)?)
    }

    /// Trust a remote node from its public peer card.
    pub fn trust_peer_card(&self, card: PeerCard) -> Result<TrustedPeer, SdkError> {
        Ok(trust::trust_peer_card(self.home_override(), card)?)
    }

    /// Trust a remote agent from a signed card exported by an already trusted peer.
    pub fn trust_remote_agent_card(
        &self,
        card: SignedAgentCard,
    ) -> Result<RemoteAgentRecord, SdkError> {
        Ok(sessions::trust_remote_agent_card(
            self.home_override(),
            card,
        )?)
    }

    /// Join a local pairing code.
    pub fn join_pairing_code(&self, code: &str) -> Result<JoinReport, SdkError> {
        Ok(trust::join_pairing_code(self.home_override(), code)?)
    }

    /// Revoke a trusted peer.
    pub fn revoke_peer(&self, peer_node_id: &str) -> Result<RevokeReport, SdkError> {
        Ok(trust::revoke_peer(self.home_override(), peer_node_id)?)
    }

    /// List explicit peer-scoped communication policies.
    pub fn list_peer_policies(&self) -> Result<Vec<PeerPolicyRecord>, SdkError> {
        Ok(policy::list_peer_policies(self.home_override())?)
    }

    /// Read one peer's effective policy. Missing policy records deny all surfaces.
    pub fn peer_policy(&self, peer_node_id: &str) -> Result<PeerPolicyRecord, SdkError> {
        Ok(policy::peer_policy(self.home_override(), peer_node_id)?)
    }

    /// Set one trusted peer's communication policy.
    pub fn set_peer_policy(
        &self,
        peer_node_id: &str,
        update: PeerPolicyUpdate,
    ) -> Result<PeerPolicyRecord, SdkError> {
        Ok(policy::set_peer_policy(
            self.home_override(),
            peer_node_id,
            update,
        )?)
    }

    /// List remote runtime sessions.
    pub fn list_remote_sessions(&self) -> Result<Vec<RemoteSession>, SdkError> {
        Ok(sessions::list_remote_sessions(self.home_override())?)
    }

    /// List mirrored remote agent cards.
    pub fn list_remote_agents(&self) -> Result<Vec<RemoteAgentRecord>, SdkError> {
        Ok(sessions::list_remote_agents(self.home_override())?)
    }

    /// Queue an opaque one-shot message.
    pub fn send_message_bytes(
        &self,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<MessageSubmission, SdkError> {
        let message = LocalMessage::new(
            from_agent_id,
            to_agent_id,
            OpaquePayload::from_bytes(payload.into()),
        )?;
        Ok(messages::submit_local_message(
            self.home_override(),
            message,
        )?)
    }

    /// Queue a UTF-8 message as opaque bytes.
    pub fn send_message_text(
        &self,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload: impl Into<String>,
    ) -> Result<MessageSubmission, SdkError> {
        self.send_message_bytes(from_agent_id, to_agent_id, payload.into().into_bytes())
    }

    /// Queue an opaque message for a trusted remote node through the relay.
    pub fn send_remote_message_bytes(
        &self,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<RemoteMessageSubmission, SdkError> {
        let message = RemoteMessage::new(
            from_agent_id,
            to_agent_id,
            peer_node_id,
            OpaquePayload::from_bytes(payload.into()),
        )?;
        Ok(relay_delivery::submit_remote_message(
            self.home_override(),
            message,
        )?)
    }

    /// Connect to the relay once, flush outbound remote messages, and receive inbound envelopes.
    pub fn relay_sync(&self, wait: Duration) -> Result<RelaySyncReport, SdkError> {
        Ok(relay_delivery::sync_relay_once(self.home_override(), wait)?)
    }

    /// Inspect relay queue metadata without connecting to the relay.
    pub fn relay_queue_summary(&self) -> Result<RelayQueueSummary, SdkError> {
        Ok(relay_delivery::relay_queue_summary(self.home_override())?)
    }

    /// List metadata for messages delivered to a local agent.
    pub fn inbox_metadata(&self, agent_id: &str) -> Result<Vec<InboxEntry>, SdkError> {
        Ok(messages::list_agent_inbox(self.home_override(), agent_id)?)
    }

    /// Read payload bytes for a delivered local message addressed to `agent_id`.
    pub fn receive_message_bytes(
        &self,
        agent_id: &str,
        envelope_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let inbox = messages::list_agent_inbox(self.home_override(), agent_id)?;
        let Some(entry) = inbox.iter().find(|entry| entry.envelope_id == envelope_id) else {
            return Err(SdkError::EnvelopeNotFound {
                agent_id: agent_id.to_string(),
                envelope_id: envelope_id.to_string(),
            });
        };

        if entry.to_agent_id != agent_id {
            return Err(SdkError::UnauthorizedReceive {
                agent_id: agent_id.to_string(),
                envelope_id: envelope_id.to_string(),
            });
        }

        let payload = messages::read_message_payload(self.home_override(), agent_id, envelope_id)?;
        Ok(payload.as_bytes().to_vec())
    }

    /// List metadata-only delivery receipts.
    pub fn list_receipts(&self) -> Result<Vec<DeliveryReceipt>, SdkError> {
        Ok(messages::list_receipts(self.home_override())?)
    }

    /// Open a metadata-tracked stream.
    pub fn open_stream(
        &self,
        from_agent_id: &str,
        to_agent_id: &str,
        kind: &str,
    ) -> Result<StreamOpenReport, SdkError> {
        Ok(streams::open_stream(
            self.home_override(),
            from_agent_id,
            to_agent_id,
            kind,
        )?)
    }

    /// Record one opaque stream chunk by byte count.
    pub fn write_stream_bytes(
        &self,
        stream_id: &str,
        payload: impl Into<Vec<u8>>,
    ) -> Result<StreamWriteReport, SdkError> {
        Ok(streams::write_stream(
            self.home_override(),
            stream_id,
            OpaquePayload::from_bytes(payload.into()),
        )?)
    }

    /// Close an open stream.
    pub fn close_stream(&self, stream_id: &str) -> Result<StreamCloseReport, SdkError> {
        Ok(streams::close_stream(self.home_override(), stream_id)?)
    }

    /// List stream metadata.
    pub fn list_streams(&self) -> Result<Vec<StreamRecord>, SdkError> {
        Ok(streams::list_streams(self.home_override())?)
    }

    /// List payload-safe stream events.
    pub fn list_stream_events(&self) -> Result<Vec<StreamEvent>, SdkError> {
        Ok(streams::list_events(self.home_override())?)
    }

    /// Create a metadata-tracked room owned by a local agent.
    pub fn create_room(
        &self,
        room_id: &str,
        display_name: &str,
        created_by_agent_id: &str,
    ) -> Result<RoomCreateReport, SdkError> {
        Ok(rooms::create_room(
            self.home_override(),
            room_id,
            display_name,
            created_by_agent_id,
        )?)
    }

    /// Join a visible local or trusted remote agent to a room.
    pub fn join_room(&self, room_id: &str, agent_id: &str) -> Result<RoomJoinReport, SdkError> {
        Ok(rooms::join_room(self.home_override(), room_id, agent_id)?)
    }

    /// Publish one opaque room event by byte count only.
    pub fn publish_room_event_bytes(
        &self,
        room_id: &str,
        from_agent_id: &str,
        topic: &str,
        payload: impl Into<Vec<u8>>,
    ) -> Result<RoomPublishReport, SdkError> {
        Ok(rooms::publish_room_event(
            self.home_override(),
            room_id,
            from_agent_id,
            topic,
            OpaquePayload::from_bytes(payload.into()),
        )?)
    }

    /// List room metadata.
    pub fn list_rooms(&self) -> Result<Vec<RoomRecord>, SdkError> {
        Ok(rooms::list_rooms(self.home_override())?)
    }

    /// List payload-safe room events.
    pub fn list_room_events(&self) -> Result<Vec<RoomEvent>, SdkError> {
        Ok(rooms::list_room_events(self.home_override())?)
    }

    /// List explicit room topic policy records.
    pub fn list_room_topic_policies(&self) -> Result<Vec<RoomTopicPolicyRecord>, SdkError> {
        Ok(rooms::list_room_topic_policies(self.home_override())?)
    }

    /// Read one explicit room topic policy record.
    pub fn room_topic_policy(
        &self,
        room_id: &str,
        agent_id: &str,
        topic: &str,
    ) -> Result<Option<RoomTopicPolicyRecord>, SdkError> {
        Ok(rooms::room_topic_policy(
            self.home_override(),
            room_id,
            agent_id,
            topic,
        )?)
    }

    /// Set one joined agent's publish/subscribe grants for a room topic.
    pub fn set_room_topic_policy(
        &self,
        room_id: &str,
        agent_id: &str,
        topic: &str,
        update: RoomTopicPolicyUpdate,
    ) -> Result<RoomTopicPolicyRecord, SdkError> {
        Ok(rooms::set_room_topic_policy(
            self.home_override(),
            room_id,
            agent_id,
            topic,
            update,
        )?)
    }

    fn home_override(&self) -> Option<PathBuf> {
        self.home.clone()
    }
}

/// Local + remote agent directory view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDirectory {
    pub local: Vec<LocalAgentRecord>,
    pub remote: Vec<RemoteAgentRecord>,
}

/// Result of one SDK-driven processing pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessReport {
    pub agents: GatewayProcessReport,
    pub messages: MessageProcessReport,
    pub sessions: SessionSyncReport,
}

/// Errors returned by the SDK.
pub enum SdkError {
    State(state::StateError),
    Security(security::SecurityError),
    Agent(agents::AgentError),
    Message(messages::MessageError),
    Policy(policy::PolicyError),
    Runtime(runtime::RuntimeError),
    Route(routes::RouteError),
    RelayDelivery(relay_delivery::RelayDeliveryError),
    Room(rooms::RoomError),
    Session(sessions::SessionError),
    Stream(streams::StreamError),
    Trust(trust::TrustError),
    EnvelopeNotFound {
        agent_id: String,
        envelope_id: String,
    },
    UnauthorizedReceive {
        agent_id: String,
        envelope_id: String,
    },
}

impl fmt::Debug for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => formatter.debug_tuple("State").field(error).finish(),
            Self::Security(error) => formatter.debug_tuple("Security").field(error).finish(),
            Self::Agent(error) => formatter.debug_tuple("Agent").field(error).finish(),
            Self::Message(error) => formatter.debug_tuple("Message").field(error).finish(),
            Self::Policy(error) => formatter.debug_tuple("Policy").field(error).finish(),
            Self::Runtime(error) => formatter.debug_tuple("Runtime").field(error).finish(),
            Self::Route(error) => formatter.debug_tuple("Route").field(error).finish(),
            Self::RelayDelivery(error) => {
                formatter.debug_tuple("RelayDelivery").field(error).finish()
            }
            Self::Room(error) => formatter.debug_tuple("Room").field(error).finish(),
            Self::Session(error) => formatter.debug_tuple("Session").field(error).finish(),
            Self::Stream(error) => formatter.debug_tuple("Stream").field(error).finish(),
            Self::Trust(error) => formatter.debug_tuple("Trust").field(error).finish(),
            Self::EnvelopeNotFound { .. } => formatter
                .debug_struct("EnvelopeNotFound")
                .field("agent_id", &"[redacted]")
                .field("envelope_id", &"[redacted]")
                .field("contents_displayed", &false)
                .finish(),
            Self::UnauthorizedReceive { .. } => formatter
                .debug_struct("UnauthorizedReceive")
                .field("agent_id", &"[redacted]")
                .field("envelope_id", &"[redacted]")
                .field("contents_displayed", &false)
                .finish(),
        }
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Security(error) => write!(formatter, "{error}"),
            Self::Agent(error) => write!(formatter, "{error}"),
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Policy(error) => write!(formatter, "{error}"),
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::Route(error) => write!(formatter, "{error}"),
            Self::RelayDelivery(error) => write!(formatter, "{error}"),
            Self::Room(error) => write!(formatter, "{error}"),
            Self::Session(error) => write!(formatter, "{error}"),
            Self::Stream(error) => write!(formatter, "{error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::EnvelopeNotFound { .. } => write!(
                formatter,
                "message envelope was not found in the addressed agent inbox; contentsDisplayed=false"
            ),
            Self::UnauthorizedReceive { .. } => write!(
                formatter,
                "agent is not authorized to receive the requested envelope; contentsDisplayed=false"
            ),
        }
    }
}

impl std::error::Error for SdkError {}

impl From<state::StateError> for SdkError {
    fn from(error: state::StateError) -> Self {
        Self::State(error)
    }
}

impl From<security::SecurityError> for SdkError {
    fn from(error: security::SecurityError) -> Self {
        Self::Security(error)
    }
}

impl From<agents::AgentError> for SdkError {
    fn from(error: agents::AgentError) -> Self {
        Self::Agent(error)
    }
}

impl From<messages::MessageError> for SdkError {
    fn from(error: messages::MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<policy::PolicyError> for SdkError {
    fn from(error: policy::PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<runtime::RuntimeError> for SdkError {
    fn from(error: runtime::RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<routes::RouteError> for SdkError {
    fn from(error: routes::RouteError) -> Self {
        Self::Route(error)
    }
}

impl From<relay_delivery::RelayDeliveryError> for SdkError {
    fn from(error: relay_delivery::RelayDeliveryError) -> Self {
        Self::RelayDelivery(error)
    }
}

impl From<rooms::RoomError> for SdkError {
    fn from(error: rooms::RoomError) -> Self {
        Self::Room(error)
    }
}

impl From<sessions::SessionError> for SdkError {
    fn from(error: sessions::SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<streams::StreamError> for SdkError {
    fn from(error: streams::StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<trust::TrustError> for SdkError {
    fn from(error: trust::TrustError) -> Self {
        Self::Trust(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sdk_sends_and_receives_opaque_payload_for_addressed_agent() {
        let client = ConuClient::with_home(test_home("send-receive"));
        client.init().expect("state initializes");
        client
            .register_agent("agent.sender", "Sender", "test-agent")
            .expect("sender registers");
        client
            .register_agent("agent.receiver", "Receiver", "test-agent")
            .expect("receiver registers");
        let agent_report = client.process_queued().expect("registrations process");
        let sent = client
            .send_message_bytes(
                "agent.sender",
                "agent.receiver",
                b"private message contents",
            )
            .expect("message queues");
        let message_report = client.process_queued().expect("message processes");
        let inbox = client
            .inbox_metadata("agent.receiver")
            .expect("inbox metadata reads");
        let received = client
            .receive_message_bytes("agent.receiver", &inbox[0].envelope_id)
            .expect("payload reads");

        assert_eq!(agent_report.agents.processed, 2);
        assert_eq!(sent.payload_bytes, 24);
        assert_eq!(message_report.messages.delivered, 1);
        assert_eq!(inbox[0].payload_bytes, 24);
        assert_eq!(received, b"private message contents");
    }

    #[test]
    fn sdk_receive_is_scoped_to_recipient_inbox() {
        let client = ConuClient::with_home(test_home("scoped-receive"));
        client.init().expect("state initializes");
        client
            .register_agent("agent.sender", "Sender", "test-agent")
            .expect("sender registers");
        client
            .register_agent("agent.receiver", "Receiver", "test-agent")
            .expect("receiver registers");
        client.process_queued().expect("registrations process");
        client
            .send_message_bytes(
                "agent.sender",
                "agent.receiver",
                b"private message contents",
            )
            .expect("message queues");
        client.process_queued().expect("message processes");
        let inbox = client
            .inbox_metadata("agent.receiver")
            .expect("inbox metadata reads");
        let error = client
            .receive_message_bytes("agent.sender", &inbox[0].envelope_id)
            .expect_err("wrong local agent cannot receive");
        let rendered = error.to_string();

        assert!(matches!(error, SdkError::EnvelopeNotFound { .. }));
        assert!(!rendered.contains("agent.sender"));
        assert!(!rendered.contains(&inbox[0].envelope_id));
        assert!(rendered.contains("contentsDisplayed=false"));
    }

    #[test]
    fn sdk_receive_error_formatting_redacts_identifiers() {
        let missing = SdkError::EnvelopeNotFound {
            agent_id: "agent.secret-token".to_string(),
            envelope_id: "env.secret-token".to_string(),
        };
        let unauthorized = SdkError::UnauthorizedReceive {
            agent_id: "agent.secret-token".to_string(),
            envelope_id: "env.secret-token".to_string(),
        };

        for rendered in [
            missing.to_string(),
            format!("{missing:?}"),
            unauthorized.to_string(),
            format!("{unauthorized:?}"),
        ] {
            assert!(!rendered.contains("agent.secret-token"));
            assert!(!rendered.contains("env.secret-token"));
            assert!(!rendered.contains("secret-token"));
            assert!(
                rendered.contains("contentsDisplayed=false")
                    || rendered.contains("contents_displayed: false")
            );
        }
    }

    #[test]
    fn sdk_room_flow_returns_metadata_only() {
        let client = ConuClient::with_home(test_home("rooms"));
        client.init().expect("state initializes");
        let mut capabilities = AgentCapabilities::basic();
        capabilities.rooms = true;
        client
            .register_agent_with_capabilities(
                "agent.codex",
                "Codex",
                "test-agent",
                capabilities.clone(),
            )
            .expect("codex registers");
        client
            .register_agent_with_capabilities("agent.hermes", "Hermes", "test-agent", capabilities)
            .expect("hermes registers");
        client.process_queued().expect("registrations process");

        let created = client
            .create_room("room.dev", "Dev Room", "agent.codex")
            .expect("room creates");
        let joined = client
            .join_room("room.dev", "agent.hermes")
            .expect("room joins");
        let published = client
            .publish_room_event_bytes(
                "room.dev",
                "agent.hermes",
                "build",
                b"private message contents",
            )
            .expect("event publishes");
        let rooms = client.list_rooms().expect("rooms list");
        let events = client.list_room_events().expect("events list");
        let debug = format!("{created:?}\n{joined:?}\n{published:?}\n{rooms:?}\n{events:?}");

        assert_eq!(published.event.payload_bytes, 24);
        assert_eq!(published.local_deliveries, 1);
        assert_eq!(rooms[0].participants.len(), 2);
        assert_eq!(events.len(), 1);
        assert!(!debug.contains("private message contents"));
    }

    #[test]
    fn sdk_room_topic_policy_controls_publish_and_subscribe() {
        let client = ConuClient::with_home(test_home("room-topic-policy"));
        client.init().expect("state initializes");
        let mut capabilities = AgentCapabilities::basic();
        capabilities.rooms = true;
        client
            .register_agent_with_capabilities(
                "agent.codex",
                "Codex",
                "test-agent",
                capabilities.clone(),
            )
            .expect("codex registers");
        client
            .register_agent_with_capabilities("agent.hermes", "Hermes", "test-agent", capabilities)
            .expect("hermes registers");
        client.process_queued().expect("registrations process");
        client
            .create_room("room.dev", "Dev Room", "agent.codex")
            .expect("room creates");
        client
            .join_room("room.dev", "agent.hermes")
            .expect("room joins");

        let publisher = client
            .set_room_topic_policy(
                "room.dev",
                "agent.hermes",
                "build",
                TopicPolicyUpdate {
                    publish: Some(true),
                    subscribe: Some(false),
                },
            )
            .expect("publisher grant writes");
        let subscriber = client
            .set_room_topic_policy(
                "room.dev",
                "agent.codex",
                "build",
                TopicPolicyUpdate {
                    publish: Some(false),
                    subscribe: Some(true),
                },
            )
            .expect("subscriber grant writes");
        let policies = client
            .list_room_topic_policies()
            .expect("topic policies list");
        let published = client
            .publish_room_event_bytes(
                "room.dev",
                "agent.hermes",
                "build",
                b"private message contents",
            )
            .expect("event publishes");
        let debug = format!("{publisher:?}\n{subscriber:?}\n{policies:?}\n{published:?}");

        assert!(publisher.publish);
        assert!(subscriber.subscribe);
        assert_eq!(policies.len(), 2);
        assert_eq!(published.local_deliveries, 1);
        assert!(!debug.contains("private message contents"));
    }

    #[test]
    fn sdk_exports_and_trusts_signed_remote_agent_cards_without_payloads() {
        let alice = ConuClient::with_home(test_home("signed-agent-card-alice"));
        let bob = ConuClient::with_home(test_home("signed-agent-card-bob"));
        alice.init().expect("alice state initializes");
        bob.init().expect("bob state initializes");

        let bob_peer_card = bob.export_peer_card().expect("bob peer card exports");
        alice
            .trust_peer_card(bob_peer_card)
            .expect("alice trusts bob peer");

        let mut capabilities = AgentCapabilities::basic();
        capabilities.streams = true;
        capabilities.rooms = true;
        bob.register_agent_with_capabilities(
            "agent.bob",
            "Bob",
            "test-agent",
            capabilities.clone(),
        )
        .expect("bob agent registers");
        bob.process_queued().expect("bob registration processes");

        let agent_card = bob
            .export_agent_card("agent.bob")
            .expect("agent card exports");
        let imported = alice
            .trust_remote_agent_card(agent_card.clone())
            .expect("alice trusts bob agent");
        let remote_agents = alice
            .list_remote_agents()
            .expect("alice remote agent list reads");
        let debug = format!("{agent_card:?}\n{imported:?}\n{remote_agents:?}");

        assert_eq!(imported.agent_id, "agent.bob");
        assert!(imported.agent_card_signed());
        assert_eq!(imported.capabilities, capabilities);
        assert_eq!(remote_agents.len(), 1);
        assert!(remote_agents[0].agent_card_signed());
        assert!(!debug.contains("private message contents"));
        assert!(!debug.contains("Review this code"));
    }

    #[test]
    fn sdk_sets_peer_policy_metadata_only() {
        let alice = ConuClient::with_home(test_home("peer-policy-alice"));
        let bob = ConuClient::with_home(test_home("peer-policy-bob"));
        alice.init().expect("alice state initializes");
        bob.init().expect("bob state initializes");
        let bob_card = bob.export_peer_card().expect("bob peer card exports");
        let bob_peer = alice.trust_peer_card(bob_card).expect("alice trusts bob");

        let policy = alice
            .set_peer_policy(
                &bob_peer.peer_node_id,
                PeerPolicyUpdate {
                    messages: Some(true),
                    streams: Some(true),
                    rooms: Some(false),
                    files: Some(false),
                    mailbox: Some(false),
                },
            )
            .expect("policy updates");
        let policies = alice.list_peer_policies().expect("policies list");
        let debug = format!("{policy:?}\n{policies:?}");

        assert_eq!(policy.peer_node_id, bob_peer.peer_node_id);
        assert!(policy.messages);
        assert!(policy.streams);
        assert!(!policy.rooms);
        assert_eq!(policies.len(), 1);
        assert!(!debug.contains("private message contents"));
        assert!(!debug.contains("Review this code"));
    }

    #[test]
    fn sdk_debug_metadata_does_not_expose_payload_contents() {
        let client = ConuClient::with_home(test_home("debug"));
        client.init().expect("state initializes");
        client
            .register_agent("agent.sender", "Sender", "test-agent")
            .expect("sender registers");
        client
            .register_agent("agent.receiver", "Receiver", "test-agent")
            .expect("receiver registers");
        let process = client.process_queued().expect("registrations process");
        let sent = client
            .send_message_bytes(
                "agent.sender",
                "agent.receiver",
                b"private message contents",
            )
            .expect("message queues");
        let debug = format!("{process:?}\n{sent:?}");

        assert!(!debug.contains("private message contents"));
        assert!(!debug.contains("Review this code"));
    }

    fn test_home(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        env::temp_dir().join(format!("conu-sdk-test-{label}-{}-{nonce}", process::id()))
    }
}
