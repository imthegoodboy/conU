//! Shared protocol types for conU runtimes and agent gateways.
//!
//! The protocol crate intentionally treats payload bytes as opaque. Routing code may
//! know who an envelope is for and how large it is, but not what it means.

use std::fmt;

/// Current protocol version used by scaffolded conU envelopes.
pub const PROTOCOL_VERSION: &str = "conu/1";

/// Errors produced while building strongly typed protocol values.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// A required identifier was empty or whitespace-only.
    EmptyIdentifier { field: &'static str },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier { field } => write!(formatter, "{field} cannot be empty"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Stable identity of a conUD runtime node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(String);

impl NodeId {
    /// Create a node id after minimal structural validation.
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        non_empty(value.into(), "node id").map(Self)
    }

    /// Borrow the id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable identity of an agent registered with a local conUD runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(String);

impl AgentId {
    /// Create an agent id after minimal structural validation.
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        non_empty(value.into(), "agent id").map(Self)
    }

    /// Borrow the id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Capabilities a registered agent is willing to expose through conU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCapabilities {
    pub messages: bool,
    pub streams: bool,
    pub rooms: bool,
    pub files: bool,
    pub presence: bool,
}

impl AgentCapabilities {
    /// Baseline capability set for an agent that can message and publish presence.
    pub const fn basic() -> Self {
        Self {
            messages: true,
            streams: false,
            rooms: false,
            files: false,
            presence: true,
        }
    }
}

/// Public discovery document for an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCard {
    pub agent_id: AgentId,
    pub display_name: String,
    pub node_id: NodeId,
    pub capabilities: AgentCapabilities,
    pub public_key: Option<String>,
}

impl AgentCard {
    /// Build a minimal agent card.
    pub fn new(
        agent_id: AgentId,
        display_name: impl Into<String>,
        node_id: NodeId,
        capabilities: AgentCapabilities,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            agent_id,
            display_name: non_empty(display_name.into(), "display name")?,
            node_id,
            capabilities,
            public_key: None,
        })
    }
}

/// A high-level envelope kind. The encrypted payload semantics belong to agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    Message,
    StreamChunk,
    Event,
    Receipt,
}

/// Opaque payload bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaquePayload {
    bytes: Vec<u8>,
}

impl OpaquePayload {
    /// Store encrypted or otherwise opaque bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Return the number of opaque bytes without exposing their contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when the payload contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the bytes for lower-level transports.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OpaquePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePayload")
            .field("bytes", &self.bytes.len())
            .field("contents", &"<private>")
            .finish()
    }
}

/// Privacy marker for envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPrivacy {
    Opaque,
    EndToEndEncrypted,
}

/// Metadata conU may use for routing and transport visualization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeMeta {
    pub route_id: Option<String>,
    pub stream_id: Option<String>,
    pub privacy: PayloadPrivacy,
}

impl EnvelopeMeta {
    /// Metadata for a private one-shot envelope.
    pub const fn private() -> Self {
        Self {
            route_id: None,
            stream_id: None,
            privacy: PayloadPrivacy::Opaque,
        }
    }
}

/// Opaque data-plane envelope routed by conUD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: String,
    pub id: String,
    pub from: AgentId,
    pub to: AgentId,
    pub kind: EnvelopeKind,
    pub meta: EnvelopeMeta,
    pub payload: OpaquePayload,
}

impl Envelope {
    /// Build a data-plane envelope.
    pub fn new(
        id: impl Into<String>,
        from: AgentId,
        to: AgentId,
        kind: EnvelopeKind,
        payload: OpaquePayload,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            version: PROTOCOL_VERSION.to_string(),
            id: non_empty(id.into(), "envelope id")?,
            from,
            to,
            kind,
            meta: EnvelopeMeta::private(),
            payload,
        })
    }
}

fn non_empty(value: String, field: &'static str) -> Result<String, ProtocolError> {
    if value.trim().is_empty() {
        Err(ProtocolError::EmptyIdentifier { field })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_agent_ids() {
        let error = AgentId::new("  ").expect_err("empty agent id should fail");
        assert_eq!(error, ProtocolError::EmptyIdentifier { field: "agent id" });
    }

    #[test]
    fn opaque_payload_debug_does_not_expose_bytes() {
        let payload = OpaquePayload::from_bytes(b"private message contents".to_vec());
        let debug = format!("{payload:?}");

        assert!(debug.contains("<private>"));
        assert!(!debug.contains("private message contents"));
    }

    #[test]
    fn envelope_uses_current_protocol_version() {
        let envelope = Envelope::new(
            "env_test",
            AgentId::new("agent_a").expect("valid sender"),
            AgentId::new("agent_b").expect("valid receiver"),
            EnvelopeKind::Message,
            OpaquePayload::from_bytes([1, 2, 3]),
        )
        .expect("valid envelope");

        assert_eq!(envelope.version, PROTOCOL_VERSION);
        assert_eq!(envelope.payload.len(), 3);
    }
}
