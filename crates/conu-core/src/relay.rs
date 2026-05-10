//! Relay frame contract shared by runtimes and the relay service.
//!
//! Phase 8 keeps relay traffic metadata-only at this layer. Payload bytes are
//! represented by byte counts and envelope ids; the relay never receives a
//! plaintext payload field.

use std::collections::HashMap;
use std::fmt;

/// Error produced while parsing or rendering relay frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrameError {
    reason: String,
}

impl RelayFrameError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for RelayFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid relay frame: {}", self.reason)
    }
}

impl std::error::Error for RelayFrameError {}

/// Runtime-to-relay hello frame.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayHello {
    pub node_id: String,
    pub auth_token: String,
}

impl RelayHello {
    pub fn new(
        node_id: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            node_id: validate_identifier(node_id.into(), "node id")?,
            auth_token: validate_token(auth_token.into())?,
        })
    }
}

impl fmt::Debug for RelayHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayHello")
            .field("node_id", &self.node_id)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

/// Runtime-to-relay opaque forwarding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayForward {
    pub to_node_id: String,
    pub envelope_id: String,
    pub payload_bytes: usize,
}

impl RelayForward {
    pub fn new(
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        payload_bytes: usize,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            payload_bytes,
        })
    }
}

/// Client frames a runtime can send to the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayClientFrame {
    Hello(RelayHello),
    Forward(RelayForward),
    Ping,
}

/// Relay frames sent back to runtimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayServerFrame {
    Welcome {
        session_id: String,
    },
    Forwarded {
        from_node_id: String,
        to_node_id: String,
        envelope_id: String,
        payload_bytes: usize,
    },
    Sent {
        to_node_id: String,
        envelope_id: String,
        payload_bytes: usize,
    },
    Undelivered {
        to_node_id: String,
        envelope_id: String,
        reason: String,
    },
    Pong,
    Error {
        reason: String,
    },
}

/// Render a client frame as a compact metadata line.
pub fn render_client_frame(frame: &RelayClientFrame) -> String {
    match frame {
        RelayClientFrame::Hello(hello) => format!(
            "HELLO node={} token={} payload=not_observed",
            hello.node_id, hello.auth_token
        ),
        RelayClientFrame::Forward(forward) => format!(
            "FORWARD to={} envelope={} bytes={} payload=opaque",
            forward.to_node_id, forward.envelope_id, forward.payload_bytes
        ),
        RelayClientFrame::Ping => "PING payload=not_observed".to_string(),
    }
}

/// Parse a client frame line received by the relay.
pub fn parse_client_frame(line: &str) -> Result<RelayClientFrame, RelayFrameError> {
    let (kind, values) = parse_frame_values(line)?;
    if values.contains_key("payload_hex") || values.contains_key("payload_text") {
        return Err(RelayFrameError::new(
            "relay frame must not include plaintext payload fields",
        ));
    }

    match kind {
        "HELLO" => Ok(RelayClientFrame::Hello(RelayHello::new(
            required(&values, "node")?,
            required(&values, "token")?,
        )?)),
        "FORWARD" => Ok(RelayClientFrame::Forward(RelayForward::new(
            required(&values, "to")?,
            required(&values, "envelope")?,
            parse_usize(&required(&values, "bytes")?)?,
        )?)),
        "PING" => Ok(RelayClientFrame::Ping),
        _ => Err(RelayFrameError::new("unsupported client frame type")),
    }
}

/// Render a relay server frame.
pub fn render_server_frame(frame: &RelayServerFrame) -> String {
    match frame {
        RelayServerFrame::Welcome { session_id } => {
            format!("WELCOME session={} payload=not_observed", session_id)
        }
        RelayServerFrame::Forwarded {
            from_node_id,
            to_node_id,
            envelope_id,
            payload_bytes,
        } => format!(
            "ENVELOPE from={} to={} envelope={} bytes={} payload=opaque",
            from_node_id, to_node_id, envelope_id, payload_bytes
        ),
        RelayServerFrame::Sent {
            to_node_id,
            envelope_id,
            payload_bytes,
        } => format!(
            "SENT to={} envelope={} bytes={} payload=not_observed",
            to_node_id, envelope_id, payload_bytes
        ),
        RelayServerFrame::Undelivered {
            to_node_id,
            envelope_id,
            reason,
        } => format!(
            "UNDELIVERED to={} envelope={} reason={} payload=not_observed",
            to_node_id,
            envelope_id,
            sanitize_reason(reason)
        ),
        RelayServerFrame::Pong => "PONG payload=not_observed".to_string(),
        RelayServerFrame::Error { reason } => {
            format!(
                "ERROR reason={} payload=not_observed",
                sanitize_reason(reason)
            )
        }
    }
}

fn parse_frame_values(line: &str) -> Result<(&str, HashMap<String, String>), RelayFrameError> {
    let mut parts = line.split_whitespace();
    let kind = parts
        .next()
        .ok_or_else(|| RelayFrameError::new("missing frame type"))?;
    let mut values = HashMap::new();

    for part in parts {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok((kind, values))
}

fn required(
    values: &HashMap<String, String>,
    key: &'static str,
) -> Result<String, RelayFrameError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| RelayFrameError::new(format!("missing {key}")))
}

fn validate_identifier(value: String, field: &'static str) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new(format!("{field} cannot be empty")));
    }
    if value.len() > 120 {
        return Err(RelayFrameError::new(format!("{field} is too long")));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(RelayFrameError::new(format!(
            "{field} must use ASCII letters, numbers, dash, underscore, or dot"
        )));
    }
    Ok(value)
}

fn validate_token(value: String) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new("token cannot be empty"));
    }
    if value.len() > 200 {
        return Err(RelayFrameError::new("token is too long"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(RelayFrameError::new("token cannot contain whitespace"));
    }
    Ok(value)
}

fn parse_usize(value: &str) -> Result<usize, RelayFrameError> {
    value
        .parse::<usize>()
        .map_err(|_| RelayFrameError::new("expected unsigned byte count"))
}

fn sanitize_reason(reason: &str) -> String {
    let sanitized = reason
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_debug_redacts_token() {
        let hello = RelayHello::new("node.a", "secret-token").expect("valid hello");
        let debug = format!("{hello:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn forward_frame_is_metadata_only() {
        let frame = RelayClientFrame::Forward(
            RelayForward::new("node.b", "env.1", 42).expect("valid forward"),
        );
        let rendered = render_client_frame(&frame);
        let parsed = parse_client_frame(&rendered).expect("frame parses");

        assert!(rendered.contains("payload=opaque"));
        assert!(!rendered.contains("private message contents"));
        assert_eq!(parsed, frame);
    }

    #[test]
    fn rejects_plaintext_payload_fields() {
        let error = parse_client_frame("HELLO node=node.b token=test-token payload_text=secret")
            .expect_err("plaintext payload should fail");

        assert!(error.to_string().contains("must not include"));
        assert!(!error.to_string().contains("secret"));
    }
}
