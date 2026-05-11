//! Relay frame contract shared by runtimes and the relay service.
//!
//! The relay can carry peer-encrypted envelope bodies, but it must never expose
//! plaintext payload fields. Frame rendering keeps ciphertext in a dedicated
//! opaque body field and all user-facing surfaces should summarize only
//! metadata.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_BYTES: usize = 8192;
const MAX_FRAME_BYTES: usize = 256 * 1024;

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

    fn io(action: &'static str, source: io::Error) -> Self {
        Self::new(format!("{action}: {source}"))
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
#[derive(Clone, PartialEq, Eq)]
pub struct RelayForward {
    pub to_node_id: String,
    pub envelope_id: String,
    pub payload_bytes: usize,
    pub from_agent_id: Option<String>,
    pub to_agent_id: Option<String>,
    pub body: Option<RelayOpaqueBody>,
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
            from_agent_id: None,
            to_agent_id: None,
            body: None,
        })
    }

    pub fn with_body(
        to_node_id: impl Into<String>,
        envelope_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        to_agent_id: impl Into<String>,
        payload_bytes: usize,
        body: RelayOpaqueBody,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            to_node_id: validate_identifier(to_node_id.into(), "to node id")?,
            envelope_id: validate_identifier(envelope_id.into(), "envelope id")?,
            from_agent_id: Some(validate_identifier(from_agent_id.into(), "from agent id")?),
            to_agent_id: Some(validate_identifier(to_agent_id.into(), "to agent id")?),
            payload_bytes,
            body: Some(body),
        })
    }
}

impl fmt::Debug for RelayForward {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayForward")
            .field("to_node_id", &self.to_node_id)
            .field("envelope_id", &self.envelope_id)
            .field("payload_bytes", &self.payload_bytes)
            .field("from_agent_id", &self.from_agent_id)
            .field("to_agent_id", &self.to_agent_id)
            .field("body", &self.body)
            .finish()
    }
}

/// Peer-encrypted body material carried by the blind relay.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayOpaqueBody {
    pub algorithm: String,
    pub key_id: String,
    pub sender_exchange_public_key_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl RelayOpaqueBody {
    pub fn new(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        sender_exchange_public_key_hex: impl Into<String>,
        nonce_hex: impl Into<String>,
        ciphertext_hex: impl Into<String>,
    ) -> Result<Self, RelayFrameError> {
        Ok(Self {
            algorithm: validate_algorithm(algorithm.into())?,
            key_id: validate_identifier(key_id.into(), "key id")?,
            sender_exchange_public_key_hex: validate_hex(
                sender_exchange_public_key_hex.into(),
                "sender exchange public key",
            )?,
            nonce_hex: validate_hex(nonce_hex.into(), "nonce")?,
            ciphertext_hex: validate_hex(ciphertext_hex.into(), "body")?,
        })
    }
}

impl fmt::Debug for RelayOpaqueBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayOpaqueBody")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("sender_exchange_public_key_hex", &"<public-key>")
            .field("nonce_hex", &"<nonce>")
            .field("ciphertext_len", &self.ciphertext_hex.len())
            .field("ciphertext", &"<encrypted>")
            .finish()
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
        from_agent_id: Option<String>,
        to_agent_id: Option<String>,
        body: Option<RelayOpaqueBody>,
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
        RelayClientFrame::Forward(forward) => render_forward_line("FORWARD", None, forward),
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
        "FORWARD" => Ok(RelayClientFrame::Forward(
            RelayForward::new(
                required(&values, "to")?,
                required(&values, "envelope")?,
                parse_usize(&required(&values, "bytes")?)?,
            )?
            .with_optional_body(&values)?,
        )),
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
            from_agent_id,
            to_agent_id,
            body,
        } => render_forwarded_line(
            from_node_id,
            to_node_id,
            envelope_id,
            *payload_bytes,
            from_agent_id.as_deref(),
            to_agent_id.as_deref(),
            body.as_ref(),
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

/// Parse a relay server frame line received by a runtime.
pub fn parse_server_frame(line: &str) -> Result<RelayServerFrame, RelayFrameError> {
    let (kind, values) = parse_frame_values(line)?;
    if values.contains_key("payload_hex") || values.contains_key("payload_text") {
        return Err(RelayFrameError::new(
            "relay frame must not include plaintext payload fields",
        ));
    }

    match kind {
        "WELCOME" => Ok(RelayServerFrame::Welcome {
            session_id: required(&values, "session")?,
        }),
        "ENVELOPE" => {
            let body = optional_body(&values)?;
            Ok(RelayServerFrame::Forwarded {
                from_node_id: validate_identifier(required(&values, "from")?, "from node id")?,
                to_node_id: validate_identifier(required(&values, "to")?, "to node id")?,
                envelope_id: validate_identifier(required(&values, "envelope")?, "envelope id")?,
                payload_bytes: parse_usize(&required(&values, "bytes")?)?,
                from_agent_id: optional_identifier(&values, "from_agent", "from agent id")?,
                to_agent_id: optional_identifier(&values, "to_agent", "to agent id")?,
                body,
            })
        }
        "SENT" => Ok(RelayServerFrame::Sent {
            to_node_id: validate_identifier(required(&values, "to")?, "to node id")?,
            envelope_id: validate_identifier(required(&values, "envelope")?, "envelope id")?,
            payload_bytes: parse_usize(&required(&values, "bytes")?)?,
        }),
        "UNDELIVERED" => Ok(RelayServerFrame::Undelivered {
            to_node_id: validate_identifier(required(&values, "to")?, "to node id")?,
            envelope_id: validate_identifier(required(&values, "envelope")?, "envelope id")?,
            reason: required(&values, "reason")?,
        }),
        "PONG" => Ok(RelayServerFrame::Pong),
        "ERROR" => Ok(RelayServerFrame::Error {
            reason: required(&values, "reason")?,
        }),
        _ => Err(RelayFrameError::new("unsupported server frame type")),
    }
}

/// Minimal std-only WebSocket client for runtime-to-relay sync.
pub struct RelayWebSocketClient {
    stream: TcpStream,
}

impl RelayWebSocketClient {
    pub fn connect(endpoint: &str, timeout: Duration) -> Result<Self, RelayFrameError> {
        let parsed = ParsedEndpoint::parse(endpoint)?;
        let mut stream = TcpStream::connect((&parsed.host[..], parsed.port))
            .map_err(|error| RelayFrameError::io("connect relay endpoint", error))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| RelayFrameError::io("configure relay read timeout", error))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| RelayFrameError::io("configure relay write timeout", error))?;
        perform_client_handshake(&mut stream, &parsed)?;

        Ok(Self { stream })
    }

    pub fn send(&mut self, frame: &RelayClientFrame) -> Result<(), RelayFrameError> {
        write_client_text_frame(&mut self.stream, &render_client_frame(frame))
    }

    pub fn read(&mut self) -> Result<Option<RelayServerFrame>, RelayFrameError> {
        let Some(text) = read_server_text_frame(&mut self.stream)? else {
            return Ok(None);
        };
        parse_server_frame(&text).map(Some)
    }
}

impl RelayForward {
    fn with_optional_body(
        mut self,
        values: &HashMap<String, String>,
    ) -> Result<Self, RelayFrameError> {
        self.body = optional_body(values)?;
        if self.body.is_some() {
            self.from_agent_id = Some(validate_identifier(
                required(values, "from_agent")?,
                "from agent id",
            )?);
            self.to_agent_id = Some(validate_identifier(
                required(values, "to_agent")?,
                "to agent id",
            )?);
        }
        Ok(self)
    }
}

fn render_forward_line(kind: &str, from_node: Option<&str>, forward: &RelayForward) -> String {
    let mut line = match from_node {
        Some(from_node) => format!(
            "{kind} from={} to={} envelope={} bytes={}",
            from_node, forward.to_node_id, forward.envelope_id, forward.payload_bytes
        ),
        None => format!(
            "{kind} to={} envelope={} bytes={}",
            forward.to_node_id, forward.envelope_id, forward.payload_bytes
        ),
    };

    append_forward_body(
        &mut line,
        forward.from_agent_id.as_deref(),
        forward.to_agent_id.as_deref(),
        forward.body.as_ref(),
    );
    line
}

fn render_forwarded_line(
    from_node_id: &str,
    to_node_id: &str,
    envelope_id: &str,
    payload_bytes: usize,
    from_agent_id: Option<&str>,
    to_agent_id: Option<&str>,
    body: Option<&RelayOpaqueBody>,
) -> String {
    let mut line = format!(
        "ENVELOPE from={} to={} envelope={} bytes={}",
        from_node_id, to_node_id, envelope_id, payload_bytes
    );
    append_forward_body(&mut line, from_agent_id, to_agent_id, body);
    line
}

fn append_forward_body(
    line: &mut String,
    from_agent_id: Option<&str>,
    to_agent_id: Option<&str>,
    body: Option<&RelayOpaqueBody>,
) {
    if let Some(body) = body {
        line.push_str(&format!(
            " from_agent={} to_agent={} cipher={} key={} sender_key={} nonce={} body={} payload=peer_encrypted",
            from_agent_id.unwrap_or("unknown"),
            to_agent_id.unwrap_or("unknown"),
            body.algorithm,
            body.key_id,
            body.sender_exchange_public_key_hex,
            body.nonce_hex,
            body.ciphertext_hex
        ));
    } else {
        line.push_str(" payload=opaque");
    }
}

fn optional_body(
    values: &HashMap<String, String>,
) -> Result<Option<RelayOpaqueBody>, RelayFrameError> {
    if !values.contains_key("body") {
        return Ok(None);
    }

    Ok(Some(RelayOpaqueBody::new(
        required(values, "cipher")?,
        required(values, "key")?,
        required(values, "sender_key")?,
        required(values, "nonce")?,
        required(values, "body")?,
    )?))
}

fn optional_identifier(
    values: &HashMap<String, String>,
    key: &'static str,
    field: &'static str,
) -> Result<Option<String>, RelayFrameError> {
    values
        .get(key)
        .map(|value| validate_identifier(value.clone(), field))
        .transpose()
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

fn validate_algorithm(value: String) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new("cipher algorithm cannot be empty"));
    }
    if value.len() > 80 {
        return Err(RelayFrameError::new("cipher algorithm is too long"));
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '+' | '.')
    }) {
        return Err(RelayFrameError::new("cipher algorithm is invalid"));
    }
    Ok(value)
}

fn validate_hex(value: String, field: &'static str) -> Result<String, RelayFrameError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayFrameError::new(format!("{field} cannot be empty")));
    }
    if value.len() > MAX_FRAME_BYTES * 2 {
        return Err(RelayFrameError::new(format!("{field} is too large")));
    }
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RelayFrameError::new(format!("{field} must be hex")));
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEndpoint {
    host: String,
    port: u16,
    path: String,
}

impl ParsedEndpoint {
    fn parse(endpoint: &str) -> Result<Self, RelayFrameError> {
        if endpoint.starts_with("wss://") {
            return Err(RelayFrameError::new(
                "wss relay endpoints need a TLS terminator; this std client supports ws://",
            ));
        }
        let rest = endpoint
            .strip_prefix("ws://")
            .ok_or_else(|| RelayFrameError::new("relay endpoint must start with ws://"))?;
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/relay".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.trim().to_string(),
                port.parse::<u16>()
                    .map_err(|_| RelayFrameError::new("relay endpoint port is invalid"))?,
            ),
            None => (authority.trim().to_string(), 80),
        };

        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(RelayFrameError::new("relay endpoint host is invalid"));
        }
        if path.is_empty() || path.chars().any(char::is_whitespace) {
            return Err(RelayFrameError::new("relay endpoint path is invalid"));
        }

        Ok(Self { host, port, path })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn perform_client_handshake(
    stream: &mut TcpStream,
    endpoint: &ParsedEndpoint,
) -> Result<(), RelayFrameError> {
    let key = websocket_key();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        endpoint.path,
        endpoint.authority(),
        key
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| RelayFrameError::io("write websocket handshake", error))?;
    let response = read_http_response(stream)?;

    if !response.starts_with("HTTP/1.1 101") && !response.starts_with("HTTP/1.0 101") {
        return Err(RelayFrameError::new(
            "relay websocket upgrade was not accepted",
        ));
    }
    let accept = header_value(&response, "sec-websocket-accept")
        .ok_or_else(|| RelayFrameError::new("relay handshake missing accept header"))?;
    if accept != websocket_accept_key(&key) {
        return Err(RelayFrameError::new("relay websocket accept key mismatch"));
    }

    Ok(())
}

fn read_http_response(stream: &mut TcpStream) -> Result<String, RelayFrameError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1];

    while bytes.len() < MAX_HTTP_HEADER_BYTES {
        stream
            .read_exact(&mut buffer)
            .map_err(|error| RelayFrameError::io("read websocket handshake", error))?;
        bytes.push(buffer[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| RelayFrameError::new("websocket handshake is not UTF-8"));
        }
    }

    Err(RelayFrameError::new(
        "websocket handshake headers are too large",
    ))
}

fn header_value(response: &str, header: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(header) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn write_client_text_frame(stream: &mut TcpStream, text: &str) -> Result<(), RelayFrameError> {
    write_client_raw_frame(stream, 0x1, text.as_bytes())
}

fn write_client_raw_frame(
    stream: &mut TcpStream,
    opcode: u8,
    payload: &[u8],
) -> Result<(), RelayFrameError> {
    let mask = websocket_mask();
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);

    if payload.len() <= 125 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }

    stream
        .write_all(&frame)
        .map_err(|error| RelayFrameError::io("write websocket frame", error))
}

fn read_server_text_frame(stream: &mut TcpStream) -> Result<Option<String>, RelayFrameError> {
    let mut header = [0_u8; 2];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(RelayFrameError::io("read websocket frame", error)),
    }

    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = u64::from(header[1] & 0x7f);

    if len == 126 {
        let mut bytes = [0_u8; 2];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayFrameError::io("read websocket frame length", error))?;
        len = u64::from(u16::from_be_bytes(bytes));
    } else if len == 127 {
        let mut bytes = [0_u8; 8];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayFrameError::io("read websocket frame length", error))?;
        len = u64::from_be_bytes(bytes);
    }

    if len as usize > MAX_FRAME_BYTES {
        return Err(RelayFrameError::new("websocket frame is too large"));
    }

    let mut mask = [0_u8; 4];
    if masked {
        stream
            .read_exact(&mut mask)
            .map_err(|error| RelayFrameError::io("read websocket frame mask", error))?;
    }

    let mut payload = vec![0_u8; len as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|error| RelayFrameError::io("read websocket frame body", error))?;

    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    match opcode {
        0x1 => String::from_utf8(payload)
            .map(Some)
            .map_err(|_| RelayFrameError::new("text frame is not UTF-8")),
        0x8 => Ok(None),
        0x9 => {
            write_client_raw_frame(stream, 0xA, &payload)?;
            Ok(Some("PONG payload=not_observed".to_string()))
        }
        _ => Err(RelayFrameError::new(
            "unsupported websocket frame opcode from relay",
        )),
    }
}

fn websocket_key() -> String {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&process::id().to_be_bytes());
    bytes[4..12].copy_from_slice(&(current_unix_nanos() as u64).to_be_bytes());
    bytes[12..].copy_from_slice(&websocket_mask());
    base64_encode(&bytes)
}

fn websocket_mask() -> [u8; 4] {
    let now = current_unix_nanos();
    [
        (now & 0xff) as u8,
        ((now >> 8) & 0xff) as u8,
        ((now >> 16) & 0xff) as u8,
        ((now >> 24) & 0xff) as u8,
    ]
}

fn websocket_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key.trim());
    input.push_str(WEBSOCKET_GUID);
    base64_encode(&sha1(input.as_bytes()))
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;

        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }

    out
}

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;
    let bit_len = (bytes.len() as u64) * 8;
    let mut message = bytes.to_vec();

    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0_u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let offset = i * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0_u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
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
