//! WebSocket relay MVP for conU.
//!
//! Phase 8 implements a small std-only WebSocket relay that authenticates
//! runtime sessions and forwards opaque envelope metadata between connected
//! nodes. It deliberately has no API for plaintext payload contents.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use conu_core::relay::{
    RelayClientFrame, RelayServerFrame, parse_client_frame, render_server_frame,
};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER_BYTES: usize = 8192;
const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Configuration for the relay server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub bind_addr: String,
    pub auth_token: String,
}

impl RelayConfig {
    pub fn new(
        bind_addr: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, RelayError> {
        let bind_addr = bind_addr.into();
        let auth_token = auth_token.into();

        if bind_addr.trim().is_empty() {
            return Err(RelayError::InvalidConfig("bind address cannot be empty"));
        }
        if auth_token.trim().is_empty() || auth_token.chars().any(char::is_whitespace) {
            return Err(RelayError::InvalidConfig(
                "relay auth token must be non-empty and contain no whitespace",
            ));
        }

        Ok(Self {
            bind_addr,
            auth_token,
        })
    }
}

/// Running relay handle used by tests and local smoke checks.
pub struct RelayHandle {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl RelayHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Errors produced by the relay server.
#[derive(Debug)]
pub enum RelayError {
    InvalidConfig(&'static str),
    Io {
        action: &'static str,
        source: io::Error,
    },
    Protocol(String),
}

impl RelayError {
    fn io(action: &'static str, source: io::Error) -> Self {
        Self::Io { action, source }
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid relay config: {reason}"),
            Self::Io { action, source } => write!(formatter, "{action}: {source}"),
            Self::Protocol(reason) => write!(formatter, "relay protocol error: {reason}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Run a relay server until the process exits.
pub fn run_blocking(config: RelayConfig) -> Result<(), RelayError> {
    let listener = TcpListener::bind(&config.bind_addr)
        .map_err(|error| RelayError::io("bind relay listener", error))?;
    let hub = Arc::new(RelayHub::new(config.auth_token));

    println!(
        "conU relay listening on {}; payloads not observed",
        listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| config.bind_addr)
    );

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let hub = hub.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, hub);
                });
            }
            Err(error) => return Err(RelayError::io("accept relay connection", error)),
        }
    }

    Ok(())
}

/// Spawn a relay server in the background for tests and local validation.
pub fn spawn_relay(config: RelayConfig) -> Result<RelayHandle, RelayError> {
    let listener = TcpListener::bind(&config.bind_addr)
        .map_err(|error| RelayError::io("bind relay listener", error))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| RelayError::io("configure relay listener", error))?;
    let local_addr = listener
        .local_addr()
        .map_err(|error| RelayError::io("read relay listener address", error))?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let hub = Arc::new(RelayHub::new(config.auth_token));

    let join = thread::spawn(move || {
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let hub = hub.clone();
                    thread::spawn(move || {
                        #[cfg(not(test))]
                        let _ = handle_connection(stream, hub);

                        #[cfg(test)]
                        if let Err(error) = handle_connection(stream, hub) {
                            eprintln!("relay test connection ended: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });

    Ok(RelayHandle {
        local_addr,
        stop,
        join: Some(join),
    })
}

/// Compute the RFC 6455 Sec-WebSocket-Accept value.
pub fn websocket_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WEBSOCKET_GUID.len());
    input.push_str(client_key.trim());
    input.push_str(WEBSOCKET_GUID);
    base64_encode(&sha1(input.as_bytes()))
}

#[derive(Debug)]
struct RelayHub {
    auth_token: String,
    clients: Mutex<HashMap<String, Arc<Mutex<TcpStream>>>>,
}

impl RelayHub {
    fn new(auth_token: String) -> Self {
        Self {
            auth_token,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn add_client(&self, node_id: String, stream: TcpStream) -> Result<(), RelayError> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| RelayError::Protocol("relay client map lock failed".to_string()))?;
        clients.insert(node_id, Arc::new(Mutex::new(stream)));
        Ok(())
    }

    fn remove_client(&self, node_id: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(node_id);
        }
    }

    fn target(&self, node_id: &str) -> Option<Arc<Mutex<TcpStream>>> {
        self.clients
            .lock()
            .ok()
            .and_then(|clients| clients.get(node_id).cloned())
    }
}

fn handle_connection(mut stream: TcpStream, hub: Arc<RelayHub>) -> Result<(), RelayError> {
    stream
        .set_nonblocking(false)
        .map_err(|error| RelayError::io("configure relay connection mode", error))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| RelayError::io("configure relay connection", error))?;
    perform_websocket_handshake(&mut stream)?;

    let mut session_node = None::<String>;

    while let Some(text) = read_text_frame(&mut stream)? {
        match parse_client_frame(&text) {
            Ok(RelayClientFrame::Hello(hello)) => {
                if hello.auth_token != hub.auth_token {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "unauthorized".to_string(),
                        }),
                    )?;
                    break;
                }
                let session_id = session_id(&hello.node_id);
                hub.add_client(
                    hello.node_id.clone(),
                    stream
                        .try_clone()
                        .map_err(|error| RelayError::io("clone relay stream", error))?,
                )?;
                session_node = Some(hello.node_id);
                write_text_frame(
                    &mut stream,
                    &render_server_frame(&RelayServerFrame::Welcome { session_id }),
                )?;
            }
            Ok(RelayClientFrame::Forward(forward)) => {
                let Some(from_node_id) = session_node.clone() else {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Error {
                            reason: "hello_required".to_string(),
                        }),
                    )?;
                    continue;
                };

                if let Some(target) = hub.target(&forward.to_node_id) {
                    let target_frame = render_server_frame(&RelayServerFrame::Forwarded {
                        from_node_id,
                        to_node_id: forward.to_node_id.clone(),
                        envelope_id: forward.envelope_id.clone(),
                        payload_bytes: forward.payload_bytes,
                        from_agent_id: forward.from_agent_id.clone(),
                        to_agent_id: forward.to_agent_id.clone(),
                        body: forward.body.clone(),
                    });
                    let mut target = target.lock().map_err(|_| {
                        RelayError::Protocol("relay target lock failed".to_string())
                    })?;
                    write_text_frame(&mut target, &target_frame)?;
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Sent {
                            to_node_id: forward.to_node_id,
                            envelope_id: forward.envelope_id,
                            payload_bytes: forward.payload_bytes,
                        }),
                    )?;
                } else {
                    write_text_frame(
                        &mut stream,
                        &render_server_frame(&RelayServerFrame::Undelivered {
                            to_node_id: forward.to_node_id,
                            envelope_id: forward.envelope_id,
                            reason: "peer_offline".to_string(),
                        }),
                    )?;
                }
            }
            Ok(RelayClientFrame::Ping) => {
                write_text_frame(&mut stream, &render_server_frame(&RelayServerFrame::Pong))?;
            }
            Err(error) => {
                write_text_frame(
                    &mut stream,
                    &render_server_frame(&RelayServerFrame::Error {
                        reason: error.to_string(),
                    }),
                )?;
            }
        }
    }

    if let Some(node_id) = session_node {
        hub.remove_client(&node_id);
    }
    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
}

fn perform_websocket_handshake(stream: &mut TcpStream) -> Result<(), RelayError> {
    let request = read_http_request(stream)?;
    let key = header_value(&request, "sec-websocket-key")
        .ok_or_else(|| RelayError::Protocol("missing Sec-WebSocket-Key header".to_string()))?;
    let accept = websocket_accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| RelayError::io("write websocket handshake", error))
}

fn read_http_request(stream: &mut TcpStream) -> Result<String, RelayError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1];

    while bytes.len() < MAX_HTTP_HEADER_BYTES {
        stream
            .read_exact(&mut buffer)
            .map_err(|error| RelayError::io("read websocket handshake", error))?;
        bytes.push(buffer[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| RelayError::Protocol("handshake is not UTF-8".to_string()));
        }
    }

    Err(RelayError::Protocol(
        "websocket handshake headers are too large".to_string(),
    ))
}

fn header_value(request: &str, header: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(header) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn read_text_frame(stream: &mut TcpStream) -> Result<Option<String>, RelayError> {
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
        Err(error) => return Err(RelayError::io("read websocket frame", error)),
    }

    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = u64::from(header[1] & 0x7f);

    if len == 126 {
        let mut bytes = [0_u8; 2];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayError::io("read websocket frame length", error))?;
        len = u64::from(u16::from_be_bytes(bytes));
    } else if len == 127 {
        let mut bytes = [0_u8; 8];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| RelayError::io("read websocket frame length", error))?;
        len = u64::from_be_bytes(bytes);
    }

    if len as usize > MAX_FRAME_BYTES {
        return Err(RelayError::Protocol(
            "websocket frame is too large".to_string(),
        ));
    }

    let mut mask = [0_u8; 4];
    if masked {
        stream
            .read_exact(&mut mask)
            .map_err(|error| RelayError::io("read websocket frame mask", error))?;
    }

    let mut payload = vec![0_u8; len as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|error| RelayError::io("read websocket frame payload", error))?;

    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }

    match opcode {
        0x1 => String::from_utf8(payload)
            .map(Some)
            .map_err(|_| RelayError::Protocol("text frame is not UTF-8".to_string())),
        0x8 => Ok(None),
        0x9 => {
            write_raw_frame(stream, 0xA, &payload)?;
            Ok(Some("PING payload=not_observed".to_string()))
        }
        _ => Err(RelayError::Protocol(
            "unsupported websocket frame opcode".to_string(),
        )),
    }
}

fn write_text_frame(stream: &mut TcpStream, text: &str) -> Result<(), RelayError> {
    write_raw_frame(stream, 0x1, text.as_bytes())
}

fn write_raw_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> Result<(), RelayError> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);

    if payload.len() <= 125 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    frame.extend_from_slice(payload);
    stream
        .write_all(&frame)
        .map_err(|error| RelayError::io("write websocket frame", error))
}

fn session_id(node_id: &str) -> String {
    format!(
        "relay_{}_{}",
        sanitize_identifier(node_id),
        current_unix_nanos()
    )
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect()
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
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

#[cfg(test)]
mod tests {
    use super::*;
    use conu_core::agents::{self, AgentRegistration};
    use conu_core::messages;
    use conu_core::relay::{RelayForward, RelayHello, render_client_frame};
    use conu_core::relay_delivery::{self, RemoteMessage};
    use conu_core::{state, trust};
    use conu_protocol::OpaquePayload;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process;

    #[test]
    fn websocket_accept_key_matches_rfc_example() {
        let accept = websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ==");

        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn relay_forwards_metadata_between_two_runtime_sessions() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "test-token").expect("valid config"))
                .expect("relay starts");
        let mut node_a = connect_client(relay.local_addr());
        let mut node_b = connect_client(relay.local_addr());

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.a", "test-token").expect("hello"),
            )),
        );
        write_client_text(
            &mut node_b,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.b", "test-token").expect("hello"),
            )),
        );
        assert!(read_server_text(&mut node_a).contains("WELCOME"));
        assert!(read_server_text(&mut node_b).contains("WELCOME"));

        write_client_text(
            &mut node_a,
            &render_client_frame(&RelayClientFrame::Forward(
                RelayForward::new("node.b", "env.1", 42).expect("forward"),
            )),
        );
        let delivered = read_server_text(&mut node_b);
        let sent = read_server_text(&mut node_a);

        assert!(delivered.contains("ENVELOPE from=node.a to=node.b envelope=env.1 bytes=42"));
        assert!(delivered.contains("payload=opaque"));
        assert!(sent.contains("SENT to=node.b envelope=env.1 bytes=42"));
        assert!(!delivered.contains("private message contents"));
        assert!(!sent.contains("private message contents"));
    }

    #[test]
    fn relay_rejects_bad_token_without_echoing_token() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "test-token").expect("valid config"))
                .expect("relay starts");
        let mut client = connect_client(relay.local_addr());

        write_client_text(
            &mut client,
            &render_client_frame(&RelayClientFrame::Hello(
                RelayHello::new("node.bad", "secret-bad-token").expect("hello"),
            )),
        );
        let response = read_server_text(&mut client);

        assert!(response.contains("ERROR reason=unauthorized"));
        assert!(!response.contains("secret-bad-token"));
    }

    #[test]
    fn relay_delivers_peer_encrypted_message_between_two_state_homes() {
        let relay =
            spawn_relay(RelayConfig::new("127.0.0.1:0", "local-dev-token").expect("valid config"))
                .expect("relay starts");
        let endpoint = format!("ws://{}", relay.local_addr());
        let alice_home = test_home("alice");
        let bob_home = test_home("bob");
        prepare_home(&alice_home, &endpoint);
        prepare_home(&bob_home, &endpoint);
        trust_each_other(&alice_home, &bob_home);
        register_agent(&alice_home, "agent.alice");
        register_agent(&bob_home, "agent.bob");
        let bob_node = node_id(&bob_home);
        let remote = RemoteMessage::new(
            "agent.alice",
            "agent.bob",
            bob_node,
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("remote message valid");
        relay_delivery::submit_remote_message(Some(alice_home.clone()), remote)
            .expect("remote message queues");

        let bob_home_for_thread = bob_home.clone();
        let bob_sync = thread::spawn(move || {
            relay_delivery::sync_relay_once(Some(bob_home_for_thread), Duration::from_millis(2_000))
                .expect("bob relay sync")
        });
        thread::sleep(Duration::from_millis(100));
        let alice_report =
            relay_delivery::sync_relay_once(Some(alice_home), Duration::from_millis(1_000))
                .expect("alice relay sync");
        let bob_report = bob_sync.join().expect("bob thread joins");
        let inbox = messages::list_agent_inbox(Some(bob_home.clone()), "agent.bob")
            .expect("bob inbox reads");
        let received =
            messages::read_message_payload(Some(bob_home), "agent.bob", &inbox[0].envelope_id)
                .expect("bob payload reads");

        assert_eq!(alice_report.sent, 1);
        assert_eq!(bob_report.received, 1);
        assert_eq!(inbox.len(), 1);
        assert_eq!(received.as_bytes(), b"private message contents");
    }

    fn connect_client(addr: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(addr).expect("client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout set");
        let request = "GET /relay HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("handshake writes");
        let mut response = Vec::new();
        let mut buf = [0_u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut buf).expect("handshake reads");
            response.push(buf[0]);
        }
        let response = String::from_utf8(response).expect("handshake utf8");
        assert!(response.contains("101 Switching Protocols"));
        stream
    }

    fn write_client_text(stream: &mut TcpStream, text: &str) {
        let mask = [1_u8, 2, 3, 4];
        let payload = text.as_bytes();
        let mut frame = Vec::new();
        frame.push(0x81);
        if payload.len() <= 125 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        stream.write_all(&frame).expect("client frame writes");
    }

    fn read_server_text(stream: &mut TcpStream) -> String {
        read_text_frame(stream)
            .expect("server frame reads")
            .expect("server frame exists")
    }

    fn prepare_home(home: &Path, endpoint: &str) {
        state::init_state(Some(home.to_path_buf())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.to_path_buf());
        fs::write(
            paths.config,
            format!("version = \"1\"\ndefault_relay = \"{endpoint}\"\n"),
        )
        .expect("config writes");
    }

    fn trust_each_other(alice_home: &Path, bob_home: &Path) {
        let alice = trust::export_peer_card(Some(alice_home.to_path_buf())).expect("alice card");
        let bob = trust::export_peer_card(Some(bob_home.to_path_buf())).expect("bob card");
        trust::trust_peer_card(Some(alice_home.to_path_buf()), bob).expect("alice trusts bob");
        trust::trust_peer_card(Some(bob_home.to_path_buf()), alice).expect("bob trusts alice");
    }

    fn register_agent(home: &Path, agent_id: &str) {
        let registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid agent");
        agents::submit_registration(Some(home.to_path_buf()), registration)
            .expect("registration submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("registration processes");
    }

    fn node_id(home: &Path) -> String {
        state::read_state(Some(home.to_path_buf()))
            .expect("state reads")
            .node
            .expect("node exists")
            .node_id
    }

    fn test_home(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "conu-relay-e2e-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
