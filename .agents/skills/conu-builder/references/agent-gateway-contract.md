# Agent Gateway Contract

The Agent Gateway is how agents use conU without learning networking.

Agents should receive simple capabilities:

```txt
register(agent_card)
peers(filter)
connect(peer_id)
send(to, opaque_payload)
open_stream(to, kind)
write_stream(stream_id, bytes)
subscribe(target, topic)
publish(topic, event)
receive()
set_presence(status)
```

## Agent View

Agents should feel:

```txt
I can discover trusted peers.
I can message trusted peers.
I can stream to trusted peers.
I can subscribe to allowed streams.
I do not need to understand networking.
```

## Runtime View

conUD handles:

- identity
- trust
- permissions
- pairing
- route selection
- encryption
- reconnects
- retries
- backpressure
- delivery receipts
- relay fallback

## Implemented Surface

The Phase 5 local agent gateway is a file-backed, metadata-only IPC path:

```txt
runtime/ipc/inbox       submitted requests
runtime/ipc/processed   accepted requests
runtime/ipc/rejected    rejected requests and safe reasons
agents/registry.toml    persisted local agent cards
logs/agents.log         metadata-only agent events
```

Supported commands:

```txt
conu agents register <agent-id> <display-name> [--kind <kind>] [--json]
conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]
conu agents [--json]
conud --process-ipc
```

Supported request types:

```txt
register_agent
presence_heartbeat
```

The Phase 6 local message gateway is a separate file-backed queue and local inbox path:

```txt
runtime/ipc/messages/inbox       submitted local message requests
runtime/ipc/messages/processed   metadata-only processed markers
runtime/ipc/messages/rejected    safe rejection reasons
messages/inbox/<agent-id>        delivered opaque local envelopes
messages/receipts                metadata-only delivery receipts
logs/messages.log                metadata-only delivery events
```

Supported commands:

```txt
conu messages send <from-agent> <to-agent> --stdin [--json]
conu messages inbox <agent-id> [--json]
conu messages receipts [--json]
```

Supported request type:

```txt
send_message
```

Phase 6 intentionally does not expose remote relay delivery, discovery, streams, rooms, or pub/sub. Those start in later phases.

The Phase 7 trust surface is local pairing groundwork:

```txt
pairing/invites       pending local pairing invitations
pairing/used          consumed local pairing invitations
trust.toml            trusted and revoked peer records
```

Supported commands:

```txt
conu pair [--json]
conu join <code> [--json]
conu peers [--json]
conu peers revoke <peer-node-id> [--json]
```

Phase 7 creates trust records but does not discover remote agents or open network sessions. Raw used pairing codes must not appear in peer list output or trust records.

The Phase 8 relay surface is a standalone WebSocket service for runtime sessions:

```txt
conu_core::relay      shared HELLO/FORWARD/PING frame contract
crates/conu-relay     WebSocket listener and metadata-only forwarding hub
CONU_RELAY_TOKEN      shared relay session token for local/dev deployment
```

Supported relay command:

```txt
conu-relay --serve [addr]
```

Supported runtime-to-relay frames:

```txt
HELLO node=<node-id> token=<token> payload=not_observed
FORWARD to=<node-id> envelope=<envelope-id> bytes=<count> payload=opaque
FORWARD to=<node-id> envelope=<envelope-id> from_agent=<agent-id> to_agent=<agent-id> bytes=<count> cipher=<cipher> key=<key-id> sender_key=<public-key> nonce=<nonce> body=<ciphertext> payload=peer_encrypted
PING payload=not_observed
```

Supported relay-to-runtime frames:

```txt
WELCOME session=<session-id> payload=not_observed
ENVELOPE from=<node-id> to=<node-id> envelope=<envelope-id> bytes=<count> payload=opaque
ENVELOPE from=<node-id> to=<node-id> envelope=<envelope-id> from_agent=<agent-id> to_agent=<agent-id> bytes=<count> cipher=<cipher> key=<key-id> sender_key=<public-key> nonce=<nonce> body=<ciphertext> payload=peer_encrypted
SENT to=<node-id> envelope=<envelope-id> bytes=<count> payload=not_observed
UNDELIVERED to=<node-id> envelope=<envelope-id> reason=<safe-reason> payload=not_observed
PONG payload=not_observed
ERROR reason=<safe-reason> payload=not_observed
```

The current relay data-plane exposes peer-encrypted one-shot messages through `conu messages send --peer`. Running conUD automatically pumps configured relay send/receive windows; `conu relay sync` remains an explicit manual/debug command. Live stream byte routing, persistent relay sessions, hosted relay auth hardening, and offline mailbox delivery land later.

The Phase 9 remote session surface is conUD-owned metadata sync:

```txt
sessions/registry.toml   remote runtime session metadata
agents/remote.toml       mirrored trusted remote agent cards
logs/sessions.log        metadata-only sync log
```

Supported commands:

```txt
conu sessions [--json]
conu sessions sync [--json]
conu agents [--json]
conud --process-ipc
```

`conu sessions sync` reads trusted peers and mirrors route/session metadata so `conu agents` can show visible remote agents. It does not transfer private payloads and does not yet create an interactive live stream. Revoked peers must disappear from the active remote-agent mirror after sync.

The Phase 13 route surface lets agents and users inspect conUD-owned route selection:

```txt
routes/registry.toml   direct/relay candidate and selected route metadata
routes/probes.toml     metadata-only route probe history
logs/routes.log        payload-safe route summaries
```

Supported commands:

```txt
conu routes [--json]
conu routes sync [--json]
conu routes probes [--json]
```

`conu routes sync` scores configured direct QUIC candidates against relay WebSocket fallback. It may show route ids, peer ids, transport labels, endpoints, scores, latency estimates, NAT profile labels, and fallback state. It must never show message text, prompt text, reasoning, file contents, private keys, shared secrets, tokens, or payload bytes.

The Phase 10 stream/watch surface is metadata-only stream lifecycle:

```txt
streams/registry.toml   stream lifecycle metadata
streams/events.toml     private watch event bus
logs/streams.log        metadata-only stream events
```

Supported commands:

```txt
conu streams [--json]
conu streams open <from-agent> <to-agent> [--kind <kind>] [--json]
conu streams write <stream-id> --stdin [--json]
conu streams close <stream-id> [--json]
conu watch
```

`conu streams write` accepts opaque bytes from stdin and records only byte counts. `conu watch` renders transport flow, route, stream id, packet count, and bytes without rendering message or chunk contents.

The Phase 11 security surface hardens local payload storage and identity metadata:

```txt
security/identity-signing.key   local Ed25519 signing key
security/identity-exchange.key  local X25519 exchange key
security/storage.key            local XChaCha20Poly1305 storage key
security/replay.toml            replay/idempotency cache
security/key-rotation.md        local rotation plan
```

Supported command:

```txt
conu security audit [--json]
```

New local message request and inbox files store encrypted-at-rest payload fields instead of `payload_hex`. New or updated local agent cards are signed in `agents/registry.toml`. `conu security audit` may report readiness and key ids, but it must not display private keys, shared secrets, plaintext payloads, or decrypted payloads.

The Phase 12 SDK/MCP surface is the preferred agent integration path:

```txt
crates/conu-sdk          Rust SDK for typed local conU calls
crates/conu-mcp          MCP stdio adapter for agent tool use
sdk/python/conu_sdk      Python wrapper around conu/conud binaries
```

Rust SDK calls:

```txt
ConuClient::register_agent()
ConuClient::set_presence()
ConuClient::list_agents()
ConuClient::list_peers()
ConuClient::sync_routes()
ConuClient::list_routes()
ConuClient::list_route_probes()
ConuClient::send_message_bytes()
ConuClient::inbox_metadata()
ConuClient::receive_message_bytes()
ConuClient::open_stream()
ConuClient::write_stream_bytes()
ConuClient::close_stream()
ConuClient::security_audit()
```

MCP tools:

```txt
conu_status
conu_security_audit
conu_register_agent
conu_set_presence
conu_process_queued
conu_sync_routes
conu_list_routes
conu_list_agents
conu_list_peers
conu_send_message
conu_receive_message
conu_open_stream
conu_write_stream
conu_close_stream
```

SDK/MCP receive is explicit. Normal list, send, receipt, status, and stream outputs remain metadata-only. Payload bytes may be returned only through `ConuClient::receive_message_bytes()` or `conu_receive_message` with `includePayload: true`, and only for an envelope present in the addressed local agent inbox.

When launching `conu-mcp` for one agent, set `CONU_AGENT_ID`. A bound MCP server must reject register, presence, send, receive, stream-open, stream-write, and stream-close attempts for a different local agent.

## Safety

"Full access" means full communication access inside trust boundaries. It does not mean raw filesystem, shell, network, or secret access.
