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
conu agents register <agent-id> <display-name> [--kind <kind>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence <true|false>] [--json]
conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]
conu agents [--json]
conud --process-ipc
```

Supported request types:

```txt
register_agent
presence_heartbeat
```

Default registration grants messages and presence only. Agents must explicitly register `streams=true` for stream/connect calls and `rooms=true` for room create/join/publish/fanout.

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

Phase 6 intentionally does not expose remote relay delivery, discovery, streams, rooms, or pub/sub. Those start in later phases and are documented below as they become available.

The Phase 7 trust surface is local pairing groundwork:

```txt
pairing/invites       pending local pairing invitations
pairing/used          consumed local pairing invitations
trust.toml            trusted and revoked peer records
policy.toml           peer-scoped communication grants
```

Supported commands:

```txt
conu pair [--json]
conu join <code> [--json]
conu peers [--json]
conu peers policy [<peer-node-id> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>]] [--json]
conu peers revoke <peer-node-id> [--json]
```

Phase 7 creates trust records but does not discover remote agents or open network sessions. Raw used pairing codes must not appear in peer list output or trust records. Peer policy records are metadata-only boolean grants; missing records deny remote message, stream, room, file, and mailbox surfaces by default.

The Phase 8 relay surface is a standalone WebSocket service for runtime sessions:

```txt
conu_core::relay      shared HELLO/FORWARD/PING frame contract
crates/conu-relay     WebSocket listener and metadata-only forwarding hub
CONU_RELAY_TOKEN      shared relay session token; local-dev-token is loopback-only
CONU_RELAY_CREDENTIALS
CONU_RELAY_CREDENTIALS_FILE
security/relay-credential.key optional local runtime client relay token
CONU_RELAY_MAX_CONNECTIONS
CONU_RELAY_MAX_CONNECTIONS_PER_IP
CONU_RELAY_MAX_FRAMES_PER_MINUTE
CONU_RELAY_IDLE_TIMEOUT_SECONDS
CONU_RELAY_SESSION_TTL_SECONDS
CONU_RELAY_SESSION_STATE_DIR
CONU_RELAY_ACCOUNTING_DIR
CONU_RELAY_ACCOUNTING_WINDOW_SECONDS
CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE
CONU_RELAY_MAX_BYTES_SENT_PER_NODE
```

Supported relay commands:

```txt
conu-relay --serve [addr]
conu-relay --hash-token
conu relay sync [--json]
conu relay credential set --stdin [--json]
conu relay credential status [--json]
conu relay credential clear [--json]
```

Supported runtime-to-relay frames:

```txt
HELLO node=<node-id> token=<token> payload=not_observed
HELLO node=<node-id> token=<token> resume=<session-id> payload=not_observed
FORWARD to=<node-id> envelope=<envelope-id> bytes=<count> payload=opaque
FORWARD to=<node-id> envelope=<envelope-id> kind=<message|stream_chunk> [stream=<stream-id>] from_agent=<agent-id> to_agent=<agent-id> bytes=<count> cipher=<cipher> key=<key-id> sender_key=<public-key> nonce=<nonce> body=<ciphertext> payload=peer_encrypted
PING payload=not_observed
```

Supported relay-to-runtime frames:

```txt
WELCOME session=<session-id> resumed=<true|false> payload=not_observed
ENVELOPE from=<node-id> to=<node-id> envelope=<envelope-id> bytes=<count> payload=opaque
ENVELOPE from=<node-id> to=<node-id> envelope=<envelope-id> kind=<message|stream_chunk> [stream=<stream-id>] from_agent=<agent-id> to_agent=<agent-id> bytes=<count> cipher=<cipher> key=<key-id> sender_key=<public-key> nonce=<nonce> body=<ciphertext> payload=peer_encrypted
SENT to=<node-id> envelope=<envelope-id> bytes=<count> payload=not_observed
UNDELIVERED to=<node-id> envelope=<envelope-id> reason=<safe-reason> payload=not_observed
PONG payload=not_observed
ERROR reason=<safe-reason> payload=not_observed
```

The relay enforces configurable total connection, per-IP connection, per-session frame-rate limits, idle timeouts, and max session TTL before forwarding frames. Limit and auth errors must remain generic and metadata-only.

The current data plane exposes peer-encrypted one-shot messages through `conu messages send --peer`, peer-encrypted stream chunks through `conu streams write`, and peer-encrypted room events through `conu rooms publish` when the trusted peer policy grants the matching surface and the remote agent is visible. Reachable trusted peers can use authenticated direct QUIC for message and stream-chunk delivery; relay remains the fallback route and room-event path. Route sync records static host candidate metadata and explicit NAT-unavailable states, but ICE/STUN/TURN candidate gathering, UDP hole punching, and managed hosted NAT traversal land later. Session sync can also exchange signed public agent cards over peer-encrypted relay control envelopes for signed trusted peers with policy grants, replacing placeholder remote-agent mirrors after verification. Running conUD automatically pumps relay send/receive over a reusable relay session when the endpoint is stable and can present the prior session id as a same-node resume hint after reconnecting to the same endpoint. Relay clients accept `ws://` and certificate-valid `wss://` endpoints; the bundled relay server remains plain WebSocket and needs TLS termination for public `wss://`. `CONU_RELAY_CREDENTIALS_FILE` provides live-reloaded hashed per-node relay credentials with status/expiry/account metadata, offline upsert/rotate/revoke helpers, and account-scoped online admin issue/rotate/revoke/audit; `CONU_RELAY_CREDENTIALS` remains compatibility config. Runtime clients can use `CONU_RELAY_TOKEN` or store a local credential with `conu relay credential set --stdin`; the environment variable wins when both are present, and status/clear commands must not display token material. The relay may hold peer-encrypted envelopes in a bounded offline mailbox until the target node reconnects; `CONU_RELAY_MAILBOX_DIR` persists those ciphertext envelope files across relay restarts. `CONU_RELAY_SESSION_STATE_DIR` persists metadata-only same-node session resume records, and `CONU_RELAY_ACCOUNTING_DIR` persists metadata-only per-node usage counters, including authenticated and resumed sessions; optional sent quotas can reject over-limit sends with `quota_exceeded`. `conu relay sync` remains an explicit manual/debug one-shot command. Hosted dashboards/accounting, hosted tenant administration, distributed multi-instance session migration, and managed direct NAT traversal land later.

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
conu agents export <agent-id> [--json]
conu agents trust <agent-id> <display-name> --node <trusted-peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id> [--messages <bool>] [--streams <bool>] [--rooms <bool>] [--files <bool>] [--presence <bool>] [--json]
conud --process-ipc
```

`conu sessions sync` reads trusted peers and mirrors route/session metadata so `conu agents` can show visible remote agents. Imported signed remote agent cards must survive session sync for their trusted peer, and their signing key must match the trusted peer card; placeholder mirrors are only a fallback when no signed card exists for that peer. It does not transfer private payloads and does not yet create an interactive live stream. Revoked peers must disappear from the active remote-agent mirror after sync.

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

`conu routes sync` probes configured direct QUIC candidates against relay WebSocket fallback. Direct is selected only after a live QUIC connection succeeds and the remote peer answers a peer-encrypted challenge with the trusted peer-card key; failed probes record `direct_quic_probe_failed` and keep relay selected. Missing candidates for NAT profiles that need traversal help record `nat_traversal_unavailable`, while relay fallback remains selected. It may show route ids, peer ids, transport labels, sanitized endpoints, candidate source/kind, rendezvous state, scores, latency estimates, NAT profile labels, failure reasons, and fallback state. It must never show message text, prompt text, reasoning, file contents, private keys, shared secrets, tokens, endpoint secrets, or payload bytes.

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

`conu streams open` requires the local source and target metadata to advertise `streams=true`. `conu streams write` accepts opaque bytes from stdin and records only byte counts. For mirrored trusted remote agents on relay routes, it queues a peer-encrypted `stream_chunk` relay envelope only when the remote target metadata advertises `streams=true`; the receiver stores it as an addressed inbox envelope with stream metadata. `conu watch` renders transport flow, route, stream id, packet count, and bytes without rendering message or chunk contents.

The Phase 14 rooms/pub-sub surface is local-first shared coordination:

```txt
rooms/registry.toml   room, participant, topic, and session metadata
rooms/events.toml     payload-safe room event bus
rooms/policy.toml     payload-safe per-topic publish/subscribe grants
logs/rooms.log        metadata-only room events
messages/inbox        encrypted-at-rest room event fanout envelopes for joined local participants
```

Supported commands:

```txt
conu connect local <from-agent> <to-agent> [--kind <kind>] [--json]
conu connect room <room-id> <agent-id> [--json]
conu rooms [--json]
conu rooms create <room-id> <display-name> --agent <agent-id> [--json]
conu rooms join <room-id> <agent-id> [--json]
conu rooms publish <room-id> <from-agent> <topic> --stdin [--json]
conu rooms policy [<room-id> <agent-id> <topic> [--publish <true|false>] [--subscribe <true|false>]] [--json]
conu rooms events [--json]
```

Room membership is the compatibility subscription boundary for unconfigured topics. `conu rooms create`, `join`, and `publish` require the acting local agent card to advertise `rooms=true`; local room event fanout also requires the recipient to keep `rooms=true`. `conu rooms policy` stores per-agent topic publish/subscribe booleans only. Once any policy exists for a room/topic, publish, local fanout, remote fanout, and inbound relay delivery require explicit grants for that topic. `conu rooms publish` accepts opaque bytes from stdin, records only metadata in room files/logs, fans out encrypted-at-rest event envelopes to joined local participants, and queues peer-encrypted room event envelopes for joined trusted remote participants when remote metadata and peer policy grant rooms.

The Phase 11 security surface hardens local payload storage and identity metadata:

```txt
security/identity-signing.key   local Ed25519 signing key
security/identity-exchange.key  local X25519 exchange key
security/storage.key            local XChaCha20Poly1305 storage key
security/storage-keys/*.key     archived old storage keys for read-compatible rotation
security/replay.toml            replay/idempotency cache
security/key-rotation.md        local rotation plan
```

Supported command:

```txt
conu security audit [--json]
conu security rotate storage --confirm [--json]
conu security retire storage --confirm [--json]
```

New local message request and inbox files store encrypted-at-rest payload fields instead of `payload_hex`. `conu security rotate storage --confirm` archives the prior storage key and re-encrypts local message queue/inbox payload files under a new active storage key. `conu security retire storage --confirm` scans local queue/inbox payload metadata and removes only archived storage keys that no scanned payload file still references. New or updated local agent cards are signed in `agents/registry.toml`; `conu agents export` emits public signed agent-card metadata, `conu agents trust` verifies that card against an already trusted peer with a matching signing key before storing `agents/remote.toml`, and session sync can exchange the same signed cards automatically through encrypted relay control envelopes. Exported public peer cards are also signed and verified on trust import when signature fields are present. On Windows, local signing, exchange, active storage, and archived storage secret bytes are wrapped with current-user DPAPI fields and older plaintext-hex key files migrate during security-state ensure. `conu security audit` may report readiness, key ids, secret storage backend, and OS-protection status; storage rotation/retirement may report old/new key ids, file counts, and retired/retained archive counts. These surfaces may not display private keys, shared secrets, plaintext payloads, or decrypted payloads.

The Phase 12 SDK/MCP surface is the preferred agent integration path:

```txt
crates/conu-sdk          Rust SDK for typed local conU calls
crates/conu-mcp          MCP stdio adapter for agent tool use
sdk/python/conu_sdk      Python wrapper around conu/conud binaries
sdk/typescript           TypeScript/JavaScript wrapper around conu/conud binaries
```

Rust SDK calls:

```txt
ConuClient::register_agent()
ConuClient::register_agent_with_capabilities()
ConuClient::set_presence()
ConuClient::list_agents()
ConuClient::list_peers()
ConuClient::export_agent_card()
ConuClient::trust_remote_agent_card()
ConuClient::sync_routes()
ConuClient::list_routes()
ConuClient::list_route_probes()
ConuClient::send_message_bytes()
ConuClient::inbox_metadata()
ConuClient::receive_message_bytes()
ConuClient::open_stream()
ConuClient::write_stream_bytes()
ConuClient::close_stream()
ConuClient::create_room()
ConuClient::join_room()
ConuClient::publish_room_event_bytes()
ConuClient::list_rooms()
ConuClient::list_room_events()
ConuClient::security_audit()
```

TypeScript SDK calls:

```txt
ConuClient.init()
ConuClient.securityAudit()
ConuClient.registerAgent()
ConuClient.heartbeat()
ConuClient.agents()
ConuClient.exportAgentCard()
ConuClient.trustAgentCard()
ConuClient.identityExport()
ConuClient.trustPeer()
ConuClient.setPeerPolicy()
ConuClient.syncRoutes()
ConuClient.routes()
ConuClient.sendMessage()
ConuClient.sendRemoteMessage()
ConuClient.inbox()
ConuClient.relaySync()
ConuClient.openStream()
ConuClient.writeStream()
ConuClient.closeStream()
ConuClient.createRoom()
ConuClient.joinRoom()
ConuClient.setRoomTopicPolicy()
ConuClient.publishRoomEvent()
ConuClient.rotateIdentity()
ConuClient.retireIdentityArchives()
ConuClient.rotateStorage()
ConuClient.retireStorage()
ConuClient.telemetrySnapshot()
ConuClient.processQueued()
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
conu_export_agent_card
conu_trust_agent_card
conu_list_peers
conu_send_message
conu_receive_message
conu_open_stream
conu_write_stream
conu_close_stream
conu_create_room
conu_join_room
conu_list_rooms
conu_publish_room_event
conu_list_room_events
```

SDK/MCP receive is explicit. Normal list, send, receipt, status, stream, and room outputs remain metadata-only. Payload bytes may be returned only through Rust `ConuClient::receive_message_bytes()`, TypeScript `receiveMessageBytes()`, or MCP `conu_receive_message` with `includePayload: true`, and only for an envelope present in the addressed local agent inbox. The TypeScript wrapper routes explicit payload receive through MCP rather than exposing payload bytes through normal CLI metadata surfaces.

When launching `conu-mcp` for one agent, set `CONU_AGENT_ID`. A bound MCP server must reject register, presence, send, receive, stream-open, stream-write, stream-close, room-create, room-join, and room-publish attempts for a different local agent.

## Safety

"Full access" means full communication access inside trust boundaries. It does not mean raw filesystem, shell, network, or secret access.
