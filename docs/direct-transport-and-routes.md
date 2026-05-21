# conU Direct Transport And Routes

conU records direct QUIC candidates, probes them with peer-authenticated encrypted challenges, and keeps a relay WebSocket route available for fallback. Payload bytes remain opaque.

```txt
Agents own the conversation.
conU owns the connection.
```

## What Exists Now

- `conu routes sync` probes trusted-peer direct endpoints and writes selected routes.
- `conu routes` lists selected, candidate, fallback, and unavailable routes.
- `conu routes probes` lists metadata-only probe history.
- `conu status` and the dashboard show selected direct, relay, and fallback counts.
- `conu sessions sync` refreshes routes before mirroring remote sessions.
- Streams opened to mirrored remote agents use the selected route label.
- Direct message and stream-chunk delivery use QUIC when a trusted peer's direct route is selected, with relay fallback preserved.
- Rust SDK, Python SDK, TypeScript SDK, and MCP expose route sync/list calls.

## State Files

```txt
routes/registry.toml   selected and candidate route metadata
routes/probes.toml     metadata-only route probe history
logs/routes.log        payload-safe route sync summaries
logs/direct.log        payload-safe direct send/receive summaries
```

These files may contain peer ids, route ids, transport labels, endpoints, scores, NAT profile labels, latency estimates, byte counts, and failure reasons. They must not contain message text, prompt text, chunk bytes, tool output, private keys, shared secrets, auth tokens, or plaintext payload fields.

## Route Selection

For each trusted peer, conUD creates:

- one `direct-quic` candidate from peer-specific config, the signed peer card, or global config
- one `relay-websocket` fallback candidate

Direct endpoints are selected only after a live QUIC connection succeeds and the remote peer proves possession of the trusted peer-card exchange key by decrypting and answering a peer-encrypted challenge. If the direct probe fails, the direct route is `unavailable` with `direct_quic_probe_failed` and relay remains selected. If the NAT profile is `relay-only`, direct probing is skipped.

NAT profile scoring:

```txt
public      direct score 98
cone        direct score 92
unknown     direct score 88
symmetric   direct score 72
relay-only  direct disabled
relay       score 70
```

## Config

`config.toml` supports a local direct listener endpoint:

```toml
default_relay = "ws://127.0.0.1:8787"
nat_profile = "public"
direct_quic_endpoint = "quic://127.0.0.1:9443"
```

When exported with `conu identity export`, this endpoint is included in the signed peer card so trusted peers can probe it. A sender can also override a peer endpoint locally with a peer-specific sanitized key:

```toml
direct_quic_peer_abcd1234 = "quic://203.0.113.10:9443"
```

Accepted direct endpoint schemes are `quic://` and `udp://` with a host and port. Endpoints with user info, query strings, fragments, paths, or whitespace are rejected so route logs cannot hide credentials.

## Agent Use

Agents should not read or write route files directly. They should use one of the supported surfaces:

```txt
CLI:        conu routes sync
Rust SDK:   ConuClient::sync_routes()
Python SDK: ConuClient.sync_routes()
MCP:        conu_sync_routes
```

Agents can inspect route metadata to understand whether conU selected direct QUIC or relay fallback, but they still own the conversation and payload bytes.

## Current Boundary

Direct QUIC is active for reachable configured endpoints between trusted peers. It does not yet implement ICE-style candidate gathering, STUN/TURN negotiation, UDP hole punching, or managed hosted NAT traversal. On NATs that do not allow the configured endpoint to be reached, route sync keeps relay selected.

Design references:

- QUIC transport: https://www.rfc-editor.org/rfc/rfc9000
- QUIC DATAGRAM extension: https://www.rfc-editor.org/rfc/rfc9221
- ICE candidate negotiation: https://www.rfc-editor.org/rfc/rfc8445
