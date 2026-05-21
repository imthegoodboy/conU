# conU Direct Transport And Routes

Phase 13 adds the conUD-owned route manager. It records configured direct QUIC candidates and relay WebSocket fallback for each trusted peer, while keeping all payloads opaque.

```txt
Agents own the conversation.
conU owns the connection.
```

## What Exists Now

- `conu routes sync` probes trusted-peer route metadata and writes selected routes.
- `conu routes` lists selected and candidate routes.
- `conu routes probes` lists metadata-only route probe history.
- `conu status` and the dashboard show selected direct, relay, and fallback counts.
- `conu sessions sync` now refreshes routes before mirroring remote sessions.
- Streams opened to mirrored remote agents use the selected route label.
- Rust SDK and MCP expose route sync/list calls.

## State Files

```txt
routes/registry.toml   selected and candidate route metadata
routes/probes.toml     metadata-only route probe history
logs/routes.log        payload-safe route sync summaries
```

These files may contain peer ids, route ids, transport labels, endpoints, scores, NAT profile labels, latency estimates, and failure reasons. They must not contain message text, prompt text, chunk bytes, tool output, private keys, shared secrets, auth tokens, or plaintext payload fields.

## Route Selection

For each trusted peer, conUD creates:

- one `direct-quic` candidate from config, when available
- one `relay-websocket` fallback candidate

Configured direct endpoints are recorded and NAT-scored, but direct QUIC transport is not active yet. Until a real direct data plane exists, valid direct endpoints remain `unavailable` with `direct_quic_transport_inactive`, relay is selected, and relay is marked as the fallback path. Invalid or missing direct endpoints also keep relay selected.

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

`config.toml` supports a global direct endpoint or a peer-specific endpoint:

```toml
default_relay = "ws://127.0.0.1:8787"
nat_profile = "public"
direct_quic_endpoint = "quic://127.0.0.1:9443"
```

Peer-specific keys use a sanitized peer node id:

```toml
direct_quic_peer_abcd1234 = "quic://203.0.113.10:9443"
```

Accepted direct endpoint schemes are `quic://` and `udp://` with a host and port. Valid endpoints are retained as future direct candidates; invalid or missing direct endpoints keep relay selected.

## Agent Use

Agents should not read or write route files directly. They should use one of the supported surfaces:

```txt
CLI:      conu routes sync
Rust SDK: ConuClient::sync_routes()
Python:   ConuClient.sync_routes()
MCP:      conu_sync_routes
```

Agents can inspect route metadata to understand whether conU recorded a direct candidate and which relay route is selected, but they still own the conversation and payload bytes.

## Current Boundary

Phase 13 is the route selection and NAT posture layer. It does not yet open a real QUIC socket, perform ICE-style candidate exchange, or move encrypted stream chunks over direct UDP. That remains future transport hardening.

Design references:

- QUIC transport: https://www.rfc-editor.org/rfc/rfc9000
- QUIC DATAGRAM extension: https://www.rfc-editor.org/rfc/rfc9221
- ICE candidate negotiation: https://www.rfc-editor.org/rfc/rfc8445
