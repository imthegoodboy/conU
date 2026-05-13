# conU SDK And MCP Adapter

Phase 12 gives agents stable ways to call conU without learning its internal file layout. Phase 14 extends that surface with local rooms/pub-sub calls.

The contract stays the same:

```txt
Agents own the conversation.
conU owns the connection.
```

conU list, send, receipt, status, watch, stream, and room outputs are metadata-only. Payload bytes are returned only through an explicit receive API for the addressed local agent.

## Rust SDK

The Rust SDK lives in `crates/conu-sdk`.

```rust
use conu_sdk::ConuClient;

let client = ConuClient::new();
client.init()?;
client.register_agent("agent.alpha", "Alpha", "local-agent")?;
client.register_agent("agent.beta", "Beta", "local-agent")?;
client.process_queued()?;

client.send_message_bytes("agent.alpha", "agent.beta", b"private bytes")?;
let report = client.process_queued()?;
let inbox = client.inbox_metadata("agent.beta")?;
let payload = client.receive_message_bytes("agent.beta", &inbox[0].envelope_id)?;
```

Useful calls:

```txt
init()
state_snapshot()
runtime_status()
security_audit()
register_agent()
register_agent_with_capabilities()
set_presence()
process_queued()
list_agents()
list_peers()
export_peer_card()
trust_peer_card()
sync_routes()
list_routes()
list_route_probes()
send_message_bytes()
send_remote_message_bytes()
relay_sync()
relay_queue_summary()
inbox_metadata()
receive_message_bytes()
list_receipts()
open_stream()
write_stream_bytes()
close_stream()
list_streams()
list_stream_events()
create_room()
join_room()
publish_room_event_bytes()
list_rooms()
list_room_events()
```

Run the example:

```bash
cargo +stable-x86_64-pc-windows-gnu run -p conu-sdk --example local_agents
```

## Python SDK

The Python wrapper lives in `sdk/python/conu_sdk`. It is stdlib-only and wraps installed `conu` and `conud` binaries.

```powershell
$env:PYTHONPATH = "$PWD\sdk\python"
```

```python
from conu_sdk import ConuClient

client = ConuClient(home=".conu-agent")
client.init()
client.register_agent("agent.alpha", "Alpha")
client.register_agent("agent.beta", "Beta")
client.process_queued()
sent = client.send_message("agent.alpha", "agent.beta", b"private bytes")
print(sent["payloadBytes"])
```

The wrapper passes send/stream payload bytes through stdin and returns command output to the caller. It does not print or log payloads.

Route helpers are available as `sync_routes()`, `routes()`, and `route_probes()`. They return route metadata only.

Remote relay helpers are available as `identity_export()`, `trust_peer()`, `send_remote_message()`, and `relay_sync()`. They exchange public peer-card metadata and queue peer-encrypted message bytes without printing payload contents. When conUD is running with relay config, queued remote messages are pumped by the daemon; `relay_sync()` remains useful for manual flush/debug flows.

Room helpers are available as `create_room()`, `join_room()`, `publish_room_event()`, `rooms()`, `room_events()`, `connect_local()`, and `connect_room()`. Room publish payloads go through stdin, joined local participants receive encrypted-at-rest event envelopes, and wrapper responses show metadata only.

## MCP Adapter

The MCP adapter lives in `crates/conu-mcp` and runs as a stdio server:

```bash
cargo +stable-x86_64-pc-windows-gnu run -p conu-mcp
```

Installed usage:

```json
{
  "mcpServers": {
    "conu": {
      "command": "conu-mcp",
      "env": {
        "CONU_HOME": "C:\\Users\\you\\AppData\\Roaming\\conU",
        "CONU_AGENT_ID": "agent.mybot"
      }
    }
  }
}
```

Implemented MCP tools:

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
conu_export_identity
conu_trust_peer
conu_send_message
conu_send_remote_message
conu_relay_sync
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

`conu_sync_routes` and `conu_list_routes` expose route ids, peer ids, transport labels, endpoints, scores, latency estimates, NAT profile labels, fallback flags, and failure reasons. They do not expose payload bytes. `conu_export_identity` returns public node id, display name, public exchange key, and relay endpoint only. `conu_trust_peer` imports another node's public card. `conu_send_message`, `conu_send_remote_message`, and `conu_publish_room_event` accept `payloadText` or `payloadHex`, but their responses report only request id, envelope/event id, byte count, local delivery count, and delivery metadata. `conu_relay_sync` reports relay counters only. `conu_receive_message` returns metadata by default. It returns `payloadHex` only when `includePayload` is `true`.

When `CONU_AGENT_ID` is set, `conu-mcp` is bound to that local agent id. Register, presence, send, receive, stream open, stream write, stream close, room create, room join, and room publish actions are rejected if they attempt to act as a different local agent.

## MCP Protocol Notes

The adapter follows MCP stdio as JSON-RPC 2.0 over stdin/stdout, with newline-delimited messages and no non-MCP data on stdout. This matches the latest MCP transport documentation, which defines stdio messages as JSON-RPC messages delimited by newlines.

Reference: [MCP 2025-11-25 Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## Current Boundaries

- TypeScript SDK remains future work.
- Remote relay-backed one-shot message delivery is active through the conUD relay pump when relay config is present; explicit relay sync remains a manual/debug tool. Stream byte routing, persistent relay sessions, offline relay mailbox delivery, and hosted relay auth hardening remain future work.
- Rooms fan out to joined local participants only. Relay-backed room event fanout and per-topic subscription policy remain future work.
- Route sync selects configured direct QUIC candidates and relay fallback metadata; it does not open a real QUIC socket yet.
- MCP uses local stdio only; HTTP MCP transport is not implemented.
- `conu_receive_message` is intentionally explicit because normal CLI and tool metadata views must not display payload contents.
