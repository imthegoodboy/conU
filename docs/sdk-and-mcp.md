# conU SDK And MCP Adapter

Phase 12 gives agents stable ways to call conU without learning its internal file layout. Phase 14 extends that surface with local rooms/pub-sub calls, and the post-Phase-15 SDK pass adds a dependency-free TypeScript/JavaScript wrapper around the installed CLI/runtime binaries.

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

`register_agent()` keeps the default message/presence-only capability set. Use `register_agent_with_capabilities()` before calling stream or room APIs so conU can enforce explicit local grants.

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
export_agent_card()
trust_peer_card()
trust_remote_agent_card()
list_peer_policies()
peer_policy()
set_peer_policy()
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
set_room_topic_policy()
list_room_topic_policies()
room_topic_policy()
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

The wrapper passes send/stream payload bytes through stdin and returns command output to the caller. It does not print or log payloads. Pass `streams=True` and/or `rooms=True` to `register_agent()` before using stream or room helpers.

Route helpers are available as `sync_routes()`, `routes()`, and `route_probes()`. They return route metadata only.

Remote relay helpers are available as `identity_export()`, `trust_peer()`, `set_peer_policy()`, `send_remote_message()`, stream calls, room calls, and `relay_sync()`. They exchange public peer-card metadata, record metadata-only peer grants, and queue peer-encrypted message, stream-chunk, or room-event bytes without printing payload contents. Remote message, stream, and room traffic fails closed unless the trusted peer policy grants `messages=true`, `streams=true`, or `rooms=true` respectively. When conUD is running with relay config, queued remote envelopes are pumped by the daemon; `relay_sync()` remains useful for manual flush/debug flows.

Signed remote agent-card helpers are available as `export_agent_card()` and `trust_agent_card()` for manual fallback. With signed peer-card trust and peer policy grants in place, session sync can exchange signed agent cards automatically over peer-encrypted relay control envelopes. Both paths pass public agent id, display name, node id, kind, capabilities, signing public key, and signature metadata only.

Room helpers are available as `create_room()`, `join_room()`, `publish_room_event()`, `rooms()`, `room_events()`, `room_topic_policies()`, `set_room_topic_policy()`, `connect_local()`, and `connect_room()`. Room publish payloads go through stdin, joined local participants receive encrypted-at-rest event envelopes, joined trusted remote participants receive peer-encrypted relay room-event envelopes, and wrapper responses show metadata only. Core routing rejects room create/join/publish when the local agent card does not advertise `rooms=true`. `set_room_topic_policy()` stores metadata-only publish/subscribe grants; once any policy exists for a room/topic, that topic requires explicit grants.

## TypeScript SDK

The TypeScript/JavaScript wrapper lives in `sdk/typescript`. It is dependency-free, runs on Node 18+, and wraps installed `conu`, `conud`, and `conu-mcp` binaries. It is not browser-native protocol support; browser-conditioned imports fail closed through a safe stub that reports `browserSupport.supported = false` and never accepts private keys, relay tokens, endpoint secrets, or payload bytes.

```javascript
import { ConuClient } from "@conu/sdk";

const client = new ConuClient({ home: ".conu-agent" });
client.init();
client.registerAgent("agent.alpha", "Alpha", { rooms: true, streams: true });
client.registerAgent("agent.beta", "Beta", { rooms: true, streams: true });
client.processQueued();

const sent = client.sendMessage("agent.alpha", "agent.beta", "private bytes");
const inbox = client.inbox("agent.beta");
const received = client.receiveMessageBytes("agent.beta", inbox.entries[0].envelopeId);
console.log({
  sentEnvelopeId: sent.envelopeId,
  inboxEntries: inbox.entries?.length ?? 0,
  receivedBytes: received.byteLength,
});
```

Useful calls include `init()`, `status()`, `securityAudit()`, `registerAgent()`, `heartbeat()`, `agents()`, `exportAgentCard()`, `trustAgentCard()`, `identityExport()`, `trustPeer()`, `setPeerPolicy()`, `sendMessage()`, `sendRemoteMessage()`, `inbox()`, `receiveMessageBytes()`, `relaySync()`, `syncRoutes()`, `routes()`, `openStream()`, `writeStream()`, `createRoom()`, `joinRoom()`, `setRoomTopicPolicy()`, `publishRoomEvent()`, `rotateIdentity()`, `retireIdentityArchives()`, `rotateStorage()`, `retireStorage()`, `telemetrySnapshot()`, and `processQueued()`.

Payload-bearing methods pass bytes through stdin rather than argv. The wrapper does not print or log payloads, and command responses stay on the current CLI metadata contract. The TypeScript wrapper exposes raw local inbox bytes only through the explicit `receiveMessageBytes(agentId, envelopeId)` helper, which calls `conu_receive_message` with `includePayload: true` and still requires the envelope to be present in that addressed local agent inbox.

For browser boundaries and the future browser-native protocol design requirements, see `docs/browser-native-typescript.md`.

Run the package smoke check:

```bash
npm run check --prefix sdk/typescript
```

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
conu_export_agent_card
conu_trust_agent_card
conu_list_peers
conu_export_identity
conu_trust_peer
conu_set_peer_policy
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
conu_set_room_topic_policy
conu_list_room_topic_policies
```

`conu_sync_routes` and `conu_list_routes` expose route ids, peer ids, transport labels, sanitized endpoints, candidate source/kind, rendezvous state, scores, latency estimates, NAT profile labels, fallback flags, and failure reasons. They do not expose payload bytes, tokens, private keys, or endpoint secrets. `conu_security_audit` may expose readiness booleans, key ids, secret storage backend, and OS-protection status, but never private keys, DPAPI blobs, shared secrets, or payload bytes. `conu_export_identity` returns public node id, display name, public exchange key, relay endpoint, and public peer-card signature fields. `conu_trust_peer` imports another node's public card and verifies the signature when those fields are present. `conu_set_peer_policy` records boolean grants for message, stream, room, file, and mailbox surfaces and returns those metadata fields only. `conu_set_room_topic_policy` records per-agent publish/subscribe grants for a room topic and returns metadata only; configured topics require explicit grants for publish, local fanout, remote fanout, and inbound relay room delivery. `conu_export_agent_card` returns public signed local agent-card metadata, and `conu_trust_agent_card` verifies and stores a signed remote agent card only for an already trusted peer node whose signing key matches the agent card. `conu_send_message`, `conu_send_remote_message`, and `conu_publish_room_event` accept `payloadText` or `payloadHex`, but their responses report only request id, envelope/event id, byte count, local and remote delivery counts, and delivery metadata. `conu_relay_sync` reports relay counters only. `conu_receive_message` returns metadata by default. It returns `payloadHex` only when `includePayload` is `true`.

When `CONU_AGENT_ID` is set, `conu-mcp` is bound to that local agent id. Register, presence, send, receive, stream open, stream write, stream close, room create, room join, room publish, and room topic policy actions are rejected if they attempt to act as a different local agent.

## MCP Protocol Notes

The adapter follows MCP stdio as JSON-RPC 2.0 over stdin/stdout, with newline-delimited messages and no non-MCP data on stdout. This matches the latest MCP transport documentation, which defines stdio messages as JSON-RPC messages delimited by newlines.

Reference: [MCP 2025-11-25 Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## Current Boundaries

- Remote relay-backed one-shot message, stream-chunk, room-event, signed-card control, and bounded offline-mailbox delivery is active through the conUD relay pump when relay config is present; conUD reuses a relay session across runtime ticks and can resume the same-node session after reconnecting to the same endpoint, while explicit relay sync remains a manual/debug one-shot tool. Signed agent-card export/import is available for already trusted peers. The relay supports live-reloaded scoped credentials, hashed `CONU_RELAY_CREDENTIALS_FILE` manifests with offline upsert/rotate/revoke helpers, account-scoped online admin issue/rotate/revoke/audit, optional metadata-only hosted tenant registry through `CONU_RELAY_TENANTS_FILE`, runtime clients can use `CONU_RELAY_TOKEN` or a local `conu relay credential set --stdin` credential, optional metadata-only `CONU_RELAY_SESSION_STATE_DIR` session files, optional `CONU_RELAY_MAILBOX_DIR` durable ciphertext files with payload-safe `conu-relay --mailbox-audit` retention snapshots, metadata-only `CONU_RELAY_ACCOUNTING_DIR` counters with optional sent quotas, metadata-only `CONU_RELAY_ABUSE_DIR` denial/enforcement counters, and local `conu-relay --hosted-dashboard` snapshots. Distributed hosted dashboards/accounting/abuse workflows, automated hosted mailbox purge workflows, distributed tenant lifecycle, distributed multi-instance session migration, and MCP credential-management tools remain future work.
- Rooms fan out to joined local participants and joined trusted remote participants. Unconfigured topics use room membership as the subscription boundary; configured topics require explicit publish/subscribe grants through the local room topic policy file.
- Route sync probes configured direct QUIC candidates, records static candidate metadata and NAT-unavailable states, selects direct only after an authenticated live probe succeeds, and keeps relay selected when direct is unavailable.
- MCP uses local stdio only; HTTP MCP transport is not implemented.
- `conu_receive_message` is intentionally explicit because normal CLI and tool metadata views must not display payload contents.
- The TypeScript wrapper follows CLI metadata surfaces for list/send/status helpers and exposes raw payload bytes only through explicit addressed-agent receive helpers. Browser-conditioned imports return a safe unsupported stub until a reviewed browser-native protocol package exists.
