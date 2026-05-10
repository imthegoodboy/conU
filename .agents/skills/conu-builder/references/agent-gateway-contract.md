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
PING payload=not_observed
```

Supported relay-to-runtime frames:

```txt
WELCOME session=<session-id> payload=not_observed
ENVELOPE from=<node-id> to=<node-id> envelope=<envelope-id> bytes=<count> payload=opaque
SENT to=<node-id> envelope=<envelope-id> bytes=<count> payload=not_observed
UNDELIVERED to=<node-id> envelope=<envelope-id> reason=<safe-reason> payload=not_observed
PONG payload=not_observed
ERROR reason=<safe-reason> payload=not_observed
```

Phase 8 does not yet expose this relay through the local agent gateway. conUD remote session management, remote agent discovery, reconnects, and relay-backed local commands begin in later phases.

## Safety

"Full access" means full communication access inside trust boundaries. It does not mean raw filesystem, shell, network, or secret access.
