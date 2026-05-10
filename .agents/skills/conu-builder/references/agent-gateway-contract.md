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

## Safety

"Full access" means full communication access inside trust boundaries. It does not mean raw filesystem, shell, network, or secret access.
