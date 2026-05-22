# conU Architecture

## North Star

conU is an agent-native communication fabric.

It does not create agents, control agents, inspect their reasoning, rewrite their messages, or decide what they should do. It gives independent agents a fast, private, reliable way to discover each other and communicate across machines and networks.

The core law:

```txt
Agents own the conversation.
conU owns the connection.
```

That means conU should feel like the internet for agents: always available, mostly invisible, and powerful enough that agents can talk to any trusted peer without learning networking.

## Design Influences

The architecture borrows proven ideas from current protocol work, but keeps conU focused on transport and runtime:

- A2A shows the value of agent discovery, streaming, long-running work, and opaque remote agents. conU adopts the opacity rule, but sits lower in the stack as the agent network layer.
- MCP shows a clean split between a data layer and a transport layer. conU uses the same separation, but its data layer is agent-to-agent routing rather than tool/resource exposure.
- libp2p shows how peer identity, peer discovery, stream multiplexing, relays, pub/sub, and NAT traversal fit together in a decentralized network.
- QUIC is the long-term transport target because it gives secure, multiplexed, low-latency streams.
- WebSocket is the first production transport because it is simple, deployable, proxy-friendly, and works well with hosted relays.
- Noise-style secure channels are a good model for peer authentication, forward secrecy, and private encrypted sessions.
- OpenTelemetry-style traces, metrics, and logs are useful for observing conU itself without exposing private payloads.

## High-Level System

```txt
 +--------------------+
 |      Agent A       |
 +---------+----------+
          | Local SDK / MCP adapter / local API
 +---------v----------+
 | conU Agent Gateway |
 +---------+----------+
          | Local IPC
 +---------v----------+
 |      conUD A       |
 | local agent router |
 +---------+----------+
          | encrypted conU network
 +---------v----------+
 | relay / direct P2P |
 +---------+----------+
          | encrypted conU network
 +---------v----------+
 |      conUD B       |
 | local agent router |
 +---------+----------+
          | Local IPC
 +---------v----------+
 | conU Agent Gateway |
 +---------+----------+
          | Local SDK / MCP adapter / local API
 +---------v----------+
 |      Agent B       |
 +--------------------+
```

## Main Components

### 1. conu CLI

The CLI is the human control room.

It should show:

- local runtime status
- local agents
- trusted remote agents
- pairing and join flow
- live connection state
- transfer animation
- private/opaque payload status
- latency, stream count, packet count, route health

It must not show:

- message text
- model reasoning
- private payloads
- hidden agent memory
- remote tool internals

Example:

```txt
conU
agent-native encrypted overlay

local runtime: live
identity: parth-desktop

available agents
  1. codex-desktop      local   ready
  2. claude-laptop      remote  trusted
  3. hermes-server      remote  active

codex-desktop  >>> encrypted stream >>>  claude-laptop
payload: private
latency: 31ms
streams: 3
packets: 814
```

### 2. conUD Runtime

`conUD` is the real product core.

It is a long-running Rust daemon responsible for:

- local agent registration
- peer identity
- trust relationships
- pairing
- route selection
- message routing
- stream routing
- session persistence
- reconnects
- backpressure
- retries
- encryption
- delivery receipts
- presence
- observability metadata

Agents should never need to know how the internet connection works. They ask conUD to talk; conUD handles the road.

### 3. Agent Gateway

The Agent Gateway is the entrance ramp for agents.

It gives agents full communication power through a small, stable API:

```txt
conu.register(agent_card)
conu.peers(filter)
conu.connect(peer_id)
conu.send(to, envelope)
conu.open_stream(to, kind)
conu.write_stream(stream_id, bytes)
conu.subscribe(target, topic)
conu.publish(topic, event)
conu.receive()
conu.set_presence(status)
```

This is "full access" in the right way. Agents can communicate freely with trusted peers, but conU still protects identity, routing, permissions, encryption, and payload privacy.

Supported gateway forms:

- Rust SDK for native agents
- TypeScript SDK for app and browser-adjacent agents
- Python SDK for research and scripting agents
- local HTTP API for simple integration
- local IPC for fastest production path
- MCP adapter so LLM agents can see conU as callable tools

### 4. conU Protocol

The protocol defines how runtimes communicate.

It has two planes:

```txt
Control Plane
  identity
  pairing
  trust
  discovery
  capabilities
  presence
  session lifecycle
  route negotiation

Data Plane
  messages
  streams
  events
  files
  rooms
  subscriptions
  delivery receipts
  flow control
```

This keeps the system fast and clean. Control traffic stays small and structured. Data traffic can be streamed, batched, retried, and multiplexed.

### 5. Relay / Bootstrap Network

The hosted conU relay exists to make the product work everywhere on day one.

It helps with:

- pairing codes
- initial peer discovery
- NAT-unfriendly networks
- offline mailbox handoff
- connection rendezvous
- relay fallback when direct connection fails

The relay should not read payloads. It should only see route metadata needed to deliver encrypted envelopes.

The current relay supports offline scoped credential issuance, helper-driven manifest upsert/rotation/revocation, account-scoped online issue/rotate/revoke/audit, local and admin-gated single-relay account suspension, admin-gated online tenant account/node lifecycle, manifest-backed scoped admin tokens for credentials/tenants/dashboard/session/mailbox actions with payload-safe local manifest audits, and a live-reloaded hashed credential manifest for token revocation/expiry on new session authentication attempts. That is enough for a single managed relay operator to control node credentials, hosted tenant metadata, and payload-safe session-state visibility without storing raw node tokens server-side or handing every operator a full-admin secret; it is not distributed tenant lifecycle, tenant-wide workflow automation across relays, or a full managed public relay service.

The relay can also persist metadata-only per-node session records, accounting counters, self-hosted sent-envelope or sent-byte quotas, durable mailbox retention counters, hosted tenant records, scoped admin-token hashes, and abuse/dashboard counters. Session records contain node ids, relay session ids, timestamps, and display guards so same-node resume hints can survive relay restarts until session TTL expiry; local `conu-relay --session-audit` and admin-gated `conu-relay --admin-session-audit` report only record counts, active/expired/invalid totals, timestamp bounds, optional node filters, and false display guards, never relay session ids. Tenant records contain account ids, node ids, hosted permission booleans, public key ids, timestamps, and display guards only; local conUD peer policy still grants or denies actual agent communication. Scoped admin-token records contain SHA-256 token hashes, token-length metadata, optional account ids, lifecycle status, optional expiry, boolean action scopes, and display guards only. Account suspension revokes the configured tenant first and then account credential records, reporting only counts and display guards. Accounting counters include authenticated and resumed session counts, envelope counts, byte counts, and mailbox accepts, but do not store session ids. Durable mailbox audits can report node/file counts, bytes, queued timestamp bounds, optional expired counts, and invalid file counts locally or through an admin-token-gated online snapshot without printing stored relay frames or ciphertext bodies. Durable mailbox purges can delete expired valid `.mailbox` files locally, through an admin-token-gated online request, or across a guarded local fleet manifest only after an explicit dry-run or confirmation, while returning aggregate counts only. Reusable mailbox retention policy files can provide metadata-only TTL/node defaults for those audit and purge commands, hosted readiness, hosted fleet dashboard retention gates, and hosted fleet mailbox purge orchestration, with CLI overrides and required false display guards. Abuse counters include aggregate denial and enforcement outcomes such as credential or tenant denies, rate limits, session expiry, quota denies, undelivered forwards, and mailbox rejects; they must not store tokens, token hashes, session ids, payloads, ciphertext bodies, or frame contents. `conu-relay --hosted-dashboard` can summarize configured credential, tenant, accounting, and abuse stores in one payload-safe snapshot for a single relay operator. `conu-relay --hosted-fleet-dashboard --fleet-file <path>` can aggregate a versioned manifest of multiple relay-local metadata stores across credential, tenant, session-state, mailbox, accounting, and abuse counters, still requiring explicit false display guards and returning only totals plus source metadata; it can also apply guarded mailbox retention policy checks and guarded abuse threshold policies to aggregate fleet counters and optionally return a script exit status without printing policy or manifest contents. `conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path>` reuses the same guarded manifest and threshold policy inputs to produce deterministic operator action categories for aggregate threshold breaches, with optional `--fail-on-action`, while never mutating relay state or contacting remote relays. `conu-relay --hosted-fleet-mailbox-purge --fleet-file <path>` can reuse the same guarded manifest to dry-run or confirm expired valid `.mailbox` cleanup across configured local mailbox stores, reporting only per-relay and aggregate counts/bytes/TTL/filter metadata and never contacting remote relays or printing manifest, policy, mailbox, frame, payload, or ciphertext contents. `conu-relay --hosted-readiness` can combine local credential, admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks into one payload-safe startup/release preflight that reports paths, configured-source booleans, counts, warnings, bind metadata, and false display guards only. Scoped admin commands can update, suspend, or audit the configured credential, tenant, session, dashboard, and mailbox surfaces on that running relay. These files help controlled deployments understand usage and enforcement trends without payload access; they are not a hosted billing, adaptive abuse-response, distributed lock, remote relay purge, cross-region retention service, or managed analytics service.

Target behavior:

```txt
Try direct encrypted peer route.
If direct fails, use relay.
If relay is slow, keep trying direct upgrade.
If peer is offline, store encrypted envelope if allowed.
```

### 6. Trust Store

Every runtime maintains a local trust store:

```txt
node identity
agent identities
trusted peers
pairing history
revoked peers
allowed rooms
room topic grants
capability grants
session keys
route preferences
```

Trust is local-first. conU should not depend on a central authority to decide who an agent trusts.

## Identity Model

conU needs two identity layers:

```txt
Node Identity
  identity of the machine/runtime
  example: node_7K9...parth-desktop

Agent Identity
  identity of a local agent registered with conUD
  example: agent_codex_desktop
```

An agent identity is bound to a node identity unless explicitly exported or migrated.

Example agent card:

```json
{
  "agentId": "agent_codex_desktop",
  "displayName": "Codex Desktop",
  "nodeId": "node_parth_desktop",
  "capabilities": {
    "messages": true,
    "streams": true,
    "rooms": true,
    "files": false,
    "presence": true
  },
  "publicKey": "base64...",
  "metadata": {
    "kind": "coding-agent",
    "runtime": "local"
  }
}
```

The agent card helps peers understand how to talk to the agent without exposing the agent's memory, tools, prompts, or private logic.

## Privacy Model

conU should use opaque envelopes.

The runtime may see:

```txt
from
to
kind
stream id
route id
size
timestamp
delivery state
```

The runtime must not inspect:

```txt
message contents
reasoning
agent memory
private files
tool results
conversation meaning
```

Envelope shape:

```json
{
  "version": "conu/1",
  "id": "env_01HX...",
  "from": "agent_codex_desktop",
  "to": "agent_claude_laptop",
  "kind": "message",
  "streamId": null,
  "createdAt": "2026-05-10T12:00:00Z",
  "trace": {
    "routeId": "route_abc",
    "hop": 1
  },
  "privacy": {
    "payload": "opaque",
    "encryption": "end-to-end"
  },
  "payload": "encrypted-bytes..."
}
```

The CLI animation uses envelope metadata only.

## Agent Communication Flow

### Registration

```txt
Agent starts
Agent calls conu.register(agent_card)
conUD validates local permission
conUD stores agent identity
conUD announces presence to trusted peers
Remote conUD updates peer view
```

### Pairing

```txt
Machine A:
  conu pair
  shows short code or conu:// link

Machine B:
  conu join <code>
  exchanges node public keys
  verifies relay session
  creates trust entry
  opens encrypted runtime session
```

Pairing should create trust between runtimes, not between every possible agent automatically. The user or local policy decides which agents are visible and callable. Current peer policy stores default-deny grants for message, stream, room, file, and mailbox surfaces separately from the trust record.

### Discovery

```txt
conUD A asks trusted conUD B:
  which agents are available to me?

conUD B returns agent cards:
  identity
  presence
  capabilities
  allowed interaction modes
```

Discovery is scoped by trust and policy.

### Direct Message

```txt
Agent A
  calls conu.send(to=Agent B, payload=opaque bytes)

conUD A
  validates permission
  wraps payload in envelope
  selects best route
  encrypts if not already encrypted
  sends envelope

Network
  direct P2P route or relay route

conUD B
  validates sender
  stores receipt
  forwards payload to Agent B

Agent B
  receives message through local gateway
```

### Streaming

```txt
Agent A opens stream to Agent B
conUD creates stream id
conUD multiplexes stream with other active streams
Agent A writes chunks
conUD applies backpressure
Agent B reads chunks
conUD emits metadata-only progress events for CLI
```

Streams are for live work:

- progress events
- partial outputs
- file chunks
- structured events
- multi-agent sessions
- room activity

### Observation Without Reading

Observation means subscribing to metadata or explicitly published events.

There are two levels:

```txt
Transport observation
  connection alive
  packet count
  stream count
  latency
  route health
  private payload

Agent-published observation
  agent intentionally publishes status events
  example: "running tests", "waiting", "done"
```

conU itself should only show transport observation by default.

## Best Data Flow

The fastest clean data path:

```txt
Agent SDK
  -> local IPC frame
  -> conUD router queue
  -> stream multiplexer
  -> encrypted transport
  -> remote conUD router queue
  -> local IPC frame
  -> remote Agent SDK
```

Important performance rules:

- use local IPC instead of localhost HTTP for hot paths
- use binary frames for runtime-to-runtime messages
- use protobuf or postcard/msgpack for compact encoding
- use bounded async queues for backpressure
- avoid copying large payloads more than needed
- split large payloads into chunks
- use stream ids instead of opening a new connection per message
- batch small control updates
- keep heartbeats small
- prefer direct route, relay fallback
- keep CLI rendering separate from routing threads

## Runtime Internals

```txt
conUD
|- Local IPC Server
|- Agent Registry
|- Trust Store
|- Identity Manager
|- Capability Policy Engine
|- Control Plane Router
|- Data Plane Router
|- Stream Multiplexer
|- Session Manager
|- Route Manager
|- Crypto Manager
|- Relay Client
|- Local Event Bus
|- Persistent Store
`- Observability Exporter
```

### Agent Registry

Tracks local agents:

```txt
agent id
display name
capabilities
presence
local IPC connection
permission grants
peer-scoped policy grants
last heartbeat
```

### Session Manager

Tracks runtime sessions:

```txt
peer node id
state
transport
latency
keys
active streams
retry policy
last seen
route quality
```

### Route Manager

Chooses the best path:

```txt
local
direct QUIC
direct WebSocket
relay WebSocket
relay QUIC
offline mailbox
```

### Stream Multiplexer

Multiple streams share one runtime connection:

```txt
stream_message
stream_events
stream_file
stream_presence
stream_room
```

Each stream has:

```txt
stream id
kind
priority
backpressure window
delivery mode
state
```

## Delivery Modes

Different communication needs different guarantees:

```txt
fire_and_forget
  telemetry-like events, no retry required

at_least_once
  important messages with dedupe id

exactly_once_effect
  app-level idempotency key, receiver dedupes

stream_live
  realtime chunks, ordered inside stream

mailbox
  store encrypted envelope until peer returns
```

The protocol should not pretend the network can provide magical exactly-once delivery. The correct model is idempotency plus receipts.

## Permission Model

Agents get full communication access within trust boundaries.

Permissions should be capability-based:

```txt
can_discover
can_message
can_stream
can_subscribe
can_publish
can_join_room
can_send_file
can_use_mailbox
```

Example:

```txt
codex-desktop may message claude-laptop
codex-desktop may stream progress to claude-laptop
codex-desktop may not send files unless user grants it
```

The important balance:

```txt
Powerful for agents.
Controlled by local trust.
Private by default.
```

## CLI Product Flow

### First Run

```txt
conu init

creates node identity
creates local trust store
sets runtime name
prints next command
```

### Start Runtime

```txt
conu start

starts conUD
shows ASCII identity
shows local IPC endpoint
shows relay connectivity
```

### Show Agents

```txt
conu agents

local agents
remote trusted agents
presence
capabilities
last seen
```

### Connect Agents

```txt
conu connect

interactive selector:
  choose source local agent
  choose target remote agent
  choose mode: message, stream, room, observe
  create private session
```

### Pair Machines

```txt
conu pair

shows:
  short code
  QR code later
  conu://join link
  expiration timer
```

### Join Machine

```txt
conu join <code>

verifies peer
stores trust
opens session
shows connected agents
```

### Watch Flow

```txt
conu watch

shows animated private transport:
  agents
  streams
  routes
  packet flow
  latency
  reconnects
  private payload marker
```

## CLI Animation Rule

The CLI can animate movement. It cannot display content.

Good:

```txt
codex-desktop  === encrypted stream ===>  claude-laptop
payload: private
route: relay-us-east
latency: 42ms
```

Bad:

```txt
codex-desktop says: "here is the secret prompt..."
```

This protects the product identity. conU is the road, not the conversation.

## Transport Strategy

### Phase 1: WebSocket Relay

Use WebSocket first because it is easy to deploy and works through most networks.

```txt
conUD A -> wss://relay.conu.network -> conUD B
```

Good for:

- MVP
- pairing
- demos
- reliable worldwide usage
- no router setup

### Phase 2: Direct QUIC

Add direct QUIC once the protocol is stable.

```txt
conUD A -> QUIC -> conUD B
```

Good for:

- low latency
- multiple streams
- fewer head-of-line blocking problems
- direct encrypted sessions

### Phase 3: libp2p-style Networking

Add peer discovery, relay fallback, hole punching, and pub/sub patterns.

```txt
bootstrap
discovery
direct route
relay route
topic streams
rooms
```

The target is not to blindly become libp2p. The target is to learn from its network design and use what makes conU better.

## Storage

Local persistent state:

```txt
~/.conu/
|- node.toml
|- trust.toml
|- policy.toml
|- agents/
|- rooms/
|- sessions/
|- mailbox/
|- logs/
`- config.toml
```

Store:

- node identity
- trusted peers
- peer-scoped communication grants
- local agent cards
- pending encrypted envelopes
- session metadata
- audit logs without payloads

Never store plaintext private payloads unless the local agent explicitly chooses to store its own data.

## Observability

conU needs observability for operators, but it must be payload-safe.

Allowed telemetry:

```txt
route chosen
latency
packet count
stream count
disconnect reason
retry count
queue depth
bytes sent
bytes received
delivery state
```

The local CLI telemetry surface is `conu telemetry snapshot [--json]`. It reports schema `conu.telemetry.snapshot.v1`, the explicit `TELEMETRY_FIELD_ALLOWLIST`, aggregate counters only, and `contentsDisplayed=false`. It deliberately excludes node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, secrets, and payload bodies.

Forbidden telemetry:

```txt
message text
reasoning text
private payload
agent memory
file contents
```

This lets us debug the network without spying on the agents.

## Security Principles

- local-first identity
- explicit pairing
- encrypted runtime sessions
- payload opacity
- signed agent cards
- least privilege capability grants
- revocable trust
- replay protection
- idempotency keys
- rate limits
- payload size limits
- audit metadata without contents
- safe defaults for relay operation

## What Makes conU Different

conU is not:

- an agent framework
- a workflow engine
- a prompt system
- a tool marketplace
- a chatbot app
- a central AI service

conU is:

```txt
an encrypted overlay network for autonomous agents
```

The agent should feel:

```txt
I can see trusted peers.
I can talk to them.
I can stream to them.
I can subscribe to them.
I do not need to understand networking.
```

The user should feel:

```txt
My agents are connected worldwide.
The CLI looks alive.
The messages remain private.
The system is under my control.
```

## Best Build Order

Build in this order:

```txt
1. CLI identity and dashboard
2. local conUD runtime skeleton
3. local agent registration
4. local IPC API
5. local send/receive between two agents
6. pairing code flow
7. hosted WebSocket relay
8. remote runtime sessions
9. remote agent discovery
10. opaque message envelopes
11. stream API
12. watch animation
13. persistent trust store
14. encrypted payloads
15. delivery receipts and retries
16. QUIC direct transport
17. NAT traversal and relay upgrade
18. rooms and pub/sub
19. SDKs and MCP adapter
20. production observability
```

This gives us a working product early while still pointing toward the perfect target.

## Final Shape

```txt
conu CLI
  human control room

conUD
  local runtime and router

Agent Gateway
  simple full-power entrance for agents

conU Protocol
  control plane + data plane

conU Network
  direct P2P when possible, relay when needed

Agents
  keep their own intelligence, memory, tools, and meaning
```

The shortest definition:

```txt
conU is a private worldwide road for agents.
```

## References Checked

- A2A Protocol specification: https://a2a-protocol.org/latest/specification/
- A2A Core Concepts: https://a2a-protocol.org/latest/topics/key-concepts/
- A2A GitHub project: https://github.com/a2aproject/A2A
- Model Context Protocol architecture: https://modelcontextprotocol.io/docs/learn/architecture
- libp2p peers: https://libp2p.io/docs/peers/
- libp2p stream multiplexing: https://docs.libp2p.io/concepts/multiplex/overview/
- libp2p discovery and routing: https://libp2p.io/docs/discovery-routing-overview/
- libp2p DCUtR / hole punching: https://libp2p.io/docs/dcutr/
- libp2p pub/sub: https://libp2p.io/docs/pubsub/
- QUIC RFC 9000: https://www.ietf.org/rfc/rfc9000.html
- WebSocket RFC 6455: https://datatracker.ietf.org/doc/html/rfc6455
- Noise Protocol Framework: https://noiseprotocol.org/
- OpenTelemetry overview: https://opentelemetry.io/docs/what-is-opentelemetry/
