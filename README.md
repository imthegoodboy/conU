# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Status

Phase 10 is complete. The CLI identity/dashboard shell exists, `conu init` creates real local state, `conu start` launches the local `conUD` runtime skeleton, local agents can register metadata and presence, registered local agents can exchange opaque message envelopes, local pairing/trust records can be created and revoked, `conu-relay` can accept WebSocket runtime sessions for metadata-only relay forwarding, conUD can sync remote session/discovery metadata for trusted peers, and streams now produce payload-safe watch events.

The repository currently contains compile-ready crate boundaries for:

- `conu-cli`: human control room.
- `conud`: local daemon/runtime scaffold.
- `conu-core`: shared runtime primitives and project invariants.
- `conu-protocol`: protocol identities, agent cards, and opaque envelopes.
- `conu-relay`: std-only WebSocket relay MVP.

This phase is intentionally std-only so the workspace validates on Windows machines that have Rust installed but do not yet have the Visual Studio C++ linker/Windows SDK configured. Production dependencies such as clap, Tokio, tracing, and serde should be introduced in the relevant future phases once linker support is available locally or in CI.

## Local State

`conu init` creates the Phase 3 state store:

```txt
%APPDATA%\conU\        Windows default
~/.conu/               Unix fallback
```

Set `CONU_HOME` to use a different directory for development or smoke checks.

```txt
node.toml              local node id only, not a secret or auth credential
config.toml            local runtime config skeleton
trust.toml             trusted/revoked peer skeleton
agents/registry.toml   local agent registry skeleton
agents/remote.toml     mirrored trusted remote agent cards
runtime/status.toml    conUD heartbeat/status metadata
runtime/conud.lock     local runtime process lock
runtime/stop.request   graceful shutdown request file
runtime/ipc/inbox/     metadata-only agent gateway requests
runtime/ipc/processed/ processed gateway requests
runtime/ipc/rejected/  rejected gateway requests and safe reasons
runtime/ipc/messages/  opaque local message request queue
messages/inbox/        delivered local opaque envelopes by recipient agent
messages/receipts/     metadata-only local delivery receipts
streams/registry.toml  stream lifecycle metadata
streams/events.toml    payload-safe watch event bus
pairing/invites/       pending local pairing invitations
pairing/used/          consumed local pairing invitations
sessions/registry.toml remote runtime session metadata
mailbox/               future encrypted mailbox storage
logs/conud.log         runtime metadata log
logs/agents.log        local agent metadata log
logs/messages.log      local message delivery metadata log
logs/sessions.log      remote session sync metadata log
logs/streams.log       stream lifecycle metadata log
```

Runtime, agent, and message logs contain metadata only, such as event name, pid, node id, agent id, envelope id, byte count, and `payload=not_observed`. Phase 6 local message payload bytes are stored only as opaque recipient-inbox envelope data; CLI output, receipts, processed markers, rejected markers, and logs do not display message contents. Until encryption hardening lands in Phase 11, agents should prefer already-encrypted payload bytes for sensitive local messages.

## Local Agent Gateway

Phase 5 exposes a local, metadata-only gateway for agent registration and presence:

```bash
conu agents register agent.codex "Codex Desktop" --kind coding-agent
conu agents heartbeat agent.codex --presence busy
conu agents
conu agents --json
```

When `conUD` is running, it processes pending requests from `runtime/ipc/inbox/` and moves them to `processed/` or `rejected/`. Without a running daemon, requests remain queued and can be processed manually:

```bash
conud --process-ipc
```

## Local Opaque Messages

Phase 6 adds local-only message delivery between registered agents:

```bash
conu messages send agent.sender agent.receiver --stdin
conu messages inbox agent.receiver
conu messages inbox agent.receiver --json
conu messages receipts
```

`conu messages send` reads bytes from stdin so payloads are not placed directly in the command line. When `conUD` is running, delivery is processed automatically. If the runtime is offline, message requests remain queued under `runtime/ipc/messages/inbox/` and can be processed with `conud --process-ipc`.

## Pairing And Trust

Phase 7 adds local trust-store mechanics before the hosted relay exists:

```bash
conu pair
conu join 123456
conu peers
conu peers --json
conu peers revoke peer_example
```

`conu pair` creates a short local invitation code with an expiration. `conu join <code>` consumes a local invitation and writes a trusted peer record to `trust.toml`. Peer ids and display names are derived from a hash suffix, and the trust store records `pairing_code_hash` instead of the raw used code. Cross-machine pairing remains local-trust groundwork until remote sessions and discovery are wired into conUD.

## WebSocket Relay

Phase 8 adds the `conu-relay` service and the shared relay frame contract in `conu-core`:

```bash
set CONU_RELAY_TOKEN=local-dev-token
cargo run -p conu-relay -- --serve 127.0.0.1:8787
```

Connected runtimes send `HELLO`, `FORWARD`, and `PING` frames. The relay answers with `WELCOME`, `ENVELOPE`, `SENT`, `UNDELIVERED`, `PONG`, or `ERROR` frames. Forwarding is metadata-only: the relay sees target node id, envelope id, and byte count, while payload fields are rejected and logs/output use `payload=not_observed` or `payload=opaque`.

The relay is available now as a standalone service. Full relay-backed live session exchange, reconnect networking, and encrypted payload hardening land in later phases.

## Remote Sessions And Discovery

Phase 9 adds a conUD-owned remote session mirror for trusted peers:

```bash
conu sessions sync
conu sessions
conu sessions --json
conu agents --json
```

`conu sessions sync` reads trusted peers, writes route/session metadata under `sessions/registry.toml`, mirrors visible remote agent cards into `agents/remote.toml`, and appends only metadata to `logs/sessions.log`. `conUD --process-ipc`, `conUD --once`, and the runtime serve loop also sync remote sessions.

This phase is still metadata/discovery groundwork: remote agent cards are derived from trusted peer metadata until the full relay-backed session exchange lands. Payloads remain opaque and are never displayed by session or agent listing commands.

## Streams And Watch

Phase 10 adds stream lifecycle metadata and a private watch view:

```bash
conu streams
conu streams open agent.sender agent.receiver
conu streams write stream_example --stdin
conu streams close stream_example
conu watch
```

`conu streams write` reads chunk bytes from stdin, records byte counts, updates backpressure metadata, and appends watch events without storing or printing the chunk contents. `conu watch` shows route, stream id, packet count, byte count, and an ASCII private-packet flow only.

The stream layer is still metadata-first. Full live relay-backed byte streaming and encrypted stream transport are future hardening/transport work.

## Development

```bash
cargo fmt
cargo check
cargo test
```

On Windows machines without Visual Studio C++ Build Tools, use the GNU Rust toolchain for commands that link binaries or tests:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

Useful CLI commands:

```bash
cargo run -p conu-cli --
cargo run -p conu-cli -- init
cargo run -p conu-cli -- status
cargo run -p conu-cli -- status --json
cargo run -p conu-cli -- agents
cargo run -p conu-cli -- agents --json
cargo run -p conu-cli -- agents register agent.codex "Codex Desktop" --kind coding-agent
cargo run -p conu-cli -- agents heartbeat agent.codex --presence busy
cargo run -p conu-cli -- messages send agent.sender agent.receiver --stdin
cargo run -p conu-cli -- messages inbox agent.receiver --json
cargo run -p conu-cli -- messages receipts --json
cargo run -p conu-cli -- streams open agent.sender agent.receiver
cargo run -p conu-cli -- streams write stream_example --stdin
cargo run -p conu-cli -- streams close stream_example
cargo run -p conu-cli -- watch
cargo run -p conu-cli -- sessions sync
cargo run -p conu-cli -- sessions --json
cargo run -p conu-cli -- pair
cargo run -p conu-cli -- join 123456
cargo run -p conu-cli -- peers --json
cargo run -p conu-cli -- peers revoke peer_example
cargo run -p conu-cli -- connect
cargo run -p conu-cli -- watch
cargo run -p conu-cli -- start
cargo run -p conu-cli -- stop
cargo run -p conud -- --check
cargo run -p conud -- --once
cargo run -p conud -- --process-ipc
cargo run -p conu-relay -- --check
cargo run -p conu-relay -- --serve 127.0.0.1:8787
```

When running from a development checkout, build `conud` first or set `CONUD_EXE` to the local daemon binary before using `conu start`.

## Project Memory

Future agents should read:

1. `architecture.md`
2. `plan.md`
3. `.agents/AGENTS.md`
4. `.agents/repo/ABOUT.md`

Before PR or merge, use the repo-local PR and security guardian skills under `.agents/skills/`.
