# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Status

Phase 7 is complete. The CLI identity/dashboard shell exists, `conu init` creates real local state, `conu start` launches the local `conUD` runtime skeleton, local agents can register metadata and presence, registered local agents can exchange opaque message envelopes, and local pairing/trust records can be created and revoked.

The repository currently contains compile-ready crate boundaries for:

- `conu-cli`: human control room.
- `conud`: local daemon/runtime scaffold.
- `conu-core`: shared runtime primitives and project invariants.
- `conu-protocol`: protocol identities, agent cards, and opaque envelopes.
- `conu-relay`: relay/bootstrap scaffold.

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
runtime/status.toml    conUD heartbeat/status metadata
runtime/conud.lock     local runtime process lock
runtime/stop.request   graceful shutdown request file
runtime/ipc/inbox/     metadata-only agent gateway requests
runtime/ipc/processed/ processed gateway requests
runtime/ipc/rejected/  rejected gateway requests and safe reasons
runtime/ipc/messages/  opaque local message request queue
messages/inbox/        delivered local opaque envelopes by recipient agent
messages/receipts/     metadata-only local delivery receipts
pairing/invites/       pending local pairing invitations
pairing/used/          consumed local pairing invitations
sessions/              future runtime sessions
mailbox/               future encrypted mailbox storage
logs/conud.log         runtime metadata log
logs/agents.log        local agent metadata log
logs/messages.log      local message delivery metadata log
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

`conu pair` creates a short local invitation code with an expiration. `conu join <code>` consumes a local invitation and writes a trusted peer record to `trust.toml`. Peer ids and display names are derived from a hash suffix, and the trust store records `pairing_code_hash` instead of the raw used code. Relay-backed cross-machine pairing starts in Phase 8.

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
```

When running from a development checkout, build `conud` first or set `CONUD_EXE` to the local daemon binary before using `conu start`.

## Project Memory

Future agents should read:

1. `architecture.md`
2. `plan.md`
3. `.agents/AGENTS.md`
4. `.agents/repo/ABOUT.md`

Before PR or merge, use the repo-local PR and security guardian skills under `.agents/skills/`.
