# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Status

Phase 15 is complete for the current local-first app, and this branch adds the first live relay-backed internet data-plane slice. The CLI identity/dashboard shell exists, `conu init` creates real local state and security keys, `conu start` launches the local `conUD` runtime skeleton, local agents can register signed metadata and presence, registered local agents can exchange encrypted-at-rest opaque message envelopes, users can exchange public peer cards, trusted peers can send peer-encrypted messages through `conu-relay`, streams produce payload-safe watch events, `conu security audit` reports hardened controls without showing secrets, agents can use conU through the Rust SDK, Python wrapper SDK, and MCP stdio adapter, conUD owns metadata-only direct/relay route selection, and release packaging/readiness checks now exist.

The repository currently contains compile-ready crate boundaries for:

- `conu-cli`: human control room.
- `conu-sdk`: Rust agent-facing API over conU local gateway surfaces.
- `conu-mcp`: MCP stdio adapter exposing conU as agent tools.
- `conud`: local daemon/runtime scaffold.
- `conu-core`: shared runtime primitives and project invariants.
- `conu-protocol`: protocol identities, agent cards, and opaque envelopes.
- `conu-relay`: std-only WebSocket relay MVP.

The runtime code still favors small std-first modules, but Phase 11 introduces audited crypto crates for encryption, signatures, hashing, randomness, and key agreement. On this Windows workstation, those dependencies require the GNU Rust toolchain for commands that compile build scripts or link tests until Visual Studio C++ Build Tools or CI are configured.

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
security/              local signing, exchange, storage, replay, and rotation files
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
routes/registry.toml   direct/relay route candidates and selected paths
routes/probes.toml     metadata-only route probe history
pairing/invites/       pending local pairing invitations
pairing/used/          consumed local pairing invitations
sessions/registry.toml remote runtime session metadata
mailbox/               future encrypted mailbox storage
mailbox/relay/outbox/  peer-encrypted outbound relay envelopes
mailbox/relay/sent/    metadata markers for relay-sent envelopes
mailbox/relay/rejected/ rejected relay outbox markers
logs/conud.log         runtime metadata log
logs/agents.log        local agent metadata log
logs/messages.log      local message delivery metadata log
logs/sessions.log      remote session sync metadata log
logs/streams.log       stream lifecycle metadata log
logs/routes.log        direct/relay route sync metadata log
logs/relay-delivery.log relay delivery metadata log
```

Runtime, agent, and message logs contain metadata only, such as event name, pid, node id, agent id, envelope id, byte count, and `payload=not_observed`. New local message request and recipient-inbox envelope files store conU-owned payload bytes with XChaCha20Poly1305 encrypted-at-rest fields. CLI output, receipts, processed markers, rejected markers, and logs do not display message contents.

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

Phase 6 added local-only message delivery between registered agents, and Phase 11 encrypts new conU-owned local payload storage:

```bash
conu messages send agent.sender agent.receiver --stdin
conu messages inbox agent.receiver
conu messages inbox agent.receiver --json
conu messages receipts
```

`conu messages send` reads bytes from stdin so payloads are not placed directly in the command line. When `conUD` is running, delivery is processed automatically. If the runtime is offline, encrypted message requests remain queued under `runtime/ipc/messages/inbox/` and can be processed with `conud --process-ipc`.

## Relay-Backed Remote Messages

conU can now move peer-encrypted message envelopes between two trusted nodes through the WebSocket relay:

```bash
conu identity export --json
conu peers trust <peer-node-id> <display-name> --exchange-key <hex> --relay ws://relay-host:8787
conu messages send agent.sender agent.remote --peer <peer-node-id> --stdin
conu relay sync --wait-ms 3000
```

Run `conu relay sync --wait-ms 10000` on the receiving node while the sender syncs. The relay sees node ids, agent ids, envelope id, byte count, public exchange key material, and ciphertext only. It does not receive plaintext message contents. See `docs/internet-relay-test.md` for a local two-node smoke and an internet test checklist.

## Security Hardening

Phase 11 adds the first production-facing security layer:

```bash
conu security audit
conu security audit --json
```

Implemented controls:

- Ed25519 node signing key for local agent-card signatures.
- X25519 node exchange key and peer key agreement helpers.
- XChaCha20Poly1305 local payload storage encryption.
- Replay cache for local message request and envelope ids.
- Local key rotation plan under `security/key-rotation.md`.

The audit reports readiness and key ids only. It never prints private keys, shared secrets, plaintext payloads, or decrypted payloads. See `docs/security-hardening.md` and `docs/production-readiness.md` for the hardening model and release blockers.

For practical user setup, installation, and current agent integration guidance, see `docs/user-install-and-agent-guide.md`.

## Release Readiness

Phase 15 adds packaging and local release checks:

```bash
conu doctor
conu doctor --json
```

Build local release artifacts:

Windows:

```powershell
.\scripts\build-release.ps1
# If MSVC Build Tools are not installed:
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

macOS/Linux:

```bash
./scripts/build-release.sh
```

The release artifact includes `conu`, `conud`, `conu-relay`, `conu-mcp`, docs, packaging templates, and a manifest that states `payload_contents_included = false`. Service templates live under `packaging/` for Windows, Linux systemd, and macOS launchd. See `docs/release-checklist.md`, `docs/observability.md`, and `packaging/README.md`.

## Pairing And Trust

Phase 7 adds local trust-store mechanics, and the relay data-plane adds manual public peer-card exchange:

```bash
conu pair
conu join 123456
conu peers
conu peers --json
conu peers revoke peer_example
conu identity export
conu peers trust node_example "Peer Node" --exchange-key <hex> --relay ws://127.0.0.1:8787
```

`conu pair` creates a short local invitation code with an expiration. `conu join <code>` consumes a local invitation and writes a trusted peer record to `trust.toml`. For cross-machine testing today, exchange `conu identity export --json` output with the other user and import their public card using `conu peers trust`. Trust records store public exchange keys and relay endpoints when available; private keys are never exported.

## WebSocket Relay

Phase 8 adds the `conu-relay` service and the shared relay frame contract in `conu-core`:

```bash
set CONU_RELAY_TOKEN=local-dev-token
cargo run -p conu-relay -- --serve 127.0.0.1:8787
```

Connected runtimes send `HELLO`, `FORWARD`, and `PING` frames. The relay answers with `WELCOME`, `ENVELOPE`, `SENT`, `UNDELIVERED`, `PONG`, or `ERROR` frames. Relay `FORWARD` can carry a peer-encrypted opaque body for message delivery, but plaintext payload fields are rejected and logs/output use `payload=not_observed`, `payload=opaque`, or `payload=peer_encrypted`.

The relay is available now as a standalone service for encrypted message sync. Full live stream byte routing, hosted relay auth hardening, offline relay mailbox storage, reconnect networking, and direct QUIC still land in later transport phases.

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

## Direct Routes And Relay Fallback

Phase 13 adds a route manager owned by conUD:

```bash
conu routes sync
conu routes
conu routes --json
conu routes probes
```

`conu routes sync` reads trusted peers and `config.toml`, scores direct QUIC candidates against relay WebSocket fallback, writes `routes/registry.toml`, appends metadata-only probes to `routes/probes.toml`, and records payload-safe summaries in `logs/routes.log`. Direct endpoints can be configured with `direct_quic_endpoint = "quic://host:port"` or a peer-specific sanitized key like `direct_quic_peer_abcd1234 = "quic://host:port"`.

This is route selection groundwork, not a full QUIC data plane yet. conU can now prefer a configured direct route and fall back to relay metadata, while live QUIC sockets and ICE-style hole punching remain future transport hardening. Relay-backed one-shot message delivery exists for trusted peers.

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

## SDK And MCP Adapter

Phase 12 adds agent-facing integrations:

```bash
cargo run -p conu-sdk --example local_agents
cargo run -p conu-mcp
```

Rust agents can use `conu_sdk::ConuClient` to register, update presence, list agents/peers, exchange peer cards, send local opaque bytes, queue remote relay messages, run relay sync, receive payload bytes for the addressed local agent, and open/write/close streams. Python agents can use the stdlib wrapper under `sdk/python`.

MCP-capable agents can launch `conu-mcp` as a stdio server. It exposes tools such as `conu_register_agent`, `conu_export_identity`, `conu_trust_peer`, `conu_send_message`, `conu_send_remote_message`, `conu_relay_sync`, `conu_receive_message`, `conu_open_stream`, and `conu_security_audit`. The adapter follows the current MCP stdio transport shape: newline-delimited JSON-RPC 2.0 messages on stdin/stdout. Tool list/send/status outputs remain metadata-only. Set `CONU_AGENT_ID` when launching one MCP server for one agent; then the adapter rejects attempts to act as another local agent. `conu_receive_message` returns payload bytes as `payloadHex` only when the addressed local agent explicitly passes `includePayload: true`.

See `docs/sdk-and-mcp.md` for SDK examples, MCP tool contracts, route tools, and privacy rules. See `docs/direct-transport-and-routes.md` for the Phase 13 route manager.

## Development

```bash
cargo fmt
cargo check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

On Windows machines without Visual Studio C++ Build Tools, use the GNU Rust toolchain for commands that link binaries or tests:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
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
cargo run -p conu-cli -- messages send agent.sender agent.remote --peer node_peer --stdin
cargo run -p conu-cli -- messages inbox agent.receiver --json
cargo run -p conu-cli -- messages receipts --json
cargo run -p conu-cli -- identity export --json
cargo run -p conu-cli -- relay sync --wait-ms 3000
cargo run -p conu-cli -- streams open agent.sender agent.receiver
cargo run -p conu-cli -- streams write stream_example --stdin
cargo run -p conu-cli -- streams close stream_example
cargo run -p conu-cli -- watch
cargo run -p conu-cli -- sessions sync
cargo run -p conu-cli -- sessions --json
cargo run -p conu-cli -- routes sync
cargo run -p conu-cli -- routes --json
cargo run -p conu-cli -- routes probes
cargo run -p conu-cli -- security audit
cargo run -p conu-cli -- security audit --json
cargo run -p conu-cli -- doctor
cargo run -p conu-cli -- doctor --json
cargo run -p conu-cli -- pair
cargo run -p conu-cli -- join 123456
cargo run -p conu-cli -- peers --json
cargo run -p conu-cli -- peers trust node_peer "Peer Node" --exchange-key <hex> --relay ws://127.0.0.1:8787
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
cargo run -p conu-sdk --example local_agents
cargo run -p conu-mcp
```

When running from a development checkout, build `conud` first or set `CONUD_EXE` to the local daemon binary before using `conu start`.

## Project Memory

Future agents should read:

1. `architecture.md`
2. `plan.md`
3. `.agents/AGENTS.md`
4. `.agents/repo/ABOUT.md`

Before PR or merge, use the repo-local PR and security guardian skills under `.agents/skills/`.
