# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Status

Phase 14 and Phase 15 are complete for the current local-first app, with rooms/pub/sub metadata, encrypted-at-rest local and relay-backed room event fanout, room topic publish/subscribe policy, a richer CLI control-room dashboard, local agent connect flows, and a hardened relay data path beyond the original MVP. The CLI identity/dashboard shell exists, `conu init` creates real local state and security keys, `conu start` launches the local `conUD` runtime, local agents can register signed metadata and presence, registered local agents can export signed public agent cards for trusted peers, remote signed agent cards can be imported after peer trust is established or exchanged automatically over encrypted relay control envelopes, registered local agents can exchange encrypted-at-rest opaque message envelopes, users can exchange signed public peer cards, trusted peers require explicit peer-scoped policy grants before sending peer-encrypted messages, stream chunks, or room events through `conu-relay`, conUD can automatically pump configured relay routes, and the relay enforces configurable connection and frame-rate limits plus offline scoped credential issuance, manifest upsert/rotate/revoke helpers, and live-reloaded hashed credential manifests while staying metadata-only. Streams and rooms produce payload-safe watch events, local metadata logs can be rotated, and local storage keys can be rotated or retired without displaying contents. `conu telemetry snapshot` exports only allowlisted local aggregate counters. Windows local secrets are wrapped with current-user DPAPI, `conu security audit` reports hardened controls without showing secrets, agents can use conU through the Rust SDK, Python wrapper SDK, TypeScript/JavaScript SDK, and MCP stdio adapter, conUD owns metadata-only direct/relay route selection, and release packaging/readiness checks now exist. The repo also contains an npm launcher package template and relay hosting docs for the first public distribution path.

The repository currently contains compile-ready crate boundaries for:

- `conu-cli`: human control room.
- `conu-sdk`: Rust agent-facing API over conU local gateway surfaces.
- `conu-mcp`: MCP stdio adapter exposing conU as agent tools.
- `conud`: local daemon/runtime scaffold.
- `conu-core`: shared runtime primitives and project invariants.
- `conu-protocol`: protocol identities, agent cards, and opaque envelopes.
- `conu-relay`: small plain WebSocket relay, with `wss://` supported by the client through TLS termination.

The runtime code still favors small std-first modules, but Phase 11 introduces audited crypto crates for encryption, signatures, hashing, randomness, and key agreement, and the relay client now uses platform TLS for `wss://`. On this Windows workstation, those dependencies require the GNU Rust toolchain for commands that compile build scripts or link tests until Visual Studio C++ Build Tools or CI are configured.

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
policy.toml            peer-scoped communication grants
agents/registry.toml   local agent registry skeleton
agents/remote.toml     signed or mirrored trusted remote agent cards
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
rooms/registry.toml    room, participant, topic, and multi-agent session metadata
rooms/events.toml      payload-safe room event bus
rooms/policy.toml      payload-safe room topic grants
routes/registry.toml   direct/relay route candidates and selected paths
routes/probes.toml     metadata-only route probe history
pairing/invites/       pending local pairing invitations
pairing/used/          consumed local pairing invitations
sessions/registry.toml remote runtime session metadata
mailbox/               local runtime relay outbox markers
mailbox/relay/outbox/  peer-encrypted outbound relay message, stream-chunk, room-event, and control envelopes
mailbox/relay/sent/    metadata markers for relay-sent envelopes
mailbox/relay/rejected/ rejected relay outbox markers
logs/conud.log         runtime metadata log
logs/agents.log        local agent metadata log
logs/messages.log      local message delivery metadata log
logs/sessions.log      remote session sync metadata log
logs/streams.log       stream lifecycle metadata log
logs/rooms.log         room/pub-sub metadata log
logs/routes.log        direct/relay route sync metadata log
logs/relay-delivery.log relay delivery metadata log
logs/*.log.N          rotated metadata log archives
```

Runtime, agent, and message logs contain metadata only, such as event name, pid, node id, agent id, envelope id, byte count, and `payload=not_observed`. `conu logs rotate` rotates local `.log` files by byte size and archive count while reporting only filenames, sizes, and counts; `conu doctor` scans active logs and rotated `.log.N` archives for known payload-leak terms without printing log contents. `conu telemetry snapshot --json` reports schema `conu.telemetry.snapshot.v1`, its explicit field allowlist, aggregate local counters, and `contentsDisplayed=false`; it does not include node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, secrets, or payload bodies. New local message request and recipient-inbox envelope files store conU-owned payload bytes with XChaCha20Poly1305 encrypted-at-rest fields. CLI output, receipts, processed markers, rejected markers, and logs do not display message contents.

## Local Agent Gateway

Phase 5 exposes a local, metadata-only gateway for agent registration and presence:

```bash
conu agents register agent.codex "Codex Desktop" --kind coding-agent --streams true --rooms true
conu agents heartbeat agent.codex --presence busy
conu agents export agent.codex --json
conu agents trust <remote-agent-id> "<remote name>" --node <trusted-peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id>
conu agents
conu agents --json
```

Agents default to message and presence capability only. Register with `--streams true` and/or `--rooms true` before using `conu connect local`, `conu streams`, or `conu rooms`; use `--messages false`, `--files true`, or `--presence false` only when an agent intentionally exposes that narrower surface.

`conu agents export --json` emits public signed agent-card metadata only: agent id, display name, node id, kind, capabilities, public signing key, and signature. A peer must already be trusted through `conu peers trust` before `conu agents trust` accepts that peer's signed remote agent card. The import verifies the signature, requires the card signing key to match the trusted peer card, and writes `agents/remote.toml` without displaying payload contents. When signed peer-card trust and at least one peer policy grant exist on both sides, conUD/session sync also exchanges these signed agent cards automatically over peer-encrypted relay control envelopes.

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

## Local Connect, Rooms, And Pub/Sub

Phase 14 adds the multi-agent room/session surface and improves the CLI control room:

```bash
conu connect
conu connect local agent.codex agent.hermes
conu rooms create room.dev "Dev Room" --agent agent.codex
conu rooms join room.dev agent.hermes
conu rooms policy room.dev agent.hermes build --publish true --subscribe false
conu rooms policy room.dev agent.codex build --publish false --subscribe true
conu rooms publish room.dev agent.hermes build --stdin
conu rooms events
conu watch
```

`conu connect local` opens a metadata-tracked local stream between two registered local agents. `conu rooms` creates shared room metadata, joins visible local or trusted remote agents, and publishes opaque room events by byte count. Joined local participants receive encrypted-at-rest event envelopes in their normal message inbox. Joined trusted remote participants receive peer-encrypted room event envelopes over the relay when their signed remote agent metadata advertises `rooms=true` and the trusted peer policy grants `rooms=true`. `conu rooms policy` can add metadata-only per-topic publish/subscribe grants; once any policy exists for a room/topic, that topic requires explicit publisher and subscriber grants. Room registry, event bus, policy file, CLI output, and logs contain room id, participant ids, topic, event id, route label, byte count, delivery count, grants, and timestamps only. They do not store or print payload text.

Current room delivery supports local pub/sub fanout, relay-backed room event fanout to joined trusted remote agents, and explicit per-topic publish/subscribe grants for configured topics. Unconfigured topics keep the existing room membership boundary for compatibility. Remote stream writes to mirrored trusted agents can travel as peer-encrypted `stream_chunk` inbox envelopes over the relay; direct QUIC stream sessions remain future transport work.

## Relay-Backed Remote Messages And Streams

conU can now move peer-encrypted message, stream-chunk, and room-event envelopes between two trusted nodes through the WebSocket relay:

```bash
conu identity export --json
conu peers trust <peer-node-id> <display-name> --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
conu start
conu messages send agent.sender agent.remote --peer <peer-node-id> --stdin
conu streams open agent.sender <remote-agent-id-with-streams>
conu streams write <stream-id> --stdin
```

`conu identity export --json` includes public exchange material plus a signed peer-card integrity proof. `conu peers trust` verifies that signature when the signing fields are supplied; older unsigned imports still work for controlled legacy tests but are not the preferred production path. Trust is not authorization by itself: `conu peers policy` records explicit metadata-only grants for messages, streams, rooms, files, and mailbox surfaces, and missing policy records deny by default. After signed peer trust and policy grants, conUD/session sync queues local signed agent cards for encrypted relay exchange so remote stream and room metadata is backed by a signed agent card rather than a placeholder mirror. Manual `conu agents export` / `conu agents trust` remains available for daemonless or controlled fallback flows. Run `conu start` on both nodes after `default_relay` or trusted peer relay endpoints are configured. conUD keeps a relay WebSocket session open across runtime ticks when the endpoint is stable, retries on failures, flushes pending outbound envelopes, receives inbound peer-encrypted envelopes, and imports verified signed agent cards. If that same daemon process reconnects to the same relay endpoint after a socket drop, it can present the prior session id as a resume hint; the relay accepts it only for the same node and accounts resumed sessions without logging session ids or payloads. Stream chunks require the local sender and remote target metadata to advertise `streams=true`, and the trusted peer policy must grant `streams=true`. Room events require the local publisher and remote target metadata to advertise `rooms=true`, and the trusted peer policy must grant `rooms=true`. Stream chunks arrive in the addressed agent inbox with `kind = "stream_chunk"` and `stream_id` metadata; room events arrive with `kind = "event"` and payload-safe room event metadata. Payload bytes remain available only through explicit receive APIs for that agent. `conu relay sync --wait-ms 3000` remains available as an explicit manual flush/debug command. The relay sees node ids, agent ids, envelope id, optional stream id, byte count, public exchange key material, and ciphertext only. It does not receive plaintext message, stream, room-event, or signed-card contents. See `docs/internet-relay-test.md` and `scripts/smoke-relay-daemon.ps1` for local two-node smoke coverage and an internet test checklist.

If the target runtime is offline, `conu-relay` can hold peer-encrypted message, stream-chunk, or room-event envelopes in a bounded mailbox and deliver them when that node reconnects. The default mailbox is memory-only. Set `CONU_RELAY_MAILBOX_DIR` on the relay to persist ciphertext envelope files across relay restarts; the stored files contain route metadata, public key material, ciphertext, and `payload_displayed = false`, never plaintext message, stream, or room-event contents. Set `CONU_RELAY_ACCOUNTING_DIR` to persist metadata-only per-node counters for authenticated and resumed sessions, sent/received bytes, and mailbox accepts, and optionally set per-window sent-envelope or sent-byte quotas. Managed hosted retention dashboards and distributed replay/resume policy remain future work.

## Security Hardening

Phase 11 adds the first production-facing security layer:

```bash
conu security audit
conu security audit --json
conu security rotate identity --confirm-peer-refresh
conu security retire identity --confirm-peer-refresh-complete
conu security rotate storage --confirm
conu security retire storage --confirm
```

Implemented controls:

- Ed25519 node signing key for local agent-card signatures.
- Signed public local agent-card export/import for trusted peers.
- Ed25519-signed public peer cards for manual cross-machine trust integrity.
- X25519 node exchange key and peer key agreement helpers.
- XChaCha20Poly1305 local payload storage encryption.
- Windows current-user DPAPI wrapping for local signing, exchange, and storage secret bytes, with migration-compatible reads for older plaintext-hex key files.
- Identity signing/exchange rotation through `conu security rotate identity --confirm-peer-refresh`, with old keys archived under `security/identity-keys/` and refreshed peer-card handoff required.
- Identity archive retirement through `conu security retire identity --confirm-peer-refresh-complete` after refreshed peer cards have been redistributed and old-key decrypt compatibility is no longer required.
- Storage-key rotation for conU-owned encrypted-at-rest message queue and inbox files, with old storage keys archived under `security/storage-keys/` for read compatibility.
- Storage-key retirement for archived keys that no scanned local encrypted-at-rest message queue or inbox file still references.
- Replay cache for local message request and envelope ids.
- Local key rotation plan under `security/key-rotation.md`.

The audit reports readiness, key ids, secret storage backend, and whether local secrets are OS-protected. Identity rotation, identity archive retirement, storage-key rotation, and storage-key retirement report only key ids, refresh requirements, booleans, and file/key counts. These commands do not print private keys, shared secrets, plaintext payloads, or decrypted payloads. See `docs/security-hardening.md` and `docs/production-readiness.md` for the hardening model and release blockers.

For practical user setup, installation, hosting, and current agent integration guidance, see `docs/user-install-and-agent-guide.md` and `docs/distribution-and-hosting.md`.

## Release Readiness

Phase 15 adds packaging and local release checks:

```bash
conu doctor
conu doctor --json
conu logs rotate --max-bytes 1048576 --keep 5
conu telemetry snapshot --json
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

The release artifact includes `conu`, `conud`, `conu-relay`, `conu-mcp`, docs, packaging templates, checksum files, and a manifest that states `payload_contents_included = false`. Service templates live under `packaging/` for Windows, Linux systemd, macOS launchd, Docker relay hosting, and the npm launcher package. Tagged release builds generate GitHub artifact attestations for each archive and checksum file. See `docs/release-checklist.md`, `docs/observability.md`, `docs/distribution-and-hosting.md`, and `packaging/README.md`.

The intended public one-command install path is:

```bash
npm install -g @conu/cli
conu doctor
```

That npm package is a thin native-binary launcher. Rust remains the product; npm only downloads the matching checksummed release asset and exposes the commands on `PATH`.

## Pairing And Trust

Phase 7 adds local trust-store mechanics, and the relay data-plane adds signed manual public peer-card exchange:

```bash
conu pair
conu join 123456
conu peers
conu peers --json
conu peers revoke peer_example
conu identity export
conu peers trust node_example "Peer Node" --exchange-key <hex> --relay ws://127.0.0.1:8787 --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers trust node_example "Peer Node" --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu agents export agent.codex --json
conu agents trust agent.remote "Remote Agent" --node node_example --kind coding-agent --signing-key <hex> --signature <hex> --signature-key-id <id>
```

`conu pair` creates a short local invitation code with an expiration. `conu join <code>` consumes a local invitation and writes a trusted peer record to `trust.toml`. For cross-machine testing today, exchange `conu identity export --json` output with the other user, import their public card using `conu peers trust`, grant the intended communication surfaces with `conu peers policy`, and let conUD/session sync exchange signed public agent cards automatically. Manual `conu agents export --json` and `conu agents trust` remain useful for offline fallback. Trust records store public exchange keys, relay endpoints, and peer-card signature metadata when available; policy records store boolean grants only; private keys are never exported.

## WebSocket Relay

Phase 8 adds the `conu-relay` service and the shared relay frame contract in `conu-core`:

```bash
set CONU_RELAY_TOKEN=local-dev-token
cargo run -p conu-relay -- --serve 127.0.0.1:8787
```

Connected runtimes send `HELLO`, `FORWARD`, and `PING` frames. `HELLO` may include an optional same-node resume hint; `WELCOME` reports whether the relay accepted it. The relay answers with `WELCOME`, `ENVELOPE`, `SENT`, `UNDELIVERED`, `PONG`, or `ERROR` frames. Relay `FORWARD` can carry a peer-encrypted opaque body for message delivery, stream chunks, room events, and signed-card control envelopes, but plaintext payload fields are rejected and logs/output use `payload=not_observed`, `payload=opaque`, or `payload=peer_encrypted`.

`conu-relay` also accepts `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, and `CONU_RELAY_MAX_FRAMES_PER_MINUTE` for basic abuse controls, plus `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE`, `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`, and optional `CONU_RELAY_MAILBOX_DIR` for bounded durable ciphertext mailbox storage. `CONU_RELAY_ACCOUNTING_DIR` persists metadata-only per-node accounting files, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS` sets the quota window, and `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE` / `CONU_RELAY_MAX_BYTES_SENT_PER_NODE` can reject over-quota sends with `UNDELIVERED reason=quota_exceeded`. The relay is available now as a standalone service for encrypted message, stream-chunk, room-event, and signed-card sync, and conUD owns a reusable relay session when a relay or trusted relay peer is configured. Same-process reconnects can resume a prior same-node relay session on the same endpoint; cross-node resume attempts mint a new session instead. A self-hosted relay can issue scoped credential tokens offline, live-reload a scoped credential manifest with hashed tokens, active/revoked status, and optional expiry metadata on new `HELLO` authentication attempts. Existing authenticated sessions remain governed by idle timeout and max TTL. Managed hosted account auth, online credential issuance APIs, hosted dashboards/abuse response, distributed hosted session state, and direct QUIC still land in later transport phases.

For self-hosted multi-node relays, prefer a scoped credential manifest so the server does not keep raw relay tokens in long-lived environment variables:

```powershell
conu-relay --issue-credential node_a --token-out C:\conu-relay\node_a.token --credentials-file C:\conu-relay\credentials.toml
conu-relay --issue-credential node_b --token-out C:\conu-relay\node_b.token --credentials-file C:\conu-relay\credentials.toml
```

The raw token is written only to the token file, not stdout. With `--credentials-file`, the relay manifest is created or appended with hashed token metadata without printing the manifest contents. Omit `--credentials-file` only when you want a hashed `manifest entry` block for manual copy.

```toml
version = "1"

[[credential]]
node_id = "node_a"
token_sha256_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
token_length = 64
status = "active"
payload_displayed = false
token_displayed = false

[[credential]]
node_id = "node_b"
token_sha256_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
token_length = 64
status = "active"
payload_displayed = false
token_displayed = false
```

```bash
set CONU_RELAY_CREDENTIALS_FILE=C:\conu-relay\credentials.toml
set CONU_RELAY_IDLE_TIMEOUT_SECONDS=120
set CONU_RELAY_SESSION_TTL_SECONDS=3600
set CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE=128
set CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS=3600
set CONU_RELAY_MAILBOX_DIR=C:\conu-relay\mailbox
set CONU_RELAY_ACCOUNTING_DIR=C:\conu-relay\accounting
set CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400
set CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000
set CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824
```

`CONU_RELAY_CREDENTIALS_FILE` overrides `CONU_RELAY_CREDENTIALS`, which remains available as comma-separated `node-id:token` compatibility config and overrides the shared `CONU_RELAY_TOKEN` on the server. The relay reloads the credential file for each new `HELLO`, so marking a credential `revoked` or setting an expired `expires_at_unix` rejects new sessions without a relay restart. `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` generates a strong scoped token, writes it to a new token file, and upserts only hashed manifest metadata. Use `--replace` with the same command to rotate an existing node credential, and use `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a node revoked without printing token material. `conu-relay --hash-token` remains available when an operator already has a token. Each runtime can set `CONU_RELAY_TOKEN` to its assigned scoped token, or store it locally without putting it in shell history:

```powershell
Get-Content -Raw C:\conu-relay\node_a.token | conu relay credential set --stdin
conu relay credential status
```

At runtime, `CONU_RELAY_TOKEN` overrides the stored credential; if neither is present, conU falls back to `local-dev-token` for loopback tests. On Windows, stored relay credentials use the same current-user DPAPI wrapping as local key files. On non-Windows, set `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` to wrap stored relay credentials and local key files under an operator-managed XChaCha20Poly1305 key; otherwise conU uses owner-only local files until native platform keychain support lands. `local-dev-token` is accepted only for loopback relay binds. Any non-loopback bind such as `0.0.0.0:8787` requires a custom shared token or scoped credential token with at least 24 characters.

Relay clients accept `ws://` and `wss://` endpoints. The bundled `conu-relay` server still listens as a plain WebSocket service; public `wss://` deployments should terminate TLS with a certificate-valid reverse proxy or load balancer in front of `conu-relay`.

## Remote Sessions And Discovery

Phase 9 adds a conUD-owned remote session mirror for trusted peers:

```bash
conu sessions sync
conu sessions
conu sessions --json
conu agents --json
```

`conu sessions sync` reads trusted peers, writes route/session metadata under `sessions/registry.toml`, mirrors visible remote agent cards into `agents/remote.toml`, and appends only metadata to `logs/sessions.log`. `conUD --process-ipc`, `conUD --once`, and the runtime serve loop also sync remote sessions.

This phase is still metadata/discovery groundwork: `conu sessions sync` preserves imported signed remote agent cards for trusted peers and falls back to a placeholder mirror only when no signed agent cards have been imported for that peer. Payloads remain opaque and are never displayed by session or agent listing commands.

## Direct Routes And Relay Fallback

Phase 13 adds a route manager owned by conUD:

```bash
conu routes sync
conu routes
conu routes --json
conu routes probes
```

`conu routes sync` reads trusted peers and `config.toml`, records direct QUIC candidates against relay WebSocket fallback, writes `routes/registry.toml`, appends metadata-only probes to `routes/probes.toml`, and records payload-safe summaries in `logs/routes.log`. Direct endpoints can be configured with `direct_quic_endpoint = "quic://host:port"` or a peer-specific sanitized key like `direct_quic_peer_abcd1234 = "quic://host:port"`.

This is route selection groundwork, not a full QUIC data plane yet. conU records configured direct candidates as unavailable with `direct_quic_transport_inactive` and keeps relay selected for delivery until live QUIC sockets and ICE-style hole punching exist. Relay-backed message, stream-chunk, and room-event delivery exists for trusted peers.

## Streams And Watch

Phase 10 adds stream lifecycle metadata and a private watch view:

```bash
conu streams
conu streams open agent.sender agent.receiver
conu streams write stream_example --stdin
conu streams close stream_example
conu watch
```

`conu streams write` reads chunk bytes from stdin, records byte counts, updates backpressure metadata, and appends watch events without storing or printing the chunk contents. For mirrored trusted remote agents on relay routes, the chunk is peer-encrypted into the relay outbox and delivered as a `stream_chunk` inbox envelope. `conu watch` shows route, stream id, packet count, byte count, and an ASCII private-packet flow only.

The stream layer is still metadata-first. Relay chunks are point-in-time encrypted envelopes, not a full direct QUIC stream session; direct stream transport remains future hardening work.

## SDK And MCP Adapter

Phase 12 adds agent-facing integrations:

```bash
cargo run -p conu-sdk --example local_agents
cargo run -p conu-mcp
npm run check --prefix sdk/typescript
```

Rust agents can use `conu_sdk::ConuClient` to register, update presence, list agents/peers, exchange peer cards, send local opaque bytes, queue remote relay messages, optionally run relay sync, receive payload bytes for the addressed local agent, open/write/close streams, and create/join/publish room metadata events with optional topic policy grants. Python agents can use the stdlib wrapper under `sdk/python`. TypeScript and JavaScript agents can use the dependency-free Node wrapper under `sdk/typescript` as `@conu/sdk`; it wraps installed `conu`/`conud`/`conu-mcp` binaries, passes payload bytes through stdin, returns metadata-only command results for normal list/status surfaces, and exposes raw inbox bytes only through explicit addressed-agent receive helpers. `@conu/sdk` is not browser-native protocol support; browser-conditioned imports fail closed through a safe unsupported stub until hosted auth, browser transport, and key-handling rules exist.

MCP-capable agents can launch `conu-mcp` as a stdio server. It exposes tools such as `conu_register_agent`, `conu_export_identity`, `conu_trust_peer`, `conu_set_peer_policy`, `conu_send_message`, `conu_send_remote_message`, `conu_relay_sync`, `conu_receive_message`, `conu_open_stream`, `conu_create_room`, `conu_join_room`, `conu_set_room_topic_policy`, `conu_publish_room_event`, and `conu_security_audit`. The adapter follows the current MCP stdio transport shape: newline-delimited JSON-RPC 2.0 messages on stdin/stdout. Tool list/send/status/room outputs remain metadata-only. Set `CONU_AGENT_ID` when launching one MCP server for one agent; then the adapter rejects attempts to act as another local agent. `conu_receive_message` returns payload bytes as `payloadHex` only when the addressed local agent explicitly passes `includePayload: true`.

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
powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu
powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Useful CLI commands:

```bash
cargo run -p conu-cli --
cargo run -p conu-cli -- init
cargo run -p conu-cli -- status
cargo run -p conu-cli -- status --json
cargo run -p conu-cli -- agents
cargo run -p conu-cli -- agents --json
cargo run -p conu-cli -- agents register agent.codex "Codex Desktop" --kind coding-agent --streams true --rooms true
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
cargo run -p conu-cli -- connect local agent.sender agent.receiver
cargo run -p conu-cli -- rooms create room.dev "Dev Room" --agent agent.sender
cargo run -p conu-cli -- rooms join room.dev agent.receiver
cargo run -p conu-cli -- rooms publish room.dev agent.receiver build --stdin
cargo run -p conu-cli -- rooms events
cargo run -p conu-cli -- watch
cargo run -p conu-cli -- sessions sync
cargo run -p conu-cli -- sessions --json
cargo run -p conu-cli -- routes sync
cargo run -p conu-cli -- routes --json
cargo run -p conu-cli -- routes probes
cargo run -p conu-cli -- security audit
cargo run -p conu-cli -- security audit --json
cargo run -p conu-cli -- security rotate identity --confirm-peer-refresh
cargo run -p conu-cli -- identity export --json
cargo run -p conu-cli -- security retire identity --confirm-peer-refresh-complete
cargo run -p conu-cli -- security rotate storage --confirm
cargo run -p conu-cli -- security retire storage --confirm
cargo run -p conu-cli -- doctor
cargo run -p conu-cli -- doctor --json
cargo run -p conu-cli -- logs rotate --max-bytes 1048576 --keep 5
cargo run -p conu-cli -- telemetry snapshot --json
cargo run -p conu-cli -- pair
cargo run -p conu-cli -- join 123456
cargo run -p conu-cli -- peers --json
cargo run -p conu-cli -- peers trust node_peer "Peer Node" --exchange-key <hex> --relay ws://127.0.0.1:8787 --signing-key <hex> --signature <hex> --signature-key-id <id>
cargo run -p conu-cli -- peers trust node_peer "Peer Node" --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
cargo run -p conu-cli -- peers policy node_peer --messages true --streams true --rooms true
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
