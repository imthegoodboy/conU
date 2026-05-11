# Implementation Guardrails

## Architecture Boundaries

- CLI is the human control room.
- conUD is the runtime and router.
- Agent Gateway is the local entrance for agents.
- Protocol types define stable control-plane and data-plane messages.
- Relay helps discovery and delivery, but does not read payloads.

## Rust Defaults

- Use Rust for runtime, CLI, protocol, and relay components.
- Use Tokio for async runtime.
- Use clap for CLI parsing.
- Use serde for config and local state.
- Use binary protocol encoding for runtime hot paths when the protocol stabilizes.
- Use WebSocket relay first for worldwide connectivity.
- Add QUIC/direct transport after core semantics are stable.

## Local Windows Toolchain Note

This workspace was first validated on Windows where the default MSVC Rust toolchain existed but Visual Studio C++ Build Tools / `link.exe` were not available. In that environment:

- `cargo check --workspace --all-targets` works with the default MSVC toolchain for std-only code.
- `cargo test` and `cargo run` require a linker.
- `rustup toolchain install stable-x86_64-pc-windows-gnu` provided a working local linker path.
- Use `cargo +stable-x86_64-pc-windows-gnu test --workspace` and matching `cargo +... run` commands until MSVC Build Tools or CI are configured.

Do not add proc-macro/build-script-heavy dependencies unless validation can still run in the active environment or CI.

## Local State Rules

- `CONU_HOME` overrides the default state directory and should be used for smoke checks.
- Windows defaults to `%APPDATA%\conU`; non-Windows falls back to `$HOME/.conu`.
- Tests should pass an explicit state home instead of mutating global process environment.
- The Phase 3 node id is a local runtime identifier only. It is not a secret, not an authentication credential, and not a replacement for future signed/encrypted identity.
- conU-owned state must not store plaintext private payloads.

## Local Runtime Rules

- Phase 4 runtime health is file-backed: `runtime/status.toml`, `runtime/conud.lock`, and `runtime/stop.request`.
- `conu start` should launch `conud --serve`; in development, set `CONUD_EXE` when the daemon binary is not beside the CLI binary.
- `conu stop` requests graceful shutdown by writing a stop request; conUD owns final stopped state and lock cleanup.
- Treat stale heartbeats as restartable runtime metadata, not proof of a live process.
- Runtime logs must remain payload-safe and use metadata-only lines such as event, pid, node id, and `payload=not_observed`.

## Local Agent Gateway Rules

- Phase 5 local gateway is file-backed and metadata-only: `runtime/ipc/inbox`, `runtime/ipc/processed`, and `runtime/ipc/rejected`.
- Accepted Phase 5 request types are only `register_agent` and `presence_heartbeat`.
- Registration may store agent id, display name, kind, node id, presence, last seen time, and capability booleans.
- Presence heartbeat may update only an already registered local agent.
- Rejected requests must not echo arbitrary request contents into CLI output, logs, tests, or `.error` files.
- Agent logs must use metadata-only lines such as event, agent id, and `payload=not_observed`.
- Do not add message send/receive, payload storage, remote discovery, or relay behavior to the Phase 5 registration inbox; Phase 6+ message work belongs in separate message routing modules and queues.

## Local Message Routing Rules

- Phase 6 local messages use a separate file-backed queue under `runtime/ipc/messages/`.
- CLI message send must read payload bytes from stdin or a future SDK/gateway API, not from a direct command-line text argument.
- Sender and recipient must both be registered local agents before conUD delivers an envelope.
- Recipient inbox files may store opaque payload bytes for local delivery, but all CLI, log, receipt, processed-marker, and rejected-marker surfaces must show metadata only.
- Rejected message requests must delete the original payload-bearing request and write only a safe reason.
- Message logs must use metadata-only lines such as envelope id, from, to, byte count, and `payload=not_observed`.
- Do not add remote message routing, relay forwarding, discovery, streams, or rooms while completing Phase 6.

## Pairing And Trust Rules

- Phase 7 pairing is local trust-store groundwork only; Phase 8 adds the relay service, while conUD-backed cross-machine pairing/session wiring remains later work.
- `conu pair` may display a fresh short code once, but peers listing and trust records must not expose the raw used pairing code.
- Store `pairing_code_hash` in `trust.toml`, not `pairing_code`.
- Trusted peer ids and display names should be derived from a hash suffix, not from the raw six-digit code.
- `conu join <code>` should create a trusted peer only when the local invitation exists, is pending, and is not expired.
- Revocation must preserve the peer record with `status = "revoked"` so future agents can reason about trust history.

## Relay Rules

- Phase 8 relay is a std-only WebSocket MVP in `crates/conu-relay` with its frame contract in `conu_core::relay`.
- Runtime clients must authenticate with `HELLO node=<id> token=<token> payload=not_observed` before forwarding.
- `FORWARD` frames may include target node id, envelope id, byte count, and `payload=opaque`; they must not include plaintext payload fields.
- Relay server output, errors, tests, and logs must not echo auth tokens or private payload contents.
- The relay may return `UNDELIVERED reason=peer_offline` when the target runtime is not connected; do not add mailbox storage until the encrypted mailbox phase.
- On Windows, accepted streams from a nonblocking listener must be set back to blocking mode before frame reads.
- `conu-relay` alone is not a live remote-agent connection; conUD session/discovery mirrors begin in Phase 9 and live stream routing remains later work.

## Remote Session And Discovery Rules

- Phase 9 remote sessions are file-backed metadata mirrors in `conu_core::sessions`.
- conUD owns session sync; CLI commands may request sync or display the mirror but must not inspect payloads.
- Remote session state belongs under `sessions/registry.toml`; mirrored remote agent cards belong under `agents/remote.toml`.
- Session logs must use metadata-only lines with counts, route state, and `payload=not_observed`.
- `conu agents` may show trusted remote agent cards from the mirror, but it must not claim live messaging/streaming before later phases wire the relay client into conUD.
- Revoked peers must not remain visible as active remote agents after session sync.
- Route metadata may include relay endpoint, peer id, state, and reconnect counts; it must not include message contents, tokens, or private payload bytes.

## Direct Route Rules

- Phase 13 route selection belongs in `conu_core::routes`; other modules should call that API instead of parsing route files directly.
- Route state belongs under `routes/registry.toml`; probe history belongs under `routes/probes.toml`; route logs belong under `logs/routes.log`.
- Route records may include route id, peer id, display name, transport label, endpoint, state, score, estimated latency, NAT profile, fallback flag, and failure reason.
- Route records must not include plaintext payloads, prompt text, reasoning, file contents, auth tokens, private keys, shared secrets, or decrypted bytes.
- Revoked peers must not remain routeable after route sync.
- `conu sessions sync`, conUD processing, SDK, and MCP may refresh or list route metadata, but they must keep outputs payload-safe.
- A configured `direct-quic` route is a candidate and route label until real QUIC sockets and NAT traversal are implemented; do not claim live direct byte transport before it exists.
- Relay fallback must remain available when direct endpoint config is missing, invalid, or disabled by `nat_profile = "relay-only"`.

## Stream And Watch Rules

- Phase 10 streams are metadata-first in `conu_core::streams`.
- Stream lifecycle state belongs under `streams/registry.toml`; watch events belong under `streams/events.toml`.
- `conu streams write` must read opaque chunk bytes from stdin and record byte counts only.
- Stream logs must use metadata-only lines with stream id, route, byte count, chunk count, state, and `payload=not_observed`.
- `conu watch` may animate agents, stream ids, routes, packet counts, byte counts, and private-packet movement.
- `conu watch` must never show message text, chunk bytes, prompt text, reasoning, file contents, or tool output.
- Backpressure checks should reject oversized chunks before writing stream metadata.
- Do not claim live relay-backed byte streaming until the transport/encryption phases actually move encrypted chunks over the relay.

## Security Hardening Rules

- Phase 11 local security state belongs under `security/`.
- `identity-signing.key` stores the local Ed25519 signing key for agent-card signatures.
- `identity-exchange.key` stores the local X25519 exchange key for explicit peer key agreement.
- `storage.key` stores the local XChaCha20Poly1305 key for conU-owned encrypted-at-rest payload storage.
- `replay.toml` records message request and envelope ids so duplicates are rejected before delivery.
- `key-rotation.md` records the local rotation plan; do not mark production release ready until automated rotation and OS-backed key storage exist.
- New message request and inbox files must use `payload_ciphertext_hex`, not `payload_hex`.
- Agent registry records should include signature metadata for new/updated local agents.
- CLI security output may show readiness booleans and key ids, but must never show private keys, shared secrets, plaintext payloads, or decrypted payloads.
- Peer key agreement helpers are available for later live relay-backed encrypted delivery, but current remote sessions are still metadata mirrors.

## SDK And MCP Rules

- Phase 12 agent-facing APIs live in `crates/conu-sdk`, `crates/conu-mcp`, and `sdk/python/conu_sdk`.
- The Rust SDK should wrap `conu-core` surfaces instead of duplicating file-format logic.
- SDK send/list/status/receipt/stream methods must return metadata only unless the method is an explicit receive call.
- `receive_message_bytes(agent_id, envelope_id)` must verify the envelope is present in that addressed local agent inbox before returning bytes.
- `conu-mcp` uses MCP stdio: newline-delimited JSON-RPC on stdin/stdout.
- `conu-mcp` stdout must contain only valid MCP messages. Use stderr only for infrastructure errors, never payloads.
- MCP tools should return text content containing JSON-shaped results for compatibility, but send/list/status/stream results must not echo payload text.
- `conu_receive_message` returns metadata by default and may return `payloadHex` only when `includePayload` is true.
- `CONU_AGENT_ID` may bind one `conu-mcp` server to one local agent; bound servers must not act as another agent.
- Python SDK wrappers should pass payload bytes through stdin and avoid printing/logging payloads.
- TypeScript SDK is intentionally later; do not mark it complete until implemented and validated.

## Privacy Rules

- Never log plaintext payloads.
- Never show message text in CLI watch views.
- Never store plaintext payloads in conU-owned storage.
- Only expose metadata needed for routing, debugging, and delivery.
- Keep telemetry payload-safe: route, latency, packet count, stream count, bytes, retries, disconnect reason.

## Delivery Rules

- Use message ids and idempotency keys.
- Use receipts for important delivery state.
- Use bounded queues and backpressure for streams.
- Do not claim impossible exactly-once network delivery.
- Model exactly-once effects with receiver-side dedupe.

## Plan Discipline

At the end of each phase, update `plan.md` with status, changed files, validation, gaps, and next recommendation.
