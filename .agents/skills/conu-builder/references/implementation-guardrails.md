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
- Use `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings`, `cargo +stable-x86_64-pc-windows-gnu test --workspace`, and matching `cargo +... run` commands until MSVC Build Tools or CI are configured.

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
- Registration may store agent id, display name, kind, node id, presence, last seen time, and capability booleans. Core routing must enforce those booleans for message, stream, and room actions.
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
- Peer trust is identity/trust metadata, not blanket authorization. `policy.toml` stores peer-scoped boolean grants for messages, streams, rooms, files, and mailbox use; missing records must deny by default.
- Remote message, stream, and room routes must enforce peer policy in addition to trusted peer status, exchange-key checks, and local/remote agent capability checks.
- Peer policy CLI/SDK/MCP output must remain metadata-only and must not include payload contents, private keys, relay tokens, or decrypted bytes.

## Relay Rules

- Phase 8 relay is a small plain WebSocket MVP in `crates/conu-relay` with its frame contract in `conu_core::relay`.
- Runtime clients must authenticate with `HELLO node=<id> token=<token> payload=not_observed` before forwarding; they may include `resume=<session-id>` only as a same-node reconnect hint for the same relay endpoint.
- `FORWARD` frames may include target node id, agent ids, envelope id, byte count, and peer-encrypted body fields; they must not include plaintext payload fields.
- Relay server output, errors, tests, and logs must not echo auth tokens or private payload contents.
- `local-dev-token` is loopback-only. Non-loopback relay binds must require explicit custom shared or scoped tokens with at least 24 characters.
- The relay may return `UNDELIVERED reason=peer_offline` for metadata-only forwards or when the bounded mailbox cannot accept an envelope; peer-encrypted message, stream-chunk, room-event, and signed-card control forwards may be mailboxed until the target runtime reconnects.
- On Windows, accepted streams from a nonblocking listener must be set back to blocking mode before frame reads.
- The relay must enforce configurable total connection, per-IP connection, per-session frame-rate caps, idle timeout, and max session TTL without logging payloads or tokens.
- `CONU_RELAY_CREDENTIALS_FILE` is the preferred per-node relay auth mode for self-hosted relays because it stores token hashes, status, and optional expiry metadata without raw server-side tokens. `conu-relay --issue-credential --credentials-file` may generate an offline scoped token and upsert hashed manifest metadata; it must write the raw token only to the requested token file and report only manifest counts/paths/status. `--replace` rotates an existing node credential, and `conu-relay --revoke-credential` marks a node revoked without displaying tokens or token hashes. Omitting `--credentials-file` may print a hashed manifest entry for manual copy, but must never show the raw token. The relay reloads the credential file for each new `HELLO`; missing or invalid manifests fail closed for new sessions. `CONU_RELAY_CREDENTIALS` remains compatibility config; runtime clients may use `CONU_RELAY_TOKEN` or a local `conu relay credential set --stdin` credential, with the client environment variable taking precedence over stored client credentials. Relay auth errors, Debug output, and credential status output must never echo tokens or token hashes.
- `CONU_RELAY_ACCOUNTING_DIR` may persist metadata-only per-node counters for authenticated sessions, resumed sessions, sent/received envelopes, byte counts, and mailbox accepts. Optional sent-envelope and sent-byte quotas may reject a forward with `quota_exceeded`, but accounting files must not contain tokens, token hashes, payloads, ciphertext bodies, session ids, or private key material.
- `conu-relay` plus the conUD relay pump can move peer-encrypted one-shot messages, stream chunks, room events, and signed-card control envelopes for trusted peers, including bounded offline mailbox delivery when the target node reconnects. Set `CONU_RELAY_MAILBOX_DIR` on the relay for durable ciphertext files across relay restarts. conUD should reuse a relay WebSocket session across serve ticks when the endpoint is stable and may resume the same-node relay session after a same-process reconnect to the same endpoint; relay-side cross-node resume attempts must mint a new session. `conu relay sync` remains a manual/debug one-shot command. Distributed hosted session state, distributed hosted dashboards/accounting, managed hosted account auth, online credential issuance APIs, and direct QUIC stream sessions remain later work.

## Remote Session And Discovery Rules

- Phase 9 remote sessions are file-backed metadata mirrors in `conu_core::sessions`.
- conUD owns session sync; CLI commands may request sync or display the mirror but must not inspect payloads.
- Remote session state belongs under `sessions/registry.toml`; mirrored remote agent cards belong under `agents/remote.toml`.
- Session logs must use metadata-only lines with counts, route state, and `payload=not_observed`.
- `conu agents` may show trusted remote agent cards from the mirror. One-shot relay messages, relay stream chunks, and relay room events are available through explicit peer-card trust, matching peer policy, signed remote agent metadata, and the conUD relay pump; direct stream routing remains future work.
- `conu agents export` emits only public signed agent-card metadata. `conu agents trust` must verify the signature, require the card node id to already be trusted as a peer, require the signing key to match the trusted peer card, preserve signed cards across session sync, and reject cross-peer agent-id collisions.
- Session sync may queue signed local agent cards for peer-encrypted relay exchange only for signed trusted peers with at least one peer policy grant. Automatic inbound cards must use the same signature, trusted-node, signing-key, and collision checks as manual `conu agents trust`.
- Revoked peers must not remain visible as active remote agents after session sync.
- Route metadata may include relay endpoint, peer id, state, and reconnect counts; it must not include message contents, tokens, or private payload bytes.

## Direct Route Rules

- Phase 13 route selection belongs in `conu_core::routes`; other modules should call that API instead of parsing route files directly.
- Route state belongs under `routes/registry.toml`; probe history belongs under `routes/probes.toml`; route logs belong under `logs/routes.log`.
- Route records may include route id, peer id, display name, transport label, endpoint, state, score, estimated latency, NAT profile, fallback flag, and failure reason.
- Route records must not include plaintext payloads, prompt text, reasoning, file contents, auth tokens, private keys, shared secrets, or decrypted bytes.
- Revoked peers must not remain routeable after route sync.
- `conu sessions sync`, conUD processing, SDK, and MCP may refresh or list route metadata, but they must keep outputs payload-safe.
- A configured `direct-quic` route is a future candidate only. Until real QUIC sockets and NAT traversal are implemented, keep it unavailable with a generic failure reason and keep relay selected for delivery.
- Relay fallback must remain available when direct endpoint config is missing, invalid, or disabled by `nat_profile = "relay-only"`.

## Stream And Watch Rules

- Phase 10 streams are metadata-first in `conu_core::streams`.
- Stream lifecycle state belongs under `streams/registry.toml`; watch events belong under `streams/events.toml`.
- `conu streams write` must read opaque chunk bytes from stdin and record byte counts only.
- Stream logs must use metadata-only lines with stream id, route, byte count, chunk count, state, and `payload=not_observed`.
- `conu watch` may animate agents, stream ids, routes, packet counts, byte counts, and private-packet movement.
- `conu watch` must never show message text, chunk bytes, prompt text, reasoning, file contents, or tool output.
- Backpressure checks should reject oversized chunks before writing stream metadata.
- Relay-backed stream chunks move as peer-encrypted point-in-time envelopes. Do not claim full direct QUIC stream sessions or bidirectional session semantics until those transports and policies actually exist.

## Room And Pub/Sub Rules

- Phase 14 rooms are metadata-first in `conu_core::rooms`.
- Room lifecycle state belongs under `rooms/registry.toml`; room event metadata belongs under `rooms/events.toml`; room logs belong under `logs/rooms.log`.
- Room membership is the compatibility subscription boundary for unconfigured topics. `rooms/policy.toml` stores metadata-only per-topic publish/subscribe grants; once any record exists for a room/topic, local publish, local fanout, remote fanout, and inbound relay room delivery require explicit grants for that topic.
- `conu rooms publish` must read opaque event bytes from stdin and record only byte counts, topics, routes, event ids, delivery counts, and participant metadata in room surfaces.
- Joined local participants may receive encrypted-at-rest event envelopes in `messages/inbox/<agent-id>`, using the same payload storage privacy rules as local messages.
- Room logs must use metadata-only lines with room id, agent id, byte count, and `payload=not_observed`.
- `conu watch`, room list/event commands, SDK room calls, and MCP room tools must never show event payload text.
- Backpressure checks should reject oversized room events before writing room metadata or fanout envelopes.
- Relay-backed room fanout moves room event packets as peer-encrypted envelopes. The relay must not see room id, topic, or event payload plaintext. Room topic policy applies after local validation/decryption and must keep policy files/logs payload-free.

## Security Hardening Rules

- Phase 11 local security state belongs under `security/`.
- `identity-signing.key` stores the local Ed25519 signing key for agent-card signatures.
- `identity-exchange.key` stores the local X25519 exchange key for explicit peer key agreement.
- `storage.key` stores the local XChaCha20Poly1305 key for conU-owned encrypted-at-rest payload storage.
- `identity-keys/*.key` stores archived old signing/exchange keys for identity-key rotation refresh compatibility; it must use the same secret-field backend and must never expose key bytes. Archived exchange keys may be used only to decrypt peer envelopes sent to a previous exchange public key during peer-card refresh, and `conu security retire identity --confirm-peer-refresh-complete` may delete those archives only after the operator confirms refresh is complete.
- `storage-keys/*.key` stores archived old storage keys for storage-key rotation read compatibility; it must use the same secret-field backend and must never expose key bytes.
- `relay-credential.key` stores an optional local relay client token for runtimes; it must use the same secret-field backend as other security files and status commands must report only configured/backend/protection booleans.
- On non-Windows targets, `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` may configure the `user-managed-wrap-key-v1` backend. The wrap key is operator-managed, never stored by conU, and must not be passed in argv. When configured, security-state ensure migrates local signing, exchange, storage, archived key, and relay credential files from plaintext-hex fields to encrypted `*_wrapped_hex` fields. Without it, non-Windows secrets remain owner-only local files until native keychain/HSM support lands.
- `replay.toml` records message request and envelope ids so duplicates are rejected before delivery.
- `key-rotation.md` records the local rotation plan. `conu security rotate identity --confirm-peer-refresh` may rotate active signing/exchange keys, archive old identity keys, and require refreshed public peer-card distribution. `conu security retire identity --confirm-peer-refresh-complete` may delete archived identity keys after refresh is complete, removing old-key decrypt compatibility. `conu security rotate storage --confirm` may rotate active storage keys and re-encrypt local message queue/inbox payload files. `conu security retire storage --confirm` may delete only archived storage keys that no scanned local queue/inbox payload file still references. Do not claim native non-Windows keychain/HSM support until it exists; user-managed wrap-key fallback is not the same as OS-backed storage.
- New message request and inbox files must use `payload_ciphertext_hex`, not `payload_hex`.
- Agent registry records should include signature metadata for new/updated local agents.
- Remote signed agent-card imports should store only public signature metadata and capability booleans under `agents/remote.toml`; trust responses must not echo private payloads or secret material.
- `conu identity export` should include a signed public peer card, and `conu peers trust` should verify the signature when present before storing peer trust metadata. Unsigned imports are legacy controlled-test compatibility only.
- Peer policy records should store only trusted peer ids, boolean grants, update timestamps, and `payload_displayed = false`.
- CLI security output may show readiness booleans, key ids, rotation/retirement counts, secret storage backend, and OS-protection status, but must never show private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- Peer key agreement helpers now back relay message delivery. The relay must carry ciphertext only, and inbound envelopes must verify the sender exchange public key against the trusted peer card before delivery.

## SDK And MCP Rules

- Phase 12 agent-facing APIs live in `crates/conu-sdk`, `crates/conu-mcp`, `sdk/python/conu_sdk`, and `sdk/typescript`.
- The Rust SDK should wrap `conu-core` surfaces instead of duplicating file-format logic.
- SDK send/list/status/receipt/stream methods must return metadata only unless the method is an explicit receive call.
- `receive_message_bytes(agent_id, envelope_id)` must verify the envelope is present in that addressed local agent inbox before returning bytes.
- `conu-mcp` uses MCP stdio: newline-delimited JSON-RPC on stdin/stdout.
- `conu-mcp` stdout must contain only valid MCP messages. Use stderr only for infrastructure errors, never payloads.
- MCP tools should return text content containing JSON-shaped results for compatibility, but send/list/status/stream results must not echo payload text.
- `conu_receive_message` returns metadata by default and may return `payloadHex` only when `includePayload` is true.
- `CONU_AGENT_ID` may bind one `conu-mcp` server to one local agent; bound servers must not act as another agent.
- Python SDK wrappers should pass payload bytes through stdin and avoid printing/logging payloads.
- TypeScript SDK wrappers should pass payload bytes through stdin, avoid printing/logging payloads, keep wrapper responses on metadata-only CLI JSON surfaces, and pass `npm run check --prefix sdk/typescript`.
- `@conu/sdk` is currently a Node.js local-binary wrapper, not a browser-native protocol package. Browser-conditioned exports must fail closed without accepting relay tokens, private keys, endpoint secrets, or payload bytes. Do not add browser-native transport until hosted auth, browser key handling, and relay credential semantics are designed.
- SDK/MCP remote send helpers must queue peer-encrypted bytes and return metadata only. Relay sync helpers report counters only.

## Packaging And Release Rules

- Phase 15 packaging artifacts must include binaries, docs, packaging templates, and manifest metadata only.
- Platform release artifacts used by npm must include a sibling SHA-256 checksum file.
- The npm package is a thin launcher/downloader for native Rust binaries; it must not reimplement conU protocol behavior in JavaScript.
- npm install scripts may download release archives and copy binaries, but must not read, upload, log, or package local conU state.
- Release artifacts must not include local conU state, `CONU_HOME`, `.conu`, private keys, logs, inboxes, route registries, message stores, or test payload output.
- `conu doctor` may report binary paths, readiness booleans, runtime health, and payload-safe log scan counts; it must not print log contents, private keys, payload text, or secrets.
- `conu logs rotate` may rotate local metadata logs by byte size and archive count, but it must report only file names, sizes, counts, and `contentsDisplayed=false`; it must not read or print log contents.
- `conu telemetry snapshot` may report only fields in `TELEMETRY_FIELD_ALLOWLIST`, aggregate counters, and `contentsDisplayed=false`; it must not print node ids, agent ids, peer ids, endpoints, paths, log lines, key ids, secrets, or payload bodies.
- Windows service, Linux systemd, and macOS launchd files are templates until a signed installer configures platform-specific users and paths.
- Docker relay templates are acceptable for controlled self-hosted tests. Relay clients accept `wss://` through platform TLS verification, but the bundled relay server still requires TLS termination in front of it; public hosted relay claims still require managed account auth, online credential issuance APIs, distributed hosted monitoring/accounting, and distributed hosted session state.
- A local release may be marked ready only with documented limits. Do not claim public hosted internet readiness until hosted account auth, distributed hosted session state, distributed hosted accounting dashboards, hosted mailbox retention policy, multi-tenant hosted permission administration, and native non-Windows OS-backed key storage are implemented.
- CI/release workflows must run metadata-only checks, including package checks for `sdk/typescript` and `packaging/npm/conu-cli`, verify release archives with `scripts/verify-release-artifacts.py`, generate GitHub artifact attestations for release archives and checksum files, and must not upload conU state directories, logs, private keys, inboxes, route registries, telemetry dumps, vendored package binaries, or payload-bearing files as artifacts.

## Privacy Rules

- Never log plaintext payloads.
- Never show message text in CLI watch views.
- Never store plaintext payloads in conU-owned storage.
- Only expose metadata needed for routing, debugging, and delivery.
- Keep telemetry payload-safe and allowlisted: readiness booleans, route counts, packet/stream/room/session/relay counts, byte counts, retry/disconnect categories, and log scan counts only.

## Delivery Rules

- Use message ids and idempotency keys.
- Use receipts for important delivery state.
- Use bounded queues and backpressure for streams.
- Do not claim impossible exactly-once network delivery.
- Model exactly-once effects with receiver-side dedupe.

## Plan Discipline

At the end of each phase, update `plan.md` with status, changed files, validation, gaps, and next recommendation.
