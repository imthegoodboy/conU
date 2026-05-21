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
- `CONU_RELAY_CREDENTIALS_FILE` is the preferred per-node relay auth mode for self-hosted and managed relays because it stores token hashes, status, optional account ids, and optional expiry metadata without raw server-side node tokens. `conu-relay --issue-credential --credentials-file` may generate an offline scoped token and upsert hashed manifest metadata; it must write the raw token only to the requested token file and report only manifest counts/paths/status. `--replace` rotates an existing node credential, and `conu-relay --revoke-credential` marks a node revoked without displaying tokens or token hashes. Omitting `--credentials-file` may print a hashed manifest entry for manual copy, but must never show the raw token. `CONU_RELAY_ADMIN_TOKEN` enables backward-compatible full-admin online credential, tenant, session, dashboard, mailbox, and account-suspension control only when `CONU_RELAY_CREDENTIALS_FILE` is configured. `CONU_RELAY_ADMIN_TOKENS_FILE` may additionally or instead provide live-read hashed admin-token records with optional account ids, active/revoked status, optional expiry, and boolean scopes for credentials, tenants, sessions, dashboard, mailbox audit, and mailbox purge; account suspension requires both credentials and tenants scopes. `conu-relay --admin-token-audit` may inspect a local scoped admin-token manifest before relay startup, but output must stay metadata-only: record counts, active/revoked/expired totals, account/global counts, scope counts, expiry bounds, path/bind metadata, and false display guards without raw admin tokens, token hashes, manifest contents, private keys, session ids, payloads, ciphertext, or frame contents. Admin commands must read the admin token from stdin, send only generated node-token hash metadata or metadata-only session, dashboard, tenant, account-suspension, and mailbox audit/purge requests to the relay, write the raw node token locally only after relay confirmation, enforce configured scopes/accounts, and report only ids/counts/status/display guards. Scope failures must return `admin_scope_denied` without echoing the submitted token or stored hash. `CONU_RELAY_TENANTS_FILE` may enable a metadata-only hosted tenant registry through local `conu-relay --tenant-upsert`, `--tenant-revoke`, `--tenant-node-upsert`, `--tenant-node-revoke`, `--tenant-audit`, and `--hosted-account-suspend`, or online through matching `--admin-tenant-*` commands and `--admin-hosted-account-suspend`; issue/rotate and new `HELLO` sessions must fail closed when tenant or node metadata is missing or revoked. Account suspension must revoke tenant metadata before account credential metadata, must remain single-relay/file-backed, and must report only counts, paths/endpoints, status, and false display guards. Tenant files may store tenant ids, node ids, hosted permission booleans, public key ids, timestamps, and display guards only; they must not store private keys, tokens, token hashes, payloads, ciphertext bodies, or local peer-policy grants. Hosted tenant permissions are operator metadata and must not weaken conUD local peer policy ownership. The relay reloads the credential file for each new `HELLO`; missing, invalid, revoked, expired, or tenant-revoked manifests fail closed for new sessions. `CONU_RELAY_CREDENTIALS` remains compatibility config; runtime clients may use `CONU_RELAY_TOKEN` or a local `conu relay credential set --stdin` credential, with the client environment variable taking precedence over stored client credentials. Relay auth errors, Debug output, admin output, and credential status output must never echo tokens or token hashes.
- `CONU_RELAY_SESSION_STATE_DIR` may persist metadata-only per-node relay session records for same-node resume across relay restarts. Session files may contain node ids, relay session ids, timestamps, and display guards; they must not contain tokens, token hashes, payloads, ciphertext bodies, private key material, or account secrets. `conu-relay --session-audit` and `conu-relay --admin-session-audit` may report only record counts, active/expired/invalid totals, timestamp bounds, optional validated node filters, statuses, and false display guards. The admin form must require an admin token from stdin, enforce `sessions` scope when scoped tokens are configured, and require account-scoped tokens to provide a node filter authorized by an active tenant-node record. Admin/audit/log output must still not print session ids or session-state file contents.
- `CONU_RELAY_ACCOUNTING_DIR` may persist metadata-only per-node counters for authenticated sessions, resumed sessions, sent/received envelopes, byte counts, and mailbox accepts. Optional sent-envelope and sent-byte quotas may reject a forward with `quota_exceeded`, but accounting files must not contain tokens, token hashes, payloads, ciphertext bodies, session ids, or private key material.
- `CONU_RELAY_ABUSE_DIR` may persist metadata-only aggregate counters for relay enforcement outcomes such as admin unauthorized attempts, admin failures, credential or tenant denied sessions, rate limits, session expiry, quota-denied forwards, undelivered forwards, mailbox rejects, and malformed client frames. Abuse files, `conu-relay --abuse-audit`, `conu-relay --abuse-threshold-report`, and admin-gated `conu-relay --admin-abuse-threshold-report` output may include aggregate counts, operator-supplied max values from CLI flags or metadata-only `--thresholds-file` policy files, exceeded booleans, optional account/node filters, window start, and false display guards only; they may return exit code 3 with `--fail-on-threshold` after preserving stdout report output, but they must not contain raw tokens, token hashes, admin tokens, private keys, session ids, payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, or room-event plaintext. Threshold policy files must require `version = "1"` and false display guards; CLI `--max-*` values override file values. The admin threshold report must require `--admin-token-stdin` and dashboard admin scope. The current store and reports are single-writer relay-local metadata, not distributed hosted alerting, adaptive response, or automated enforcement.
- `conu-relay --mailbox-audit` may scan `CONU_RELAY_MAILBOX_DIR` durable mailbox files for aggregate retention metadata only. `conu-relay --admin-mailbox-audit` may request the same class of read-only retention metadata from a running relay through the admin WebSocket control plane, but it must require `--admin-token-stdin`, hosted admin configuration through `CONU_RELAY_ADMIN_TOKEN` or `CONU_RELAY_ADMIN_TOKENS_FILE`, and configured durable mailbox storage. These audits may report mailbox file counts, durable byte totals, oldest/newest queued timestamps, optional expired counts under an operator-supplied TTL, invalid mailbox-file counts, optional validated node id filters, and false display guards. `conu-relay --mailbox-purge` and `conu-relay --admin-mailbox-purge` may delete only expired valid `.mailbox` files after a positive TTL and explicit `--confirm`, or report the same aggregate expired set without deleting when `--dry-run` is used; the admin form must use the relay admin control plane, read the admin token from stdin, enforce scoped admin boundaries when configured, and operate only on configured durable mailbox storage. Reusable `--retention-policy-file` files may provide metadata-only `ttl_seconds` and optional `node_id` defaults for local/admin audit and purge commands, but they must require `version = "1"` plus false display guards, must reject unknown keys, and CLI `--ttl-seconds`/`--node` values must override file values. Purge commands must still require a TTL from file or CLI plus exactly one of `--dry-run` or `--confirm`. `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` may enable relay-local scheduled deletion of expired valid `.mailbox` files using `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`; it must require `CONU_RELAY_MAILBOX_DIR` and must not print stored file contents. Audit, manual purge, admin purge, and scheduled purge must not print stored relay frames, ciphertext bodies, raw tokens, token hashes, admin tokens, private keys, session ids, plaintext payloads, message text, stream chunks, room-event plaintext, or arbitrary mailbox file contents. These are single-relay operator workflows, not distributed hosted retention, billing, adaptive automation, distributed remote purge orchestration, or tenant-wide retention orchestration.
- `conu-relay --hosted-dashboard` may combine credential manifest, tenant registry, accounting, and abuse summaries into one local operator snapshot. `conu-relay --hosted-readiness` may combine local credential, scoped admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks into one pre-startup/release report, and may return exit code 3 with `--fail-on-warning` after preserving stdout when warnings exist. Readiness output may include only configured paths, configured-source booleans, aggregate counts, warning totals, bind metadata, optional account/node filters, and false display guards; it must not output raw tokens, admin tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, room-event plaintext, or manifest contents. `conu-relay --admin-hosted-dashboard` may request the same class of aggregate snapshot from a running relay through the admin WebSocket control plane, but it must require `--admin-token-stdin` plus either `CONU_RELAY_ADMIN_TOKEN` or a scoped `CONU_RELAY_ADMIN_TOKENS_FILE` record with dashboard scope. `conu-relay --abuse-threshold-report` and `conu-relay --admin-abuse-threshold-report` may derive threshold status from those abuse counters and explicit operator maximums from CLI flags or reusable policy files, and may optionally return exit code 3 with `--fail-on-threshold`, but must not add adaptive enforcement or distributed alerting. These forms may output only aggregate counts, configured paths or relay endpoint, optional account/node filters, max values, exceeded booleans, and false display guards; they must not output raw tokens, admin tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, or room-event plaintext. These commands are single-relay snapshots/reports, not distributed hosted dashboards, alerting, billing, workflow automation, or adaptive response services.
- `conu-relay` plus the conUD relay pump can move peer-encrypted one-shot messages, stream chunks, room events, and signed-card control envelopes for trusted peers, including bounded offline mailbox delivery when the target node reconnects. Set `CONU_RELAY_MAILBOX_DIR` on the relay for durable ciphertext files across relay restarts. conUD should reuse a relay WebSocket session across serve ticks when the endpoint is stable and may resume the same-node relay session after reconnecting to the same endpoint; relay-side cross-node resume attempts must mint a new session. `CONU_RELAY_SESSION_STATE_DIR` lets the relay validate the same-node resume hint after a relay restart until TTL expiry, but it is a single-writer file-backed boundary, not distributed locking or multi-region migration. `conu relay sync` remains a manual/debug one-shot command. Distributed hosted dashboards/accounting, distributed tenant lifecycle beyond single-relay account suspension/scoped admin commands, full hosted identity/key administration, and managed direct NAT traversal remain later work.

## Remote Session And Discovery Rules

- Phase 9 remote sessions are file-backed metadata mirrors in `conu_core::sessions`.
- conUD owns session sync; CLI commands may request sync or display the mirror but must not inspect payloads.
- Remote session state belongs under `sessions/registry.toml`; mirrored remote agent cards belong under `agents/remote.toml`.
- Session logs must use metadata-only lines with counts, route state, and `payload=not_observed`.
- `conu agents` may show trusted remote agent cards from the mirror. One-shot direct or relay messages, direct or relay stream chunks, and relay room events are available through explicit peer-card trust, matching peer policy, signed remote agent metadata, and the conUD route/relay pumps.
- `conu agents export` emits only public signed agent-card metadata. `conu agents trust` must verify the signature, require the card node id to already be trusted as a peer, require the signing key to match the trusted peer card, preserve signed cards across session sync, and reject cross-peer agent-id collisions.
- Session sync may queue signed local agent cards for peer-encrypted relay exchange only for signed trusted peers with at least one peer policy grant. Automatic inbound cards must use the same signature, trusted-node, signing-key, and collision checks as manual `conu agents trust`.
- Revoked peers must not remain visible as active remote agents after session sync.
- Route metadata may include relay endpoint, peer id, state, and reconnect counts; it must not include message contents, tokens, or private payload bytes.

## Direct Route Rules

- Phase 13 route selection belongs in `conu_core::routes`; other modules should call that API instead of parsing route files directly.
- Route state belongs under `routes/registry.toml`; probe history belongs under `routes/probes.toml`; route logs belong under `logs/routes.log`.
- Route records may include route id, peer id, display name, transport label, sanitized endpoint, state, score, estimated latency, NAT profile, candidate source/kind, rendezvous state, fallback flag, and failure reason.
- Route records must not include plaintext payloads, prompt text, reasoning, file contents, auth tokens, private keys, shared secrets, endpoint secrets, or decrypted bytes.
- Revoked peers must not remain routeable after route sync.
- `conu sessions sync`, conUD processing, SDK, and MCP may refresh or list route metadata, but they must keep outputs payload-safe.
- A configured `direct-quic` route must be selected only after a live QUIC probe succeeds and the remote peer answers an encrypted challenge with the trusted peer-card key. If probing fails, record a generic metadata-only failure such as `direct_quic_probe_failed` and keep relay selected.
- Route sync may record static host candidate metadata from peer-specific config, signed peer cards, or local config. Missing candidates for `unknown`, `cone`, or `symmetric` NAT profiles should record `nat_traversal_unavailable`; this is not ICE/STUN/TURN negotiation or UDP hole punching.
- Relay fallback must remain available when direct endpoint config is missing, invalid, unavailable, or disabled by `nat_profile = "relay-only"`.

## Stream And Watch Rules

- Phase 10 streams are metadata-first in `conu_core::streams`.
- Stream lifecycle state belongs under `streams/registry.toml`; watch events belong under `streams/events.toml`.
- `conu streams write` must read opaque chunk bytes from stdin and record byte counts only.
- Stream logs must use metadata-only lines with stream id, route, byte count, chunk count, state, and `payload=not_observed`.
- `conu watch` may animate agents, stream ids, routes, packet counts, byte counts, and private-packet movement.
- `conu watch` must never show message text, chunk bytes, prompt text, reasoning, file contents, or tool output.
- Backpressure checks should reject oversized chunks before writing stream metadata.
- Remote stream chunks move as peer-encrypted point-in-time envelopes over direct QUIC or relay. Do not claim long-lived bidirectional application stream semantics until that transport and policy layer exists.

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
- macOS should use the user Keychain for local signing, exchange, storage, archived key, and relay credential secret fields. Linux should use Secret Service through `secret-tool` when a user session is available. Native backend files may store only OS-secret references and lengths, never key bytes, relay tokens, wrapped blobs, plaintext payloads, or decrypted payloads.
- On non-Windows targets without an available native backend, `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` may configure the `user-managed-wrap-key-v1` backend. The wrap key is operator-managed, never stored by conU, and must not be passed in argv. When configured, security-state ensure migrates local signing, exchange, storage, archived key, and relay credential files from plaintext-hex fields to encrypted `*_wrapped_hex` fields. Without native storage or a configured wrap key, non-Windows secrets remain owner-only local files. `CONU_DISABLE_OS_SECRET_BACKEND=1` may force the fallback path for controlled tests.
- `replay.toml` records message request and envelope ids so duplicates are rejected before delivery.
- `key-rotation.md` records the local rotation plan. `conu security rotate identity --confirm-peer-refresh` may rotate active signing/exchange keys, archive old identity keys, and require refreshed public peer-card distribution. `conu security retire identity --confirm-peer-refresh-complete` may delete archived identity keys after refresh is complete, removing old-key decrypt compatibility. `conu security rotate storage --confirm` may rotate active storage keys and re-encrypt local message queue/inbox payload files. `conu security retire storage --confirm` may delete only archived storage keys that no scanned local queue/inbox payload file still references. Do not claim Secure Enclave, HSM, or managed key administration until it exists; user-managed wrap-key fallback is not the same as OS-backed storage.
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
- Windows service, Linux systemd, and macOS launchd files are templates until an installer configures platform-specific users and paths.
- Docker relay templates are acceptable for controlled self-hosted tests. Relay clients accept `wss://` through platform TLS verification, but the bundled relay server still requires TLS termination in front of it; public hosted relay claims still require distributed hosted monitoring/accounting, distributed tenant lifecycle, and distributed multi-instance session migration.
- A local release may be marked ready only with documented limits. Do not claim public hosted internet readiness until distributed multi-instance session migration, distributed hosted accounting dashboards beyond local/admin-gated single-relay dashboard snapshots, distributed hosted mailbox retention orchestration beyond local/admin-gated mailbox audit/purge plus relay-local scheduled purge workflows, distributed tenant lifecycle/workflow automation beyond single-relay account suspension/scoped admin tokens, and managed hosted key administration are implemented.
- CI/release workflows must run metadata-only checks, including package checks for `sdk/typescript` and `packaging/npm/conu-cli`, verify release archives with `scripts/verify-release-artifacts.py`, sign Windows binaries with Authenticode on tag builds, sign and notarize macOS ZIP archives on tag builds, generate GitHub artifact attestations for release archives and checksum files, and must not upload conU state directories, logs, private keys, inboxes, route registries, telemetry dumps, vendored package binaries, or payload-bearing files as artifacts. Signing jobs must fail closed on `v*` tags when required maintainer secrets are missing and must never print certificates, private keys, signing passwords, tokens, local state, or payload contents.

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
