# conU Production Readiness

This document tracks what is ready, what is intentionally local-only, and what must be finished before a real public release.

For hands-on install and agent usage instructions, see `docs/user-install-and-agent-guide.md`.

## Ready In The Current Repo

- Rust workspace for CLI, runtime daemon, core, protocol, and relay.
- `conu init`, status, start, stop, and dashboard.
- File-backed local agent gateway for registration and presence.
- Local message delivery between registered agents.
- Encrypted-at-rest conU-owned local message payload storage.
- Signed local agent cards.
- Signed public peer-card export/import for manual cross-machine trust integrity.
- Signed public agent-card export/import for trusted peers.
- Automatic encrypted signed agent-card exchange during trusted session sync.
- User-visible local agent capability flags with core enforcement for messages, streams, and rooms.
- Peer-scoped permission policy with default-deny grants for messages, streams, rooms, files, and mailbox use.
- Local pairing/trust records with revocation.
- Metadata-only relay frame contract and standalone WebSocket relay MVP.
- Peer-card exchange and daemon-pumped relay-backed peer-encrypted one-shot message delivery.
- Relay-backed peer-encrypted stream chunk delivery for trusted remote agents with metadata-only inbox and receipt surfaces.
- Relay-backed peer-encrypted room event fanout for joined trusted remote agents with metadata-only room and inbox surfaces.
- Reusable daemon relay WebSocket session across conUD runtime ticks.
- Relay client support for `ws://` and certificate-validated `wss://` endpoints.
- Configurable relay connection caps, per-IP caps, and per-session frame-rate limits.
- Static per-node relay credentials through `CONU_RELAY_CREDENTIALS` for self-hosted/hosted relays.
- Offline scoped relay credential issuance through `conu-relay --issue-credential`, manifest upsert/rotation through `--credentials-file` and `--replace`, manifest revocation through `conu-relay --revoke-credential`, plus live-reloaded file-backed scoped relay credential manifests through `CONU_RELAY_CREDENTIALS_FILE`, with token hashes, active/revoked status, optional expiry, and a token-safe `conu-relay --hash-token` helper for already-created tokens.
- Metadata-only relay accounting through `CONU_RELAY_ACCOUNTING_DIR`, with per-node session, sent/received byte, envelope, and mailbox counters plus optional per-window sent-envelope and sent-byte quotas.
- Local relay client credential storage through `conu relay credential set --stdin`, with token-safe status/clear commands.
- Configurable relay idle timeout and max session TTL.
- Relay bind guard that rejects `local-dev-token` and short tokens on non-loopback binds.
- Remote session and remote agent metadata mirror for trusted peers.
- Stream lifecycle metadata, backpressure counters, and private watch animation.
- Direct QUIC candidate scoring, NAT profile labels, route probes, inactive direct-candidate guards, and relay fallback selection.
- Replay protection for local message request and envelope ids.
- Rust SDK for local agent registration, messaging, receive, peer, security, and stream calls.
- Python stdlib wrapper SDK around installed `conu` and `conud` binaries.
- TypeScript/JavaScript stdlib-free Node wrapper SDK around installed `conu` and `conud` binaries.
- MCP stdio adapter exposing conU as JSON-RPC tools for MCP-capable agents.
- `conu doctor` local readiness and payload-safe log scanner.
- Payload-safe local log rotation through `conu logs rotate`, with active and rotated logs covered by doctor scanning.
- Payload-safe local structured telemetry through `conu telemetry snapshot`, with schema `conu.telemetry.snapshot.v1`, an explicit field allowlist, aggregate counters only, and `contentsDisplayed=false`.
- Signing/exchange identity-key rotation through `conu security rotate identity --confirm-peer-refresh`, with archived old identity keys, peer-card refresh reporting, and old exchange-key decrypt compatibility during refresh.
- Identity archive retirement through `conu security retire identity --confirm-peer-refresh-complete`, removing archived old identity keys after refreshed peer cards have been distributed and old-key decrypt compatibility is no longer required.
- Storage-key rotation through `conu security rotate storage --confirm`, including archived old storage keys and local encrypted-at-rest message queue/inbox re-encryption.
- Storage-key retirement through `conu security retire storage --confirm`, removing only archived keys that no scanned local encrypted-at-rest queue/inbox payload still references.
- Cross-platform release build scripts under `scripts/`.
- Platform-named release artifacts with SHA-256 checksum files.
- Windows install/uninstall scripts and Windows service creation path.
- Linux systemd and macOS launchd service templates.
- Docker relay hosting template.
- npm native launcher package template under `packaging/npm/conu-cli`.
- GitHub CI and release artifact workflows.
- Release checklist and observability docs.
- Payload-safe logs, receipts, watch output, and CLI JSON.
- Phase 11 security audit command, Phase 12 SDK/MCP receive path, Phase 13 route manager, and Phase 15 packaging layer.

## Still Local Or Groundwork

- File-backed IPC is reliable for development, but not yet a production named-pipe/socket transport.
- Remote sessions are still metadata mirrors; signed manual peer-card exchange is the current cross-machine trust path.
- Local agent capabilities are enforced for message, stream, and room surfaces. Trusted peers also need explicit local policy grants before remote message, stream, or room traffic is accepted. Remote stream and room metadata must advertise matching capabilities; imported signed remote agent cards preserve peer-authored capability metadata only when the card signing key matches the trusted peer card, while placeholder mirrors remain a controlled fallback when no signed cards have been imported for a trusted peer.
- The relay-backed data plane supports one-shot peer-encrypted messages, stream chunks, and room events through the conUD relay pump when a relay or trusted relay peer is configured. The daemon keeps a reusable relay session while serving; explicit `conu relay sync` remains a one-shot manual flush/debug flow. If the same daemon process reconnects to the same endpoint after a socket drop, it can present a prior relay session id as a same-node resume hint; the relay accepts only same-node hints and records resumed-session counters without logging session ids or payloads. The relay can hold peer-encrypted envelopes in a bounded offline mailbox until the target node reconnects; `CONU_RELAY_MAILBOX_DIR` makes those ciphertext envelope files survive relay restarts. Self-hosted relay credential manifests can be generated and updated with `conu-relay --issue-credential --credentials-file`, rotated with `--replace`, and revoked with `conu-relay --revoke-credential`; manifests reload on each new `HELLO`, so revoked or expired scoped tokens are denied for new sessions without relay restart. `CONU_RELAY_ACCOUNTING_DIR` can persist metadata-only usage counters with optional per-node sent quotas. Managed hosted account auth, online credential issuance workflows beyond the offline helper, distributed hosted dashboards/abuse response, and distributed hosted session state are not active yet.
- Windows local signing, exchange, storage, archived identity/storage, and stored relay credential secrets are wrapped with current-user DPAPI and older plaintext-hex key files are migrated during security-state ensure. Identity-key rotation archives old signing/exchange keys, requires a refreshed public peer-card handoff, and keeps archived exchange keys available for old-key peer envelope decryption during the refresh window; identity archive retirement deletes those archived old identity keys after operators confirm peer-card refresh is complete. Storage-key rotation re-encrypts conU-owned local encrypted-at-rest message queue/inbox payload files while retaining archived old keys for read compatibility, and storage-key retirement removes only archived keys no scanned local payload file still references. Non-Windows builds still rely on owner-only secret files until a platform keychain, Secure Enclave, HSM, or user-managed backend is added.
- Direct transport is route metadata only. Configured direct candidates are recorded as inactive with `direct_quic_transport_inactive`, while relay remains selected for delivery. Real QUIC sockets, ICE-style candidate exchange, and NAT hole punching are not active yet.
- Local telemetry is allowlisted aggregate counters only. Hosted telemetry pipelines, retention controls, alerting, and distributed dashboards are not active yet.
- Stream writes count bytes and emit events. Local stream writes do not persist plaintext chunks; remote relay writes are delivered as encrypted `stream_chunk` inbox envelopes, not as full direct QUIC stream sessions.
- Room membership remains the compatibility boundary for unconfigured room topics. `conu rooms policy`, SDK calls, and MCP tools can configure metadata-only per-topic publish/subscribe grants; once any policy exists for a room/topic, that topic requires explicit publisher and subscriber grants.
- Pairing is local trust-store groundwork, not full cross-machine rendezvous.
- MCP is stdio-only. HTTP MCP transport, auth, and remote MCP hosting are intentionally not implemented.
- Packaging is unsigned and local-first. Code signing, notarization, package-manager publishing, and auto-update are not implemented.
- The npm launcher template is present, but `@conu/cli` should only be published after GitHub Release archives and checksum files exist for the supported platforms.
- The Docker relay template runs the current relay with scoped credentials or a live-reloaded hashed credential manifest, configurable connection/frame-rate caps, metadata-only accounting, idle/TTL session policy, durable ciphertext mailbox directory, and non-loopback token guard. The client supports `wss://`, but the relay server itself still needs TLS termination in front of it for public operation, and managed hosted account auth is not implemented.

## Release Blockers

- Distributed hosted relay session state/accounting, distributed hosted accounting dashboards, hosted retry policy, and managed mailbox retention policy.
- Full direct stream transport over QUIC or another authenticated direct transport.
- Real direct QUIC transport with peer authentication and NAT traversal.
- Hosted multi-tenant room permission administration beyond the current local room topic policy file.
- Multi-tenant hosted SDK/MCP permission administration beyond the current local peer policy file.
- Non-Windows OS-backed private key and relay credential storage.
- Signed installer/package publishing for Windows, macOS, and Linux.
- Published npm package backed by verified release checksums.
- Hosted telemetry pipeline, distributed hosted abuse monitoring, adaptive response, bounded persistent queues, managed online credential issuance, and online token rotation workflows.
- Security review of relay auth, replay cache behavior, and storage migration.

## Validation Baseline

Before merging production-affecting work, run:

```bash
cargo fmt --all -- --check
cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu test --workspace
python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py
npm run check --prefix sdk/typescript
powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu
powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
conu doctor --json
conu telemetry snapshot --json
git diff --check
```

On Windows machines without Visual Studio C++ Build Tools, the default MSVC toolchain can fail when dependencies compile build scripts. Use `stable-x86_64-pc-windows-gnu` until MSVC Build Tools or CI are configured.

## Privacy Baseline

Every release candidate must confirm:

- CLI output does not show message text, prompt text, reasoning, file contents, private keys, or shared secrets.
- SDK/MCP list, send, status, receipt, and stream outputs stay metadata-only.
- SDK/MCP receive APIs return payload bytes only to the addressed local agent by explicit request.
- Logs use `payload=not_observed` or metadata-only equivalents.
- Route registry, route probes, and route logs contain route metadata only.
- `conu telemetry snapshot --json` includes only fields from `TELEMETRY_FIELD_ALLOWLIST` and reports `contentsDisplayed=false`.
- Relay frames reject plaintext payload fields.
- Relay message, stream-chunk, room-event, and signed-card control frames may carry ciphertext bodies only after local trust verifies the sender public exchange key.
- Message and mailbox storage use encrypted payload fields.
- Tests use artificial negative strings only to prove they do not leak.

## Release Artifacts

Build artifacts with:

```powershell
.\scripts\build-release.ps1
# On Windows without MSVC Build Tools:
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

or:

```sh
./scripts/build-release.sh
```

Each artifact must include only binaries, docs, packaging templates, and `manifest.toml`. It must not include developer state directories, keys, logs, inboxes, route files, or payload-bearing test output.

Archives intended for npm installation must use platform suffixes such as `windows-x64`, `linux-x64`, `linux-arm64`, `macos-x64`, and `macos-arm64`, and each archive must have a sibling `.sha256` file.

## Local Release Decision

Current status is `daemon_relay_message_stream_chunk_room_topic_policy_durable_mailbox_offline_relay_credential_issuance_manifest_lifecycle_hashed_relay_credential_manifest_accounting_quotas_session_resume_direct_route_selection_guard_log_rotation_structured_telemetry_identity_key_rotation_storage_key_rotation_and_retirement_windows_dpapi_stored_relay_client_credentials_local_capabilities_signed_agent_cards_peer_policy_and_auto_agent_card_exchange_ready_with_known_limits`.

This means a developer can install, initialize, start conUD, pair locally, exchange signed public peer cards, grant peer-scoped message/stream/room policy, configure per-topic room publish/subscribe grants for local or relay-backed room events, exchange signed public agent cards manually or automatically during session sync, send a peer-encrypted one-shot message, stream chunk, or room event through a reachable `ws://` relay or a certificate-valid `wss://` relay path without manual per-message sync, keep the daemon relay session alive across runtime ticks, resume the same-node relay session after a same-process socket reconnect to the same endpoint, receive bounded offline relay envelopes after reconnect, persist those ciphertext envelopes across relay restarts when `CONU_RELAY_MAILBOX_DIR` is set, persist metadata-only relay accounting counters and optional per-node sent quotas when `CONU_RELAY_ACCOUNTING_DIR` and quota env vars are set, record configured direct QUIC candidates without selecting them before a direct data plane exists, rotate local metadata logs without displaying contents, export allowlisted local telemetry counters without displaying contents, rotate local identity signing/exchange keys without displaying key material, rotate local storage keys and re-encrypt conU-owned encrypted-at-rest message queue/inbox payload files without displaying contents, retire unused archived local storage keys without displaying contents, wrap local Windows private key and stored relay credential bytes with current-user DPAPI, store a relay client credential without displaying it, run readiness checks, configure basic relay connection/frame limits, issue self-hosted scoped relay credentials without printing raw tokens to stdout, upsert/rotate/revoke self-hosted credential manifests without displaying token material, assign per-node relay credentials through a live-reloaded hashed credential manifest with revocation/expiry metadata, configure relay idle/TTL and offline-mailbox policy, reject unsafe public dev-token binds, and inspect payload-safe logs. It does not mean conU is ready as a hosted public internet network with managed account auth, hosted TLS policy, hosted distributed accounting dashboards, distributed hosted session migration, online managed credential issuance APIs, non-Windows OS keychain integration, hosted multi-tenant room permission administration, or direct QUIC.
