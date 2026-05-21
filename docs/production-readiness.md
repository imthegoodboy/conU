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
- Account-scoped online relay credential issue, rotate, revoke, and audit commands through `CONU_RELAY_ADMIN_TOKEN` plus `CONU_RELAY_CREDENTIALS_FILE`, sending only node-token hash metadata to the relay and returning metadata-only admin results.
- Metadata-only hosted tenant registry through `CONU_RELAY_TENANTS_FILE` plus `conu-relay --tenant-*` commands, with fail-closed issue/rotate and new-session auth when tenant or node metadata is missing or revoked.
- Metadata-only relay session state through `CONU_RELAY_SESSION_STATE_DIR`, durable mailbox retention audits through `conu-relay --mailbox-audit`, confirm-gated expired mailbox deletion through `conu-relay --mailbox-purge`, relay accounting through `CONU_RELAY_ACCOUNTING_DIR`, relay abuse counters through `CONU_RELAY_ABUSE_DIR`, and `conu-relay --hosted-dashboard` snapshots across credential, tenant, accounting, and abuse stores, with per-node session, sent/received byte, envelope, mailbox, durable-mailbox, and enforcement counters plus optional per-window sent-envelope and sent-byte quotas.
- Local relay client credential storage through `conu relay credential set --stdin`, with token-safe status/clear commands.
- Configurable relay idle timeout and max session TTL.
- Relay bind guard that rejects `local-dev-token` and short tokens on non-loopback binds.
- Remote session and remote agent metadata mirror for trusted peers.
- Stream lifecycle metadata, backpressure counters, and private watch animation.
- Authenticated direct QUIC probing and message/stream-chunk delivery for reachable trusted peers, with candidate source/kind metadata, NAT profile labels, explicit NAT-traversal-unavailable reporting, and relay fallback selection.
- Replay protection for local message request and envelope ids.
- Rust SDK for local agent registration, messaging, receive, peer, security, and stream calls.
- Python stdlib wrapper SDK around installed `conu` and `conud` binaries.
- TypeScript/JavaScript stdlib-free Node wrapper SDK around installed `conu`, `conud`, and `conu-mcp` binaries, including explicit addressed-agent payload receive and a fail-closed browser export boundary.
- MCP stdio adapter exposing conU as JSON-RPC tools for MCP-capable agents.
- `conu doctor` local readiness and payload-safe log scanner.
- Payload-safe local log rotation through `conu logs rotate`, with active and rotated logs covered by doctor scanning.
- Payload-safe local structured telemetry through `conu telemetry snapshot`, with schema `conu.telemetry.snapshot.v1`, an explicit field allowlist, aggregate counters only, and `contentsDisplayed=false`.
- Signing/exchange identity-key rotation through `conu security rotate identity --confirm-peer-refresh`, with archived old identity keys, peer-card refresh reporting, and old exchange-key decrypt compatibility during refresh.
- Identity archive retirement through `conu security retire identity --confirm-peer-refresh-complete`, removing archived old identity keys after refreshed peer cards have been distributed and old-key decrypt compatibility is no longer required.
- Storage-key rotation through `conu security rotate storage --confirm`, including archived old storage keys and local encrypted-at-rest message queue/inbox re-encryption.
- Storage-key retirement through `conu security retire storage --confirm`, removing only archived keys that no scanned local encrypted-at-rest queue/inbox payload still references.
- macOS user Keychain and Linux Secret Service native secret backends for local signing, exchange, storage, archived key, and stored relay credential secret fields when available.
- Non-Windows operator-managed secret wrapping through `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE`, using XChaCha20Poly1305 to migrate and protect local signing, exchange, storage, archived key, and stored relay credential secret fields when configured.
- Cross-platform release build scripts under `scripts/`.
- Platform-named release artifacts with SHA-256 checksum files.
- GitHub artifact attestations for release archives and checksum files generated by the release workflow.
- Tagged release workflow support for Windows Authenticode-signed binaries, macOS Developer ID-signed and notarized ZIP archives, and a documented Linux SHA-256/GitHub-attestation signing policy.
- Windows install/uninstall scripts and Windows service creation path.
- Linux systemd and macOS launchd service templates.
- Docker relay hosting template.
- npm native launcher package template under `packaging/npm/conu-cli`.
- GitHub CI and release artifact workflows, including Rust matrix checks, Python wrapper compile, TypeScript SDK check, npm launcher check, archive verification, GitHub Release asset upload, and optional npm publication when `NPM_TOKEN` is configured.
- Release checklist and observability docs.
- Payload-safe logs, receipts, watch output, and CLI JSON.
- Phase 11 security audit command, Phase 12 SDK/MCP receive path, Phase 13 route manager, and Phase 15 packaging layer.

## Still Local Or Groundwork

- File-backed IPC is reliable for development, but not yet a production named-pipe/socket transport.
- Remote sessions are still metadata mirrors; signed manual peer-card exchange is the current cross-machine trust path.
- Local agent capabilities are enforced for message, stream, and room surfaces. Trusted peers also need explicit local policy grants before remote message, stream, or room traffic is accepted. Remote stream and room metadata must advertise matching capabilities; imported signed remote agent cards preserve peer-authored capability metadata only when the card signing key matches the trusted peer card, while placeholder mirrors remain a controlled fallback when no signed cards have been imported for a trusted peer.
- The relay-backed data plane supports one-shot peer-encrypted messages, stream chunks, and room events through the conUD relay pump when a relay or trusted relay peer is configured. The daemon keeps a reusable relay session while serving; explicit `conu relay sync` remains a one-shot manual flush/debug flow. If the same daemon process reconnects to the same endpoint after a socket drop, it can present a prior relay session id as a same-node resume hint; the relay accepts only same-node hints and records resumed-session counters without logging session ids or payloads. `CONU_RELAY_SESSION_STATE_DIR` can persist metadata-only same-node session records across relay restarts until TTL expiry, but it is not distributed multi-instance session migration. The relay can hold peer-encrypted envelopes in a bounded offline mailbox until the target node reconnects; `CONU_RELAY_MAILBOX_DIR` makes those ciphertext envelope files survive relay restarts. `conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--json]` renders local durable-mailbox retention metadata, byte totals, queue timestamp bounds, optional expired counts, invalid mailbox-file counts, and false display guards without printing frame contents or ciphertext bodies. `conu-relay --mailbox-purge --mailbox-dir <path> --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]` reports the same retention boundary and, only with `--confirm`, deletes expired valid `.mailbox` files without printing stored frames, ciphertext bodies, payloads, tokens, hashes, private keys, or session ids. Self-hosted relay credential manifests can be generated and updated with `conu-relay --issue-credential --credentials-file`, rotated with `--replace`, and revoked with `conu-relay --revoke-credential`; managed relay operators can also issue, rotate, revoke, and audit account-scoped credentials online with the admin token control plane. Manifests reload on each new `HELLO`, so revoked or expired scoped tokens are denied for new sessions without relay restart. `CONU_RELAY_ACCOUNTING_DIR` can persist metadata-only usage counters with optional per-node sent quotas. `CONU_RELAY_ABUSE_DIR` can persist metadata-only denial/enforcement counters, `conu-relay --abuse-audit` can render aggregate or per-node counts, and `conu-relay --hosted-dashboard` can render a combined single-relay snapshot across credential, tenant, accounting, and abuse stores without tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, or frame contents. Distributed hosted dashboard services/abuse response, distributed multi-instance session migration, scheduled hosted mailbox purge orchestration, and full tenant lifecycle services are not active yet.
- Windows local signing, exchange, storage, archived identity/storage, and stored relay credential secrets are wrapped with current-user DPAPI and older plaintext-hex key files are migrated during security-state ensure. macOS uses the user Keychain, and Linux uses Secret Service through `secret-tool` when a user session is available; native files store only OS-secret references and lengths. On non-Windows without a native store, operators can configure `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` to wrap those same local secret fields with XChaCha20Poly1305 under an external key conU never stores; older plaintext-hex key and relay credential files migrate when the selected backend can read them. Identity-key rotation archives old signing/exchange keys, requires a refreshed public peer-card handoff, and keeps archived exchange keys available for old-key peer envelope decryption during the refresh window; identity archive retirement deletes those archived old identity keys after operators confirm peer-card refresh is complete. Storage-key rotation re-encrypts conU-owned local encrypted-at-rest message queue/inbox payload files while retaining archived old keys for read compatibility, and storage-key retirement removes only archived keys no scanned local payload file still references. Secure Enclave, HSM, and managed key administration remain future work.
- Direct QUIC is active for reachable configured endpoints between trusted peers. Route sync records static host candidate metadata from peer config, signed peer cards, or local config, and reports `nat_traversal_unavailable` when no candidate exists for NAT profiles that need traversal help. ICE-style candidate gathering, STUN/TURN negotiation, UDP hole punching, and managed hosted NAT traversal are not active yet, so relay remains the fallback for hard NATs.
- Local telemetry is allowlisted aggregate counters only. Hosted telemetry pipelines, retention controls, alerting, and distributed dashboards are not active yet.
- Stream writes count bytes and emit events. Local stream writes do not persist plaintext chunks; remote direct or relay writes are delivered as encrypted `stream_chunk` inbox envelopes, not as long-lived application stream sessions with end-to-end flow negotiation yet.
- Room membership remains the compatibility boundary for unconfigured room topics. `conu rooms policy`, SDK calls, and MCP tools can configure metadata-only per-topic publish/subscribe grants; once any policy exists for a room/topic, that topic requires explicit publisher and subscriber grants.
- Pairing is local trust-store groundwork, not full cross-machine rendezvous.
- MCP is stdio-only. HTTP MCP transport, auth, and remote MCP hosting are intentionally not implemented.
- Browser-native TypeScript protocol support is intentionally not implemented. The current `@conu/sdk` package is a Node wrapper, and browser-conditioned imports expose only a safe unsupported stub until hosted auth, browser transport, and key-handling rules are designed.
- Packaging is still local-first, but tagged release builds now fail closed unless Windows Authenticode and macOS Developer ID/notarization secrets are configured. Manual workflow builds can remain unsigned for maintainer smoke tests. Linux package-manager signing, OS package publishing, and auto-update are not implemented.
- The npm launcher template is present, but `@conu/cli` should only be published after GitHub Release archives and checksum files exist for the supported platforms.
- The Docker relay template runs the current relay with scoped credentials or a live-reloaded hashed credential manifest, optional hosted admin account-credential lifecycle, configurable connection/frame-rate caps, metadata-only accounting and abuse counters, idle/TTL session policy, durable ciphertext mailbox directory, and non-loopback token guard. The client supports `wss://`, but the relay server itself still needs TLS termination in front of it for public operation, and distributed hosted account/session/abuse services are not implemented.

## Release Blockers

- Distributed multi-instance relay session migration/accounting, distributed hosted accounting dashboards beyond local dashboard snapshots, hosted retry policy, scheduled/distributed hosted mailbox purge orchestration beyond the local confirm-gated command, and managed mailbox retention dashboards beyond relay-local audit snapshots.
- ICE-style direct NAT traversal, STUN/TURN support, UDP hole punching, and hosted direct-candidate rendezvous beyond the current static candidate metadata.
- Hosted multi-tenant room permission administration beyond the current local room topic policy file.
- Multi-tenant hosted SDK/MCP permission administration beyond the current local peer policy file.
- Browser-native TypeScript protocol support beyond the current fail-closed Node-wrapper package boundary.
- Secure Enclave, HSM, or managed key administration beyond current local OS/user secret backends.
- OS package-manager publishing, detached Linux package signatures, and auto-update policy.
- Published npm package backed by verified release checksums.
- Hosted telemetry pipeline, distributed hosted abuse monitoring beyond single-relay `.abuse` counters, adaptive response, bounded persistent queues, distributed managed account lifecycle, and hosted token distribution workflows.
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
- Route registry, route probes, and route logs contain route metadata only, and rejected direct endpoint strings are sanitized before persistence.
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

Current status is `daemon_relay_message_stream_chunk_room_topic_policy_durable_mailbox_offline_relay_credential_issuance_manifest_lifecycle_hashed_relay_credential_manifest_account_admin_lifecycle_accounting_quotas_abuse_counters_hosted_dashboard_snapshot_session_resume_session_state_authenticated_direct_quic_log_rotation_structured_telemetry_identity_key_rotation_storage_key_rotation_and_retirement_windows_dpapi_macos_keychain_linux_secret_service_nonwindows_user_managed_secret_wrap_key_stored_relay_client_credentials_local_capabilities_signed_agent_cards_peer_policy_and_auto_agent_card_exchange_ready_with_known_limits`.

This means a developer can install, initialize, start conUD, pair locally, exchange signed public peer cards, grant peer-scoped message/stream/room policy, configure per-topic room publish/subscribe grants for local or relay-backed room events, exchange signed public agent cards manually or automatically during session sync, send a peer-encrypted one-shot message, stream chunk, or room event through authenticated direct QUIC when the peer endpoint is reachable or through a reachable `ws://` relay or certificate-valid `wss://` relay path without manual per-message sync, keep the daemon relay session alive across runtime ticks, resume the same-node relay session after a same-process socket reconnect to the same endpoint, persist same-node relay session state across relay restarts when `CONU_RELAY_SESSION_STATE_DIR` is set, receive bounded offline relay envelopes after reconnect, persist those ciphertext envelopes across relay restarts when `CONU_RELAY_MAILBOX_DIR` is set, audit durable mailbox retention metadata without displaying frames or ciphertext bodies, purge expired durable mailbox files only after dry-run or explicit confirmation, persist metadata-only relay accounting counters and optional per-node sent quotas when `CONU_RELAY_ACCOUNTING_DIR` and quota env vars are set, persist metadata-only relay abuse counters when `CONU_RELAY_ABUSE_DIR` is set, render a payload-safe local hosted dashboard snapshot across credential, tenant, accounting, and abuse stores, probe configured direct QUIC candidates before selecting them, rotate local metadata logs without displaying contents, export allowlisted local telemetry counters without displaying contents, rotate local identity signing/exchange keys without displaying key material, rotate local storage keys and re-encrypt conU-owned encrypted-at-rest message queue/inbox payload files without displaying contents, retire unused archived local storage keys without displaying contents, wrap local Windows private key and stored relay credential bytes with current-user DPAPI, store macOS local secrets in user Keychain, store Linux local secrets in Secret Service when available, wrap non-Windows local secret files with a user-managed XChaCha20Poly1305 key when configured, store a relay client credential without displaying it, run readiness checks, configure basic relay connection/frame limits, issue scoped relay credentials without printing raw tokens to stdout, upsert/rotate/revoke credential manifests without displaying token material, run account-scoped online issue/rotate/revoke/audit against a live relay credential manifest, assign per-node relay credentials through a live-reloaded hashed credential manifest with revocation/expiry metadata, configure a metadata-only hosted tenant registry for issue/rotate and new-session fail-closed checks, configure relay idle/TTL and offline-mailbox policy, reject unsafe public dev-token binds, verify release archives before publication, generate GitHub artifact attestations for archives/checksums, publish platform archives/checksums to GitHub Releases on tags with Windows Authenticode and macOS notarization when maintainer secrets are configured, optionally publish npm packages with provenance, and inspect payload-safe logs. It does not mean conU is ready as a hosted public internet network with hosted TLS policy, hosted distributed accounting dashboards, distributed multi-instance session migration, hosted dashboards and adaptive abuse workflows, distributed tenant lifecycle, full hosted identity/key administration, or managed NAT traversal.
