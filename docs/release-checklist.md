# conU Release Checklist

Use this checklist before publishing any conU build.

## Version And Scope

- Confirm the release version in all Cargo packages.
- Confirm `packaging/npm/conu-cli/package.json` has the same version.
- Confirm `sdk/typescript/package.json` has the same version if publishing the TypeScript/JavaScript SDK package.
- Confirm `plan.md` reflects the completed phase and known gaps.
- Confirm Phase 14 room claims stay scoped to implemented local metadata/fanout, relay-backed room-event fanout, and local room topic policy behavior. Do not claim hosted multi-tenant room permission administration.
- Confirm relay hosting docs mention `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, `CONU_RELAY_MAX_FRAMES_PER_MINUTE`, `CONU_RELAY_IDLE_TIMEOUT_SECONDS`, `CONU_RELAY_SESSION_TTL_SECONDS`, `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE`, `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`, optional `CONU_RELAY_MAILBOX_DIR`, optional `CONU_RELAY_ACCOUNTING_DIR`, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS`, `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE`, and `CONU_RELAY_MAX_BYTES_SENT_PER_NODE`.
- Confirm non-loopback relay examples use custom shared or scoped tokens with at least 24 characters, not `local-dev-token`.
- Confirm hosted/self-hosted examples prefer live-reloaded `CONU_RELAY_CREDENTIALS_FILE` where node ids are known, and that manifest examples store `token_sha256_hex`, `token_length`, status/expiry metadata, `payload_displayed = false`, and `token_displayed = false`.
- Confirm credential issuance examples use `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` where a manifest should be updated, `--replace` for rotation, `conu-relay --revoke-credential <node-id> --credentials-file <path>` for revocation, or `conu-relay --hash-token` without printing raw tokens to docs, logs, or command output.
- Confirm runtime relay client examples use either `CONU_RELAY_TOKEN` or `conu relay credential set --stdin`, and `conu relay credential status/clear` never display token material.
- Confirm identity-key rotation examples use `conu security rotate identity --confirm-peer-refresh`, then `conu identity export`, and optionally `conu security retire identity --confirm-peer-refresh-complete` only after peer-card refresh is complete; these commands must never display private signing/exchange keys or DPAPI blobs.
- Confirm cross-machine trust examples carry `signingPublicKeyHex`, `signatureHex`, and `signatureKeyId` from `conu identity export --json`, and peer imports reject tampered signed cards.
- Confirm cross-machine relay examples grant only intended surfaces with `conu peers policy` after peer trust and before remote sends/streams.
- Confirm room examples use `conu rooms policy` only for metadata-only per-topic publish/subscribe grants and explain that unconfigured topics still use room membership as the compatibility boundary.
- Confirm remote agent examples prefer automatic encrypted signed agent-card exchange during session sync, and manual fallback imports still carry signed agent-card fields from `conu agents export --json` with an already trusted peer node id and matching signing key.
- Confirm public relay examples use `wss://` when they describe internet-facing traffic, and state that `conu-relay` itself still needs TLS termination in front of it.
- Confirm public internet claims are limited to the current daemon-pumped relay message, stream-chunk, room-event, signed-card control, same-process same-node relay-session resume, offline scoped credential issuance plus manifest upsert/rotate/revoke helpers, live-reloaded hashed self-hosted relay credential manifest, metadata-only self-hosted relay accounting/quotas, and bounded offline-mailbox paths unless hosted account auth, online credential issuance APIs, distributed hosted session state, distributed hosted dashboards/accounting, hosted mailbox retention policy, and direct transport are implemented.

## Build

Windows:

```powershell
cargo fmt --all -- --check
cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu test --workspace
npm run check --prefix sdk/typescript
npm run check --prefix packaging/npm/conu-cli
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64
python scripts\verify-release-artifacts.py dist
```

macOS/Linux:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run check --prefix sdk/typescript
npm run check --prefix packaging/npm/conu-cli
./scripts/build-release.sh
PACKAGE_SUFFIX=linux-x64 ./scripts/build-release.sh
PACKAGE_SUFFIX=macos-arm64 ./scripts/build-release.sh
python scripts/verify-release-artifacts.py dist
```

## Smoke

```powershell
.\scripts\smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu
.\scripts\smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu
.\scripts\smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Manual installed smoke:

```sh
conu init
conu security audit
conu security rotate identity --confirm-peer-refresh
conu identity export
conu security retire identity --confirm-peer-refresh-complete
conu security rotate storage --confirm
conu security retire storage --confirm
conu doctor
conu telemetry snapshot --json
conu start
conu status
conu pair
conu join <code>
conu routes sync
conu identity export
conu connect
conu stop
```

## Privacy And Security

- `conu doctor` reports payload-safe logs.
- `conu logs rotate --max-bytes <bytes> --keep <count>` reports only file names, sizes, rotation counts, and `contentsDisplayed=false`; it must not print log contents.
- `conu telemetry snapshot --json` reports schema `conu.telemetry.snapshot.v1`, its explicit field allowlist, aggregate counters, and `contentsDisplayed=false`; it must not print node ids, agent ids, peer ids, endpoints, paths, log lines, key ids, secrets, or payload bodies.
- `conu security audit` reports initialized local controls, the secret storage backend, and whether local secret bytes are OS-protected.
- `conu security rotate identity --confirm-peer-refresh` and `conu security retire identity --confirm-peer-refresh-complete` report only key ids, archive counts, refresh/confirmation booleans, compatibility status, and `contentsDisplayed=false`; they must not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- `conu security rotate storage --confirm` reports only old/new key ids and migration counts; it must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu security retire storage --confirm` reports only archived-key, migrated-file, and dependent-file counts; it must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu relay credential status --json` reports configuration/backend/protection status only, with `contentsDisplayed` false and no token fields.
- CLI output does not show message text, prompt text, reasoning, file contents, private keys, shared secrets, or raw payload bytes.
- Logs use metadata-only fields such as `payload=not_observed`.
- Relay frames carry ciphertext bodies only; no plaintext payload fields are accepted or logged.
- Release archives do not include `CONU_HOME`, `.conu`, `node.toml`, `security/*.key`, `messages/`, `runtime/`, `logs/`, or `routes/` from a developer machine.
- MCP stdout remains JSON-RPC only.
- `conu_receive_message` and SDK receive APIs return payload bytes only to the addressed local agent by explicit request.
- TypeScript/JavaScript SDK payload helpers pass bytes through stdin and do not put payload contents in argv, logs, or wrapper output.
- TypeScript/JavaScript SDK raw inbox receive is explicit, addressed-agent scoped, and routed through `conu-mcp`/`conu_receive_message` rather than normal metadata listings.

## Packaging

- Release archive includes `bin/conu`, `bin/conud`, `bin/conu-relay`, and `bin/conu-mcp`.
- Release archive includes docs and packaging templates.
- `manifest.toml` contains `payload_contents_included = false`.
- Release archive has a matching `.sha256` checksum file.
- `scripts/verify-release-artifacts.py dist` passes for every archive and rejects local conU state, logs, private key files, inboxes, route registries, telemetry dumps, node modules, vendored package binaries, and payload-bearing paths.
- Windows install script copies binaries to a current-user install directory.
- Linux systemd template is present and documents the required user/state path edits.
- macOS launchd template is present and documents the required user/state path edits.
- Docker relay template is present and documents current relay limits and knobs.
- npm launcher package passes `npm run check` from `packaging/npm/conu-cli`.
- TypeScript/JavaScript SDK package passes `npm run check --prefix sdk/typescript`.

## GitHub

- CI passed on pull request or equivalent local validation is recorded, including the Rust OS matrix and the package job for `sdk/typescript` plus `packaging/npm/conu-cli`.
- PR body lists validation commands.
- The `Release Artifacts` workflow is green for the release tag.
- GitHub Release has platform-named archives plus matching `.sha256` files before npm publishing.
- `@conu/cli` and `@conu/sdk` npm package dry-runs pass before publication.
- `@conu/cli` and `@conu/sdk` are published only after the matching GitHub Release assets are available; configure the repository `NPM_TOKEN` secret for automated npm publication with provenance.
- Platform code signing is not implemented yet; the current release trust decision is CI-built archives, SHA-256 checksums, GitHub Release assets, and npm provenance when `NPM_TOKEN` is configured.
- `plan.md` completion log is updated.
- Issue is closed by PR merge.

## Release Decision

Use one of:

```txt
local_release_ready
needs_fix
blocked
```

Current decision target is `daemon_relay_message_stream_chunk_room_topic_policy_durable_mailbox_live_reloaded_hashed_relay_credential_manifest_lifecycle_accounting_quotas_session_resume_direct_route_selection_guard_log_rotation_identity_key_rotation_and_retirement_storage_key_rotation_and_retirement_windows_dpapi_stored_relay_client_credentials_local_capabilities_signed_agent_cards_peer_policy_and_auto_agent_card_exchange_ready_with_known_limits`. Public hosted/internet release remains blocked until hosted account auth, managed online credential issuance APIs, distributed hosted session state, distributed hosted dashboards/accounting, hosted mailbox retention policy, hosted multi-tenant room permission administration, direct QUIC, and non-Windows OS-backed key storage are finished.
