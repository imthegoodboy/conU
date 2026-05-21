# conU Release Checklist

Use this checklist before publishing any conU build.

## Version And Scope

- Confirm the release version in all Cargo packages.
- Confirm `packaging/npm/conu-cli/package.json` has the same version.
- Confirm `sdk/typescript/package.json` has the same version if publishing the TypeScript/JavaScript SDK package.
- Confirm `plan.md` reflects the completed phase and known gaps.
- Confirm Phase 14 room claims stay scoped to implemented local metadata/fanout, relay-backed room-event fanout, and local room topic policy behavior. Do not claim hosted multi-tenant room permission administration.
- Confirm relay hosting docs mention `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, `CONU_RELAY_MAX_FRAMES_PER_MINUTE`, `CONU_RELAY_IDLE_TIMEOUT_SECONDS`, `CONU_RELAY_SESSION_TTL_SECONDS`, `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE`, `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`, optional `CONU_RELAY_MAILBOX_DIR`, optional `CONU_RELAY_ACCOUNTING_DIR`, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS`, `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE`, `CONU_RELAY_MAX_BYTES_SENT_PER_NODE`, and optional `CONU_RELAY_ADMIN_TOKEN` for account-scoped online credential lifecycle.
- Confirm non-loopback relay examples use custom shared or scoped tokens with at least 24 characters, not `local-dev-token`.
- Confirm hosted/self-hosted examples prefer live-reloaded `CONU_RELAY_CREDENTIALS_FILE` where node ids are known, and that manifest examples store `token_sha256_hex`, `token_length`, status/expiry metadata, `payload_displayed = false`, and `token_displayed = false`.
- Confirm credential issuance examples use `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` where a manifest should be updated, `--replace` for rotation, `conu-relay --revoke-credential <node-id> --credentials-file <path>` for revocation, or `conu-relay --hash-token` without printing raw tokens to docs, logs, or command output.
- Confirm hosted admin examples use `conu-relay --admin-issue-credential`, `--admin-rotate-credential`, `--admin-revoke-credential`, and `--admin-audit-credentials` only with `--admin-token-stdin`, and that outputs show ids/counts/status plus display guards without raw node tokens, token hashes, admin tokens, payloads, or manifest contents.
- Confirm runtime relay client examples use either `CONU_RELAY_TOKEN` or `conu relay credential set --stdin`, and `conu relay credential status/clear` never display token material.
- Confirm identity-key rotation examples use `conu security rotate identity --confirm-peer-refresh`, then `conu identity export`, and optionally `conu security retire identity --confirm-peer-refresh-complete` only after peer-card refresh is complete; these commands must never display private signing/exchange keys or DPAPI blobs.
- Confirm non-Windows hardening docs explain `CONU_SECRET_WRAP_KEY_HEX` and `CONU_SECRET_WRAP_KEY_FILE`, and that the configured wrap key is operator-managed, never stored by conU, and never passed on the command line.
- Confirm cross-machine trust examples carry `signingPublicKeyHex`, `signatureHex`, and `signatureKeyId` from `conu identity export --json`, and peer imports reject tampered signed cards.
- Confirm cross-machine relay examples grant only intended surfaces with `conu peers policy` after peer trust and before remote sends/streams.
- Confirm room examples use `conu rooms policy` only for metadata-only per-topic publish/subscribe grants and explain that unconfigured topics still use room membership as the compatibility boundary.
- Confirm remote agent examples prefer automatic encrypted signed agent-card exchange during session sync, and manual fallback imports still carry signed agent-card fields from `conu agents export --json` with an already trusted peer node id and matching signing key.
- Confirm public relay examples use `wss://` when they describe internet-facing traffic, and state that `conu-relay` itself still needs TLS termination in front of it.
- Confirm public internet claims are limited to the current authenticated direct QUIC path for reachable configured endpoints, daemon-pumped relay message, stream-chunk, room-event, signed-card control, same-process same-node relay-session resume, offline scoped credential issuance plus manifest upsert/rotate/revoke helpers, account-scoped online credential issue/rotate/revoke/audit APIs, live-reloaded hashed relay credential manifest, metadata-only relay accounting/quotas, and bounded offline-mailbox paths unless distributed hosted session state, distributed hosted dashboards/accounting, hosted mailbox retention policy, distributed tenant lifecycle, and managed NAT traversal are implemented.

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
- `conu security audit` reports initialized local controls, the secret storage backend, and whether local secret bytes are OS-protected. Windows should report `windows-dpapi-user`, macOS should report `macos-keychain-user`, Linux with Secret Service should report `linux-secret-service-user`, and a configured non-Windows user-managed wrap key should report `user-managed-wrap-key-v1` while keeping `secretsOsProtected = false`.
- macOS and Linux native secret storage smoke coverage follows `docs/native-secret-storage.md` where those platform services are available.
- `conu security rotate identity --confirm-peer-refresh` and `conu security retire identity --confirm-peer-refresh-complete` report only key ids, archive counts, refresh/confirmation booleans, compatibility status, and `contentsDisplayed=false`; they must not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- `conu security rotate storage --confirm` reports only old/new key ids and migration counts; it must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu security retire storage --confirm` reports only archived-key, migrated-file, and dependent-file counts; it must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu relay credential status --json` reports configuration/backend/protection status only, with `contentsDisplayed` false and no token fields.
- Hosted relay admin issue/rotate/revoke/audit commands read admin tokens from stdin, do not print raw node tokens or token hashes, and report `tokenDisplayed=false` and `contentsDisplayed=false`.
- CLI output does not show message text, prompt text, reasoning, file contents, private keys, shared secrets, or raw payload bytes.
- Logs use metadata-only fields such as `payload=not_observed`.
- Relay frames carry ciphertext bodies only; no plaintext payload fields are accepted or logged.
- Release archives do not include `CONU_HOME`, `.conu`, `node.toml`, `security/*.key`, `messages/`, `runtime/`, `logs/`, or `routes/` from a developer machine.
- MCP stdout remains JSON-RPC only.
- `conu_receive_message` and SDK receive APIs return payload bytes only to the addressed local agent by explicit request.
- TypeScript/JavaScript SDK payload helpers pass bytes through stdin and do not put payload contents in argv, logs, or wrapper output.
- TypeScript/JavaScript SDK raw inbox receive is explicit, addressed-agent scoped, and routed through `conu-mcp`/`conu_receive_message` rather than normal metadata listings.
- TypeScript/JavaScript SDK browser-conditioned exports fail closed and do not accept private keys, relay tokens, endpoint secrets, payload bytes, or account credentials.

## Packaging

- Release archive includes `bin/conu`, `bin/conud`, `bin/conu-relay`, and `bin/conu-mcp`.
- Release archive includes docs and the required packaging templates: Windows install/uninstall scripts, Linux systemd unit, macOS launchd plist, Docker relay files, and npm launcher install metadata.
- `manifest.toml` contains `payload_contents_included = false`.
- Release archive has a matching `.sha256` checksum file.
- macOS npm release assets are ZIP archives so Apple notarization can run on the distribution container.
- `scripts/verify-release-artifacts.py dist` passes for every archive and rejects local conU state, logs, private key files, inboxes, route registries, telemetry dumps, node modules, vendored package binaries, and payload-bearing paths.
- Windows install script copies binaries to a current-user install directory.
- Linux systemd template is present and documents the required user/state path edits.
- macOS launchd template is present and documents the required user/state path edits.
- Docker relay template is present and documents current relay limits and knobs.
- npm launcher package passes `npm run check` from `packaging/npm/conu-cli`.
- TypeScript/JavaScript SDK package passes `npm run check --prefix sdk/typescript`.

## Platform Signing

- Repository signing secrets are configured before a `v*` tag release:
  `CONU_WINDOWS_SIGN_CERT_PFX_BASE64`, `CONU_WINDOWS_SIGN_CERT_PASSWORD`,
  `CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64`,
  `CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD`,
  `CONU_MACOS_CODESIGN_IDENTITY`, `CONU_MACOS_NOTARY_APPLE_ID`,
  `CONU_MACOS_NOTARY_TEAM_ID`, and `CONU_MACOS_NOTARY_PASSWORD`.
- Windows release ZIPs contain Authenticode-signed binaries. Verify after extraction:

```powershell
Get-AuthenticodeSignature .\bin\conu.exe
Get-AuthenticodeSignature .\bin\conud.exe
Get-AuthenticodeSignature .\bin\conu-relay.exe
Get-AuthenticodeSignature .\bin\conu-mcp.exe
```

- macOS release ZIPs contain Developer ID-signed binaries and are submitted to Apple notarization by the release workflow. Verify after extraction:

```sh
codesign --verify --strict --verbose=2 bin/conu
codesign --verify --strict --verbose=2 bin/conud
codesign --verify --strict --verbose=2 bin/conu-relay
codesign --verify --strict --verbose=2 bin/conu-mcp
spctl -a -vv -t exec bin/conu
```

- Linux release tarballs use SHA-256 checksum files plus GitHub artifact attestations until distro package signing exists:

```sh
sha256sum -c conu-0.1.0-linux-x64.tar.gz.sha256
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

- Signing workflows and logs do not print certificates, private keys, signing passwords, npm tokens, relay tokens, local conU state, or payload contents.
- See `docs/platform-code-signing.md` for the full signing policy and secret names.

## GitHub

- CI passed on pull request or equivalent local validation is recorded, including the Rust OS matrix and the package job for `sdk/typescript` plus `packaging/npm/conu-cli`.
- PR body lists validation commands.
- The `Release Artifacts` workflow is green for the release tag.
- GitHub Release has platform-named archives plus matching `.sha256` files before npm publishing.
- GitHub artifact attestations exist for every platform archive and checksum file generated by the release workflow.
- Verify a downloaded archive's provenance before install when `gh` is available:

```sh
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

- `@conu/cli` and `@conu/sdk` npm package dry-runs pass before publication.
- `@conu/cli` and `@conu/sdk` are published only after the matching GitHub Release assets are available; configure the repository `NPM_TOKEN` secret for automated npm publication with provenance.
- Platform signing workflow is implemented for tagged releases: Windows Authenticode, macOS Developer ID signing/notarization, Linux SHA-256 plus GitHub artifact attestations.
- `plan.md` completion log is updated.
- Issue is closed by PR merge.

## Release Decision

Use one of:

```txt
local_release_ready
needs_fix
blocked
```

Current decision target is `daemon_relay_message_stream_chunk_room_topic_policy_durable_mailbox_live_reloaded_hashed_relay_credential_manifest_account_admin_lifecycle_accounting_quotas_session_resume_authenticated_direct_quic_log_rotation_identity_key_rotation_and_retirement_storage_key_rotation_and_retirement_windows_dpapi_macos_keychain_linux_secret_service_nonwindows_user_managed_secret_wrap_key_stored_relay_client_credentials_local_capabilities_signed_agent_cards_peer_policy_auto_agent_card_exchange_attested_release_archives_and_platform_signing_workflow_ready_with_known_limits`. Public hosted/internet release remains blocked until distributed hosted session state, distributed hosted dashboards/accounting, hosted mailbox retention policy, hosted multi-tenant permission administration, distributed tenant lifecycle, and managed NAT traversal are finished.
