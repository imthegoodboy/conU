# conU Repository Overview

This repository contains conU, an agent-native encrypted communication layer.

conU is not an agent framework. It is the runtime, protocol, CLI, and network layer that lets trusted agents discover each other, connect, send opaque messages, stream events, and maintain sessions across machines.

## Current State

The repository has completed Phase 14 and Phase 15 for the current local-first app. It includes authenticated direct QUIC probing and message/stream-chunk delivery for reachable trusted peers, daemon-pumped relay-backed one-shot message, stream-chunk, and room-event delivery, peer-scoped default-deny policy grants for trusted peers, automatic encrypted signed agent-card exchange during session sync, bounded offline relay mailbox delivery with optional durable ciphertext files, payload-safe local/admin-gated relay session-state audits, payload-safe local and admin-gated online relay mailbox retention audits, confirm-gated local, admin-gated online, and guarded hosted fleet expired mailbox purge, relay-local scheduled expired mailbox purge, offline scoped relay credential issuance with manifest upsert/rotate/revoke helpers, account-scoped online hosted relay credential issue/rotate/revoke/audit, manifest-backed scoped hosted admin tokens with payload-safe local audits, admin-gated online hosted tenant lifecycle, local/admin-gated hosted account suspension, guarded hosted fleet account/node audit, credential revoke, tenant account upsert/revoke, tenant-node upsert/revoke, and account/node suspension, admin-gated online hosted dashboard snapshots, local/admin-gated hosted abuse threshold reports with reusable policy files and optional fail-on-threshold exit status, guarded hosted fleet abuse response plans with optional fail-on-action exit status, live-reloaded hashed relay credential manifests, metadata-only relay accounting/quotas, metadata-only relay abuse counters, payload-safe hosted dashboard snapshots, payload-safe hosted fleet dashboard mailbox retention policy gates, payload-safe hosted relay readiness preflights, plus local rooms/pub/sub metadata with encrypted-at-rest local fanout to joined local participants.

Implemented so far:

- project memory and architecture
- Rust workspace scaffold
- CLI identity/dashboard command shell
- local node identity persistence
- local config, trust store skeleton, and agent registry skeleton
- conUD runtime heartbeat/status skeleton
- `conu start`, `conu stop`, and runtime-aware `conu status`
- file-backed local IPC gateway under `runtime/ipc/`
- local agent registration through `conu agents register`
- local presence heartbeat through `conu agents heartbeat`
- persisted local agent registry with capability metadata and Ed25519 signatures
- core enforcement for local message, stream, and room capability booleans
- signed public agent-card export/import for trusted peers
- automatic peer-encrypted signed agent-card exchange during trusted session sync
- local opaque envelope submission through `conu messages send --stdin`
- local recipient inbox listing through `conu messages inbox`
- metadata-only delivery receipts through `conu messages receipts`
- conUD processing for local message delivery
- encrypted-at-rest local message request and inbox payload storage
- local X25519 peer key agreement helpers
- Windows current-user DPAPI wrapping for local signing, exchange, storage, and stored relay credential secret bytes, with migration-compatible reads for older plaintext-hex key files
- macOS user Keychain and Linux Secret Service native secret backends for local signing, exchange, storage, archived key, and stored relay credential secret bytes when available
- non-Windows user-managed secret wrapping through `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE`, with XChaCha20Poly1305 protection for local signing, exchange, storage, archived key, and stored relay credential secret fields when configured
- identity-key rotation through `conu security rotate identity --confirm-peer-refresh`, including archived old signing/exchange keys and refreshed public peer-card handoff
- identity archive retirement through `conu security retire identity --confirm-peer-refresh-complete` after peer-card refresh is complete
- storage-key rotation through `conu security rotate storage --confirm`, including archived old storage keys and local message queue/inbox re-encryption
- storage-key retirement through `conu security retire storage --confirm`, removing only archived keys no scanned local queue/inbox payload file still references
- signed manual public peer-card export/import through `conu identity export` and `conu peers trust`
- peer-scoped policy grants through `conu peers policy`
- relay-backed peer-encrypted remote message queueing through `conu messages send --peer`
- relay-backed peer-encrypted remote stream chunks through `conu streams write`
- relay-backed peer-encrypted room events through `conu rooms publish`
- metadata-only room topic publish/subscribe grants through `conu rooms policy`
- bounded relay mailbox delivery for peer-encrypted message, stream-chunk, room-event, and signed-card control envelopes when the target node reconnects, with optional `CONU_RELAY_MAILBOX_DIR` persistence across relay restarts, payload-safe local `conu-relay --mailbox-audit` and admin-gated online `conu-relay --admin-mailbox-audit` retention snapshots with reusable `--retention-policy-file` policy files, confirm-gated local `conu-relay --mailbox-purge`, admin-gated online `conu-relay --admin-mailbox-purge`, guarded local fleet `conu-relay --hosted-fleet-mailbox-purge` expired-file cleanup, and optional relay-local `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` scheduled cleanup
- daemon-owned relay send/receive pump with reusable relay sessions and same-node resume when relay config or trusted relay peer endpoints exist, plus optional `CONU_RELAY_SESSION_STATE_DIR` metadata persistence across relay restarts and payload-safe local/admin-gated session-state audits through `conu-relay --session-audit` and `conu-relay --admin-session-audit`
- explicit manual relay send/receive sync through `conu relay sync`
- replay protection for local message request and envelope ids
- `conu security audit` for payload-safe hardening status
- Rust SDK crate `conu-sdk` for agent-facing registration, messaging, receive, peer, security, and stream calls
- MCP stdio adapter crate `conu-mcp` exposing conU tools over newline-delimited JSON-RPC
- Python stdlib wrapper SDK under `sdk/python`
- TypeScript/JavaScript wrapper SDK under `sdk/typescript`
- explicit TypeScript addressed-agent receive helpers backed by MCP `conu_receive_message`
- fail-closed browser export boundary for `@conu/sdk`; browser-native protocol support remains future work
- local examples for Rust, Python, and TypeScript agents
- local pairing invitation creation through `conu pair`
- local pairing join/trust creation through `conu join <code>`
- trusted peer listing and revocation through `conu peers`
- shared relay frame contract in `conu-core`
- small plain `conu-relay` WebSocket service
- offline scoped relay credential issuance through `conu-relay --issue-credential`, writing raw tokens to a chosen file while manifest upsert/rotation output reports only counts, paths, and status
- relay session authentication with a shared token, compatibility static per-node scoped credentials, or a live-reloaded hashed `CONU_RELAY_CREDENTIALS_FILE` manifest with status/expiry metadata and helper-driven upsert/replace/revoke operations
- hosted relay account metadata and online admin lifecycle through `CONU_RELAY_ADMIN_TOKEN`, optional hashed scoped entries in `CONU_RELAY_ADMIN_TOKENS_FILE`, payload-safe local `--admin-token-audit`, `--admin-issue-credential`, `--admin-rotate-credential`, `--admin-revoke-credential`, `--admin-audit-credentials`, and `--admin-session-audit`, with admin-token stdin, node-token hash-only relay updates, scope/account enforcement, and metadata-only audit output
- metadata-only hosted tenant registry through `CONU_RELAY_TENANTS_FILE`, local `conu-relay --tenant-*` commands, and admin-gated online `conu-relay --admin-tenant-*` commands for account/node status, hosted permission booleans, and public key-id metadata without granting local peer policy
- local and admin-gated hosted account suspension through `conu-relay --hosted-account-suspend` and `conu-relay --admin-hosted-account-suspend`, plus guarded local fleet account/node audit, credential revoke, tenant account upsert/revoke, tenant-node upsert/revoke, and account/node suspension through `conu-relay --hosted-fleet-account-audit`, `conu-relay --hosted-fleet-credential-revoke`, `conu-relay --hosted-fleet-tenant-upsert`, `conu-relay --hosted-fleet-tenant-revoke`, `conu-relay --hosted-fleet-tenant-node-upsert`, `conu-relay --hosted-fleet-tenant-node-revoke`, and `conu-relay --hosted-fleet-account-suspend`, reporting account-wide or node-scoped credential/tenant consistency warnings before mutation, preflighting credential revoke, tenant account lifecycle, and tenant-node lifecycle sources before mutation, rejecting credential node ownership collisions or duplicates, revoking tenant metadata before account credential records in account-wide mode, and revoking tenant-node metadata before node credential records with `--node` while reporting metadata-only counts and display guards
- configurable relay total connection, per-IP connection, and per-session frame-rate caps
- configurable relay idle timeout and max session TTL
- metadata-only relay accounting with optional file-backed authenticated/resumed session counters and per-node sent quotas
- metadata-only relay abuse/dashboard counters for denial and enforcement trends
- local/admin-gated relay abuse threshold reports that compare aggregate counters against inline or reusable policy-file maximums, optionally exit 3 for script automation, and avoid adaptive enforcement
- guarded hosted fleet abuse response plans that reuse fleet manifests and threshold policies to map aggregate threshold breaches to static operator action categories without mutating relay state
- payload-safe local `conu-relay --hosted-dashboard` snapshots and admin-gated online `conu-relay --admin-hosted-dashboard` snapshots across credential, tenant, accounting, and abuse stores
- manifest-driven payload-safe `conu-relay --hosted-fleet-dashboard` snapshots that aggregate multiple relay-local credential, tenant, session-state, mailbox, accounting, and abuse metadata stores with optional guarded mailbox retention policy gates and optional guarded abuse threshold policy checks, without printing secrets or payloads
- guarded local `conu-relay --hosted-fleet-mailbox-purge` dry-run/confirm cleanup across manifest-listed local mailbox stores, using the same metadata-only retention policy files and reporting only aggregate/per-relay counts
- payload-safe local `conu-relay --hosted-readiness` preflights across credential, scoped admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks, with optional fail-on-warning exit code 3
- admin-gated online `conu-relay --admin-mailbox-audit` snapshots and `conu-relay --admin-mailbox-purge` dry-run/confirm cleanup for running-relay durable mailbox retention metadata, including reusable metadata-only retention policy files for TTL/node settings
- relay public-bind guard that keeps `local-dev-token` loopback-only
- local relay client credential storage through `conu relay credential set --stdin`, with token-safe status and clear commands
- relay client support for `ws://` plus certificate-validated `wss://` endpoints through TLS termination
- connected-runtime blind forwarding with `WELCOME`, `ENVELOPE`, `SENT`, and `UNDELIVERED` frames
- conUD-owned remote session sync through `conu sessions sync`
- remote runtime session metadata under `sessions/registry.toml`
- trusted remote agent mirror under `agents/remote.toml`
- remote agents visible through `conu agents`
- stream lifecycle metadata through `conu streams`
- stream open/write/close commands with stdin-only opaque writes
- local connect flows through `conu connect local`
- rooms/pub-sub metadata and per-topic authorization through `conu rooms`
- encrypted-at-rest local room event fanout to joined local participants' message inboxes plus relay-backed room event fanout to joined trusted remote participants
- room tools in the Rust SDK, Python wrapper SDK, TypeScript wrapper SDK, and MCP adapter
- payload-safe watch event bus under `streams/events.toml`
- payload-safe room event bus under `rooms/events.toml`
- `conu watch` private transport animation
- conUD-owned direct/relay route manager through `conu routes`, including authenticated direct QUIC probes, static candidate metadata, NAT-unavailable reporting, and relay fallback
- peer-encrypted direct QUIC one-shot message and stream-chunk delivery for reachable trusted peer endpoints
- conUD-owned reusable relay session pump for peer-encrypted one-shot remote message delivery
- metadata-only route registry under `routes/registry.toml`
- metadata-only route probes under `routes/probes.toml`
- route sync integration with remote sessions, streams, Rust SDK, Python wrapper SDK, TypeScript wrapper SDK, and MCP
- `conu doctor` local install/readiness check with payload-safe log scanning
- `conu telemetry snapshot` local structured telemetry with an explicit payload-safe field allowlist and aggregate counters only
- `conu update check --policy-file <path> [--gpg-verify]` and `conu update check --policy-url <https-url> [--gpg-verify]` installed release update-policy validation, including strict checksum sidecar matching, detached-signature sidecar presence, optional GPG verification, public URL checks, npm package version matching, false display guards, auto-apply disabled, and bounded remote policy/sidecar fetching; `conu update download --policy-file <path>|--policy-url <https-url> --output-dir <dir> [--target <target>] [--gpg-verify]` revalidates that policy, downloads one selected public platform archive plus strict `.sha256` and detached `.asc` sidecars with HTTPS/TLS/public-host/timeout/size/redirect limits, verifies SHA-256 and optional GPG signature, and writes only to an operator-chosen output directory without clobbering existing files; `conu update apply --policy-file <path>|--policy-url <https-url> --artifact-file <archive> --install-dir <dir> [--target <target>] [--gpg-verify] (--dry-run|--confirm)` revalidates the policy/archive, rejects cross-target and unsafe archive members, stages only the four conU binaries, reports dry-run install plans without writing, and backs up existing binaries before confirmed replacement
- release build scripts under `scripts/`
- bounded streaming release archive verifier under `scripts/verify-release-artifacts.py` with regression checks in `scripts/check-release-artifact-verifier.py`
- packaging templates under `packaging/`, including Windows install, Linux systemd, macOS launchd, Docker relay, and npm launcher templates
- platform-named release artifacts with SHA-256 checksum support
- live tagged-release readiness audit under `scripts/check-tagged-release-readiness.py`, combining release-secret name presence, default Pages or custom S3 repository settings, GitHub Release clobber status, package version/tag consistency, optional target-commit CI status, optional default-branch head matching, optional npm registry availability, and payload-safe JSON/text output before a maintainer creates a production tag
- release secret setup under `scripts/set-github-release-secrets.py`, with dry-run value preflights for Windows/macOS PKCS#12 and Linux GPG signing values before GitHub writes and stdin-only `gh secret set` uploads
- GitHub CI and release artifact workflows, including Rust OS-matrix checks plus TypeScript SDK, release artifact verifier regression checks, release artifact smoke preflight regression checks for missing/non-file binaries before execution, package-manager manifest generation regressions with APT/RPM metadata checks plus native RPM spec and RPM asset preflight, package-manager submission bundle regressions, release update-policy regressions, release update-download/apply dry-run gate regressions, Linux signing-secret preflight regression checks, Windows/macOS signing-secret value preflight regression checks, native RPM package-signing regression checks, fingerprint-pinned Linux detached-signing regression checks, fingerprint-pinned Linux repository-signing regression checks, hosted Linux repository bundle, site, Pages extraction, custom S3 publication, and endpoint cache-header regression checks, GitHub Pages repository-setting readiness checks, GitHub Release clobber preflight regression checks, GitHub Release asset publication regression checks, fingerprint-pinned Linux GPG public-key export regression checks, npm launcher local-smoke preflight regression checks, npm launcher package checks with local binary directory preflight, archive-member count/duplicate/state-path preflight, trusted download URL, strict checksum archive-name matching, streamed npm archive hashing, bounded extracted-tree scanning, exact extracted release-root binary selection, bounded download coverage, verified npm package content dry-runs, npm publish metadata and duplicate-version preflights before tagged publication, bounded streaming release archive verification, GitHub Release asset upload including generated Homebrew/Scoop/winget/Chocolatey/Debian/RPM package-manager files, a signed package-manager submission bundle, signed RPM packages, signed APT/RPM repository metadata ZIPs, a signed hosted Linux repository bundle, a signed hosted Linux repository site artifact with public endpoint metadata, install snippets, and checked cache policy files, signed `conu-<version>-update-policy.json` metadata with public asset URLs, strict SHA-256 values, signature URLs, npm package versions, and auto-apply disabled, post-upload public `conu update check --policy-url --gpg-verify`, `conu update download --policy-url --gpg-verify`, and `conu update apply --policy-url --gpg-verify --dry-run` verification against the published GitHub Release, verified GitHub Pages deployment prep for the default repository Pages URL, supported S3-compatible custom hosted repository publication with live endpoint readiness before npm, default Pages repository metadata preflight on tags, live hosted repository endpoint metadata/cache-header readiness tooling for custom HTTPS URLs, metadata-only GitHub Release clobber checks before asset upload, metadata-only public GitHub Release asset checks before npm registry access, `conu-linux-gpg-key.asc` plus its `.sha256` sidecar, detached Linux `.asc` signatures, and optional npm package publishing
- GitHub artifact attestation generation for release archives and checksum files
- tagged release signing workflow for Windows Authenticode and macOS Developer ID/notarized ZIP archives, with fail-closed Windows/macOS PKCS#12 value parsing and Linux GPG key import/fingerprint/probe-sign preflight, Linux SHA-256, GitHub-attestation, fingerprint-pinned public GPG key release asset, native RPM package signatures, native repository metadata signatures, and detached GPG `.asc` signature policy
- release checklist and observability docs
- payload-safe status and agent registry reporting
- payload-safe runtime and agent metadata logs
- payload-safe message delivery metadata logs
- payload-safe remote session metadata logs
- payload-safe stream metadata logs
- payload-safe route metadata logs
- payload-safe local log rotation through `conu logs rotate`
- payload-safe structured telemetry snapshot through `conu telemetry snapshot`
- payload-safe protocol scaffold
- daemon runtime skeleton and relay service binary

Current important files:

- `architecture.md`: production architecture and protocol direction.
- `plan.md`: phase-by-phase execution plan.
- `docs/direct-transport-and-routes.md`: Phase 13 route manager, config, and privacy boundary.
- `docs/internet-relay-test.md`: current relay-backed remote message smoke test.
- `docs/distribution-and-hosting.md`: how users install conU, how npm packaging should publish native binaries, and how to self-host the current relay.
- `docs/hosted-relay-account-auth.md`: account-scoped hosted relay credential lifecycle, tenant registry, and privacy boundary.
- `docs/browser-native-typescript.md`: browser boundary and future browser-native TypeScript protocol requirements.
- `docs/native-secret-storage.md`: native and fallback local secret backend selection plus platform smoke checks.
- `docs/platform-code-signing.md`: platform signing/notarization policy, required GitHub secrets, and verification commands.
- `docs/release-checklist.md`: Phase 15 release gate.
- `docs/observability.md`: payload-safe observability policy.
- `packaging/README.md`: install, npm launcher, Docker relay, and service templates.
- `.agents/AGENTS.md`: future-agent onboarding.
- `.agents/about/`: original product vision.
- `.agents/Rules/SKILL.MD`: hard project rules.
- `.agents/Pr/SKILL.MD`: runtime/protocol memory.
- `.agents/skills/conu-builder/`: main implementation skill.
- `.agents/skills/conu-repo-steward/`: repo navigation and working rules.
- `.agents/skills/conu-phase-keeper/`: phase tracking and `plan.md` updates.
- `.agents/skills/conu-pr-guardian/`: PR and pre-merge review.
- `.agents/skills/conu-security-guardian/`: privacy and security review.

## Intended Future Layout

```txt
crates/
|- conu-cli/       human control room
|- conud/          local daemon/runtime
|- conu-core/      shared runtime logic
|- conu-protocol/  protocol types and envelopes
|- conu-relay/     hosted WebSocket relay/bootstrap service
|- conu-sdk/       Rust agent-facing client API
`- conu-mcp/       MCP stdio adapter for agent tool use
```

Current Rust crates:

- `crates/conu-cli`
- `crates/conud`
- `crates/conu-core`
- `crates/conu-protocol`
- `crates/conu-relay`
- `crates/conu-sdk`
- `crates/conu-mcp`

## Non-Negotiable Product Rule

```txt
Agents own the conversation.
conU owns the connection.
```

conU must never become the agent brain, orchestrator, message inspector, or prompt manager.

## Future Agent Start Sequence

Before changing code:

1. Read `architecture.md`.
2. Read `plan.md`.
3. Read this file.
4. Read `.agents/AGENTS.md`.
5. Use the relevant skill in `.agents/skills/`.

Before opening a PR or merging:

1. Use `.agents/skills/conu-pr-guardian/SKILL.md`.
2. Use `.agents/skills/conu-security-guardian/SKILL.md` for any networking, protocol, logging, storage, encryption, relay, CLI watch, SDK, or IPC change.
3. Update `plan.md` if a phase changed.
4. Record validation honestly.
