# conU Build Plan

This is the living execution plan for conU. Future agents must update this file when a phase is completed or materially changed.

## Update Rules For Agents

At the end of each completed phase, update:

- phase status
- summary of completed work
- files changed
- validation run
- known gaps
- recommended next phase

Do not mark a phase complete unless the implementation exists and validation was attempted. If validation cannot run, record why.

Status values:

```txt
not_started
in_progress
blocked
completed
needs_revision
```

## Current Status

```txt
Current phase: Phase 14 - Rooms, Pub/Sub, And Multi-Agent Sessions
Status: completed
Last updated: 2026-05-22
Note: Phase 14 and Phase 15 are complete for the current local-first app. Post-Phase-15 relay data-plane, CLI polish, daemon relay hardening, distribution/hosting, Phase 14 local rooms/pub-sub, relay abuse-control, reusable daemon relay-session, same-node relay-session resume, public-bind token-guard, `wss://` relay-client, static scoped relay credential/session-policy, offline scoped relay credential issuance, relay credential manifest upsert/rotate/revoke helpers, account-scoped online hosted relay credential issue/rotate/revoke/audit, scoped hosted admin-token manifest RBAC for credential/tenant/dashboard/session/mailbox actions, payload-safe local scoped admin-token manifest audit, payload-safe hosted relay readiness preflight, admin-gated online hosted relay dashboard snapshots, local/admin-gated hosted abuse threshold reports with reusable policy files and optional fail-on-threshold exit status, metadata-only hosted tenant registry, admin-gated online hosted tenant lifecycle, local and admin-gated hosted account suspension, live-reloaded hashed relay credential manifest, relay accounting/quotas, metadata-only relay abuse/dashboard counters, payload-safe hosted relay dashboard snapshots, payload-safe hosted relay readiness preflights, guarded hosted fleet dashboard snapshots with aggregate mailbox retention policy gates and aggregate abuse threshold checks, relay session state storage, payload-safe local/admin-gated relay session-state audit, direct route selection guard, authenticated direct QUIC probing and message/stream-chunk delivery for reachable trusted peers, static direct candidate metadata with NAT-unavailable reporting, payload-safe local log rotation, structured telemetry snapshot, identity-key rotation with peer-card refresh, identity archive retirement after peer-card refresh, storage-key rotation/re-encryption migration, storage-key retirement, relay-backed stream-chunk, relay-backed room-event fanout, room topic policy, bounded offline relay mailbox, durable relay mailbox storage, payload-safe durable mailbox retention audit, admin-gated online durable mailbox retention audit, reusable durable mailbox retention policy files, confirm-gated local and admin-gated online durable relay mailbox purge, relay-local scheduled durable relay mailbox purge, durable mailbox FIFO reload ordering, bounded relay sync wait handling, Windows DPAPI secret wrapping, macOS Keychain/Linux Secret Service secret storage, non-Windows user-managed secret wrapping, stored relay client credential, signed peer-card, local capability-enforcement, signed remote agent-card, peer-scoped permission-policy, automatic encrypted signed agent-card exchange, TypeScript/JavaScript SDK wrapper, TypeScript explicit addressed-agent receive helper, TypeScript browser boundary hardening, GitHub CI package-validation passes, release publishing workflow hardening, GitHub artifact attestation release hardening, platform signing/notarization workflow hardening, tagged release preflight hardening, and Node LTS package hardening are complete. Public hosted internet readiness remains scoped by the known distributed hosted accounting/dashboards/adaptive abuse workflows beyond local/admin-gated single-relay snapshots, guarded fleet snapshots, threshold reports, and readiness preflights, distributed multi-instance session migration, ICE/STUN/TURN managed direct NAT traversal, managed hosted identity/key administration, distributed tenant lifecycle/workflow automation beyond single-relay account suspension/scoped admin tokens, tenant-wide hosted dashboard workflow services, and distributed hosted mailbox retention orchestration beyond read-only fleet gates plus single-relay purge gaps.
```

## Phase 0 - Project Memory

Status: completed

Goal:

Create the shared architecture, rules, skill memory, and phase plan future agents must follow.

Deliverables:

- `architecture.md`
- `plan.md`
- `.agents/AGENTS.md`
- `.agents/repo/ABOUT.md`
- `.agents/Rules/SKILL.MD`
- `.agents/Pr/SKILL.MD`
- `.agents/skills/conu-builder/SKILL.md`
- `.agents/skills/conu-builder/references/*`
- `.agents/skills/conu-repo-steward/*`
- `.agents/skills/conu-phase-keeper/*`
- `.agents/skills/conu-pr-guardian/*`
- `.agents/skills/conu-security-guardian/*`

Completion checklist:

- [x] Architecture document exists.
- [x] Agent rules exist.
- [x] Repo-local conU builder skill exists.
- [x] Repo overview exists.
- [x] Repo steward skill exists.
- [x] Phase keeper skill exists.
- [x] PR guardian skill exists.
- [x] Security guardian skill exists.
- [x] Phase plan exists.
- [x] User approves moving into implementation.

Validation:

- Documentation reviewed manually.
- Repo-local skill validated with `quick_validate.py`.
- Additional repo skills validated with `quick_validate.py`.

Known gaps:

- No Rust code exists yet.
- No cargo validation can run until Rust is installed and project is scaffolded.

Next:

- Phase 1 completed after user approval.

## Phase 1 - Rust Workspace Scaffold

Status: completed

Goal:

Create the Rust workspace foundation for the CLI, daemon, protocol, and relay.

Deliverables:

- `Cargo.toml` workspace
- `crates/conu-cli`
- `crates/conud`
- `crates/conu-protocol`
- `crates/conu-core`
- `crates/conu-relay`
- `.gitignore`
- baseline README if needed

Validation:

- `cargo fmt`
- `cargo check`
- `cargo test`

Exit criteria:

- [x] Workspace compiles.
- [x] CLI binary starts with the GNU Rust toolchain.
- [x] Shared protocol crate builds.

Completed work:

- Created root Cargo workspace.
- Added compile-ready crates for CLI, daemon, core, protocol, and relay.
- Added std-only Phase 1 binaries so local validation works without MSVC Build Tools.
- Added opaque protocol payload primitives with Debug redaction.
- Added component manifest and product-law invariant in `conu-core`.
- Added README and `.gitignore`.
- Created GitHub issue #1 for this phase.

Files changed:

- `.gitignore`
- `Cargo.toml`
- `Cargo.lock`
- `.gitignore`
- `README.md`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/lib.rs`
- `crates/conu-protocol/Cargo.toml`
- `crates/conu-protocol/src/lib.rs`
- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/main.rs`
- `crates/conud/Cargo.toml`
- `crates/conud/src/main.rs`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed with the default MSVC Rust toolchain.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- components` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conud -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --check` passed.

Known gaps:

- Default MSVC `cargo test` and `cargo run` fail locally because Visual Studio C++ Build Tools / `link.exe` are not installed.
- Phase 1 intentionally avoids clap, Tokio, tracing, and serde until linker support or CI validation is available.
- No real daemon, IPC, relay networking, or persistent state exists yet.

Next:

- Start Phase 2: CLI identity and dashboard.

## Phase 2 - CLI Identity And Dashboard

Status: completed

Goal:

Build the first advanced CLI shell with ASCII identity, status layout, and production command structure.

Commands:

```txt
conu
conu init
conu status
conu agents
conu pair
conu join <code>
conu connect
conu watch
```

Exit criteria:

- [x] CLI renders cleanly on Windows terminals.
- [x] No private payload contents are displayed.
- [x] Commands have helpful structured output.

Completed work:

- Created GitHub issue #3 for Phase 2.
- Created and pushed branch `codex/phase-2-cli-dashboard`.
- Refactored `conu-cli` into a testable library plus thin binary adapter.
- Added ASCII dashboard for `conu`.
- Added command shell for `init`, `status`, `agents`, `peers`, `pair`, `join <code>`, `connect`, `watch`, `components`, and reserved `start`.
- Added text and JSON status/agent outputs where useful.
- Kept Phase 3+ behavior honest: no persistent identity, trust store, IPC, relay, or real daemon state is created in Phase 2.
- Added tests for command registration, dashboard rendering, status JSON, join usage, unknown command handling, and watch content privacy.
- Updated README and repo overview for the completed CLI shell.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `plan.md`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli --` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- agents` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- pair` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- join 482913` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- connect` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- watch` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- peers --json` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- start` passed.

Known gaps:

- No real local identity is created; that remains Phase 3.
- No real daemon lifecycle is implemented; that remains Phase 4.
- No real local agent registration exists; that remains Phase 5.
- Pairing/join are command-shape previews only; trust creation remains Phase 7.
- Watch shows a static transport view only; live animation remains Phase 10.

Next:

- Start Phase 3: local identity, config, trust store skeleton, and safe state path resolution.

## Phase 3 - Local Identity And Persistent State

Status: completed

Goal:

Create local node identity, config, trust store, and data directory.

Deliverables:

- node id generation
- local config file
- trust store skeleton
- agent registry persistence
- state path resolution

Exit criteria:

- [x] `conu init` creates local identity.
- [x] `conu status` reads identity and config.
- [x] Re-running init is safe.

Completed work:

- Created GitHub issue #5 for Phase 3.
- Created and pushed branch `codex/phase-3-local-identity`.
- Added std-only local state management in `conu-core`.
- Added safe state path resolution with `CONU_HOME`, Windows `%APPDATA%\conU`, and Unix `$HOME/.conu` fallback.
- Added idempotent creation of `node.toml`, `config.toml`, `trust.toml`, `agents/registry.toml`, and future runtime directories.
- Added `conu init` integration that creates or repairs Phase 3 state without overwriting existing files.
- Added `conu status` and `conu status --json` integration that reads persisted identity/config/trust/registry readiness.
- Added `conu agents --json` registry readiness metadata while keeping actual registration reserved for Phase 5.
- Added tests for local state creation, idempotency, missing-state reads, CLI status, JSON shape, and watch payload privacy.
- Updated README, repo overview, and implementation guardrails.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `plan.md`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed a second time and preserved the same node id.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- agents --json` passed with isolated `CONU_HOME`.

Known gaps:

- Phase 3 node id is a local identifier only, not a cryptographic identity or authentication credential.
- No private keys, signed identities, encrypted mailbox, or key storage exists yet; those remain Phase 11 hardening work.
- No real daemon lifecycle exists yet; that remains Phase 4.
- No local agent registration exists yet; that remains Phase 5.
- Trust store and agent registry are skeleton files only until pairing/registration phases.

Next:

- Start Phase 4: conUD daemon skeleton with runtime state, health/status detection, graceful shutdown, and payload-safe logs.

## Phase 4 - conUD Daemon Skeleton

Status: completed

Goal:

Create the local runtime daemon that will own routing, sessions, identity, and agent connections.

Deliverables:

- daemon process
- runtime state machine
- graceful shutdown
- local health endpoint or IPC ping
- daemon logs without payloads

Exit criteria:

- [x] `conu start` launches runtime.
- [x] `conu status` detects runtime.
- [x] Runtime can restart cleanly.

Completed work:

- Created GitHub issue #7 for Phase 4.
- Created and pushed branch `codex/phase-4-conud-daemon`.
- Added std-only `conu_core::runtime` lifecycle module.
- Added runtime heartbeat/status metadata under `runtime/status.toml`.
- Added local process lock handling with stale heartbeat replacement.
- Added graceful shutdown request handling through `runtime/stop.request`.
- Added payload-safe runtime log lines under `logs/conud.log`.
- Updated `conud` with `--serve`, `--once`, `--status`, and enhanced `--check`.
- Wired `conu start` to launch `conud --serve`.
- Added `conu stop` for graceful shutdown.
- Updated `conu status`, `conu status --json`, and dashboard output to detect local runtime state.
- Added tests for runtime acquire, already-running guard, stop request, stopped cleanup, stale replacement, CLI runtime status, start already-running path, and stop request path.
- Updated README, repo overview, and implementation guardrails.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conud -p conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- start` launched `conud --serve` with isolated `CONU_HOME` and `CONUD_EXE`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status` detected the running daemon.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` reported running runtime metadata.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- stop` requested graceful shutdown and observed stopped state.
- `cargo +stable-x86_64-pc-windows-gnu run -p conud -- --once` passed.
- Smoke log review confirmed only metadata lines with `payload=not_observed`.

Known gaps:

- Phase 4 health is file-backed heartbeat metadata, not real IPC.
- `conu start` needs an installed/sibling `conud` binary or `CONUD_EXE` in development.
- There is no local agent registration yet; that remains Phase 5.
- There is no message routing, transport encryption session, relay, or remote discovery yet.
- Runtime logs are std-only text metadata and do not yet have rotation or structured logging.

Next:

- Start Phase 5: local IPC transport and agent registration with payload-safe agent registry updates.

## Phase 5 - Local IPC And Agent Registration

Status: completed

Goal:

Let local agents register with conUD through a local gateway.

Deliverables:

- [x] local IPC transport
- [x] register agent request
- [x] agent card model
- [x] presence heartbeat
- [x] `conu agents` local list

Exit criteria:

- [x] A sample local agent can register.
- [x] CLI lists local registered agents.
- [x] Agent identity persists.

Completed work:

- Created GitHub issue #9 for Phase 5.
- Created and pushed branch `codex/phase-5-local-ipc-agents`.
- Added std-only `conu_core::agents` local gateway and registry module.
- Added file-backed IPC directories under `runtime/ipc/inbox`, `runtime/ipc/processed`, and `runtime/ipc/rejected`.
- Added metadata-only registration request submission and processing.
- Added presence heartbeat submission and processing for registered local agents.
- Persisted local agent records in `agents/registry.toml` with id, display name, node id, kind, presence, last seen time, and capability booleans.
- Integrated conUD serve loop and `conud --process-ipc` with gateway request processing.
- Updated `conu agents`, `conu agents --json`, `conu agents register`, and `conu agents heartbeat`.
- Updated `conu status` and dashboard output with local IPC and local agent count.
- Added payload-safe `logs/agents.log` metadata lines with `payload=not_observed`.
- Hardened rejected IPC request errors so arbitrary request contents are not echoed into rejection reasons.
- Updated README, repo overview, builder guardrails, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conud -p conu-cli` passed.
- Direct binary smoke passed with isolated `CONU_HOME`: `conu init`, `conu start`, `conu agents register agent.codex "Codex Desktop" --kind coding-agent`, `conu agents heartbeat agent.codex --presence busy`, `conu status --json`, and `conu stop`.
- Smoke follow-up confirmed `conu agents --json` showed `presence: busy`.
- Smoke log review confirmed `logs/agents.log` contains only metadata lines with `payload=not_observed`.
- `conud --process-ipc` passed after daemon stop with no pending requests.
- Explicit process check confirmed no `conud` process remained running after smoke.

Known gaps:

- Phase 5 IPC is file-backed for reliability and visibility; it is not yet named pipes, Unix sockets, or binary framed IPC.
- The gateway only supports registration and presence. Message send/receive starts in Phase 6.
- Agent capabilities are basic booleans only; policy grants and signed agent cards arrive in later trust/security phases.
- There is no remote discovery or relay integration yet.

Next:

- Start Phase 6: local opaque envelope messaging with sender/receiver validation, local inbox, and delivery metadata that never displays payload contents.

## Phase 6 - Opaque Envelope Messaging

Status: completed

Goal:

Implement local opaque message envelopes and local send/receive routing.

Deliverables:

- [x] envelope type
- [x] message id
- [x] sender/receiver validation
- [x] local inbox
- [x] delivery receipt skeleton

Exit criteria:

- [x] One local agent can send an opaque payload to another local agent.
- [x] CLI can show delivery metadata without showing payload.

Completed work:

- Created GitHub issue #11 for Phase 6.
- Created and pushed branch `codex/phase-6-opaque-messaging`.
- Added std-only `conu_core::messages` local message routing module.
- Added file-backed message request queue under `runtime/ipc/messages/`.
- Added recipient inbox storage under `messages/inbox/<agent-id>/`.
- Added metadata-only delivery receipts under `messages/receipts/`.
- Added sender and recipient validation against the local registered agent registry.
- Added `conu messages send <from-agent> <to-agent> --stdin`.
- Added `conu messages inbox <agent-id>` and JSON output.
- Added `conu messages receipts` and JSON output.
- Wired conUD serve loop, `conud --once`, and `conud --process-ipc` to process local message requests.
- Added payload-safe `logs/messages.log` metadata lines with `payload=not_observed`.
- Ensured processed and rejected message request markers do not keep or display payload contents.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conud -p conu-cli` passed.
- Live isolated `CONU_HOME` smoke passed: `conu init`, `conu start`, two `conu agents register` calls, `conu messages send agent.sender agent.receiver --stdin`, `conu messages inbox agent.receiver --json`, `conu messages receipts --json`, `conu stop`, and `conud --process-ipc`.
- Smoke confirmed delivery status `delivered`, recipient inbox metadata, `delivered_local` receipt metadata, and `logs/messages.log` with `payload=not_observed`.
- Explicit process check confirmed no `conud` process remained running after smoke.

Known gaps:

- Phase 6 is local-only; there is no remote relay, remote discovery, pairing, streams, rooms, or pub/sub yet.
- Message payload bytes are stored as opaque local recipient-inbox envelope data, not displayed or logged. Encryption hardening and encrypted mailbox storage remain Phase 11 work.
- The CLI can submit from stdin and list metadata, but SDK/MCP receive APIs arrive in Phase 12.
- File-backed message IPC is intentionally simple; named pipes, Unix sockets, and binary framed IPC remain future production upgrades.

Next:

- Start Phase 7: pairing and trust records between runtimes, including code lifecycle, trust entry persistence, and revocation/listing groundwork.

## Phase 7 - Pairing And Trust

Status: completed

Goal:

Create the trust-forming flow between runtimes.

Deliverables:

- [x] `conu pair`
- [x] `conu join <code>`
- [x] pairing code lifecycle
- [x] trust entry
- [x] peer revocation command if needed

Exit criteria:

- [x] Pairing creates trusted peer records.
- [x] Trust can be listed and revoked.

Completed work:

- Created GitHub issue #13 for Phase 7.
- Created and pushed branch `codex/phase-7-pairing-trust`.
- Added std-only `conu_core::trust` local pairing and trust store module.
- Added local pairing invitation persistence under `pairing/invites/` and consumed invitations under `pairing/used/`.
- Added `conu pair` to create a six-digit local pairing invitation with expiration.
- Added `conu join <code>` to consume a local invitation and write a trusted peer record.
- Added `conu peers` and `conu peers --json` for trust listing.
- Added `conu peers revoke <peer-node-id>` for revocation.
- Updated status/dashboard output to count trusted peers.
- Stored `pairing_code_hash` in `trust.toml` instead of raw used pairing codes.
- Derived peer ids and display names from a hash suffix instead of the raw pairing code.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/trust.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-cli` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, `conu pair`, `conu join <code>`, `conu peers --json`, and `conu peers revoke <peer-node-id> --json`.
- Smoke confirmed peer output does not expose the raw used pairing code and `trust.toml` stores `pairing_code_hash`.

Known gaps:

- Phase 7 pairing is local-only trust groundwork; cross-machine rendezvous requires the Phase 8 relay service plus Phase 9 session/discovery wiring.
- Pairing invitations are file-backed and not cryptographically signed yet.
- Trust records are persistent metadata, but full permission grants, key exchange, and signed peer verification arrive in later security phases.
- Remote agent discovery over trusted peers starts in Phase 9.

Next:

- Start Phase 8: WebSocket relay MVP for hosted rendezvous and opaque forwarding groundwork.

## Phase 8 - WebSocket Relay MVP

Status: completed

Goal:

Make conU work across the internet through a relay-first transport.

Deliverables:

- [x] relay service crate
- [x] runtime relay frame contract
- [x] relay session auth
- [x] peer rendezvous groundwork
- [x] opaque metadata forwarding path

Exit criteria:

- [x] Two runtime sessions can connect through relay in tests.
- [x] Relay forwards only opaque envelope metadata.
- [x] Relay output and tests do not expose payloads.

Completed work:

- Created GitHub issue #15 for Phase 8.
- Created and pushed branch `codex/phase-8-websocket-relay`.
- Added shared `conu_core::relay` frame types for `HELLO`, `FORWARD`, `PING`, `WELCOME`, `ENVELOPE`, `SENT`, `UNDELIVERED`, `PONG`, and `ERROR`.
- Added metadata-only relay rendering/parsing that rejects plaintext payload fields.
- Added a std-only WebSocket relay service in `crates/conu-relay`.
- Added relay session token authentication through `HELLO`.
- Added connected-peer forwarding from one runtime session to another using node id, envelope id, and byte count only.
- Added `conu-relay --serve [addr]`, `--check`, `--help`, and `CONU_RELAY_TOKEN`.
- Fixed Windows accepted-socket behavior by returning nonblocking listener streams to blocking mode before frame reads.
- Updated CLI/status wording to show the relay service is available while remote sessions/discovery remain future work.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract for the relay MVP.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed.
- Privacy scan reviewed relay payload/token terms; matches were limited to negative tests, placeholder frame documentation, and existing opaque local storage internals.

Known gaps:

- Phase 8 relay is plain local WebSocket for MVP validation, not TLS-hosted WSS.
- conUD does not yet own a relay client, remote session manager, reconnect loop, or route selection.
- Relay authentication is a shared token suitable for local/dev deployment only; signed node identity and key exchange remain security-hardening work.
- Relay forwards metadata only and does not store offline mailbox messages.
- Remote agent discovery over trusted peers begins in Phase 9.

Next:

- Start Phase 9: remote discovery and sessions through trusted peers, with conUD-owned relay client integration and metadata-only presence sync.

## Phase 9 - Remote Discovery And Sessions

Status: completed

Goal:

Let paired runtimes discover allowed remote agents and maintain sessions.

Deliverables:

- [x] remote agent cards
- [x] presence sync mirror
- [x] session manager
- [x] reconnect metadata loop
- [x] route metadata

Exit criteria:

- [x] `conu agents` shows trusted remote agents after conUD/session sync.
- [x] Presence and visibility metadata propagates from trusted peer session state.
- [x] Sessions retain route/reconnect metadata for later live networking.

Completed work:

- Created GitHub issue #17 for Phase 9.
- Created and pushed branch `codex/phase-9-remote-sessions`.
- Added `conu_core::sessions` for remote runtime session metadata, trusted remote agent mirrors, and payload-safe session logs.
- Added `sessions/registry.toml` and `agents/remote.toml` state paths.
- Added conUD-owned session sync in the runtime serve loop, `conud --once`, and `conud --process-ipc`.
- Added `conu sessions`, `conu sessions --json`, `conu sessions sync`, and `conu sessions sync --json`.
- Updated `conu agents`, `conu agents --json`, `conu connect`, `conu status`, and dashboard output to include remote session/agent visibility.
- Ensured revoked peers are not visible as active remote agents after session sync.
- Added tests for session sync, remote agent visibility, revoked peer removal, and payload-safe session logs.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all` passed.
- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `git diff --check` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, `conu pair`, `conu join <code>`, `conu sessions sync`, `conu agents --json`, `conu sessions --json`, and `conud --process-ipc`.
- Privacy scan reviewed payload/token terms; matches were limited to negative tests, placeholder frame documentation, original product examples, and existing opaque local storage internals.

Known gaps:

- Phase 9 remote agent cards are derived from trusted peer metadata; full relay-backed card exchange remains later work.
- Session state is metadata-only and file-backed; no live stream, relay client connection, backoff timer, or network retry loop is active yet.
- Reconnect attempts are recorded as metadata groundwork but not driven by real transport failure events.
- Signed remote agent cards, permission grants, and encrypted session key exchange remain security-hardening work.
- Streams and CLI watch animation begin in Phase 10.

Next:

- Start Phase 10: stream ids, stream lifecycle metadata, backpressure counters, and payload-safe watch animation.

## Phase 10 - Streams And Watch Animation

Status: completed

Goal:

Add stream support and the private CLI animation showing agent traffic flow.

Deliverables:

- [x] stream ids
- [x] stream open/write/close
- [x] backpressure windows
- [x] watch event bus
- [x] CLI animation

Exit criteria:

- [x] Agents can open streams.
- [x] `conu watch` shows traffic metadata only.
- [x] No payload text appears in watch output.

Completed work:

- Created GitHub issue #19 for Phase 10.
- Created and pushed branch `codex/phase-10-streams-watch`.
- Added `conu_core::streams` for stream lifecycle metadata, opaque chunk byte counts, backpressure validation, watch events, and payload-safe stream logs.
- Added `streams/registry.toml`, `streams/events.toml`, and `logs/streams.log` state surfaces.
- Added `conu streams`, `conu streams --json`, `conu streams open`, `conu streams write --stdin`, and `conu streams close`.
- Updated the CLI binary so `streams write --stdin` reads stdin like message send.
- Updated `conu watch` to render private stream flow, route, stream id, event type, open stream count, packet count, and byte count without payload contents.
- Updated `conu status`, `conu connect`, help text, README, repo overview, builder guardrails, repo map, CLI experience reference, and agent gateway contract.
- Added tests for stream lifecycle, backpressure rejection, target visibility, binary stdin routing, CLI stream flow, and watch privacy.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/cli-experience.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/streams.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `git diff --check` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, two `conu agents register` calls, two `conud --process-ipc` calls, `conu streams open`, `conu streams write <stream-id> --stdin`, `conu watch`, `conu streams close`, and `conu streams --json`.
- Privacy scan reviewed payload/token terms; matches were limited to negative tests, placeholder frame documentation, original product examples, and existing opaque local storage internals.

Known gaps:

- Phase 10 streams record metadata and byte counts only; they do not yet move encrypted chunk bytes over a live relay transport.
- Stream chunks are accepted from stdin and counted, but conU-owned stream storage intentionally does not persist chunk contents.
- Watch animation is static CLI rendering over the event bus, not a continuously refreshing TUI yet.
- End-to-end stream encryption, signed stream peers, and replay protection begin in Phase 11.

Next:

- Start Phase 11: encryption hardening, signed cards, replay protection, encrypted storage, and key rotation planning.

## Phase 11 - Encryption Hardening

Status: completed

Goal:

Make payload and session security production-grade.

Deliverables:

- peer key exchange
- signed agent cards
- replay protection
- encrypted payload storage
- key rotation plan

Exit criteria:

- [x] Payloads are encrypted before conU-owned local storage and peer encryption helpers exist for relay transit.
- [x] Trust verification is explicit through signed local agent cards and X25519 public exchange material.
- [x] Revoked peers remain excluded by the Phase 9 session mirror and replayed local message ids are rejected.

Completed work:

- Created GitHub issue #22 for Phase 11.
- Created branch `codex/phase-11-encryption-hardening`.
- Added `conu_core::security` for Ed25519 signing, X25519 key agreement, XChaCha20Poly1305 encrypted storage, replay cache, security audit, and local key rotation plan generation.
- Added local security state under `security/`.
- Updated `conu init` to create local security keys and `conu security audit` to report payload-safe readiness.
- Encrypted new local message request and recipient inbox payload storage with authenticated metadata.
- Added replay protection for local message request ids and envelope ids.
- Added Ed25519 signatures to new/updated local agent registry records.
- Added peer encryption/key-agreement helpers for the later live relay-backed data path.
- Added docs for security hardening and production readiness.
- Updated future-agent guardrails, repo overview, gateway contract, security checklist, and repo map.

Files changed:

- `Cargo.lock`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `.agents/about/how_it_will_work.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/security.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `git diff --check` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, `conu security audit --json`, two signed `conu agents register` flows, `conud --process-ipc`, `conu messages send --stdin`, `conu messages inbox --json`, encrypted field scan, signature field scan, and plaintext payload scan.
- Privacy scan confirmed `Review this code` remains only in artificial negative tests and the smoke payload was not present in conU-owned state.
- Initial default `cargo check --workspace --all-targets` failed because the local MSVC linker is not installed and new crypto dependencies compile build scripts. This matches the existing Windows toolchain gap; use the GNU toolchain until MSVC Build Tools or CI are configured.

Known gaps:

- Local private key files are protected by filesystem permissions/profile ACL only; production release still needs OS keychain, DPAPI, Secure Enclave, HSM, or user-managed secret backend support.
- Automated key rotation, multi-key reads, and storage re-encryption migration are documented but not implemented.
- Remote session mirrors do not yet exchange signed remote agent cards over a live transport.
- Relay-backed encrypted remote data-plane delivery is not active yet; Phase 11 provides the key agreement and encryption helpers for that next transport phase.
- Capability grants and full permission policy remain future work.

Next:

- Start Phase 12: SDK and MCP adapter so agents can call register, peers, send, receive, stream, and security-safe receive APIs without learning conU internals.

## Phase 12 - SDK And MCP Adapter

Status: completed

Goal:

Give agents a simple way to use conU.

Deliverables:

- Rust SDK
- Python SDK
- TypeScript SDK, completed by the post-Phase-15 wrapper pass below
- MCP adapter exposing conU communication tools
- examples for local agents

Exit criteria:

- [x] Agent can call register, peers, send, receive, stream.
- [x] MCP-capable agents can use conU as tools.

Completed work:

- Created GitHub issue #26 for Phase 12.
- Created branch `codex/phase-12-sdk-mcp-adapter`.
- Added `crates/conu-sdk`, a Rust SDK wrapping existing `conu-core` gateway, message, trust, session, stream, runtime, state, and security surfaces.
- Added explicit addressed-agent receive API through `ConuClient::receive_message_bytes`.
- Added `crates/conu-mcp`, a newline-delimited JSON-RPC MCP stdio adapter exposing conU as tools.
- Added MCP tools for status, security audit, register, presence, process queued, list agents, list peers, send message, receive message, open stream, write stream, and close stream.
- Added payload-safe MCP behavior: list/send/status/stream results are metadata-only, while `conu_receive_message` returns `payloadHex` only when `includePayload` is true.
- Added optional `CONU_AGENT_ID` binding so one `conu-mcp` stdio server can be scoped to one local agent.
- Added stdlib Python wrapper SDK under `sdk/python/conu_sdk`.
- Added Rust and Python local-agent examples.
- Updated README, user install guide, production/security docs, repo memory, agent gateway contract, implementation guardrails, repo map, and security checklist.
- Checked current MCP transport docs and aligned the adapter with stdio JSON-RPC messages delimited by newlines.

Files changed:

- `Cargo.toml`
- `Cargo.lock`
- `README.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `docs/production-readiness.md`
- `docs/security-hardening.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/SKILL.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-core/src/lib.rs`
- `crates/conu-sdk/Cargo.toml`
- `crates/conu-sdk/src/lib.rs`
- `crates/conu-sdk/examples/local_agents.rs`
- `crates/conu-mcp/Cargo.toml`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-mcp/src/main.rs`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `examples/python/local_agent_pair.py`

Validation:

- `cargo fmt` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-sdk --example local_agents` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-mcp` stdio `tools/list` smoke passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- Python SDK smoke passed with local `target/debug/conu.exe` and `target/debug/conud.exe`.
- Default `cargo check --workspace` still fails locally because the active MSVC toolchain cannot find `link.exe`; GNU toolchain validation passed.

Known gaps:

- Superseded by the post-Phase-15 TypeScript SDK wrapper pass below; TypeScript/JavaScript agents now have a dependency-free Node wrapper around installed `conu`/`conud` binaries.
- MCP adapter is stdio-only; no HTTP MCP transport is implemented.
- SDK/MCP local receive returns payload bytes only for local addressed inboxes; real remote data-plane delivery remains future work.
- Capability grants and richer permission policy are not complete yet.
- Packaging and installer support remain Phase 15.

Next:

- Start Phase 13: direct transport and NAT upgrade, including route selection, relay fallback integration in conUD, and live encrypted data-plane delivery groundwork.

## Phase 13 - Direct Transport And NAT Upgrade

Status: completed

Goal:

Move beyond relay-only networking.

Deliverables:

- [x] direct QUIC candidate route records
- [x] direct route attempt/probe metadata
- [x] relay fallback
- [x] route quality scoring
- [x] NAT profile config and hole-punching research notes
- [ ] live QUIC socket transport

Exit criteria:

- [x] Direct route candidate is recorded when a valid direct endpoint is configured; later production guard keeps relay selected until live direct transport exists.
- [x] Relay fallback keeps route selection reliable when direct is unavailable.

Completed work:

- Added `conu_core::routes`, a conUD-owned route manager that builds direct QUIC candidates and relay WebSocket fallback candidates for trusted peers only.
- Added route scoring by NAT profile, deterministic selected-route lookup, relay fallback flags, route probe history, and payload-safe route logs.
- Added route state layout under `routes/registry.toml`, `routes/probes.toml`, and `logs/routes.log`.
- Integrated route sync into `conu sessions sync`, conUD runtime processing, stream route labels for remote agents, Rust SDK, Python SDK wrapper, and MCP.
- Added CLI commands: `conu routes`, `conu routes sync`, and `conu routes probes`, with text and JSON output.
- Updated `conu status`, dashboard, and `conu connect` to show selected direct/relay/fallback route metadata.
- Updated docs and future-agent skills to explain Phase 13 route behavior, config, validation, and privacy boundaries.

Files changed:

- `crates/conu-core/src/routes.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conud/src/main.rs`
- `sdk/python/conu_sdk/__init__.py`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `.agents/repo/ABOUT.md`
- `.agents/Pr/SKILL.MD`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`

Validation:

- `cargo fmt` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- Python wrapper route smoke passed with local `target/debug/conu.exe`.
- Isolated CLI smoke passed with `CONU_HOME` under `%TEMP%`: `conu init`, `conu pair`, `conu join`, `conu routes sync --json`, `conu routes --json`, and `conu status --json`.
- `git diff --check` passed.
- Privacy scan reviewed payload-looking strings; new route files, logs, CLI, SDK, MCP, and docs remained metadata-only.

Known gaps:

- Real QUIC packet transport is not implemented yet; Phase 13 records `direct-quic` route candidates, and the later direct route selection guard keeps relay selected until direct transport exists.
- NAT traversal is config/profile based; live ICE-style candidate gathering, STUN/TURN, and hole punching remain future transport work.
- Route probes are metadata/config probes with latency estimates, not real RTT measurements.
- conUD still does not own live relay-backed encrypted message or stream-chunk delivery.
- Direct endpoint config is manual today.

Next:

- Start Phase 14: rooms, pub/sub, and multi-agent session metadata, while keeping live direct QUIC and relay-backed encrypted data-plane delivery as future transport hardening.

## Phase 14 - Rooms, Pub/Sub, And Multi-Agent Sessions

Status: completed

Goal:

Support shared spaces and multiple agents in one session.

Deliverables:

- [x] rooms
- [x] membership-based local subscriptions
- [x] publish/subscribe topics
- [x] room presence through participant metadata
- [x] group stream/room metadata in CLI status, dashboard, connect, and watch

Exit criteria:

- [x] Trusted agents can join a room.
- [x] Events route to subscribed local agents.
- [x] CLI shows room flow without payloads.

Completed work:

- Added `conu_core::rooms` with room registry, participants, topics, payload-safe event bus, metadata logs, and backpressure limits.
- Added local room event fanout: publishing to a room delivers encrypted-at-rest event envelopes to joined local participants' message inboxes while room registry/event/log surfaces keep only metadata.
- Added `conu rooms`, `conu rooms create`, `conu rooms join`, `conu rooms publish --stdin`, and `conu rooms events` with text and JSON output.
- Fixed the real CLI binary stdin path so `conu rooms publish --stdin` reads payload bytes outside unit tests.
- Added `conu connect local` and `conu connect room` flows, plus a richer ASCII dashboard/watch view with rooms, room events, local deliveries, routes, streams, relay queue state, and payload privacy markers.
- Added room APIs to the Rust SDK, Python wrapper SDK, and MCP adapter.
- Updated user docs, release checklist, repo memory, README, and tests for rooms/pub-sub behavior.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `docs/observability.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `sdk/python/conu_sdk/__init__.py`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Release archive inspection passed, including all binaries plus `docs/sdk-and-mcp.md` and `docs/internet-relay-test.md`, and excluding local conU state/log/security/message directories.
- `git diff --check` passed.
- Direct binary room smoke passed with isolated `CONU_HOME`: `conu init`, agent registration, `conud --process-ipc`, `conu rooms create`, `conu rooms join --json`, real stdin `conu rooms publish --stdin --json`, `conu rooms events`, `conu messages inbox --json`, payload-text scan across conU-owned state, and rejected nonlocal publisher spoof without payload echo.

Known gaps:

- Superseded by the post-Phase-15 relay-backed room event fanout pass below: joined trusted remote room participants now receive peer-encrypted relay room-event envelopes.
- Superseded by the post-Phase-15 room topic policy pass below: unconfigured topics keep room membership as the compatibility boundary, while configured room/topic pairs require explicit publish/subscribe grants.
- Relay-backed stream-chunk routing, hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, offline mailbox, and OS-backed key storage remain future hardening work.
- Public managed online release remains blocked until the hosted relay/TLS/auth/session work is complete.

Next recommendation:

- Prioritize hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, and then remote room fanout/stream-chunk routing before advertising conU as a managed public internet service.

## Phase 15 - Packaging And Production Readiness

Status: completed

Goal:

Prepare conU for real users.

Deliverables:

- [x] Windows build
- [x] macOS build path
- [x] Linux build path
- [x] installer strategy
- [x] service installation templates
- [x] config docs
- [x] security review checklist
- [x] observability setup

Exit criteria:

- [x] User can install, start, pair, and connect agents for local-first usage.
- [x] Logs and telemetry guidance are payload-safe.
- [x] Release checklist exists.

Completed work:

- Created GitHub issue #30 for Phase 15 and worked on `codex/phase-15-production-readiness`.
- Added `conu doctor` and `conu doctor --json` for local readiness, companion-binary discovery, security readiness, runtime health, release gates, and payload-safe log scanning.
- Added toolchain-aware release build scripts for Windows PowerShell and macOS/Linux shell workflows.
- Added local smoke script for install/start/message/route/doctor validation, including native exit-code checks and a `localInstallReady=true` doctor gate.
- Added packaging templates for Windows current-user install/uninstall plus optional service creation, Linux systemd, and macOS launchd.
- Added GitHub CI and release artifact workflows.
- Added release checklist and observability docs.
- Updated README, user install guide, production readiness docs, repo memory, guardrails, repo map, and security checklist.
- Kept Phase 14 rooms/pub-sub explicitly not started.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.gitignore`
- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conud/src/main.rs`
- `docs/observability.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/linux/conud.service`
- `packaging/macos/com.conu.conud.plist`
- `packaging/windows/install.ps1`
- `packaging/windows/uninstall.ps1`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `scripts/smoke-local.ps1`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and asserted `conu doctor --json` reported `releaseGates.localInstallReady = true` in an isolated `CONU_HOME`.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed and created `dist/conu-0.1.0-host.zip`.
- `target\release\conu.exe doctor --json` passed and reported shipped companion binaries without displaying payload contents.
- `git diff --check` passed.
- Privacy scan reviewed payload-looking terms; matches are existing negative tests, storage field names, and SDK/MCP input contracts, not Phase 15 runtime output, logs, docs, or release artifacts.

Known gaps:

- Phase 14 rooms/pub-sub remains not started.
- Release artifacts are unsigned and not notarized.
- Windows service script requires an elevated shell for service creation.
- Linux/macOS service templates require user/path edits before installation.
- Public hosted internet readiness remains blocked by live encrypted remote data-plane delivery, real direct QUIC transport, remote signed agent-card exchange, capability policy, and OS-backed key storage.

Next:

- Return to Phase 14 rooms, pub/sub, and multi-agent sessions, or harden signed installers/OS key storage if the product priority stays packaging.

## Post Phase 15 Audit - Production Polish

Status: completed

Goal:

Audit the whole repo after Phase 15, fix small maintainability issues, and raise the validation bar without starting Phase 14 feature work.

Completed work:

- Created GitHub issue #32 for the final audit and production polish pass.
- Updated the CLI crate header so it describes the current control-room surface instead of stale Phase 13 wording.
- Boxed the `RuntimeError::AlreadyRunning` status payload to keep runtime error results small.
- Moved the test-only runtime nanosecond helper before the test module for cleaner module layout.
- Simplified MCP JSON-RPC notification handling with `?` while preserving notification behavior.
- Refactored status rendering through a `StatusView` to avoid long argument lists.
- Tightened a CLI test helper to accept `&Path` instead of `&PathBuf`.
- Added clippy with `-D warnings` to CI, release checklist, production readiness docs, README development commands, and PR guardrails.

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.
- Privacy scan reviewed payload-looking terms; matches are existing negative tests, storage field names, and SDK/MCP input contracts.

Known gaps:

- No Phase 14 rooms/pub-sub implementation was started in this audit.
- Public hosted internet readiness remains blocked by the known Phase 15 release blockers.

## Post Phase 15 Internet Data-Plane And CLI Polish

Status: completed

Goal:

Make conU testable over a reachable WebSocket relay for one-shot peer-encrypted agent messages, while improving the CLI control-room flow and keeping all payload surfaces private.

Completed work:

- Created GitHub issue #34 and branch `codex/internet-data-plane-cli-polish`.
- Extended the shared relay frame contract to carry peer-encrypted opaque bodies while still rejecting plaintext payload fields.
- Added a std-only relay WebSocket client in `conu_core::relay`.
- Added manual public peer-card export/import with `conu identity export` and `conu peers trust`.
- Added relay-backed remote message queueing with `conu messages send --peer <peer-node-id> --stdin`.
- Added `conu relay sync --wait-ms <ms>` for explicit outbound flush and inbound receive over the relay.
- Delivered inbound relay envelopes to the addressed local agent inbox after verifying the sender exchange public key against local trust.
- Added relay queue counters and a richer ASCII `conu watch` transport view.
- Exposed peer-card, remote send, and relay sync helpers through the Rust SDK, Python wrapper, and MCP adapter.
- Added `docs/internet-relay-test.md` and updated user, SDK/MCP, production, security, release, README, and future-agent docs.

Files changed:

- `Cargo.toml` lock/dependency metadata as needed by existing workspace updates.
- `README.md`
- `docs/internet-relay-test.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `docs/security-hardening.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/trust.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `crates/conu-sdk/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `sdk/python/conu_sdk/__init__.py`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed, including a two-home relay E2E test that sends and receives a peer-encrypted message through `conu-relay`.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed and created `dist/conu-0.1.0-host.zip`.
- `git diff --check` passed.
- Targeted CLI remote queue test passed and confirmed the relay outbox stores encrypted fields without literal payload text.
- Privacy scan reviewed payload-looking strings; matches are artificial negative tests, docs examples, or encrypted field names, not runtime log/CLI payload leakage.

Known gaps:

- Superseded by the `wss://` relay-client pass below: relay clients now accept `ws://` and certificate-valid `wss://`; public `wss://` still requires TLS termination in front of `conu-relay`.
- Superseded by the daemon relay production hardening pass below: conUD now owns bounded relay sync windows when configured.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- For user testing, run `docs/internet-relay-test.md` locally or over a reachable `ws://` relay.
- For product hardening, add a conUD-owned relay pump with reconnect/backoff, then stream-chunk routing and hosted relay auth/TLS strategy.

## Post Phase 15 Daemon Relay Production Hardening

Status: completed

Goal:

Move the relay message path beyond manual MVP sync by letting conUD own bounded relay send/receive windows while preserving payload opacity and adding daemon-level end-to-end smoke coverage.

Completed work:

- Created GitHub issue #36 and branch `codex/relay-daemon-production-hardening`.
- Added `relay_auto_sync = true` to new local config files.
- Added conUD runtime processing reports and a daemon relay pump that runs when a relay endpoint or trusted relay peer is configured.
- Added relay pump retry/backoff behavior so relay connection failures do not crash conUD or block local IPC forever.
- Kept relay pump logs metadata-only with `payload=not_observed` in runtime logs and encrypted-body-only relay delivery logs.
- Added `scripts/smoke-relay-daemon.ps1`, which starts a local relay, two isolated conUD runtimes, registers two agents, sends a peer-encrypted remote message without manual `conu relay sync`, waits for delivery, and scans conU-owned state for payload leaks.
- Hardened Windows daemon launching by routing `conu start` through a no-window background start path.
- Updated README, user guide, internet relay test, production readiness, SDK/MCP docs, release checklist, observability docs, repo memory, guardrails, repo map, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `docs/internet-relay-test.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/observability.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`
- `scripts/smoke-relay-daemon.ps1`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery without manual sync.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed and created `dist/conu-0.1.0-host.zip`.
- `git diff --check` passed.

Known gaps:

- Superseded by the reusable daemon relay-session pass below: conUD now keeps a relay WebSocket session alive across serve ticks when the endpoint is stable.
- Superseded by the `wss://` relay-client pass below: public `wss://` now has client support, while the plain relay server still needs hosted TLS termination in front of it.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- Run full validation, merge the daemon relay hardening branch, then choose between Phase 14 rooms/pub-sub or deeper hosted relay auth/TLS/session-policy work.

## Post Phase 15 Distribution And Hosting

Status: completed

Goal:

Make the user install and relay hosting story concrete without overstating the current public-network readiness.

Completed work:

- Created GitHub issue #38 and branch `codex/distribution-hosting-npm`.
- Added `docs/distribution-and-hosting.md` explaining how users install conU, how agents use it, how to self-host the current relay, and why Rust native binaries plus an npm launcher is the best first public distribution path.
- Added npm package template `packaging/npm/conu-cli` with launcher shims for `conu`, `conud`, `conu-relay`, and `conu-mcp`.
- Added npm postinstall downloader that selects the platform release asset, requires SHA-256 verification by default, supports local binary-dir testing, and keeps protocol behavior in Rust.
- Added Docker relay hosting template under `packaging/docker`.
- Updated release scripts to create platform-suffixed artifacts and matching `.sha256` files.
- Updated GitHub release workflow to build/upload `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` artifacts.
- Updated README, user guide, packaging docs, production readiness, release checklist, internet relay test, repo memory, repo map, implementation guardrails, and security checklist.
- Kept public-hosting guidance honest: the current client supported `ws://` at this point; managed public relay still required `wss://`, hosted auth/TLS policy, hosted quotas/monitoring, hosted session policy/resume, stream-chunk routing, offline mailbox, capability policy, signed remote cards, and OS-backed key storage.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/.npmignore`
- `packaging/npm/conu-cli/README.md`
- `packaging/npm/conu-cli/bin/conu.js`
- `packaging/npm/conu-cli/bin/conud.js`
- `packaging/npm/conu-cli/bin/conu-relay.js`
- `packaging/npm/conu-cli/bin/conu-mcp.js`
- `packaging/npm/conu-cli/lib/platform.js`
- `packaging/npm/conu-cli/lib/run.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/install.js`
- `.github/workflows/release.yml`
- `.gitignore`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js`, `node --check packaging\npm\conu-cli\lib\platform.js`, and `node --check packaging\npm\conu-cli\lib\run.js` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `npm pack --dry-run` passed and confirmed the npm tarball includes only launcher/package files, not vendored binaries.
- npm installer local binary-dir smoke passed and launched `conu 0.1.0`.
- npm installer HTTP smoke passed against `dist/conu-0.1.0-windows-x64.zip`, verified the `.sha256`, extracted the archive, and launched `conu 0.1.0`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `dist/conu-0.1.0-windows-x64.zip.sha256`.
- Release archive listing confirmed `docs/distribution-and-hosting.md`, `packaging/docker/relay.Dockerfile`, and `packaging/npm/conu-cli/package.json` are included without conU state/log/security-key paths.
- `git diff --check` passed.
- Privacy scan reviewed payload/secret terms in docs, packaging, and agent memory; new matches are warnings, placeholder env examples, or metadata-only policy text.

Known gaps:

- `@conu/cli` is a package template and has not been published yet.
- GitHub Release assets must be attached before users can run `npm install -g @conu/cli` successfully.
- Release artifacts are checksummed but not signed/notarized.
- The relay host path remains controlled self-hosting over reachable `ws://`, not a managed public relay network.
- Hosted relay auth/rate limits, hosted session policy/resume, stream-chunk routing, offline mailbox, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- Publish the first GitHub Release with platform artifacts/checksums, then publish `@conu/cli`; after that, prioritize hosted relay auth/session policy before advertising a public managed relay.

## Post Phase 15 Relay Abuse Controls

Status: completed

Goal:

Reduce the self-hosted relay's production risk by adding basic in-process abuse controls while preserving relay blindness and payload-safe outputs.

Completed work:

- Added `RelayLimits` to `crates/conu-relay` with configurable total connection, per-IP connection, and per-session frame-rate caps.
- Enforced connection caps before WebSocket handshake processing so unauthenticated TCP sessions cannot grow without bound inside one relay process.
- Enforced per-session frame-rate checks before parsing frame contents, returning a generic `rate_limited` error without echoing arbitrary frame text.
- Changed relay client tracking to store session ids and avoid stale same-node disconnect cleanup removing a newer session mapping.
- Added relay CLI environment knobs: `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, and `CONU_RELAY_MAX_FRAMES_PER_MINUTE`.
- Added a regression test confirming rate-limit errors stay metadata-only and do not echo payload-looking frame contents.
- Updated README, user install, hosting, Docker, production-readiness, release-checklist, repo memory, guardrails, gateway contract, and security checklist docs.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.

Known gaps:

- Relay abuse controls are local in-process caps, not hosted account quotas, distributed rate limits, abuse analytics, or adaptive banning.
- Relay authentication remains shared-token local/dev auth; public managed hosting still needs stronger auth, token rotation, TLS strategy, and operational policy.
- Superseded by the `wss://` relay-client pass below: the built-in client now supports certificate-valid `wss://`, while public deployments still need TLS termination in front of the plain relay server.
- Hosted session resume/policy, stream-chunk routing, offline mailbox delivery, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.

Next recommendation:

- Prioritize hosted relay auth/TLS and hosted session resume/policy before advertising conU as a public managed relay network.

## Post Phase 15 Reusable Daemon Relay Sessions

Status: completed

Goal:

Move conUD's relay path from repeated short WebSocket windows to a reusable daemon-owned relay session while preserving the manual one-shot sync command and relay payload opacity.

Completed work:

- Added `RelayRuntimePump` in `conu_core::relay_delivery` to hold a relay WebSocket client, endpoint, and session id across daemon ticks.
- Wired `RuntimeLease::serve_until_stop` to use the reusable relay pump while keeping `conu relay sync` and `conud --once` on the existing one-shot path.
- Reconnects now happen when the relay endpoint changes or the relay session fails; disabling relay auto-sync disconnects the reusable pump.
- Kept relay logs and runtime logs metadata-only and did not add relay session ids, tokens, or payload contents to log surfaces.
- Added a relay E2E regression test that opens a daemon-style relay pump, sends two peer-encrypted messages across ticks, and verifies the receiver kept the same relay session id.
- Updated README, user guide, SDK/MCP docs, production readiness, packaging notes, release checklist, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-relay/src/lib.rs`
- `plan.md`

Validation:

- Targeted relay/runtime tests passed during implementation: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` and `cargo +stable-x86_64-pc-windows-gnu test -p conu-core runtime::tests::process_once_keeps_relay_idle_without_relay_config`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.

Known gaps:

- The reusable daemon relay session is local runtime behavior; it is not hosted account/session resume, distributed session migration, or managed relay policy.
- Superseded by the `wss://` relay-client pass below: the built-in client now supports certificate-valid `wss://`, while public deployments still need TLS termination in front of the plain relay server.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.

Next recommendation:

- Prioritize hosted relay auth/session policy before advertising conU as a public managed relay network.

## Post Phase 15 Public Relay Token Guard

Status: completed

Goal:

Prevent accidental public exposure of the relay with the default local development token while keeping loopback development and local smoke tests simple.

Completed work:

- Added relay bind-address classification in `crates/conu-relay` to distinguish loopback binds from exposed binds.
- Kept `local-dev-token` valid for loopback binds such as `127.0.0.1`.
- Rejected non-loopback relay binds such as `0.0.0.0:8787` when the token is `local-dev-token`.
- Rejected non-loopback relay binds when the custom token is shorter than 24 characters.
- Kept relay auth errors generic and avoided echoing rejected token values.
- Updated `conu-relay --help`, internet relay test docs, user guide, Docker/package docs, production readiness, release checklist, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `plan.md`

Validation:

- Targeted relay validation passed during implementation: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- Stale unsafe-token scans passed: no public-bind docs/package examples still use `CONU_RELAY_TOKEN=replace-me` or `CONU_RELAY_TOKEN=replace-with-a-shared-test-token`; remaining `local-dev-token` references are loopback guidance.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.

Known gaps:

- This is a local configuration guard, not hosted account auth, token rotation, scoped credentials, mTLS, or signed relay sessions.
- Superseded by the `wss://` relay-client pass below: the built-in client now supports certificate-valid `wss://`, while public deployments still need TLS termination in front of the plain relay server.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.

Next recommendation:

- Prioritize stronger hosted relay auth/session policy before advertising conU as a public managed relay network.

## Post Phase 15 WSS Relay Client Support

Status: completed

Goal:

Allow conUD and manual relay sync to connect to certificate-valid `wss://` relay endpoints while preserving local `ws://` development, relay payload opacity, and the existing plain `conu-relay` server deployment model.

Completed work:

- Added TLS-capable relay client streams in `conu_core::relay` while keeping the relay frame parser and WebSocket framing metadata-only.
- Extended relay endpoint parsing to accept `ws://` and `wss://`, with default ports `80` and `443` respectively.
- Added certificate-validated `wss://` connection support through platform TLS via `native-tls`.
- Pinned `native-tls` and Windows `schannel` versions so the repository's current `stable-x86_64-pc-windows-gnu` validation does not require missing `dlltool.exe` or `gcc.exe`.
- Updated relay delivery config validation and manual peer-card trust validation to accept `wss://` endpoints.
- Updated CLI peer-trust usage text to advertise `ws://host:port|wss://host/path`.
- Updated README, internet relay test, distribution/hosting, user guide, production readiness, release checklist, packaging docs, repo memory, guardrails, gateway contract, and security checklist.
- Kept the server-side `conu-relay` scope honest: it still listens as plain WebSocket; public `wss://` requires TLS termination in front of it.

Files changed:

- `Cargo.lock`
- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/trust.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted WSS tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay::tests::endpoint_parser`.
- Targeted relay config validation passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::relay_endpoint_validation_accepts_wss`.
- Targeted trust validation passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core trust::tests::manual_peer_card_accepts_wss_relay_endpoint`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Stale docs scan found no remaining live ws-only relay-client claims or live statements that TLS relay clients are still future work.
- `git diff --check` passed.

Known gaps:

- `wss://` support is client-side only. The bundled relay server still needs a reverse proxy or load balancer for TLS termination.
- Superseded by the scoped relay credential/session-policy pass below: static per-node relay credentials and idle/TTL policy now exist, while managed account auth, credential rotation/revocation, distributed quotas, hosted monitoring, and hosted session resume/accounting remain future work.
- Superseded by the relay stream-chunk pass below: relay-backed stream chunks now move as peer-encrypted envelopes, while remote room fanout, offline mailbox delivery, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- The Windows TLS dependency is pinned to preserve the current GNU validation path; revisit the pin when the project moves to a toolchain/CI path that can consume newer Windows TLS bindings without local binutils gaps.

Next recommendation:

- Continue with managed hosted relay account auth, credential rotation/revocation, session resume/accounting, stream-chunk routing, offline mailbox, and OS-backed key storage before advertising conU as a managed public relay network.

## Post Phase 15 Scoped Relay Credentials And Session Policy

Status: completed

Goal:

Move the current self-hosted relay beyond a single shared server token by adding static per-node credentials, configurable authenticated-session policy, token-safe comparisons, and payload-safe documentation while keeping the local shared-token path compatible.

Completed work:

- Added `RelayAuth`, `RelayCredential`, and redacted Debug output in `crates/conu-relay`.
- Kept `RelayConfig::new(bind, token)` for shared-token compatibility and added `RelayConfig::with_scoped_credentials`.
- Added token-safe authorization comparisons for shared and scoped relay credentials.
- Added `RelaySessionPolicy` with configurable idle timeout and max session TTL.
- Wired `conu-relay --serve` to read `CONU_RELAY_CREDENTIALS`, `CONU_RELAY_IDLE_TIMEOUT_SECONDS`, and `CONU_RELAY_SESSION_TTL_SECONDS`.
- Kept `CONU_RELAY_TOKEN` as the shared-token server mode and as the runtime client token env var.
- Preserved the loopback-only `local-dev-token` guard and applied the public-bind minimum token length to scoped credentials.
- Added regression tests for scoped credential authorization, public scoped dev-token rejection, redacted config/credential Debug output, and session TTL expiry without payload echo.
- Updated README, hosting docs, internet relay test docs, production readiness, release checklist, SDK/MCP docs, packaging docs, repo memory, implementation guardrails, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted scoped auth test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay scoped_credentials_accept_only_matching_node_token`.
- Targeted relay session TTL test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_session_ttl_expires_without_echoing_payloads`.
- Targeted redaction test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_config_debug_redacts_tokens`.
- Full relay crate tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Stale code/docs scans found no `config.auth_token` relay test references and no live docs still saying hosted relay auth/session policy is entirely future work.
- `git diff --check` passed.

Known gaps:

- Static scoped credentials are not managed hosted accounts, dynamic token issuance, token rotation, revocation, mTLS, or signed relay sessions.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.
- Hosted relay session resume/accounting, distributed quotas, hosted mailbox accounting/quotas, hosted monitoring, and adaptive abuse response remain future work.
- Superseded by the relay stream-chunk pass below: relay-backed stream chunks now move as peer-encrypted envelopes, while remote room fanout, offline mailbox delivery, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- `wss://` support remains client-side; the bundled relay server still needs a reverse proxy or load balancer for TLS termination.

Next recommendation:

- Prioritize hosted relay account/credential lifecycle work, hosted session resume/accounting, offline mailbox delivery, and OS-backed key storage before public managed relay claims.

## Post Phase 15 Relay Stream-Chunk Delivery

Status: completed

Goal:

Move stream writes for trusted remote agents from metadata-only local counters to relay-backed peer-encrypted stream-chunk delivery while preserving payload opacity and honest public-hosting limits.

Completed work:

- Added relay envelope kind metadata for `message` and `stream_chunk`, including stream id validation for stream chunks and rejection of stream ids on normal message frames.
- Added relay outbox support for peer-encrypted stream chunks with stream-specific authenticated data and metadata-only `.relay` request files.
- Wired `conu streams write` so remote streams on relay routes queue peer-encrypted chunks to the trusted peer instead of only counting local bytes.
- Delivered inbound stream chunks as addressed inbox envelopes with `kind = "stream_chunk"`, `stream_id`, metadata-only receipts, encrypted-at-rest payload storage, and `delivered_relay_stream` status.
- Updated message inbox, receipt, and log metadata so stream chunks are visible by kind and stream id without displaying bytes.
- Added relay E2E coverage proving a stream chunk moves through a live relay between two isolated conU homes and arrives as an encrypted inbox envelope.
- Reduced relay frame enum size and constructor argument width so the workspace stays clippy-clean under `-D warnings`.
- Updated README, user/install docs, hosting docs, release checklist, SDK/MCP docs, security docs, packaging docs, repo memory, repo map, implementation guardrails, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay frame stream-kind test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay::tests::stream_chunk_frame_carries_stream_metadata_only`.
- Targeted stream inbox metadata test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core messages::tests::remote_stream_chunk_delivers_kind_and_stream_metadata`.
- Targeted stream outbox encryption test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core streams::tests::remote_stream_write_queues_peer_encrypted_chunk_without_payload`.
- Targeted relay request consistency test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::relay_request_rejects_type_kind_mismatch`.
- Targeted relay E2E stream test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_delivers_peer_encrypted_stream_chunk_between_two_state_homes`.
- Targeted relay metadata-forwarding regression passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_forwards_metadata_between_two_runtime_sessions`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Stale docs scan found no remaining live outdated stream-route claims.
- `git diff --check` passed.

Known gaps:

- Relay stream chunks are point-in-time peer-encrypted envelopes, not full bidirectional direct stream sessions.
- Direct QUIC sockets, NAT traversal, and direct stream transport remain future work.
- Superseded by the offline and durable relay mailbox passes below: bounded offline relay mailbox delivery with optional durable ciphertext files now exists, while remote room fanout, hosted mailbox accounting, managed hosted relay accounts, credential rotation/revocation, hosted session resume/accounting, hosted quotas/monitoring, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting, OS-backed key storage, and remote room fanout before public managed relay claims.

## Post Phase 15 Offline Relay Mailbox

Status: completed

Goal:

Let the self-hosted relay hold peer-encrypted message and stream-chunk envelopes for temporarily offline trusted nodes, without giving the relay plaintext payload access or claiming durable hosted mailbox behavior.

Completed work:

- Added `RelayMailboxPolicy` with configurable per-node envelope cap and envelope TTL.
- Added bounded in-memory relay mailbox queues keyed by target node id.
- Mailboxed peer-encrypted `message` and `stream_chunk` forwards when the target node is offline and the frame carries a ciphertext body.
- Drained queued envelopes immediately after the target node authenticates with `HELLO`.
- Preserved `UNDELIVERED reason=peer_offline` for metadata-only forwards and `UNDELIVERED reason=mailbox_full` when the bounded queue cannot accept another envelope.
- Added relay env vars `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE` and `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`.
- Added regression coverage for offline mailbox delivery, per-node mailbox bounds, TTL expiry, and payload-safe errors.
- Updated README, user/install docs, hosting docs, production/readiness docs, release checklist, packaging docs, repo memory, implementation guardrails, agent gateway contract, and security checklist so public claims describe the in-memory limit honestly.

Files changed:

- `README.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted mailbox policy tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_offline_mailbox -- --nocapture`.
- Targeted offline E2E relay mailbox test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_mailboxes_peer_encrypted_message_until_receiver_connects -- --nocapture`.
- Full relay crate tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- Stale docs scan found no remaining live claims that offline mailbox delivery is unimplemented; older phase history still records earlier limitations.
- `git diff --check` passed.

Known gaps:

- Superseded by the durable relay mailbox pass below: `CONU_RELAY_MAILBOX_DIR` now persists queued peer-encrypted envelopes across relay restarts, while hosted mailbox accounting, managed retention policy, and session resume integration remain future work.
- Relay mailbox delivery is only for peer-encrypted relay envelopes; the relay still must not accept plaintext payloads.
- Remote room fanout, direct QUIC sockets, NAT traversal, capability policy, signed remote agent-card exchange, managed hosted accounts, credential rotation/revocation, hosted quotas/monitoring, and OS-backed key storage remain future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting, OS-backed key storage, and remote room fanout before public managed relay claims.

## Post Phase 15 Durable Relay Mailbox

Status: completed

Goal:

Make self-hosted relay offline mailbox delivery survive relay process restarts while preserving payload opacity and avoiding managed public-relay claims.

Completed work:

- Added `RelayMailboxStorage` with memory-only default behavior and optional file-backed storage.
- Added `CONU_RELAY_MAILBOX_DIR` to `conu-relay --serve` so operators can persist peer-encrypted mailbox envelopes on disk.
- Loaded valid persisted mailbox entries when a relay starts, pruned expired entries by mailbox TTL, and removed invalid or expired entries without echoing contents.
- Enforced the current per-node mailbox cap while loading persisted entries, removing excess stored envelope files without echoing contents.
- Persisted only rendered relay `ENVELOPE` metadata plus ciphertext body fields and `payload_displayed = false`; no plaintext payload fields are accepted or stored.
- Removed stored mailbox files after successful drain to the target node.
- Added a relay restart regression proving a peer-encrypted offline envelope survives relay restart, is delivered after the target authenticates, and does not store or output private payload text.
- Updated Docker relay image/template to create `/var/lib/conu-relay/mailbox`, default `CONU_RELAY_MAILBOX_DIR` inside the container, and document a persistent volume mount.
- Updated README, internet relay test docs, hosting docs, production readiness, release checklist, SDK/MCP docs, packaging docs, repo memory, implementation guardrails, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted durable relay restart test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_mailbox_survives_relay_restart_without_payloads -- --nocapture`.
- Targeted durable mailbox load-cap test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_mailbox_load_respects_current_cap_without_payloads -- --nocapture`.
- Targeted mailbox policy tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_offline_mailbox -- --nocapture`.
- Full relay crate tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.
- Docker image build was not run because Docker is not installed in this Windows environment.

Known gaps:

- Durable relay mailbox storage is self-hosted filesystem storage, not managed hosted mailbox accounting, quotas, or retention dashboards.
- Relay mailbox persistence still stores relay-visible metadata, public key material, and ciphertext; it must not be marketed as hiding metadata from the relay.
- Superseded by the Windows DPAPI secret wrapping pass below for local Windows private-key bytes; hosted relay account auth, credential rotation/revocation, hosted session resume/accounting, hosted quotas/monitoring, remote room fanout, direct QUIC sockets, NAT traversal, capability policy, signed remote agent-card exchange, and non-Windows OS-backed key storage remain future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting/quotas, non-Windows OS-backed key storage, and remote room fanout before public managed relay claims.

## Post Phase 15 Windows DPAPI Secret Wrapping

Status: completed

Goal:

Reduce local private-key exposure on supported Windows installs by wrapping conU-owned local signing, exchange, and storage secret bytes with the OS user secret backend while preserving older state compatibility and payload opacity.

Completed work:

- Added Windows current-user DPAPI wrapping for local Ed25519 signing secret bytes, X25519 exchange secret bytes, and XChaCha20Poly1305 storage key bytes.
- Kept migration-compatible reads for existing plaintext-hex key files and migrated those files to DPAPI-wrapped fields during `ensure_security_state`.
- Added security audit fields for `secretStorageBackend` and `secretsOsProtected` without exposing private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- Added regression coverage for new wrapped key files, plaintext-key migration, CLI audit redaction, and MCP audit redaction.
- Updated README, security hardening docs, production readiness docs, install guide, release checklist, SDK/MCP docs, distribution docs, repo memory, implementation guardrails, agent gateway contract, and security checklist.

Files changed:

- `Cargo.lock`
- `README.md`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `scripts/smoke-relay-daemon.ps1`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted security key creation test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::security_state_creates_key_material_without_plaintext_payloads -- --nocapture`.
- Targeted plaintext migration test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::existing_plaintext_secret_files_are_read_and_migrated_when_supported -- --nocapture`.
- Focused security module tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security -- --nocapture`.
- Focused CLI security audit test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security -- --nocapture`.
- Focused MCP audit redaction test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp security_audit_tool_reports_backend_without_secret_material -- --nocapture`.
- Manual isolated audit run confirmed `secretStorageBackend = "windows-dpapi-user"`, `secretsOsProtected = true`, wrapped key files contain `*_dpapi_hex`, and CLI JSON does not expose private key fields.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and recreated `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.

Known gaps:

- DPAPI support covers Windows current-user local secrets only; Linux/macOS still need platform keychain, Secure Enclave, HSM, or user-managed secret backend integration.
- Superseded by the storage-key rotation, storage-key retirement, and identity-key rotation passes below for local key lifecycle operations; hosted managed identity/key administration remains future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.
- Hosted relay account auth, credential rotation/revocation, hosted session resume/accounting, hosted mailbox accounting/quotas, remote room fanout, direct QUIC sockets, NAT traversal, capability policy, and signed remote agent-card exchange remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, capability policy, signed remote agent-card exchange, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Relay Credential Storage

Status: completed

Goal:

Let runtime clients store a scoped relay token in conU local security state instead of relying only on process environment, while preserving token opacity across CLI, logs, tests, and docs.

Completed work:

- Added `security/relay-credential.key` to local state paths for an optional runtime relay client token.
- Added relay credential store/read/status/clear helpers that use the same secret-field backend as other security files: current-user DPAPI on Windows and owner-only local file fallback on non-Windows.
- Kept `CONU_RELAY_TOKEN` as the runtime override, then fall back to the stored credential, then `local-dev-token` for loopback tests.
- Added `conu relay credential set --stdin`, `status`, and `clear` with JSON/text output that reports configured/backend/protection status but never displays token material.
- Updated relay delivery so daemon and manual sync paths resolve tokens through environment, stored credential, then loopback default.
- Added regression tests for storage redaction, runtime token precedence, and CLI stdin/status behavior.
- Updated README, security hardening docs, install guide, hosting docs, production readiness, release checklist, SDK/MCP docs, repo memory, guardrails, repo map, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/security.rs`
- `crates/conu-core/src/state.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `scripts/smoke-identity-retirement.ps1`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay credential storage test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::relay_credential_storage_hides_token_and_reports_backend -- --nocapture`.
- Targeted relay token precedence test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::relay_token_prefers_env_then_stored_credential_without_echoing_secret -- --nocapture`.
- Focused CLI relay credential test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli relay_credential_cli_uses_stdin_and_never_prints_token -- --nocapture`.
- Focused security module tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security -- --nocapture`.
- Focused relay delivery tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and recreated `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.
- Docker image build was not run because Docker is not installed in this Windows environment.

Known gaps:

- Stored relay client credentials are local runtime configuration, not managed hosted account auth, dynamic credential issuance, token rotation, revocation, or tenant accounting.
- Non-Windows stored relay credentials still use owner-only local files until platform keychain, Secure Enclave, HSM, or user-managed secret backend support lands.
- Hosted relay session resume/accounting, hosted mailbox accounting/quotas, remote room fanout, direct QUIC sockets, NAT traversal, capability policy, and signed remote agent-card exchange remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, capability policy, signed remote agent-card exchange, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Signed Peer Cards

Status: completed

Goal:

Add cryptographic integrity checks to manual public peer-card exchange so cross-machine trust imports can detect modified node id, exchange key, display name, or relay endpoint fields without exposing private keys or payloads.

Completed work:

- Added Ed25519 signature fields to exported `PeerCard` values using the existing local node signing key.
- Added peer-card canonicalization and signature verification in `trust_peer_card`; tampered signed cards are rejected before trust storage.
- Stored public peer-card signature metadata in `trust.toml` and exposed payload-safe `peerCardSigned` status through CLI and MCP peer surfaces.
- Kept unsigned peer-card imports as legacy controlled-test compatibility while preferring signed cards in docs and examples.
- Added CLI flags for signed peer-card import: `--signing-key`, `--signature`, `--signature-key-id`, and optional `--signature-algorithm`.
- Updated Python SDK trust helper and MCP `conu_export_identity`/`conu_trust_peer` tool fields for signed peer-card exchange.
- Updated README, install guide, relay test guide, hosting docs, security hardening docs, SDK/MCP docs, production readiness, release checklist, repo memory, guardrails, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/trust.rs`
- `crates/conu-mcp/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted trust tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core trust -- --nocapture`.
- Targeted CLI peer test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli peers -- --nocapture`.
- Targeted MCP metadata test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp route_tools_return_metadata_only -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed signed peer-card trust plus daemon-owned relay delivery.

Known gaps:

- Signed peer cards are local/manual trust setup integrity, not a managed hosted account identity system, certificate transparency log, revocation service, or web-of-trust.
- Remote agent-card exchange over real sessions is still future work; current remote agents are still metadata mirrors or explicit local trust artifacts.
- Peer-scoped permission grants, hosted relay account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize signed remote agent-card exchange, peer-scoped permission policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Local Capability Enforcement

Status: completed

Goal:

Make agent capability booleans user-visible and enforce them in the core message, stream, and room routing paths without exposing payload contents.

Completed work:

- Added explicit `conu agents register` capability flags for `messages`, `streams`, `rooms`, `files`, and `presence`, preserving message/presence defaults.
- Enforced local recipient capabilities for inbound remote messages, stream chunks, and room event fanout.
- Enforced stream capability on local stream source/target agents, remote stream target metadata, and relay-backed stream chunk submission.
- Enforced room capability on room create, join, publish, and local room-event recipients.
- Updated the Python wrapper registration API to pass explicit capability booleans.
- Added regression coverage for stream source/target capability denial, relay stream sender denial, room create/join denial, inbound stream/room delivery denial, and CLI capability persistence.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening docs, production readiness, release checklist, repo memory, guardrails, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted stream tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core streams`.
- Targeted room tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core rooms`.
- Targeted message tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core messages`.
- Targeted relay stream capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::remote_stream_chunk_requires_sender_stream_capability`.
- Targeted CLI capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli agents_register_persists_explicit_capabilities`.
- Targeted MCP room capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp room_tools_keep_publish_payload_safe`.
- Targeted relay stream E2E capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_delivers_peer_encrypted_stream_chunk_between_two_state_homes`.
- Targeted SDK room capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk sdk_room_flow_returns_metadata_only`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery after capability enforcement.
- `git diff --check` passed.

Known gaps:

- Capability enforcement is now backed by manual signed remote agent-card import for trusted peers; automatic live agent-card exchange and peer-scoped permission grants remain future work.
- Superseded by later passes below: relay-backed room fanout and room topic policy are now implemented. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize peer-scoped permission policy, automatic live agent-card exchange, managed hosted relay account/credential lifecycle, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Signed Remote Agent Cards

Status: completed

Goal:

Add a verified remote agent-card exchange path so remote agent capability metadata can be imported from a trusted peer's signed public agent card instead of relying only on placeholder mirrors.

Completed work:

- Added `SignedAgentCard` export and verification helpers in `conu_core::agents`.
- Added `trust_remote_agent_card` in `conu_core::sessions`, including signature verification, trusted-peer node/signing-key binding, cross-peer agent-id collision checks, and preservation of imported signed cards during session sync.
- Added `conu agents export` and `conu agents trust` CLI commands with JSON/text output that stays payload-safe.
- Exposed signed agent-card export/import through the Rust SDK, Python wrapper SDK, and MCP tools.
- Added regression coverage for signed-card export, import, session sync preservation, tamper rejection, trusted-peer signing-key mismatch rejection, CLI, SDK, and MCP paths.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening docs, production readiness, release checklist, repo memory, guardrails, agent gateway contract, Python SDK docs, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted core signed-card tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core signed`.
- Targeted CLI signed-card test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli signed_agent_card_cli_export_and_import_verifies_without_payloads`.
- Targeted SDK signed-card test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk signed_remote_agent_cards`.
- Targeted MCP signed-card test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp signed_agent_card_tools_export_and_trust_metadata_only`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Signed remote agent cards are manual public card exchange after peer trust; automatic live agent-card distribution over sessions remains future work.
- Superseded by the peer-scoped permission policy pass below: trusted peers now require explicit local policy grants before remote message, stream, or room surfaces are accepted.
- Superseded by later passes below: relay-backed room fanout and room topic policy are now implemented. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize automatic live agent-card exchange, remote room fanout/per-topic policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Peer-Scoped Permission Policy

Status: completed

Goal:

Add a local default-deny peer policy layer so trusting a peer establishes identity, while explicit metadata-only grants authorize messages, streams, rooms, files, and mailbox surfaces.

Completed work:

- Added `conu_core::policy` with `PeerPolicyRecord`, `PeerPolicyUpdate`, `PeerPermission`, `policy.toml` persistence, trusted-peer validation, default-deny effective policy reads, and payload-safe record rendering.
- Enforced peer policy on relay-backed outbound and inbound message envelopes, relay-backed stream chunks, remote stream opens/writes, and remote room participant visibility.
- Added `conu peers policy` CLI read/list/update flows with JSON/text output and updated help/next-command guidance.
- Exposed peer policy through the Rust SDK, Python wrapper SDK, and MCP `conu_set_peer_policy` tool.
- Updated relay E2E helpers and `scripts/smoke-relay-daemon.ps1` so relay flows grant scoped message/stream policy after peer-card trust.
- Updated README, architecture, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening, production readiness, release checklist, repo memory, guardrails, gateway contract, Python SDK docs, and the security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/policy.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `scripts/smoke-relay-daemon.ps1`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/Pr/SKILL.MD`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted CLI peer-policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli peer_policy_cli_sets_scoped_grants_without_payloads`.
- Targeted SDK peer-policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk sdk_sets_peer_policy_metadata_only`.
- Targeted MCP peer-policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp peer_policy_tool_sets_scoped_grants_without_payloads`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed with explicit peer policy grants before remote delivery.
- `git diff --check` passed.

Known gaps:

- Peer policy is local file-backed policy, not hosted multi-tenant permission administration.
- File and mailbox policy bits are stored for forward compatibility; no active file-transfer or user-controlled remote mailbox surface is implemented yet.
- Superseded by the automatic signed agent-card exchange pass below: session sync now exchanges signed public agent cards over peer-encrypted relay control envelopes for signed trusted peers with policy grants.
- Superseded by later passes below: relay-backed room fanout and room topic policy are now implemented. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize remote room fanout/per-topic policy, managed hosted relay account/credential lifecycle, direct transport, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Automatic Signed Agent-Card Exchange

Status: completed

Goal:

Remove the manual signed-agent-card exchange requirement for normal trusted relay sessions by sending signed local agent cards as encrypted control-plane relay envelopes during session sync.

Completed work:

- Added metadata render/parse helpers for signed agent cards in `conu_core::agents`.
- Added `agent_card` relay envelope kind and a ciphertext-only relay frame path for signed-card control envelopes.
- Added session-sync queuing of signed local agent cards for signed trusted peers that have at least one peer policy grant.
- Added inbound automatic card import in relay delivery, using the existing signature verification, trusted-node binding, signing-key match, and cross-peer collision checks before replacing placeholder remote-agent records.
- Kept relay-visible data to node ids, agent ids, envelope ids, byte counts, public exchange key material, and ciphertext.
- Added core and relay E2E coverage proving encrypted card queuing and two-node automatic signed-card import.
- Updated the relay daemon smoke to trust signed peer cards and keep the explicit peer policy grant step.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening, production readiness, release checklist, repo memory, guardrails, gateway contract, Python SDK docs, and security checklist.

Files changed:

- `README.md`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `scripts/smoke-relay-daemon.ps1`
- `sdk/python/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted core automatic-card queue test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core session_sync_queues_signed_agent_cards_without_payloads`.
- Targeted relay automatic-card E2E test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_exchanges_signed_agent_cards_during_session_sync`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed with signed peer-card trust, explicit peer policy grants, daemon relay delivery, and payload leak checks.
- `git diff --check` passed.

Known gaps:

- Automatic signed-card exchange requires signed peer-card trust, at least one local peer policy grant, and a relay route/pump; manual signed-card import remains the fallback for daemonless or unsigned controlled tests.
- The relay control envelope is still relay-routed, not direct QUIC.
- Superseded by the remote room fanout and room topic policy passes below: relay-backed room events now fan out to joined trusted remote agents, and configured topics require explicit publish/subscribe grants. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, multi-tenant hosted permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle next, then direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Relay-Backed Room Event Fanout

Status: completed

Goal:

Move room publishes for joined trusted remote participants from metadata-only representation to relay-backed peer-encrypted event delivery while preserving payload opacity and default-deny room policy.

Completed work:

- Added a `room_event` relay envelope kind and ciphertext-only relay frame constructor.
- Added peer-encrypted remote room event outbox queuing with room event packets that keep room id, topic, event id, and event bytes inside the encrypted body rather than relay-visible frame metadata.
- Added room publish fanout to joined trusted remote participants when remote signed agent metadata advertises `rooms=true` and peer policy grants `rooms=true`.
- Added inbound relay room event delivery to the addressed local agent inbox as encrypted-at-rest `kind = "event"` envelopes, with payload-safe room event metadata recorded locally after delivery.
- Kept room publish responses metadata-only while reporting both local and remote delivery counts.
- Added core relay-outbox privacy coverage and relay E2E coverage for two-node peer-encrypted room event delivery.
- Updated the relay daemon smoke setup to grant room policy and register room-capable smoke agents.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening, production readiness, release checklist, repo memory, guardrails, gateway contract, repo map, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay frame privacy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core room_event_frame_carries_ciphertext_only`.
- Targeted core remote-room outbox privacy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core room_publish_queues_remote_relay_events_without_payloads`.
- Targeted relay room E2E test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_delivers_peer_encrypted_room_event_between_two_state_homes`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed with signed peer-card trust, explicit peer policy grants including rooms, daemon relay delivery, and payload leak checks.
- `git diff --check` passed.

Known gaps:

- Superseded by the room topic policy pass below: configured room/topic pairs now require explicit publish/subscribe grants; unconfigured topics retain the room membership boundary for compatibility. Hosted multi-tenant room permission administration remains future work.
- Relay room events are point-in-time peer-encrypted envelopes, not direct QUIC room sessions.
- Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle next, then hosted accounting, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Room Topic Policy

Status: completed

Goal:

Add metadata-only per-topic room publish/subscribe authorization across local room publishes, local fanout, relay fanout, and inbound relay room-event delivery without exposing payload bytes.

Completed work:

- Added `rooms/policy.toml` state path support and a metadata-only `RoomTopicPolicyRecord` with room id, agent id, topic, publish/subscribe booleans, timestamps, and `payload_displayed = false`.
- Added `RoomTopicPolicyUpdate`, list/read/set core APIs, and `conu rooms policy` text/JSON CLI surfaces.
- Added Rust SDK, Python SDK, and MCP room topic policy methods/tools.
- Enforced configured topic policy on local publish, local subscriber fanout, remote subscriber fanout, and inbound relay room-event delivery.
- Preserved compatibility for unconfigured topics: room membership remains the subscription boundary until any policy record exists for that exact room/topic.
- Added local core tests for allowed subscriber fanout, denied publisher behavior, and inbound relay publish denial.
- Added CLI, SDK, MCP, and relay E2E coverage proving metadata-only topic grants and relay denial without leaking room-event payloads.
- Updated README, install guide, relay test guide, SDK/MCP docs, security hardening, production readiness, release checklist, architecture, repo memory, guardrails, gateway contract, repo map, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted core room topic policy tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core room_topic_policy -- --nocapture`.
- Targeted CLI room policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli rooms_policy_cli_sets_topic_grants_without_payloads -- --nocapture`.
- Targeted SDK room topic policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk sdk_room_topic_policy_controls_publish_and_subscribe -- --nocapture`.
- Targeted MCP room topic policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp room_topic_policy_tool_sets_grants_without_payloads -- --nocapture`.
- Targeted relay room topic denial test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_rejects_room_event_when_inbound_topic_policy_denies_sender -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Unconfigured room topics intentionally keep the existing membership boundary for compatibility; strict default-deny for every new topic would need an explicit room-level strict-mode migration.
- Room topic policy is local file-backed administration only, not hosted multi-tenant permission management.
- Relay room events are still point-in-time peer-encrypted envelopes, not direct QUIC room sessions.
- Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle and hosted accounting next, then direct QUIC/NAT traversal, hosted multi-tenant permission administration, non-Windows keychain support, and optional strict room topic default-deny mode.

## Post Phase 15 Relay Credential Manifest Lifecycle

Status: completed

Goal:

Move self-hosted relay credential lifecycle beyond raw static server tokens by adding a token-safe manifest with per-node hashed credentials, revocation, and expiry metadata while preserving the existing relay protocol and local compatibility paths.

Completed work:

- Added hashed scoped relay credentials through `RelayCredential::from_sha256_hex`, with token-safe constant-time hash comparisons and redacted Debug output.
- Added `RelayCredentialStatus` with `active` and `revoked` lifecycle states, plus optional `expires_at_unix` denial for expired credentials.
- Added `CONU_RELAY_CREDENTIALS_FILE` support in `conu-relay --serve`; the file path overrides `CONU_RELAY_CREDENTIALS`, which still overrides shared `CONU_RELAY_TOKEN`.
- Added a versioned `[[credential]]` manifest parser that accepts `node_id`, `token_sha256_hex`, `token_length`, `status`, optional `expires_at_unix`, and token/payload display guards.
- Added `conu-relay --hash-token`, which reads a token from stdin and prints only `token_sha256_hex`, `token_length`, and `token_displayed = false`.
- Extended the public-bind guard to hashed credentials by rejecting the `local-dev-token` hash and token length metadata under 24 characters for non-loopback binds.
- Added relay tests for hashed credential acceptance, manifest revocation/expiry, public-bind rejection without hash echo, and manifest display-guard validation.
- Updated relay hosting, Docker, npm, install, production-readiness, release-checklist, architecture, repo memory, guardrail, gateway-contract, and security-checklist docs to describe the manifest as self-hosted lifecycle hardening rather than managed hosted account auth.

Files changed:

- `Cargo.lock`
- `README.md`
- `architecture.md`
- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay credential tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay credential -- --nocapture`.
- Focused relay check passed: `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --hash-token` with stdin passed and printed only hash/length/display metadata.
- `git diff --check` passed.

Known gaps:

- This is self-hosted static manifest lifecycle, not managed hosted account auth, tenant identity, or online credential issuance.
- Superseded by the live credential manifest reload pass below: manifest revocation/expiry now affects new `HELLO` authentications without relay restart; no admin API, audit log, hosted account auth, or hosted credential issuance service exists yet.
- Token hashes reduce raw server-side token storage but remain brute-forceable if operators choose weak tokens; public binds still require custom tokens with at least 24 characters.
- Hosted relay quotas/accounting, hosted mailbox accounting, hosted session resume/accounting, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize hosted relay accounting/quotas and session accounting next, then direct QUIC/NAT traversal, hosted multi-tenant permission administration, non-Windows keychain support, and managed hosted account APIs.

## Post Phase 15 Relay Accounting And Quotas

Status: completed

Goal:

Add payload-safe self-hosted relay accounting and per-node quota enforcement so operators can track usage and cap abuse without inspecting message, stream, room-event, or signed-card payloads.

Completed work:

- Added `RelayAccountingPolicy` with a configurable accounting window plus optional per-node sent-envelope and sent-byte quotas.
- Added `RelayAccountingStorage` with optional file-backed accounting under `CONU_RELAY_ACCOUNTING_DIR`.
- Added metadata-only per-node accounting records with authenticated session counts, sent/received envelope counts, byte counters, mailbox counters, `payload_displayed = false`, and `token_displayed = false`.
- Wired the relay hub to record authenticated sessions, accepted online forwards, accepted mailbox forwards, receiver counters, and persisted accounting files without storing tokens, token hashes, payload text, ciphertext bodies, or frame bodies.
- Added quota denial before forwarding; over-quota sends return `UNDELIVERED reason=quota_exceeded` without echoing payload or token material.
- Added env knobs: `CONU_RELAY_ACCOUNTING_DIR`, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS`, `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE`, and `CONU_RELAY_MAX_BYTES_SENT_PER_NODE`.
- Updated Docker defaults to create and persist `/var/lib/conu-relay/accounting`.
- Updated README, hosting docs, install guide, Docker/npm docs, production-readiness, release checklist, architecture, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay accounting tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay accounting -- --nocapture`.
- Focused relay check passed: `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets`.
- Focused relay clippy passed: `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is self-hosted relay accounting, not hosted billing, tenant management, distributed dashboards, adaptive abuse response, or a managed account service.
- Accounting files contain metadata counters and node ids; operators should treat them as usage metadata, not payload-private from the relay operator.
- Quotas apply per relay process/accounting file window and do not yet coordinate across a horizontally scaled relay fleet.
- Superseded by the relay session resume semantics pass below for same-process same-node reconnects; distributed hosted session state, distributed hosted accounting dashboards, managed hosted mailbox retention policy, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize direct QUIC/NAT traversal or managed hosted account APIs next, then distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Relay Session Resume Semantics

Status: completed

Goal:

Add payload-safe relay session resume semantics for same-process daemon reconnects without turning self-hosted relay state into a managed hosted session service.

Completed work:

- Extended the relay frame contract so `HELLO` can carry an optional `resume=<session-id>` hint and `WELCOME` reports `resumed=<true|false>`, while legacy `WELCOME` frames still parse as `resumed = false`.
- Added relay-side same-node validation for resume hints. A resume id is accepted only when it belongs to the authenticated node and the node does not already have an active client; cross-node or stale active-session attempts get a new session id instead.
- Updated `RelayRuntimePump` to remember the prior session id only for the same endpoint after disconnects and to redact active/resume session ids from Debug output.
- Added `sessions_resumed` to metadata-only relay accounting files with backward-compatible reads for older accounting files.
- Added protocol, relay, accounting, and daemon pump regression coverage for resume round trips, cross-node resume rejection, resumed-session accounting, and Debug redaction.
- Updated README, hosting docs, production readiness, release checklist, SDK/MCP boundaries, install guide, packaging docs, architecture, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused core resume tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core resume -- --nocapture`.
- Focused relay resume tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay resume -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Resume hints are same-process and same-endpoint only; conUD does not persist relay session ids across daemon restarts.
- Session ids are relay metadata visible on the wire to the relay process. They are not stored in relay accounting files and Debug/runtime log surfaces should not display them.
- This is not distributed hosted session migration, multi-region relay state, hosted billing/accounting, managed account auth, online credential issuance APIs, adaptive abuse response, or hosted tenant administration.
- Direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize direct QUIC/NAT traversal or managed hosted relay account/credential lifecycle next, then distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Live Relay Credential Manifest Reload

Status: completed

Goal:

Reduce self-hosted relay credential lifecycle downtime by applying hashed manifest revocation and expiry to new relay sessions without restarting `conu-relay`, while keeping token and payload material out of logs, errors, docs, and relay storage.

Completed work:

- Added a live-reloaded `RelayAuth::ScopedCredentialsFile` mode that stores only the manifest path and bind address in relay config.
- Added `RelayConfig::with_scoped_credentials_file`, which validates the initial manifest at startup and then reloads the manifest on each new `HELLO` authentication attempt.
- Kept `CONU_RELAY_CREDENTIALS_FILE` precedence over `CONU_RELAY_CREDENTIALS` and shared `CONU_RELAY_TOKEN`, but changed the environment path to use the live-reloaded file mode.
- Added fail-closed behavior for missing, unreadable, invalid, duplicate-node, revoked, expired, weak public-bind, or malformed live manifest updates. Existing authenticated sessions remain governed by idle timeout and max TTL.
- Added credential manifest regression coverage for revoking a token without relay restart, fail-closed invalid manifest updates, and token/hash redaction in responses and Debug output.
- Updated README, hosting docs, internet test docs, production readiness, release checklist, user guide, SDK/MCP boundaries, packaging docs, repo memory, implementation guardrails, gateway contract, security checklist, and repo map.

Files changed:

- `README.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused credential tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay credential -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is live self-hosted manifest reload, not managed hosted account auth, tenant lifecycle, online credential issuance APIs, hosted audit logs, hosted revocation workflows, or a hosted admin service.
- Manifest updates should use atomic replacement. Invalid or missing manifests fail closed for new sessions until a valid manifest is restored.
- Existing authenticated sessions are not forcibly disconnected by manifest edits; configure idle timeout and max TTL for revocation latency bounds.
- Direct QUIC/NAT traversal, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize direct QUIC/NAT traversal or managed hosted account/credential issuance APIs next, then hosted audit/admin controls, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Direct Route Selection Guard

Status: completed

Goal:

Keep the production route manager honest by preventing configured direct QUIC metadata from becoming a selected delivery route before a real direct data plane exists.

Completed work:

- Changed route sync so valid configured `quic://` and `udp://` endpoints are still recorded and NAT-scored, but remain `unavailable` with `direct_quic_transport_inactive`.
- Kept relay selected for trusted-peer delivery when direct transport is inactive, preserving relay-backed remote stream chunk delivery instead of opening streams on an unusable direct route label.
- Added CLI route text output for failure reasons so users can see why a direct candidate was not selected without inspecting payloads.
- Updated route, stream, and CLI tests for inactive direct candidates, relay selection, payload-safe probe history, and relay-backed remote stream chunks.
- Updated README, direct-route docs, production readiness, user guide, SDK/MCP docs, release checklist, and future-agent guardrails to describe direct candidates as inactive metadata until real QUIC/NAT transport lands.

Files changed:

- `crates/conu-core/src/routes.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused route tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core routes -- --nocapture`.
- Focused remote stream test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core streams::tests::remote_stream_write_queues_peer_encrypted_chunk_without_payload -- --nocapture`.
- Focused CLI route tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli routes_sync -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed after formatting.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is a selection guard, not direct QUIC implementation. Real QUIC sockets, peer authentication over direct transport, ICE-style candidate exchange, STUN/TURN, NAT hole punching, and direct stream byte routing remain future work.
- Direct endpoint probes remain metadata-only route records; they do not validate that a QUIC peer is reachable or authenticated.
- Relay remains the only active remote data-plane path for peer-encrypted one-shot messages, stream chunks, room events, and signed-card control envelopes.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Implement a real authenticated direct QUIC/NAT traversal data plane before allowing direct routes to become selected, or prioritize managed hosted account/credential issuance APIs if hosted relay readiness is more urgent.

## Post Phase 15 Payload-Safe Log Rotation

Status: completed

Goal:

Add a production maintenance path for long-running local deployments to rotate conU metadata logs without reading, printing, classifying, uploading, or otherwise exposing log contents.

Completed work:

- Added `conu_core::observability` with `LogRotationPolicy`, `LogRotationReport`, and `rotate_logs`, rotating active `.log` files by byte threshold while keeping a bounded number of `.log.N` archives.
- Added `conu logs rotate [--max-bytes <bytes>] [--keep <count>] [--json]` with payload-safe text/JSON reports containing only log filenames, byte sizes, rotated booleans, archive-removal counts, and `contentsDisplayed=false`.
- Updated `conu doctor` log scanning to include rotated `.log.N` archives, so rotation cannot hide a payload leak from the readiness scanner.
- Added core and CLI regression coverage for archive bounds, no-content reporting, and doctor detection of payload text in rotated archives.
- Updated README, observability docs, production readiness, release checklist, user guide, repo memory, repo map, builder guardrails, and security checklist.

Files changed:

- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/observability.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/observability.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused observability tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core observability -- --nocapture`.
- Focused CLI log tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli logs -- --nocapture`.
- Focused doctor tests passed during the CLI log test and full workspace test, including rotated archive scanning.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is local file rotation only, not a structured telemetry exporter, hosted log pipeline, retention dashboard, or alerting system.
- Rotation uses local active `.log` files in `CONU_HOME`; relay-host operating-system log management remains the host operator's responsibility.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted multi-tenant permission administration, real direct QUIC/NAT traversal, managed hosted identity/key administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize structured telemetry with field allowlists, managed hosted account/credential issuance APIs, or direct QUIC/NAT traversal next, depending on whether local release hardening or hosted-relay readiness is more urgent.

## Post Phase 15 Storage-Key Rotation Migration

Status: completed

Summary:

- Added `security/storage-keys/` as the archived local storage-key ring.
- Added multi-key storage payload reads so encrypted-at-rest local payload files can remain readable after active storage-key rotation.
- Added `conu security rotate storage --confirm [--json]` to archive the old storage key, create a new active storage key, and re-encrypt conU-owned encrypted-at-rest message queue and inbox payload files.
- Kept rotation output payload-safe: only key ids, file counts, archive counts, and `contentsDisplayed=false`; no key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- Updated security, release, user, and future-agent docs to move storage-key migration tooling from a blocker to an implemented local hardening control.

Files changed:

- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused storage rotation tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_rotation_reencrypts_local_payload_files`.
- Focused archived old-key read test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_archive_keeps_old_payloads_readable_after_rotation`.
- Focused older archived-key migration retry test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_rotation_migrates_older_archived_key_payloads`.
- Focused CLI storage rotation test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_rotate_storage_requires_confirmation_and_hides_payloads`.
- Focused security suites passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security -- --nocapture` and `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Storage-key rotation currently migrates local encrypted-at-rest message queue and inbox files. Relay durable mailbox ciphertext is peer-encrypted and intentionally not re-encrypted by local storage-key rotation.
- Superseded by the storage-key retirement pass below: unused archived storage keys can now be deleted after local queue/inbox dependency scanning.
- Superseded by the identity-key rotation pass below: local signing/exchange keys can be rotated with explicit peer-card refresh requirements.
- Non-Windows local secret storage still needs platform keychain, Secure Enclave, HSM, or a user-managed secret backend before high-security public release claims.

Next recommendation:

- Prioritize structured telemetry with payload-safe field allowlists, managed hosted account/credential issuance APIs, or direct QUIC/NAT traversal.

## Post Phase 15 Storage-Key Retirement

Status: completed

Summary:

- Added `conu security retire storage --confirm [--json]` to remove archived storage keys only when no scanned local encrypted-at-rest message queue or inbox payload still references them.
- Added core retirement reporting for archived keys scanned, retired keys, retained keys, scanned files, dependent files, and `contentsDisplayed=false`.
- Kept dependent archived keys readable and retained when local queue/inbox payload metadata still references them.
- Updated security, release, user, and future-agent docs to move old storage-key retirement from a known gap to an implemented local hardening control.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused unused-archive retirement test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_retirement_removes_unused_archives_after_migration`.
- Focused dependent-archive retention test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_retirement_retains_archives_with_dependencies`.
- Focused CLI retirement test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_retire_storage_requires_confirmation_and_hides_payloads`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Retirement scans conU-owned local message queue and inbox payload metadata only; relay durable mailbox ciphertext is peer-encrypted and intentionally outside local storage-key retirement.
- Superseded by the identity-key rotation pass below: local signing/exchange keys can be rotated with explicit peer-card refresh requirements.
- Non-Windows local secret storage still needs platform keychain, Secure Enclave, HSM, or a user-managed secret backend before high-security public release claims.

Next recommendation:

- Prioritize managed hosted account/credential issuance APIs, hosted telemetry/dashboard pipelines, or direct QUIC/NAT traversal.

## Post Phase 15 Structured Telemetry Snapshot

Status: completed

Summary:

- Added `conu telemetry snapshot [--json]` for local structured telemetry with schema `conu.telemetry.snapshot.v1`.
- Added `TELEMETRY_FIELD_ALLOWLIST` in `conu_core::observability` and wired CLI output to report only allowlisted aggregate counters.
- Telemetry covers local state readiness, runtime health, local/remote agent counts, sessions, streams, rooms, selected routes, relay queue counts, log scan counts, and security readiness booleans.
- Kept telemetry payload-safe: no node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, private keys, shared secrets, auth tokens, plaintext payloads, decrypted payloads, or ciphertext bodies.
- Updated docs and future-agent memory to move local structured telemetry from a known gap to an implemented local hardening control while leaving hosted telemetry pipelines/dashboards as future work.

Files changed:

- `crates/conu-core/src/observability.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `architecture.md`
- `docs/observability.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused telemetry CLI tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli telemetry_snapshot -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Telemetry is local CLI snapshot output only; there is no hosted telemetry collector, OTLP exporter, retention policy engine, alerting, or distributed dashboard.
- The log privacy scan remains a guardrail for known forbidden terms, not a substitute for code review or a comprehensive DLP engine.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted multi-tenant permission administration, direct transport, managed hosted identity/key administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted account APIs, online credential issuance/rotation workflows beyond the offline helper, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, managed hosted identity/key administration, or non-Windows keychain support.

## Post Phase 15 Offline Relay Credential Issuance

Status: completed

Summary:

- Added `conu-relay --issue-credential <node-id> --token-out <path> [--expires-at-unix <seconds>] [--json]` for offline scoped relay credential issuance.
- Added `IssuedRelayCredential`, token generation, manifest-entry rendering, and token-file writing in `conu-relay`.
- Kept the secret split explicit: the raw generated token is written only to a new token file, while stdout reports only node id, token path, token length, optional expiry, display guards, and the hashed manifest entry.
- Kept manifest compatibility with the live-reloaded `CONU_RELAY_CREDENTIALS_FILE` parser, including `token_sha256_hex`, `token_length`, `status`, optional `expires_at_unix`, `payload_displayed = false`, and `token_displayed = false`.
- Updated relay hosting, Docker, internet test, security, production-readiness, release-checklist, architecture, and future-agent docs to describe offline issuance as self-hosted lifecycle hardening, not managed hosted account auth.

Files changed:

- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `architecture.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused issuance tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay issued_relay -- --nocapture`.
- Command smoke passed: `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --issue-credential node.issue --token-out <temp> --json`; the token file was non-empty and stdout did not contain the raw token.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is offline self-hosted credential issuance, not hosted account auth, online issuance APIs, tenant lifecycle, hosted audit logs, online token rotation, or a hosted admin service.
- Issued token files are explicit local secret artifacts; operators still need secure delivery and lifecycle practices outside conU.
- Managed hosted account auth, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, managed hosted identity/key administration, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted account APIs, online credential rotation/revocation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, managed hosted identity/key administration, or non-Windows keychain support.

## Post Phase 15 Relay Credential Manifest Operations

Status: completed

Summary:

- Added helper-driven self-hosted relay credential manifest updates through `upsert_issued_relay_credential_in_file` and `revoke_relay_credential_in_file`.
- Extended `conu-relay --issue-credential` with `--credentials-file` and `--replace` so operators can create, append, or rotate hashed manifest entries without hand-editing.
- Added `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a scoped credential revoked without displaying raw tokens, token hashes, payloads, or manifest contents.
- Preserved the existing live-reload manifest shape while parsing and rendering `created_at_unix` / `updated_at_unix` metadata and enforcing token/payload display guards.
- Updated relay hosting, Docker, internet test, security, production-readiness, release-checklist, SDK/MCP, and future-agent docs to prefer helper-driven manifest lifecycle operations for self-hosted relays.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused manifest reload/revoke tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay credential_manifest -- --nocapture`.
- Focused issuance/upsert tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay issued_relay_credential -- --nocapture`.
- Relay credential lifecycle command smoke passed: `conu-relay --issue-credential node.smoke --token-out <temp> --credentials-file <temp> --json`, duplicate issue without `--replace`, then `conu-relay --revoke-credential node.smoke --credentials-file <temp> --json`; stdout and manifest did not contain the raw token, duplicate issue did not create a token file, and the manifest ended revoked.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is self-hosted offline manifest lifecycle tooling, not managed hosted account auth, tenant identity, online issuance APIs, hosted audit logs, hosted revocation workflows, or a hosted admin service.
- Issued token files are still explicit local secret artifacts; operators remain responsible for secure delivery to the intended node.
- Managed hosted account auth, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, managed hosted identity/key administration, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted account APIs, online credential issuance/rotation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, managed hosted identity/key administration, or non-Windows keychain support.

## Post Phase 15 Identity-Key Rotation

Status: completed

Summary:

- Added `conu security rotate identity --confirm-peer-refresh [--json]` for explicit local Ed25519 signing-key and X25519 exchange-key rotation.
- Archived the previous signing and exchange private keys under `security/identity-keys/` using the same secret-field backend as active key files: current-user DPAPI on Windows and owner-only secret files on non-Windows.
- Generated fresh active signing/exchange key material and reported old/new key ids, archive counts, peer-card refresh requirements, signed-agent-card refresh requirements, and `contentsDisplayed=false`.
- Kept archived exchange keys available for decrypting peer envelopes addressed to the previous public exchange key during the peer-card refresh window.
- Updated the key-rotation plan and public docs so local identity-key rotation is implemented while hosted managed identity/key administration and non-Windows keychain integration remain future work.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused identity-key rotation core test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core identity_key_rotation_archives_old_exchange_key_without_secret_output -- --nocapture`.
- Focused identity-key rotation CLI test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_rotate_identity_requires_peer_refresh_and_hides_keys -- --nocapture`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- Manual isolated identity rotation smoke passed: initialized a fresh `CONU_HOME`, ran `conu security rotate identity --confirm-peer-refresh --json`, verified no secret/DPAPI/private/plaintext markers in output, and verified `conu identity export --json` produced new public signing and exchange material.
- `git diff --check` passed.

Known gaps:

- Peer-card refresh distribution is explicit and local through `conu identity export`; there is no hosted managed key-publication, revocation, or account administration service.
- Superseded by the identity archive-retirement pass below: archived identity keys can now be removed after operators confirm peer-card refresh is complete.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize non-Windows OS-backed secret storage, managed hosted account/key administration, or real direct QUIC/NAT traversal depending on the next release target.

## Post Phase 15 Identity Archive Retirement

Status: completed

Summary:

- Added `conu security retire identity --confirm-peer-refresh-complete [--json]` for explicitly deleting archived old identity signing/exchange keys after refreshed public peer cards have been redistributed.
- Added `IdentityKeyRetirementReport` with archive counts, peer-card refresh confirmation, old-key decrypt compatibility status, and `contentsDisplayed=false`.
- Kept the command payload-safe: it reports counts and booleans only, and does not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- Preserved the active signing/exchange keys while deleting archived old identity keys from `security/identity-keys/`; after retirement, peer envelopes encrypted to the old exchange public key no longer decrypt locally.
- Updated README, security hardening docs, production readiness docs, release checklist, user guide, repo memory, guardrails, repo map, and security checklist.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused identity archive-retirement core test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core identity_key_retirement_removes_archives_after_refresh_confirmation -- --nocapture`.
- Focused identity archive-retirement CLI test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_retire_identity_requires_refresh_confirmation_and_hides_keys -- --nocapture`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Peer-card refresh distribution is still explicit and local through `conu identity export`; there is no hosted managed key-publication, revocation, or account administration service.
- Identity archive retirement intentionally removes old-key decrypt compatibility for envelopes addressed to old exchange public keys; operators must run it only after refresh is complete.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize non-Windows OS-backed secret storage, managed hosted identity/key administration, or real direct QUIC/NAT traversal depending on the next release target.

## Post Phase 15 TypeScript SDK Wrapper

Status: completed

Summary:

- Added `sdk/typescript`, a dependency-free Node 18+ TypeScript/JavaScript wrapper package named `@conu/sdk` around installed `conu` and `conud` binaries.
- Added typed wrappers for status, security audit, identity/storage rotation and retirement, agent registration/presence/cards, peer trust/policy, route sync/listing, local and remote messages, relay sync/credential status/set/clear, streams, rooms, room topic policy, telemetry snapshot, log rotation, and queued processing.
- Kept payload-bearing helpers on stdin-only command paths for message, remote message, stream write, room publish, and relay credential set. The smoke test asserts private payload/token bytes are passed as process input and are not present in argv.
- Added a local TypeScript example that registers two agents, sends opaque bytes, processes queued work, and prints metadata only with `contentsDisplayed=false`.
- Updated public docs, release checklists, security docs, repo memory, guardrails, and SDK/MCP docs so TypeScript is no longer described as future work.
- Aligned the TypeScript and Python signed-agent-card helper default signature algorithm with the current core/CLI `Ed25519` contract.

Files changed:

- `sdk/typescript/package.json`
- `sdk/typescript/src/index.js`
- `sdk/typescript/src/index.d.ts`
- `sdk/typescript/test/smoke.mjs`
- `sdk/typescript/README.md`
- `examples/typescript/local_agent_pair.mjs`
- `sdk/python/conu_sdk/__init__.py`
- `README.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/security-hardening.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Superseded by the post-Phase-15 TypeScript explicit receive helper pass below; JavaScript agents now have `receiveMessageBytes()` for addressed local inbox bytes.
- The TypeScript package wraps local installed binaries; it is not a browser-native SDK, hosted API client, or direct protocol implementation.
- Package publishing is not done in this pass; release publication still depends on signed/package release decisions and matching version management.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Superseded by the later TypeScript explicit receive helper pass; after that, prioritize managed hosted relay/account work, browser-native protocol support, or package publication.

## Post Phase 15 GitHub CI Package Validation

Status: completed

Summary:

- Added a dedicated GitHub Actions package-validation job that installs Node 20 and runs the TypeScript SDK package check plus the npm native launcher package check on every push and pull request.
- Kept Python wrapper compile coverage in the existing Rust OS matrix.
- Stabilized durable relay mailbox reload ordering by persisting a nanosecond enqueue sequence and using it when applying current mailbox caps, preserving FIFO behavior even when several envelopes share the same millisecond timestamp.
- Fixed relay sync wait handling so one-shot sync continues polling through the caller's bounded wait instead of returning on the first empty read timeout.
- Updated production-readiness docs, release checklist, repo memory, and implementation guardrails so package checks are part of the expected CI gate rather than only local release practice.

Files changed:

- `.github/workflows/ci.yml`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay --lib relay_file_backed_mailbox_load_respects_current_cap_without_payloads` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay --lib relay_delivers_peer_encrypted_message_between_two_state_homes` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `git diff --check` passed locally.

Known gaps:

- The CI package job validates syntax and package install logic only; it does not publish `@conu/sdk` or `@conu/cli`.
- GitHub Release asset publication, npm publication, signed installers, managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Open a PR for package CI validation and let GitHub prove the new job, then prioritize managed hosted relay/account work after the TypeScript receive-helper pass below.

## Post Phase 15 TypeScript Explicit Receive Helper

Status: completed

Summary:

- Added `mcpBin` support to the dependency-free TypeScript/JavaScript SDK wrapper so it can call installed `conu-mcp` for explicit MCP tool paths.
- Added `receiveMessage(agentId, envelopeId, { includePayload })` for addressed-agent receive metadata and `receiveMessageBytes(agentId, envelopeId)` for explicit raw inbox bytes.
- Kept normal inbox/list/send/status helpers metadata-only; payload bytes are returned only through the explicit receive helper and only after the MCP `conu_receive_message` path verifies the envelope belongs to the addressed local agent.
- Updated the TypeScript smoke test, local TypeScript example, public docs, security docs, release checklist, repo memory, and gateway contract to remove the previous TypeScript receive-helper gap.

Files changed:

- `sdk/typescript/src/index.js`
- `sdk/typescript/src/index.d.ts`
- `sdk/typescript/test/smoke.mjs`
- `sdk/typescript/README.md`
- `examples/typescript/local_agent_pair.mjs`
- `README.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.

Known gaps:

- TypeScript still wraps local installed binaries and `conu-mcp`; it is not a browser-native SDK, hosted API client, or direct protocol implementation.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay/account work, npm/release publication, browser-native protocol support, or non-Windows OS-backed key storage depending on the next release target.

## Post Phase 15 Release Publishing Workflow

Status: completed

Summary:

- Added `scripts/verify-release-artifacts.py` to validate release archives and checksum files before upload.
- The verifier checks required binaries, `manifest.toml`, `payload_contents_included = false`, matching SHA-256 files, and rejects common local-state or payload-bearing paths such as `.conu`, `security/`, `messages/`, `runtime/`, `logs/`, `routes/`, `node_modules/`, `target/`, and vendored npm binaries.
- Hardened `.github/workflows/release.yml` with a package-check job, npm dry-runs for `@conu/cli` and `@conu/sdk`, archive verification on every platform build, automatic GitHub Release asset upload for `v*` tags, and optional npm publication with provenance when `NPM_TOKEN` is configured.
- Updated distribution, packaging, release checklist, production readiness, repo memory, and security guardrails so release publication is no longer a manual-only path.

Files changed:

- `.github/workflows/release.yml`
- `scripts/verify-release-artifacts.py`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.
- `npm pack --dry-run --json` passed locally in `packaging/npm/conu-cli`.
- `python -m py_compile scripts/verify-release-artifacts.py` passed locally.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())"` passed locally.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed locally.
- `python scripts\verify-release-artifacts.py dist` passed locally against the generated Windows archive.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.

Known gaps:

- Platform code signing/notarization is not implemented; current release trust is CI-built archives, SHA-256 checksums, GitHub Release assets, and npm provenance when `NPM_TOKEN` is configured.
- npm publication still requires maintainers to configure the repository `NPM_TOKEN` secret before a tagged release that should publish packages.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Add platform code signing/notarization or prioritize managed hosted relay/account work depending on the next public release target.

## Post Phase 15 Non-Windows User-Managed Secret Wrapping

Status: completed

Summary:

- Added a non-Windows `user-managed-wrap-key-v1` secret backend selected by `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE`.
- The backend wraps local signing, exchange, storage, archived key, and stored relay credential secret fields with XChaCha20Poly1305 and per-secret AAD while keeping the wrap key external to conU-owned state.
- Security-state ensure now migrates older plaintext-hex key files and stored relay credential files to encrypted `*_wrapped_hex` fields when the wrap key is configured.
- `conu security audit` and relay credential status continue to report backend/protection metadata only; no key bytes, tokens, wrapped blobs, plaintext payloads, or decrypted payloads are printed.
- Updated security, production readiness, install, release, repo memory, and security guardrail docs to distinguish this encrypted fallback from native macOS Keychain/Linux Secret Service/HSM support.

Files changed:

- `crates/conu-core/src/security.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `docs/distribution-and-hosting.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::relay_credential_storage_hides_token_and_reports_backend` passed locally during implementation.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-core --all-targets -- -D warnings` passed locally during implementation.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py scripts\verify-release-artifacts.py` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- Isolated `CONU_HOME` smoke passed locally: `conu init` then `conu security audit --json` reported backend/protection metadata and `contentsDisplayed=false` without key bytes or token material.
- `git diff --check` passed locally.
- Default `cargo check --workspace --all-targets` was attempted and failed locally because the MSVC linker `link.exe` is not installed on this machine; the repo guardrails already require the GNU toolchain in this environment.

Known gaps:

- Native non-Windows OS keychain, Secure Enclave, HSM, or hosted key administration is not implemented; the new fallback requires operators to provide and protect the wrap key outside conU.
- Losing the external wrap key makes user-managed wrapped local secret files unreadable until restored from the operator's secret store.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and platform code signing remain future work.

Next recommendation:

- Add native macOS Keychain/Linux Secret Service or HSM-backed storage when choosing a platform-specific hardening track, or move to managed hosted relay/account work.

## Post Phase 15 Release Artifact Attestation Hardening

Status: completed

Summary:

- Added GitHub artifact attestation generation to the release build matrix for platform archives and matching `.sha256` files.
- Added a second verifier pass in the GitHub Release publication job after build artifacts are downloaded and before release upload.
- Strengthened `scripts/verify-release-artifacts.py` so every archive must include the required Windows, Linux, macOS, Docker, and npm packaging templates in addition to binaries, checksums, and `manifest.toml`.
- Updated release, distribution, packaging, production-readiness, repo memory, and guardrail docs with artifact attestation verification guidance and the stronger release trust boundary.

Files changed:

- `.github/workflows/release.yml`
- `scripts/verify-release-artifacts.py`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed locally.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())"` passed locally.
- Synthetic release verifier positive/negative cases passed locally, including rejection when a required packaging template was missing.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed locally.
- `python scripts\verify-release-artifacts.py dist` passed locally against the generated Windows release archive.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.
- `npm pack --dry-run --json` passed locally in `packaging/npm/conu-cli`.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.

Known gaps:

- Platform-native code signing and notarization are still not implemented; artifact attestations improve provenance but do not replace OS trust prompts or signed installers.
- npm publication still requires maintainers to configure the repository `NPM_TOKEN` secret before a tagged release that should publish packages.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and native non-Windows keychain support remain future work.

Next recommendation:

- Add platform code signing/notarization when release certificates are available, or prioritize managed hosted relay/account work for public network readiness.

## Post Phase 15 TypeScript Browser Boundary Hardening

Status: completed

Summary:

- Added a browser-conditioned `@conu/sdk` export that fails closed with `browserSupport.supported = false` and `BrowserUnsupportedError` instead of bundling the Node local-binary wrapper into browser apps.
- Added an explicit `@conu/sdk/browser` subpath for browser-boundary detection without accepting private keys, relay tokens, endpoint secrets, payload bytes, or account credentials.
- Updated the TypeScript package description, README, smoke test, and package check so the Node wrapper and browser boundary are validated together.
- Added `docs/browser-native-typescript.md` to document future browser-native protocol requirements around hosted auth, browser key handling, payload opacity, explicit receive semantics, and package naming.
- Updated SDK/MCP, install guide, production readiness, release checklist, repo memory, and security guardrails to distinguish the Node wrapper from future browser-native support.

Files changed:

- `sdk/typescript/package.json`
- `sdk/typescript/src/browser.js`
- `sdk/typescript/src/browser.d.ts`
- `sdk/typescript/test/smoke.mjs`
- `sdk/typescript/README.md`
- `docs/browser-native-typescript.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `docs/release-checklist.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py scripts\verify-release-artifacts.py` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.

Known gaps:

- This is a browser-boundary hardening pass, not browser-native protocol transport.
- Browser-native support still requires hosted account auth, short-lived scoped browser credentials, reviewed browser key handling, and `wss://` or direct transport semantics that preserve peer trust and policy checks.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, direct transport, hosted multi-tenant permission administration, native non-Windows keychain support, and platform code signing remain future work.

Next recommendation:

- Prioritize managed hosted relay/account auth before implementing a real browser-native TypeScript protocol package, or move to direct transport if relay independence is more urgent.

## Post Phase 15 Native Non-Windows Secret Storage

Status: completed

Summary:

- Added native macOS user Keychain support for the shared conU secret-field backend through the target-gated `keyring` crate.
- Added Linux Secret Service support through `secret-tool` when a user Secret Service session is available.
- Kept Windows on current-user DPAPI and kept the non-Windows user-managed XChaCha20Poly1305 wrap-key fallback for systems without native secret storage.
- Added native OS-secret reference fields that store only references and plaintext lengths in conU files; key bytes, relay tokens, protected blobs, plaintext payloads, and decrypted payloads stay out of files and CLI output.
- Added migration coverage for plaintext local signing, exchange, storage, and relay credential files into native OS-secret references with an in-memory native-store test backend for macOS/Linux CI.
- Added `docs/native-secret-storage.md` with backend selection, migration rules, and macOS/Linux smoke commands.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-core/Cargo.toml`
- `Cargo.lock`
- `docs/native-secret-storage.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `docs/distribution-and-hosting.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py scripts\verify-release-artifacts.py` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-core --target x86_64-apple-darwin --tests` passed locally, validating the target-gated macOS Keychain/keyring compile path.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-core --target x86_64-unknown-linux-gnu --tests` was attempted locally but blocked by the existing OpenSSL cross-compilation sysroot/pkg-config requirement on Windows; the GitHub Ubuntu job should validate this path natively.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.

Known gaps:

- Linux native Secret Service requires `secret-tool` and a user Secret Service session. Headless systems without that service use the user-managed wrap-key fallback or owner-only file fallback.
- Existing `user-managed-wrap-key-v1` files can migrate to native macOS/Linux storage only when the operator still provides the wrap key needed to decrypt the existing wrapped field.
- Secure Enclave, HSM, hosted managed key administration, managed hosted account auth, online credential issuance APIs, distributed hosted state/accounting, direct transport, hosted multi-tenant permission administration, and platform package-manager signing remain future work.

Next recommendation:

- Prioritize managed hosted relay/account auth and online credential issuance before public hosted relay claims, or move to direct transport if relay independence is more urgent.

## Post Phase 15 Platform Signing And Notarization

Status: completed

Summary:

- Added tagged-release signing gates for Windows Authenticode and macOS Developer ID signing/notarization while preserving unsigned manual `workflow_dispatch` and local smoke builds when signing secrets are absent.
- Added Windows release-script support for decoding a maintainer PFX from repository secrets, signing each `.exe` with SHA-256 Authenticode and timestamping, verifying signatures, then generating the release ZIP/checksum.
- Added macOS release-script support for Developer ID signing with hardened runtime/timestamps, notarizing ZIP distribution archives through `notarytool`, and switching macOS npm release assets from `.tar.gz` to `.zip`.
- Kept Linux release policy explicit: SHA-256 checksum files plus GitHub artifact attestations until detached/distro package signatures are introduced.
- Updated npm asset resolution, release verifier ZIP handling, release workflow secret wiring, release notes, release checklist, distribution docs, repo memory, and security guardrails without adding any payload or local-state inspection.

Files changed:

- `.github/workflows/release.yml`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `scripts/verify-release-artifacts.py`
- `packaging/npm/conu-cli/lib/platform.js`
- `docs/platform-code-signing.md`
- `docs/release-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed locally.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())"` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed locally and produced an unsigned manual platform ZIP/checksum with the expected manifest signing booleans.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed locally and produced an unsigned manual host ZIP/checksum.
- `python scripts\verify-release-artifacts.py dist` passed locally against both generated Windows archives.
- `node -e "Object.defineProperty(process, 'platform', { value: 'darwin' }); Object.defineProperty(process, 'arch', { value: 'arm64' }); const p = require('./packaging/npm/conu-cli/lib/platform'); if (p.assetName('0.1.0') !== 'conu-0.1.0-macos-arm64.zip') { throw new Error(p.assetName('0.1.0')); } console.log(p.assetName('0.1.0'));"` passed locally.
- `bash -n scripts/build-release.sh` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.
- `npm pack --dry-run --json` passed locally in `packaging/npm/conu-cli`.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.

Known gaps:

- Actual release signing still requires maintainers to configure the repository signing secrets before creating a `v*` tag.
- Linux detached signatures and distro/package-manager signatures are documented as the next packaging layer, not implemented in this pass.
- One-click OS installers, package-manager publishing, auto-update, managed hosted account auth, online credential issuance APIs, distributed hosted state/accounting, direct transport, hosted multi-tenant permission administration, and hosted managed key administration remain future work.

Next recommendation:

- Configure the Windows and macOS signing secrets before the next tagged release, then prioritize managed hosted relay account auth or authenticated direct QUIC/NAT transport.

## Post Phase 15 Authenticated Direct QUIC/NAT Transport

Status: completed

Completed work:

- Added authenticated direct QUIC listener/client support for reachable trusted peer endpoints.
- Added peer-encrypted direct probe, message, and stream-chunk frames that authenticate with existing trusted peer-card exchange keys.
- Updated route sync so direct is selected only after a live authenticated QUIC probe succeeds; failed probes record `direct_quic_probe_failed` and keep relay selected.
- Preserved relay fallback for direct message and stream-chunk send failures without weakening local capability or peer policy checks.
- Added signed peer-card direct endpoint support and legacy signed-card compatibility when no direct endpoint is claimed.
- Exposed direct endpoint fields through CLI identity/trust/peer output, MCP, Python SDK, and TypeScript SDK wrapper options.
- Updated direct transport, route, production readiness, SDK/MCP, user guide, release checklist, README, repo memory, and guardrail docs.

Files changed:

- `Cargo.lock`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/direct_transport.rs`
- `crates/conu-core/src/routes.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-core/src/trust.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `sdk/python/conu_sdk/__init__.py`
- `sdk/typescript/src/index.js`
- `sdk/typescript/src/index.d.ts`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/hosted-relay-account-auth.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all` and `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli` passed locally after the final CLI fallback cleanup.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `git diff --check` passed locally.

Known gaps:

- Direct QUIC requires a reachable configured UDP endpoint. ICE-style candidate gathering, STUN/TURN, UDP hole punching, and hosted direct-candidate rendezvous remain future work.
- The local Windows GNU validation path needs `w64devkit` on `PATH` and `rust-lld` as the linker because Quinn/ring native build scripts require a C compiler.
- Direct stream chunks are point-in-time encrypted envelopes, not long-lived application stream sessions with end-to-end flow negotiation yet.

Next recommendation:

- Run full workspace validation and CI, then continue with distributed hosted session/accounting state, hosted dashboards/abuse workflows, hosted tenant administration, or managed direct NAT traversal.

## Post Phase 15 Distributed Relay State/Accounting Foundation

Status: completed

Completed work:

- Added `RelaySessionStorage` with memory-only and file-backed modes.
- Added `CONU_RELAY_SESSION_STATE_DIR` for metadata-only per-node session records across relay restarts.
- Kept cross-node resume attempts on the new-session path and preserved relay accounting files without session ids.
- Updated relay hosting, production readiness, internet test, package, Docker, repo memory, and guardrail docs to distinguish single-writer file-backed state from hosted distributed migration/dashboards.
- Added restart coverage proving file-backed session state can resume the same node without storing tokens, token hashes, payload text, ciphertext bodies, or private keys.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `architecture.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/hosted-relay-account-auth.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_session_state_survives_restart_without_payloads` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_resumes_same_node_session_and_accounts_metadata_only` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.
- `git diff --check` passed locally.

Known gaps:

- File-backed relay session state is a single-writer storage boundary, not a distributed lock service or multi-region migration layer.
- Hosted dashboards, abuse response, tenant lifecycle, managed permission administration, and managed direct NAT traversal remain future work.
- Default Windows MSVC validation still requires `link.exe`; local Windows validation uses the GNU toolchain path.

Next recommendation:

- Run full workspace validation and CI, then merge this branch for issue #64 before starting managed direct NAT traversal or hosted tenant administration.

## Post Phase 15 Managed Direct NAT Rendezvous Foundation

Status: completed

Completed work:

- Added static direct candidate metadata to route records and probes: `candidate_source`, `candidate_kind`, and `rendezvous_state`.
- Added `nat_traversal_unavailable` reporting so route sync distinguishes reachable configured endpoints, failed static probes, missing traversal support, relay-only profiles, and relay fallback.
- Kept direct selection gated on live authenticated QUIC probes and preserved relay fallback for failed, missing, invalid, or disabled direct routes.
- Sanitized invalid direct endpoints as `quic://invalid` and derived route ids from sanitized display endpoints instead of rejected endpoint strings.
- Exposed candidate metadata and NAT-unavailable counts through CLI route JSON/text output and MCP route tools.
- Updated direct transport, production readiness, user guide, SDK/MCP, release checklist, repo memory, and future-agent guardrails to describe the supported static candidate boundary and unsupported ICE/STUN/TURN behavior.

Files changed:

- `crates/conu-core/src/routes.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all` and `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core routes::tests` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli routes_sync` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.

Known gaps:

- This is static host-candidate metadata and honest NAT-unavailable reporting, not ICE-style candidate gathering, STUN/TURN negotiation, UDP hole punching, or hosted direct-candidate rendezvous.
- Direct QUIC still requires a reachable configured UDP endpoint and a trusted peer-card key for the authenticated probe.
- Distributed hosted dashboards/accounting, hosted tenant administration, distributed multi-instance session migration, and managed hosted identity/key administration remain future work.

Next recommendation:

- Open the PR for issue #65, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 Hosted Tenant Admin Foundation

Status: completed

Completed work:

- Added a metadata-only hosted tenant registry file for `conu-relay` with tenant account status, hosted node status, hosted permission booleans, optional public signing/exchange key ids, timestamps, and display guards.
- Added `conu-relay --tenant-upsert`, `--tenant-revoke`, `--tenant-node-upsert`, `--tenant-node-revoke`, and `--tenant-audit` for single-writer tenant lifecycle administration without raw tokens, token hashes, private keys, payloads, ciphertext bodies, or manifest contents in output.
- Added optional `CONU_RELAY_TENANTS_FILE` relay configuration. When configured with `CONU_RELAY_ADMIN_TOKEN` and `CONU_RELAY_CREDENTIALS_FILE`, online issue/rotate and new runtime `HELLO` sessions fail closed when tenant or node metadata is missing or revoked.
- Kept hosted tenant permissions as operator-side metadata only. Local conUD peer policy, agent capabilities, room topic policy, trust, and peer encryption remain the delivery authority.
- Kept admin credential revoke available after tenant/node revocation so operators can clean up credential metadata.
- Updated hosted relay docs, hosting docs, production readiness, release checklist, user guide, SDK/MCP notes, repo memory, and future-agent guardrails for the tenant registry boundary.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay tenant_ -- --nocapture` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.
- `git diff --check` passed locally.
- Tenant CLI smoke passed locally for `--tenant-upsert`, `--tenant-node-upsert`, and `--tenant-audit`, with JSON output reporting `tokenDisplayed=false`, `keyMaterialDisplayed=false`, `payloadDisplayed=false`, and `contentsDisplayed=false`.

Known gaps:

- The hosted tenant registry is a single-writer file-backed foundation, not a distributed tenant lifecycle, dashboard, RBAC, billing, or abuse workflow service.
- Hosted key administration stores only public key ids; no hosted private-key custody, HSM, Secure Enclave, or managed key rotation service exists.
- Existing authenticated sessions are still bounded by relay idle timeout and max TTL; tenant revocation gates new `HELLO` sessions and admin issue/rotate.
- Distributed hosted dashboards/accounting, hosted mailbox retention workflows, distributed multi-instance migration, ICE/STUN/TURN managed traversal, and full hosted identity/key administration remain future work.

Next recommendation:

- Open the PR for issue #66, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 - Hosted Relay Dashboard Snapshot

Status: completed

Goal:

Give hosted or self-hosted relay operators a single payload-safe snapshot command that summarizes credential, tenant, accounting, and abuse stores without exposing relay secrets, payload material, ciphertext bodies, or session ids.

Completed work:

- Created GitHub issue #72 for the dashboard snapshot slice.
- Added public `RelayAccountingAudit` and `audit_relay_accounting_dir` support so relay accounting files can be summarized without exposing tokens, token hashes, session ids, payloads, ciphertext bodies, or private key material.
- Added `conu-relay --hosted-dashboard` with optional `--credentials-file`, `--tenants-file`, `--accounting-dir`, `--abuse-dir`, `--account`, `--node`, and `--json` flags.
- Kept dashboard output aggregate-only: credential counts, tenant/node counts, accounting counters, abuse counters, configured paths, optional filters, and false display guards.
- Added renderer/parser privacy coverage and accounting audit coverage.
- Updated hosted relay docs, distribution/hosting docs, production readiness, release checklist, user guide, SDK/MCP notes, packaging docs, repo memory, architecture notes, and future-agent guardrails.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `architecture.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_dashboard -- --nocapture` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay accounting_audit -- --nocapture` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU environment.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --hosted-dashboard --credentials-file <temp>\credentials.toml --tenants-file <temp>\tenants.toml --accounting-dir <temp>\accounting --abuse-dir <temp>\abuse --account account.prod --node node.hosted --json` passed and returned `tokenDisplayed=false`, `tokenHashDisplayed=false`, `sessionIdDisplayed=false`, `ciphertextDisplayed=false`, and `contentsDisplayed=false`.
- `git diff --check` passed.

Known gaps:

- The hosted dashboard snapshot is single-relay and file-backed. It is not distributed dashboard storage, a hosted UI, RBAC, alert routing, tenant suspension, billing, or adaptive abuse response.
- Accounting, abuse, tenant, and credential stores are still single-writer local files; distributed hosted accounting, tenant lifecycle, and multi-instance session migration remain future work.
- Hosted key administration still stores only public key ids; no hosted private-key custody, HSM, Secure Enclave, or managed key rotation service exists.
- Managed direct NAT traversal still needs ICE/STUN/TURN-style candidate gathering, hosted direct-candidate rendezvous, and UDP hole punching beyond the current static direct candidate metadata.

Next recommendation:

- Open the PR for issue #72, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 - Hosted Abuse Threshold Report

Status: completed

Goal:

Give hosted/self-hosted relay operators a payload-safe threshold report that compares relay abuse counters against explicit operator maximums without adding adaptive enforcement or distributed alerting.

Completed work:

- Created GitHub issue #92 for the hosted abuse threshold report slice.
- Added local `conu-relay --abuse-threshold-report --abuse-dir <path> [--node <node-id>] --max-<metric> <count>... [--json]` for `CONU_RELAY_ABUSE_DIR` counters.
- Added admin-gated `conu-relay --admin-abuse-threshold-report --relay <endpoint> --admin-token-stdin [--account <account-id>] [--node <node-id>] --max-<metric> <count>... [--json]`, reusing the existing dashboard admin request and dashboard scope.
- Supported threshold maximums for admin unauthorized, admin failed, unauthorized sessions, credential denied sessions, tenant denied sessions, rate limited sessions, session expired, quota denied forwards, undelivered forwards, mailbox rejected forwards, and malformed client frames.
- Rendered text/JSON reports with `ok` or `threshold_exceeded` status, checked/exceeded counts, count/max/exceeded metadata per metric, source/relay/path/filter metadata, and false display guards.
- Added parser, threshold, and renderer privacy tests for local and admin report forms.
- Updated hosted relay docs, distribution/hosting docs, production readiness, release checklist, SDK/MCP notes, user guide, packaging docs, repo memory, and future-agent guardrails.

Files changed:

- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay abuse_threshold -- --nocapture` passed with the same GNU environment.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help | Select-String -Pattern 'abuse-threshold|admin-abuse-threshold|threshold-report'` passed.
- `target\debug\conu-relay.exe --abuse-threshold-report --abuse-dir <temp> --max-admin-unauthorized 0 --json` passed and returned `status="ok"`, `thresholdChecks=1`, `thresholdExceeded=0`, and false display guards.

Known gaps:

- The threshold reports are single-relay reporting workflows over existing metadata counters. They do not implement distributed hosted dashboards, alert routing, adaptive enforcement, tenant-wide workflow automation, or billing.
- Admin threshold reports require dashboard admin scope and inherit the current account-scoped dashboard behavior where global accounting and abuse counters are suppressed without a node filter.
- Abuse, accounting, tenant, and credential stores are still single-writer relay-local storage.

Next recommendation:

- Open the PR for issue #92, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 - Abuse Threshold Fail-On-Threshold Mode

Status: completed

Goal:

Make local and admin-gated hosted abuse threshold reports scriptable for CI, cron, and operator monitoring without adding adaptive enforcement or distributed alerting.

Completed work:

- Created GitHub issue #94 for the fail-on-threshold report slice.
- Added optional `--fail-on-threshold` to `conu-relay --abuse-threshold-report`.
- Added optional `--fail-on-threshold` to `conu-relay --admin-abuse-threshold-report`.
- Preserved normal stdout report rendering and default success exit behavior.
- Added exit code 3 only when `--fail-on-threshold` is set and one or more configured thresholds are exceeded.
- Kept admin threshold reports behind `--admin-token-stdin` and the existing dashboard admin scope.
- Added parser and report-exit tests for local and admin threshold forms.
- Updated hosted relay docs, distribution/hosting docs, production readiness, release checklist, user guide, SDK/MCP notes, packaging docs, repo memory, and future-agent security/build guardrails.

Files changed:

- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay abuse_threshold -- --nocapture` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU environment.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed with the same GNU environment.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--fail-on-threshold` is documented.
- Local threshold CLI smoke passed against a temporary `.abuse` file: `--fail-on-threshold` returned exit code 3 with `status=threshold_exceeded`, and the same report without the flag returned exit code 0 while preserving `status=threshold_exceeded`.

Known gaps:

- The fail-on-threshold flag is a local process exit mode only. It is not distributed alerting, adaptive abuse response, tenant-wide workflow automation, or hosted dashboard storage.
- Abuse, accounting, tenant, credential, mailbox, and dashboard stores are still single-relay storage boundaries.
- Admin threshold reports still inherit dashboard scope and the existing account-scoped dashboard behavior where global accounting and abuse counters are suppressed without a node filter.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Abuse Threshold Policy Files (Completed)

Objective: let self-hosted and managed relay operators reuse payload-safe threshold limits across local/admin abuse threshold reports without adding adaptive enforcement, alerting, distributed dashboards, or tenant-wide workflow automation.

Current status:

- Created GitHub issue #96 for reusable abuse threshold policy files.
- Created branch `codex/abuse-threshold-policy-file` from `main`.
- Added `--thresholds-file <path>` to local `conu-relay --abuse-threshold-report`.
- Added `--thresholds-file <path>` to admin-gated `conu-relay --admin-abuse-threshold-report`.
- Added metadata-only policy parsing with `version = "1"`, supported `max_*` threshold keys, and required false display guards for payload, token, token hash, key material, session id, ciphertext, and contents.
- Kept CLI `--max-*` values as one-run overrides over policy-file defaults.
- Kept the existing requirement that at least one threshold must be supplied by file or CLI.
- Added parser and CLI override tests for local/admin threshold reports.
- Updated docs, package notes, repo memory, release checklist, and security guardrails.
- Merged PR #97 and closed issue #96.
- Preserved local and remote branch `codex/abuse-threshold-policy-file`.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay abuse_threshold -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--thresholds-file` is documented.
- Local policy-file threshold smoke passed against a temporary `.abuse` directory: without `--fail-on-threshold` it returned exit code 0 with `status=threshold_exceeded`, and with `--fail-on-threshold` it returned exit code 3 while preserving stdout.

Known gaps:

- Threshold policy files are local/admin single-relay reporting inputs only. They are not distributed alerting, adaptive enforcement, tenant-wide workflow automation, hosted dashboard storage, or managed policy distribution.

## Post Phase 15 Mailbox Retention Policy Files (Completed)

Objective: let self-hosted and managed relay operators reuse payload-safe mailbox retention TTL/node settings across local and admin audit/purge commands without adding distributed retention orchestration, hosted policy distribution, billing, or adaptive automation.

Current status:

- Created GitHub issue #99 for reusable mailbox retention policy files.
- Created branch `codex/mailbox-retention-policy-file` from `main`.
- Added `--retention-policy-file <path>` to local `conu-relay --mailbox-audit`.
- Added `--retention-policy-file <path>` to local `conu-relay --mailbox-purge`.
- Added `--retention-policy-file <path>` to admin-gated `conu-relay --admin-mailbox-audit`.
- Added `--retention-policy-file <path>` to admin-gated `conu-relay --admin-mailbox-purge`.
- Added metadata-only policy parsing with `version = "1"`, optional `ttl_seconds`, optional `node_id`, and required false display guards for payload, token, token hash, key material, session id, ciphertext, and contents.
- Kept CLI `--ttl-seconds` and `--node` values as one-run overrides over policy-file defaults.
- Kept purge safety behavior: purge commands still require a retention TTL from file or CLI and exactly one of `--dry-run` or `--confirm`.
- Added parser and CLI override tests for local/admin mailbox audit and purge commands.
- Updated docs, package notes, repo memory, release checklist, and security guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all` passed during implementation.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay mailbox -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--retention-policy-file` is documented.
- Local mailbox policy-file smoke passed against a temporary mailbox directory: `--mailbox-audit` and `--mailbox-purge --dry-run` loaded `ttl_seconds` and `node_id` from the policy file, returned JSON metadata, and kept every display guard false.

Known gaps:

- Retention policy files are local/admin single-relay command inputs only. They are not distributed policy distribution, tenant-wide retention orchestration, hosted workflow automation, billing, or adaptive cleanup.

Next recommendation:

- Open and merge a PR for issue #99 while preserving the local and remote feature branch. Then continue with distributed hosted mailbox retention orchestration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Relay Session-State Audit (Completed)

Objective: let self-hosted and managed relay operators inspect metadata-only same-node relay session resume records locally or through the running relay admin control plane without adding distributed session migration, distributed locking, hosted analytics, or a new tenant-wide workflow service.

Current status:

- Created GitHub issue #101 for payload-safe relay session-state audit.
- Created branch `codex/session-state-audit` from `main`.
- Added local `conu-relay --session-audit --session-state-dir <path> [--node <node-id>] [--json]`.
- Added admin-gated `conu-relay --admin-session-audit --relay <endpoint> --admin-token-stdin [--node <node-id>] [--json]`.
- Added relay admin `session_audit` frames and `RelayAdminResult` session-state counters/timestamp bounds.
- Added `scope_sessions = true` to hashed hosted admin-token manifests while preserving full-admin compatibility.
- Kept account-scoped session audit constrained to an explicit node filter plus an active tenant-node record.
- Reports record counts, active/expired/invalid counts, oldest created timestamp, newest last-seen timestamp, next active expiry timestamp, and false display guards only.
- Does not print relay session ids, raw node tokens, token hashes, admin tokens, payloads, ciphertext bodies, private keys, arbitrary frame contents, or session-state file contents.
- Updated README, hosted relay docs, distribution/user guides, release checklist, packaging docs, repo memory, and security/build guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core admin_frames_round_trip_with_debug_redaction -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay session -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--session-audit` and `--admin-session-audit` are documented.
- Local `conu-relay --session-audit --session-state-dir <temp> --node node.smoke --json` smoke passed against a temporary valid `.session` file and confirmed no relay session id was rendered.
- `git diff --check` passed.

Known gaps:

- The session-state audit is a single-relay metadata view over file-backed same-node resume records. It is not distributed multi-instance session migration, a distributed lock service, hosted analytics, billing, or tenant-wide workflow automation.
- Admin session audit returns `session_state_unavailable` when the running relay is configured for memory-only session state.

Next recommendation:

- Continue with distributed multi-instance session migration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Admin-Token Manifest Audit (Completed)

Objective: let self-hosted and managed relay operators inspect scoped hosted admin-token manifest boundaries locally without exposing raw admin tokens, token hashes, manifest contents, payloads, key material, session ids, ciphertext bodies, or frame contents.

Current status:

- Created GitHub issue #103 for payload-safe hosted admin-token manifest audit.
- Created branch `codex/admin-token-audit` from `main`.
- Added local `conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <account-id>] [--json]`.
- Added `HostedAdminTokenAudit` and `audit_hosted_admin_tokens_file` for record counts, active/revoked/expired totals, account-scoped/global records, unique account counts, expiring-record counts, expiry bounds, and per-scope counts.
- Kept the command local and metadata-only; it does not print raw admin tokens, token hashes, private keys, relay session ids, payloads, ciphertext bodies, arbitrary frame contents, or manifest contents.
- Kept `--bind-addr` parsing to host:port-style characters so invalid secret-bearing values fail without echoing the submitted string.
- Extended scoped admin-token manifest display guards to accept and require false `key_material_displayed`, `session_id_displayed`, and `ciphertext_displayed` keys when present, in addition to the existing payload/token/token-hash/content guards.
- Updated README, architecture, hosted relay docs, production readiness docs, release checklist, package notes, repo memory, and security/build guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all` passed during implementation.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay admin_token -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--admin-token-audit` is documented.
- Local `conu-relay --admin-token-audit --admin-tokens-file <temp> --bind-addr 0.0.0.0:8787 --account account.prod --json` smoke passed and confirmed neither the raw admin token nor token hash was rendered.
- `git diff --check` passed.

Known gaps:

- The admin-token manifest audit is a local single-relay operator check. It is not distributed RBAC administration, hosted identity/key management, tenant-wide workflow automation, adaptive abuse response, billing, or a managed hosted control plane.

Next recommendation:

- Open and merge a PR for issue #103 while preserving the local and remote feature branch. Then continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Relay Readiness Preflight (Completed)

Objective: give self-hosted and managed relay operators one payload-safe local preflight before startup or release smoke that combines configured credential, scoped admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks without exposing secrets or payload material.

Current status:

- Created GitHub issue #105 for payload-safe hosted relay readiness preflight.
- Created branch `codex/hosted-relay-readiness` from `main`.
- Added `conu-relay --hosted-readiness [--bind-addr <addr>] [--credentials-file <path>] [--tenants-file <path>] [--admin-tokens-file <path>] [--session-state-dir <path>] [--mailbox-dir <path>] [--ttl-seconds <seconds>] [--accounting-dir <path>] [--abuse-dir <path>] [--account <account-id>] [--node <node-id>] [--json] [--fail-on-warning]`.
- Reused existing local audit boundaries for hosted credentials, hosted tenants, hosted admin-token manifests, relay session state, durable mailbox retention, relay accounting, and relay abuse counters.
- Kept output metadata-only: configured paths, configured-source booleans, aggregate counts, warning count, bind metadata, optional account/node filters, and false display guards only.
- Added exit code 3 for `--fail-on-warning` after preserving stdout when warnings exist.
- Updated README, architecture, hosted relay docs, production readiness docs, distribution/hosting docs, release checklist, package notes, SDK/user guides, repo memory, and security/build guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU linker path.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU linker path.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay --bin conu-relay hosted_readiness_parser_and_renderers_are_metadata_only -- --nocapture` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed with the GNU linker path.
- Local `target\debug\conu-relay.exe --hosted-readiness ... --json` smoke passed against temporary credential, tenant, session, mailbox, accounting, and abuse paths.
- Local `target\debug\conu-relay.exe --hosted-readiness ... --json --fail-on-warning` smoke preserved stdout and returned exit code 3 when admin-token readiness warnings existed.
- `git diff --check` passed.

Known gaps:

- Hosted readiness is a local single-relay preflight over configured files/directories. It is not distributed hosted monitoring, adaptive abuse response, tenant-wide workflow automation, distributed mailbox retention orchestration, distributed session migration, billing, or a managed hosted control plane.

Next recommendation:

- Open and merge a PR for issue #105 while preserving the local and remote feature branch. Then continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 GitHub Actions Node 24 Runtime Hardening (Completed)

Objective: remove GitHub Actions Node 20 action-runtime deprecation warnings from CI and release workflows before GitHub-hosted runners force JavaScript actions to Node 24.

Current status:

- Created GitHub issue #107 for GitHub Actions Node 24 runtime hardening.
- Created branch `codex/actions-node24-runtime` from `main`.
- Merged PR #108 and preserved the local and remote feature branch.
- Confirmed `actions/checkout` latest release `v6.0.2` declares `using: node24` in `action.yml`.
- Confirmed `actions/setup-node` latest release `v6.4.0` declares `using: node24` in `action.yml`.
- Updated `.github/workflows/ci.yml` from `actions/checkout@v4` and `actions/setup-node@v4` to v6.
- Updated `.github/workflows/release.yml` from `actions/checkout@v4` and `actions/setup-node@v4` to v6.
- Updated the release checklist to keep CI/release action runtimes on Node 24-compatible versions.

Validation:

- `gh api repos/actions/checkout/releases/latest --jq '.tag_name'` returned `v6.0.2`.
- `gh api repos/actions/setup-node/releases/latest --jq '.tag_name'` returned `v6.4.0`.
- `gh api repos/actions/checkout/contents/action.yml?ref=v6.0.2 --jq '.content'` decoded to an action with `using: node24`.
- `gh api repos/actions/setup-node/contents/action.yml?ref=v6.4.0 --jq '.content'` decoded to an action with `using: 'node24'`.
- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- `rg -n "actions/(checkout|setup-node)@v4|actions/(checkout|setup-node)@v5" .github/workflows` returned no matches.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `git diff --check` passed.

Known gaps:

- This update only hardens JavaScript action runtime compatibility. It does not change the package test Node version matrix, release signing secrets, or hosted/distributed product gaps.

Next recommendation:

- Continue with release workflow hardening, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Release Artifact Action Runtime Hardening (Completed)

Objective: keep release artifact upload/download/provenance steps on GitHub JavaScript action versions that declare the Node 24 action runtime and preserve release artifact integrity checks.

Current status:

- Created GitHub issue #109 for release artifact action runtime hardening.
- Created branch `codex/release-actions-node24` from `main`.
- Confirmed `actions/upload-artifact` latest release `v7.0.1` declares `using: 'node24'` in `action.yml`.
- Confirmed `actions/download-artifact` latest release `v8.0.1` declares `using: 'node24'` in `action.yml`.
- Confirmed `actions/attest` latest release `v4.1.0` declares `using: node24` in `action.yml`.
- Updated `.github/workflows/release.yml` artifact provenance/upload/download steps to `actions/attest@v4.1.0`, `actions/upload-artifact@v7.0.1`, and `actions/download-artifact@v8.0.1`.
- Updated the release checklist with the self-hosted runner caveat for Node 24-runtime GitHub actions.

Validation:

- `gh api repos/actions/upload-artifact/releases/latest --jq '.tag_name'` returned `v7.0.1`.
- `gh api repos/actions/download-artifact/releases/latest --jq '.tag_name'` returned `v8.0.1`.
- `gh api repos/actions/attest/releases/latest --jq '.tag_name'` returned `v4.1.0`.
- Decoded upstream `action.yml` files for all three action versions declare Node 24 runtimes.
- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- `rg -n "actions/(upload-artifact|download-artifact)@v4|actions/attest@v4$" .github/workflows` returned no matches.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `git diff --check` passed.

Known gaps:

- This update hardens release action runtime compatibility only. It does not configure signing secrets, publish a release tag, or change the known hosted/distributed product gaps.

Next recommendation:

- Issue #109 was closed by PR #110, and `codex/release-actions-node24` remains preserved locally and on origin. Continue with release workflow smoke validation, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Release Workflow Smoke Validation (Completed)

Objective: prove the Node 24 release action updates by running the multi-platform release workflow on `main` without publishing a GitHub Release or npm packages.

Current status:

- Created GitHub issue #111 for release workflow smoke validation.
- Created branch `codex/release-workflow-smoke-record` from `main`.
- Ran `gh workflow run release.yml --ref main`, which created workflow run `https://github.com/imthegoodboy/conU/actions/runs/26264867145`.
- The `Release Artifacts` workflow completed successfully on `main` for the package checks plus `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` build jobs.
- The non-tag `workflow_dispatch` run skipped `Publish GitHub Release` and `Publish npm Packages` as expected, so no release or npm package was published.
- Uploaded artifacts were present for `conu-windows-x64`, `conu-linux-x64`, `conu-linux-arm64`, `conu-macos-arm64`, and `conu-macos-x64`.
- Updated the release checklist so future CI or release action-version changes require a `workflow_dispatch` smoke run before tagging.

Validation:

- Post-merge CI run `https://github.com/imthegoodboy/conU/actions/runs/26264717227` completed successfully on `main` after PR #110.
- `gh run view 26264867145 --json status,conclusion,url,workflowName,displayTitle,headBranch,event,createdAt,updatedAt` reported `status=completed` and `conclusion=success`.
- `gh api repos/imthegoodboy/conU/actions/runs/26264867145/artifacts` showed all five platform artifacts present and not expired.
- Release workflow jobs passed for package checks, `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64`; release and npm publication jobs were skipped on the non-tag run.

Known gaps:

- This smoke validates manual multi-platform artifact builds, checksums, artifact attestations, and uploads after the Node 24 action updates. A real tagged release still needs configured Windows/macOS signing secrets, GitHub Release publication, npm provenance publication, and final tag-run verification. It does not change the known hosted/distributed product gaps.

Next recommendation:

- Issue #111 was closed by PR #112, and `codex/release-workflow-smoke-record` remains preserved locally and on origin. Continue with GitHub Actions runner-image migration hardening, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 GitHub Actions Runner Image Pinning (Completed)

Objective: remove GitHub-hosted runner image migration warnings and make CI/release platform labels explicit before the June 2026 Windows/macOS hosted-runner migrations.

Current status:

- Created GitHub issue #113 for runner-image pinning.
- Created branch `codex/pin-actions-runner-images` from `main`.
- Observed post-merge CI run `https://github.com/imthegoodboy/conU/actions/runs/26265143809` reporting the GitHub notice that `windows-latest` requests are being redirected to `windows-2025-vs2026` by June 15, 2026.
- Verified the May 14, 2026 GitHub Actions changelog: `windows-latest`/`windows-2025` migrate to Visual Studio 2026 by June 15, 2026, and `macos-latest` begins migrating to macOS 26 on June 15, 2026.
- Verified the `actions/runner-images` label table includes `windows-2025-vs2026`, `macos-15`, and `macos-15-intel`.
- Updated `.github/workflows/ci.yml` to run Rust CI on `ubuntu-latest`, `windows-2025-vs2026`, and `macos-15`.
- Updated `.github/workflows/release.yml` so `windows-x64` uses `windows-2025-vs2026` and `macos-arm64` uses `macos-15`; `macos-x64` already used `macos-15-intel`.
- Updated the release checklist with the explicit runner labels and the reminder to revisit the Windows label after the June 2026 migration completes.
- User preference captured for future work: create new branches without the `codex/` prefix. Existing preserved `codex/*` branches are not deleted.

Validation:

- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- `rg -n "windows-latest|macos-latest" .github/workflows` returned no matches.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `git diff --check` passed.
- PR #114 CI passed: Packages, CodeRabbit, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run `https://github.com/imthegoodboy/conU/actions/runs/26265326440` completed successfully.
- The branch release smoke passed package checks plus `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` builds; `Publish GitHub Release` and `Publish npm Packages` skipped on the non-tag branch run.

Known gaps:

- This runner-image update does not configure release signing secrets, publish a release tag, publish npm packages, or change the known hosted/distributed product gaps.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Node LTS Package Hardening (Completed)

Objective: keep npm package checks, publication jobs, and package engine metadata on currently supported Node.js LTS lines.

Current status:

- Created GitHub issue #115 for Node LTS package hardening.
- Created branch `node-lts-package-hardening` from `main` without a `codex/` prefix, per user preference.
- Verified the official Node.js release table on 2026-05-22: Node 24 and Node 22 are LTS; Node 20, Node 18, and Node 16 are EOL.
- Updated CI and release package jobs to use Node 24.
- Updated `@conu/sdk` and `@conu/cli` package `engines` to accept Node 22 LTS or Node 24 LTS and reject EOL Node lines.
- Updated npm package docs, SDK/MCP docs, and the release checklist with the supported Node LTS requirement.
- Opened and merged PR #116 to close issue #115.

Validation:

- `node --version` reported `v24.14.1`.
- `npm --version` reported `11.11.0`.
- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- Stale reference scan passed for `node-version: 20`, old package engine ranges, `Node 18+`, and `Node 20` in current workflow/package docs.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm pack --dry-run --json` passed for `sdk/typescript`.
- `npm pack --dry-run --json` passed for `packaging/npm/conu-cli`.
- `git diff --check` passed.
- PR #116 CI run `https://github.com/imthegoodboy/conU/actions/runs/26266048350` completed successfully: Packages, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run `https://github.com/imthegoodboy/conU/actions/runs/26266054245` completed successfully.
- The branch release smoke passed package checks plus `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` builds with artifact attestations/uploads; `Publish GitHub Release` and `Publish npm Packages` skipped on the non-tag branch run.
- PR #116 was merged into `main` on 2026-05-22, issue #115 was closed, local and remote `node-lts-package-hardening` branches were preserved, and post-merge CI run `https://github.com/imthegoodboy/conU/actions/runs/26266342419` completed successfully.

Known gaps:

- This package-runtime update does not configure release signing secrets, publish a release tag, publish npm packages, or change the known hosted/distributed product gaps.

Next recommendation:

- Revisit the Node engine range when the next Node LTS line is promoted, and continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Hosted Readiness Policy Files (Completed)

Objective: make `conu-relay --hosted-readiness` reuse the same metadata-only mailbox retention and abuse threshold policy files already supported by the dedicated relay audit/report commands.

Current status:

- Created GitHub issue #117 for hosted readiness policy-file reuse.
- Created branch `hosted-readiness-policy-files` from `main` without a `codex/` prefix, per user preference.
- Added `--retention-policy-file <path>` to hosted readiness when `--mailbox-dir` is configured.
- Reused mailbox retention policy merge semantics so policy `ttl_seconds` and `node_id` apply to the readiness mailbox audit, with CLI `--ttl-seconds` and `--node` overrides.
- Added `--thresholds-file <path>` and inline `--max-* <count>` threshold options to hosted readiness when `--abuse-dir` is configured.
- Reused abuse threshold policy merge semantics so CLI `--max-*` values override policy-file defaults.
- Added threshold checks/exceeded counts to hosted readiness text/JSON output, kept display guard aggregation payload-safe, and made exceeded thresholds contribute to warning status and `--fail-on-warning`.
- Updated README, hosted relay docs, distribution/hosting docs, production readiness docs, release checklist, SDK/MCP docs, Docker/package docs, and user install docs.

Validation so far:

- `cargo fmt --all -- --check` passed.
- `git diff --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- Local Rust compile/test was blocked on this Windows environment because the default MSVC target could not find `link.exe` and the GNU toolchain could not find `dlltool.exe`.
- PR #118 CI run `https://github.com/imthegoodboy/conU/actions/runs/26267121539` completed successfully: Packages, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- PR #118 was merged into `main` on 2026-05-22, issue #117 was closed, and local/remote `hosted-readiness-policy-files` branches were preserved.

Known gaps:

- This readiness-policy update does not add distributed hosted dashboards/adaptive abuse workflows, distributed mailbox retention orchestration, distributed tenant workflow services, distributed multi-instance session migration, managed hosted identity/key administration, release signing secrets, release tags, or npm publication.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Tagged Release Preflight Hardening (Completed)

Objective: prevent `v*` tag releases from creating a partial GitHub-only release when required signing or npm publication secrets are incomplete.

Current status:

- Created GitHub issue #120 for fail-closed tagged release publish secrets.
- Created branch `release-tag-preflight-hardening` from `main` without a `codex/` prefix, per user preference.
- Added a `Release Tag Preflight` job to `.github/workflows/release.yml`.
- The preflight requires Windows Authenticode secrets, macOS Developer ID/notarization secrets, and `NPM_TOKEN` before `v*` tag package checks or platform builds can start.
- Kept manual `workflow_dispatch` release smoke runs available without signing or npm secrets on non-tag refs.
- Changed tagged npm publish steps from warning-and-skip to fail-closed when `NPM_TOKEN` is missing.
- Updated release, distribution, signing, packaging, and npm launcher docs to describe the strict tagged-release behavior.
- Opened PR #121 to close issue #120.
- PR #121 CI passed across Packages plus Rust on `ubuntu-latest`, `windows-2025-vs2026`, and `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run passed with release preflight, package checks, all five platform builds, artifact verification, attestations, uploads, and expected non-tag skips for GitHub Release/npm publication.

Validation so far:

- `cargo fmt --all -- --check` passed.
- Python YAML parse passed for `.github/workflows/release.yml` and `.github/workflows/ci.yml`.
- Basic workflow text checks passed for tabs, `release-preflight`, and the package job dependency.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `git diff --check` passed.
- Default MSVC `cargo check --workspace --all-targets` was blocked locally because `link.exe` is not installed.
- GNU `cargo +stable-x86_64-pc-windows-gnu test --workspace` was blocked locally because `dlltool.exe` is not installed.
- PR #121 CI run `https://github.com/imthegoodboy/conU/actions/runs/26267680993` completed successfully: Packages, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run `https://github.com/imthegoodboy/conU/actions/runs/26267754923` completed successfully: Release Tag Preflight, Package Checks, and platform builds for `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64`.

Known gaps:

- This hardening does not configure repository signing secrets or `NPM_TOKEN`; `gh secret list` showed no repository secrets configured in this environment, so a real `v*` tag would correctly fail at the new preflight until maintainers add them.
- This hardening does not publish a release tag, publish npm packages, add OS package-manager distribution, or change the known hosted/distributed product gaps.

Next recommendation:

- Configure release signing secrets plus `NPM_TOKEN` before the next real `v*` tag, then continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Release Version Consistency Gate (Completed)

Objective: prevent a release tag, native archive, or npm package publication from using inconsistent Cargo/npm package versions.

Current status:

- Created GitHub issue #122 for release tag and package version consistency.
- Created branch `release-version-consistency-gate` from `main` without a `codex/` prefix, per user preference.
- Added `scripts/verify-release-versions.py` to validate all conU Cargo crate versions, `@conu/cli`, and `@conu/sdk` share one semver-like version.
- The verifier also compares `v*` tag names against the package version when `GITHUB_REF_TYPE=tag`/`GITHUB_REF_NAME` or `CONU_RELEASE_TAG` is present.
- Wired the verifier into the CI package job and the `Release Artifacts` package gate before npm checks/dry-runs.
- Updated README, distribution, production-readiness, release checklist, and packaging docs with the automated version gate.
- Opened PR #123 for the gate and linked it to issue #122.

Validation:

- `python scripts\verify-release-versions.py` passed.
- `GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v0.1.0 python scripts\verify-release-versions.py` passed.
- `GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v9.9.9 python scripts\verify-release-versions.py` failed as expected with a tag/package mismatch.
- `CONU_RELEASE_TAG=0.1.0 python scripts\verify-release-versions.py` failed as expected with a clean non-`v` tag error.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- Python YAML parse passed for `.github/workflows/release.yml` and `.github/workflows/ci.yml`.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `git diff --check` passed.
- PR #123 CI passed across Packages plus Rust on Ubuntu, Windows, and macOS: https://github.com/imthegoodboy/conU/actions/runs/26268247436
- Branch `Release Artifacts` smoke passed across release preflight, package checks, attestations/uploads, and five platform builds: https://github.com/imthegoodboy/conU/actions/runs/26268351380
- Default MSVC `cargo check --workspace --all-targets` was blocked locally because `link.exe` is not installed.
- GNU `cargo +stable-x86_64-pc-windows-gnu test --workspace` was blocked locally because `dlltool.exe` is not installed.

Known gaps:

- This version gate does not publish a release tag, publish npm packages, configure signing/npm secrets, or change the known hosted/distributed product gaps.

Next recommendation:

- Merge PR #123 without deleting local or remote work branches, then continue with tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Dashboard Snapshot (Completed)

Objective: give controlled multi-relay operators a payload-safe fleet-level dashboard snapshot without claiming hosted billing, distributed alerting, or adaptive abuse automation.

Current status:

- Created GitHub issue #124 for hosted fleet dashboard snapshots.
- Created branch `hosted-fleet-dashboard` from `main` without a `codex/` prefix, per user preference.
- Added `conu-relay --hosted-fleet-dashboard --fleet-file <path> [--account <account-id>] [--node <node-id>] [--json]`.
- Added a versioned fleet manifest parser with required false display guards and `[[relay]]` entries for optional credential, tenant, session-state, mailbox, accounting, and abuse metadata stores.
- The fleet command resolves relative source paths from the manifest directory, reuses the existing payload-safe audit functions, and returns only relay names, source paths, aggregate counters, filters, and display guards.
- Updated README, architecture, relay hosting docs, release checklist, security docs, user guide, repo memory, and implementation guardrails to describe the fleet dashboard boundary.
- Merged PR #125 and closed issue #124 while preserving the `hosted-fleet-dashboard` branch.

Validation:

- `cargo fmt --all` passed after implementation.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `cargo fmt --all -- --check` passed.
- `git diff --check` passed.
- PR #125 CI passed across Packages plus Rust on Ubuntu, Windows, and macOS: https://github.com/imthegoodboy/conU/actions/runs/26269521890
- Branch `Release Artifacts` smoke passed across release preflight, package checks, attestations/uploads, and five platform builds: https://github.com/imthegoodboy/conU/actions/runs/26269402546
- Post-merge main CI passed: https://github.com/imthegoodboy/conU/actions/runs/26269603066
- Post-merge main `Release Artifacts` smoke passed: https://github.com/imthegoodboy/conU/actions/runs/26269682067
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_dashboard_parser_and_renderers_are_metadata_only` was blocked locally because `dlltool.exe` is not installed.

Known gaps:

- This is a manifest-driven local/operator aggregate over available relay-local metadata stores. It is not hosted billing, distributed alerting, adaptive abuse response, distributed retention orchestration, a managed analytics service, or distributed session migration.

Next recommendation:

- Continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Dashboard Threshold Policy (Completed)

Objective: make controlled multi-relay fleet snapshots scriptable by applying the existing guarded abuse threshold policy format to aggregate fleet abuse counters without creating adaptive enforcement or exposing relay contents.

Current status:

- Created GitHub issue #126 for hosted fleet dashboard abuse threshold policy.
- Created branch `fleet-dashboard-threshold-policy` from `main` without a `codex/` prefix, per user preference.
- Extended `conu-relay --hosted-fleet-dashboard --fleet-file <path>` with `--thresholds-file <path>`, inline `--max-*` overrides, and `--fail-on-threshold`.
- The fleet command now evaluates thresholds only against aggregate abuse counters from configured fleet `abuse_dir` stores, preserves stdout, and returns exit code 3 only when `--fail-on-threshold` is set and at least one configured limit is exceeded.
- Threshold policy files reuse the existing metadata-only `version = "1"` format and required false display guards; CLI overrides still win for one-off runs.
- The command fails closed when threshold evaluation is requested but no fleet relay supplies an `abuse_dir`.
- Output remains limited to relay names, source paths, filters, aggregate counters, threshold check/exceeded metadata, and false display guards.
- Updated README, architecture, relay hosting docs, production/security/release docs, user guide, repo memory, and implementation guardrails to describe the new fleet threshold boundary.
- Opened PR #127 to close issue #126.

Validation:

- `cargo fmt --all` passed after implementation.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_dashboard_parser_and_renderers_are_metadata_only` was blocked locally because `dlltool.exe` is not installed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` was blocked locally by the same missing `dlltool.exe` linker dependency.
- PR #127 CI passed across Packages plus Rust on Ubuntu, Windows, and macOS: https://github.com/imthegoodboy/conU/actions/runs/26270473795
- Branch `Release Artifacts` smoke passed across release preflight, package checks, attestations/uploads, and five platform builds at the current PR head: https://github.com/imthegoodboy/conU/actions/runs/26270567039

Known gaps:

- This is a fleet-level aggregate threshold gate over relay-local metadata stores. It is not distributed alert routing, adaptive abuse response, hosted billing, distributed retention orchestration, distributed session migration, or tenant-wide workflow automation.
- Full local runtime/test proof for this Windows workstation still depends on installing `dlltool.exe`; GitHub CI covered the test path.

Next recommendation:

- Merge PR #127 without deleting local or remote work branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Dashboard Mailbox Retention Policy (Completed)

Objective: make controlled multi-relay fleet snapshots scriptable for durable mailbox retention pressure by reusing the existing guarded mailbox retention policy format without adding remote purge, adaptive cleanup, distributed retention orchestration, or payload exposure.

Current status:

- Created GitHub issue #128 for fleet mailbox retention policy gates.
- Created branch `fleet-mailbox-retention-policy` from `main` without a `codex/` prefix, per user preference.
- Opened PR #129 to close issue #128 without deleting local or remote branches.
- Extended `conu-relay --hosted-fleet-dashboard --fleet-file <path>` with `--retention-policy-file <path>`, `--ttl-seconds <seconds>`, and `--fail-on-retention`.
- Fleet retention policy files reuse the existing metadata-only `version = "1"` mailbox retention policy format with optional `ttl_seconds`, optional `node_id`, and required false display guards.
- Hosted fleet dashboards now apply a mailbox retention node filter only to mailbox metadata scans. CLI `--node` still remains the global source filter and overrides policy-file mailbox node defaults.
- CLI `--ttl-seconds` overrides all fleet mailbox TTLs for one run; per-relay manifest `mailbox_ttl_seconds` values remain source-specific overrides ahead of policy-file TTL defaults.
- Output adds effective mailbox retention node, policy path, TTL metadata, aggregate expired mailbox records/bytes, retention check counts, exceeded source counts, and existing false display guards only.
- `--fail-on-retention` preserves stdout and returns exit code 3 only when at least one TTL-checked fleet mailbox source reports expired durable records.
- The command fails closed when retention evaluation is requested but the fleet manifest has no mailbox source, or when `--fail-on-retention` is requested without any effective TTL.
- Updated README, architecture, relay hosting docs, production/security/release docs, SDK/MCP boundaries, user guide, repo memory, and implementation/security guardrails.

Validation:

- `cargo fmt --all` passed after implementation.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- GitHub PR CI passed for commit `3e039743b2b6261fe660dd5c4bea1e235b334541`: https://github.com/imthegoodboy/conU/actions/runs/26271673595
- Branch Release Artifacts smoke passed for commit `3e039743b2b6261fe660dd5c4bea1e235b334541`: https://github.com/imthegoodboy/conU/actions/runs/26271801283
- PR #129 status checks are clean, including CodeRabbit `Review skipped` success.
- Security review retained payload-safe behavior. The new gate reads configured local mailbox metadata only, reports counts/bytes/TTL/status/filter metadata, does not purge files, does not call remote relays, and does not print mailbox contents, manifest contents, policy contents, tokens, token hashes, session ids, payloads, ciphertext, or frame bodies.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_dashboard_parser_and_renderers_are_metadata_only` was blocked locally because `dlltool.exe` is not installed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` was blocked locally by the same missing `dlltool.exe` linker dependency.

Known gaps:

- This is a read-only fleet-level retention gate over relay-local durable mailbox metadata stores. It is not remote purge, distributed lock coordination, hosted billing, adaptive cleanup, managed alerting, tenant-wide retention orchestration, or distributed retention automation.
- Full local runtime/test proof for this Windows workstation still depends on installing `dlltool.exe`; GitHub CI covered the test path.

Next recommendation:

- Merge PR #129 without deleting local or remote work branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration beyond read-only fleet gates, or ICE/STUN/TURN managed traversal.

## Phase Completion Log

Add entries here when a phase is completed.

```txt
2026-05-10 - Phase 0 started. Architecture and agent memory created. Waiting for user approval before implementation.
2026-05-10 - Phase 0 completed. User approved implementation and Phase 1 started.
2026-05-10 - Phase 1 completed. Rust workspace scaffold created and validated with cargo fmt/check/test plus binary smoke commands using stable-x86_64-pc-windows-gnu. Next: Phase 2 CLI identity and dashboard.
2026-05-10 - Phase 2 completed. CLI dashboard and command shell created with payload-safe outputs, tests, and smoke validation. Next: Phase 3 local identity and persistent state.
2026-05-10 - Phase 3 completed. Local identity and persistent state added with idempotent init, status reads, tests, and isolated CONU_HOME smoke validation. Next: Phase 4 conUD daemon skeleton.
2026-05-10 - Phase 4 completed. conUD daemon skeleton added with start/stop, runtime heartbeat status, stale restart handling, payload-safe logs, tests, and isolated CONU_HOME process smoke. Next: Phase 5 local IPC and agent registration.
2026-05-10 - Phase 5 completed. File-backed local IPC gateway added with metadata-only agent registration, presence heartbeat, persisted local agent registry, conUD processing, CLI listing, tests, docs, and isolated CONU_HOME smoke validation. Next: Phase 6 opaque envelope messaging.
2026-05-10 - Phase 6 completed. Local opaque envelope messaging added with stdin submission, registered sender/receiver validation, recipient inboxes, metadata-only receipts/logs, conUD processing, tests, docs, and isolated CONU_HOME smoke validation. Next: Phase 7 pairing and trust.
2026-05-10 - Phase 7 completed. Local pairing invitations, join-to-trust, peer listing, revocation, pairing code hash storage, tests, docs, and isolated CONU_HOME smoke validation added. Next: Phase 8 WebSocket relay MVP.
2026-05-10 - Phase 8 completed. std-only WebSocket relay service, shared relay frame contract, token-authenticated sessions, metadata-only connected-peer forwarding, tests, docs, and relay binary smoke validation added. Next: Phase 9 remote discovery and sessions.
2026-05-10 - Phase 9 completed. conUD-owned remote session mirror, trusted remote agent cards, `conu sessions`, remote visibility in agents/status/connect, tests, docs, and isolated CONU_HOME smoke validation added. Next: Phase 10 streams and watch animation.
2026-05-10 - Phase 10 completed. Stream lifecycle metadata, stdin-only opaque stream writes, backpressure checks, watch event bus, private watch animation, tests, docs, and isolated CONU_HOME smoke validation added. Next: Phase 11 encryption hardening.
2026-05-10 - Phase 11 completed. Local security module added with Ed25519 signed agent cards, X25519 peer key agreement helpers, XChaCha20Poly1305 encrypted-at-rest message storage, replay protection, `conu security audit`, tests, docs, and GNU-toolchain validation. Next: Phase 12 SDK and MCP adapter.
2026-05-11 - Phase 12 completed. Rust SDK, MCP stdio adapter, Python wrapper SDK, local agent examples, explicit addressed-agent receive API, tests, docs, and GNU-toolchain validation added. Next: Phase 13 direct transport and NAT upgrade.
2026-05-11 - Phase 13 completed. conUD-owned direct/relay route manager, NAT-profile scoring, relay fallback selection, route probes/logs, CLI route commands, SDK/Python/MCP route tools, docs, skills, and GNU-toolchain validation added. Next: Phase 14 rooms, pub/sub, and multi-agent sessions.
2026-05-11 - Phase 15 completed as a user-directed skip-ahead. Added doctor readiness checks, release/smoke scripts, packaging templates, CI/release workflows, release checklist, observability docs, strict local-install smoke validation, and GNU-toolchain release validation. Phase 14 remains not started.
2026-05-11 - Post Phase 15 audit completed. Added clippy-clean polish across runtime, CLI, MCP, CI, and docs while preserving payload privacy and leaving Phase 14 not started.
2026-05-11 - Post Phase 15 internet data-plane and CLI polish completed. Added public peer-card trust, peer-encrypted relay message queueing, explicit relay sync, richer watch animation, SDK/Python/MCP remote helpers, relay E2E tests, and internet relay test docs. Phase 14 remains not started.
2026-05-11 - Post Phase 15 daemon relay production hardening completed. Added conUD-owned relay pump, retry/backoff, relay daemon smoke script, Windows start hardening, docs/skill updates, and daemon-owned remote message validation. Phase 14 remains not started.
2026-05-11 - Post Phase 15 distribution and hosting completed. Added native npm launcher package template, platform release artifact naming/checksums, Docker relay hosting template, distribution/hosting docs, release workflow updates, and installer validation. Phase 14 remains not started.
2026-05-13 - Phase 14 completed after the Phase 15 skip-ahead. Added local rooms/pub-sub metadata, encrypted-at-rest local room event fanout, room CLI/SDK/Python/MCP surfaces, connect/dashboard/watch polish, docs, and GNU-toolchain validation. Next: hosted relay TLS/auth, hosted session policy, remote room fanout, and stream-chunk routing.
2026-05-20 - Post Phase 15 relay abuse controls completed. Added configurable relay total connection, per-IP connection, and per-session frame-rate caps; generic metadata-only rate-limit errors; same-node session cleanup hardening; docs/skill updates; and GNU-toolchain release validation. Next: hosted relay auth/TLS and reusable daemon relay sessions.
2026-05-20 - Post Phase 15 reusable daemon relay sessions completed. Added daemon-owned relay session reuse across serve ticks, reconnect-on-failure behavior, endpoint-change handling, relay E2E session-reuse coverage, docs/skill updates, and validation. Next then: hosted relay auth/TLS policy, `wss://`, stream-chunk routing, and hosted session resume.
2026-05-20 - Post Phase 15 public relay token guard completed. Added non-loopback relay bind rejection for `local-dev-token` and short tokens, docs/skill updates, stale-token doc scans, and full release validation. Next then: `wss://`, stronger hosted relay auth/session policy, stream-chunk routing, and OS-backed key storage.
2026-05-20 - Post Phase 15 WSS relay client support completed. Added certificate-validated `wss://` relay client support, endpoint validation across relay delivery and peer-card trust, CLI/docs updates, Windows GNU-compatible TLS dependency pins, and full release validation. Next: stronger hosted relay auth/session policy, stream-chunk routing, offline mailbox, and OS-backed key storage.
2026-05-20 - Post Phase 15 scoped relay credentials and session policy completed. Added static per-node relay credentials, token-safe authorization, idle timeout and max session TTL controls, redacted auth Debug output, docs/skill updates, focused relay auth/session tests, and full release validation. Next: stream-chunk routing, managed hosted account/credential lifecycle, hosted session resume/accounting, and OS-backed key storage.
2026-05-21 - Post Phase 15 relay stream-chunk delivery completed. Added relay envelope kind/stream metadata, peer-encrypted stream chunk outbox and delivery, inbox/receipt stream metadata, live relay E2E coverage, docs/skill updates, and full release validation. Next: hosted relay account/credential lifecycle, hosted session resume/accounting, offline mailbox, OS-backed key storage, and remote room fanout.
2026-05-21 - Post Phase 15 offline relay mailbox completed. Added bounded in-memory relay mailbox delivery for peer-encrypted message and stream-chunk envelopes, mailbox cap/TTL env controls, mailbox TTL regression coverage, docs/skill updates, and GNU-toolchain validation. Next: hosted account/credential lifecycle, hosted session resume/accounting, durable hosted mailbox storage/accounting, OS-backed key storage, and remote room fanout.
2026-05-21 - Post Phase 15 durable relay mailbox completed. Added optional `CONU_RELAY_MAILBOX_DIR` file-backed ciphertext envelope persistence, relay restart mailbox delivery coverage, Docker mailbox volume defaults/docs, docs/skill updates, and GNU-toolchain validation. Next: hosted account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting/quotas, OS-backed key storage, and remote room fanout.
2026-05-21 - Post Phase 15 Windows DPAPI secret wrapping completed. Added current-user DPAPI wrapping for local signing/exchange/storage secret bytes, migration-compatible reads for older plaintext-hex key files, audit/backend reporting without secret material, CLI/MCP redaction coverage, docs/skill updates, and GNU-toolchain release validation. Next: managed hosted relay account/credential lifecycle, relay credential storage, capability policy, signed remote agent-card exchange, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay credential storage completed. Added local runtime relay client credential storage, DPAPI-backed token fields on Windows, `conu relay credential set/status/clear`, env-over-stored token resolution, docs/skill updates, and GNU-toolchain release validation. Next: managed hosted relay account/credential lifecycle, capability policy, signed remote agent-card exchange, and non-Windows keychain support.
2026-05-21 - Post Phase 15 signed peer cards completed. Added Ed25519-signed public peer-card export, signed-card verification on trust import, trust-store signature metadata, CLI/MCP/Python signed-card fields, tamper regression coverage, docs/skill updates, and GNU-toolchain validation. Next: signed remote agent-card exchange, capability policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 local capability enforcement completed. Added explicit agent capability registration flags, core enforcement for messages/streams/rooms, stream/room denial tests, docs/skill updates, and GNU-toolchain targeted validation. Next: signed remote agent-card exchange, peer-scoped permission policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 signed remote agent cards completed. Added signed public agent-card export/import for trusted peers, session-sync preservation of signed remote cards, tamper and collision checks, CLI/SDK/Python/MCP surfaces, docs/skill updates, and GNU-toolchain validation. Next: peer-scoped permission policy, automatic live agent-card exchange, managed hosted relay account/credential lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 peer-scoped permission policy completed. Added default-deny peer policy records, `conu peers policy`, SDK/Python/MCP policy controls, relay message/stream and remote room policy enforcement, docs/skill updates, and full GNU-toolchain validation. Next: automatic live agent-card exchange, remote room fanout/per-topic policy, managed hosted relay lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 automatic signed agent-card exchange completed. Added peer-encrypted relay control envelopes for signed local agent cards, session-sync queueing for signed trusted peers with policy grants, inbound verification/import, relay E2E coverage, docs/skill updates, and full GNU-toolchain validation. Next: remote room fanout/per-topic policy, managed hosted relay lifecycle, direct transport, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay-backed room event fanout completed. Added `room_event` relay envelopes, peer-encrypted room event packets with room id/topic hidden from relay frames, remote room publish fanout with `rooms=true` peer policy and agent capability checks, inbound encrypted-at-rest event delivery, docs/skill updates, and full GNU-toolchain validation. Next: per-topic room policy, managed hosted relay lifecycle, direct transport, and non-Windows keychain support.
2026-05-21 - Post Phase 15 room topic policy completed. Added metadata-only per-topic room publish/subscribe grants, `conu rooms policy`, SDK/Python/MCP topic policy surfaces, local and relay inbound enforcement, docs/skill updates, and targeted GNU-toolchain validation. Next: managed hosted relay lifecycle/accounting, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay credential manifest lifecycle completed. Added hashed self-hosted relay credential manifests with active/revoked status, optional expiry, token-safe hash generation, public-bind guard coverage, docs/skill updates, and full GNU-toolchain validation. Next: hosted relay accounting/quotas, session accounting, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay accounting and quotas completed. Added metadata-only per-node relay accounting files, authenticated-session/sent/received/mailbox counters, optional sent-envelope and sent-byte quotas, quota denial coverage, docs/skill updates, and GNU-toolchain validation. Next: hosted session resume semantics, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay session resume semantics completed. Added optional HELLO resume hints and WELCOME resumed status, same-node relay validation with cross-node fallback to a new session, daemon pump same-endpoint resume after same-process disconnects, sessions_resumed accounting, docs/skill updates, and full GNU-toolchain validation. Next: direct QUIC/NAT traversal, managed hosted relay account lifecycle, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 live relay credential manifest reload completed. Added live-reloaded `CONU_RELAY_CREDENTIALS_FILE` auth for new HELLO sessions, fail-closed invalid manifest updates, revoke-without-restart coverage, token/hash redaction checks, docs/skill updates, and validation. Next: direct QUIC/NAT traversal, managed hosted relay account/credential issuance APIs, hosted audit/admin controls, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 direct route selection guard completed. Configured direct QUIC/UDP endpoints now remain inactive metadata with `direct_quic_transport_inactive`, relay stays selected for remote delivery, remote stream chunks continue over relay, docs/skills were updated, and full validation passed. Next: real authenticated direct QUIC/NAT traversal data plane or managed hosted account/credential issuance APIs.
2026-05-21 - Post Phase 15 payload-safe log rotation completed. Added `conu logs rotate` and core observability rotation for local metadata logs, bounded `.log.N` archives, doctor scanning for rotated archives, docs/skill updates, and full validation. Next: storage-key rotation migration tooling, structured telemetry allowlists, managed hosted credential issuance, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 storage-key rotation migration completed. Added archived storage-key ring reads, `conu security rotate storage --confirm`, local encrypted-at-rest message queue/inbox re-encryption, payload-safe rotation reports, docs/skill updates, and full validation. Next: old storage-key retirement, structured telemetry allowlists, managed hosted credential issuance, direct QUIC/NAT traversal, hosted multi-tenant permission administration, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 storage-key retirement completed. Added `conu security retire storage --confirm`, unused archived storage-key deletion after local queue/inbox dependency scanning, dependent-key retention, payload-safe retirement reports, docs/skill updates, and validation. Next: structured telemetry allowlists, managed hosted credential issuance, direct QUIC/NAT traversal, hosted multi-tenant permission administration, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 structured telemetry snapshot completed. Added `conu telemetry snapshot`, `conu.telemetry.snapshot.v1`, explicit allowlisted aggregate telemetry fields, payload-safe JSON/text output, privacy regression tests, docs/skill updates, and full validation. Next: managed hosted credential issuance, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, hosted multi-tenant permission administration, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 offline relay credential issuance completed. Added `conu-relay --issue-credential`, strong offline scoped token generation, raw-token file output with hashed manifest stdout, manifest compatibility tests, docs/skill updates, and full validation. Next: managed hosted account APIs, online credential rotation/revocation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay credential manifest operations completed. Added `conu-relay --issue-credential --credentials-file`, `--replace`, and `--revoke-credential` for self-hosted manifest upsert/rotation/revocation without raw-token output, token-safe manifest lifecycle tests, docs/skill updates, and full validation. Next: managed hosted account APIs, online credential issuance/rotation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 identity-key rotation completed. Added `conu security rotate identity --confirm-peer-refresh`, archived old signing/exchange keys with secret-backend protection, refreshed active peer-card material, old exchange-key decrypt compatibility during refresh, payload-safe CLI/JSON reports, docs/skill updates, and validation. Next: managed hosted identity/key administration, non-Windows keychain support, direct QUIC/NAT traversal, and managed hosted account APIs.
2026-05-21 - Post Phase 15 identity archive retirement completed. Added `conu security retire identity --confirm-peer-refresh-complete`, payload-safe archive retirement reports, active-key preservation with old-key decrypt compatibility removal after refresh, docs/skill updates, and validation. Next: managed hosted identity/key administration, non-Windows keychain support, direct QUIC/NAT traversal, and managed hosted account APIs.
2026-05-21 - Post Phase 15 TypeScript SDK wrapper completed. Added dependency-free `@conu/sdk` wrapper around installed `conu`/`conud`, stdin-only payload helpers, TypeScript declarations, smoke tests, a local example, docs/skill updates, and full validation. Next then: TypeScript receive helper or managed hosted relay/account work.
2026-05-21 - Post Phase 15 GitHub CI package validation completed. Added a Node 20 package job for `sdk/typescript` and `packaging/npm/conu-cli`, documented package checks as a CI gate, stabilized durable relay mailbox FIFO reload ordering and relay sync bounded-wait handling exposed by GitHub CI, and validated package/Python/Rust checks locally. Next then: TypeScript receive helper or managed hosted relay/account work.
2026-05-21 - Post Phase 15 TypeScript explicit receive helper completed. Added MCP-backed `receiveMessage()` and `receiveMessageBytes()` to the TypeScript SDK wrapper, kept normal metadata surfaces payload-safe, updated docs/skills/examples, and validated package/Python/fmt checks locally. Next: managed hosted relay/account work, npm/release publication, browser-native protocol support, or non-Windows keychain support.
2026-05-21 - Post Phase 15 release publishing workflow completed. Added release archive verification, package dry-runs, tag-driven GitHub Release asset upload, optional npm provenance publication, docs/skill updates, and local archive validation. Next: platform code signing/notarization, managed hosted relay/account work, or non-Windows keychain support.
2026-05-21 - Post Phase 15 non-Windows user-managed secret wrapping completed. Added `CONU_SECRET_WRAP_KEY_HEX`/`CONU_SECRET_WRAP_KEY_FILE` encrypted secret-field wrapping for non-Windows local keys and stored relay credentials, migration from plaintext-hex fields when configured, docs/skill updates, and GNU-toolchain validation. Next: native macOS Keychain/Linux Secret Service/HSM support or managed hosted relay/account work.
2026-05-21 - Post Phase 15 release artifact attestation hardening completed. Added GitHub artifact attestations for release archives/checksums, a publish-job verifier pass, required packaging-template archive checks, docs/skill updates, and full GNU-toolchain/package/release validation. Next: platform code signing/notarization or managed hosted relay/account work.
2026-05-21 - Post Phase 15 TypeScript browser boundary hardening completed. Added fail-closed browser-conditioned `@conu/sdk` exports, browser-native design docs, package/check coverage, docs/skill updates, and GNU-toolchain/package validation. Next: managed hosted relay/account auth before real browser-native protocol support, or direct transport if relay independence is more urgent.
2026-05-21 - Post Phase 15 native non-Windows secret storage completed. Added macOS Keychain and Linux Secret Service secret backends, native OS-secret reference files, migration/readback coverage, docs/smoke guidance, and full GNU-toolchain validation with macOS target compile coverage. Next: managed hosted relay/account auth, direct transport, or platform code signing.
2026-05-21 - Post Phase 15 platform signing and notarization completed. Added Windows Authenticode and macOS Developer ID/notarization release workflow gates, macOS ZIP asset naming for npm, Linux checksum plus GitHub-attestation policy docs, release verifier updates, docs/skill updates, and full GNU-toolchain/package/release validation. Next: configure signing secrets before the next tag, then prioritize managed hosted account auth or direct QUIC/NAT transport.
2026-05-21 - Post Phase 15 hosted relay account auth completed. Added account-scoped relay credential metadata, admin WebSocket frames, `CONU_RELAY_ADMIN_TOKEN`, online issue/rotate/revoke/audit commands with admin-token stdin, raw node-token local-only issuance after relay confirmation, fail-closed revoked/expired/missing credential behavior, token/hash redaction coverage, docs/skill updates, full GNU-toolchain validation, package checks, relay daemon smoke, and admin CLI smoke. Next: distributed hosted session/accounting state, hosted dashboards/abuse workflows, hosted tenant administration, direct QUIC/NAT transport, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 authenticated direct QUIC/NAT transport completed. Added Quinn-based direct listener/client support, trusted-peer encrypted probes, direct message and stream-chunk delivery, route selection only after live authenticated probes, relay fallback preservation, direct endpoint peer-card/SDK/MCP surfaces, docs/skill updates, and GNU-toolchain core validation. Next: distributed hosted session/accounting state, hosted dashboards/abuse workflows, hosted tenant administration, managed direct NAT traversal, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 distributed relay state/accounting foundation completed. Added metadata-only file-backed relay session state through `CONU_RELAY_SESSION_STATE_DIR`, relay restart same-node resume validation, cross-node resume fallback preservation, docs/skill/package updates, and full GNU-toolchain/package validation. Next: hosted dashboards/abuse workflows, managed direct NAT traversal, hosted tenant administration, distributed multi-instance session migration, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 managed direct NAT rendezvous foundation completed. Added static direct candidate source/kind/rendezvous metadata, explicit `nat_traversal_unavailable` reporting, invalid endpoint secret sanitization, CLI/MCP route surfaces, docs/skill updates, and full GNU-toolchain/package validation. Next: hosted dashboards/abuse workflows, ICE/STUN/TURN managed traversal, hosted tenant administration, distributed multi-instance session migration, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 hosted tenant admin foundation completed. Added `CONU_RELAY_TENANTS_FILE`, metadata-only tenant/node lifecycle commands, hosted permission and public key-id metadata, fail-closed admin issue/rotate and new-session authorization, docs/skill updates, CLI smoke, and full GNU-toolchain/package validation. Next: hosted dashboards/abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted relay abuse dashboard foundation completed. Added `CONU_RELAY_ABUSE_DIR`, metadata-only `.abuse` denial/enforcement counters, `conu-relay --abuse-audit`, payload-safe per-node/global audit output, credential/tenant deny, quota, rate-limit, session-expiry, mailbox-reject, and malformed-frame coverage, docs/skill updates, and GNU-toolchain targeted validation. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted relay dashboard snapshot completed. Added public metadata-only accounting audit support and `conu-relay --hosted-dashboard` to combine credential, tenant, accounting, and abuse summaries with account/node filters and JSON/text output without tokens, token hashes, session ids, private keys, payloads, ciphertext bodies, or frame contents. Updated docs/skills/plan and full GNU-toolchain/package validation passed. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 durable relay mailbox retention audit completed. Added public metadata-only durable mailbox audit support and `conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--json]` for file counts, byte totals, queue timestamp bounds, optional expired counts, invalid mailbox-file counts, and false display guards without printing stored frames, ciphertext bodies, tokens, token hashes, session ids, private keys, or payloads. Updated docs/skills/plan and full GNU-toolchain/package validation passed, including a CLI smoke against a temporary mailbox directory. Next: mailbox purge workflows, distributed hosted dashboards/adaptive abuse workflows, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 durable relay mailbox retention purge completed. Added `conu-relay --mailbox-purge --mailbox-dir <path> --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]`, dry-run and confirm-gated deletion of expired valid `.mailbox` files, aggregate metadata/reporting, display guards, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI smoke against a temporary mailbox directory. Next: relay-local scheduled mailbox retention purge, distributed hosted dashboards/adaptive abuse workflows, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 relay-local scheduled mailbox retention purge completed. Added `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` for opt-in relay-local expired valid `.mailbox` cleanup using the offline envelope TTL, required durable mailbox storage for scheduled purge, left invalid and display-guard-failed files untouched, updated docs/skills/plan, and completed full GNU-toolchain/package validation plus CLI help/config smoke. Next: distributed hosted dashboards/adaptive abuse workflows, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated hosted dashboard snapshot completed. Added `conu-relay --admin-hosted-dashboard --relay <endpoint> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]`, a relay admin `dashboard` control-plane action, metadata-only credential/tenant/accounting/abuse counters from the running relay, token-safe admin output, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI help smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay snapshots, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated mailbox retention audit completed. Added `conu-relay --admin-mailbox-audit --relay <endpoint> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--json]`, a relay admin `mailbox_audit` control-plane action, metadata-only durable mailbox node/file/byte/timestamp/expiry counters from the running relay, token-safe admin output, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI help smoke. Next: distributed hosted mailbox retention orchestration beyond read-only single-relay audits, distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated mailbox retention purge completed. Added `conu-relay --admin-mailbox-purge --relay <endpoint> --admin-token-stdin --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]`, a relay admin `mailbox_purge` control-plane action, dry-run and confirm-gated expired valid `.mailbox` cleanup from the running relay, aggregate-only retention/purge counters, token-safe admin output, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI help smoke. Next: distributed hosted mailbox retention orchestration beyond single-relay purge, distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated hosted tenant lifecycle completed. Added relay admin `tenant_upsert`, `tenant_revoke`, `tenant_node_upsert`, `tenant_node_revoke`, and `tenant_audit` control-plane actions plus `conu-relay --admin-tenant-upsert`, `--admin-tenant-revoke`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, and `--admin-tenant-audit` with `--admin-token-stdin`; online tenant updates modify only the configured relay tenant registry, return tenant/node/policy counts and display guards only, preserve hosted permission metadata as separate from local peer policy, fail closed for missing or revoked tenant records, and do not print admin tokens, raw node tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, frame contents, or manifest contents. Updated docs/skills/plan and validated with GNU `fmt`, workspace `check`, `clippy -D warnings`, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, and CLI help smoke. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle/RBAC workflows beyond single-relay admin commands, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 scoped hosted admin-token RBAC completed. Added live-read `CONU_RELAY_ADMIN_TOKENS_FILE` hashed admin-token records with optional account ids, active/revoked status, optional expiry, and credentials/tenants/dashboard/mailbox-audit/mailbox-purge scopes while preserving `CONU_RELAY_ADMIN_TOKEN` as the full-admin compatibility path. Online admin requests now fail closed with `admin_scope_denied` for valid tokens outside their action or account boundary, account-scoped dashboard snapshots avoid global accounting/abuse counters without a node filter, account-scoped mailbox audit/purge requires an active tenant node, and admin outputs still avoid admin tokens, raw node tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, frame contents, and manifest contents. Updated docs/skills/plan and added scoped manifest coverage for credential, tenant, dashboard, mailbox-audit, and mailbox-purge paths. Validation passed with GNU `fmt`, workspace `check`, `clippy -D warnings`, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, and CLI help smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay snapshots, distributed tenant lifecycle/workflow automation beyond scoped single-relay admin tokens, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted account suspension workflow completed. Added relay admin `account_suspend`, `conu-relay --hosted-account-suspend`, and `conu-relay --admin-hosted-account-suspend` so one configured relay can revoke hosted tenant metadata first and then all credential records for that account while returning only account, credential, tenant, node, policy, path/endpoint, and display-guard metadata. Scoped admin tokens require both credentials and tenants scopes for this workflow; full-admin compatibility remains available. Updated docs/skills/plan and validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, workspace tests, Python compile, TypeScript/package checks, npm launcher check, diff check, conu-relay build, CLI help smoke, and a local hosted account-suspend CLI smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay snapshots, distributed tenant lifecycle/workflow automation beyond single-relay account suspension/scoped admin tokens, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted abuse threshold report completed. Added local `conu-relay --abuse-threshold-report` and admin-gated `conu-relay --admin-abuse-threshold-report` over metadata-only abuse counters, with explicit max thresholds, count/max/exceeded JSON/text output, dashboard-scope admin authorization, payload-safe display guards, docs/skills/plan updates, targeted threshold tests, full GNU workspace validation, Python/package checks, diff check, conu-relay build, CLI help smoke, and local JSON threshold smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 abuse threshold fail-on-threshold mode completed. Added optional `--fail-on-threshold` to local and admin-gated abuse threshold reports, preserving stdout report output and returning exit code 3 only when configured thresholds are exceeded; updated docs/skills/plan and validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, focused threshold tests, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, CLI help smoke, and local exit-code smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 abuse threshold policy files completed. Added reusable metadata-only `--thresholds-file` support to local and admin-gated abuse threshold reports, required versioned policy files with false display guards, kept CLI `--max-*` overrides and `--fail-on-threshold` behavior, updated docs/skills/plan, validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, focused threshold tests, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, CLI help smoke, and local policy-file exit-code smoke. PR #97 merged, issue #96 closed, and local/remote feature branches were preserved. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 mailbox retention policy files completed. Added reusable metadata-only `--retention-policy-file` support to local/admin mailbox audit and purge commands, required versioned policy files with optional `ttl_seconds`, optional `node_id`, and false display guards, kept CLI `--ttl-seconds`/`--node` overrides plus existing dry-run/confirm purge safety, updated docs/skills/plan, and validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, focused mailbox tests, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, CLI help smoke, and local policy-file audit/purge smoke. Next: distributed hosted mailbox retention orchestration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 relay session-state audit completed. Added payload-safe local `--session-audit` and admin-gated `--admin-session-audit`, relay admin `session_audit` frames, `scope_sessions` scoped admin-token RBAC, account-scoped node/tenant guardrails, docs/skills/plan updates, full GNU workspace validation, Python/package checks, conu-relay build, CLI help smoke, local session-audit smoke, and diff check. Next: distributed multi-instance session migration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted admin-token manifest audit completed. Added payload-safe local `conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <id>] [--json]`, metadata-only admin-token audit structs/counts, host:port-only bind parser hardening, stricter false display guard support for key material/session id/ciphertext markers, docs/skills/plan updates, full GNU workspace validation, Python/package checks, conu-relay build, CLI help smoke, local admin-token audit smoke, and diff check. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted relay readiness preflight completed. Added payload-safe local `conu-relay --hosted-readiness` to combine credential, admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks with JSON/text output, warning counts, display guards, and optional `--fail-on-warning` exit code 3 after preserving stdout. Updated docs/skills/plan and validated with GNU fmt/check/clippy/workspace tests, focused readiness test, Python compile, TypeScript/package checks, conu-relay build, local readiness/fail-on-warning smoke, and diff check. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 GitHub Actions Node 24 runtime hardening completed. Updated CI and release workflows to `actions/checkout@v6` and `actions/setup-node@v6`, confirmed both current action releases declare Node 24 runtimes, updated release checklist, and validated YAML parse, package checks, no stale v4/v5 action references, and diff check. Next: release workflow hardening, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 release artifact action runtime hardening completed. Updated release artifact provenance/upload/download steps to `actions/attest@v4.1.0`, `actions/upload-artifact@v7.0.1`, and `actions/download-artifact@v8.0.1` after confirming those upstream action metadata files declare Node 24 runtimes. Updated release checklist with the self-hosted runner caveat and validated YAML parse, package checks, no stale artifact action references, and diff check. Next: release workflow smoke, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 release workflow smoke validation completed. Ran `Release Artifacts` through `workflow_dispatch` on `main` after the Node 24 action updates; package checks and all five platform artifact builds passed, artifact uploads were present, GitHub Release/npm publication jobs skipped as expected on the non-tag run, and post-merge CI was green. Next: tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 GitHub Actions runner image pinning completed. Pinned CI/release Windows jobs to `windows-2025-vs2026`, pinned macOS arm64 jobs to `macos-15`, kept macOS x64 release on `macos-15-intel`, removed floating Windows/macOS workflow labels, updated release checklist, validated local workflow/package checks, passed PR CI on the explicit labels, and passed a branch `Release Artifacts` smoke run across all five platform builds. Next: revisit the Windows label after GitHub completes the June 2026 migration, tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 Node LTS package hardening completed. Moved CI/release npm package jobs to Node 24, restricted `@conu/sdk` and `@conu/cli` package engines to Node 22 or Node 24 LTS, documented the supported LTS policy, validated local package checks/dry-runs, passed PR CI, passed a branch `Release Artifacts` smoke run across all five platform builds, merged PR #116, closed issue #115, and preserved local/remote branches. Next: revisit the Node engine range when the next Node LTS line is promoted, tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted readiness policy files completed. Added `--retention-policy-file`, `--thresholds-file`, and inline `--max-*` support to payload-safe local `conu-relay --hosted-readiness`, reused existing metadata-only retention/threshold policy parsers and CLI override semantics, added threshold checks/exceeded counts to text/JSON output, made exceeded thresholds contribute to warnings and `--fail-on-warning`, updated docs/plan, validated local fmt/diff/Python/package checks, passed PR #118 CI across Packages plus Rust on Ubuntu/Windows/macOS, merged PR #118, closed issue #117, and preserved local/remote branches. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 tagged release preflight hardening completed. Added a fail-closed `Release Tag Preflight` for `v*` releases requiring Windows signing, macOS signing/notarization, and `NPM_TOKEN` before package checks/builds, changed tagged npm publish steps from warning-and-skip to errors, preserved unsigned non-tag workflow_dispatch smoke builds, updated release docs/plan, passed local workflow/package/Rust GNU checks with documented local linker blockers, passed PR #121 CI, and passed a branch `Release Artifacts` smoke run across preflight, package checks, attestations/uploads, and five platform builds. Next: configure release signing secrets plus `NPM_TOKEN` before the next real tag, then continue hosted/distributed product gaps.
2026-05-22 - Post Phase 15 release version consistency gate completed. Added `scripts/verify-release-versions.py` for shared Cargo/npm package version checks and `v*` tag-to-package-version enforcement, wired it into CI and Release Artifacts package gates before npm checks/dry-runs, updated release/package docs, validated local good and fail-closed tag paths, passed PR #123 CI, and passed a branch `Release Artifacts` smoke across release preflight, package checks, attestations/uploads, and five platform builds. Next: configure release signing secrets plus `NPM_TOKEN` before the next real tag, then continue hosted/distributed product gaps.
2026-05-22 - Post Phase 15 hosted fleet dashboard snapshot completed. Added `conu-relay --hosted-fleet-dashboard --fleet-file <path>` for guarded multi-relay metadata aggregation across credential, tenant, session-state, mailbox, accounting, and abuse stores; required versioned manifest false display guards; kept output to relay names, source paths, filters, aggregate counters, and display guards; updated docs/skills/plan; passed local GNU workspace check/clippy, package/Python checks, PR #125 CI, and a branch `Release Artifacts` smoke across all five platform builds. Next: adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet dashboard threshold policy completed. Added reusable `--thresholds-file`, inline `--max-*`, and `--fail-on-threshold` support to `conu-relay --hosted-fleet-dashboard`, evaluating only aggregate fleet abuse counters and returning exit code 3 only when requested and exceeded; preserved stdout and payload-safe output boundaries, updated docs/skills/plan, and passed local GNU check/clippy, workspace check/clippy, package/Python checks, version gate, diff check, PR #127 CI, and a branch `Release Artifacts` smoke across all five platform builds. Local targeted test/run smoke remained blocked by missing `dlltool.exe`; GitHub Windows CI covered the test path. Next: merge PR #127 without deleting branches, then adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet dashboard mailbox retention policy completed. Added reusable `--retention-policy-file`, `--ttl-seconds`, and `--fail-on-retention` support to `conu-relay --hosted-fleet-dashboard`, reused metadata-only durable mailbox retention policy files with required false display guards, preserved CLI `--node` as the global source filter, added aggregate retention status/count/byte reporting, failed closed for missing mailbox sources or missing effective TTL under fail-on-retention, updated docs/skills/plan, and kept output payload-safe. GitHub PR CI and branch Release Artifacts smoke passed; local Rust runtime/test execution remains blocked on this Windows workstation until `dlltool.exe` is installed. Next: merge PR #129 without deleting branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration beyond read-only fleet gates, or ICE/STUN/TURN managed traversal.
```
