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
Last updated: 2026-05-13
Note: Phase 14 and Phase 15 are complete for the current local-first app. Post-Phase-15 relay data-plane, CLI polish, daemon relay hardening, distribution/hosting, and Phase 14 local rooms/pub-sub passes are complete. Public hosted internet readiness remains scoped by the known relay TLS/auth/session gaps.
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
- Relay-backed encrypted message/stream byte delivery is not active yet; Phase 11 provides the key agreement and encryption helpers for that next transport phase.
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
- TypeScript SDK later
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

- TypeScript SDK remains future work.
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

- [x] Direct route is preferred when a valid direct endpoint is configured.
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

- Real QUIC packet transport is not implemented yet; Phase 13 selects and records `direct-quic` route candidates.
- NAT traversal is config/profile based; live ICE-style candidate gathering, STUN/TURN, and hole punching remain future transport work.
- Route probes are metadata/config probes with latency estimates, not real RTT measurements.
- conUD still does not own live relay-backed encrypted message or stream byte delivery.
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

- Relay-backed room event fanout is not implemented yet; remote room participants are metadata-visible only.
- Room membership is the current subscription model; per-topic subscription grants and policy are still future work.
- Live relay-backed stream byte routing, persistent relay sessions, hosted relay auth/rate limits, `wss://` client support, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, offline mailbox, and OS-backed key storage remain future hardening work.
- Public managed online release remains blocked until the hosted relay/TLS/auth/session work is complete.

Next recommendation:

- Prioritize `wss://` client support, hosted relay auth/rate limits, persistent relay sessions, and then remote room fanout/stream byte routing before advertising conU as a managed public internet service.

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

- The relay client supports `ws://`; public `wss://` requires client support plus hosted TLS termination in front of `conu-relay`.
- Superseded by the daemon relay production hardening pass below: conUD now owns bounded relay sync windows when configured.
- Relay-backed stream byte routing, offline mailbox delivery, hosted relay auth/rate limits, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- For user testing, run `docs/internet-relay-test.md` locally or over a reachable `ws://` relay.
- For product hardening, add a conUD-owned relay pump with reconnect/backoff, then stream byte routing and hosted relay auth/TLS strategy.

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

- Relay pump uses bounded reconnect/sync windows, not a single long-lived persistent relay session.
- Public `wss://` still requires client support plus hosted TLS termination in front of `conu-relay`.
- Relay-backed stream byte routing, offline mailbox delivery, hosted relay auth/rate limits, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- Run full validation, merge the daemon relay hardening branch, then choose between Phase 14 rooms/pub-sub or deeper hosted relay auth/TLS plus persistent relay session work.

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
- Kept public-hosting guidance honest: the current client supports `ws://`; managed public relay still requires `wss://`, hosted auth/rate limits, persistent sessions, stream byte routing, offline mailbox, capability policy, signed remote cards, and OS-backed key storage.

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
- Hosted relay auth/rate limits, `wss://` client support, persistent relay sessions, stream byte routing, offline mailbox, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- Publish the first GitHub Release with platform artifacts/checksums, then publish `@conu/cli`; after that, prioritize `wss://` client support and hosted relay auth before advertising a public managed relay.

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
2026-05-13 - Phase 14 completed after the Phase 15 skip-ahead. Added local rooms/pub-sub metadata, encrypted-at-rest local room event fanout, room CLI/SDK/Python/MCP surfaces, connect/dashboard/watch polish, docs, and GNU-toolchain validation. Next: hosted relay TLS/auth, persistent relay sessions, remote room fanout, and stream byte routing.
```
