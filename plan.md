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
Current phase: Phase 12 - SDK And MCP Adapter
Status: not_started
Last updated: 2026-05-10
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

Status: not_started

Goal:

Give agents a simple way to use conU.

Deliverables:

- Rust SDK
- Python SDK
- TypeScript SDK later
- MCP adapter exposing conU communication tools
- examples for local agents

Exit criteria:

- Agent can call register, peers, send, receive, stream.
- MCP-capable agents can use conU as tools.

## Phase 13 - Direct Transport And NAT Upgrade

Status: not_started

Goal:

Move beyond relay-only networking.

Deliverables:

- QUIC transport
- direct route attempt
- relay fallback
- route quality scoring
- hole-punching research/prototype

Exit criteria:

- Direct route is preferred when available.
- Relay fallback keeps product reliable.

## Phase 14 - Rooms, Pub/Sub, And Multi-Agent Sessions

Status: not_started

Goal:

Support shared spaces and multiple agents in one session.

Deliverables:

- rooms
- subscriptions
- publish/subscribe topics
- room presence
- group stream metadata

Exit criteria:

- Trusted agents can join a room.
- Events route to subscribed agents.
- CLI shows room flow without payloads.

## Phase 15 - Packaging And Production Readiness

Status: not_started

Goal:

Prepare conU for real users.

Deliverables:

- Windows build
- macOS build path
- Linux build path
- installer strategy
- service installation
- config docs
- security review checklist
- observability setup

Exit criteria:

- User can install, start, pair, and connect agents.
- Logs and telemetry are payload-safe.
- Release checklist exists.

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
```
