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
Current phase: Phase 2 - CLI Identity And Dashboard
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

Status: not_started

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

- CLI renders cleanly on Windows terminals.
- No private payload concepts are displayed.
- Commands have helpful structured output.

## Phase 3 - Local Identity And Persistent State

Status: not_started

Goal:

Create local node identity, config, trust store, and data directory.

Deliverables:

- node id generation
- local config file
- trust store skeleton
- agent registry persistence
- state path resolution

Exit criteria:

- `conu init` creates local identity.
- `conu status` reads identity and config.
- Re-running init is safe.

## Phase 4 - conUD Daemon Skeleton

Status: not_started

Goal:

Create the local runtime daemon that will own routing, sessions, identity, and agent connections.

Deliverables:

- daemon process
- runtime state machine
- graceful shutdown
- local health endpoint or IPC ping
- daemon logs without payloads

Exit criteria:

- `conu start` launches runtime.
- `conu status` detects runtime.
- Runtime can restart cleanly.

## Phase 5 - Local IPC And Agent Registration

Status: not_started

Goal:

Let local agents register with conUD through a local gateway.

Deliverables:

- local IPC transport
- register agent request
- agent card model
- presence heartbeat
- `conu agents` local list

Exit criteria:

- A sample local agent can register.
- CLI lists local registered agents.
- Agent identity persists.

## Phase 6 - Opaque Envelope Messaging

Status: not_started

Goal:

Implement local opaque message envelopes and local send/receive routing.

Deliverables:

- envelope type
- message id
- sender/receiver validation
- local inbox
- delivery receipt skeleton

Exit criteria:

- One local agent can send an opaque payload to another local agent.
- CLI can show delivery metadata without showing payload.

## Phase 7 - Pairing And Trust

Status: not_started

Goal:

Create the trust-forming flow between runtimes.

Deliverables:

- `conu pair`
- `conu join <code>`
- pairing code lifecycle
- trust entry
- peer revocation command if needed

Exit criteria:

- Pairing creates trusted peer records.
- Trust can be listed and revoked.

## Phase 8 - WebSocket Relay MVP

Status: not_started

Goal:

Make conU work across the internet through a relay-first transport.

Deliverables:

- relay service crate
- runtime relay client
- relay session auth
- peer rendezvous
- encrypted envelope forwarding path

Exit criteria:

- Two runtimes can connect through relay.
- Relay forwards only opaque envelopes.
- Relay logs do not contain payloads.

## Phase 9 - Remote Discovery And Sessions

Status: not_started

Goal:

Let paired runtimes discover allowed remote agents and maintain sessions.

Deliverables:

- remote agent cards
- presence sync
- session manager
- reconnect loop
- route metadata

Exit criteria:

- `conu agents` shows trusted remote agents.
- Presence changes propagate.
- Sessions reconnect after interruption.

## Phase 10 - Streams And Watch Animation

Status: not_started

Goal:

Add stream support and the private CLI animation showing agent traffic flow.

Deliverables:

- stream ids
- stream open/write/close
- backpressure windows
- watch event bus
- CLI animation

Exit criteria:

- Agents can open streams.
- `conu watch` shows traffic metadata only.
- No payload text appears in watch output.

## Phase 11 - Encryption Hardening

Status: not_started

Goal:

Make payload and session security production-grade.

Deliverables:

- peer key exchange
- signed agent cards
- replay protection
- encrypted payload storage
- key rotation plan

Exit criteria:

- Payloads are encrypted before relay transit.
- Trust verification is explicit.
- Revoked peers cannot communicate.

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
```
