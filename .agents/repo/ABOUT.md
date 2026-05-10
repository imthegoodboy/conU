# conU Repository Overview

This repository contains conU, an agent-native encrypted communication layer.

conU is not an agent framework. It is the runtime, protocol, CLI, and network layer that lets trusted agents discover each other, connect, send opaque messages, stream events, and maintain sessions across machines.

## Current State

The repository has completed Phase 6.

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
- persisted local agent registry with capability metadata
- local opaque envelope submission through `conu messages send --stdin`
- local recipient inbox listing through `conu messages inbox`
- metadata-only delivery receipts through `conu messages receipts`
- conUD processing for local message delivery
- payload-safe status and agent registry reporting
- payload-safe runtime and agent metadata logs
- payload-safe message delivery metadata logs
- payload-safe protocol scaffold
- daemon and relay placeholder binaries

Current important files:

- `architecture.md`: production architecture and protocol direction.
- `plan.md`: phase-by-phase execution plan.
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
|- conu-relay/     hosted relay/bootstrap service
`- conu-sdk/       agent-facing client libraries later
```

Current Rust crates:

- `crates/conu-cli`
- `crates/conud`
- `crates/conu-core`
- `crates/conu-protocol`
- `crates/conu-relay`

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
