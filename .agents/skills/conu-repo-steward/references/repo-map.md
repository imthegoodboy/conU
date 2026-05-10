# conU Repo Map

## Current Planning Files

```txt
architecture.md
  target architecture and protocol direction

plan.md
  living phase plan and completion log

.agents/
  future-agent memory, rules, and skills
```

## Rust Workspace

```txt
crates/conu-cli
  CLI commands, ASCII dashboard, stream/watch animation, user control flow

crates/conud
  daemon process, local gateway/message/session processing, session manager, runtime lifecycle

crates/conu-core
  local state, security keys/encryption/signatures/replay, runtime lifecycle, agent registry, local message routing, stream metadata, trust store, relay frame contract, remote session mirror, future policy logic

crates/conu-protocol
  envelopes, agent cards, control-plane messages, data-plane messages

crates/conu-relay
  std-only WebSocket relay service, session auth, metadata-only forwarding, relay/bootstrap groundwork

crates/conu-sdk
  agent gateway clients later
```

## Placement Rule

If a file is meant to guide future agents, put it under `.agents/`. If it is product architecture, update `architecture.md`. If it is execution status, update `plan.md`.
