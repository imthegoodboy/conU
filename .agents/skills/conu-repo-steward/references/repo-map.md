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
  CLI commands, ASCII dashboard, watch animation, user control flow

crates/conud
  daemon process, local gateway processing, session manager, runtime lifecycle

crates/conu-core
  local state, runtime lifecycle, agent registry, gateway processing, future trust/policy logic

crates/conu-protocol
  envelopes, agent cards, control-plane messages, data-plane messages

crates/conu-relay
  hosted relay/bootstrap service, pairing rendezvous, encrypted forwarding

crates/conu-sdk
  agent gateway clients later
```

## Placement Rule

If a file is meant to guide future agents, put it under `.agents/`. If it is product architecture, update `architecture.md`. If it is execution status, update `plan.md`.
