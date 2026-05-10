---
name: conu-builder
description: Build and maintain the conU Rust CLI, daemon, protocol, agent gateway, relay, SDK, and project documentation. Use when working inside the conU repository on architecture, implementation, planning, agent communication, privacy, CLI UX, networking, runtime behavior, or future-agent handoff.
---

# conU Builder

Use this skill when working on conU.

## Required Reading

Before implementation, read:

1. `architecture.md`
2. `plan.md`
3. `.agents/Rules/SKILL.MD`
4. `.agents/Pr/SKILL.MD`

Use reference files only when needed:

- `references/implementation-guardrails.md` for engineering rules.
- `references/agent-gateway-contract.md` for how agents should access conU.
- `references/cli-experience.md` for CLI behavior and privacy-safe animation.

## Product Law

```txt
Agents own the conversation.
conU owns the connection.
```

conU must not inspect, rewrite, summarize, classify, judge, or modify agent messages. conU transports opaque envelopes between trusted agents.

## Default Workflow

1. Read the current phase in `plan.md`.
2. Inspect existing code and docs before deciding.
3. Keep changes scoped to the active phase unless the user asks otherwise.
4. Preserve payload privacy in CLI, logs, telemetry, tests, and docs.
5. Prefer Rust, Tokio, clap, structured protocol types, local IPC, and clear module boundaries.
6. Add or update tests when behavior changes.
7. Run available validation.
8. Update `plan.md` before finishing a completed phase.

## Build Shape

The project should grow around these boundaries:

```txt
conu CLI
  human control room

conUD
  local runtime and router

Agent Gateway
  local entrance for agents

Protocol
  control plane + data plane

Network
  WebSocket relay first, QUIC/direct later
```

## Non-Negotiables

- Keep payloads opaque.
- Show transport flow, not message contents.
- Keep trust local-first and revocable.
- Separate control plane from data plane.
- Make CLI beautiful but honest.
- Make future phases easy to resume from `plan.md`.
