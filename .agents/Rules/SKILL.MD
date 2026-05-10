---
name: conu-rules
description: Project rules for future agents working on conU. Use when editing conU architecture, Rust implementation, CLI behavior, daemon/runtime code, protocol design, relay behavior, privacy boundaries, agent gateway behavior, or phase planning.
---

# conU Rules

## Core Law

```txt
Agents own the conversation.
conU owns the connection.
```

## What conU Must Be

- A Rust runtime and protocol for agent-to-agent communication.
- A neutral encrypted network layer.
- A local daemon that agents connect to.
- A private road between trusted agents.
- A CLI that shows status, presence, pairing, and transport flow.

## What conU Must Not Be

- Not a chatbot.
- Not an agent brain.
- Not an orchestrator.
- Not a prompt framework.
- Not a message reader.
- Not a payload modifier.
- Not a central AI service.

## Payload Privacy

Never expose private payloads in:

- CLI output
- logs
- telemetry
- traces
- tests
- examples
- docs screenshots

The CLI may show metadata:

```txt
from, to, route, latency, stream id, byte count, packet count, delivery state
```

The CLI must not show:

```txt
message text, reasoning, memory, tool results, file contents
```

## Future Agent Rule

Every future agent must read `architecture.md` and `plan.md` before implementation, then update `plan.md` after completing a phase.

## PR And Merge Rule

Before opening a PR or merging to `main`, use `.agents/skills/conu-pr-guardian/SKILL.md`.

For any protocol, networking, relay, storage, logging, telemetry, CLI watch, SDK, IPC, encryption, identity, permission, or trust change, also use `.agents/skills/conu-security-guardian/SKILL.md`.

Never recommend merge if private payloads can appear in CLI output, logs, telemetry, relay storage, or tests as real content.
