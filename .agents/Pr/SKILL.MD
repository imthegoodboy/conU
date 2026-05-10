---
name: conu-project-runtime
description: Project runtime and protocol memory for conU. Use when future agents need to understand the conU product shape, runtime flow, protocol layers, CLI goal, build order, and how agents should communicate through conU.
---

# conU Project Runtime

## Product Shape

```txt
Agent
  -> Agent Gateway
  -> local conUD
  -> encrypted conU network
  -> remote conUD
  -> Agent Gateway
  -> remote Agent
```

## Main Parts

- `conu` CLI: human control room.
- `conUD`: local daemon and router.
- Agent Gateway: local API/IPC/SDK/MCP adapter for agents.
- Protocol: control plane and data plane.
- Relay: pairing, discovery, NAT fallback, offline handoff.
- Trust Store: local identities, trusted peers, permissions, revocations.

## Control Plane

Handles:

- identity
- pairing
- trust
- discovery
- capabilities
- presence
- session lifecycle
- route negotiation

## Data Plane

Handles:

- opaque messages
- streams
- events
- rooms
- subscriptions
- files later
- delivery receipts
- flow control

## Best Build Order

Build in resumable phases:

1. project memory and architecture
2. Rust workspace scaffold
3. CLI identity and dashboard
4. local identity and persistent state
5. conUD daemon skeleton
6. local IPC and agent registration
7. opaque envelope send/receive
8. pairing and trust store
9. WebSocket relay
10. remote discovery and sessions
11. streams and watch animation
12. encryption hardening
13. SDK/MCP adapter
14. QUIC/direct transport
15. packaging and production readiness

Always check `plan.md` for the active phase before changing code.

## Required Skills By Situation

- Starting repo work: `.agents/skills/conu-repo-steward/SKILL.md`
- Implementing product code: `.agents/skills/conu-builder/SKILL.md`
- Updating phase status: `.agents/skills/conu-phase-keeper/SKILL.md`
- Preparing PR or merge: `.agents/skills/conu-pr-guardian/SKILL.md`
- Reviewing security/privacy: `.agents/skills/conu-security-guardian/SKILL.md`
