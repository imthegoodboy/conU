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

0. project memory and architecture
1. Rust workspace scaffold
2. CLI identity and dashboard
3. local identity and persistent state
4. conUD daemon skeleton
5. local IPC and agent registration
6. opaque envelope send/receive
7. pairing and trust store
8. WebSocket relay
9. remote discovery and sessions
10. streams and watch animation
11. encryption hardening
12. SDK/MCP adapter
13. direct transport and NAT route manager
14. rooms, pub/sub, and multi-agent sessions
15. packaging and production readiness

Always check `plan.md` for the active phase before changing code.

## Required Skills By Situation

- Starting repo work: `.agents/skills/conu-repo-steward/SKILL.md`
- Implementing product code: `.agents/skills/conu-builder/SKILL.md`
- Updating phase status: `.agents/skills/conu-phase-keeper/SKILL.md`
- Preparing PR or merge: `.agents/skills/conu-pr-guardian/SKILL.md`
- Reviewing security/privacy: `.agents/skills/conu-security-guardian/SKILL.md`
