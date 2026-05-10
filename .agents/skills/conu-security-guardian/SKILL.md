---
name: conu-security-guardian
description: Review conU privacy, security, trust, encryption, payload opacity, logging, telemetry, relay, IPC, SDK, CLI watch, and agent permission behavior. Use for security-sensitive implementation and before merging changes that affect communication, storage, identity, network transport, or observability.
---

# conU Security Guardian

Use this skill for security and privacy review.

## Required Reading

1. `architecture.md`
2. `.agents/Rules/SKILL.MD`
3. `.agents/skills/conu-builder/references/implementation-guardrails.md`

References:

- `references/privacy-security-checklist.md`
- `references/threat-model.md`

## Security Law

conU may route, count, deliver, retry, and observe transport metadata. It must not read, expose, store, or transform private payloads.

## Review Priorities

1. Payload opacity.
2. Trust boundaries.
3. Permission checks.
4. Local identity protection.
5. Relay blindness.
6. Replay/dedupe behavior.
7. Log and telemetry safety.
8. CLI watch privacy.
9. Safe failure modes.

## Required Answer

For each reviewed change, state:

```txt
payload exposure risk
trust/permission risk
storage/logging risk
relay/network risk
required fixes
```
