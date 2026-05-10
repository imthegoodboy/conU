# conU Agent Onboarding

This folder is the project memory for future agents working on conU.

Before changing code, read these files in order:

1. `architecture.md`
2. `plan.md`
3. `.agents/repo/ABOUT.md`
4. `.agents/skills/conu-repo-steward/SKILL.md`
5. `.agents/skills/conu-builder/SKILL.md`
6. `.agents/Rules/SKILL.MD`
7. `.agents/Pr/SKILL.MD`

Core rule:

```txt
Agents own the conversation.
conU owns the connection.
```

Do not build conU as a chatbot, prompt manager, workflow orchestrator, or message inspector. Build it as an encrypted runtime and protocol that lets trusted agents discover, connect, message, stream, and observe transport state without exposing private payloads.

Every meaningful implementation phase must end by updating `plan.md` with:

- completed work
- files changed
- validation run
- known gaps or blockers
- next phase recommendation

## Skill Index

- `.agents/skills/conu-repo-steward/`: understand repo structure and file placement.
- `.agents/skills/conu-builder/`: implement conU features.
- `.agents/skills/conu-phase-keeper/`: update `plan.md` and phase handoff.
- `.agents/skills/conu-pr-guardian/`: check PRs and pre-merge readiness.
- `.agents/skills/conu-security-guardian/`: review privacy, trust, relay, logging, and payload opacity.

Before opening a PR or merging to main, use `conu-pr-guardian`. If the change touches protocol, networking, storage, relay, logging, telemetry, CLI watch, SDK, IPC, encryption, identity, or permissions, also use `conu-security-guardian`.
