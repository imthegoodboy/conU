---
name: conu-repo-steward
description: Understand and maintain the conU repository structure, project memory, file organization, implementation boundaries, and future-agent onboarding. Use at the start of repository work, when adding folders/files, when reorganizing code or docs, or when a future agent needs to understand where things belong.
---

# conU Repo Steward

Use this skill before changing repository structure or when starting unfamiliar work.

## Required Reading

1. `.agents/repo/ABOUT.md`
2. `architecture.md`
3. `plan.md`
4. `.agents/AGENTS.md`

Read references as needed:

- `references/repo-map.md` for intended file layout.
- `references/working-rules.md` for day-to-day agent rules.

## Stewardship Rules

- Keep project memory inside `.agents/`.
- Keep user/product docs at repo root only when they are meant for humans outside agent workflows.
- Keep implementation phase status in `plan.md`.
- Keep protocol, runtime, CLI, relay, and SDK boundaries separate.
- Do not create random one-off notes when a structured existing file should be updated.
- Do not mark work complete without validation notes.

## When Adding Files

Choose the right home:

```txt
architecture/design target -> architecture.md
phase status -> plan.md
future-agent instructions -> .agents/
Rust code -> crates/
CLI code -> crates/conu-cli/
daemon code -> crates/conud/
protocol types -> crates/conu-protocol/
relay service -> crates/conu-relay/
shared runtime code -> crates/conu-core/
```

## Handoff Rule

Leave the next agent able to answer:

```txt
What phase are we in?
What changed?
What was validated?
What is still risky?
What should happen next?
```
