---
name: conu-phase-keeper
description: Maintain conU phase discipline and update plan.md. Use when starting, pausing, completing, or revising a build phase; when handoff context is needed; or when future agents need to know current status, validation, changed files, gaps, and next work.
---

# conU Phase Keeper

Use this skill whenever phase status changes.

## Required Reading

1. `plan.md`
2. `architecture.md`
3. `.agents/repo/ABOUT.md`

Reference:

- `references/plan-update-template.md`

## Phase Rules

- Work from the current phase unless the user explicitly redirects.
- Do not mark a phase complete until implementation exists and validation was attempted.
- If validation cannot run, record the exact reason.
- Keep known gaps honest.
- Do not hide blockers.
- Add a completion log entry when a phase is completed.

## Required Plan Update Fields

When updating a phase, include:

```txt
Status
Completed work
Files changed
Validation
Known gaps
Next recommendation
```

## Completion Rule

A future agent should be able to resume from `plan.md` without reading the whole conversation.
