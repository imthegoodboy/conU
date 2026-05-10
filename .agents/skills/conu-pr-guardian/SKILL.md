---
name: conu-pr-guardian
description: Review conU changes before pull request, branch merge, or merge to main. Use for pre-merge checks, PR readiness, code review, branch hygiene, validation, plan.md updates, privacy-safe output checks, and deciding whether changes are safe to merge.
---

# conU PR Guardian

Use this skill before opening a PR, merging a branch, or declaring work ready.

## Required Reading

1. `architecture.md`
2. `plan.md`
3. `.agents/Rules/SKILL.MD`
4. `.agents/skills/conu-security-guardian/SKILL.md` if the change touches protocol, networking, relay, storage, logging, encryption, CLI watch, IPC, SDK, or permissions.

References:

- `references/pre-merge-checklist.md`
- `references/review-template.md`

## Review Stance

Lead with blockers and risks. Do not bury important findings under summaries.

Check:

- Does the change preserve conU's product law?
- Does it keep payloads opaque?
- Does it fit the active phase?
- Does it update `plan.md` when phase status changed?
- Does it avoid unrelated refactors?
- Does it include tests or validation appropriate to risk?
- Does it preserve user changes and avoid destructive git operations?

## Merge Rule

Do not recommend merge when:

- payloads are logged or displayed
- relay can read plaintext payloads without explicit design approval
- trust/permission checks are bypassed
- tests were skipped without a recorded reason
- `plan.md` is stale for completed phase work
- branch contains unrelated or unexplained changes

## Output Shape

Use this order:

1. Blockers
2. Important risks
3. Validation status
4. Plan/doc status
5. Merge recommendation
