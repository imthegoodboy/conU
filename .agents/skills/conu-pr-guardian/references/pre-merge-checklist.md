# Pre-Merge Checklist

## Git Hygiene

- Check `git status --short`.
- Identify untracked files.
- Identify files changed by the agent versus pre-existing user changes.
- Do not revert unrelated user changes.
- Keep branch scope aligned to the phase or PR goal.

## Architecture Fit

- Change aligns with `architecture.md`.
- CLI remains a control room, not a message viewer.
- conUD remains the runtime/router.
- Agent Gateway remains the local entrance for agents.
- Protocol keeps control plane and data plane distinct.

## Privacy And Security

- No plaintext payload in CLI output.
- No plaintext payload in logs/traces/metrics.
- No plaintext payload in tests/examples unless explicitly artificial and labeled.
- Trust checks exist before cross-agent or cross-node communication.
- Permission checks are not skipped.
- Relay does not need payload visibility.

## Validation

Run what exists for the phase:

```txt
cargo fmt
cargo check
cargo test
unit tests
integration tests
manual CLI smoke test
```

If a command cannot run, record why.

## Docs And Plan

- `plan.md` updated if phase status changed.
- Architecture docs updated if design changed.
- Agent skills updated if workflow changed.
- Completion log updated when phase is complete.

## Merge Decision

Use one of:

```txt
merge_ready
merge_ready_with_notes
needs_fix
blocked
```
