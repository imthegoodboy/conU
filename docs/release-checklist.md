# conU Release Checklist

Use this checklist before publishing any conU build.

## Version And Scope

- Confirm the release version in all Cargo packages.
- Confirm `plan.md` reflects the completed phase and known gaps.
- Confirm Phase 14 rooms are not claimed unless implemented.
- Confirm public internet data-plane delivery is not claimed until live relay/direct byte transport exists.

## Build

Windows:

```powershell
cargo fmt --all -- --check
cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu test --workspace
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

macOS/Linux:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/build-release.sh
```

## Smoke

```powershell
.\scripts\smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Manual installed smoke:

```sh
conu init
conu security audit
conu doctor
conu start
conu status
conu pair
conu join <code>
conu routes sync
conu connect
conu stop
```

## Privacy And Security

- `conu doctor` reports payload-safe logs.
- `conu security audit` reports initialized local controls.
- CLI output does not show message text, prompt text, reasoning, file contents, private keys, shared secrets, or raw payload bytes.
- Logs use metadata-only fields such as `payload=not_observed`.
- Release archives do not include `CONU_HOME`, `.conu`, `node.toml`, `security/*.key`, `messages/`, `runtime/`, `logs/`, or `routes/` from a developer machine.
- MCP stdout remains JSON-RPC only.
- `conu_receive_message` and SDK receive APIs return payload bytes only to the addressed local agent by explicit request.

## Packaging

- Release archive includes `bin/conu`, `bin/conud`, `bin/conu-relay`, and `bin/conu-mcp`.
- Release archive includes docs and packaging templates.
- `manifest.toml` contains `payload_contents_included = false`.
- Windows install script copies binaries to a current-user install directory.
- Linux systemd template is present and documents the required user/state path edits.
- macOS launchd template is present and documents the required user/state path edits.

## GitHub

- CI passed on pull request or equivalent local validation is recorded.
- PR body lists validation commands.
- `plan.md` completion log is updated.
- Issue is closed by PR merge.

## Release Decision

Use one of:

```txt
local_release_ready
needs_fix
blocked
```

Current Phase 15 decision target is `local_release_ready`. Public hosted/internet release remains blocked until live encrypted remote data-plane delivery, OS-backed key storage, capability policy, and remote signed agent-card exchange are finished.
