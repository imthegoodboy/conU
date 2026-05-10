# Implementation Guardrails

## Architecture Boundaries

- CLI is the human control room.
- conUD is the runtime and router.
- Agent Gateway is the local entrance for agents.
- Protocol types define stable control-plane and data-plane messages.
- Relay helps discovery and delivery, but does not read payloads.

## Rust Defaults

- Use Rust for runtime, CLI, protocol, and relay components.
- Use Tokio for async runtime.
- Use clap for CLI parsing.
- Use serde for config and local state.
- Use binary protocol encoding for runtime hot paths when the protocol stabilizes.
- Use WebSocket relay first for worldwide connectivity.
- Add QUIC/direct transport after core semantics are stable.

## Local Windows Toolchain Note

This workspace was first validated on Windows where the default MSVC Rust toolchain existed but Visual Studio C++ Build Tools / `link.exe` were not available. In that environment:

- `cargo check --workspace --all-targets` works with the default MSVC toolchain for std-only code.
- `cargo test` and `cargo run` require a linker.
- `rustup toolchain install stable-x86_64-pc-windows-gnu` provided a working local linker path.
- Use `cargo +stable-x86_64-pc-windows-gnu test --workspace` and matching `cargo +... run` commands until MSVC Build Tools or CI are configured.

Do not add proc-macro/build-script-heavy dependencies unless validation can still run in the active environment or CI.

## Local State Rules

- `CONU_HOME` overrides the default state directory and should be used for smoke checks.
- Windows defaults to `%APPDATA%\conU`; non-Windows falls back to `$HOME/.conu`.
- Tests should pass an explicit state home instead of mutating global process environment.
- The Phase 3 node id is a local runtime identifier only. It is not a secret, not an authentication credential, and not a replacement for future signed/encrypted identity.
- conU-owned state must not store plaintext private payloads.

## Privacy Rules

- Never log plaintext payloads.
- Never show message text in CLI watch views.
- Never store plaintext payloads in conU-owned storage.
- Only expose metadata needed for routing, debugging, and delivery.
- Keep telemetry payload-safe: route, latency, packet count, stream count, bytes, retries, disconnect reason.

## Delivery Rules

- Use message ids and idempotency keys.
- Use receipts for important delivery state.
- Use bounded queues and backpressure for streams.
- Do not claim impossible exactly-once network delivery.
- Model exactly-once effects with receiver-side dedupe.

## Plan Discipline

At the end of each phase, update `plan.md` with status, changed files, validation, gaps, and next recommendation.
