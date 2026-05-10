# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Phase

Phase 1: Rust workspace scaffold.

The repository currently contains compile-ready crate boundaries for:

- `conu-cli`: human control room.
- `conud`: local daemon/runtime scaffold.
- `conu-core`: shared runtime primitives and project invariants.
- `conu-protocol`: protocol identities, agent cards, and opaque envelopes.
- `conu-relay`: relay/bootstrap scaffold.

This phase is intentionally std-only so the workspace validates on Windows machines that have Rust installed but do not yet have the Visual Studio C++ linker/Windows SDK configured. Production dependencies such as clap, Tokio, tracing, and serde should be introduced in the relevant future phases once linker support is available locally or in CI.

## Development

```bash
cargo fmt
cargo check
cargo test
```

On Windows machines without Visual Studio C++ Build Tools, use the GNU Rust toolchain for commands that link binaries or tests:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

Useful scaffold commands:

```bash
cargo run -p conu-cli -- status
cargo run -p conu-cli -- components
cargo run -p conud -- --check
cargo run -p conu-relay -- --check
```

## Project Memory

Future agents should read:

1. `architecture.md`
2. `plan.md`
3. `.agents/AGENTS.md`
4. `.agents/repo/ABOUT.md`

Before PR or merge, use the repo-local PR and security guardian skills under `.agents/skills/`.
