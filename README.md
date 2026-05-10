# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Status

Phase 2 is complete. The CLI identity and dashboard shell exists; Phase 3 will add real local identity and persistent state.

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

Useful CLI commands:

```bash
cargo run -p conu-cli --
cargo run -p conu-cli -- init
cargo run -p conu-cli -- status
cargo run -p conu-cli -- agents
cargo run -p conu-cli -- pair
cargo run -p conu-cli -- join 482913
cargo run -p conu-cli -- connect
cargo run -p conu-cli -- watch
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
