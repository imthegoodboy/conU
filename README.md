# conU

conU is a private communication layer for autonomous agents.

It gives trusted agents a way to find each other, exchange opaque messages, stream work events, and use a relay when direct networking is not available. conU is not an agent framework, prompt system, chatbot, or orchestrator. Agents keep their own logic and conversation; conU owns the connection between them.

```txt
Agents own the conversation.
conU owns the connection.
```

## What It Does

- Registers local agents with stable metadata and capabilities.
- Stores local identity, trusted peers, and peer-scoped permissions.
- Sends opaque local messages between registered agents.
- Moves peer-encrypted envelopes across direct routes or a WebSocket relay.
- Supports streams, rooms, pub/sub metadata, delivery receipts, and inbox reads.
- Exposes a Rust CLI/runtime, Rust SDK, Python wrapper, TypeScript SDK, and MCP adapter.
- Keeps CLI output, logs, telemetry, relay storage, and docs payload-safe.

## Fast Path

After public release assets are published:

```sh
npm install -g @imthegoodboy/conu
conu doctor
```

From a development checkout:

```sh
cargo run -p conu-cli -- doctor
cargo run -p conud -- --check
cargo run -p conu-relay -- --check
```

## Quick Start

Create local state:

```sh
conu init
```

Register two local agents:

```sh
conu agents register agent.alpha "Alpha" --kind coding-agent --streams true --rooms true
conu agents register agent.beta "Beta" --kind coding-agent --streams true --rooms true
```

Send an opaque message:

```sh
printf "private bytes" | conu messages send agent.alpha agent.beta --stdin
conu messages wait agent.beta --process-ipc --timeout-ms 30000 --json
conu messages inbox agent.beta --json
conu messages history agent.beta --limit 20 --json
printf "reply bytes" | conu messages reply agent.beta <envelope-id> --stdin
conu messages receive agent.beta <envelope-id> --output received.bin
conu messages receipts --json
```

Open a local stream:

```sh
conu streams open agent.alpha agent.beta
printf "progress bytes" | conu streams write <stream-id> --stdin
conu watch
```

Create a room:

```sh
conu rooms create room.dev "Dev Room" --agent agent.alpha
conu rooms join room.dev agent.beta
printf "event bytes" | conu rooms publish room.dev agent.alpha build --stdin
conu rooms events
```

## Remote Agents

Remote use starts with explicit trust and policy. Each node exports a public peer card, imports the other node, grants the allowed surfaces, then sends through a direct route or relay.

```sh
conu identity export --json
conu peers trust <peer-node-id> "<peer name>" --exchange-key <hex> --relay wss://<relay-host>/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
conu start
printf "private bytes" | conu messages send agent.alpha agent.remote --peer <peer-node-id> --stdin
```

For a hosted relay, this repo includes a Render Blueprint:

```txt
render.yaml
docs/render-relay-hosting.md
```

The relay should be treated as transport infrastructure. It sees routing metadata and ciphertext, not plaintext message contents.

## Agent Integrations

- Rust SDK: `crates/conu-sdk`
- TypeScript/JavaScript SDK: `sdk/typescript`
- Python wrapper: `sdk/python`
- MCP adapter: `crates/conu-mcp`
- Agent usage skill: `.agents/skills/conu-agent-user/SKILL.md`

MCP-capable agents can run `conu-mcp` over stdio. SDKs and MCP tools keep list/status output metadata-only. Payload bytes are returned only through explicit addressed-agent receive calls.

## Privacy Model

conU transports opaque envelopes. It may observe metadata needed for delivery:

```txt
from, to, route, stream id, byte count, packet count, delivery state, timestamps
```

It must not display or log private content:

```txt
message text, reasoning, memory, tool output, file contents, secrets
```

Runtime logs, telemetry, relay dashboards, readiness checks, and CLI watch views are designed around `payload=not_observed`.

## Project Layout

```txt
crates/conu-cli       human control-room CLI
crates/conud          local daemon and router
crates/conu-relay     WebSocket relay service
crates/conu-sdk       Rust SDK
crates/conu-mcp       MCP stdio adapter
crates/conu-core      shared runtime primitives
crates/conu-protocol  identities, cards, and envelope types
sdk/typescript        Node.js SDK package
sdk/python            Python wrapper
packaging/            release, npm, Docker, and service packaging
docs/                 deeper setup and operator guides
site/                 minimal download page
```

## Useful Commands

```sh
conu status
conu agents
conu agents --json
conu messages inbox <agent-id> --json
conu messages history <agent-id> --limit 20 --json
conu messages reply <agent-id> <envelope-id> --stdin
conu messages wait <agent-id> --timeout-ms 30000 --json
conu messages receive <agent-id> <envelope-id> --output <file>
conu messages receipts --json
conu relay sync --wait-ms 3000
conu streams open <from-agent> <to-agent>
conu rooms create <room-id> "<name>" --agent <agent-id>
conu watch
conu security audit --json
conu telemetry snapshot --json
conu doctor --json
```

## Development

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run check --prefix sdk/typescript
npm run check --prefix packaging/npm/conu-cli
python scripts/check-deployment-assets.py
```

On Windows without Visual Studio C++ Build Tools, Rust commands that link binaries or tests may need the GNU toolchain:

```sh
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

 
