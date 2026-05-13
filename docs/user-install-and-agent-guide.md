# conU User Install And Agent Guide

This guide explains how a user can install the current conU app, start it on their PC, and let local agents use it.

Current version status: Phase 14 and Phase 15 are complete for the current local-first app, with rooms/pub-sub metadata, encrypted-at-rest local room event fanout, a stronger CLI dashboard/connect flow, and a relay-backed message path that runs from conUD when configured. conU is usable for local agent registration, local encrypted-at-rest message submission, local agent connect streams, room/pub-sub metadata and local fanout, manual public peer-card exchange, peer-encrypted one-shot relay messages between trusted nodes, stream metadata, trust metadata, direct/relay route metadata, private CLI watch output, Rust SDK calls, a Python wrapper SDK, an MCP stdio adapter, repeatable release builds, service templates, a native-binary npm launcher template, Docker relay hosting template, and `conu doctor` readiness checks. It is not yet a managed public hosted internet release.

## What Works Today

- Install from source with Rust or from a Phase 15 release artifact.
- Initialize local conU state and security keys.
- Start and stop the local `conUD` runtime.
- Register local agents by id.
- Send local opaque payload bytes from one registered local agent to another.
- Connect two local registered agents with `conu connect local`.
- Create room metadata, join local or mirrored trusted remote agents, and publish opaque room events by topic and byte count with local inbox fanout for joined local participants.
- Store new conU-owned local payload files encrypted at rest.
- List inbox, receipt, stream, peer, session, and security metadata.
- Sync and inspect direct QUIC route candidates and relay fallback metadata.
- Run a standalone `conu-relay` and let conUD move peer-encrypted one-shot messages through it when relay config or trusted peer relay endpoints exist.
- Export/import public peer cards for manual cross-machine trust.
- Let Rust agents use `conu_sdk::ConuClient`.
- Let Python agents use `sdk/python/conu_sdk`.
- Let MCP-capable agents launch `conu-mcp` and call conU tools.
- Run `conu doctor` to check local install readiness and payload-safe logs.
- Use Windows, systemd, and launchd service templates.
- Use the npm launcher packaging template once platform release assets are published.
- Host the current relay yourself for controlled `ws://` tests.

## What Does Not Work Yet

- No signed one-click installer yet.
- No published `@conu/cli` package yet; the package template exists under `packaging/npm/conu-cli` and should be published after GitHub Release assets/checksums exist.
- No TypeScript SDK yet.
- No CLI command that reveals message contents. This is intentional; use SDK or MCP explicit receive APIs when the addressed local agent needs payload bytes.
- Rooms currently provide local pub/sub coordination, encrypted-at-rest local fanout, and watch visibility. Relay-backed room event fanout is not implemented yet.
- No hosted relay service, TLS client, or managed public relay auth yet. The current client supports reachable `ws://` relay endpoints.
- No real QUIC socket or NAT hole punching yet; Phase 13 selects configured direct route candidates and relay fallback metadata.
- Pairing and remote sessions are local metadata groundwork, not full cross-machine rendezvous.
- Relay-backed one-shot message delivery exists through the conUD relay pump; persistent relay sessions, stream byte routing, hosted relay auth/TLS, and offline mailbox delivery are not implemented yet.
- Service templates exist, but users still need to install/register them for their platform.
- Local private keys are file-backed today; OS keychain/DPAPI/HSM support is still a release blocker.

## Install With npm

This is the best public install shape once the first GitHub Release and npm package are published:

```powershell
npm install -g @conu/cli
conu doctor
conu init
conu start
```

The npm package is not the conU implementation. It is a small launcher that downloads the native Rust archive for the user's platform, verifies the `.sha256` checksum, and exposes `conu`, `conud`, `conu-relay`, and `conu-mcp` on `PATH`.

For local testing of the package template from this repo:

```powershell
$env:CONU_NPM_BINARY_DIR = "$PWD\dist\conu-0.1.0-windows-x64\bin"
npm install -g .\packaging\npm\conu-cli
conu doctor
```

See `docs/distribution-and-hosting.md` for the release asset names, publish flow, and relay hosting path.

## Install From Source

### Requirements

- Git.
- Rust from `rustup`.
- On Windows without Visual Studio C++ Build Tools, install the GNU Rust toolchain:

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
```

### Clone The Repo

```powershell
git clone https://github.com/imthegoodboy/conU.git
cd conU
```

### Install The Binaries

Windows PowerShell:

```powershell
cargo +stable-x86_64-pc-windows-gnu install --path crates/conu-cli --locked --force
cargo +stable-x86_64-pc-windows-gnu install --path crates/conud --locked --force
cargo +stable-x86_64-pc-windows-gnu install --path crates/conu-relay --locked --force
cargo +stable-x86_64-pc-windows-gnu install --path crates/conu-mcp --locked --force
```

macOS/Linux shell, assuming the default toolchain links successfully:

```bash
cargo install --path crates/conu-cli --locked --force
cargo install --path crates/conud --locked --force
cargo install --path crates/conu-relay --locked --force
cargo install --path crates/conu-mcp --locked --force
```

Make sure Cargo's bin directory is on `PATH`.

Windows normally uses:

```txt
%USERPROFILE%\.cargo\bin
```

macOS/Linux normally uses:

```txt
$HOME/.cargo/bin
```

Check the install:

```powershell
conu --version
conud --check
conu-relay --check
conu doctor
```

`conu-mcp` is a stdio server for MCP clients, so it normally waits for JSON-RPC input instead of printing a standalone check screen.

## Install From A Release Artifact

Build or unpack a release artifact, then use the package scripts.

On Windows without Visual Studio C++ Build Tools, build artifacts with the GNU toolchain:

```powershell
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Windows current-user install:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin
```

Optional Windows service install from an elevated shell:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin -InstallService
```

Linux systemd:

```bash
sudo cp bin/conu bin/conud bin/conu-relay bin/conu-mcp /usr/local/bin/
sudo cp packaging/linux/conud.service /etc/systemd/system/conud.service
sudo systemctl daemon-reload
sudo systemctl enable --now conud
```

macOS launchd:

```bash
sudo cp bin/conu bin/conud bin/conu-relay bin/conu-mcp /usr/local/bin/
# Edit packaging/macos/com.conu.conud.plist and replace /Users/YOU first.
cp packaging/macos/com.conu.conud.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.conu.conud.plist
```

Edit the service template paths and user/state location before enabling a machine-wide service.

## First Run

Initialize local state and local security keys:

```powershell
conu init
conu security audit
conu status
conu doctor
```

Start conUD:

```powershell
conu start
conu status
```

Stop conUD:

```powershell
conu stop
```

If `conu start` cannot find `conud`, set `CONUD_EXE`:

```powershell
$env:CONUD_EXE = "$env:USERPROFILE\.cargo\bin\conud.exe"
conu start
```

For scripts and smoke checks, it is also valid to process queued gateway work without a long-running daemon:

```powershell
conud --process-ipc
```

## Register Local Agents

Choose stable ids for each local agent:

```powershell
conu agents register agent.codex "Codex Desktop" --kind coding-agent
conu agents register agent.helper "Helper Agent" --kind coding-agent
conu agents
```

If conUD is not running, process the queued registration requests:

```powershell
conud --process-ipc
conu agents --json
```

Agents can update presence:

```powershell
conu agents heartbeat agent.codex --presence busy
conud --process-ipc
```

## Send A Local Message

Send payload bytes through stdin. Do not put private payload text directly in command arguments.

PowerShell:

```powershell
"opaque bytes from agent.codex" | conu messages send agent.codex agent.helper --stdin
conud --process-ipc
conu messages inbox agent.helper --json
conu messages receipts --json
```

The inbox command shows metadata only: envelope id, sender, receiver, receipt id, byte count, and delivery time. It does not print the payload.

## Connect Two Local Agents

If two agents are on the same PC, register both and open a local metadata stream:

```powershell
conu agents register agent.codex "Codex Desktop" --kind coding-agent
conu agents register agent.hermes "Hermes" --kind coding-agent
conud --process-ipc
conu connect local agent.codex agent.hermes
conu watch
```

This gives the agents a conU connection surface and gives the user a live dashboard/watch view. The stream can record opaque chunks with:

```powershell
"opaque stream bytes" | conu streams write <stream-id> --stdin
```

The CLI shows stream id, route, packet count, and byte count. It does not show the stream bytes.

## Create A Local Room

Rooms are the current multi-agent coordination layer:

```powershell
conu rooms create room.dev "Dev Room" --agent agent.codex
conu rooms join room.dev agent.hermes
"opaque room bytes" | conu rooms publish room.dev agent.hermes build --stdin
conu rooms
conu rooms events
conu watch
```

Room commands show only room id, participants, topic, event id, route label, byte count, local delivery count, and timestamps. Room registry/events/log files do not store the room event payload; joined local recipients receive the opaque bytes as encrypted-at-rest event envelopes in their message inbox. Use rooms when several agents need a shared bus; use direct messages when one agent is addressing exactly one other agent.

## Sync Routes

Phase 13 lets conUD choose route metadata for trusted peers:

```powershell
conu pair
conu join <code>
conu routes sync
conu routes
conu routes --json
conu routes probes
```

To test a direct route candidate, add a direct endpoint to `config.toml`:

```toml
default_relay = "ws://127.0.0.1:8787"
relay_auto_sync = true
nat_profile = "public"
direct_quic_endpoint = "quic://127.0.0.1:9443"
```

Use a peer-specific sanitized key when one peer needs its own endpoint:

```toml
direct_quic_peer_abcd1234 = "quic://203.0.113.10:9443"
```

`conu routes sync` writes only route metadata. It does not print, log, or inspect message contents.

## Send A Remote Relay Message

Start a reachable relay. For local testing:

```powershell
$env:CONU_RELAY_TOKEN = "local-dev-token"
conu-relay --serve 0.0.0.0:8787
```

On each node, set `default_relay` in `config.toml` or pass the relay endpoint when trusting a peer. `relay_auto_sync = true` is the default for new state and lets conUD pump relay send/receive automatically when a relay route is configured. Then exchange public cards:

```powershell
conu identity export --json
conu peers trust <peer-node-id> "<peer name>" --exchange-key <exchange-public-key-hex> --relay ws://<relay-host>:8787
```

Start conUD and register a local agent on each side:

```powershell
conu start
conu agents register agent.local "Local Agent" --kind test-agent
```

On the sender:

```powershell
"opaque bytes for the remote agent" | conu messages send agent.sender agent.remote --peer <receiver-node-id> --stdin
```

On the receiver:

```powershell
conu messages inbox agent.remote --json
```

The running daemon performs relay send/receive in bounded sync windows and retries on failures. The explicit `conu relay sync` command still exists for manual flushes, debugging, or daemonless scripts; it shows counts and route metadata only. It does not show message contents. For a full two-terminal walkthrough, see `docs/internet-relay-test.md`.

## Give conU To An Agent

Agents can use conU through MCP, Rust, Python, or direct CLI calls.

### MCP Agent Setup

Add `conu-mcp` to the agent's MCP server config:

```json
{
  "mcpServers": {
    "conu": {
      "command": "conu-mcp",
      "env": {
        "CONU_HOME": "C:\\Users\\you\\AppData\\Roaming\\conU",
        "CONU_AGENT_ID": "agent.mybot"
      }
    }
  }
}
```

Tell the MCP agent:

```txt
Use conU tools for communication.

Rules:
- Launch one `conu-mcp` server per agent and set `CONU_AGENT_ID`.
- Register once with conu_register_agent.
- Use conu_set_presence when your state changes.
- Discover local and trusted remote metadata with conu_list_agents and conu_list_peers.
- Exchange public peer cards with conu_export_identity and conu_trust_peer when setting up remote trust.
- Sync and inspect route metadata with conu_sync_routes and conu_list_routes.
- Send opaque bytes with conu_send_message.
- Send remote peer-encrypted bytes with conu_send_remote_message while conUD is running; call conu_relay_sync only for manual flush/debug flows.
- Read inbox metadata first; request payloadHex only with conu_receive_message when you are the addressed local agent.
- Use conu_open_stream, conu_write_stream, and conu_close_stream for stream metadata flows.
- Use conu_create_room, conu_join_room, conu_publish_room_event, conu_list_rooms, and conu_list_room_events for shared room/pub-sub metadata and local fanout.
- Treat conU as the road, not the conversation.
```

### Rust Agent Setup

Inside this workspace, Rust agents can depend on:

```toml
conu-sdk = { path = "crates/conu-sdk" }
```

Minimal usage:

```rust
use conu_sdk::ConuClient;

let client = ConuClient::new();
client.init()?;
client.register_agent("agent.mybot", "My Bot", "local-agent")?;
client.process_queued()?;
client.send_message_bytes("agent.mybot", "agent.other", b"opaque bytes")?;
client.send_remote_message_bytes("agent.mybot", "agent.remote", "node_peer", b"opaque bytes")?;
client.create_room("room.dev", "Dev Room", "agent.mybot")?;
client.join_room("room.dev", "agent.other")?;
client.publish_room_event_bytes("room.dev", "agent.mybot", "build", b"opaque bytes")?;
client.relay_sync(std::time::Duration::from_millis(3000))?;
```

### Python Agent Setup

For local development:

```powershell
$env:PYTHONPATH = "$PWD\sdk\python"
```

```python
from conu_sdk import ConuClient

client = ConuClient(home=".conu-agent")
client.init()
client.register_agent("agent.mybot", "My Bot")
client.process_queued()
client.send_message("agent.mybot", "agent.other", b"opaque bytes")
client.send_remote_message("agent.mybot", "agent.remote", "node_peer", b"opaque bytes")
client.create_room("room.dev", "Dev Room", "agent.mybot")
client.join_room("room.dev", "agent.other")
client.publish_room_event("room.dev", "agent.mybot", "build", b"opaque bytes")
client.relay_sync(wait_ms=3000)
```

### CLI Agent Fallback

Give the agent this operating contract:

```txt
You may use conU as a local communication transport.

Rules:
- Register once at startup:
  conu agents register <agent-id> <display-name> --kind <kind>
- Refresh presence when your state changes:
  conu agents heartbeat <agent-id> --presence <ready|busy|idle|offline>
- Send payload bytes through stdin only:
  <payload bytes> | conu messages send <your-agent-id> <target-agent-id> --stdin
- Connect to a local peer:
  conu connect local <your-agent-id> <target-agent-id>
- Use rooms for shared coordination:
  conu rooms create <room-id> <display-name> --agent <your-agent-id>
  conu rooms join <room-id> <target-agent-id>
  <payload bytes> | conu rooms publish <room-id> <your-agent-id> <topic> --stdin
- Use JSON commands for machine-readable metadata:
  conu status --json
  conu agents --json
  conu rooms --json
  conu rooms events --json
  conu identity export --json
  conu messages inbox <agent-id> --json
  conu messages receipts --json
  conu security audit --json
- For remote delivery, import a peer card once:
  conu peers trust <peer-node-id> <display-name> --exchange-key <hex> --relay <ws://host:port>
- Send remote payload bytes through stdin only:
  <payload bytes> | conu messages send <your-agent-id> <target-agent-id> --peer <peer-node-id> --stdin
- Keep conUD running for relay delivery:
  conu start
- Optional manual flush/receive:
  conu relay sync --wait-ms 3000
- Never expect conU CLI output to show message contents.
- Treat conU as the road, not the conversation.
```

For local testing, a wrapper script can call:

```powershell
conu agents register agent.mybot "My Bot" --kind local-agent
conu agents register agent.other "Other Agent" --kind local-agent
conud --process-ipc
"hello as opaque bytes" | conu messages send agent.mybot agent.other --stdin
conud --process-ipc
conu messages inbox agent.other --json
```

## Current App Issues To Know

These are not hidden bugs; they are the honest state of the current app:

| Area | Current issue | User impact | Workaround today |
| --- | --- | --- | --- |
| Installer | Release artifact scripts exist, but packages are not signed | Users must trust a source build or unsigned artifact | Use `cargo install --path` or inspect/build artifacts locally |
| npm install | `@conu/cli` template exists but is not published until release assets are attached | `npm install -g @conu/cli` is the target path, not a live package guarantee yet | Use source install or a local `CONU_NPM_BINARY_DIR` package test |
| Windows linker | Default MSVC toolchain may fail without `link.exe` | `cargo check/test/install` can fail | Use `stable-x86_64-pc-windows-gnu` or install Visual Studio C++ Build Tools |
| Runtime discovery | `conu start` needs `conud` beside `conu` or on PATH | Start can fail after manual binary moves | Install both with Cargo or set `CONUD_EXE` |
| Agent API | Rust SDK, Python wrapper, and MCP adapter exist; TypeScript is later | Most agents can integrate now, TS apps need wrapper work | Use MCP, Rust SDK, Python SDK, or CLI/stdin |
| Receiving payloads | CLI intentionally lists inbox metadata only | Agents needing bytes must use explicit receive APIs | Use Rust SDK `receive_message_bytes` or MCP `conu_receive_message` with `includePayload` |
| Internet messaging | One-shot relay messages work through the conUD relay pump, but no hosted relay/TLS client, persistent relay session, stream byte routing, or offline mailbox exists | Users can test over reachable `ws://`; managed public network is not ready | Run `conu-relay` yourself on a trusted host or private network path |
| Direct transport | Route selection exists, but real QUIC sockets and NAT hole punching do not | Direct routes show as metadata only | Configure direct endpoints for route scoring tests |
| Pairing | Pair/join are local trust groundwork | Not real cross-machine pairing yet | Use for metadata/trust testing |
| Service install | Service templates exist but need local edits/admin steps | User must choose service path/user | Use `packaging/windows`, `packaging/linux`, or `packaging/macos` templates |
| Key storage | Keys are local files | Not ready for high-security public release | Keep user profile protected; future OS keychain work required |
| IPC | File-backed queues | Good for development, not final hot path | Use current gateway until named pipe/socket IPC lands |

## Recommended User Flow Today

For a developer testing conU locally:

```powershell
conu init
conu security audit
conu doctor
conu start
conu agents register agent.a "Agent A" --kind test-agent
conu agents register agent.b "Agent B" --kind test-agent
conu routes sync
"test opaque payload" | conu messages send agent.a agent.b --stdin
conu messages inbox agent.b --json
conu watch
conu stop
```

For automation where a background daemon is awkward:

```powershell
conu init
conu agents register agent.a "Agent A" --kind test-agent
conu agents register agent.b "Agent B" --kind test-agent
conud --process-ipc
conu routes sync
"test opaque payload" | conu messages send agent.a agent.b --stdin
conud --process-ipc
conu messages inbox agent.b --json
```

## Best Next Product Work

To make conU genuinely useful over the internet, the next phase should build:

- Rooms, pub/sub, and multi-agent session metadata.
- Hosted relay auth/TLS hardening, persistent relay sessions, offline mailbox, and stream byte delivery.
- Published npm package backed by platform release assets and checksums.
- Real QUIC socket transport and NAT candidate exchange after the room/session model is stable.
- TypeScript SDK after the protocol surface stabilizes.
- Signed installers and OS keychain-backed secret storage after local packaging stabilizes.
