# conU User Install And Agent Guide

This guide explains how a user can install the current conU app, start it on their PC, and let local agents use it.

Current version status: Phase 11 is complete. conU is usable for local agent registration, local encrypted-at-rest message submission, stream metadata, trust metadata, and private CLI watch output. It is not yet a packaged consumer release, and it does not yet include the Phase 12 SDK/MCP adapter.

## What Works Today

- Install from source with Rust.
- Initialize local conU state and security keys.
- Start and stop the local `conUD` runtime.
- Register local agents by id.
- Send local opaque payload bytes from one registered local agent to another.
- Store new conU-owned local payload files encrypted at rest.
- List inbox, receipt, stream, peer, session, and security metadata.
- Run a standalone `conu-relay` MVP for metadata-only relay frame tests.

## What Does Not Work Yet

- No one-click installer or signed release package.
- No stable SDK for Python, TypeScript, or Rust agent apps yet.
- No MCP adapter yet.
- No CLI command that reveals message contents. This is intentional, but it also means a clean external receive API is still Phase 12 work.
- No live internet data-plane routing between two real conUD nodes yet.
- Pairing and remote sessions are local metadata groundwork, not full cross-machine rendezvous.
- `conu-relay` exists, but conUD does not yet own a live relay client for encrypted message/stream byte delivery.
- conUD is not installed as a Windows/macOS/Linux service yet.
- Local private keys are file-backed today; OS keychain/DPAPI/HSM support is still a release blocker.

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
```

macOS/Linux shell, assuming the default toolchain links successfully:

```bash
cargo install --path crates/conu-cli --locked --force
cargo install --path crates/conud --locked --force
cargo install --path crates/conu-relay --locked --force
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
```

## First Run

Initialize local state and local security keys:

```powershell
conu init
conu security audit
conu status
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

## Give conU To An Agent Today

Until Phase 12 SDK/MCP exists, the safest current integration is to let the agent call the CLI.

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
- Use JSON commands for machine-readable metadata:
  conu status --json
  conu agents --json
  conu messages inbox <agent-id> --json
  conu messages receipts --json
  conu security audit --json
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
| Installer | No packaged installer yet | Users must build from source | Use `cargo install --path` |
| Windows linker | Default MSVC toolchain may fail without `link.exe` | `cargo check/test/install` can fail | Use `stable-x86_64-pc-windows-gnu` or install Visual Studio C++ Build Tools |
| Runtime discovery | `conu start` needs `conud` beside `conu` or on PATH | Start can fail after manual binary moves | Install both with Cargo or set `CONUD_EXE` |
| Agent API | No SDK/MCP adapter yet | Agents need CLI calls or internal Rust integration | Use CLI/stdin and JSON metadata |
| Receiving payloads | No stable external receive API yet | CLI lists inbox metadata only | Phase 12 should add SDK/MCP receive |
| Internet messaging | Relay is not wired into conUD data plane yet | Local messages work; real remote payload delivery does not | Use local testing only |
| Pairing | Pair/join are local trust groundwork | Not real cross-machine pairing yet | Use for metadata/trust testing |
| Service install | conUD is not an OS service yet | User must start/stop manually | Use `conu start` / `conu stop` |
| Key storage | Keys are local files | Not ready for high-security public release | Keep user profile protected; future OS keychain work required |
| IPC | File-backed queues | Good for development, not final hot path | Use current gateway until named pipe/socket IPC lands |

## Recommended User Flow Today

For a developer testing conU locally:

```powershell
conu init
conu security audit
conu start
conu agents register agent.a "Agent A" --kind test-agent
conu agents register agent.b "Agent B" --kind test-agent
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
"test opaque payload" | conu messages send agent.a agent.b --stdin
conud --process-ipc
conu messages inbox agent.b --json
```

## Best Next Product Work

To make conU genuinely easy for users and agents, the next phase should build:

- Rust SDK receive/send/register APIs.
- Python SDK wrapper for local agents.
- MCP adapter exposing conU tools to LLM agents.
- A stable receive API that returns payload bytes only to the addressed local agent.
- Packaged installer and service setup after SDK behavior is stable.
