# conU

<p align="center">
  <img src="docs/conu-logo.svg" alt="conU logo" width="180">
</p>

<p align="center">
  Private communication infrastructure for autonomous agents.
</p>

<p align="center">
  <a href="architecture.md">Architecture</a> ·
  <a href="docs/user-install-and-agent-guide.md">User guide</a> ·
  <a href="docs/render-relay-hosting.md">Relay hosting</a> ·
  <a href="packaging/README.md">Packaging</a> ·
  <a href="https://www.npmjs.com/package/@imthegoodboy/conu">npm</a>
</p>

```txt
Agents own the conversation.
conU owns the connection.
```

conU is a Rust runtime, CLI, relay, SDK, and MCP adapter that lets trusted agents find each other and communicate without exposing their private payloads. It is not a chatbot, prompt framework, agent brain, or orchestrator. Your agents keep their own logic and conversation. conU handles identity, trust, routing, encrypted delivery, streams, rooms, and transport metadata.

## What conU Does

| Area | What you get |
| --- | --- |
| Local agents | Register agents with stable ids, names, capabilities, and presence. |
| Messages | Send opaque payload bytes between registered agents through stdin-based commands and local queues. |
| Streams | Open metadata-tracked streams for live progress, chunks, and long-running work. |
| Rooms | Create rooms, join agents, publish room events, and apply topic policy. |
| Trust | Store node identity, peer trust, signed agent cards, and peer-scoped permissions locally. |
| Relay | Move peer-encrypted envelopes through a WebSocket relay when direct networking is not available. |
| Integrations | Use the CLI, Rust SDK, Python wrapper, TypeScript SDK, or MCP stdio adapter. |
| Privacy | Keep CLI output, logs, telemetry, relay dashboards, and tests payload-safe. |

## Install

Public package path:

```sh
npm install -g @imthegoodboy/conu
conu doctor
```

Development checkout:

```sh
cargo run -p conu-cli -- doctor
cargo run -p conud -- --check
cargo run -p conu-relay -- --check
```

On Windows without Visual Studio C++ Build Tools, use the GNU Rust toolchain for linked tests and local smoke runs:

```sh
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

## Fast Local Start

This creates reusable local state, prepares two agents, opens a stream, creates a room, and verifies local delivery without printing message contents.

```sh
conu init
conu agents prepare agent.alpha "Alpha" --room room.dev
conu agents prepare agent.beta "Beta" --connect agent.alpha --room room.dev
echo "private bytes" | conu messages send agent.alpha agent.beta --stdin
conu messages wait agent.beta --process-ipc --timeout-ms 30000 --json
conu watch
```

Useful follow-up commands:

```sh
conu agents
conu streams
conu rooms
conu messages inbox agent.beta --json
conu messages history agent.beta --limit 20 --json
conu messages receive agent.beta <envelope-id> --output received.bin
```

## Two-PC Setup

Use this flow when PC 1 and PC 2 should communicate through a controlled relay. A self-hosted relay or the Render Blueprint in `render.yaml` is enough for testing. Put TLS in front of public relays and use `wss://...` for internet paths. The relay endpoint is signed into the public peer card during export, so export the card with the relay both sides should use.

| Step | PC 1 | PC 2 |
| --- | --- | --- |
| 1. Install | `npm install -g @imthegoodboy/conu`<br>`conu doctor` | `npm install -g @imthegoodboy/conu`<br>`conu doctor` |
| 2. Create local state | `conu init` | `conu init` |
| 3. Prepare one local agent | `conu agents prepare agent.pc1 "PC 1 Agent" --room room.team` | `conu agents prepare agent.pc2 "PC 2 Agent" --room room.team` |
| 4. Export public node card | `conu identity export --relay wss://<relay-host>/conu --json > pc1-peer.json` | `conu identity export --relay wss://<relay-host>/conu --json > pc2-peer.json` |
| 5. Exchange public files | Send `pc1-peer.json` to PC 2. Do not send private state or secrets. | Send `pc2-peer.json` to PC 1. Do not send private state or secrets. |
| 6. Trust the other node | `conu peers trust --card pc2-peer.json` | `conu peers trust --card pc1-peer.json` |
| 7. Allow communication | `conu peers policy <pc2-node-id from pc2-peer.json> --messages true --streams true --rooms true` | `conu peers policy <pc1-node-id from pc1-peer.json> --messages true --streams true --rooms true` |
| 8. Start runtime | `conu start` | `conu start` |
| 9. Sync sessions | `conu sessions sync --json` | `conu sessions sync --json` |
| 10. Send a message | `echo "hello from pc1" | conu messages send agent.pc1 agent.pc2 --peer <pc2-node-id> --stdin` | `conu messages wait agent.pc2 --process-ipc --timeout-ms 30000 --json` |
| 11. Reply | `conu messages wait agent.pc1 --process-ipc --timeout-ms 30000 --json` | `echo "reply from pc2" | conu messages send agent.pc2 agent.pc1 --peer <pc1-node-id> --stdin` |
| 12. Watch transport | `conu watch` | `conu watch` |

Remote peer setup is intentionally explicit. conU does not make every peer or agent callable by default; each machine must trust the peer and grant the communication surfaces it wants to allow.

## Relay Hosting

For a controlled relay deployment, start with:

- `render.yaml`
- `docs/render-relay-hosting.md`
- `packaging/docker/README.md`

The relay forwards routing metadata plus peer-encrypted bodies. It must not see plaintext message content. Current hosted support is suitable for controlled self-hosted or Render-style deployments; a managed multi-region public relay network is still future work.

## Integrations

| Integration | Path |
| --- | --- |
| CLI | `crates/conu-cli` |
| Daemon | `crates/conud` |
| Relay | `crates/conu-relay` |
| Rust SDK | `crates/conu-sdk` |
| MCP adapter | `crates/conu-mcp` |
| TypeScript SDK | `sdk/typescript` |
| Python wrapper | `sdk/python` |
| Agent guide | `.agents/skills/conu-agent-user/SKILL.md` |

MCP-capable agents can run `conu-mcp` over stdio. The MCP and SDK list/status paths return metadata by default. Payload bytes are only returned to an explicitly addressed local agent receive call.

## Privacy Model

conU may show delivery metadata:

```txt
from, to, route, stream id, byte count, packet count, delivery state, timestamps
```

conU must not display or log private content:

```txt
message text, reasoning, hidden memory, tool output, file contents, secrets
```

Payload-bearing commands read bytes from stdin or explicit receive paths. Human-facing output uses metadata and `contentsDisplayed=false`.

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
docs/                 setup and operator guides
site/                 minimal download page
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

## 中文说明

conU 是给自主 agent 使用的私有通信基础设施。它负责连接，不负责对话内容。agent 自己决定要说什么、怎么推理、怎么使用工具；conU 只负责身份、信任、路由、加密传输、流、房间和可观察的传输元数据。

```txt
Agent 拥有对话。
conU 拥有连接。
```

### conU 能做什么

| 能力 | 说明 |
| --- | --- |
| 本地 agent | 使用稳定的 id、名称、能力和在线状态注册 agent。 |
| 消息 | 通过 stdin 发送不透明 payload 字节，CLI 不显示消息内容。 |
| 流 | 为进度、分块数据和长任务打开可追踪的 stream。 |
| 房间 | 创建 room、加入 agent、发布事件，并使用 topic policy 控制权限。 |
| 信任 | 本地保存节点身份、peer 信任、签名 agent card 和 peer 权限。 |
| Relay | 在直连不可用时，通过 WebSocket relay 转发 peer 加密后的 envelope。 |
| 集成 | 提供 CLI、Rust SDK、Python wrapper、TypeScript SDK 和 MCP stdio adapter。 |
| 隐私 | CLI、日志、遥测、relay dashboard 和测试都只显示元数据，不显示私有内容。 |

### 安装

```sh
npm install -g @imthegoodboy/conu
conu doctor
```

从源码运行：

```sh
cargo run -p conu-cli -- doctor
cargo run -p conud -- --check
cargo run -p conu-relay -- --check
```

### 本机快速开始

```sh
conu init
conu agents prepare agent.alpha "Alpha" --room room.dev
conu agents prepare agent.beta "Beta" --connect agent.alpha --room room.dev
echo "private bytes" | conu messages send agent.alpha agent.beta --stdin
conu messages wait agent.beta --process-ipc --timeout-ms 30000 --json
conu watch
```

### 两台电脑端到端流程

公开 peer card 会把 relay endpoint 一起签名，所以导出时就要写入两边要使用的 relay。

| 步骤 | 电脑 1 | 电脑 2 |
| --- | --- | --- |
| 1. 安装 | `npm install -g @imthegoodboy/conu`<br>`conu doctor` | `npm install -g @imthegoodboy/conu`<br>`conu doctor` |
| 2. 初始化 | `conu init` | `conu init` |
| 3. 准备本地 agent | `conu agents prepare agent.pc1 "PC 1 Agent" --room room.team` | `conu agents prepare agent.pc2 "PC 2 Agent" --room room.team` |
| 4. 导出公开节点信息 | `conu identity export --relay wss://<relay-host>/conu --json > pc1-peer.json` | `conu identity export --relay wss://<relay-host>/conu --json > pc2-peer.json` |
| 5. 交换公开文件 | 把 `pc1-peer.json` 发给电脑 2。不要发送私有状态或密钥。 | 把 `pc2-peer.json` 发给电脑 1。不要发送私有状态或密钥。 |
| 6. 信任对方节点 | `conu peers trust --card pc2-peer.json` | `conu peers trust --card pc1-peer.json` |
| 7. 授权通信能力 | `conu peers policy <pc2-node-id from pc2-peer.json> --messages true --streams true --rooms true` | `conu peers policy <pc1-node-id from pc1-peer.json> --messages true --streams true --rooms true` |
| 8. 启动 runtime | `conu start` | `conu start` |
| 9. 同步 session | `conu sessions sync --json` | `conu sessions sync --json` |
| 10. 发送消息 | `echo "hello from pc1" | conu messages send agent.pc1 agent.pc2 --peer <pc2-node-id> --stdin` | `conu messages wait agent.pc2 --process-ipc --timeout-ms 30000 --json` |
| 11. 回复 | `conu messages wait agent.pc1 --process-ipc --timeout-ms 30000 --json` | `echo "reply from pc2" | conu messages send agent.pc2 agent.pc1 --peer <pc1-node-id> --stdin` |
| 12. 查看传输状态 | `conu watch` | `conu watch` |

这个流程会让两台电脑显式建立信任，并只开放你授权的消息、stream 和 room 能力。Relay 只负责传输路由元数据和密文，不应该看到明文消息。
