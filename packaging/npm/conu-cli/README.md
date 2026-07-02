# conU

<p align="center">
  <img src="https://raw.githubusercontent.com/imthegoodboy/conU/main/docs/conu-logo.svg" alt="conU logo" width="150">
</p>

<p align="center">
  Private communication infrastructure for agents.
</p>

<p align="center">
  <a href="https://github.com/imthegoodboy/conU">Repository</a> ·
  <a href="https://github.com/imthegoodboy/conU/blob/main/docs/user-install-and-agent-guide.md">User Guide</a> ·
  <a href="https://github.com/imthegoodboy/conU/blob/main/docs/render-relay-hosting.md">Relay Hosting</a> ·
  <a href="https://github.com/imthegoodboy/conU/blob/main/architecture.md">Architecture</a>
</p>

```txt
Agents own the conversation.
conU owns the connection.
```

conU is a native Rust CLI, daemon, relay, SDK, and MCP adapter that lets trusted agents communicate across local machines or remote peers without exposing private payload contents. It is not an agent framework or chatbot. Your agent keeps its own prompts, reasoning, memory, and tools; conU handles identity, trust, routing, encrypted delivery, streams, rooms, and metadata-only observability.

## What It Does

| Area | Purpose |
| --- | --- |
| Agents | Register local agents with stable ids, names, capabilities, and presence. |
| Messages | Send opaque payload bytes between agents through stdin and explicit receive calls. |
| Streams | Track live progress, chunks, and long-running work between agents. |
| Rooms | Create shared rooms, join agents, publish events, and apply topic policy. |
| Trust | Store node identity, trusted peers, signed agent cards, and peer permissions locally. |
| Relay | Forward peer-encrypted envelopes over WebSocket when direct routes are not available. |
| Integrations | Use the CLI, Rust SDK, TypeScript SDK, Python wrapper, or MCP stdio adapter. |

## Install

```sh
npm install -g @imthegoodboy/conu
conu doctor
```

The package installs these native binaries:

| Command | Purpose |
| --- | --- |
| `conu` | Human and agent-friendly CLI. |
| `conud` | Local daemon and router. |
| `conu-relay` | Blind WebSocket relay for peer-encrypted internet delivery. |
| `conu-mcp` | MCP stdio adapter for agent tools. |

Supported Node.js lines: Node 22 LTS and Node 24 LTS.

## Start On One PC

```sh
conu setup --start
conu connect
```

Send and receive private bytes:

```sh
conu send agent.alpha agent.beta --file ./message.bin --json
conu listen agent.beta --json
conu pull agent.beta --dir ./agent-inbox --process-ipc --json
```

Useful daily commands:

```sh
conu dashboard
conu chat
conu inbox agent.beta --json
conu next agent.beta --json
conu watch
```

## Connect Two PCs

If both machines use a shared relay, configure it once on each PC:

```sh
printf "$CONU_RELAY_TOKEN" | conu online wss://your-relay.example.com/conu --token-stdin --verify
```

Then exchange public invite files:

| Step | PC 1 | PC 2 |
| --- | --- | --- |
| Prepare | `conu setup --from agent.pc1 --to agent.pc1.helper --start` | `conu setup --from agent.pc2 --to agent.pc2.helper --start` |
| Create invite | `conu invite --relay wss://your-relay.example.com/conu --json > pc1-invite.json` | `conu invite --relay wss://your-relay.example.com/conu --json > pc2-invite.json` |
| Exchange | Send `pc1-invite.json` to PC 2. | Send `pc2-invite.json` to PC 1. |
| Accept | `conu accept pc2-invite.json` | `conu accept pc1-invite.json` |
| Sync | `conu sessions sync --json` | `conu sessions sync --json` |
| Send | `conu send agent.pc1 agent.pc2 --file ./message.bin --json` | `conu listen agent.pc2 --json` |

Only public invite files are exchanged. Private identity files, relay tokens, and payload files stay on each machine. For relay hosting and deeper workflows, use the full guide:

```txt
https://github.com/imthegoodboy/conU/blob/main/docs/user-install-and-agent-guide.md
```

## Relay Hosting

For quick local testing:

```sh
conu-relay --serve 127.0.0.1:8787
```

For internet use, run the relay behind TLS or deploy the Render Blueprint from the repository. The relay forwards route metadata and peer-encrypted envelopes; it must not see plaintext agent messages.

## Privacy

conU may show transport metadata:

```txt
agent ids, node ids, route, byte counts, delivery state, timestamps
```

conU must not show private content:

```txt
message text, reasoning, hidden memory, tool output, file contents, secrets
```

Payload-bearing commands read from stdin or explicit files. Human-facing output stays metadata-only and uses `contentsDisplayed=false`.

## 中文说明

conU 是给 agent 使用的私有通信基础设施。它负责连接，不负责思考或对话内容。agent 自己保留提示词、推理、记忆和工具；conU 负责身份、信任、路由、加密投递、stream、room，以及只显示元数据的状态观察。

快速开始：

```sh
npm install -g @imthegoodboy/conu
conu setup --start
conu connect
```

两台电脑使用同一个 relay 时，可以先配置在线连接：

```sh
printf "$CONU_RELAY_TOKEN" | conu online wss://your-relay.example.com/conu --token-stdin --verify
```

然后交换公开 invite 文件：

| 步骤 | 电脑 1 | 电脑 2 |
| --- | --- | --- |
| 准备 | `conu setup --from agent.pc1 --to agent.pc1.helper --start` | `conu setup --from agent.pc2 --to agent.pc2.helper --start` |
| 创建 invite | `conu invite --relay wss://your-relay.example.com/conu --json > pc1-invite.json` | `conu invite --relay wss://your-relay.example.com/conu --json > pc2-invite.json` |
| 接受对方 | `conu accept pc2-invite.json` | `conu accept pc1-invite.json` |
| 发送 | `conu send agent.pc1 agent.pc2 --file ./message.bin --json` | `conu listen agent.pc2 --json` |

conU 可以显示 agent id、路由、字节数和投递状态；不显示消息正文、推理内容、隐藏记忆、工具输出、文件内容或 secret。

## Package Security

This npm package is a launcher for native release binaries. During install it downloads the matching GitHub Release archive, verifies the sibling `.sha256` checksum, checks archive members before extraction, and installs binaries under the package-local `vendor/` directory.

Advanced release-testing overrides:

| Variable | Purpose |
| --- | --- |
| `CONU_NPM_DIST_BASE` | Override release download base URL. HTTPS is required unless using loopback HTTP. |
| `CONU_NPM_BINARY_DIR` | Copy binaries from an existing local directory after preflight checks. |
| `CONU_NPM_SKIP_DOWNLOAD` | Skip download for package publishing checks. |
| `CONU_NPM_ALLOW_UNVERIFIED` | Allow missing checksums only for loopback testing downloads. |
| `CONU_NPM_DOWNLOAD_TIMEOUT_MS` | Override per-request download timeout. |
| `CONU_NPM_MAX_ARCHIVE_BYTES` | Override native archive download limit. |
| `CONU_NPM_MAX_CHECKSUM_BYTES` | Override checksum response limit. |

## Links

| Resource | URL |
| --- | --- |
| Repository | `https://github.com/imthegoodboy/conU` |
| npm | `https://www.npmjs.com/package/@imthegoodboy/conu` |
| User guide | `https://github.com/imthegoodboy/conU/blob/main/docs/user-install-and-agent-guide.md` |
| Relay hosting | `https://github.com/imthegoodboy/conU/blob/main/docs/render-relay-hosting.md` |
