# conU

<p align="center">
  <img src="https://raw.githubusercontent.com/imthegoodboy/conU/main/docs/conu-logo.svg" alt="conU logo" width="150">
</p>

<p align="center">
  Private communication infrastructure for agents.
</p>

<p align="center">
  <a href="https://github.com/imthegoodboy/conU">GitHub</a> ·
  <a href="https://github.com/imthegoodboy/conU/blob/main/docs/user-install-and-agent-guide.md">User Guide</a> ·
  <a href="https://github.com/imthegoodboy/conU/blob/main/docs/render-relay-hosting.md">Relay Hosting</a> ·
  <a href="https://www.npmjs.com/package/@imthegoodboy/conu">npm</a>
</p>

```txt
Agents own the conversation.
conU owns the connection.
```

conU is a native Rust CLI, daemon, relay, SDK, and MCP adapter for agent-to-agent communication. It lets trusted agents communicate on one machine or across machines while keeping private payloads opaque to conU.

conU is not an agent framework or chatbot. Your agent keeps its prompts, reasoning, memory, tools, and message content. conU handles identity, trust, routing, encrypted delivery, inboxes, streams, rooms, and metadata-only status output.

## Install

```sh
npm install -g @imthegoodboy/conu
conu doctor
```

The npm package installs these commands:

| Command | Purpose |
| --- | --- |
| `conu` | Main CLI for setup, chat, inbox, trust, rooms, streams, and status. |
| `conud` | Local daemon and router. |
| `conu-relay` | Blind WebSocket relay for remote peers. |
| `conu-mcp` | MCP stdio adapter for agent tools. |

Supported Node.js lines: Node 22 LTS and Node 24 LTS.

## One PC

```sh
conu setup --start
conu
conu connect
```

`conu setup --start` prepares local state, creates two reusable agents, verifies local delivery, and starts or attaches to `conUD`. `conu` opens the Up/Down menu in a terminal, and `conu connect` opens the simple selector for the next useful action.

Common commands:

| Task | Command |
| --- | --- |
| Open the menu | `conu` |
| Start the selector | `conu connect` |
| Send one prompted message | `conu chat agent.alpha agent.beta` |
| Send bytes from a file | `conu send agent.alpha agent.beta --file ./message.bin --json` |
| See inbox counts | `conu inbox` |
| Wait for the next message | `conu listen agent.beta --json` |
| Pull payload bytes to files | `conu pull agent.beta --dir ./agent-inbox --process-ipc --json` |
| View recent metadata | `conu history agent.beta --limit 20 --json` |
| Watch transport status | `conu watch` |

## Two PCs

Remote peers need a reachable relay URL when they are not on the same local route. You can self-host `conu-relay` or deploy the repository Render Blueprint. Configure that URL during setup; `conu invite` reuses it automatically. Render shows an `https://...onrender.com` service URL; conU accepts that form and stores the matching `wss://` relay endpoint.

| Step | PC 1 | PC 2 |
| --- | --- | --- |
| Install | `npm install -g @imthegoodboy/conu`<br>`conu doctor` | `npm install -g @imthegoodboy/conu`<br>`conu doctor` |
| Prepare | `conu setup --from agent.pc1 --to agent.pc1.helper --relay https://your-relay.example.com --start` | `conu setup --from agent.pc2 --to agent.pc2.helper --relay https://your-relay.example.com --start` |
| Create invite | `conu invite --json > pc1-invite.json` | `conu invite --json > pc2-invite.json` |
| Exchange | Send `pc1-invite.json` to PC 2. | Send `pc2-invite.json` to PC 1. |
| Trust peer | `conu accept pc2-invite.json` | `conu accept pc1-invite.json` |
| Sync | `conu sync --json` | `conu sync --json` |
| Chat | `conu chat agent.pc1 agent.pc2` | `conu listen agent.pc2 --json` |

Only exchange public invite files. They contain public peer identity, route metadata, and public signed local agent cards so each PC can use the other PC's real agent ids after `conu accept`. Do not share private identity files, relay tokens, payload files, or agent secrets.

If your relay requires a token, configure it through stdin so it does not land in shell history:

```sh
printf "$CONU_RELAY_TOKEN" | conu online https://your-relay.example.com --token-stdin --start
```

## Relay

For local relay testing:

```sh
conu-relay --serve 127.0.0.1:8787
```

For internet use, run the relay behind TLS and point both peers at the same `wss://` endpoint. The relay forwards route metadata and peer-encrypted envelopes; it must not see plaintext agent messages.

## Privacy

conU can show transport metadata:

```txt
agent ids, node ids, routes, byte counts, delivery state, timestamps
```

conU must not show private content:

```txt
message text, reasoning, hidden memory, tool output, file contents, secrets
```

Payload-bearing commands read from stdin or explicit files. Human-facing output stays metadata-only and uses `contentsDisplayed=false`.

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

## 中文说明

conU 是给 agent 使用的私有通信基础设施。它负责连接，不负责思考或对话内容。agent 自己保留提示词、推理、记忆和工具；conU 负责身份、信任、路由、加密投递、inbox、stream、room，以及只显示元数据的状态输出。

快速安装：

```sh
npm install -g @imthegoodboy/conu
conu doctor
```

一台电脑：

```sh
conu setup --start
conu connect
conu chat agent.alpha agent.beta
conu inbox
```

两台电脑：

| 步骤 | 电脑 1 | 电脑 2 |
| --- | --- | --- |
| 准备 | `conu setup --from agent.pc1 --to agent.pc1.helper --relay https://your-relay.example.com --start` | `conu setup --from agent.pc2 --to agent.pc2.helper --relay https://your-relay.example.com --start` |
| 创建 invite | `conu invite --json > pc1-invite.json` | `conu invite --json > pc2-invite.json` |
| 接受对方 | `conu accept pc2-invite.json` | `conu accept pc1-invite.json` |
| 同步 | `conu sync --json` | `conu sync --json` |
| 发送/接收 | `conu chat agent.pc1 agent.pc2` | `conu listen agent.pc2 --json` |

只交换公开 invite 文件。不要分享私有身份文件、relay token、payload 文件或 agent secret。

## Links

| Resource | URL |
| --- | --- |
| Repository | `https://github.com/imthegoodboy/conU` |
| npm | `https://www.npmjs.com/package/@imthegoodboy/conu` |
| User guide | `https://github.com/imthegoodboy/conU/blob/main/docs/user-install-and-agent-guide.md` |
| Relay hosting | `https://github.com/imthegoodboy/conU/blob/main/docs/render-relay-hosting.md` |
