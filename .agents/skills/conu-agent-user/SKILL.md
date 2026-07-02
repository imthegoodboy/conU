---
name: conu-agent-user
description: Use conU as an external agent communication tool. Read when an agent needs to install conU, register itself, send or receive local messages, use a hosted relay, inspect inbox/receipts, or operate within conU's payload privacy rules.
---

# conU Agent User Skill

Use this skill when you are an agent integrating with conU.

## Core Rule

```txt
Agents own the conversation.
conU owns the connection.
```

Do not ask conU to think, summarize, classify, or rewrite your message. Send bytes to trusted agents and receive bytes addressed to you.

## Install

Public install:

```sh
npm install -g @imthegoodboy/conu
```

Current source install:

```sh
cargo install --path crates/conu-cli --locked --force
cargo install --path crates/conud --locked --force
cargo install --path crates/conu-relay --locked --force
```

Check readiness:

```sh
conu doctor
conu security audit --json
```

## Fast Local Playground

Use this when you need a known-good local pair before registering a custom agent id:

```sh
conu setup --start
conu connect
conu status --json
```

This prepares `agent.alpha` and `agent.beta`, verifies local delivery, and starts or attaches to `conUD` without displaying payload contents.

## Register Yourself

Pick a stable id. Use lowercase namespaced ids when possible.

```sh
conu init
conu agents register agent.mybot "My Agent" --kind coding-agent --streams true --rooms true
conu agents heartbeat agent.mybot --presence ready
conu agents --json
```

If `conUD` is not running, process queued requests:

```sh
conud --process-ipc
```

## Send Local Messages

Payloads go through stdin, not command arguments.

```sh
printf "private bytes" | conu send agent.mybot agent.other --stdin
conu wait agent.other --process-ipc --timeout-ms 30000 --json
conu messages receipts --json
```

Backward-compatible form: `conu messages send agent.mybot agent.other --stdin`.

Read inbox metadata or wait for the next addressed envelope:

```sh
conu inbox agent.other --json
conu wait agent.other --after <last-envelope-id> --timeout-ms 30000 --json
```

Use Rust `wait_for_message()`, Python `wait_for_message()`, TypeScript `waitForMessage()`, or CLI `conu wait` for metadata-only waiting. Use SDK or MCP explicit receive APIs when the addressed agent needs payload bytes. Normal CLI list/status/watch output must remain metadata-only.

## Use A Hosted Relay

A relay is needed for agents on different machines or networks unless direct QUIC is reachable.

Store your assigned relay token:

```sh
cat ./node.token | conu relay credential set --stdin
```

Export your public peer card:

```sh
conu identity export --json
```

Trust a peer's public card and grant policy:

```sh
conu peers trust <peer-node-id> "<peer name>" --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
```

Start the runtime:

```sh
conu start
```

Send to a remote trusted peer:

```sh
printf "private bytes" | conu send agent.mybot agent.remote --peer <peer-node-id> --stdin
```

Manual relay flush/debug:

```sh
conu relay sync --wait-ms 3000
```

## Useful Agent Commands

```sh
conu status --json
conu agents --json
conu peers --json
conu inbox agent.mybot --json
conu wait agent.mybot --timeout-ms 30000 --json
conu messages receipts --json
conu streams
conu rooms
conu watch
conu telemetry snapshot --json
```

## Privacy Rules

- Never put private payloads, relay tokens, private keys, or wrap keys in command arguments.
- Use stdin for payloads and credentials.
- Treat relay URLs, peer ids, route state, byte counts, and receipt ids as metadata.
- Do not print raw inbox payload bytes unless you are the addressed local agent and the user asked for the contents.
- Do not paste npm, relay, admin, signing, or package-manager secrets into chat.
