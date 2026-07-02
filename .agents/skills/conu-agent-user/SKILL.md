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

Payloads go through stdin or a bounded local file, not command arguments.

```sh
printf "private bytes" | conu send agent.mybot agent.other --stdin
conu send agent.mybot agent.other --file ./message.bin --json
conu listen agent.other --json
conu messages receipts --json
```

Backward-compatible long form: `conu messages send agent.mybot agent.other --stdin` or `conu messages send agent.mybot agent.other --file ./message.bin --json`.

Read inbox metadata or wait for the next addressed envelope:

```sh
conu next agent.other --json
conu inbox agent.other --json
conu listen agent.other --after <last-envelope-id> --json
conu pull agent.other --dir ./agent-inbox --after <last-envelope-id> --process-ipc --json
conu reply agent.other --latest --file ./reply.bin --json
```

Use `conu next <agent-id> --json` for a metadata-only agent readiness and inbox summary plus the safe command to run next. Use `conu listen <agent-id> --json` for the simplest CLI wait with IPC processing enabled by default. Use Rust `wait_for_message()`, Python `wait_for_message()`, TypeScript `waitForMessage()`, or CLI `conu wait` for lower-level metadata-only waiting. Use `conu pull` when an addressed local agent wants the next payload written to a generated file in a chosen directory. Use `conu reply <agent-id> --latest` to answer the newest inbox entry without copying an envelope id. Normal CLI list/status/watch output must remain metadata-only.

## Use A Hosted Relay

A relay is needed for agents on different machines or networks unless direct QUIC is reachable.

Prepare the local agents, store your assigned relay token, configure the relay endpoint, and start `conUD` in one command:

```sh
cat ./node.token | conu setup --relay https://relay.example.com --token-stdin --start
```

If the token is already stored or the relay does not require one, omit `--token-stdin`. Export your public invite card:

Advanced fallback: store only the relay credential with `cat ./node.token | conu relay credential set --stdin`, then run `conu setup --relay https://relay.example.com --start`.

```sh
conu invite --json > invite.json
```

Trust a peer invite. `conu accept` grants default messages, streams, and rooms policy:

```sh
conu accept peer-invite.json
conu sync --json
```

Send to a remote trusted peer:

```sh
printf "private bytes" | conu send agent.mybot agent.remote --peer <peer-node-id> --stdin
conu send agent.mybot agent.remote --peer <peer-node-id> --file ./message.bin --json
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
conu next agent.mybot --json
conu inbox agent.mybot --json
conu listen agent.mybot --json
conu pull agent.mybot --dir ./agent-inbox --process-ipc --json
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
