# conU Internet Relay Test

This is the practical smoke test for the current relay-backed message MVP. It proves that two conU nodes can exchange public peer cards, trust each other, and move a peer-encrypted message through a WebSocket relay without showing the payload in CLI output or relay logs.

Current limit: the built-in client supports `ws://` endpoints. For a real internet test, expose the relay port directly or use a tunnel/reverse proxy that accepts TLS publicly and forwards plain WebSocket traffic to `conu-relay`.

## 1. Start The Relay

On the relay machine:

```powershell
$env:CONU_RELAY_TOKEN = "local-dev-token"
conu-relay --serve 0.0.0.0:8787
```

For same-machine testing, use `ws://127.0.0.1:8787`. For two machines, use the reachable host or IP, for example `ws://203.0.113.10:8787`.

## 2. Prepare Node A And Node B

On each node:

```powershell
conu init
conu security audit
```

Set `default_relay` in each node's `config.toml`:

```toml
version = "1"
default_relay = "ws://<relay-host>:8787"
```

## 3. Exchange Public Cards

On Node A:

```powershell
conu identity export --json
```

On Node B:

```powershell
conu identity export --json
```

Give each side the other side's `nodeId`, `displayName`, `exchangePublicKeyHex`, and `relayEndpoint`.

On Node A, trust Node B:

```powershell
conu peers trust <node-b-id> "<node-b-name>" --exchange-key <node-b-exchange-key> --relay ws://<relay-host>:8787
```

On Node B, trust Node A:

```powershell
conu peers trust <node-a-id> "<node-a-name>" --exchange-key <node-a-exchange-key> --relay ws://<relay-host>:8787
```

## 4. Register Agents

On Node A:

```powershell
conu agents register agent.a "Agent A" --kind test-agent
conud --process-ipc
```

On Node B:

```powershell
conu agents register agent.b "Agent B" --kind test-agent
conud --process-ipc
```

## 5. Send Through The Relay

On Node B, start a receive sync and keep it open:

```powershell
conu relay sync --wait-ms 10000
```

On Node A, queue and flush the message:

```powershell
"hello over encrypted relay" | conu messages send agent.a agent.b --peer <node-b-id> --stdin
conu relay sync --wait-ms 3000
```

On Node B, inspect the addressed inbox metadata:

```powershell
conu messages inbox agent.b --json
```

The inbox should show an envelope from `agent.a` to `agent.b` with a byte count and `contentsDisplayed: false`.

## Privacy Checks

Good outputs:

```txt
payload view  contents are not displayed by conU
relay view    encrypted body plus route metadata only
```

Files/logs to spot-check:

```powershell
conu watch
conu messages receipts --json
```

The relay and CLI may show node ids, agent ids, envelope ids, byte counts, route labels, and encrypted-body state. They must not show message text, private keys, shared secrets, prompt text, reasoning, files, or tool output.
