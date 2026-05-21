# conU Internet Relay Test

This is the practical smoke test for the current relay-backed message, stream-chunk, and room-event path. It proves that two conU nodes can exchange signed public peer cards and signed public agent cards, trust each other, keep conUD running, and move peer-encrypted payloads through a WebSocket relay without showing the payload in CLI output or relay logs.

Current limit: the relay server itself speaks plain WebSocket. The client accepts both `ws://` and `wss://`; for a public internet test, place a certificate-valid TLS terminator or reverse proxy in front of `conu-relay` and give conU the `wss://` endpoint. See `docs/distribution-and-hosting.md` for the hosting and public-release path.

## 1. Start The Relay

On the relay machine:

```powershell
New-Item -ItemType Directory -Force C:\conu-relay | Out-Null
conu-relay --issue-credential node-a-id --token-out C:\conu-relay\node-a.token --credentials-file C:\conu-relay\credentials.toml
conu-relay --issue-credential node-b-id --token-out C:\conu-relay\node-b.token --credentials-file C:\conu-relay\credentials.toml
$env:CONU_RELAY_CREDENTIALS_FILE = "C:\conu-relay\credentials.toml"
$env:CONU_RELAY_MAX_CONNECTIONS = "512"
$env:CONU_RELAY_MAX_CONNECTIONS_PER_IP = "64"
$env:CONU_RELAY_MAX_FRAMES_PER_MINUTE = "600"
$env:CONU_RELAY_IDLE_TIMEOUT_SECONDS = "120"
$env:CONU_RELAY_SESSION_TTL_SECONDS = "3600"
$env:CONU_RELAY_SESSION_STATE_DIR = "C:\conu-relay\sessions"
$env:CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE = "128"
$env:CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS = "3600"
$env:CONU_RELAY_MAILBOX_DIR = "C:\conu-relay\mailbox"
$env:CONU_RELAY_ACCOUNTING_DIR = "C:\conu-relay\accounting"
$env:CONU_RELAY_ACCOUNTING_WINDOW_SECONDS = "86400"
$env:CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE = "10000"
$env:CONU_RELAY_MAX_BYTES_SENT_PER_NODE = "1073741824"
$env:CONU_RELAY_ABUSE_DIR = "C:\conu-relay\abuse"
$env:CONU_RELAY_ABUSE_WINDOW_SECONDS = "86400"
conu-relay --serve 0.0.0.0:8787
```

`local-dev-token` is accepted only for loopback binds such as `127.0.0.1`; a relay exposed on `0.0.0.0` requires a custom shared token or scoped credential token with at least 24 characters. For a self-hosted two-node relay, prefer `CONU_RELAY_CREDENTIALS_FILE` after the node ids are known. `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` writes the raw token to a new file and creates or updates the manifest with only hashed metadata; `--replace` rotates an existing node credential and `conu-relay --revoke-credential <node-id> --credentials-file <path>` marks it revoked. `conu-relay --hash-token` remains available for already-created tokens. The manifest stores only token hashes plus status/expiry metadata, reloads on each new `HELLO` authentication attempt, and overrides `CONU_RELAY_CREDENTIALS`, which remains available for controlled compatibility tests. On each node, either set `CONU_RELAY_TOKEN` to that node's assigned scoped token before starting conUD, or store it with `conu relay credential set --stdin`.

For a managed relay test, set `CONU_RELAY_ADMIN_TOKEN` on the relay process together with `CONU_RELAY_CREDENTIALS_FILE`. To test tenant fail-closed behavior, also set `CONU_RELAY_TENANTS_FILE` and create tenant/node metadata before issuing credentials:

```powershell
conu-relay --tenant-upsert account.test --tenants-file C:\conu-relay\tenants.toml
conu-relay --tenant-node-upsert account.test node-a-id --tenants-file C:\conu-relay\tenants.toml --messages true --streams true --rooms true --mailbox true
```

Then issue or rotate node credentials online:

```powershell
Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-issue-credential account.test node-a-id --relay wss://relay.example.com/conu --admin-token-stdin --token-out C:\conu-relay\node-a.token
```

The admin frame sends only the generated node token hash and length to the relay. The raw node token is written locally after the relay confirms the manifest update, and admin/audit output reports only counts, statuses, ids, and display guards. Tenant metadata does not grant local peer policy; each runtime still needs trusted peer cards and explicit peer policy grants.

For same-machine testing, use `ws://127.0.0.1:8787`. For two machines on a trusted private path, use the reachable host or IP, for example `ws://203.0.113.10:8787`. For public internet testing, terminate TLS in front of the relay and use a certificate-valid endpoint such as `wss://relay.example.com/conu`.

## 2. Prepare Node A And Node B

On each node:

```powershell
conu init
conu security audit
Get-Content -Raw <path-to-this-node-token-file> | conu relay credential set --stdin
```

Set `default_relay` in each node's `config.toml`:

```toml
version = "1"
default_relay = "wss://relay.example.com/conu"
relay_auto_sync = true
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

Give each side the other side's `nodeId`, `displayName`, `exchangePublicKeyHex`, `relayEndpoint`, `signingPublicKeyHex`, `signatureHex`, and `signatureKeyId`.

On Node A, trust Node B:

```powershell
conu peers trust <node-b-id> "<node-b-name>" --exchange-key <node-b-exchange-key> --relay wss://relay.example.com/conu --signing-key <node-b-signing-public-key> --signature <node-b-signature> --signature-key-id <node-b-signature-key-id>
```

On Node B, trust Node A:

```powershell
conu peers trust <node-a-id> "<node-a-name>" --exchange-key <node-a-exchange-key> --relay wss://relay.example.com/conu --signing-key <node-a-signing-public-key> --signature <node-a-signature> --signature-key-id <node-a-signature-key-id>
```

Trust identifies a peer, but it does not grant communication by itself. Grant only the relay-backed surfaces you intend to use.

On Node A:

```powershell
conu peers policy <node-b-id> --messages true --streams true --rooms true
```

On Node B:

```powershell
conu peers policy <node-a-id> --messages true --streams true --rooms true
```

## 4. Register Agents

Start conUD on both nodes so the runtime owns local IPC plus relay send/receive:

```powershell
conu start
```

On Node A:

```powershell
conu agents register agent.a "Agent A" --kind test-agent --streams true
conu agents export agent.a --json
```

On Node B:

```powershell
conu agents register agent.b "Agent B" --kind test-agent --streams true
conu agents export agent.b --json
```

With conUD running, session sync exchanges signed public agent cards automatically over peer-encrypted relay control envelopes after signed peer-card trust and policy grants exist on both sides. The relay sees ciphertext and routing metadata only.

Manual fallback: give each side the other side's signed agent-card output. On Node A, trust Node B's agent card:

```powershell
conu agents trust agent.b "Agent B" --node <node-b-id> --kind test-agent --streams true --signing-key <node-b-agent-signing-public-key> --signature <node-b-agent-signature> --signature-key-id <node-b-agent-signature-key-id>
```

On Node B, trust Node A's agent card:

```powershell
conu agents trust agent.a "Agent A" --node <node-a-id> --kind test-agent --streams true --signing-key <node-a-agent-signing-public-key> --signature <node-a-agent-signature> --signature-key-id <node-a-agent-signature-key-id>
```

The agent-card signing key, signature, signature key id, kind, and capability booleans come from `conu agents export <agent-id> --json`. `conu agents trust` requires the card's `nodeId` to already be trusted through `conu peers trust`, and the agent-card signing key must match the trusted peer card. Automatic exchange uses the same verification before writing `agents/remote.toml`. The local peer policy must also grant `messages=true` before relay messages, `streams=true` before relay stream chunks, and `rooms=true` before relay room events are accepted.

## 5. Send Through The Relay

On Node A, queue the message. The running conUD relay pump flushes it and the running Node B conUD receives it:

```powershell
"hello over encrypted relay" | conu messages send agent.a agent.b --peer <node-b-id> --stdin
```

On Node B, inspect the addressed inbox metadata:

```powershell
conu messages inbox agent.b --json
```

The inbox should show an envelope from `agent.a` to `agent.b` with a byte count and `contentsDisplayed: false`.

To test relay-backed stream chunks after Node A can see Node B's signed remote agent metadata and that metadata advertises `streams=true`:

```powershell
conu streams open agent.a <node-b-agent-id-with-streams>
"opaque stream bytes" | conu streams write <stream-id> --stdin
```

Node B's inbox should then show `kind: "stream_chunk"` plus `streamId` metadata for the addressed envelope. The payload remains hidden from CLI output and is available only through explicit receive APIs for `agent.b`.

To test relay-backed room events after Node A can see Node B's signed remote agent metadata and that metadata advertises `rooms=true`:

```powershell
conu rooms create room.dev "Dev Room" --agent agent.a
conu rooms join room.dev <node-b-agent-id-with-rooms>
"opaque room bytes" | conu rooms publish room.dev agent.a build --stdin
```

Node B's inbox should then show a room event envelope with `kind: "event"`, and `conu rooms events --json` should show the room id, topic, sender, byte count, and `contentsDisplayed: false`. The payload remains hidden from CLI output and is available only through explicit receive APIs for the addressed local agent.

If you need topic-level authorization, configure it before publishing. Unconfigured topics use room membership as the compatibility boundary; once any policy exists for a room/topic, that topic requires explicit grants:

```powershell
conu rooms policy room.dev agent.a build --publish true --subscribe true
conu rooms policy room.dev <node-b-agent-id-with-rooms> build --publish false --subscribe true
```

If you are testing without a long-running daemon, use the manual fallback: run `conu relay sync --wait-ms 10000` on the receiver while the sender runs `conu relay sync --wait-ms 3000`.

To test the offline relay mailbox, stop Node B's conUD before sending from Node A, then start Node B again before `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS` expires. The relay should accept the peer-encrypted envelope while Node B is offline and deliver it after Node B reconnects. If `CONU_RELAY_MAILBOX_DIR` is set, repeat the test with a relay restart between send and receive; the ciphertext envelope should survive the restart and then be removed after delivery. While Node B is still offline, `conu-relay --mailbox-audit --mailbox-dir C:\conu-relay\mailbox --ttl-seconds 3600 --json` should show mailbox counts and display guards without frame contents or ciphertext bodies.

To test relay session state, inspect `C:\conu-relay\sessions` after a successful `HELLO`. The `.session` files should show node ids, relay session ids, timestamps, and `payload_displayed = false` / `token_displayed = false` / `contents_displayed = false`, without relay tokens, token hashes, plaintext message text, stream chunks, room-event plaintext, ciphertext bodies, or private keys. Same-process daemon reconnects to the same relay endpoint may increment `sessions_resumed`; with `CONU_RELAY_SESSION_STATE_DIR` set, the relay can also accept that same-node resume hint after a relay restart until the session TTL expires. A daemon restart still loses the client-side resume hint.

To test relay accounting, inspect `C:\conu-relay\accounting` after a successful send. The `.accounting` files should show node ids, authenticated-session counts, resumed-session counts, envelope counts, byte counts, and `payload_displayed = false` / `token_displayed = false`, without relay tokens, token hashes, session ids, plaintext message text, stream chunks, room-event plaintext, or ciphertext bodies. Lower `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE` to `1`, restart the relay, and send twice from the same node to verify that the second send returns `UNDELIVERED reason=quota_exceeded`.

For same-machine validation of the daemon-owned path:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

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
conu relay sync --wait-ms 1000 --json
```

The relay and CLI may show node ids, agent ids, envelope ids, stream ids, byte counts, route labels, and encrypted-body state. Room id and topic stay inside the peer-encrypted room-event packet on the relay path and should only appear after delivery in local room metadata. They must not show message text, stream bytes, room event bytes, private keys, shared secrets, prompt text, reasoning, files, or tool output.
