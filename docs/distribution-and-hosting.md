# conU Distribution And Hosting

This is the practical path for getting conU onto a user's machine and making two agents talk through a reachable relay.

## Best Distribution Shape

conU should stay a native Rust product. The best public install path is:

```txt
GitHub Release native binaries
  -> npm launcher package for one-command install
  -> optional OS package managers after signing
```

Why this shape:

- Rust binaries keep the CLI, daemon, relay, protocol, crypto, and MCP adapter fast and self-contained.
- GitHub Releases are the source of truth for platform archives and checksums.
- npm gives agents and developers a familiar install command without making conU a JavaScript runtime.
- Homebrew, winget, Chocolatey, apt, and signed installers can come after versioning, signing, and update policy are stable.

The target public command is:

```sh
npm install -g @conu/cli
conu init
conu doctor
conu start
```

The npm package under `packaging/npm/conu-cli` is a launcher. It downloads the native release archive for the user's platform, verifies the `.sha256` file, and exposes:

```txt
conu
conud
conu-relay
conu-mcp
```

## Release Asset Names

The npm installer expects these assets for version `0.1.0`:

```txt
conu-0.1.0-windows-x64.zip
conu-0.1.0-linux-x64.tar.gz
conu-0.1.0-linux-arm64.tar.gz
conu-0.1.0-macos-x64.tar.gz
conu-0.1.0-macos-arm64.tar.gz
```

Each archive must have:

```txt
<asset>.sha256
```

The release workflow builds platform-named artifacts and uploads matching checksum files.

## Publishing Flow

1. Update all Cargo package versions and `packaging/npm/conu-cli/package.json` to the same version.
2. Run the release validation checklist.
3. Tag the release, for example `v0.1.0`.
4. Let GitHub Actions build platform archives and checksum files.
5. Create a GitHub Release from the tag and attach the archive/checksum artifacts.
6. From `packaging/npm/conu-cli`, run `npm publish --access public`.
7. Test from a clean shell:

```sh
npm install -g @conu/cli
conu doctor
conud --check
conu-relay --check
```

For local package testing without downloading from GitHub Releases:

```sh
CONU_NPM_BINARY_DIR=/absolute/path/to/bin npm install -g ./packaging/npm/conu-cli
```

## User Install Choices

Recommended for normal users after the first public release:

```sh
npm install -g @conu/cli
```

Recommended for Rust developers:

```sh
cargo install --git https://github.com/imthegoodboy/conU --package conu-cli --bin conu --locked
cargo install --git https://github.com/imthegoodboy/conU --package conud --bin conud --locked
cargo install --git https://github.com/imthegoodboy/conU --package conu-relay --bin conu-relay --locked
cargo install --git https://github.com/imthegoodboy/conU --package conu-mcp --bin conu-mcp --locked
```

Recommended for early testers:

```txt
Download the GitHub Release archive
unpack it
run the platform install script in packaging/
run conu doctor
```

## How It Works For A User

On each user's machine:

```txt
agent
  -> conu-mcp / SDK / CLI stdin
  -> local conUD
  -> peer-encrypted relay message, stream chunk, or room event
  -> conu-relay
  -> remote conUD
  -> remote agent inbox
```

The user or agent does this once:

```sh
conu init
conu start
conu agents register agent.local "Local Agent" --kind coding-agent --streams true
conu identity export --json
conu agents export agent.local --json
```

Then the peer's public card is trusted:

```sh
conu peers trust <peer-node-id> "<peer name>" --exchange-key <peer-exchange-key> --relay wss://relay.example.com/conu --signing-key <peer-signing-public-key> --signature <peer-signature> --signature-key-id <peer-signature-key-id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
```

The signing fields come from `conu identity export --json`. They let the importing node verify that the public peer card was not modified between export and trust import. Unsigned imports remain available for older controlled test cards, but hosted/self-hosted production guidance should use signed peer cards. `conu peers policy` stores metadata-only boolean grants; missing policy records deny remote message, stream, room, file, and mailbox surfaces by default.

After signed peer trust and policy are in place, conUD/session sync exchanges signed public agent cards automatically over peer-encrypted relay control envelopes. The relay sees ciphertext and route metadata only. Manual fallback remains available:

```sh
conu agents trust <remote-agent-id> "<remote agent name>" --node <peer-node-id> --kind coding-agent --streams true --signing-key <agent-signing-public-key> --signature <agent-signature> --signature-key-id <agent-signature-key-id>
```

The agent signing fields and capability booleans come from `conu agents export <agent-id> --json`. Manual and automatic imports both verify the agent-card signature and only accept cards whose `nodeId` belongs to an already trusted peer with the same signing public key.

Then an agent can send through conU:

```sh
printf "opaque bytes" | conu messages send agent.local agent.remote --peer <peer-node-id> --stdin
conu streams open agent.local <remote-agent-id-with-streams>
printf "opaque stream bytes" | conu streams write <stream-id> --stdin
```

Stream chunks require the local sender and signed remote target metadata to advertise `streams=true`. conU CLI output shows metadata only. It should never show message text, reasoning, prompt content, private keys, or decrypted bytes.

## Hosting The Relay

The current hostable component is `conu-relay`.

Minimal VPS run:

```sh
mkdir -p /etc/conu-relay
conu-relay --issue-credential node-a-id --token-out /etc/conu-relay/node-a.token --credentials-file /etc/conu-relay/credentials.toml
conu-relay --issue-credential node-b-id --token-out /etc/conu-relay/node-b.token --credentials-file /etc/conu-relay/credentials.toml
export CONU_RELAY_CREDENTIALS_FILE=/etc/conu-relay/credentials.toml
export CONU_RELAY_MAX_CONNECTIONS=512
export CONU_RELAY_MAX_CONNECTIONS_PER_IP=64
export CONU_RELAY_MAX_FRAMES_PER_MINUTE=600
export CONU_RELAY_IDLE_TIMEOUT_SECONDS=120
export CONU_RELAY_SESSION_TTL_SECONDS=3600
export CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting
export CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400
export CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000
export CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824
conu-relay --serve 0.0.0.0:8787
```

`conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` generates a strong scoped token, writes the raw token to a new file for delivery to that node, and creates or appends only hashed metadata in `credentials.toml`. Omit `--credentials-file` when you intentionally want a hashed manifest entry for manual copy. Use `--replace` to rotate an existing node credential and `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a node revoked. `conu-relay --hash-token` remains available when an operator already has a token and only needs the hash fields.

`CONU_RELAY_CREDENTIALS_FILE` is the preferred self-hosted mode because each node gets its own relay token while the server keeps only a SHA-256 hash, lifecycle status, token length metadata, and optional `expires_at_unix`. The relay reloads this manifest for each new `HELLO` authentication attempt, so a revoked or expired credential is rejected for new sessions without a process restart. Existing authenticated sessions remain governed by idle timeout and max TTL. A missing or invalid manifest fails closed for new sessions until a valid file is restored. `CONU_RELAY_CREDENTIALS` remains available as comma-separated `node-id:token` compatibility config for controlled tests, and server-side `CONU_RELAY_TOKEN` is still available for local or tightly controlled shared-token tests. File credentials override `CONU_RELAY_CREDENTIALS`, which overrides `CONU_RELAY_TOKEN`. Each runtime can set `CONU_RELAY_TOKEN` to its assigned scoped token before `conu start` or `conu relay sync`, or store that client credential with `conu relay credential set --stdin`. The client environment variable wins when both client env and local stored credential are present. For non-loopback binds, every shared or scoped token must be custom and at least 24 characters.

`CONU_RELAY_ACCOUNTING_DIR` persists metadata-only `.accounting` files per node. They contain node ids, accounting window start, authenticated session counts, sent/received envelope counts, byte counts, mailbox counts, `payload_displayed = false`, and `token_displayed = false`; they do not contain relay tokens, message text, stream chunks, room-event plaintext, or ciphertext bodies. Set `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE` and/or `CONU_RELAY_MAX_BYTES_SENT_PER_NODE` to reject over-quota sends for a node during the configured accounting window with `UNDELIVERED reason=quota_exceeded`.

Open TCP port `8787` only to machines on a trusted private path, then give users:

```txt
ws://<relay-host>:8787
```

For public internet use, put a TLS terminator or reverse proxy with a valid certificate in front of `conu-relay` and give users the TLS endpoint:

```txt
wss://relay.example.com/conu
```

Systemd template:

```txt
packaging/linux/conud.service      local daemon template
```

Relay Docker template:

```sh
docker build -f packaging/docker/relay.Dockerfile -t conu-relay .
docker run --rm -p 8787:8787 \
  -e CONU_RELAY_CREDENTIALS_FILE=/var/lib/conu-relay/credentials/credentials.toml \
  -e CONU_RELAY_MAX_CONNECTIONS=512 \
  -e CONU_RELAY_MAX_CONNECTIONS_PER_IP=64 \
  -e CONU_RELAY_MAX_FRAMES_PER_MINUTE=600 \
  -e CONU_RELAY_IDLE_TIMEOUT_SECONDS=120 \
  -e CONU_RELAY_SESSION_TTL_SECONDS=3600 \
  -e CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE=128 \
  -e CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS=3600 \
  -e CONU_RELAY_MAILBOX_DIR=/var/lib/conu-relay/mailbox \
  -e CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting \
  -e CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400 \
  -e CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000 \
  -e CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824 \
  -v conu-relay-data:/var/lib/conu-relay \
  conu-relay
```

## Current Hosting Limit

The built-in client accepts `ws://` and `wss://` relay endpoints. `wss://` uses the platform certificate verifier, so the relay hostname must match a valid certificate. The bundled `conu-relay` server still listens as plain WebSocket; public TLS belongs in a reverse proxy or load balancer in front of it.

Before running a managed public relay, conU still needs:

- Managed hosted accounts, online credential issuance APIs, audit workflows, and tenant lifecycle beyond the offline `conu-relay --issue-credential` helper, `--revoke-credential`, and live-reloaded self-hosted credential manifest.
- Managed hosted quotas, abuse monitoring, dashboards, and adaptive response beyond the current self-hosted connection/frame caps and per-node accounting quotas.
- Distributed hosted relay session migration and accounting beyond the current idle-timeout, max-TTL session policy, same-process same-node resume hints, and authenticated/resumed session counters.
- Managed hosted mailbox retention/accounting dashboards beyond the current self-hosted durable ciphertext files and metadata-only mailbox counters.
- Multi-tenant hosted permission administration beyond the current local peer and room topic policy files.
- Non-Windows OS-backed private key storage. Windows local key and stored relay credential files already wrap secret bytes with current-user DPAPI, but hosted relay credentials still need a managed issuance, rotation, and revocation lifecycle.

Until those are complete, the best real-world test setup is a self-hosted relay behind TLS on a trusted VPS or a private network relay, using signed peer-card trust, explicit peer policy grants, optional local room topic policy grants, and peer-encrypted messages, stream chunks, and room events only.

## Agent Integration

For most modern agents, the easiest integration is MCP:

```json
{
  "mcpServers": {
    "conu": {
      "command": "conu-mcp",
      "env": {
        "CONU_AGENT_ID": "agent.mybot"
      }
    }
  }
}
```

Agents should use conU like this:

```txt
Register yourself.
List trusted peers and agents.
Send opaque bytes through conU.
Receive only messages addressed to you.
Never expect CLI output to show private message contents.
Treat conU as the road, not the conversation.
```

## Best Next Product Step

For the user install story, finish publishing in this order:

1. Keep release assets and checksums generated by CI.
2. Publish `@conu/cli` after the GitHub Release exists.
3. Put public relay tests behind TLS termination and use `wss://` endpoints.
4. Add hosted account auth, online credential issuance APIs, distributed monitoring/dashboards, hosted mailbox retention policy, and distributed hosted session state before opening a managed relay to everyone.
5. Add signed installers and OS package managers after npm and release archives are stable.
