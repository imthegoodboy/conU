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
  -> peer-encrypted relay message
  -> conu-relay
  -> remote conUD
  -> remote agent inbox
```

The user or agent does this once:

```sh
conu init
conu start
conu agents register agent.local "Local Agent" --kind coding-agent
conu identity export --json
```

Then the peer's public card is trusted:

```sh
conu peers trust <peer-node-id> "<peer name>" --exchange-key <peer-exchange-key> --relay ws://<relay-host>:8787
```

Then an agent can send through conU:

```sh
printf "opaque bytes" | conu messages send agent.local agent.remote --peer <peer-node-id> --stdin
```

conU CLI output shows metadata only. It should never show message text, reasoning, prompt content, private keys, or decrypted bytes.

## Hosting The Relay

The current hostable component is `conu-relay`.

Minimal VPS run:

```sh
export CONU_RELAY_TOKEN="replace-with-a-shared-test-token"
conu-relay --serve 0.0.0.0:8787
```

Open TCP port `8787` to the machines that need to connect, then give users:

```txt
ws://<relay-host>:8787
```

Systemd template:

```txt
packaging/linux/conud.service      local daemon template
```

Relay Docker template:

```sh
docker build -f packaging/docker/relay.Dockerfile -t conu-relay .
docker run --rm -p 8787:8787 -e CONU_RELAY_TOKEN=replace-me conu-relay
```

## Current Hosting Limit

The built-in client currently accepts `ws://` relay endpoints. That is enough for local networks, private VPNs, and controlled internet tests, but it is not the final public cloud shape.

Before running a managed public relay, conU still needs:

- `wss://` client support.
- Strong hosted relay auth and token rotation.
- Public relay rate limits and abuse controls.
- Persistent relay sessions instead of bounded sync windows.
- Offline encrypted mailbox delivery.
- Relay-backed stream byte routing.
- Remote signed agent-card exchange.
- Capability policy.
- OS-backed private key storage.

Until those are complete, the best real-world test setup is a self-hosted relay on a trusted VPS or private network, using peer-card trust and peer-encrypted messages only.

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
3. Add `wss://` client support before advertising a public hosted relay.
4. Add relay auth/rate limits and persistent sessions before opening a managed relay to everyone.
5. Add signed installers and OS package managers after npm and release archives are stable.
