# conU User Install And Agent Guide

This guide explains how a user can install the current conU app, start it on their PC, and let local agents use it.

Current version status: Phase 14 and Phase 15 are complete for the current local-first app, with rooms/pub/sub metadata, encrypted-at-rest local room event fanout, relay-backed room event fanout, authenticated direct QUIC delivery for reachable trusted peers, a stronger CLI dashboard/connect flow, and relay-backed message, stream-chunk, and room-event paths that run from conUD when configured. conU is usable for local agent registration, signed public agent-card exchange after peer trust, automatic encrypted signed-agent-card exchange during session sync, peer-scoped permission grants, local encrypted-at-rest message submission, local identity-key rotation with peer-card refresh, local archived identity-key retirement after peer-card refresh, local storage-key rotation with message queue/inbox re-encryption, local archived storage-key retirement after dependency scanning, local agent connect streams, room/pub/sub metadata and local or remote fanout, signed manual public peer-card exchange, peer-encrypted one-shot direct or relay messages, stream chunks, and room events between trusted nodes, bounded offline relay mailbox delivery with optional durable ciphertext files, configurable relay connection/frame/mailbox limits, payload-safe relay session-state audits, metadata-only relay accounting and abuse counters, stream metadata, trust metadata, direct/relay route metadata, private CLI watch output, payload-safe local log rotation, payload-safe local telemetry snapshots, Rust SDK calls, Python and TypeScript/JavaScript wrapper SDKs, an MCP stdio adapter, repeatable release builds, service templates, a native-binary npm launcher template, Docker relay hosting template, and `conu doctor` readiness checks. It is not yet a managed public hosted internet release.

## What Works Today

- Install from source with Rust or from a Phase 15 release artifact.
- Initialize local conU state and security keys.
- Start and stop the local `conUD` runtime.
- Register local agents by id.
- Send local opaque payload bytes from one registered local agent to another.
- Connect two local registered agents with `conu connect local`.
- Create room metadata, join local or mirrored trusted remote agents, and publish opaque room events by topic and byte count with local inbox fanout for joined local participants and relay-backed fanout for joined trusted remote participants.
- Store new conU-owned local payload files encrypted at rest.
- Rotate local identity signing/exchange keys with `conu security rotate identity --confirm-peer-refresh`, export the refreshed public card with `conu identity export`, and retire archived identity keys after peer-card refresh with `conu security retire identity --confirm-peer-refresh-complete`.
- Rotate local storage keys and re-encrypt conU-owned encrypted-at-rest message queue/inbox payload files with `conu security rotate storage --confirm`.
- Retire archived local storage keys that no scanned queue/inbox payload file still references with `conu security retire storage --confirm`.
- On macOS, local signing, exchange, storage, archived key, and stored relay credential secret fields use the user Keychain. On Linux with `secret-tool` and a user Secret Service session, those fields use Secret Service. Other non-Windows systems can configure `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` before `conu init` or `conu security audit` to encrypt those fields under an operator-managed wrap key.
- List inbox, receipt, stream, peer, session, and security metadata.
- Sync and inspect authenticated direct QUIC routes and relay fallback metadata.
- Run a standalone `conu-relay` and let conUD move peer-encrypted one-shot messages, stream chunks, and room events through it when relay config or trusted peer relay endpoints exist, including bounded mailbox delivery when the target node reconnects.
- Configure basic `conu-relay` total connection, per-IP connection, and per-session frame-rate limits.
- Export/import signed public peer cards for manual cross-machine trust.
- Export/import signed public agent cards for trusted peers.
- Let Rust agents use `conu_sdk::ConuClient`.
- Let Python agents use `sdk/python/conu_sdk`.
- Let TypeScript/JavaScript agents use `sdk/typescript` / `@conu/sdk`.
- Let MCP-capable agents launch `conu-mcp` and call conU tools.
- Run `conu doctor` to check local install readiness and payload-safe logs.
- Rotate local metadata logs by size and archive count with `conu logs rotate`.
- Export a local allowlisted aggregate telemetry snapshot with `conu telemetry snapshot --json`.
- Use Windows, systemd, and launchd service templates.
- Use the npm launcher packaging template once platform release assets are published.
- Host the current relay yourself for controlled `ws://` tests or behind TLS termination for `wss://`.
- Aggregate multiple relay-local credential, tenant, session-state, mailbox, accounting, and abuse metadata stores with `conu-relay --hosted-fleet-dashboard --fleet-file <path> [--account <id>] [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold] [--fail-on-retention]`.

## What Does Not Work Yet

- No signed one-click installer yet.
- No published `@conu/cli` package yet; the package template exists under `packaging/npm/conu-cli` and should be published after GitHub Release assets/checksums exist.
- No CLI command that reveals message contents. This is intentional; use SDK or MCP explicit receive APIs when the addressed local agent needs payload bytes.
- Rooms provide local pub/sub coordination, encrypted-at-rest local fanout, relay-backed fanout to joined trusted remote agents, per-topic publish/subscribe grants for configured topics, and watch visibility.
- No hosted relay service yet. The client supports reachable `ws://` and certificate-valid `wss://` relay endpoints, and relays can use offline scoped credentials or account-scoped online issue/rotate/revoke/audit against a live credential manifest, but the bundled relay server itself is still plain WebSocket and needs TLS termination for public use.
- Direct QUIC works for reachable configured endpoints between trusted peers. Route sync records static host candidate metadata and reports `nat_traversal_unavailable` when no usable candidate exists for NAT profiles that need traversal help, but ICE-style candidate gathering, STUN/TURN, UDP hole punching, and managed hosted NAT traversal are not implemented yet.
- Pairing and remote sessions are local metadata groundwork, not full cross-machine rendezvous.
- Relay-backed one-shot message, stream-chunk, room-event, and bounded offline-mailbox delivery exists through the conUD relay pump with a reusable daemon relay session and same-node reconnect resume; set `CONU_RELAY_SESSION_STATE_DIR` on the relay for metadata-only same-node resume records across relay restarts and `CONU_RELAY_MAILBOX_DIR` for ciphertext persistence across relay restarts. Relays can use offline scoped credential issuance, manifest upsert/rotation/revocation helpers, account-scoped online issue/rotate/revoke/audit, scoped hosted admin-token manifests with payload-safe local `--admin-token-audit`, payload-safe local `--hosted-readiness` startup/release preflights, admin-gated online tenant account/node lifecycle for one configured relay registry, local/admin-gated hosted account suspension, live-reloaded hashed scoped credential manifests with revocation/expiry metadata, payload-safe local and admin-gated online session-state audits, payload-safe local and admin-gated online mailbox retention audits with reusable policy files, confirm-gated local/admin expired mailbox purge, relay-local scheduled expired mailbox purge, metadata-only accounting with optional sent quotas, metadata-only abuse counters, local/admin-gated abuse threshold reports with reusable policy files and optional fail-on-threshold exit status, local hosted-dashboard snapshots, and admin-gated online hosted-dashboard snapshots. Distributed hosted dashboards/accounting/adaptive abuse workflows beyond single-relay threshold reports and readiness preflights, distributed tenant lifecycle/workflow services beyond scoped single-relay account suspension/admin tokens, distributed hosted mailbox retention orchestration beyond single-relay purge, and distributed multi-instance session migration are not implemented yet.
- `conu-relay --hosted-fleet-dashboard --fleet-file <path>` can aggregate multiple relay-local metadata stores from a guarded manifest and apply reusable mailbox retention policies plus reusable abuse thresholds to aggregate counters, but it is still an operator snapshot/script gate, not hosted billing, distributed alerting, adaptive abuse response, remote purge, or distributed retention orchestration.
- Service templates exist, but users still need to install/register them for their platform.
- On Windows, local signing, exchange, active storage, archived identity/storage, and stored relay credential secret bytes are wrapped with current-user DPAPI and older plaintext-hex key files migrate during `conu init` or `conu security audit`. On macOS, conU uses the user Keychain. On Linux, conU uses Secret Service when `secret-tool` and a user session are available. Non-Windows systems without a native store can set `CONU_SECRET_WRAP_KEY_HEX` to 64 hex characters or `CONU_SECRET_WRAP_KEY_FILE` to a file containing 64 hex characters before initialization/audit to migrate those same secret fields to `secret_protection = "user-managed-wrap-key-v1"`. The wrap key is not stored by conU, so keep it in your OS/user secret manager or deployment secret store and do not pass it on the command line. `CONU_DISABLE_OS_SECRET_BACKEND=1` forces the non-Windows fallback path for controlled tests. `conu security rotate identity --confirm-peer-refresh` rotates active signing/exchange keys while keeping prior identity keys readable from `security/identity-keys/` for the peer-card refresh window; `conu security retire identity --confirm-peer-refresh-complete` removes those archived identity keys after old-key decrypt compatibility is no longer needed. `conu security rotate storage --confirm` rotates the active storage key and re-encrypts local encrypted-at-rest message queue/inbox payload files while keeping the prior key readable from `security/storage-keys/`; `conu security retire storage --confirm` removes only archived keys that no scanned local queue/inbox payload file still references. Non-Windows builds without a native store or configured wrap key rely on owner-only key files.

## Install With npm

This is the best public install shape once the first GitHub Release and npm package are published:

```powershell
npm install -g @conu/cli
conu doctor
conu init
conu logs rotate --max-bytes 1048576 --keep 5
conu telemetry snapshot --json
conu start
```

The npm package is not the conU implementation. It is a small launcher that downloads the native Rust archive for the user's platform, verifies the `.sha256` checksum, and exposes `conu`, `conud`, `conu-relay`, and `conu-mcp` on `PATH`.

For local testing of the package template from this repo:

```powershell
$env:CONU_NPM_BINARY_DIR = "$PWD\dist\conu-0.1.0-windows-x64\bin"
npm install -g .\packaging\npm\conu-cli
conu doctor
conu logs rotate --max-bytes 1048576 --keep 5
conu telemetry snapshot --json
```

See `docs/distribution-and-hosting.md` for the release asset names, publish flow, and relay hosting path.

## Install From Source

### Requirements

- Git.
- Rust from `rustup`.
- On Linux source builds, OpenSSL development headers may be needed for the `wss://` relay client dependency.
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
cargo +stable-x86_64-pc-windows-gnu install --path crates/conu-mcp --locked --force
```

macOS/Linux shell, assuming the default toolchain links successfully:

```bash
cargo install --path crates/conu-cli --locked --force
cargo install --path crates/conud --locked --force
cargo install --path crates/conu-relay --locked --force
cargo install --path crates/conu-mcp --locked --force
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
conu doctor
```

`conu-mcp` is a stdio server for MCP clients, so it normally waits for JSON-RPC input instead of printing a standalone check screen.

## Install From A Release Artifact

Build or unpack a release artifact, then use the package scripts.

On Windows without Visual Studio C++ Build Tools, build artifacts with the GNU toolchain:

```powershell
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Windows current-user install:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin
```

Optional Windows service install from an elevated shell:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin -InstallService
```

Linux systemd:

```bash
sudo cp bin/conu bin/conud bin/conu-relay bin/conu-mcp /usr/local/bin/
sudo cp packaging/linux/conud.service /etc/systemd/system/conud.service
sudo systemctl daemon-reload
sudo systemctl enable --now conud
```

macOS launchd:

```bash
sudo cp bin/conu bin/conud bin/conu-relay bin/conu-mcp /usr/local/bin/
# Edit packaging/macos/com.conu.conud.plist and replace /Users/YOU first.
cp packaging/macos/com.conu.conud.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.conu.conud.plist
```

Edit the service template paths and user/state location before enabling a machine-wide service.

## First Run

Initialize local state and local security keys:

```powershell
conu init
conu security audit
conu status
conu doctor
```

To rotate local identity keys and refresh public peer-card material:

```powershell
conu security rotate identity --confirm-peer-refresh
conu identity export
conu security retire identity --confirm-peer-refresh-complete
```

Run the retire command only after trusted peers have imported the refreshed public peer card and old-key decrypt compatibility is no longer needed.

To rotate the local storage encryption key after messages have been queued or delivered:

```powershell
conu security rotate storage --confirm
conu security retire storage --confirm
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

Default registration allows messages and presence. Add `--streams true` for stream/connect use and `--rooms true` for room/pub-sub use.

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

## Connect Two Local Agents

If two agents are on the same PC, register both and open a local metadata stream:

```powershell
conu agents register agent.codex "Codex Desktop" --kind coding-agent --streams true --rooms true
conu agents register agent.hermes "Hermes" --kind coding-agent --streams true --rooms true
conud --process-ipc
conu connect local agent.codex agent.hermes
conu watch
```

This gives the agents a conU connection surface and gives the user a live dashboard/watch view. The stream can record opaque chunks with:

```powershell
"opaque stream bytes" | conu streams write <stream-id> --stdin
```

The CLI shows stream id, route, packet count, and byte count. It does not show the stream bytes.

## Create A Local Room

Rooms are the current multi-agent coordination layer:

```powershell
conu rooms create room.dev "Dev Room" --agent agent.codex
conu rooms join room.dev agent.hermes
conu rooms policy room.dev agent.hermes build --publish true --subscribe false
conu rooms policy room.dev agent.codex build --publish false --subscribe true
"opaque room bytes" | conu rooms publish room.dev agent.hermes build --stdin
conu rooms
conu rooms events
conu watch
```

Room commands show only room id, participants, topic, event id, route label, byte count, local/remote delivery counts, topic grants, and timestamps. Room registry/events/policy/log files do not store the room event payload; joined local recipients receive the opaque bytes as encrypted-at-rest event envelopes in their message inbox, and joined trusted remote recipients receive peer-encrypted relay room-event envelopes. Use rooms when several agents need a shared bus; use direct messages when one agent is addressing exactly one other agent.

`conu rooms policy` is optional until a topic needs stricter control. Unconfigured topics use room membership as the subscription boundary. Once any policy record exists for a room/topic, publishing and receiving that topic require explicit per-agent grants:

```powershell
conu rooms policy <room-id> <agent-id> <topic> --publish true --subscribe true
conu rooms policy --json
```

## Sync Routes

Phase 13 lets conUD choose route metadata for trusted peers:

```powershell
conu pair
conu join <code>
conu routes sync
conu routes
conu routes --json
conu routes probes
```

To advertise this node's direct listener, add a direct endpoint to `config.toml` before exporting your peer card:

```toml
default_relay = "ws://127.0.0.1:8787"
relay_auto_sync = true
nat_profile = "public"
direct_quic_endpoint = "quic://127.0.0.1:9443"
```

Use a peer-specific sanitized key when one peer needs its own endpoint:

```toml
direct_quic_peer_abcd1234 = "quic://203.0.113.10:9443"
```

`conu routes sync` writes only route metadata. A direct route is selected only after a live QUIC probe succeeds and the remote node answers a peer-encrypted challenge using the trusted peer-card key. Failed direct probes are recorded with `direct_quic_probe_failed`, and missing traversal support is recorded with `nat_traversal_unavailable`; relay remains selected in both cases. Route and probe output includes candidate source, candidate kind, and rendezvous state, but it does not print, log, or inspect message contents, tokens, private keys, or endpoint secrets.

## Send Remote Relay Messages And Streams

Start a reachable relay. For local testing:

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
$env:CONU_RELAY_ACCOUNTING_DIR = "C:\conu-relay\accounting"
$env:CONU_RELAY_ACCOUNTING_WINDOW_SECONDS = "86400"
$env:CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE = "10000"
$env:CONU_RELAY_MAX_BYTES_SENT_PER_NODE = "1073741824"
$env:CONU_RELAY_ABUSE_DIR = "C:\conu-relay\abuse"
$env:CONU_RELAY_ABUSE_WINDOW_SECONDS = "86400"
conu-relay --serve 0.0.0.0:8787
```

`conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` writes the raw token only to a new token file and creates or updates `credentials.toml` with `version = "1"` plus one `[[credential]]` entry per node containing `node_id`, `token_sha256_hex`, `token_length`, lifecycle status, optional expiry, `payload_displayed = false`, and `token_displayed = false`. Use `--replace` on the issue command to rotate an existing node credential, or `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a credential revoked. A revoked or expired credential is rejected for new sessions without restarting the relay. Existing authenticated sessions remain bounded by idle timeout and max TTL. Missing or invalid manifests fail closed for new sessions.

Managed relay operators can also set full-admin `CONU_RELAY_ADMIN_TOKEN`, or `CONU_RELAY_ADMIN_TOKENS_FILE` for hashed scoped admin tokens, plus optional `CONU_RELAY_TENANTS_FILE`. Tenant commands such as `conu-relay --tenant-upsert`, `--tenant-node-upsert`, `--tenant-node-revoke`, `--tenant-revoke`, and `--tenant-audit` store account/node status, hosted permission booleans, and public key ids only. Operators can run the same tenant lifecycle online against the running relay with `conu-relay --admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, and `--admin-tenant-audit`, always with `--admin-token-stdin`; admin tenant output is tenant/node counts and display guards only. Operators can suspend one account locally with `conu-relay --hosted-account-suspend` or online with `conu-relay --admin-hosted-account-suspend`, which revoke tenant metadata before account credential records and report counts/display guards only. Scoped admin manifests can grant separate credentials, tenants, dashboard, sessions, mailbox-audit, and mailbox-purge scopes with optional account ids; audit them locally with `conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <id>] [--json]` before startup. Account suspension requires both credentials and tenants scopes unless the full-admin token is used, account-scoped session audit requires a node filter plus an active tenant-node record, and scope failures return `admin_scope_denied` without echoing tokens or hashes. When the tenant file is configured, credential issue/rotate and new relay sessions fail closed for missing or revoked tenant/node records.

`local-dev-token` is loopback-only. Use a custom shared token or scoped credential token with at least 24 characters before binding a relay to `0.0.0.0`. For a self-hosted relay with multiple known nodes, prefer `CONU_RELAY_CREDENTIALS_FILE` so each node has its own relay token without storing raw tokens on the server. On each node, either set `CONU_RELAY_TOKEN` to that node's assigned scoped token before starting conUD, or store it locally without printing the token:

```powershell
Get-Content -Raw <path-to-this-node-token-file> | conu relay credential set --stdin
conu relay credential status
```

`CONU_RELAY_TOKEN` overrides the stored credential when both are present. `conu relay credential status` reports only whether a credential is configured and which secret backend protects it; it does not display the token.

`CONU_RELAY_SESSION_STATE_DIR` writes per-node `.session` files with node ids, relay session ids, timestamps, and display guards only. These files are useful for self-hosted relay restart recovery, but they are not a distributed session migration or lock service. Inspect local session-state metadata with `conu-relay --session-audit --session-state-dir C:\conu-relay\sessions [--node <node-id>] --json`; managed relay operators can query the same metadata from the running relay with `conu-relay --admin-session-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] --json`. Both forms report counts, active/expired/invalid totals, timestamp bounds, and false display guards only, not relay session ids or file contents. `CONU_RELAY_MAILBOX_DIR` writes durable `.mailbox` files for peer-encrypted offline envelopes. Inspect local mailbox retention pressure with `conu-relay --mailbox-audit --mailbox-dir C:\conu-relay\mailbox --ttl-seconds 3600 --retention-policy-file C:\conu-relay\mailbox-retention.toml --json`; audit output reports file counts, byte totals, timestamp bounds, optional expired counts, invalid mailbox-file counts, and display guards only, not stored frames or ciphertext bodies. Managed relay operators can query the same read-only retention metadata from the running relay with `conu-relay --admin-mailbox-audit --relay wss://relay.example.com/conu --admin-token-stdin --ttl-seconds 3600 --retention-policy-file C:\conu-relay\mailbox-retention.toml --json`. To remove expired durable mailbox files, run `conu-relay --mailbox-purge --mailbox-dir C:\conu-relay\mailbox --retention-policy-file C:\conu-relay\mailbox-retention.toml --dry-run --json`, review the aggregate counts, then rerun with `--confirm`; managed relay operators can run the same cleanup against the running relay with `conu-relay --admin-mailbox-purge --relay wss://relay.example.com/conu --admin-token-stdin --retention-policy-file C:\conu-relay\mailbox-retention.toml (--dry-run|--confirm) --json`. Confirmed purge deletes only expired valid `.mailbox` files and still reports only aggregate metadata. Account-scoped admin session and mailbox tokens require a node filter and an active tenant-node record. Set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` with `CONU_RELAY_MAILBOX_DIR` to run the same expired valid-file cleanup on a relay-local schedule using the offline envelope TTL. `CONU_RELAY_ACCOUNTING_DIR` writes per-node `.accounting` files with metadata counters only. `CONU_RELAY_ABUSE_DIR` writes `.abuse` files with aggregate denial/enforcement counters for unauthorized sessions, credential or tenant denies, rate limits, session expiry, quota denies, undelivered forwards, and mailbox rejects. Inspect them with `conu-relay --abuse-audit --abuse-dir C:\conu-relay\abuse --json`, compare explicit maximums with `conu-relay --abuse-threshold-report --abuse-dir C:\conu-relay\abuse --max-admin-unauthorized 0 --max-rate-limited-sessions 100 --json --fail-on-threshold`, inspect a combined local operator snapshot with `conu-relay --hosted-dashboard --credentials-file C:\conu-relay\credentials.toml --tenants-file C:\conu-relay\tenants.toml --accounting-dir C:\conu-relay\accounting --abuse-dir C:\conu-relay\abuse --json`, run a pre-startup/release check with `conu-relay --hosted-readiness --bind-addr 0.0.0.0:8787 --credentials-file C:\conu-relay\credentials.toml --admin-tokens-file C:\conu-relay\admin-tokens.toml --tenants-file C:\conu-relay\tenants.toml --session-state-dir C:\conu-relay\sessions --mailbox-dir C:\conu-relay\mailbox --retention-policy-file C:\conu-relay\mailbox-retention.toml --accounting-dir C:\conu-relay\accounting --abuse-dir C:\conu-relay\abuse --thresholds-file C:\conu-relay\abuse-thresholds.toml --max-rate-limited-sessions 100 --json --fail-on-warning`, suspend one account with `conu-relay --hosted-account-suspend <account-id> --credentials-file C:\conu-relay\credentials.toml --tenants-file C:\conu-relay\tenants.toml --json`, or query a running managed relay with `conu-relay --admin-hosted-dashboard --relay wss://relay.example.com/conu --admin-token-stdin --json`. Managed operators can also run `conu-relay --admin-abuse-threshold-report --relay wss://relay.example.com/conu --admin-token-stdin --max-admin-unauthorized 0 --max-rate-limited-sessions 100 --json --fail-on-threshold` to get count/max/exceeded metadata from the running relay. With `--fail-on-threshold`, threshold reports preserve stdout and return exit code 3 only when a configured maximum is exceeded; with `--fail-on-warning`, hosted-readiness preserves stdout and returns exit code 3 when warnings exist, including exceeded configured abuse thresholds. Audit, threshold, dashboard, and readiness output does not show tokens, token hashes, admin tokens, private keys, session ids, payloads, ciphertext bodies, frame contents, or manifest contents. Account-scoped dashboard tokens without a node filter suppress global accounting and abuse counters. These files and snapshots are useful for self-hosted usage checks, session-state visibility, quota enforcement, mailbox pressure checks, local/admin expired-mailbox cleanup, relay-local tenant lifecycle/account suspension, and relay-local abuse visibility, but they are not a managed billing, distributed abuse-monitoring, distributed hosted retention orchestration, or distributed hosted dashboard system.

For repeated mailbox retention checks or cleanup, create a metadata-only retention policy file and pass `--retention-policy-file C:\conu-relay\mailbox-retention.toml` to local/admin mailbox audit/purge commands, hosted readiness, or hosted fleet dashboards. The file uses `version = "1"`, optional `ttl_seconds` and `node_id` keys, and false display guards; CLI `--ttl-seconds` and `--node` options can override it for a single run. On hosted fleet dashboards, `--fail-on-retention` preserves stdout and returns exit code 3 only when TTL-checked fleet mailbox sources report expired records; it does not purge files or contact remote relays. For repeated threshold checks, create a metadata-only thresholds file and pass `--thresholds-file C:\conu-relay\abuse-thresholds.toml` to local/admin threshold commands, hosted readiness, or hosted fleet dashboards. The file uses `version = "1"`, supported `max_*` keys, and false display guards; CLI `--max-*` options can override it for a single run.

On each node, set `default_relay` in `config.toml` or pass the relay endpoint when trusting a peer. `relay_auto_sync = true` is the default for new state and lets conUD pump relay send/receive automatically when a relay route is configured. Then exchange signed public cards:

```powershell
conu identity export --json
conu peers trust <peer-node-id> "<peer name>" --exchange-key <exchange-public-key-hex> --relay wss://relay.example.com/conu --signing-key <signing-public-key-hex> --signature <signature-hex> --signature-key-id <signature-key-id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
```

The `signingPublicKeyHex`, `signatureHex`, and `signatureKeyId` values come from the peer's `conu identity export --json` output. conU verifies the signature before storing the trusted peer when those fields are supplied. Legacy unsigned imports still work for controlled tests, but signed peer cards are the production-oriented path. Trust does not grant communication by itself; `conu peers policy` grants only the peer surfaces you choose and missing policy records deny by default.

After signed peer trust and policy are in place, conUD/session sync exchanges signed public agent cards automatically over peer-encrypted relay control envelopes. The relay sees routing metadata and ciphertext, not the signed-card contents. Manual signed agent-card import remains available for daemonless fallback:

```powershell
conu agents export agent.sender --json
conu agents trust agent.remote "Remote Agent" --node <receiver-node-id> --kind test-agent --streams true --signing-key <agent-signing-public-key> --signature <agent-signature> --signature-key-id <agent-signature-key-id>
```

The signing fields, kind, and capability booleans come from the peer's `conu agents export <agent-id> --json` output. conU verifies the agent-card signature and rejects cards whose `nodeId` is not already trusted or whose signing key does not match the trusted peer card. Automatic exchange uses the same verification path before writing `agents/remote.toml`.

Use `ws://127.0.0.1:8787` for same-machine tests. Use `wss://...` for public internet relay paths after TLS is terminated in front of `conu-relay`.

Start conUD and register the addressed local agent on each side:

```powershell
conu start
conu agents register agent.sender "Sender Agent" --kind test-agent --streams true
```

On the receiver:

```powershell
conu start
conu agents register agent.remote "Remote Agent" --kind test-agent --streams true
```

On the sender:

```powershell
"opaque bytes for the remote agent" | conu messages send agent.sender agent.remote --peer <receiver-node-id> --stdin
```

Remote stream writes use the same relay route after the remote agent is visible through trusted discovery and advertises `streams=true`.

```powershell
conu streams open agent.sender <remote-agent-id-with-streams>
"opaque stream bytes" | conu streams write <stream-id> --stdin
```

On the receiver:

```powershell
conu messages inbox agent.remote --json
```

The running daemon keeps a relay WebSocket session open across runtime ticks while the endpoint is stable, and reconnects after failures. Stream chunks arrive in the addressed inbox with `kind` and `streamId` metadata. Room events arrive as `kind = "event"` inbox entries and payload-safe room event metadata. The explicit `conu relay sync` command still exists for manual flushes, debugging, or daemonless scripts; it shows counts and route metadata only. It does not show message, stream, or room-event contents. For a full two-terminal walkthrough, see `docs/internet-relay-test.md`.

## Give conU To An Agent

Agents can use conU through MCP, Rust, Python, TypeScript/JavaScript, or direct CLI calls.

### MCP Agent Setup

Add `conu-mcp` to the agent's MCP server config:

```json
{
  "mcpServers": {
    "conu": {
      "command": "conu-mcp",
      "env": {
        "CONU_HOME": "C:\\Users\\you\\AppData\\Roaming\\conU",
        "CONU_AGENT_ID": "agent.mybot"
      }
    }
  }
}
```

Tell the MCP agent:

```txt
Use conU tools for communication.

Rules:
- Launch one `conu-mcp` server per agent and set `CONU_AGENT_ID`.
- Register once with conu_register_agent.
- Use conu_set_presence when your state changes.
- Discover local and trusted remote metadata with conu_list_agents and conu_list_peers.
- Exchange signed public peer cards with conu_export_identity and conu_trust_peer when setting up remote trust.
- Grant intended peer surfaces with conu_set_peer_policy before remote message, stream, or room traffic.
- Let session sync exchange signed public agent cards automatically after signed peer trust and peer policy grants; use conu_export_agent_card and conu_trust_agent_card only for manual fallback.
- Sync and inspect route metadata with conu_sync_routes and conu_list_routes.
- Send opaque bytes with conu_send_message.
- Send remote peer-encrypted bytes with conu_send_remote_message while conUD is running; call conu_relay_sync only for manual flush/debug flows.
- Read inbox metadata first; request payloadHex only with conu_receive_message when you are the addressed local agent.
- Use conu_open_stream, conu_write_stream, and conu_close_stream for stream metadata flows; remote writes to mirrored trusted peers are delivered as relay `stream_chunk` envelopes when a relay route exists.
- Use conu_create_room, conu_join_room, conu_publish_room_event, conu_list_rooms, and conu_list_room_events for shared room/pub-sub metadata and local or trusted remote fanout.
- Use conu_set_room_topic_policy and conu_list_room_topic_policies when a room topic needs explicit publish/subscribe grants.
- Treat conU as the road, not the conversation.
```

### Rust Agent Setup

Inside this workspace, Rust agents can depend on:

```toml
conu-sdk = { path = "crates/conu-sdk" }
```

Minimal usage:

```rust
use conu_sdk::{ConuClient, PeerPolicyUpdate};

let client = ConuClient::new();
client.init()?;
client.register_agent("agent.mybot", "My Bot", "local-agent")?;
client.process_queued()?;
let _local_agent_card = client.export_agent_card("agent.mybot")?;
// Manual fallback for a SignedAgentCard received from an already trusted peer:
// client.trust_remote_agent_card(remote_agent_card)?;
client.set_peer_policy("node_peer", PeerPolicyUpdate {
    messages: Some(true),
    streams: Some(true),
    rooms: Some(false),
    files: Some(false),
    mailbox: Some(false),
})?;
client.send_message_bytes("agent.mybot", "agent.other", b"opaque bytes")?;
client.send_remote_message_bytes("agent.mybot", "agent.remote", "node_peer", b"opaque bytes")?;
client.create_room("room.dev", "Dev Room", "agent.mybot")?;
client.join_room("room.dev", "agent.other")?;
client.set_room_topic_policy("room.dev", "agent.mybot", "build", conu_sdk::TopicPolicyUpdate {
    publish: Some(true),
    subscribe: Some(true),
})?;
client.publish_room_event_bytes("room.dev", "agent.mybot", "build", b"opaque bytes")?;
client.relay_sync(std::time::Duration::from_millis(3000))?;
```

### Python Agent Setup

For local development:

```powershell
$env:PYTHONPATH = "$PWD\sdk\python"
```

```python
from conu_sdk import ConuClient

client = ConuClient(home=".conu-agent")
client.init()
client.register_agent("agent.mybot", "My Bot")
client.process_queued()
local_agent_card = client.export_agent_card("agent.mybot")
# Manual fallback for a dict received from an already trusted peer:
# client.trust_agent_card(remote_agent_card)
client.set_peer_policy("node_peer", messages=True, streams=True)
client.send_message("agent.mybot", "agent.other", b"opaque bytes")
client.send_remote_message("agent.mybot", "agent.remote", "node_peer", b"opaque bytes")
client.create_room("room.dev", "Dev Room", "agent.mybot")
client.join_room("room.dev", "agent.other")
client.set_room_topic_policy("room.dev", "agent.mybot", "build", publish=True, subscribe=True)
client.publish_room_event("room.dev", "agent.mybot", "build", b"opaque bytes")
client.relay_sync(wait_ms=3000)
```

### TypeScript/JavaScript Agent Setup

For local development:

```powershell
npm run check --prefix sdk/typescript
```

```javascript
import { ConuClient } from "@conu/sdk";

const client = new ConuClient({ home: ".conu-agent" });
client.init();
client.registerAgent("agent.mybot", "My Bot", { rooms: true, streams: true });
client.registerAgent("agent.other", "Other", { rooms: true, streams: true });
client.processQueued();
const localAgentCard = client.exportAgentCard("agent.mybot");
// Manual fallback for a signed card received from an already trusted peer:
// client.trustAgentCard(remoteAgentCard);
client.setPeerPolicy("node_peer", { messages: true, streams: true, rooms: true });
client.sendMessage("agent.mybot", "agent.other", "opaque bytes");
client.processQueued();
const inbox = client.inbox("agent.other");
const received = client.receiveMessageBytes("agent.other", inbox.entries[0].envelopeId);
client.sendRemoteMessage("agent.mybot", "agent.remote", "node_peer", "opaque bytes");
client.createRoom("room.dev", "Dev Room", "agent.mybot");
client.joinRoom("room.dev", "agent.other");
client.setRoomTopicPolicy("room.dev", "agent.mybot", "build", { publish: true, subscribe: true });
client.publishRoomEvent("room.dev", "agent.mybot", "build", "opaque bytes");
client.relaySync(3000);
console.log({ receivedBytes: received.byteLength, contentsDisplayed: false });
```

The wrapper passes payload bytes through stdin and returns CLI JSON metadata for normal list/status surfaces. It does not print payloads, and raw inbox bytes are available only through explicit addressed-agent receive helpers such as `receiveMessageBytes(agentId, envelopeId)`.

### CLI Agent Fallback

Give the agent this operating contract:

```txt
You may use conU as a local communication transport.

Rules:
- Register once at startup:
  conu agents register <agent-id> <display-name> --kind <kind> [--streams true] [--rooms true]
- Refresh presence when your state changes:
  conu agents heartbeat <agent-id> --presence <ready|busy|idle|offline>
- Send payload bytes through stdin only:
  <payload bytes> | conu messages send <your-agent-id> <target-agent-id> --stdin
- Connect to a local peer:
  conu connect local <your-agent-id> <target-agent-id>
- Use rooms for shared coordination:
  conu rooms create <room-id> <display-name> --agent <your-agent-id>
  conu rooms join <room-id> <target-agent-id>
  conu rooms policy <room-id> <your-agent-id> <topic> --publish true --subscribe true
  <payload bytes> | conu rooms publish <room-id> <your-agent-id> <topic> --stdin
- Use JSON commands for machine-readable metadata:
  conu status --json
  conu agents --json
  conu rooms --json
  conu rooms events --json
  conu rooms policy --json
  conu identity export --json
  conu agents export <agent-id> --json
  conu messages inbox <agent-id> --json
  conu messages receipts --json
  conu security audit --json
- For remote delivery, import a peer card once:
  conu peers trust <peer-node-id> <display-name> --exchange-key <hex> --relay <ws://host:port|wss://host/path> --signing-key <hex> --signature <hex> --signature-key-id <id>
- Grant the intended remote surfaces:
  conu peers policy <peer-node-id> --messages true --streams true --rooms true
- For remote agent discovery, keep conUD running so session sync can exchange signed agent cards automatically. Manual fallback:
  conu agents trust <remote-agent-id> <display-name> --node <peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id>
- Send remote payload bytes through stdin only:
  <payload bytes> | conu messages send <your-agent-id> <target-agent-id> --peer <peer-node-id> --stdin
- Keep conUD running for relay delivery:
  conu start
- Optional manual flush/receive:
  conu relay sync --wait-ms 3000
- Never expect conU CLI output to show message contents.
- Treat conU as the road, not the conversation.
```

For local testing, a wrapper script can call:

```powershell
conu agents register agent.mybot "My Bot" --kind local-agent --streams true --rooms true
conu agents register agent.other "Other Agent" --kind local-agent --streams true --rooms true
conud --process-ipc
"hello as opaque bytes" | conu messages send agent.mybot agent.other --stdin
conud --process-ipc
conu messages inbox agent.other --json
```

## Current App Issues To Know

These are not hidden bugs; they are the honest state of the current app:

| Area | Current issue | User impact | Workaround today |
| --- | --- | --- | --- |
| Installer | Release artifact scripts exist, tagged release workflow supports Windows Authenticode and macOS notarization, but one-click OS installers are not published | Users still install from archives or source until package-manager distribution exists | Verify checksums, GitHub attestations, and platform signatures before install |
| npm install | `@conu/cli` template exists but is not published until release assets are attached | `npm install -g @conu/cli` is the target path, not a live package guarantee yet | Use source install or a local `CONU_NPM_BINARY_DIR` package test |
| Windows linker | Default MSVC toolchain may fail without `link.exe` | `cargo check/test/install` can fail | Use `stable-x86_64-pc-windows-gnu` or install Visual Studio C++ Build Tools |
| Runtime discovery | `conu start` needs `conud` beside `conu` or on PATH | Start can fail after manual binary moves | Install both with Cargo or set `CONUD_EXE` |
| Agent API | Rust SDK, Python wrapper, TypeScript/JavaScript Node wrapper, and MCP adapter exist | Most local/server-side agents can integrate now; browser-native and hosted SDK permission work still need future design | Use MCP, Rust SDK, Python SDK, TypeScript Node SDK, or CLI/stdin |
| Browser TypeScript | `@conu/sdk` has a fail-closed browser export boundary, but no browser-native protocol transport | Browser apps cannot safely use long-lived local relay tokens, node keys, or local `CONU_HOME` state directly | Use the Node wrapper outside the browser until hosted auth, browser transport, and key handling are designed |
| Receiving payloads | CLI and wrapper SDKs intentionally list inbox metadata only | Agents needing bytes must use explicit receive APIs | Use Rust SDK `receive_message_bytes`, TypeScript `receiveMessageBytes`, or MCP `conu_receive_message` with `includePayload` |
| Internet messaging | One-shot relay messages, stream chunks, room events, same-node relay-session resume with optional file-backed session state, and bounded offline mailbox delivery work through the conUD relay pump, the client accepts `ws://` plus certificate-valid `wss://`, and relays support offline scoped credential issuance, account-scoped online issue/rotate/revoke/audit/dashboard snapshots, hashed scoped hosted admin tokens with local manifest audit, policy-aware local hosted-readiness preflights, admin-gated online tenant lifecycle for one configured relay registry, local/admin-gated hosted account suspension, live-reloaded scoped credentials, hashed credential manifests, payload-safe local/admin-gated session-state audits, metadata-only accounting/quotas, metadata-only abuse counters and scriptable threshold reports, payload-safe local and admin-gated online mailbox retention audits with reusable policy files, confirm-gated local/admin and relay-local scheduled expired mailbox purge, local hosted-dashboard snapshots, and optional durable ciphertext mailbox files; no hosted relay service, distributed multi-instance session migration, or distributed hosted dashboard/accounting/adaptive abuse workflow exists | Users can test over private `ws://` or public `wss://` with TLS termination; managed public network is not ready | Run `conu-relay` yourself on a trusted host with relay limit/session/mailbox/accounting/abuse env vars, issue scoped tokens with `conu-relay --issue-credential --credentials-file` or the hosted admin credential commands, manage tenant metadata locally with `conu-relay --tenant-*` or online with `conu-relay --admin-tenant-*`, suspend one hosted account with `conu-relay --hosted-account-suspend` or `conu-relay --admin-hosted-account-suspend`, use `CONU_RELAY_ADMIN_TOKENS_FILE` for narrower admin tokens and audit it with `conu-relay --admin-token-audit`, persist `CONU_RELAY_SESSION_STATE_DIR`, `CONU_RELAY_MAILBOX_DIR`, `CONU_RELAY_ACCOUNTING_DIR`, and `CONU_RELAY_ABUSE_DIR`, inspect session state with `conu-relay --session-audit` or `conu-relay --admin-session-audit`, inspect mailbox pressure with `conu-relay --mailbox-audit` or `conu-relay --admin-mailbox-audit`, clean expired durable mailbox files with `conu-relay --mailbox-purge --dry-run` then `--confirm` or `conu-relay --admin-mailbox-purge`, use `--retention-policy-file` for repeated mailbox TTL/node settings, set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` for local scheduled cleanup, inspect hosted counters with `conu-relay --hosted-dashboard` or `conu-relay --admin-hosted-dashboard`, run `conu-relay --hosted-readiness` with optional retention/threshold policy files before startup/release smoke, compare abuse thresholds with `conu-relay --abuse-threshold-report` or `conu-relay --admin-abuse-threshold-report` plus optional `--fail-on-threshold`, and put TLS termination in front of it for public endpoints |
| Direct transport | Authenticated QUIC works for reachable configured endpoints, and route sync records static candidate metadata plus `nat_traversal_unavailable`; ICE/STUN/TURN hole punching and hosted NAT traversal do not | Direct works on public or otherwise reachable UDP endpoints; difficult NATs use relay | Configure signed direct endpoints where reachable and keep relay fallback configured |
| Pairing | Pair/join are local trust groundwork | Not real cross-machine pairing yet | Use for metadata/trust testing |
| Service install | Service templates exist but need local edits/admin steps | User must choose service path/user | Use `packaging/windows`, `packaging/linux`, or `packaging/macos` templates |
| Key storage | Windows wraps local key, archived identity/storage key, and stored relay credential secret bytes with current-user DPAPI; macOS uses user Keychain; Linux uses Secret Service when `secret-tool` and a user session are available; other non-Windows paths can use `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE`, otherwise secrets are owner-only local files; identity-key rotation, identity archive retirement, storage-key rotation, and unused storage archive retirement exist for local state | Local secret exposure is reduced on Windows/macOS/Linux native paths, non-Windows operators still have an encrypted external-key fallback, public peer-card material can be refreshed after identity rotation, archived old identity keys can be removed after peer-card refresh, local storage payloads can be re-encrypted under a new key, and unused archived storage keys can be retired after dependency scanning | Run `conu security audit --json`, confirm `secretStorageBackend` and `secretsOsProtected`, see `docs/native-secret-storage.md` for macOS/Linux smoke checks, and use the rotation/retirement commands when changing keys |
| Logs and telemetry | Local metadata logs can be rotated by size and archive count, and local structured telemetry can be exported as allowlisted aggregate counters | Rotation reports filenames and counts only; telemetry reports schema, field allowlist, aggregate counters, and `contentsDisplayed=false` only | Run `conu logs rotate --max-bytes 1048576 --keep 5`, `conu doctor --json`, and `conu telemetry snapshot --json` |
| IPC | File-backed queues | Good for development, not final hot path | Use current gateway until named pipe/socket IPC lands |

## Recommended User Flow Today

For a developer testing conU locally:

```powershell
conu init
conu security audit
conu doctor
conu logs rotate --max-bytes 1048576 --keep 5
conu telemetry snapshot --json
conu start
conu agents register agent.a "Agent A" --kind test-agent
conu agents register agent.b "Agent B" --kind test-agent
conu routes sync
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
conu routes sync
"test opaque payload" | conu messages send agent.a agent.b --stdin
conud --process-ipc
conu messages inbox agent.b --json
```

## Best Next Product Work

To make conU genuinely useful over the internet, the next phase should build:

- Distributed hosted session lifecycle beyond local/admin-gated single-relay `--session-audit` snapshots, distributed hosted dashboards/accounting beyond local/admin-gated single-relay `--hosted-dashboard`, `--hosted-readiness`, `--hosted-fleet-dashboard`, `--admin-hosted-dashboard`, `--abuse-threshold-report`, and `--admin-abuse-threshold-report` snapshots/reports with optional script exit status, distributed hosted mailbox retention orchestration beyond read-only hosted fleet retention gates, local/admin-gated `--mailbox-audit`, local/admin-gated `--mailbox-purge`, and scheduled purge workflows, and distributed tenant lifecycle/workflow automation beyond the single-relay account credential, scoped admin-token manifest and audit, hosted account suspension, and local/admin-gated tenant registry lifecycle.
- Published npm package backed by platform release assets and checksums.
- Tenant-wide hosted dashboard workflow services beyond the current admin-token-gated single-relay dashboard snapshot, scoped admin-token manifest and audit, local topic policy file, and single-writer hosted tenant registry.
- Managed direct NAT traversal beyond static candidate metadata, including ICE/STUN/TURN or hosted direct-candidate rendezvous.
- Browser-native TypeScript protocol support remains future work; the current Node wrapper uses installed binaries and MCP for explicit payload receive, while browser-conditioned imports fail closed through a safe unsupported stub.
- OS package-manager installers, detached Linux package signatures, and managed hosted account/key administration after local packaging stabilizes.
