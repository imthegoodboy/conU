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
conu-0.1.0-macos-x64.zip
conu-0.1.0-macos-arm64.zip
```

Each archive must have:

```txt
<asset>.sha256
```

The release workflow builds platform-named artifacts and uploads matching checksum files. Tagged release builds run a fail-closed preflight before package checks and platform builds; that preflight requires maintainer-owned signing secrets for Windows Authenticode, macOS Developer ID/notarization, and the repository `NPM_TOKEN` used for npm provenance publication. Linux archives use SHA-256 files plus GitHub artifact attestations until native distro package signing is added.

## Publishing Flow

1. Update all Cargo package versions, `packaging/npm/conu-cli/package.json`, and `sdk/typescript/package.json` to the same version.
2. Run `python scripts/verify-release-versions.py` locally; on `v*` tag builds the release workflow runs the same verifier and fails before packaging if the tag version does not match.
3. Run the release validation checklist.
4. Tag the release, for example `v0.1.0`.
5. Configure the repository signing secrets and `NPM_TOKEN` before creating the tag; the tagged release workflow fails before package checks if any required release secret is missing.
6. Let the `Release Artifacts` GitHub Actions workflow build platform archives, sign Windows binaries, sign and notarize macOS ZIP archives, verify that archives exclude conU state/log/payload paths and include the required install/service templates with strict checksum parsing and bounded streaming archive inspection, smoke-test the unpacked archive, the npm launcher local install path, and the npm launcher download/checksum install path with HTTPS-or-loopback URL enforcement, bounded timeout/size behavior, strict checksum archive-name matching, streamed npm archive hashing, archive-member count/duplicate/state-path preflight, bounded extracted-tree scanning, and exact extracted release-root binary selection, generate GitHub artifact attestations for the archives and `.sha256` files, upload the archives and `.sha256` files to the GitHub Release, run verified npm package content dry-runs that reject unexpected files, local state/build/payload paths, oversized files, and bundled dependencies, and publish `@conu/cli` plus `@conu/sdk` with npm provenance after GitHub Release assets are available.
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
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

For a local archive verification pass after running a build script:

```sh
python scripts/verify-release-artifacts.py dist
python scripts/smoke-release-artifacts.py dist
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

For a downloaded release archive, verify the GitHub artifact attestation when `gh` is available:

```sh
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

For platform signing verification commands and the required repository secrets,
see `docs/platform-code-signing.md`.

The verifier streams each archive check, requires a strict checksum line naming
the matching archive, bounds archive/member/manifest sizes plus member counts,
checks required binaries, `manifest.toml` payload flags, required install/service templates, and common forbidden
local-state paths such as `.conu`, `security/`, `messages/`, `runtime/`,
`logs/`, `routes/`, `node_modules/`, and vendored package binaries. The smoke
scripts then prove the current-platform archive starts from an unpacked install
and that the npm launcher package can copy those binaries into `vendor/`, create
npm bin shims, download the archive through an HTTPS `CONU_NPM_DIST_BASE` or a
loopback HTTP smoke server with bounded request time and response sizes, require
a strict `.sha256` line naming the archive, stream the archive hash, reject excessive members, duplicate normalized paths, and forbidden state paths before extraction, extract it, bound extracted-tree entry/depth scanning, require either a rootless release layout or the expected `conu-<version>-<platform>/bin/` layout without duplicate binary names elsewhere, and report
`ready_for_local_use` without displaying payload contents.

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
export CONU_RELAY_SESSION_STATE_DIR=/var/lib/conu-relay/sessions
export CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE=128
export CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS=3600
export CONU_RELAY_MAILBOX_DIR=/var/lib/conu-relay/mailbox
export CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS=3600
export CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting
export CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400
export CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000
export CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824
export CONU_RELAY_ABUSE_DIR=/var/lib/conu-relay/abuse
export CONU_RELAY_ABUSE_WINDOW_SECONDS=86400
conu-relay --serve 0.0.0.0:8787
```

`conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` generates a strong scoped token, writes the raw token to a new file for delivery to that node, and creates or appends only hashed metadata in `credentials.toml`. Omit `--credentials-file` when you intentionally want a hashed manifest entry for manual copy. Use `--replace` to rotate an existing node credential and `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a node revoked. `conu-relay --hash-token` remains available when an operator already has a token and only needs the hash fields.

`CONU_RELAY_CREDENTIALS_FILE` is the preferred self-hosted mode because each node gets its own relay token while the server keeps only a SHA-256 hash, lifecycle status, token length metadata, and optional `expires_at_unix`. The relay reloads this manifest for each new `HELLO` authentication attempt, so a revoked or expired credential is rejected for new sessions without a process restart. Existing authenticated sessions remain governed by idle timeout and max TTL. A missing or invalid manifest fails closed for new sessions until a valid file is restored. `CONU_RELAY_CREDENTIALS` remains available as comma-separated `node-id:token` compatibility config for controlled tests, and server-side `CONU_RELAY_TOKEN` is still available for local or tightly controlled shared-token tests. File credentials override `CONU_RELAY_CREDENTIALS`, which overrides `CONU_RELAY_TOKEN`. Each runtime can set `CONU_RELAY_TOKEN` to its assigned scoped token before `conu start` or `conu relay sync`, or store that client credential with `conu relay credential set --stdin`. The client environment variable wins when both client env and local stored credential are present. For non-loopback binds, every shared or scoped token must be custom and at least 24 characters.

`CONU_RELAY_SESSION_STATE_DIR` persists metadata-only `.session` files per node so a same-node resume hint can survive a relay restart until the session TTL expires. They contain node ids, relay session ids, timestamps, and display guards; they do not contain relay tokens, token hashes, payloads, ciphertext bodies, private keys, or account secrets. Keep this directory on protected relay storage. Inspect local session-state pressure with `conu-relay --session-audit --session-state-dir /var/lib/conu-relay/sessions [--node <node-id>] [--json]`; it reports record counts, active/expired/invalid totals, timestamp bounds, and false display guards without printing session ids. Managed relay operators can query the same metadata from the running relay with `conu-relay --admin-session-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--json]`. The current file-backed session store is a single-writer boundary for self-hosted relays and controlled failover tests; it is not a distributed lock service or multi-region session migration layer.

`CONU_RELAY_MAILBOX_DIR` persists durable `.mailbox` files for peer-encrypted offline envelopes. These files contain route metadata, public key material, ciphertext, and `payload_displayed = false`; they do not contain plaintext message text, stream chunks, room-event plaintext, relay tokens, token hashes, private keys, or session ids. Inspect local retention pressure with `conu-relay --mailbox-audit --mailbox-dir /var/lib/conu-relay/mailbox [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--json]`. Managed relay operators can query the same retention metadata from the running relay with `conu-relay --admin-mailbox-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--json]`. The audits report aggregate file counts, byte totals, queue timestamp bounds, optional expired counts, invalid mailbox-file counts, and false display guards only. To enforce the same retention boundary manually, run `conu-relay --mailbox-purge --mailbox-dir /var/lib/conu-relay/mailbox [--ttl-seconds 3600] [--node <node-id>] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] --dry-run [--json]`, review the aggregate expired counts, then rerun with `--confirm` to delete only expired valid `.mailbox` files. Managed operators can run the same confirm-gated cleanup against a running relay with `conu-relay --admin-mailbox-purge --relay wss://relay.example.com/conu --admin-token-stdin [--ttl-seconds 3600] [--node <node-id>] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] (--dry-run|--confirm) [--json]`. Set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` when the relay should run the same expired-file cleanup on a local schedule using `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`; this requires `CONU_RELAY_MAILBOX_DIR`, and `0` or an empty value disables it. Purge output does not render stored relay frames, ciphertext bodies, payloads, tokens, token hashes, private keys, or session ids. Retention policy files are metadata-only TOML-style files with `version = "1"`, optional `ttl_seconds` and `node_id`, and false display guards for payload, token, token hash, key material, session id, ciphertext, and contents. CLI `--ttl-seconds` and `--node` values override file defaults, and purge commands still require a TTL from file or CLI plus exactly one of `--dry-run` or `--confirm`. This is a single-relay operator workflow, not distributed hosted retention automation or billing.

`CONU_RELAY_ACCOUNTING_DIR` persists metadata-only `.accounting` files per node. They contain node ids, accounting window start, authenticated session counts, sent/received envelope counts, byte counts, mailbox counts, `payload_displayed = false`, and `token_displayed = false`; they do not contain relay tokens, token hashes, session ids, message text, stream chunks, room-event plaintext, or ciphertext bodies. Set `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE` and/or `CONU_RELAY_MAX_BYTES_SENT_PER_NODE` to reject over-quota sends for a node during the configured accounting window with `UNDELIVERED reason=quota_exceeded`.

`CONU_RELAY_ABUSE_DIR` persists metadata-only `.abuse` files for enforcement outcomes such as admin unauthorized attempts, credential-denied sessions, tenant-denied sessions, rate limits, session expiry, quota-denied forwards, undelivered forwards, and mailbox rejects. They contain aggregate counters, optional node ids, window start, and display guards only; they do not contain raw tokens, token hashes, admin tokens, session ids, payloads, ciphertext bodies, private keys, or arbitrary frame contents. Inspect them with `conu-relay --abuse-audit --abuse-dir /var/lib/conu-relay/abuse [--node <node-id>] [--json]`, or compare local counters against explicit maximums with `conu-relay --abuse-threshold-report --abuse-dir /var/lib/conu-relay/abuse [--node <node-id>] --max-<metric> <count>... [--json] [--fail-on-threshold]`. To inspect a local operator dashboard snapshot across credential, tenant, accounting, and abuse stores, run `conu-relay --hosted-dashboard --credentials-file /etc/conu-relay/credentials.toml --tenants-file /etc/conu-relay/tenants.toml --accounting-dir /var/lib/conu-relay/accounting --abuse-dir /var/lib/conu-relay/abuse [--account <account-id>] [--node <node-id>] [--json]`. Before startup or release smoke, run `conu-relay --hosted-readiness --bind-addr 0.0.0.0:8787 --credentials-file /etc/conu-relay/credentials.toml --admin-tokens-file /etc/conu-relay/admin-tokens.toml --tenants-file /etc/conu-relay/tenants.toml --session-state-dir /var/lib/conu-relay/sessions --mailbox-dir /var/lib/conu-relay/mailbox --accounting-dir /var/lib/conu-relay/accounting --abuse-dir /var/lib/conu-relay/abuse [--account <account-id>] [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--thresholds-file /etc/conu-relay/abuse-thresholds.toml] [--max-<metric> <count>...] [--json] [--fail-on-warning]`; it reports only configured paths, source booleans, counts, threshold checks/exceeded counts, warnings, bind metadata, and false display guards. To inspect a local scoped admin-token manifest before loading it, run `conu-relay --admin-token-audit --admin-tokens-file /etc/conu-relay/admin-tokens.toml --bind-addr 0.0.0.0:8787 [--account <account-id>] [--json]`; it reports scope/account/lifecycle/expiry counts and false display guards without printing admin tokens, token hashes, or manifest contents. To query the same class of counters from a running managed relay, pipe an admin token into `conu-relay --admin-hosted-dashboard --relay wss://relay.example.com/conu --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]`; to evaluate thresholds online, use `conu-relay --admin-abuse-threshold-report --relay wss://relay.example.com/conu --admin-token-stdin [--account <account-id>] [--node <node-id>] --max-<metric> <count>... [--json] [--fail-on-threshold]`. With `--fail-on-threshold`, threshold commands preserve the stdout report and return exit code 3 only when at least one configured threshold is exceeded; with `--fail-on-warning`, readiness also returns exit code 3 when configured abuse thresholds are exceeded. Use `conu-relay --admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, and `--admin-tenant-audit` with `--admin-token-stdin` to update or audit the configured tenant registry on a running relay without shell access to the file; output is tenant/node counts and display guards only. Suspend one hosted account locally with `conu-relay --hosted-account-suspend <account-id> --credentials-file /etc/conu-relay/credentials.toml --tenants-file /etc/conu-relay/tenants.toml [--json]`, or online with `conu-relay --admin-hosted-account-suspend <account-id> --relay wss://relay.example.com/conu --admin-token-stdin [--json]`; both forms revoke tenant metadata before account credential records and report counts/display guards only. Use `conu-relay --admin-session-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--json]` for a read-only online snapshot of configured file-backed session-state metadata. Use `conu-relay --admin-mailbox-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--json]` for a read-only online snapshot of configured durable mailbox retention metadata, and `conu-relay --admin-mailbox-purge --relay wss://relay.example.com/conu --admin-token-stdin [--ttl-seconds 3600] [--node <node-id>] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] (--dry-run|--confirm) [--json]` for confirm-gated online cleanup. `CONU_RELAY_ADMIN_TOKEN` is a full-admin compatibility secret; `CONU_RELAY_ADMIN_TOKENS_FILE` can live-read hashed scoped admin tokens for credential, tenant, dashboard, sessions, mailbox-audit, and mailbox-purge actions, with optional account ids for account-bound operators. Hosted account suspension requires full-admin access or both credential and tenant scopes; hosted abuse threshold reports use dashboard scope, and account-scoped session audits require a node filter plus an active tenant-node record. The current stores, threshold reports, and readiness preflights are single-writer relay-local workflows for self-hosted or controlled managed deployments, not a distributed abuse pipeline, hosted workflow system, alerting service, or hosted dashboard service.

For a controlled multi-relay deployment where metadata stores are available to one operator host, create a guarded fleet manifest and run `conu-relay --hosted-fleet-dashboard --fleet-file /etc/conu-relay/fleet-dashboard.toml [--account <account-id>] [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--thresholds-file /etc/conu-relay/abuse-thresholds.toml] [--max-<metric> <count>...] [--json] [--fail-on-retention] [--fail-on-threshold]`. To plan a static response workflow for aggregate fleet abuse threshold breaches, run `conu-relay --hosted-fleet-abuse-response-plan --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] [--thresholds-file /etc/conu-relay/abuse-thresholds.toml] [--max-<metric> <count>...] [--json] [--fail-on-action]`; it reports categories such as admin access, credential/tenant access, traffic pressure, delivery health, and mailbox pressure without changing any relay state. Before tenant workflow mutation, run `conu-relay --hosted-fleet-account-audit <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] [--json] [--fail-on-warning]` to report credential/tenant source coverage and account or node consistency warning categories across local stores. To revoke one compromised account/node credential across local credential manifests without changing tenant metadata, run `conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml --dry-run [--json]`, review the aggregate and per-relay credential counts, then rerun with `--confirm`. To suspend one account or one account node across complete local credential/tenant source pairs, run `conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] --dry-run [--json]`, review the aggregate and per-relay counts, then rerun with `--confirm`. To clean expired durable mailbox files across those manifest-listed local stores, run `conu-relay --hosted-fleet-mailbox-purge --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] --dry-run [--json]`, review the aggregate and per-relay counts, then rerun with `--confirm`. The manifest uses `version = "1"`, explicit false display guards, and one or more `[[relay]]` entries with `name`, plus optional `credentials_file`, `tenants_file`, `session_state_dir`, `mailbox_dir`, `mailbox_ttl_seconds`, `accounting_dir`, and `abuse_dir`. Relative paths resolve from the manifest directory. Fleet output sums only metadata counters and source paths; when retention is configured it evaluates relay-local mailbox TTL metadata and returns exit code 3 only with `--fail-on-retention` and at least one TTL-checked source with expired records. CLI `--ttl-seconds` overrides all fleet mailbox TTLs for that run, while per-relay `mailbox_ttl_seconds` entries remain source-specific overrides ahead of the policy-file TTL. The fleet account audit command is read-only, may narrow counts and warning categories with `--node`, and returns exit code 3 only with `--fail-on-warning` and at least one warning; the fleet credential revoke command requires explicit dry-run or confirm, preflights all credential sources before confirmed mutation, rejects node/account collisions, and never contacts remote relays; the fleet account suspension command rejects partial credential/tenant entries, preflights all complete sources before confirmed mutation, revokes tenant metadata before credentials in account-wide mode, revokes tenant-node metadata before matching node credentials with `--node`, and never contacts remote relays. The fleet purge command uses the same TTL precedence and deletes only expired valid `.mailbox` files when `--confirm` is supplied. When thresholds are configured the dashboard evaluates aggregate abuse counters and returns exit code 3 only with `--fail-on-threshold` and at least one exceeded limit; the response plan returns exit code 3 only with `--fail-on-action` and at least one recommended action category. These fleet commands do not read or print tokens, token hashes, session ids, payloads, ciphertext bodies, arbitrary frame contents, private keys, mailbox file contents, policy contents, or manifest contents, and they are not hosted billing, remote relay purge, remote tenant control, cross-region retention locking, or adaptive abuse automation services.

For tenant account lifecycle across the same manifest-listed local tenant registries, run `conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml --dry-run [--json]`, review tenant/source counts, then rerun with `--confirm`; revoke uses `conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml --dry-run [--json]` followed by `--confirm`. The tenant account commands require explicit dry-run or confirm, preflight every configured local `tenants_file` before confirmed mutation, create missing tenant files only for confirmed upsert, require the account to exist before revoke, never contact remote relays, and report only account id, counts, paths, mode/status, and display guards.

Threshold commands and hosted readiness can load reusable policy files with `--thresholds-file /etc/conu-relay/abuse-thresholds.toml` when an abuse store is configured. A threshold policy file must contain `version = "1"`, any supported `max_*` keys, and explicit `payload_displayed = false`, `token_displayed = false`, `token_hash_displayed = false`, `key_material_displayed = false`, `session_id_displayed = false`, `ciphertext_displayed = false`, and `contents_displayed = false` guards. CLI `--max-*` values override file defaults for one-off runs.

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
  -e CONU_RELAY_SESSION_STATE_DIR=/var/lib/conu-relay/sessions \
  -e CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE=128 \
  -e CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS=3600 \
  -e CONU_RELAY_MAILBOX_DIR=/var/lib/conu-relay/mailbox \
  -e CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS=3600 \
  -e CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting \
  -e CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400 \
  -e CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000 \
  -e CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824 \
  -e CONU_RELAY_ABUSE_DIR=/var/lib/conu-relay/abuse \
  -e CONU_RELAY_ABUSE_WINDOW_SECONDS=86400 \
  -v conu-relay-data:/var/lib/conu-relay \
  conu-relay
```

For a managed relay, provide `CONU_RELAY_ADMIN_TOKEN` from your secret manager for full-admin compatibility, or set `CONU_RELAY_ADMIN_TOKENS_FILE` to a protected hashed admin-token manifest for scoped operator tokens, and keep `CONU_RELAY_CREDENTIALS_FILE` enabled. Audit scoped admin-token manifests locally with `conu-relay --admin-token-audit --admin-tokens-file <path> --bind-addr <relay-bind> [--account <id>] [--json]` before loading them into the relay, and run `conu-relay --hosted-readiness ... [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] --json --fail-on-warning` against the configured local stores before startup or release smoke. Optionally set `CONU_RELAY_TENANTS_FILE` to a protected tenant registry file. The online admin commands in `docs/hosted-relay-account-auth.md` issue, rotate, revoke, audit account-scoped node credentials, manage tenant account/node metadata, suspend a single relay-local hosted account, request admin-gated session-state/dashboard snapshots and abuse threshold reports, and run mailbox retention audit/purge by sending only token hash metadata or metadata-only requests to the relay; the tenant commands in the same doc manage account, node, hosted permission, and public key-id metadata without granting local peer policy. Where several local relay stores are available on one operator host, the guarded fleet account audit command can report account-wide or node-scoped credential/tenant consistency warnings, the guarded fleet credential revoke command can dry-run or confirm account/node credential revocation across manifest-listed credential files, and the guarded fleet account suspension command can dry-run or confirm tenant-first account suspension or tenant-node-first node suspension across complete manifest-listed credential/tenant file pairs without remote relay control.

## Current Hosting Limit

The built-in client accepts `ws://` and `wss://` relay endpoints. `wss://` uses the platform certificate verifier, so the relay hostname must match a valid certificate. The bundled `conu-relay` server still listens as plain WebSocket; public TLS belongs in a reverse proxy or load balancer in front of it.

Before running a managed public relay, conU still needs:

- Distributed hosted account control planes and remote tenant lifecycle beyond the current single-relay file-backed account metadata, hosted tenant registry, scoped admin-token manifest and audit, local/admin-gated account suspension, guarded local fleet account/node audit, tenant-node upsert/revoke, account/node suspension, online credential issue/rotate/revoke/audit APIs, online tenant account/node lifecycle, offline `conu-relay --issue-credential` helper, `--revoke-credential`, and live-reloaded credential manifest.
- Managed hosted quotas, distributed abuse monitoring, dashboards, and adaptive response beyond the current self-hosted connection/frame caps, per-node accounting quotas, single-relay metadata-only abuse counters, local `--abuse-threshold-report` reports with optional `--fail-on-threshold`, local `--hosted-dashboard` snapshots, local `--hosted-readiness` preflights, admin-gated online `--admin-abuse-threshold-report` reports with optional `--fail-on-threshold`, and admin-gated online `--admin-hosted-dashboard` snapshots.
- Distributed hosted relay session migration and accounting beyond the current idle-timeout, max-TTL session policy, same-node resume hints, file-backed session records, payload-safe local/admin session-state audits, and authenticated/resumed session counters.
- Managed hosted mailbox retention/accounting dashboards beyond the current self-hosted durable ciphertext files, metadata-only mailbox counters, relay-local and admin-gated online mailbox audit snapshots, confirm-gated local/admin online purge commands, and relay-local scheduled purge policy.
- Hosted dashboard services and distributed permission administration beyond the current single-writer local/admin-gated tenant registry, account suspension, guarded fleet account/node suspension, local/admin-gated single-relay dashboard snapshots, and local peer/room topic policy files.
- Hosted managed key administration and hardware-backed key policy. Windows local key and stored relay credential files wrap secret bytes with current-user DPAPI, macOS uses user Keychain, Linux uses Secret Service when available, and non-Windows operators can still configure `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` for a user-managed encrypted fallback. Secure Enclave, HSM, and hosted identity/key administration still need dedicated work.

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
4. Add distributed account control planes, remote tenant lifecycle/workflow automation beyond guarded local fleet account/node audit, tenant-node upsert/revoke, account/node suspension plus single-relay account suspension/scoped admin tenant commands, distributed monitoring/dashboards/alerting beyond single-relay threshold reports, distributed hosted mailbox retention policy beyond local/admin-gated audit and purge plus local scheduled purge workflows, and distributed multi-instance session migration before opening a managed relay to everyone.
5. Add OS package managers, detached Linux package signatures, and auto-update policy after npm and release archives are stable.
