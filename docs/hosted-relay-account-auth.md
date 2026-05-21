# Hosted Relay Account Auth

conU now has a metadata-only hosted relay credential lifecycle for managed relay operators. It is still a relay connection feature, not a central agent service:

```txt
Agents own the conversation.
conU owns the connection.
```

## Account Model

Hosted relay credentials are scoped by:

- `account_id`: the hosted owner or tenant record.
- `node_id`: the runtime node allowed to connect.
- `token_sha256_hex` and `token_length`: token verifier metadata.
- `status`: `active` or `revoked`.
- `expires_at_unix`: optional expiry for new relay sessions.

Runtime clients still authenticate with `HELLO node=<node-id> token=<node-token> payload=not_observed`. The relay maps the node credential to account metadata server-side. Payloads, room topics, message contents, stream chunks, private keys, and raw node tokens are not part of account records or admin output.

## Tenant Registry

Managed relays can add a metadata-only tenant registry beside the credential manifest:

- tenant account id and `active` or `revoked` status
- hosted node id and `active` or `revoked` status
- hosted permission booleans for `messages`, `streams`, `rooms`, `files`, and `mailbox`
- optional public signing/exchange key ids
- display guards proving tokens, key material, payloads, ciphertext bodies, and manifest contents were not displayed

These hosted permission booleans are an operator-side boundary only. They do not grant local peer policy. conUD still enforces local trust, peer policy, agent capabilities, room topic policy, and peer encryption before delivery.

## Relay Setup

Online admin lifecycle requires the live credential manifest:

```powershell
$env:CONU_RELAY_CREDENTIALS_FILE = "C:\conu-relay\credentials.toml"
$env:CONU_RELAY_TENANTS_FILE = "C:\conu-relay\tenants.toml"
$env:CONU_RELAY_ABUSE_DIR = "C:\conu-relay\abuse"
$env:CONU_RELAY_ADMIN_TOKEN = (Get-Content -Raw C:\secure\relay-admin.token).Trim()
conu-relay --serve 0.0.0.0:8787
```

`CONU_RELAY_ADMIN_TOKEN` must be custom, contain no whitespace, and be at least 24 characters. It is the backward-compatible full-admin path and is accepted only when `CONU_RELAY_CREDENTIALS_FILE` is configured. Operators can also set `CONU_RELAY_ADMIN_TOKENS_FILE` with hashed scoped admin tokens. `CONU_RELAY_TENANTS_FILE` is optional, but when set it requires either `CONU_RELAY_ADMIN_TOKEN` or `CONU_RELAY_ADMIN_TOKENS_FILE` plus `CONU_RELAY_CREDENTIALS_FILE`. Missing credential or tenant records fail closed for new runtime sessions.

Scoped admin tokens are live-read from a metadata-only manifest. Generate each `token_sha256_hex` with `conu-relay --hash-token` over stdin, store the raw token in your secret manager, and grant only the needed action scopes:

```toml
version = "1"

[[admin_token]]
account_id = "account.prod"
token_sha256_hex = "<sha256-hex-from-conu-relay-hash-token>"
token_length = 48
status = "active"
scope_credentials = true
scope_tenants = false
scope_dashboard = false
scope_mailbox_audit = false
scope_mailbox_purge = false
payload_displayed = false
token_displayed = false
token_hash_displayed = false
contents_displayed = false

[[admin_token]]
account_id = "account.prod"
token_sha256_hex = "<sha256-hex-from-conu-relay-hash-token>"
token_length = 48
status = "active"
scope_credentials = false
scope_tenants = true
scope_dashboard = true
scope_mailbox_audit = false
scope_mailbox_purge = false
payload_displayed = false
token_displayed = false
token_hash_displayed = false
contents_displayed = false
```

Scopes map to admin actions: `scope_credentials` allows issue/rotate/revoke/audit credential commands, `scope_tenants` allows tenant upsert/revoke/audit commands, `scope_dashboard` allows hosted dashboard snapshots and hosted abuse threshold reports, and the mailbox scopes allow read-only mailbox audits or confirm-gated mailbox purges. Hosted account suspension requires either the full-admin compatibility token or a scoped admin token with both `scope_credentials = true` and `scope_tenants = true`, because it revokes tenant and credential metadata together. If `account_id` is present, credential, tenant, and account-suspension actions are limited to that account. Account-scoped dashboard snapshots or threshold reports without a node filter suppress global accounting and abuse counters; account-scoped mailbox audit/purge requires a node filter and an active tenant-node record. Scope failures return `admin_scope_denied` without echoing the submitted token or stored hash.

## Tenant Lifecycle

Tenant commands can run as local/offline file updates for the relay operator:

```powershell
conu-relay --tenant-upsert account.prod `
  --tenants-file C:\conu-relay\tenants.toml

conu-relay --tenant-node-upsert account.prod node-a-id `
  --tenants-file C:\conu-relay\tenants.toml `
  --messages true `
  --streams true `
  --rooms true `
  --files false `
  --mailbox true `
  --signing-key-id signing.key.2026-05 `
  --exchange-key-id exchange.key.2026-05 `
  --json

conu-relay --tenant-node-revoke account.prod node-a-id `
  --tenants-file C:\conu-relay\tenants.toml

conu-relay --tenant-revoke account.prod `
  --tenants-file C:\conu-relay\tenants.toml

conu-relay --tenant-audit `
  --tenants-file C:\conu-relay\tenants.toml `
  --account account.prod `
  --json
```

The same lifecycle is available against a running managed relay through the admin control plane:

```powershell
Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-tenant-upsert account.prod `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-tenant-node-upsert account.prod node-a-id `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --messages true `
    --streams true `
    --rooms true `
    --files false `
    --mailbox true `
    --signing-key-id signing.key.2026-05 `
    --exchange-key-id exchange.key.2026-05 `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-tenant-node-revoke account.prod node-a-id `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-tenant-revoke account.prod `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-tenant-audit `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --account account.prod `
    --json
```

When `CONU_RELAY_TENANTS_FILE` is configured, online issue and rotate require an active tenant account and active hosted node. New `HELLO` sessions also fail closed when the tenant account or hosted node is missing or revoked. Credential revoke remains available so operators can clean up credential metadata even after tenant or node revocation.

## Account Suspension

Managed relay operators can suspend one hosted account against a single relay's configured credential and tenant files:

```powershell
conu-relay --hosted-account-suspend account.prod `
  --credentials-file C:\conu-relay\credentials.toml `
  --tenants-file C:\conu-relay\tenants.toml `
  --json
```

The local command revokes the tenant record first, then marks every credential record for that account as revoked. Revoking the tenant first makes new issue/rotate operations and new `HELLO` sessions fail closed before credential cleanup continues. The command reports only account, credential, tenant, node, policy, path, and display-guard metadata. It does not print raw node tokens, admin tokens, token hashes, private keys, relay session ids, payloads, ciphertext bodies, frame contents, or manifest contents.

The same workflow can run through the admin control plane:

```powershell
Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-hosted-account-suspend account.prod `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --json
```

The admin form requires `CONU_RELAY_CREDENTIALS_FILE`, `CONU_RELAY_TENANTS_FILE`, and hosted admin configuration through `CONU_RELAY_ADMIN_TOKEN` or `CONU_RELAY_ADMIN_TOKENS_FILE`. A full-admin token can suspend any account. A scoped admin-token record must have both credential and tenant scopes and, when it carries an `account_id`, can suspend only that account. Output is metadata-only: action/status, account id, credential counts, tenant/node counts, hosted policy counts, relay endpoint, and false display guards.

This is a single-relay file-backed operator workflow. It is not a distributed account lifecycle service, transactional billing suspension, hosted identity/key suspension, cross-relay revocation, or tenant-wide workflow automation.

## Online Lifecycle

Admin commands read the admin token from stdin. Issue and rotate generate the raw node token locally, send only its SHA-256 hash and length to the relay, and write the raw token file only after the relay confirms the manifest update.

```powershell
Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-issue-credential account.prod node-a-id `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --token-out C:\secure\node-a.token `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-rotate-credential account.prod node-a-id `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --token-out C:\secure\node-a-rotated.token `
    --expires-at-unix 1893456000

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-revoke-credential account.prod node-a-id `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-audit-credentials `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --account account.prod `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-hosted-dashboard `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --account account.prod `
    --node node-a-id `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-mailbox-audit `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --node node-a-id `
    --ttl-seconds 3600 `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-mailbox-purge `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --node node-a-id `
    --ttl-seconds 3600 `
    --dry-run `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-hosted-account-suspend account.prod `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --json
```

Admin results report only metadata:

- action and status
- account id and node id where applicable
- credential, active, revoked, expired, and account counts
- tenant account/node lifecycle counts for `--admin-tenant-*`
- dashboard credential, tenant, accounting, and abuse counts for `--admin-hosted-dashboard`
- account, credential, tenant, node, and hosted policy counts for `--admin-hosted-account-suspend`
- durable mailbox node/file/byte/timestamp and optional expired counts for `--admin-mailbox-audit`
- durable mailbox scanned, invalid, expired, and purged counts for `--admin-mailbox-purge`
- token length and expiry where applicable
- `payloadDisplayed=false`, `tokenHashDisplayed=false`, `sessionIdDisplayed=false`, and `ciphertextDisplayed=false` on dashboard snapshots
- `tokenDisplayed=false`
- `contentsDisplayed=false`
- `payload=not_observed` on relay frames

They never report raw node tokens, token hashes, admin tokens, payload plaintext, ciphertext bodies, private keys, relay session ids, arbitrary frame contents, or manifest contents.

## Failure Behavior

- Wrong or disabled admin token returns `admin_unauthorized` without echoing either token; a valid scoped token without the requested action/account boundary returns `admin_scope_denied` without echoing the token or hash.
- Duplicate issue returns `already_exists`.
- Rotate/revoke for a missing credential returns `not_found`.
- Issue/rotate with a missing hosted tenant returns `tenant_not_found`.
- Issue/rotate with a revoked hosted tenant returns `tenant_revoked`.
- Issue/rotate with a missing hosted node returns `tenant_node_not_found`.
- Issue/rotate with a revoked hosted node returns `tenant_node_revoked`.
- Online tenant-node upsert before tenant creation returns `tenant_not_found`.
- Online tenant revoke or tenant-node revoke for missing records returns `tenant_not_found` or `tenant_node_not_found`.
- Account suspension with a missing tenant registry returns `tenant_unavailable`; with a missing tenant record it returns `tenant_not_found`; with a missing credential manifest it still returns a zero-credential metadata result after tenant revocation.
- Rotate refuses to move an existing node credential to a different account.
- Revoked, expired, missing, malformed, public-bind-invalid, or tenant-revoked credentials fail closed for new `HELLO` sessions.

## Abuse Audit Foundation

Managed relay operators can enable a local metadata-only abuse/dashboard counter store:

```powershell
$env:CONU_RELAY_ABUSE_DIR = "C:\conu-relay\abuse"
$env:CONU_RELAY_ABUSE_WINDOW_SECONDS = "86400"

conu-relay --abuse-audit `
  --abuse-dir C:\conu-relay\abuse `
  --node node-a-id `
  --json
```

The relay increments counters for admin unauthorized attempts, admin failures, credential-denied sessions, tenant-denied sessions, rate-limited sessions, session expiry, quota-denied forwards, undelivered forwards, mailbox rejects, and malformed client frames. Abuse files and audit output contain aggregate counters, optional node ids, a window start, and false display guards only. They never contain raw node tokens, token hashes, admin tokens, private keys, session ids, payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, or room-event plaintext.

Operators can also compare those same metadata counters against explicitly supplied maximums without exposing raw records:

```powershell
conu-relay --abuse-threshold-report `
  --abuse-dir C:\conu-relay\abuse `
  --node node-a-id `
  --max-admin-unauthorized 0 `
  --max-credential-denied-sessions 10 `
  --max-mailbox-rejected-forwards 25 `
  --json `
  --fail-on-threshold

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-abuse-threshold-report `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --account account.prod `
    --node node-a-id `
    --max-admin-unauthorized 0 `
    --max-rate-limited-sessions 100 `
    --json `
    --fail-on-threshold
```

Threshold reports return `status` (`ok` or `threshold_exceeded`), count/max/exceeded metadata for every abuse metric, the number of checked and exceeded thresholds, the optional account/node filters, and false display guards. By default they exit successfully after rendering the report. With `--fail-on-threshold`, they still preserve stdout report output but return exit code 3 when one or more configured thresholds are exceeded. The admin form reads the token from stdin, uses the same dashboard admin scope as hosted dashboard snapshots, and never echoes the token, token hashes, session ids, payloads, ciphertext bodies, frame contents, or raw abuse records.

This is a single-relay file-backed/admin-gated foundation for operator visibility. It is not distributed alerting, adaptive throttling, tenant-wide workflow automation, or a hosted dashboard service yet.

## Mailbox Retention Audit

When `CONU_RELAY_MAILBOX_DIR` is configured, operators can audit durable offline-mailbox pressure without opening ciphertext-bearing files manually:

```powershell
conu-relay --mailbox-audit `
  --mailbox-dir C:\conu-relay\mailbox `
  --node node-a-id `
  --ttl-seconds 3600 `
  --json
```

The audit reports aggregate node/file counts, total mailbox bytes, oldest/newest queued timestamps, optional expired record and byte counts for the supplied TTL, invalid mailbox-file counts, and false display guards only. It never prints stored relay frames, ciphertext bodies, plaintext payloads, raw node tokens, token hashes, admin tokens, private keys, or relay session ids.

The running relay can return the same class of retention metadata through the admin control plane without exposing the mailbox directory path:

```powershell
Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-mailbox-audit `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --node node-a-id `
    --ttl-seconds 3600 `
    --json
```

The online mailbox audit requires hosted admin configuration through `CONU_RELAY_ADMIN_TOKEN` or a scoped `CONU_RELAY_ADMIN_TOKENS_FILE` entry with `scope_mailbox_audit = true`, reads the admin token from stdin, and reports only aggregate counts and display guards from the configured `CONU_RELAY_MAILBOX_DIR`. It is read-only and does not purge files.

Operators can enforce that same local retention boundary with an explicit dry-run or confirmation:

```powershell
conu-relay --mailbox-purge `
  --mailbox-dir C:\conu-relay\mailbox `
  --node node-a-id `
  --ttl-seconds 3600 `
  --dry-run `
  --json

conu-relay --mailbox-purge `
  --mailbox-dir C:\conu-relay\mailbox `
  --node node-a-id `
  --ttl-seconds 3600 `
  --confirm `
  --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-mailbox-purge `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --node node-a-id `
    --ttl-seconds 3600 `
    --dry-run `
    --json

Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-mailbox-purge `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --node node-a-id `
    --ttl-seconds 3600 `
    --confirm `
    --json
```

Dry-run deletes nothing. Confirm mode deletes only expired valid `.mailbox` files under the selected durable mailbox directories. The admin form performs the same single-relay cleanup against the running relay's configured durable mailbox storage and requires `--admin-token-stdin`, a positive TTL, and exactly one of `--dry-run` or `--confirm`. Purge output reports aggregate scanned, invalid, expired, purged, and byte counts with false display guards only; it never prints stored frames, ciphertext bodies, plaintext payloads, tokens, hashes, private keys, or session ids.

For unattended single-relay cleanup, set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` beside `CONU_RELAY_MAILBOX_DIR`. The relay uses `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS` as the retention boundary, deletes only expired valid `.mailbox` files, leaves invalid or display-guard-failed files untouched, and does not render stored contents. `0` or an empty interval disables the scheduled worker.

This is a single-relay operator workflow. It is not distributed retention storage, legal retention policy, billing, tenant-wide workflow automation, or distributed hosted purge orchestration.

## Hosted Dashboard Snapshot

Managed relay operators can combine the current metadata-only stores into one local dashboard snapshot:

```powershell
conu-relay --hosted-dashboard `
  --credentials-file C:\conu-relay\credentials.toml `
  --tenants-file C:\conu-relay\tenants.toml `
  --accounting-dir C:\conu-relay\accounting `
  --abuse-dir C:\conu-relay\abuse `
  --account account.prod `
  --node node-a-id `
  --json
```

The snapshot is an audit surface, not a control plane. It aggregates credential counts, tenant/node counts, accounting counters, and abuse counters with display guards only. It does not show raw node tokens, admin tokens, token hashes, private keys, relay session ids, plaintext payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, or room-event plaintext.

The running relay can also return an admin-token-gated snapshot over the online admin control plane:

```powershell
Get-Content -Raw C:\secure\relay-admin.token |
  conu-relay --admin-hosted-dashboard `
    --relay wss://relay.example.com/conu `
    --admin-token-stdin `
    --account account.prod `
    --node node-a-id `
    --json
```

The online form requires hosted admin configuration through `CONU_RELAY_ADMIN_TOKEN` or a scoped `CONU_RELAY_ADMIN_TOKENS_FILE` entry with `scope_dashboard = true`, and reads the admin token from stdin. It returns metadata-only counters from the running relay's configured credential, tenant, accounting, and abuse stores. The same dashboard scope authorizes `conu-relay --admin-abuse-threshold-report`, which derives count/max/exceeded metadata from the running relay's dashboard snapshot and can return exit code 3 with `--fail-on-threshold` when a configured maximum is exceeded. Neither form echoes the admin token, raw node tokens, token hashes, private keys, relay session ids, payloads, ciphertext bodies, frame contents, or manifest contents.

This is still single-relay and file-backed/admin-gated, even with scoped admin tokens. It is not distributed dashboard storage, alert routing, adaptive response, billing, or tenant-wide workflow automation.

## Remaining Hosted Work

This closes the online credential lifecycle gap and adds single-writer hosted tenant, scoped admin-token, hosted account-suspension, abuse-audit, local/admin-gated abuse threshold reports with optional fail-on-threshold exit status, local and admin-gated online mailbox-audit, local and admin-gated online mailbox-purge, relay-local scheduled mailbox purge, local dashboard-snapshot, and admin-gated online dashboard-snapshot foundations. Public managed hosting still needs distributed tenant lifecycle/workflow automation beyond single-relay account suspension/scoped admin tokens, distributed hosted dashboards and adaptive abuse workflows, distributed multi-instance session migration, distributed accounting, distributed hosted mailbox retention orchestration beyond single-relay purge, full hosted identity/key administration, and managed direct NAT traversal.
