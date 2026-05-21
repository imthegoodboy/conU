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

`CONU_RELAY_ADMIN_TOKEN` must be custom, contain no whitespace, and be at least 24 characters. It is accepted only when `CONU_RELAY_CREDENTIALS_FILE` is configured. `CONU_RELAY_TENANTS_FILE` is optional, but when set it also requires `CONU_RELAY_ADMIN_TOKEN` and `CONU_RELAY_CREDENTIALS_FILE`. Missing credential or tenant records fail closed for new runtime sessions.

## Tenant Lifecycle

Tenant commands are local/offline file updates for the relay operator:

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

When `CONU_RELAY_TENANTS_FILE` is configured, online issue and rotate require an active tenant account and active hosted node. Revoke remains available so operators can clean up credential metadata even after tenant or node revocation.

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
```

Admin results report only metadata:

- action and status
- account id and node id where applicable
- credential, active, revoked, expired, and account counts
- token length and expiry where applicable
- `tokenDisplayed=false`
- `contentsDisplayed=false`
- `payload=not_observed` on relay frames

They never report raw node tokens, token hashes, admin tokens, payload plaintext, ciphertext bodies, private keys, or manifest contents.

## Failure Behavior

- Wrong or disabled admin token returns `admin_unauthorized` without echoing either token.
- Duplicate issue returns `already_exists`.
- Rotate/revoke for a missing credential returns `not_found`.
- Issue/rotate with a missing hosted tenant returns `tenant_not_found`.
- Issue/rotate with a revoked hosted tenant returns `tenant_revoked`.
- Issue/rotate with a missing hosted node returns `tenant_node_not_found`.
- Issue/rotate with a revoked hosted node returns `tenant_node_revoked`.
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

This is a single-relay file-backed foundation for operator visibility. It is not distributed alerting, adaptive throttling, account suspension, tenant-wide workflow automation, or a hosted dashboard service yet.

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
```

Dry-run deletes nothing. Confirm mode deletes only expired valid `.mailbox` files under the selected durable mailbox directories. Purge output reports aggregate scanned, invalid, expired, purged, and byte counts with false display guards only; it never prints stored frames, ciphertext bodies, plaintext payloads, tokens, hashes, private keys, or session ids.

This is a single-relay operator workflow. It is not distributed retention storage, legal retention policy, billing, tenant-wide workflow automation, or hosted scheduled purge orchestration.

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

This is still single-relay and file-backed. It is not distributed dashboard storage, RBAC, alert routing, adaptive response, billing, tenant-wide workflow automation, or managed hosted account suspension.

## Remaining Hosted Work

This closes the online credential lifecycle gap and adds single-writer hosted tenant, abuse-audit, mailbox-audit, mailbox-purge, and dashboard-snapshot foundations. Public managed hosting still needs distributed tenant lifecycle, distributed hosted dashboards and adaptive abuse workflows, distributed multi-instance session migration, distributed accounting, scheduled/distributed hosted mailbox retention orchestration, full hosted identity/key administration, and managed direct NAT traversal.
