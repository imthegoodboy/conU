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

## Relay Setup

Online admin lifecycle requires the live credential manifest:

```powershell
$env:CONU_RELAY_CREDENTIALS_FILE = "C:\conu-relay\credentials.toml"
$env:CONU_RELAY_ADMIN_TOKEN = (Get-Content -Raw C:\secure\relay-admin.token).Trim()
conu-relay --serve 0.0.0.0:8787
```

`CONU_RELAY_ADMIN_TOKEN` must be custom, contain no whitespace, and be at least 24 characters. It is accepted only when `CONU_RELAY_CREDENTIALS_FILE` is configured. The manifest may start missing or empty; new runtime sessions fail closed until credentials are issued.

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
- Rotate refuses to move an existing node credential to a different account.
- Revoked, expired, missing, malformed, or public-bind-invalid credentials fail closed for new `HELLO` sessions.

## Remaining Hosted Work

This closes the online credential lifecycle gap for a single running relay and file-backed manifest. Public managed hosting still needs distributed multi-instance session migration, distributed accounting dashboards, abuse workflows, hosted mailbox retention policy, multi-tenant permission administration, hosted identity/key administration, and managed direct NAT traversal/rendezvous.
