# conU Relay Docker Template

This template builds and runs the current `conu-relay` service.

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

Create the credential file with hashed scoped tokens before starting the container:

```sh
conu-relay --issue-credential node-a-id --token-out ./node-a.token --credentials-file ./credentials.toml
```

The raw token is written only to the token file for delivery to that node. With `--credentials-file`, the mounted `credentials.toml` is created or updated with only hashed token metadata and lifecycle fields.

```toml
version = "1"

[[credential]]
node_id = "node-a-id"
token_sha256_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
token_length = 64
status = "active"
payload_displayed = false
token_displayed = false
```

Use `--replace` on `conu-relay --issue-credential` to rotate an existing node credential and `conu-relay --revoke-credential <node-id> --credentials-file ./credentials.toml` to mark a node revoked without printing tokens. Use `conu-relay --hash-token` with stdin only when an operator already has a token and needs the `token_sha256_hex` and `token_length` fields. Revoked or expired credentials are rejected for new sessions without restarting the relay; existing authenticated sessions remain bounded by idle timeout and max TTL. Invalid manifests fail closed for new sessions.

Current relay limits still apply:

- The client accepts `ws://` relay endpoints for local or private-network relay paths.
- The client also accepts certificate-valid `wss://` relay endpoints when TLS is terminated in front of this plain WebSocket container.
- The relay forwards metadata plus peer-encrypted message, stream-chunk, room-event, and signed-card control bodies only.
- The relay has configurable connection caps, per-IP caps, and per-session frame-rate limits.
- The relay can persist metadata-only per-node session files under `CONU_RELAY_SESSION_STATE_DIR` for same-node resume after relay restarts until the session TTL expires. Session files contain node ids, relay session ids, timestamps, and display guards only, not tokens, token hashes, payloads, ciphertext bodies, or private keys.
- The relay has a bounded offline mailbox for peer-encrypted envelopes. The Docker image defaults `CONU_RELAY_MAILBOX_DIR` to `/var/lib/conu-relay/mailbox`; mount `/var/lib/conu-relay` to keep queued ciphertext envelopes across container restarts. Inspect durable mailbox pressure with `conu-relay --mailbox-audit --mailbox-dir /var/lib/conu-relay/mailbox [--ttl-seconds 3600] [--json]`; output contains counts, byte totals, queue timestamps, optional expired counts, invalid mailbox-file counts, and display guards only. Managed operators can also query the running relay with `conu-relay --admin-mailbox-audit --relay <wss://...> --admin-token-stdin [--ttl-seconds 3600] [--json]`. Remove expired valid `.mailbox` files only after `conu-relay --mailbox-purge --mailbox-dir /var/lib/conu-relay/mailbox --ttl-seconds 3600 --dry-run`, then rerun with `--confirm`; managed operators can run the same cleanup against the running relay with `conu-relay --admin-mailbox-purge --relay <wss://...> --admin-token-stdin --ttl-seconds 3600 (--dry-run|--confirm)`. Purge output is aggregate-only. Set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` with `CONU_RELAY_MAILBOX_DIR` for relay-local scheduled cleanup using the offline envelope TTL.
- The relay can persist metadata-only per-node accounting files under `CONU_RELAY_ACCOUNTING_DIR` and enforce optional per-window sent-envelope or sent-byte quotas. Accounting files contain node ids, authenticated/resumed session counters, envelope counters, byte counters, and display guards only, not tokens, token hashes, session ids, or payload/ciphertext bodies.
- The relay can persist metadata-only abuse/dashboard counter files under `CONU_RELAY_ABUSE_DIR` and render them with `conu-relay --abuse-audit --abuse-dir <path>`. Operators can compare those counters against explicit maximums with `conu-relay --abuse-threshold-report --abuse-dir <path> --max-<metric> <count>... [--fail-on-threshold]`, or with `conu-relay --admin-abuse-threshold-report --relay <wss://...> --admin-token-stdin --max-<metric> <count>... [--fail-on-threshold]` against a running relay. The optional fail flag preserves stdout and returns exit code 3 only when a configured threshold is exceeded. It can also render a local hosted dashboard snapshot with `conu-relay --hosted-dashboard --credentials-file <path> --tenants-file <path> --accounting-dir <path> --abuse-dir <path>` or an admin-gated online snapshot with `conu-relay --admin-hosted-dashboard --relay <wss://...> --admin-token-stdin`. Managed operators can update and audit one configured tenant registry online with `conu-relay --admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, and `--admin-tenant-audit`, always with `--admin-token-stdin`, and can suspend one account with `conu-relay --admin-hosted-account-suspend`. `CONU_RELAY_ADMIN_TOKENS_FILE` can live-read hashed admin tokens scoped to credentials, tenants, dashboard, mailbox audit, and mailbox purge actions; account suspension requires both credentials and tenants scopes. Abuse/dashboard/threshold/tenant/account/mailbox audit and purge output contains aggregate enforcement, tenant, credential, or retention counters, optional node ids, window/timestamp metadata, and display guards only, not tokens, token hashes, admin tokens, session ids, payloads, ciphertext bodies, private keys, or frame contents.
- Both abuse threshold commands also accept `--thresholds-file <path>` for reusable metadata-only policy files with `version = "1"`, supported `max_*` keys, and false payload/token/hash/key/session/ciphertext/content display guards; inline `--max-*` values override file defaults.
- Daemon reconnects to the same relay endpoint can resume a prior same-node relay session when the daemon still has the resume hint and the relay has in-memory or file-backed session state. Cross-node resume attempts receive a new session instead.
- The relay supports offline scoped credential issuance and manifest upsert/rotate/revoke helpers through `conu-relay --issue-credential` and `conu-relay --revoke-credential`, account-scoped online issue/rotate/revoke/audit/dashboard snapshots and read-only mailbox retention audits through full-admin `CONU_RELAY_ADMIN_TOKEN` or scoped `CONU_RELAY_ADMIN_TOKENS_FILE` plus `CONU_RELAY_CREDENTIALS_FILE`, live-reloaded per-node scoped credentials through a hashed `CONU_RELAY_CREDENTIALS_FILE`, compatibility `CONU_RELAY_CREDENTIALS`, and shared-token local tests through `CONU_RELAY_TOKEN`.
- Non-loopback Docker binds require custom shared or scoped tokens with at least 24 characters; `local-dev-token` is loopback-only.
- Distributed multi-instance session migration/accounting, distributed dashboards and adaptive abuse response beyond single-relay threshold reports, hosted tenant lifecycle/workflow automation beyond one relay's account suspension/scoped admin tenant commands, and distributed hosted mailbox retention orchestration remain future hardening work.
