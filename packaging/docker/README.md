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
- The relay has a bounded offline mailbox for peer-encrypted envelopes. The Docker image defaults `CONU_RELAY_MAILBOX_DIR` to `/var/lib/conu-relay/mailbox`; mount `/var/lib/conu-relay` to keep queued ciphertext envelopes across container restarts.
- The relay can persist metadata-only per-node accounting files under `CONU_RELAY_ACCOUNTING_DIR` and enforce optional per-window sent-envelope or sent-byte quotas. Accounting files contain node ids, authenticated/resumed session counters, envelope counters, byte counters, and display guards only, not tokens, session ids, or payload/ciphertext bodies.
- Same-process daemon reconnects to the same relay endpoint can resume a prior same-node relay session. Cross-node resume attempts receive a new session instead.
- The relay supports offline scoped credential issuance and manifest upsert/rotate/revoke helpers through `conu-relay --issue-credential` and `conu-relay --revoke-credential`, live-reloaded per-node scoped credentials through a hashed `CONU_RELAY_CREDENTIALS_FILE`, compatibility `CONU_RELAY_CREDENTIALS`, and shared-token local tests through `CONU_RELAY_TOKEN`.
- Non-loopback Docker binds require custom shared or scoped tokens with at least 24 characters; `local-dev-token` is loopback-only.
- Managed hosted account auth, online credential issuance APIs beyond the offline issuance helper, distributed hosted session state/accounting, dashboards, abuse response, and hosted mailbox retention policy remain future hardening work.
