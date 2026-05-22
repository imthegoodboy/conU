# Privacy And Security Checklist

## Payload Opacity

- Payload content is opaque to conU runtime surfaces unless the local agent intentionally handles it.
- CLI does not print payload text.
- SDK and MCP list/send/status/stream/room outputs do not print payload text.
- TypeScript/JavaScript SDK payload helpers pass bytes through stdin and do not put payload contents in argv, logs, or wrapper output.
- Browser-conditioned TypeScript SDK exports must fail closed until browser-native transport exists; they must not accept private keys, relay tokens, endpoint secrets, payload bytes, or account credentials.
- Logs do not include payload text.
- Metrics do not include payload text.
- Route registry, probe history, and route logs include only metadata.
- Tests do not normalize leaking payload contents as expected behavior.

## Identity And Trust

- Node identity is generated locally.
- Agent identity is bound to a trusted node.
- Pairing is explicit.
- Manual peer-card trust must import only public node id, display name, public exchange key, relay endpoint, and public signature metadata.
- Manual peer-card trust should verify signed peer-card metadata when present and must store only public signature material.
- Identity-key rotation must archive old signing/exchange key files with the configured secret backend, require refreshed public peer-card distribution, and keep CLI output to old/new key ids plus refresh booleans only.
- Manual remote agent-card trust must import only public agent id, display name, node id, kind, capabilities, and public signature metadata.
- Remote agent-card trust must verify the signature, require the card node id to already be trusted as a peer, and require the signing key to match the trusted peer card.
- Automatic agent-card exchange must carry signed card metadata as peer-encrypted relay control envelopes and must use the same verification checks as manual import.
- Trust is revocable.
- Discovery is scoped by trust and policy.

## Permissions

- Agent actions require grants where appropriate.
- Sending, streaming, subscribing, room joining, file transfer, and mailbox use are separately controllable.
- Core routing must enforce local agent capability booleans: `messages` for message send/receive, `streams` for stream open/write and inbound stream chunks, and `rooms` for room create/join/publish and local or relay-backed room fanout.
- Core routing must enforce peer-scoped policy grants for trusted remote peers; missing peer policy records deny by default.
- Peer policy records must contain only peer node ids, boolean grants, timestamps, and `payload_displayed = false`.
- Room topic policy records must contain only room id, agent id, topic, publish/subscribe booleans, timestamps, and `payload_displayed = false`; configured topics must require explicit grants for publish, local fanout, remote fanout, and inbound relay room delivery.
- "Full access" means full communication within trust boundaries, not raw system access.
- SDK/MCP receive APIs return payload bytes only to the addressed local agent and only after an explicit receive request.

## Relay

- Relay forwards opaque envelopes.
- Relay logs metadata only.
- Relay cannot impersonate a peer.
- Relay fallback does not weaken trust checks.
- Relay message, stream-chunk, room-event, and signed-card control delivery must decrypt only after the sender exchange public key matches the trusted peer card.
- Relay frames may carry ciphertext bodies, never plaintext payload fields.
- The default `local-dev-token` must be limited to loopback relay binds; exposed relay binds require explicit custom shared or scoped tokens.
- Self-hosted relay deployments should prefer offline issuance through `conu-relay --issue-credential --credentials-file` plus live-reloaded per-node credentials through a hashed `CONU_RELAY_CREDENTIALS_FILE` with status/expiry metadata. Managed relay deployments may enable full-admin `CONU_RELAY_ADMIN_TOKEN` or scoped hashed admin entries in `CONU_RELAY_ADMIN_TOKENS_FILE` with the credential file for account-scoped online issue/rotate/revoke/audit/dashboard snapshots, session-state audits, hosted tenant lifecycle, hosted account suspension, and mailbox audit/purge. Scoped admin manifests may contain only token hashes, token length metadata, optional account ids, lifecycle/expiry metadata, boolean scopes, and display guards. `conu-relay --admin-token-audit` may inspect these manifests locally, but must report only records, account/global counts, active/revoked/expired totals, scope counts, expiry bounds, path/bind metadata, and false display guards without admin tokens, token hashes, manifest contents, private keys, session ids, payloads, ciphertext, or frame contents. Hosted account suspension requires both credential and tenant scopes unless the full-admin compatibility token is used. Issuance output must write the raw token only to the requested token file; manifest upsert/rotation/revocation/admin output must report only ids/counts/paths/status/display guards, not raw node tokens, admin tokens, hashes, or manifest contents. Missing or invalid manifests fail closed for new sessions and must not echo tokens or token hashes. `CONU_RELAY_CREDENTIALS` remains compatibility config, runtime clients may use `CONU_RELAY_TOKEN` or `conu relay credential set --stdin`, and shared server-side `CONU_RELAY_TOKEN` remains for local or tightly controlled tests.
- `CONU_RELAY_TENANTS_FILE` may store hosted tenant ids, node ids, active/revoked status, hosted permission booleans, public key ids, timestamps, and display guards only. It can be managed by local `conu-relay --tenant-*` and `--hosted-account-suspend` commands or admin-token-gated online `conu-relay --admin-tenant-*` and `--admin-hosted-account-suspend` commands. It must not store private keys, relay tokens, token hashes, payloads, ciphertext bodies, or local peer-policy grants. When enabled, tenant/node absence or revocation must fail closed for admin issue/rotate and new runtime `HELLO` sessions without weakening local conUD peer policy.
- Relay idle timeout and max session TTL must stay configurable and must close sessions without exposing payloads or tokens.
- Relay connection/rate-limit errors must stay generic and must not echo tokens, payloads, or arbitrary frame contents.
- Relay session resume may use a session id only as same-node same-endpoint reconnect metadata. `CONU_RELAY_SESSION_STATE_DIR` may persist node ids, relay session ids, timestamps, and display guards, but must not contain tokens, token hashes, plaintext payloads, ciphertext bodies, private keys, or frame bodies. Cross-node resume attempts must not inherit the requested session id, and runtime/admin/Debug/log surfaces must not display relay session ids.
- `conu-relay --session-audit` and `conu-relay --admin-session-audit` output may contain record counts, active/expired/invalid counts, optional validated node ids, timestamp bounds, statuses, and display guards only. The admin-hosted form must require an admin token read from stdin, enforce `sessions` scope when scoped tokens are configured, and constrain account-scoped tokens to an active tenant node. Neither form may echo admin tokens, relay session ids, raw node tokens, token hashes, plaintext payloads, ciphertext bodies, private keys, arbitrary frame bodies, message text, stream chunks, room-event plaintext, or session-state file contents.
- Relay accounting files may contain node ids, authenticated/resumed session counts, sent/received envelope counts, byte counts, mailbox counters, accounting windows, and display guards only. They must not contain relay tokens, token hashes, plaintext payloads, ciphertext bodies, session ids, private keys, or frame bodies.
- Relay abuse/dashboard files may contain aggregate enforcement counters, optional validated node ids, window starts, and display guards only. They must not contain relay tokens, token hashes, admin tokens, plaintext payloads, ciphertext bodies, session ids, private keys, or arbitrary frame bodies. `conu-relay --abuse-audit`, `conu-relay --abuse-threshold-report`, and `conu-relay --admin-abuse-threshold-report` output must stay aggregate and payload-safe; threshold reports may add operator-supplied max values from CLI flags or metadata-only `--thresholds-file` policy files, exceeded booleans, and optional `--fail-on-threshold` exit code 3 behavior, but not raw records or adaptive enforcement actions.
- `conu-relay --mailbox-audit` and `conu-relay --admin-mailbox-audit` output may contain durable mailbox file counts, byte totals, queued timestamp bounds, optional expired counts for an operator-provided TTL, invalid mailbox-file counts, optional validated node ids, and display guards only. The commands may load metadata-only `--retention-policy-file` files containing `version = "1"`, optional `ttl_seconds`, optional `node_id`, and false display guards only; CLI `--ttl-seconds` and `--node` values must override file defaults. The admin-hosted form must require an admin token read from stdin, and scoped account tokens must be constrained to an active tenant node. Neither form may echo the admin token on success or failure, or print stored relay frames, ciphertext bodies, raw tokens, token hashes, admin tokens, plaintext payloads, session ids, private keys, arbitrary frame bodies, message text, stream chunks, or room-event plaintext.
- `conu-relay --mailbox-purge` and `conu-relay --admin-mailbox-purge` output may contain durable mailbox scanned counts, invalid counts, expired counts, purged counts, byte totals, optional validated node ids, positive TTL metadata from CLI or metadata-only `--retention-policy-file`, dry-run/confirmed mode, and display guards only. The admin-hosted form must require an admin token read from stdin, and scoped account tokens must be constrained to an active tenant node. Both forms must require a TTL from CLI or policy file and exactly one of `--dry-run` or `--confirm`; dry-run must delete nothing, and confirmed mode may delete only expired valid `.mailbox` files. They must not echo the admin token on success or failure, or print stored relay frames, ciphertext bodies, raw tokens, token hashes, admin tokens, plaintext payloads, session ids, private keys, arbitrary frame bodies, message text, stream chunks, or room-event plaintext.
- `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` may enable relay-local scheduled deletion of expired valid `.mailbox` files only when `CONU_RELAY_MAILBOX_DIR` is configured. It must use the existing offline mailbox TTL boundary, leave invalid or display-guard-failed files untouched, and must not print stored relay frames, ciphertext bodies, raw tokens, token hashes, admin tokens, plaintext payloads, session ids, private keys, arbitrary frame bodies, message text, stream chunks, or room-event plaintext.
- `conu-relay --hosted-dashboard`, `conu-relay --hosted-fleet-dashboard`, `conu-relay --admin-hosted-dashboard`, `conu-relay --abuse-threshold-report`, and `conu-relay --admin-abuse-threshold-report` output may combine or evaluate credential, tenant, accounting, and abuse summaries only as aggregate metadata with false display guards. Fleet dashboards may include session-state and mailbox aggregate counters, optional read-only mailbox retention policy checks, and optional aggregate abuse threshold checks, but must not print policy, mailbox file, or manifest contents. `conu-relay --hosted-readiness` may combine credential, scoped admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks for local startup/release preflight only, returning paths, source booleans, aggregate counts, warnings, bind metadata, optional filters, and false display guards. Retention policy files must stay metadata-only with `version = "1"`, optional TTL/node keys, and false display guards; threshold policy files must stay metadata-only with `version = "1"`, max keys, and false display guards, and CLI overrides must not echo policy values on parse failures. Hosted fleet retention gates may return exit code 3 with `--fail-on-retention` after preserving stdout only when TTL-checked mailbox sources report expired records; they must not delete files or contact remote relays. The admin-hosted forms must require an admin token read from stdin, and account-scoped dashboard tokens without a node filter must not return global accounting or abuse counters. Neither form may echo that token on success or failure, or print raw node tokens, admin tokens, token hashes, private keys, relay session ids, plaintext payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, room-event plaintext, or manifest contents.
- `conu-relay --admin-tenant-upsert`, `--admin-tenant-revoke`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, and `--admin-tenant-audit` output may contain account id, node id, tenant/node counts, hosted policy counts, action/status, relay endpoint, and display guards only. They must require an admin token read from stdin, enforce tenant scope and optional account boundaries, must not echo that token on success or failure, and must not print raw node tokens, token hashes, private keys, relay session ids, plaintext payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, room-event plaintext, or tenant manifest contents.
- `conu-relay --hosted-account-suspend` and `conu-relay --admin-hosted-account-suspend` output may contain action/status, account id, credential counts, tenant/node counts, hosted policy counts, credential and tenant paths or relay endpoint, and display guards only. They must revoke the tenant before revoking account credential records, must not weaken local peer policy, and the admin-hosted form must require an admin token read from stdin with full-admin access or both credential and tenant scopes. They must not echo the admin token on success or failure, or print raw node tokens, token hashes, private keys, relay session ids, plaintext payloads, ciphertext bodies, arbitrary frame contents, message text, stream chunks, room-event plaintext, or manifest contents.
- Relay clients may use `wss://` only through certificate-validated TLS. Public deployments must terminate TLS before the plain `conu-relay` service and must not disable hostname/certificate verification in production.
- The conUD relay pump may maintain a reusable relay session, retry, count, and route envelopes, but runtime logs must stay metadata-only and must not include relay session ids, relay tokens, or plaintext payloads.
- The relay offline mailbox may store only peer-encrypted message, stream-chunk, room-event, or signed-card control envelopes in bounded memory or in the configured `CONU_RELAY_MAILBOX_DIR`; it must not store plaintext payloads and must expire/drop envelopes without echoing contents.

## Storage

- Trust store avoids plaintext secrets when possible.
- Peer policy store contains metadata-only grants and no payloads or secrets.
- Message request and inbox files use encrypted-at-rest payload fields.
- Room registry, room events, room topic policy, and room logs contain metadata only; local room fanout payloads live only as encrypted-at-rest inbox envelopes for joined local participants, and remote room fanout payloads live only inside peer-encrypted relay envelopes until delivered to the addressed local inbox.
- Relay mailbox stores encrypted envelopes only; `conu-relay --mailbox-audit` and `conu-relay --admin-mailbox-audit` report retention metadata only and may load metadata-only retention policy files; `conu-relay --hosted-fleet-dashboard` may reuse those policy files for read-only aggregate retention gates over guarded relay-local mailbox stores; `conu-relay --mailbox-purge` and `conu-relay --admin-mailbox-purge` report dry-run metadata without deleting and delete expired valid durable files only with explicit confirmation; relay-local scheduled purge deletes expired valid durable files only when explicitly configured; relay accounting and relay abuse files store metadata counters only; abuse threshold reports evaluate those counters only, may load metadata-only threshold policy files, and may fail the process for automation only when `--fail-on-threshold` is set. Distributed hosted mailbox retention orchestration beyond read-only fleet gates plus single-relay purge and distributed adaptive abuse workflows remain future work.
- Relay outbox stores peer-encrypted message, stream-chunk, room-event, and signed-card control envelope bodies, not plaintext payloads.
- Stored relay client credentials must live under `security/relay-credential.key`, use OS wrapping when available, and never appear in CLI output, logs, docs examples, or tests except artificial field-name checks.
- macOS native secret fields may store only user Keychain references and lengths. Linux native secret fields may store only Secret Service references and lengths. They must not store key bytes, relay tokens, wrapped blobs, plaintext payloads, or decrypted payloads.
- On non-Windows targets without an available native backend, the user-managed wrap-key fallback may write encrypted `*_wrapped_hex` secret fields when `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` is configured. The wrap key is external/operator-managed, never stored by conU, and must not appear in argv, CLI output, logs, docs examples, telemetry, or tests except artificial field-name checks.
- Logs are payload-safe.
- Config does not store private keys.
- Security key files remain local-only and must not appear in CLI output, logs, docs examples, or tests except artificial field-name checks. On Windows, local signing, exchange, and storage secret bytes should be wrapped with current-user DPAPI fields, and older plaintext-hex key files should migrate during security-state ensure. On macOS/Linux with a native store available, older plaintext-hex key and relay credential files should migrate to OS-secret references. On non-Windows with a configured user-managed wrap key and no native store, older plaintext-hex files should migrate to encrypted wrapped fields; without native storage or a wrap key, files remain owner-only local secrets.

## Replay And Signatures

- Local agent cards are signed and signature verification fails on tampering.
- Remote signed agent-card imports reject tampered cards and cross-peer agent-id collisions.
- Replay cache rejects duplicate message request and envelope ids before duplicate delivery.
- Revoked peers must not remain visible or routeable.

## Routes

- Direct route candidates are recorded only for trusted peers and must be selected only after a live authenticated QUIC probe succeeds; failed probes and NAT-traversal-unavailable states must keep relay selected.
- Relay fallback does not weaken trust checks.
- Direct endpoint config must not contain tokens, private keys, endpoint secrets, or payload material, and rejected endpoint strings must not be persisted in route ids, route registries, probes, logs, CLI output, SDK output, or MCP output.
- Route failure reasons stay generic and must not echo arbitrary payload-bearing input.

## Packaging And Doctor

- Release archives do not include local state, private keys, logs, inboxes, message stores, routes, or payload-bearing files.
- `conu doctor` reports readiness and scan counts only; it must not print log contents.
- `conu logs rotate` reports only metadata such as file names, byte sizes, rotation counts, and archive removals. It must not read, print, upload, or classify log contents.
- `conu telemetry snapshot` reports only schema, explicit allowlist, aggregate counters, and display guards. It must not print node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, private keys, shared secrets, auth tokens, plaintext payloads, decrypted payloads, or ciphertext bodies.
- `conu security rotate storage --confirm` reports only key ids and migration counts. It must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu security rotate identity --confirm-peer-refresh` and `conu security retire identity --confirm-peer-refresh-complete` report only key ids, archive counts, refresh/confirmation booleans, compatibility status, and `contentsDisplayed=false`. They must not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- `conu security retire storage --confirm` reports only archived-key, migrated-file, and dependent-file counts. It must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- CI and release workflows upload binaries/docs/templates only.
- Release workflows must verify archives before upload, require install/service templates in each archive, reject local conU state, private keys, logs, inboxes, route registries, telemetry dumps, node modules, vendored npm binaries, and payload-bearing files, sign Windows binaries, sign/notarize macOS ZIP archives, and generate GitHub artifact attestations for release archives plus checksum files. Signing and notarization logs must not display certificates, private keys, signing passwords, npm tokens, relay tokens, local conU state, or payload contents.
- Service templates must not bake in developer-specific secrets, tokens, or private paths beyond editable placeholders.
- npm packaging must verify release checksums by default and must not package or inspect local `CONU_HOME` state.
- Docker relay templates must keep relay tokens in runtime configuration or explicit issued token files only; credential manifests may store token hashes and lifecycle metadata, but never raw relay tokens, and examples should prefer `--credentials-file`, `--replace`, and `--revoke-credential` over hand-editing where possible.

## CLI Watch

- Shows route, latency, bytes, packet count, stream count, presence.
- Never shows message text, prompt text, reasoning, file contents, or tool output.

## MCP Adapter

- stdout contains only valid MCP JSON-RPC messages.
- Tool schemas do not encourage plaintext payload logging.
- `conu_receive_message` returns metadata by default.
- `payloadHex` is returned only for explicit addressed-agent receive calls.
- When `CONU_AGENT_ID` is set, the MCP server rejects attempts to act as another local agent.
