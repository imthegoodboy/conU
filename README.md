# conU

conU is an agent-native encrypted communication fabric.

It is not an agent framework, prompt system, orchestrator, or chatbot. conU is the runtime and protocol layer that lets trusted agents discover each other, connect, exchange opaque messages, and stream transport events across machines.

```txt
Agents own the conversation.
conU owns the connection.
```

## Current Status

Phase 14 and Phase 15 are complete for the current local-first app, with rooms/pub/sub metadata, encrypted-at-rest local and relay-backed room event fanout, room topic publish/subscribe policy, a richer CLI control-room dashboard, local agent connect flows, authenticated direct QUIC delivery for reachable trusted peers, and a hardened relay data path beyond the original MVP. The CLI identity/dashboard shell exists, `conu init` creates real local state and security keys, `conu start` launches the local `conUD` runtime, local agents can register signed metadata and presence, registered local agents can export signed public agent cards for trusted peers, remote signed agent cards can be imported after peer trust is established or exchanged automatically over encrypted relay control envelopes, registered local agents can exchange encrypted-at-rest opaque message envelopes, users can exchange signed public peer cards, trusted peers require explicit peer-scoped policy grants before sending peer-encrypted messages, stream chunks, or room events through direct QUIC or `conu-relay`, conUD can automatically pump configured relay routes, and the relay enforces configurable connection and frame-rate limits plus offline scoped credential issuance, manifest upsert/rotate/revoke helpers, online account-scoped credential admin, payload-safe local scoped admin-token manifest audits, payload-safe hosted relay readiness preflights, admin-gated online hosted tenant lifecycle, local/admin-gated hosted account suspension, guarded hosted fleet account/node audit and suspension plus credential revoke over local manifests, guarded hosted fleet tenant account upsert/revoke plus tenant-node upsert/revoke over local tenant registries, a metadata-only hosted tenant registry, live-reloaded hashed credential manifests, metadata-only accounting/quotas, metadata-only abuse/dashboard counters, local/admin-gated hosted abuse threshold reports with reusable policy files and optional fail-on-threshold exit status, payload-safe local/admin-gated session-state audits, payload-safe local and admin-gated online mailbox retention audits with reusable policy files, confirm-gated local/admin online and scheduled relay-local expired mailbox purge, confirm-gated hosted fleet mailbox purge orchestration over guarded local fleet manifests, local hosted-dashboard snapshots, admin-gated online hosted-dashboard snapshots, guarded hosted fleet dashboards with reusable mailbox retention policy gates plus abuse threshold checks, and guarded hosted fleet abuse response plans that turn aggregate threshold breaches into deterministic operator action categories. Streams and rooms produce payload-safe watch events, local metadata logs can be rotated, and local storage keys can be rotated or retired without displaying contents. `conu telemetry snapshot` exports only allowlisted local aggregate counters. Windows local secrets are wrapped with current-user DPAPI, macOS uses user Keychain, Linux uses Secret Service when available, and `conu security audit` reports hardened controls without showing secrets. Agents can use conU through the Rust SDK, Python wrapper SDK, TypeScript/JavaScript SDK, and MCP stdio adapter, conUD owns payload-safe direct/relay route selection, and release packaging/readiness checks now exist. The repo also contains an npm launcher package template and relay hosting docs for the first public distribution path.

Release packaging/readiness checks include bounded archive verification, release artifact smoke preflights for missing or non-file binaries, package-manager manifest and APT/RPM metadata generation regressions, hosted Linux repository site cache-policy regressions, Linux signing-secret preflight regressions, native RPM package-signing regressions, fingerprint-pinned Linux detached/repository signing regressions, Linux GPG public-key export regressions, npm launcher local-binary preflights, deterministic npm package-content verification, artifact attestations, and tagged release signing/npm secret gates.

Managed operators can also run `conu-relay --hosted-fleet-dashboard --fleet-file <path> [--account <id>] [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold] [--fail-on-retention]` to aggregate a guarded manifest of multiple relay-local metadata stores, apply reusable mailbox retention TTL/node policy defaults, and apply reusable abuse thresholds without printing tokens, token hashes, session ids, payloads, ciphertext bodies, mailbox file contents, manifest contents, or frame contents. `conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path> [--node <id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-action]` reuses the same guarded manifest and threshold inputs to return aggregate threshold status plus static operator action categories such as admin access, credential/tenant access, traffic pressure, delivery health, and mailbox pressure. For tenant workflow checks across manifest-listed local credential/tenant stores, run `conu-relay --hosted-fleet-account-audit <account-id> --fleet-file <path> [--node <id>] [--json] [--fail-on-warning]` to report missing source pairs, missing account or node records, and active/revoked credential/tenant mismatches before any mutation. For compromised account/node credentials across manifest-listed local credential stores, run `conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file <path> --dry-run [--json]`, review the credential counts, then rerun with `--confirm`. For guarded tenant account lifecycle across manifest-listed local tenant registries, run `conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file <path> --dry-run [--json]`, review tenant/source counts, then rerun with `--confirm`; revoke uses `conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file <path> --dry-run [--json]` followed by `--confirm`. For guarded tenant-node lifecycle across those registries, run `conu-relay --hosted-fleet-tenant-node-upsert <account-id> <node-id> --fleet-file <path> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] --dry-run [--json]`, review the per-relay tenant counts, then rerun with `--confirm`; revoke uses `conu-relay --hosted-fleet-tenant-node-revoke <account-id> <node-id> --fleet-file <path> --dry-run [--json]` followed by `--confirm`. For tenant workflow cleanup, run `conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file <path> [--node <id>] --dry-run [--json]`, review the aggregate and per-relay credential/tenant counts, then rerun with `--confirm`; without `--node` it revokes tenant metadata first and account credential records second, and with `--node` it revokes tenant-node metadata first and that node's credential records second. For mailbox cleanup orchestration over the same local fleet manifest, run `conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] --dry-run [--json]`, review the aggregate and per-relay expired counts, then rerun with `--confirm` to delete only expired valid `.mailbox` files from configured local mailbox stores. This is a fleet snapshot, scriptable policy gate, deterministic response-plan, guarded local tenant audit/account-lifecycle/node-lifecycle/credential-revoke/suspension, and confirm-gated local cleanup workflow, not hosted billing, adaptive abuse automation, remote relay purge, remote tenant control, or a cross-region retention service.

The repository currently contains compile-ready crate boundaries for:

- `conu-cli`: human control room.
- `conu-sdk`: Rust agent-facing API over conU local gateway surfaces.
- `conu-mcp`: MCP stdio adapter exposing conU as agent tools.
- `conud`: local daemon/runtime scaffold.
- `conu-core`: shared runtime primitives and project invariants.
- `conu-protocol`: protocol identities, agent cards, and opaque envelopes.
- `conu-relay`: small plain WebSocket relay, with `wss://` supported by the client through TLS termination.

The runtime code still favors small std-first modules, but Phase 11 introduces audited crypto crates for encryption, signatures, hashing, randomness, and key agreement, and the relay client now uses platform TLS for `wss://`. On this Windows workstation, those dependencies require the GNU Rust toolchain for commands that compile build scripts or link tests until Visual Studio C++ Build Tools or CI are configured.

## Local State

`conu init` creates the Phase 3 state store:

```txt
%APPDATA%\conU\        Windows default
~/.conu/               Unix fallback
```

Set `CONU_HOME` to use a different directory for development or smoke checks.

```txt
node.toml              local node id only, not a secret or auth credential
config.toml            local runtime config skeleton
trust.toml             trusted/revoked peer skeleton
policy.toml            peer-scoped communication grants
agents/registry.toml   local agent registry skeleton
agents/remote.toml     signed or mirrored trusted remote agent cards
security/              local signing, exchange, storage, replay, and rotation files
runtime/status.toml    conUD heartbeat/status metadata
runtime/conud.lock     local runtime process lock
runtime/stop.request   graceful shutdown request file
runtime/ipc/inbox/     metadata-only agent gateway requests
runtime/ipc/processed/ processed gateway requests
runtime/ipc/rejected/  rejected gateway requests and safe reasons
runtime/ipc/messages/  opaque local message request queue
messages/inbox/        delivered local opaque envelopes by recipient agent
messages/receipts/     metadata-only local delivery receipts
streams/registry.toml  stream lifecycle metadata
streams/events.toml    payload-safe watch event bus
rooms/registry.toml    room, participant, topic, and multi-agent session metadata
rooms/events.toml      payload-safe room event bus
rooms/policy.toml      payload-safe room topic grants
routes/registry.toml   direct/relay route candidates and selected paths
routes/probes.toml     metadata-only route probe history
pairing/invites/       pending local pairing invitations
pairing/used/          consumed local pairing invitations
sessions/registry.toml remote runtime session metadata
mailbox/               local runtime relay outbox markers
mailbox/relay/outbox/  peer-encrypted outbound relay message, stream-chunk, room-event, and control envelopes
mailbox/relay/sent/    metadata markers for relay-sent envelopes
mailbox/relay/rejected/ rejected relay outbox markers
logs/conud.log         runtime metadata log
logs/agents.log        local agent metadata log
logs/messages.log      local message delivery metadata log
logs/sessions.log      remote session sync metadata log
logs/streams.log       stream lifecycle metadata log
logs/rooms.log         room/pub-sub metadata log
logs/routes.log        direct/relay route sync metadata log
logs/relay-delivery.log relay delivery metadata log
logs/*.log.N          rotated metadata log archives
```

Runtime, agent, and message logs contain metadata only, such as event name, pid, node id, agent id, envelope id, byte count, and `payload=not_observed`. `conu logs rotate` rotates local `.log` files by byte size and archive count while reporting only filenames, sizes, and counts; `conu doctor` scans active logs and rotated `.log.N` archives for known payload-leak terms without printing log contents. `conu telemetry snapshot --json` reports schema `conu.telemetry.snapshot.v1`, its explicit field allowlist, aggregate local counters, and `contentsDisplayed=false`; it does not include node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, secrets, or payload bodies. New local message request and recipient-inbox envelope files store conU-owned payload bytes with XChaCha20Poly1305 encrypted-at-rest fields. CLI output, receipts, processed markers, rejected markers, and logs do not display message contents.

## Local Agent Gateway

Phase 5 exposes a local, metadata-only gateway for agent registration and presence:

```bash
conu agents register agent.codex "Codex Desktop" --kind coding-agent --streams true --rooms true
conu agents heartbeat agent.codex --presence busy
conu agents export agent.codex --json
conu agents trust <remote-agent-id> "<remote name>" --node <trusted-peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id>
conu agents
conu agents --json
```

Agents default to message and presence capability only. Register with `--streams true` and/or `--rooms true` before using `conu connect local`, `conu streams`, or `conu rooms`; use `--messages false`, `--files true`, or `--presence false` only when an agent intentionally exposes that narrower surface.

`conu agents export --json` emits public signed agent-card metadata only: agent id, display name, node id, kind, capabilities, public signing key, and signature. A peer must already be trusted through `conu peers trust` before `conu agents trust` accepts that peer's signed remote agent card. The import verifies the signature, requires the card signing key to match the trusted peer card, and writes `agents/remote.toml` without displaying payload contents. When signed peer-card trust and at least one peer policy grant exist on both sides, conUD/session sync also exchanges these signed agent cards automatically over peer-encrypted relay control envelopes.

When `conUD` is running, it processes pending requests from `runtime/ipc/inbox/` and moves them to `processed/` or `rejected/`. Without a running daemon, requests remain queued and can be processed manually:

```bash
conud --process-ipc
```

## Local Opaque Messages

Phase 6 added local-only message delivery between registered agents, and Phase 11 encrypts new conU-owned local payload storage:

```bash
conu messages send agent.sender agent.receiver --stdin
conu messages inbox agent.receiver
conu messages inbox agent.receiver --json
conu messages receipts
```

`conu messages send` reads bytes from stdin so payloads are not placed directly in the command line. When `conUD` is running, delivery is processed automatically. If the runtime is offline, encrypted message requests remain queued under `runtime/ipc/messages/inbox/` and can be processed with `conud --process-ipc`.

## Local Connect, Rooms, And Pub/Sub

Phase 14 adds the multi-agent room/session surface and improves the CLI control room:

```bash
conu connect
conu connect local agent.codex agent.hermes
conu rooms create room.dev "Dev Room" --agent agent.codex
conu rooms join room.dev agent.hermes
conu rooms policy room.dev agent.hermes build --publish true --subscribe false
conu rooms policy room.dev agent.codex build --publish false --subscribe true
conu rooms publish room.dev agent.hermes build --stdin
conu rooms events
conu watch
```

`conu connect local` opens a metadata-tracked local stream between two registered local agents. `conu rooms` creates shared room metadata, joins visible local or trusted remote agents, and publishes opaque room events by byte count. Joined local participants receive encrypted-at-rest event envelopes in their normal message inbox. Joined trusted remote participants receive peer-encrypted room event envelopes over the relay when their signed remote agent metadata advertises `rooms=true` and the trusted peer policy grants `rooms=true`. `conu rooms policy` can add metadata-only per-topic publish/subscribe grants; once any policy exists for a room/topic, that topic requires explicit publisher and subscriber grants. Room registry, event bus, policy file, CLI output, and logs contain room id, participant ids, topic, event id, route label, byte count, delivery count, grants, and timestamps only. They do not store or print payload text.

Current room delivery supports local pub/sub fanout, relay-backed room event fanout to joined trusted remote agents, and explicit per-topic publish/subscribe grants for configured topics. Unconfigured topics keep the existing room membership boundary for compatibility. Remote stream writes to mirrored trusted agents can travel as peer-encrypted `stream_chunk` inbox envelopes over an authenticated direct QUIC route when reachable, with relay fallback preserved.

## Relay-Backed Remote Messages And Streams

conU can now move peer-encrypted message, stream-chunk, and room-event envelopes between two trusted nodes through the WebSocket relay:

```bash
conu identity export --json
conu peers trust <peer-node-id> <display-name> --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
conu start
conu messages send agent.sender agent.remote --peer <peer-node-id> --stdin
conu streams open agent.sender <remote-agent-id-with-streams>
conu streams write <stream-id> --stdin
```

`conu identity export --json` includes public exchange material plus a signed peer-card integrity proof. `conu peers trust` verifies that signature when the signing fields are supplied; older unsigned imports still work for controlled legacy tests but are not the preferred production path. Trust is not authorization by itself: `conu peers policy` records explicit metadata-only grants for messages, streams, rooms, files, and mailbox surfaces, and missing policy records deny by default. After signed peer trust and policy grants, conUD/session sync queues local signed agent cards for encrypted relay exchange so remote stream and room metadata is backed by a signed agent card rather than a placeholder mirror. Manual `conu agents export` / `conu agents trust` remains available for daemonless or controlled fallback flows. Run `conu start` on both nodes after `default_relay` or trusted peer relay endpoints are configured. conUD keeps a relay WebSocket session open across runtime ticks when the endpoint is stable, retries on failures, flushes pending outbound envelopes, receives inbound peer-encrypted envelopes, and imports verified signed agent cards. If that same daemon process reconnects to the same relay endpoint after a socket drop, it can present the prior session id as a resume hint; the relay accepts it only for the same node and accounts resumed sessions without logging session ids or payloads. Set `CONU_RELAY_SESSION_STATE_DIR` on the relay when same-node resume metadata must survive a relay restart; the session files contain node/session metadata plus display guards, not tokens, token hashes, payloads, ciphertext bodies, or private keys. Inspect those records locally with `conu-relay --session-audit --session-state-dir <path> [--node <node-id>] [--json]`, or from a running managed relay with `conu-relay --admin-session-audit --relay <wss://...> --admin-token-stdin [--node <node-id>] [--json]`; both forms report counts, active/expired/invalid totals, timestamp bounds, and false display guards without rendering relay session ids. Stream chunks require the local sender and remote target metadata to advertise `streams=true`, and the trusted peer policy must grant `streams=true`. Room events require the local publisher and remote target metadata to advertise `rooms=true`, and the trusted peer policy must grant `rooms=true`. Stream chunks arrive in the addressed agent inbox with `kind = "stream_chunk"` and `stream_id` metadata; room events arrive with `kind = "event"` and payload-safe room event metadata. Payload bytes remain available only through explicit receive APIs for that agent. `conu relay sync --wait-ms 3000` remains available as an explicit manual flush/debug command. The relay sees node ids, agent ids, envelope id, optional stream id, byte count, public exchange key material, and ciphertext only. It does not receive plaintext message, stream, room-event, or signed-card contents. See `docs/internet-relay-test.md` and `scripts/smoke-relay-daemon.ps1` for local two-node smoke coverage and an internet test checklist.

If the target runtime is offline, `conu-relay` can hold peer-encrypted message, stream-chunk, or room-event envelopes in a bounded mailbox and deliver them when that node reconnects. The default mailbox is memory-only. Set `CONU_RELAY_MAILBOX_DIR` on the relay to persist ciphertext envelope files across relay restarts; the stored files contain route metadata, public key material, ciphertext, and `payload_displayed = false`, never plaintext message, stream, or room-event contents. Inspect durable mailbox pressure with `conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]`; it reports file counts, byte totals, queue timestamp bounds, optional expired counts, invalid mailbox-file counts, and false display guards without rendering frame contents or ciphertext bodies. Managed relay operators can query the same retention metadata from the running relay with `conu-relay --admin-mailbox-audit --relay <wss://...> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]`. Remove expired valid mailbox files with `conu-relay --mailbox-purge --mailbox-dir <path> [--ttl-seconds <seconds>] [--node <node-id>] [--retention-policy-file <path>] --dry-run [--json]` first, then rerun with `--confirm` to delete only the expired `.mailbox` files reported by the same retention scan. Managed operators can run the same confirm-gated cleanup against a running relay with `conu-relay --admin-mailbox-purge --relay <wss://...> --admin-token-stdin [--ttl-seconds <seconds>] [--node <node-id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]`. When several relay mailbox stores are available locally through a guarded fleet manifest, run `conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] --dry-run [--json]`, review the aggregate and per-relay expired counts, then rerun with `--confirm` to delete only expired valid `.mailbox` files from those configured local stores. Set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` with `CONU_RELAY_MAILBOX_DIR` when the relay should run the same expired-file cleanup on a local schedule using `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`; `0` or an empty value disables it. Purge output is aggregate-only and never prints stored frames, ciphertext bodies, payloads, tokens, token hashes, private keys, or relay session ids. Set `CONU_RELAY_ACCOUNTING_DIR` to persist metadata-only per-node counters for authenticated and resumed sessions, sent/received bytes, and mailbox accepts, and optionally set per-window sent-envelope or sent-byte quotas. Set `CONU_RELAY_ABUSE_DIR` to persist metadata-only abuse/dashboard counters for unauthorized sessions, credential or tenant denies, rate limits, session expiry, quota denies, undelivered forwards, and mailbox rejects; inspect them with `conu-relay --abuse-audit --abuse-dir <path> [--node <node-id>] [--json]`, evaluate operator-supplied maximums with `conu-relay --abuse-threshold-report --abuse-dir <path> --max-<metric> <count>... [--json] [--fail-on-threshold]`, combine local files with `conu-relay --hosted-dashboard ... --json`, or query a running managed relay with `conu-relay --admin-hosted-dashboard --relay <wss://...> --admin-token-stdin [--account <id>] [--node <id>] [--json]`. Before startup or release smoke, run `conu-relay --hosted-readiness --bind-addr <addr> --credentials-file <path> --admin-tokens-file <path> --tenants-file <path> --session-state-dir <path> --mailbox-dir <path> --accounting-dir <path> --abuse-dir <path> [--account <id>] [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-warning]` to combine those local single-relay checks into one metadata-only preflight; it reports only paths, counts, threshold checks/exceeded counts, warning totals, bind metadata, and false display guards. Managed operators can run the same threshold report against the running relay with `conu-relay --admin-abuse-threshold-report --relay <wss://...> --admin-token-stdin [--account <id>] [--node <id>] --max-<metric> <count>... [--json] [--fail-on-threshold]`; it uses dashboard authorization and reports counts, max values, exceeded flags, and display guards only. With `--fail-on-threshold`, both threshold commands still print the report to stdout and return exit code 3 only when one or more configured thresholds are exceeded; hosted readiness returns exit code 3 with `--fail-on-warning` when any warning exists, including exceeded configured abuse thresholds. Managed relay operators can also update and audit the configured tenant registry online with `conu-relay --admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, and `--admin-tenant-audit`, audit configured file-backed session state with `conu-relay --admin-session-audit`, or suspend one hosted account with `conu-relay --admin-hosted-account-suspend`; these commands use `--admin-token-stdin` and return tenant/session/credential counts plus display guards only. `CONU_RELAY_SESSION_STATE_DIR` persists metadata-only same-node session resume records for a single relay storage boundary, and `conu-relay --session-audit --session-state-dir <path> [--node <node-id>] [--json]` reports only record counts, active/expired/invalid totals, timestamp bounds, and false display guards. Distributed hosted dashboards, distributed multi-instance locking, remote relay retention purge, cross-region retention locking, remote/distributed tenant lifecycle/workflow services beyond guarded local fleet account/node audit, tenant-node lifecycle, account/node suspension plus single-relay account suspension/scoped admin tokens, and tenant-wide adaptive abuse workflows remain future work.

Guarded fleet account audit, credential revoke, tenant account lifecycle, tenant-node lifecycle, and suspension use the same fleet manifest as hosted fleet dashboards. Run `conu-relay --hosted-fleet-account-audit <account-id> --fleet-file <path> [--node <node-id>] [--json] [--fail-on-warning]` to inspect credential/tenant source coverage, missing account or node records, and active/revoked mismatches across manifest-listed local stores without mutating files; with `--node`, the audit narrows credential and tenant-node counts to that node and can report node-specific categories such as `node_missing_credentials`, `tenant_node_missing`, and node credential/tenant-node lifecycle mismatches. With `--fail-on-warning`, it preserves stdout and returns exit code 3 when any warning category is present. To revoke a compromised account/node credential across manifest-listed local credential stores without changing tenant metadata, run `conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file <path> --dry-run [--json]`, review the aggregate and per-relay credential counts, then rerun with `--confirm`; every configured `credentials_file` is preflighted first, node ownership collisions and duplicate node records fail closed, and output is counts/paths/mode/status/display guards only. To add or revoke tenant accounts across manifest-listed local tenant registries, run `conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file <path> --dry-run [--json]` or `conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file <path> --dry-run [--json]`, review tenant/source counts, then rerun the selected command with `--confirm`; account lifecycle preflights every configured `tenants_file`, allows upsert to create missing tenant files, requires the account to exist before revoke, and reports only counts, paths, mode/status, account id, and display guards. To update tenant-node metadata across those registries, run `conu-relay --hosted-fleet-tenant-node-upsert <account-id> <node-id> --fleet-file <path> ... --dry-run [--json]`, review the tenant/node counts, then rerun with `--confirm`; revoke uses `conu-relay --hosted-fleet-tenant-node-revoke <account-id> <node-id> --fleet-file <path> --dry-run [--json]` followed by `--confirm`. Fleet tenant-node lifecycle preflights every configured `tenants_file` before confirmed mutation, requires the account to exist and be active for upsert, rejects node ownership collisions, and reports only permissions, key-id presence booleans, counts, paths, mode/status, and false display guards. Then run `conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file <path> [--node <node-id>] --dry-run [--json]`, review the aggregate and per-relay credential/tenant counts, and rerun with `--confirm`; account-wide mode revokes tenant metadata first and account credential records second, while node mode revokes tenant-node metadata first and matching node credential records second. Each affected suspension relay entry must include both `credentials_file` and `tenants_file`; partial credential/tenant entries fail closed for suspension, all complete sources are preflighted before confirmed mutation, output is metadata-only, and none of these fleet commands contacts remote relays.

Threshold reports and hosted readiness also accept `--thresholds-file <path>` for reusable operator policy files when an abuse store is configured. The file is TOML-style metadata with `version = "1"`, `max_*` keys such as `max_admin_unauthorized = 0`, and explicit false display guards for payload, token, token hash, key material, session id, ciphertext, and contents; any CLI `--max-*` value overrides the file default.

Mailbox audit, purge, hosted readiness, and hosted fleet mailbox purge commands also accept `--retention-policy-file <path>` for reusable retention policy files when a mailbox store is configured. The file is TOML-style metadata with `version = "1"`, optional `ttl_seconds` and `node_id` keys, and the same explicit false display guards; any CLI `--ttl-seconds` or `--node` value overrides the file default. Purge commands still require a retention TTL from the policy file, CLI, or per-relay `mailbox_ttl_seconds` where supported, plus exactly one of `--dry-run` or `--confirm`.

Hosted fleet dashboards also accept `--retention-policy-file <path>`, `--ttl-seconds <seconds>`, and `--fail-on-retention` for reusable metadata-only retention gates across manifest-listed relay-local mailbox stores. Fleet retention output reports the effective mailbox node filter, aggregate expired record/byte counts, retention check counts, exceeded source counts, and false display guards only; it does not delete files, contact remote relays, print mailbox contents, or render the fleet manifest/policy contents. `conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path>` accepts the same reusable threshold policy files and inline `--max-*` overrides, reports deterministic action categories for aggregate threshold breaches, and returns exit code 3 only with `--fail-on-action`. For actual cleanup across manifest-listed local stores, use `conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> ... --dry-run` first, then rerun with `--confirm`; it reports aggregate and per-relay counts only and deletes only expired valid `.mailbox` files from configured local paths. CLI `--ttl-seconds` overrides all fleet mailbox TTLs for that run, while per-relay `mailbox_ttl_seconds` entries remain source-specific overrides ahead of the policy-file TTL.

## Security Hardening

Phase 11 adds the first production-facing security layer:

```bash
conu security audit
conu security audit --json
conu security rotate identity --confirm-peer-refresh
conu security retire identity --confirm-peer-refresh-complete
conu security rotate storage --confirm
conu security retire storage --confirm
```

Implemented controls:

- Ed25519 node signing key for local agent-card signatures.
- Signed public local agent-card export/import for trusted peers.
- Ed25519-signed public peer cards for manual cross-machine trust integrity.
- X25519 node exchange key and peer key agreement helpers.
- XChaCha20Poly1305 local payload storage encryption.
- Windows current-user DPAPI wrapping, macOS user Keychain storage, Linux Secret Service storage when available, and non-Windows user-managed wrap-key fallback for local signing, exchange, storage, archived key, and relay credential secret bytes, with migration-compatible reads for older plaintext-hex key files.
- Identity signing/exchange rotation through `conu security rotate identity --confirm-peer-refresh`, with old keys archived under `security/identity-keys/` and refreshed peer-card handoff required.
- Identity archive retirement through `conu security retire identity --confirm-peer-refresh-complete` after refreshed peer cards have been redistributed and old-key decrypt compatibility is no longer required.
- Storage-key rotation for conU-owned encrypted-at-rest message queue and inbox files, with old storage keys archived under `security/storage-keys/` for read compatibility.
- Storage-key retirement for archived keys that no scanned local encrypted-at-rest message queue or inbox file still references.
- Replay cache for local message request and envelope ids.
- Local key rotation plan under `security/key-rotation.md`.

The audit reports readiness, key ids, secret storage backend, and whether local secrets are OS-protected. Identity rotation, identity archive retirement, storage-key rotation, and storage-key retirement report only key ids, refresh requirements, booleans, and file/key counts. These commands do not print private keys, shared secrets, plaintext payloads, or decrypted payloads. See `docs/security-hardening.md` and `docs/production-readiness.md` for the hardening model and release blockers.

For practical user setup, installation, hosting, and current agent integration guidance, see `docs/user-install-and-agent-guide.md` and `docs/distribution-and-hosting.md`.

## Release Readiness

Phase 15 adds packaging and local release checks:

```bash
conu doctor
conu doctor --json
conu logs rotate --max-bytes 1048576 --keep 5
conu telemetry snapshot --json
```

Build local release artifacts:

Windows:

```powershell
.\scripts\build-release.ps1
# If MSVC Build Tools are not installed:
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

macOS/Linux:

```bash
./scripts/build-release.sh
```

The release artifact includes `conu`, `conud`, `conu-relay`, `conu-mcp`, docs, packaging templates, checksum files, and a manifest that states `payload_contents_included = false`. Service templates live under `packaging/` for Windows, Linux systemd, macOS launchd, Docker relay hosting, npm launcher package, and generated package-manager manifest guidance. Tagged release builds run a fail-closed preflight for Windows Authenticode signing, macOS Developer ID signing/notarization, fingerprint-pinned Linux GPG signing secret presence, key import, full-fingerprint match, and probe signing, `NPM_TOKEN` publication, npm package publish metadata, package/tag version consistency, package-manager manifest generation, GitHub Release clobber safety, GitHub Release asset publication metadata, and existing npm package-version conflicts before platform builds or npm publication; release artifacts get GitHub attestations for each archive and checksum file, Linux archives use SHA-256 plus GitHub attestations plus detached `.asc` signatures, generated Debian packages use SHA-256 sidecars plus detached `.asc` signatures, generated RPM packages use native RPM signatures plus refreshed SHA-256 sidecars plus detached `.asc` signatures, generated APT/RPM metadata ZIPs add native repository signatures before receiving detached `.asc` signatures, and `conu-linux-gpg-key.asc` lets users verify Linux signatures from release assets after comparing its full fingerprint with the published maintainer fingerprint. The release workflow verifies archives, generates Homebrew, Scoop, winget, Chocolatey, Debian, and RPM package-manager files plus RPM packages from strict release checksums, verifies the imported Linux signing key matches `CONU_LINUX_GPG_KEY_FINGERPRINT`, signs generated RPM packages before generating RPM repository metadata, exports the Linux GPG public key, adds APT `InRelease`/`Release.gpg` and RPM `repodata/repomd.xml.asc` signatures, signs Linux release assets after package generation, smoke-tests unpacked installs, smoke-tests the npm launcher local install path with an existing regular-file binary directory, runs local-smoke, package-manager, Linux-signing-secret-preflight, RPM-package-signing, Linux-signing, Linux-repository-signing, Linux-public-key-export, GitHub Release clobber, GitHub Release asset publication, and npm-publish preflight regression checks, and smoke-tests the npm launcher download/checksum install path with HTTPS-or-loopback URL enforcement, bounded timeout/size behavior, archive-member count/duplicate/state-path preflight, and bounded extracted-tree binary selection before attestation/upload. Before GitHub Release asset upload, tagged publication verifies no public release already exists for the tag and refuses to overwrite assets; before npm registry access, tagged npm publication verifies the public GitHub Release has all expected platform archives, checksum sidecars, Linux signatures, package-manager files, public-key asset, hosted repository bundle, and hosted repository site artifact with checked cache policy files. See `docs/release-checklist.md`, `docs/platform-code-signing.md`, `docs/observability.md`, `docs/distribution-and-hosting.md`, and `packaging/README.md`.

The intended public one-command install path is:

```bash
npm install -g @conu/cli
conu doctor
```

That npm package is a thin native-binary launcher. Rust remains the product; npm only downloads the matching checksummed release asset with bounded request time, response sizes, and post-extraction binary selection, then exposes the commands on `PATH`.

## Pairing And Trust

Phase 7 adds local trust-store mechanics, and the relay data-plane adds signed manual public peer-card exchange:

```bash
conu pair
conu join 123456
conu peers
conu peers --json
conu peers revoke peer_example
conu identity export
conu peers trust node_example "Peer Node" --exchange-key <hex> --relay ws://127.0.0.1:8787 --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers trust node_example "Peer Node" --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu agents export agent.codex --json
conu agents trust agent.remote "Remote Agent" --node node_example --kind coding-agent --signing-key <hex> --signature <hex> --signature-key-id <id>
```

`conu pair` creates a short local invitation code with an expiration. `conu join <code>` consumes a local invitation and writes a trusted peer record to `trust.toml`. For cross-machine testing today, exchange `conu identity export --json` output with the other user, import their public card using `conu peers trust`, grant the intended communication surfaces with `conu peers policy`, and let conUD/session sync exchange signed public agent cards automatically. Manual `conu agents export --json` and `conu agents trust` remain useful for offline fallback. Trust records store public exchange keys, relay endpoints, and peer-card signature metadata when available; policy records store boolean grants only; private keys are never exported.

## WebSocket Relay

Phase 8 adds the `conu-relay` service and the shared relay frame contract in `conu-core`:

```bash
set CONU_RELAY_TOKEN=local-dev-token
cargo run -p conu-relay -- --serve 127.0.0.1:8787
```

Connected runtimes send `HELLO`, `FORWARD`, and `PING` frames. `HELLO` may include an optional same-node resume hint; `WELCOME` reports whether the relay accepted it. The relay answers with `WELCOME`, `ENVELOPE`, `SENT`, `UNDELIVERED`, `PONG`, or `ERROR` frames. Relay `FORWARD` can carry a peer-encrypted opaque body for message delivery, stream chunks, room events, and signed-card control envelopes, but plaintext payload fields are rejected and logs/output use `payload=not_observed`, `payload=opaque`, or `payload=peer_encrypted`.

`conu-relay` also accepts `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, and `CONU_RELAY_MAX_FRAMES_PER_MINUTE` for basic abuse controls, plus `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE`, `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`, and optional `CONU_RELAY_MAILBOX_DIR` for bounded durable ciphertext mailbox storage. `conu-relay --mailbox-audit --mailbox-dir <path> [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]` renders local retention metadata for those durable mailbox files without printing frame contents, ciphertext bodies, tokens, hashes, private keys, session ids, or payloads. `conu-relay --admin-mailbox-audit --relay <wss://...> --admin-token-stdin [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]` returns the same class of metadata from a running relay after admin-token authorization. `conu-relay --mailbox-purge --mailbox-dir <path> [--ttl-seconds <seconds>] [--node <id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]` is the confirm-gated local purge workflow for expired valid `.mailbox` files and reports scanned, invalid, expired, purged, and byte counts only. `conu-relay --admin-mailbox-purge --relay <wss://...> --admin-token-stdin [--ttl-seconds <seconds>] [--node <id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]` runs the same metadata-only retention purge against a running relay's configured durable mailbox storage. `conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> [--node <id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]` applies the same confirm-gated cleanup across guarded manifest-listed local mailbox stores and reports aggregate plus per-relay counts only. `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` enables relay-local scheduled cleanup of expired valid `.mailbox` files and requires `CONU_RELAY_MAILBOX_DIR`; it uses the offline envelope TTL and does not render stored contents. `CONU_RELAY_SESSION_STATE_DIR` persists metadata-only same-node session resume files across relay restarts, `conu-relay --session-audit --session-state-dir <path> [--node <id>] [--json]` renders local record counts/timestamp bounds, `conu-relay --admin-session-audit --relay <wss://...> --admin-token-stdin [--node <id>] [--json]` returns the same session-state metadata from a running relay after admin-token authorization, `CONU_RELAY_ACCOUNTING_DIR` persists metadata-only per-node accounting files, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS` sets the quota window, and `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE` / `CONU_RELAY_MAX_BYTES_SENT_PER_NODE` can reject over-quota sends with `UNDELIVERED reason=quota_exceeded`. `CONU_RELAY_ABUSE_DIR` persists metadata-only `.abuse` counter files for denial and enforcement trends, `CONU_RELAY_ABUSE_WINDOW_SECONDS` sets that counter window, `conu-relay --abuse-audit --abuse-dir <path>` renders aggregate or per-node counts, `conu-relay --abuse-threshold-report --abuse-dir <path> [--node <id>] --max-<metric> <count>... [--json] [--fail-on-threshold]` compares those counts against operator-supplied maximums, `conu-relay --hosted-dashboard --credentials-file <path> --tenants-file <path> --accounting-dir <path> --abuse-dir <path> [--account <id>] [--node <id>] [--json]` renders one local operator snapshot, `conu-relay --hosted-readiness ... [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-warning]` combines credential, admin-token, tenant, session-state, mailbox retention, accounting, abuse, and abuse threshold checks into one pre-startup/readiness report, and `conu-relay --admin-hosted-dashboard --relay <wss://...> --admin-token-stdin [--account <id>] [--node <id>] [--json]` returns the same class of metadata from a running relay after admin-token authorization. The online threshold form is `conu-relay --admin-abuse-threshold-report --relay <wss://...> --admin-token-stdin [--account <id>] [--node <id>] --max-<metric> <count>... [--json] [--fail-on-threshold]`; it reuses dashboard authorization and returns only count/max/exceeded metadata, with exit code 3 for exceeded thresholds only when `--fail-on-threshold` is set. `conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path> [--node <id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-action]` turns guarded local fleet abuse thresholds into aggregate action categories without changing relay state or contacting remote relays. Dashboard, readiness, session audit, threshold, response-plan, tenant/admin account, and mailbox audit/purge output never includes tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, or frame contents. The relay is available now as a standalone service for encrypted message, stream-chunk, room-event, and signed-card sync, and conUD owns a reusable relay session when a relay or trusted relay peer is configured. Same-node reconnects can resume a prior relay session on the same endpoint when the daemon still has the resume hint and the relay has in-memory or file-backed session state; cross-node resume attempts mint a new session instead. A relay can issue scoped credential tokens offline, accept account-scoped online issue/rotate/revoke/audit, local/admin-gated account suspension, admin-gated tenant lifecycle, admin-gated session-state audits, admin-gated dashboard snapshots, admin-gated abuse threshold reports, admin-gated mailbox retention audits, and admin-gated mailbox retention purges through the hosted admin control plane, and live-reload a scoped credential manifest with hashed tokens, active/revoked status, account metadata, and optional expiry metadata on new `HELLO` authentication attempts. Existing authenticated sessions remain governed by idle timeout and max TTL. Distributed hosted dashboards/adaptive abuse automation beyond guarded fleet response plans, distributed multi-instance state stores, remote/distributed tenant lifecycle/RBAC workflows beyond guarded local fleet account/node audit, tenant-node lifecycle, account/node suspension plus single-relay account suspension/scoped admin tokens, remote relay retention purge/cross-region retention locking beyond guarded local fleet cleanup, and managed ICE/STUN/TURN NAT traversal still land in later transport phases.

For repeated mailbox retention checks or cleanups, add `--retention-policy-file <path>` to local/admin mailbox commands, hosted readiness, or hosted fleet dashboards and keep shared `ttl_seconds` plus optional `node_id` in a metadata-only policy file; CLI `--ttl-seconds` and `--node` values stay useful for temporary overrides. Hosted fleet dashboards use the same policy file as a read-only aggregate retention gate, and `--fail-on-retention` returns exit code 3 only when TTL-checked fleet mailbox sources report expired records. For repeated threshold checks, add `--thresholds-file <path>` to local/admin threshold commands, hosted readiness, hosted fleet dashboards, or hosted fleet abuse response plans and keep shared `max_*` values in a metadata-only policy file; CLI `--max-*` values stay useful for temporary overrides.

For self-hosted multi-node relays, prefer a scoped credential manifest so the server does not keep raw relay tokens in long-lived environment variables:

```powershell
conu-relay --issue-credential node_a --token-out C:\conu-relay\node_a.token --credentials-file C:\conu-relay\credentials.toml
conu-relay --issue-credential node_b --token-out C:\conu-relay\node_b.token --credentials-file C:\conu-relay\credentials.toml
```

The raw token is written only to the token file, not stdout. With `--credentials-file`, the relay manifest is created or appended with hashed token metadata without printing the manifest contents. Omit `--credentials-file` only when you want a hashed `manifest entry` block for manual copy.

```toml
version = "1"

[[credential]]
account_id = "account_prod"
node_id = "node_a"
token_sha256_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
token_length = 64
status = "active"
payload_displayed = false
token_displayed = false

[[credential]]
node_id = "node_b"
token_sha256_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
token_length = 64
status = "active"
payload_displayed = false
token_displayed = false
```

```bash
set CONU_RELAY_CREDENTIALS_FILE=C:\conu-relay\credentials.toml
set CONU_RELAY_IDLE_TIMEOUT_SECONDS=120
set CONU_RELAY_SESSION_TTL_SECONDS=3600
set CONU_RELAY_SESSION_STATE_DIR=C:\conu-relay\sessions
set CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE=128
set CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS=3600
set CONU_RELAY_MAILBOX_DIR=C:\conu-relay\mailbox
set CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS=3600
set CONU_RELAY_ACCOUNTING_DIR=C:\conu-relay\accounting
set CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400
set CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000
set CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824
set CONU_RELAY_ABUSE_DIR=C:\conu-relay\abuse
set CONU_RELAY_ABUSE_WINDOW_SECONDS=86400
set CONU_RELAY_ADMIN_TOKEN=<custom-admin-token-from-secret-store>
set CONU_RELAY_ADMIN_TOKENS_FILE=C:\conu-relay\admin-tokens.toml
set CONU_RELAY_TENANTS_FILE=C:\conu-relay\tenants.toml
```

`CONU_RELAY_CREDENTIALS_FILE` overrides `CONU_RELAY_CREDENTIALS`, which remains available as comma-separated `node-id:token` compatibility config and overrides the shared `CONU_RELAY_TOKEN` on the server. The relay reloads the credential file for each new `HELLO`, so marking a credential `revoked` or setting an expired `expires_at_unix` rejects new sessions without a relay restart. `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` generates a strong scoped token, writes it to a new token file, and upserts only hashed manifest metadata. Use `--replace` with the same command to rotate an existing node credential, and use `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a node revoked without printing token material. `conu-relay --hash-token` remains available when an operator already has a token. For managed relay operators, `CONU_RELAY_ADMIN_TOKEN` enables the backward-compatible full-admin online lifecycle. `CONU_RELAY_ADMIN_TOKENS_FILE` can additionally or instead live-read hashed scoped admin tokens for credentials, tenants, dashboard, sessions, mailbox-audit, and mailbox-purge actions, with optional account scoping; inspect that local manifest with `conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <account-id>] [--json]` to verify scope/account/expiry counts without printing admin tokens or token hashes. Hosted account suspension requires a full-admin token or both credentials and tenants scopes. Online admin commands such as `conu-relay --admin-issue-credential <account-id> <node-id> --relay <wss://...> --admin-token-stdin --token-out <path>`, `--admin-rotate-credential`, `--admin-revoke-credential`, `--admin-audit-credentials`, `--admin-hosted-dashboard`, `--admin-session-audit`, `--admin-abuse-threshold-report`, `--admin-hosted-account-suspend`, `--admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, `--admin-tenant-audit`, `--admin-mailbox-audit`, and `--admin-mailbox-purge` send only node-token hash metadata or metadata-only dashboard, session, threshold, tenant, account-suspension, and mailbox requests to the relay and report metadata counts/status only. `CONU_RELAY_TENANTS_FILE` adds a metadata-only hosted tenant registry controlled locally by `--tenant-upsert`, `--tenant-node-upsert`, `--tenant-node-revoke`, `--tenant-revoke`, `--tenant-audit`, and `--hosted-account-suspend`, or online through scoped admin tenant/account commands; issue/rotate and new `HELLO` sessions fail closed when tenant or node records are missing or revoked. See `docs/hosted-relay-account-auth.md`. Each runtime can set `CONU_RELAY_TOKEN` to its assigned scoped token, or store it locally without putting it in shell history:

```powershell
Get-Content -Raw C:\conu-relay\node_a.token | conu relay credential set --stdin
conu relay credential status
```

At runtime, `CONU_RELAY_TOKEN` overrides the stored credential; if neither is present, conU falls back to `local-dev-token` for loopback tests. Stored relay credentials use the same secret-field backend as local key files: Windows DPAPI, macOS user Keychain, Linux Secret Service when available, non-Windows user-managed XChaCha20Poly1305 wrapping when configured, or owner-only files as the final fallback. `local-dev-token` is accepted only for loopback relay binds. Any non-loopback bind such as `0.0.0.0:8787` requires a custom shared token or scoped credential token with at least 24 characters.

Relay clients accept `ws://` and `wss://` endpoints. The bundled `conu-relay` server still listens as a plain WebSocket service; public `wss://` deployments should terminate TLS with a certificate-valid reverse proxy or load balancer in front of `conu-relay`.

## Remote Sessions And Discovery

Phase 9 adds a conUD-owned remote session mirror for trusted peers:

```bash
conu sessions sync
conu sessions
conu sessions --json
conu agents --json
```

`conu sessions sync` reads trusted peers, writes route/session metadata under `sessions/registry.toml`, mirrors visible remote agent cards into `agents/remote.toml`, and appends only metadata to `logs/sessions.log`. `conUD --process-ipc`, `conUD --once`, and the runtime serve loop also sync remote sessions.

This phase is still metadata/discovery groundwork: `conu sessions sync` preserves imported signed remote agent cards for trusted peers and falls back to a placeholder mirror only when no signed agent cards have been imported for that peer. Payloads remain opaque and are never displayed by session or agent listing commands.

## Direct Routes And Relay Fallback

Phase 13 adds a route manager owned by conUD:

```bash
conu routes sync
conu routes
conu routes --json
conu routes probes
```

`conu routes sync` reads trusted peers and `config.toml`, probes direct QUIC candidates against relay WebSocket fallback, writes `routes/registry.toml`, appends metadata-only probes to `routes/probes.toml`, and records payload-safe summaries in `logs/routes.log`. Direct endpoints can be advertised in signed peer cards with `direct_quic_endpoint = "quic://host:port"` or overridden locally with a peer-specific sanitized key like `direct_quic_peer_abcd1234 = "quic://host:port"`. Route records include candidate source, candidate kind, and rendezvous state so operators can distinguish peer-card/config candidates from missing NAT traversal support without exposing endpoint secrets.

Direct is selected only after a live QUIC connection succeeds and the peer answers an encrypted challenge with the trusted peer-card key. If a static candidate cannot be reached, conU records `direct_quic_probe_failed`; if no candidate exists for NAT profiles that need traversal help, it records `nat_traversal_unavailable`. Relay remains selected in both cases. conU does not yet perform ICE/STUN/TURN negotiation or UDP hole punching.

## Streams And Watch

Phase 10 adds stream lifecycle metadata and a private watch view:

```bash
conu streams
conu streams open agent.sender agent.receiver
conu streams write stream_example --stdin
conu streams close stream_example
conu watch
```

`conu streams write` reads chunk bytes from stdin, records byte counts, updates backpressure metadata, and appends watch events without storing or printing the chunk contents. For mirrored trusted remote agents on relay routes, the chunk is peer-encrypted into the relay outbox and delivered as a `stream_chunk` inbox envelope. `conu watch` shows route, stream id, packet count, byte count, and an ASCII private-packet flow only.

The stream layer is still metadata-first. Remote chunks are point-in-time encrypted envelopes over direct QUIC or relay, not a long-lived application stream with end-to-end flow negotiation yet.

## SDK And MCP Adapter

Phase 12 adds agent-facing integrations:

```bash
cargo run -p conu-sdk --example local_agents
cargo run -p conu-mcp
npm run check --prefix sdk/typescript
```

Rust agents can use `conu_sdk::ConuClient` to register, update presence, list agents/peers, exchange peer cards, send local opaque bytes, queue remote relay messages, optionally run relay sync, receive payload bytes for the addressed local agent, open/write/close streams, and create/join/publish room metadata events with optional topic policy grants. Python agents can use the stdlib wrapper under `sdk/python`. TypeScript and JavaScript agents can use the dependency-free Node wrapper under `sdk/typescript` as `@conu/sdk`; it wraps installed `conu`/`conud`/`conu-mcp` binaries, passes payload bytes through stdin, returns metadata-only command results for normal list/status surfaces, and exposes raw inbox bytes only through explicit addressed-agent receive helpers. `@conu/sdk` is not browser-native protocol support; browser-conditioned imports fail closed through a safe unsupported stub until hosted auth, browser transport, and key-handling rules exist.

MCP-capable agents can launch `conu-mcp` as a stdio server. It exposes tools such as `conu_register_agent`, `conu_export_identity`, `conu_trust_peer`, `conu_set_peer_policy`, `conu_send_message`, `conu_send_remote_message`, `conu_relay_sync`, `conu_receive_message`, `conu_open_stream`, `conu_create_room`, `conu_join_room`, `conu_set_room_topic_policy`, `conu_publish_room_event`, and `conu_security_audit`. The adapter follows the current MCP stdio transport shape: newline-delimited JSON-RPC 2.0 messages on stdin/stdout. Tool list/send/status/room outputs remain metadata-only. Set `CONU_AGENT_ID` when launching one MCP server for one agent; then the adapter rejects attempts to act as another local agent. `conu_receive_message` returns payload bytes as `payloadHex` only when the addressed local agent explicitly passes `includePayload: true`.

See `docs/sdk-and-mcp.md` for SDK examples, MCP tool contracts, route tools, and privacy rules. See `docs/direct-transport-and-routes.md` for the Phase 13 route manager.

## Development

```bash
cargo fmt
cargo check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

On Windows machines without Visual Studio C++ Build Tools, use the GNU Rust toolchain for commands that link binaries or tests:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu test --workspace
powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -Toolchain stable-x86_64-pc-windows-gnu
powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu
powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Useful CLI commands:

```bash
cargo run -p conu-cli --
cargo run -p conu-cli -- init
cargo run -p conu-cli -- status
cargo run -p conu-cli -- status --json
cargo run -p conu-cli -- agents
cargo run -p conu-cli -- agents --json
cargo run -p conu-cli -- agents register agent.codex "Codex Desktop" --kind coding-agent --streams true --rooms true
cargo run -p conu-cli -- agents heartbeat agent.codex --presence busy
cargo run -p conu-cli -- messages send agent.sender agent.receiver --stdin
cargo run -p conu-cli -- messages send agent.sender agent.remote --peer node_peer --stdin
cargo run -p conu-cli -- messages inbox agent.receiver --json
cargo run -p conu-cli -- messages receipts --json
cargo run -p conu-cli -- identity export --json
cargo run -p conu-cli -- relay sync --wait-ms 3000
cargo run -p conu-cli -- streams open agent.sender agent.receiver
cargo run -p conu-cli -- streams write stream_example --stdin
cargo run -p conu-cli -- streams close stream_example
cargo run -p conu-cli -- connect local agent.sender agent.receiver
cargo run -p conu-cli -- rooms create room.dev "Dev Room" --agent agent.sender
cargo run -p conu-cli -- rooms join room.dev agent.receiver
cargo run -p conu-cli -- rooms publish room.dev agent.receiver build --stdin
cargo run -p conu-cli -- rooms events
cargo run -p conu-cli -- watch
cargo run -p conu-cli -- sessions sync
cargo run -p conu-cli -- sessions --json
cargo run -p conu-cli -- routes sync
cargo run -p conu-cli -- routes --json
cargo run -p conu-cli -- routes probes
cargo run -p conu-cli -- security audit
cargo run -p conu-cli -- security audit --json
cargo run -p conu-cli -- security rotate identity --confirm-peer-refresh
cargo run -p conu-cli -- identity export --json
cargo run -p conu-cli -- security retire identity --confirm-peer-refresh-complete
cargo run -p conu-cli -- security rotate storage --confirm
cargo run -p conu-cli -- security retire storage --confirm
cargo run -p conu-cli -- doctor
cargo run -p conu-cli -- doctor --json
cargo run -p conu-cli -- logs rotate --max-bytes 1048576 --keep 5
cargo run -p conu-cli -- telemetry snapshot --json
cargo run -p conu-cli -- pair
cargo run -p conu-cli -- join 123456
cargo run -p conu-cli -- peers --json
cargo run -p conu-cli -- peers trust node_peer "Peer Node" --exchange-key <hex> --relay ws://127.0.0.1:8787 --signing-key <hex> --signature <hex> --signature-key-id <id>
cargo run -p conu-cli -- peers trust node_peer "Peer Node" --exchange-key <hex> --relay wss://relay.example.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
cargo run -p conu-cli -- peers policy node_peer --messages true --streams true --rooms true
cargo run -p conu-cli -- peers revoke peer_example
cargo run -p conu-cli -- connect
cargo run -p conu-cli -- watch
cargo run -p conu-cli -- start
cargo run -p conu-cli -- stop
cargo run -p conud -- --check
cargo run -p conud -- --once
cargo run -p conud -- --process-ipc
cargo run -p conu-relay -- --check
cargo run -p conu-relay -- --serve 127.0.0.1:8787
cargo run -p conu-sdk --example local_agents
cargo run -p conu-mcp
```

When running from a development checkout, build `conud` first or set `CONUD_EXE` to the local daemon binary before using `conu start`.

## Project Memory

Future agents should read:

1. `architecture.md`
2. `plan.md`
3. `.agents/AGENTS.md`
4. `.agents/repo/ABOUT.md`

Before PR or merge, use the repo-local PR and security guardian skills under `.agents/skills/`.
