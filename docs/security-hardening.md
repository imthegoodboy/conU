# conU Security Hardening

Phase 11 adds the first production-facing security layer around conU-owned identity and payload storage.

The product rule still controls every design choice:

```txt
Agents own the conversation.
conU owns the connection.
```

## Implemented Controls

### Local Key Material

`conu init` and `conu security audit` ensure a local security directory exists:

```txt
security/identity-signing.key   Ed25519 node signing key
security/identity-exchange.key  X25519 node exchange key
security/identity-keys/*.key    archived signing/exchange keys kept until identity refresh compatibility is no longer needed
security/storage.key            XChaCha20Poly1305 storage key
security/storage-keys/*.key     archived storage keys kept for migration/read compatibility
security/replay.toml            replay/idempotency cache
security/key-rotation.md        local key rotation plan
```

Private keys are never printed by CLI output. On Windows, new security key files wrap local signing, exchange, storage, archived key, and relay credential secret bytes with current-user DPAPI (`secretStorageBackend = "windows-dpapi-user"`), and `conu security audit` migrates older plaintext-hex key files to wrapped fields when it can read them. On macOS, conU uses the user Keychain (`secretStorageBackend = "macos-keychain-user"`). On Linux, conU uses Secret Service through `secret-tool` when a user session is available (`secretStorageBackend = "linux-secret-service-user"`). Native protected files store only OS-secret references and lengths, not key bytes or protected blobs.

On non-Windows targets without an available native store, conU can use an operator-managed XChaCha20Poly1305 wrap key for local signing, exchange, storage, archived key, and relay credential secret fields. Set exactly one of:

```txt
CONU_SECRET_WRAP_KEY_HEX=<64 hex chars>
CONU_SECRET_WRAP_KEY_FILE=<path containing 64 hex chars>
```

When either value is configured, `conu init`, `conu security audit`, and relay credential status/read paths migrate older plaintext-hex secret files to `secret_protection = "user-managed-wrap-key-v1"` with encrypted `*_wrapped_hex` fields. The wrap key is never stored by conU and must not be passed as a command-line argument. A native macOS/Linux backend takes precedence when available; migrating an existing user-managed wrapped file to a native backend still requires the configured wrap key so conU can decrypt the old field first. If no native backend or wrap key is available on non-Windows, conU falls back to owner-only local secret files (`secretStorageBackend = "filesystem-permissions"`). Set `CONU_DISABLE_OS_SECRET_BACKEND=1` to force that fallback path for controlled tests. See `docs/native-secret-storage.md` for backend selection and smoke coverage.

### Encrypted Local Payload Storage

New local message request files and recipient inbox envelope files store payload bytes as:

```txt
payload_privacy = "encrypted_at_rest"
payload_cipher = "XChaCha20Poly1305"
payload_key_id = "<metadata id>"
payload_nonce_hex = "<24-byte nonce>"
payload_ciphertext_hex = "<ciphertext plus auth tag>"
```

The authenticated data binds ciphertext to message metadata such as request id, envelope id, sender, and receiver. CLI, logs, receipts, processed markers, and rejected markers still expose metadata only.

### Key Rotation

Run:

```bash
conu security rotate identity --confirm-peer-refresh
conu security rotate identity --confirm-peer-refresh --json
conu security retire identity --confirm-peer-refresh-complete
conu security retire identity --confirm-peer-refresh-complete --json
conu security rotate storage --confirm
conu security rotate storage --confirm --json
conu security retire storage --confirm
conu security retire storage --confirm --json
```

The identity command creates fresh active Ed25519 signing and X25519 exchange keys, archives the prior keys in `security/identity-keys/`, and reports that peers need a refreshed signed public peer card. Archived exchange keys remain available locally so peer-encrypted envelopes sent to the previous exchange public key can still decrypt during the refresh window. Identity rotation output reports only old/new key ids, archive counts, refresh booleans, and `contentsDisplayed=false`; it does not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.

After identity rotation, run `conu identity export` and share the refreshed public card with trusted peers before expecting them to accept newly signed agent cards or encrypt to the new exchange key. After that refresh is complete and old-key peer envelope decrypt compatibility is no longer needed, run `conu security retire identity --confirm-peer-refresh-complete` to delete archived identity key files. Identity archive retirement output reports only archive counts, confirmation booleans, compatibility status, and `contentsDisplayed=false`; it does not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.

The storage command creates a fresh active XChaCha20Poly1305 storage key, archives the prior storage key in `security/storage-keys/`, and re-encrypts conU-owned encrypted-at-rest local message queue and recipient inbox payload files. The archived key ring lets older local payload files remain readable during and after migration. Rotation output reports only old/new key ids, file counts, archive counts, and `contentsDisplayed=false`; it does not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.

The retire command scans local encrypted-at-rest message queue and inbox metadata, removes only archived storage keys that no scanned payload file references, and retains archived keys that are still needed for read compatibility. Retirement output reports only archive counts, file counts, dependent-file counts, and `contentsDisplayed=false`; it does not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.

### Telemetry Output

`conu telemetry snapshot [--json]` reports local aggregate readiness and usage counters only. The JSON output includes schema `conu.telemetry.snapshot.v1`, the explicit `TELEMETRY_FIELD_ALLOWLIST`, and `contentsDisplayed=false`. It must not include node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, private keys, shared secrets, auth tokens, plaintext payloads, decrypted payloads, or ciphertext bodies.

### Signed Agent Cards

Local agent registry records now include Ed25519 signature metadata:

```txt
signature_algorithm = "Ed25519"
signature_key_id = "<metadata id>"
signing_public_key_hex = "<public key>"
signature_hex = "<signature>"
```

The signature covers stable agent-card identity fields and capabilities. Presence and last-seen timestamps are not part of the signature because they are live state, not identity.

`conu agents export --json`, Rust SDK `export_agent_card()`, Python `export_agent_card()`, TypeScript `exportAgentCard()`, and MCP `conu_export_agent_card` expose only the public signed agent-card metadata. `conu agents trust`, Rust SDK `trust_remote_agent_card()`, Python `trust_agent_card()`, TypeScript `trustAgentCard()`, and MCP `conu_trust_agent_card` verify the signature, require the card's node id to already be trusted as a peer, and require the agent-card signing key to match the trusted peer card before writing `agents/remote.toml`. The import stores public signature metadata and capabilities only; payload bytes are not part of the card or trust response.

When signed peer-card trust and at least one peer policy grant exist, session sync queues local signed agent cards as peer-encrypted relay control envelopes. Inbound automatic cards are decrypted only by the addressed runtime and go through the same signature, trusted-node, signing-key, and cross-peer collision checks before replacing placeholder remote-agent metadata. The relay sees node ids, agent ids, envelope ids, byte counts, public exchange key material, and ciphertext only.

### Signed Peer Cards

`conu identity export --json` now includes a public peer-card signature:

```txt
signingPublicKeyHex = "<public Ed25519 key>"
signatureAlgorithm = "Ed25519"
signatureKeyId = "<metadata id>"
signatureHex = "<signature>"
```

The signature covers the exported node id, display name, X25519 exchange public key, and relay endpoint. `conu peers trust` and MCP `conu_trust_peer` verify the signature when those fields are present, then store the public signature metadata in `trust.toml`. This protects manual peer-card exchange from accidental or malicious field changes, while still requiring the user or agent to decide which peer card to trust.

### Replay Protection

Message request ids and delivered envelope ids are recorded in `security/replay.toml`. A repeated id is rejected before payload decryption or delivery. This gives conU receiver-side dedupe groundwork without pretending the network can provide magical exactly-once delivery.

### Peer Key Agreement Helpers

The security module exposes X25519 key agreement helpers and peer payload encryption helpers used by relay message, stream-chunk, room-event, and signed-card control delivery. They derive a symmetric key from local exchange material, peer public material, ordered public keys, and context bytes. The derived shared secret is not returned or printed.

Inbound relay messages, stream chunks, room events, and signed-card control envelopes are decrypted only after the sender exchange public key matches the locally trusted peer card. The relay sees ciphertext and routing metadata, not plaintext message, stream, room-event, or signed-card contents.

### Capability Enforcement

Local agent cards carry `messages`, `streams`, `rooms`, `files`, and `presence` booleans. The CLI exposes these through `conu agents register`, and the Rust SDK, TypeScript SDK, and MCP surfaces can submit explicit capability sets. Core routing enforces `messages` for local and inbound message delivery, `streams` for stream open/write and inbound stream chunks, and `rooms` for room create/join/publish plus local and relay-backed room event fanout. Stream and room routes fail closed when remote metadata does not advertise the matching capability.

### Peer-Scoped Permissions

Peer trust identifies a node, but it does not authorize every communication surface. `conu peers policy`, Rust SDK `set_peer_policy()`, Python `set_peer_policy()`, TypeScript `setPeerPolicy()`, and MCP `conu_set_peer_policy` store boolean grants for messages, streams, rooms, files, and mailbox use in `policy.toml`. Missing peer policy records deny by default.

Relay-backed message send/receive requires `messages=true` for the trusted peer. Relay-backed stream chunks and remote stream opens require `streams=true` plus the agent capability checks above. Relay-backed room event fanout requires `rooms=true` plus local and remote agent room capabilities. File/mailbox policy bits are stored for forward compatibility and stay metadata-only.

Room topic policy is stored under `rooms/policy.toml` with room id, agent id, topic, publish/subscribe booleans, timestamps, and `payload_displayed = false`. Unconfigured topics keep room membership as the compatibility boundary. Once any policy exists for a room/topic, local publish, local fanout, remote fanout, and inbound relay room delivery require explicit publish or subscribe grants for the addressed agent. Topic policies never store event payload bytes.

## CLI Audit

Run:

```bash
conu security audit
conu security audit --json
```

The audit reports whether local signing, exchange, storage encryption, replay cache, key rotation plan, secret storage backend, and OS-protected secret wrapping are ready. It never displays private keys, relay tokens, shared secrets, plaintext payloads, or decrypted payloads.

## Relay Client Credential Storage

Runtime relay clients may still use `CONU_RELAY_TOKEN`, which takes precedence for scripts and CI. For local installs, users can store a scoped relay client token without putting it in shell history:

```bash
cat ./node.token | conu relay credential set --stdin
conu relay credential status
conu relay credential clear
```

Self-hosted relay operators can generate that token with `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>`. The raw token is written only to the chosen token file, while the manifest receives only hashed metadata with `token_displayed = false`. Use `--replace` to rotate an existing node credential and `conu-relay --revoke-credential <node-id> --credentials-file <path>` to revoke it without printing token material. `conu-relay --hash-token` remains available for already-created tokens.

The credential file is `security/relay-credential.key`. On Windows it stores `token_dpapi_hex` with current-user DPAPI wrapping. On macOS/Linux native backends it stores only `token_os_secret_ref`, `token_plaintext_len`, and metadata while the token bytes live in the OS user secret store. On non-Windows fallback it stores `token_wrapped_hex` when `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` is configured, otherwise it stores an owner-only local secret file. CLI and MCP status surfaces report only configured/backend/protection booleans and never print the token or protected blob.

## SDK And MCP Receive Boundary

Phase 12 adds agent-facing receive APIs without changing CLI privacy:

- `conu_sdk::ConuClient::receive_message_bytes(agent_id, envelope_id)` returns bytes only after the envelope is found in that local agent inbox.
- `conu-mcp` returns message metadata by default and only returns `payloadHex` when `conu_receive_message` is called with `includePayload: true`.
- `conu-mcp` stdout is reserved for valid MCP JSON-RPC messages; send/list/status/stream tool responses do not echo payload text.
- The TypeScript/JavaScript wrapper passes payload bytes through stdin for send, stream, room, and relay credential helpers, returns CLI metadata/JSON for normal list/status surfaces, and exposes raw inbox bytes only through explicit addressed-agent receive helpers.

## Production Gaps

Phase 11 hardens the current local product surface, but these items still need dedicated future work:

- Secure Enclave, HSM, or managed key administration beyond the current Windows DPAPI, macOS Keychain, Linux Secret Service, and user-managed wrap-key backends.
- Hosted account auth, managed online relay credential issuance APIs beyond the offline issuance helper, distributed hosted relay session state, distributed hosted dashboards/accounting, and hosted relay mailbox retention policy.
- SDK/MCP permission hardening for multi-tenant or hosted deployments.
- Hosted relay credential lifecycle, hosted retention/accounting policy, and managed key administration beyond the current local secret storage backends, durable ciphertext relay mailbox files, and metadata-only relay accounting counters.
- CI on Windows, macOS, and Linux with security/privacy regression scans.

## Implementation References Checked

- `chacha20poly1305` 0.10.1 docs for XChaCha20Poly1305 AEAD and 24-byte nonce usage.
- `ed25519-dalek` 2.2.0 docs for Ed25519 signing, verification, and `rand_core` key generation.
- `x25519-dalek` 2.0.1 docs for X25519 static key agreement.
- `sha2` 0.10.9 docs for SHA-256 hashing.
- `keyring` 3.6.3 docs for the macOS Keychain-backed secret API.
- `secret-tool`/Secret Service behavior is covered by `docs/native-secret-storage.md` smoke commands.
