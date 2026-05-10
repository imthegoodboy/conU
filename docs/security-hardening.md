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
security/storage.key            XChaCha20Poly1305 storage key
security/replay.toml            replay/idempotency cache
security/key-rotation.md        local key rotation plan
```

Private keys are never printed by CLI output. On Unix targets, key files are created with owner-only permissions. On Windows, conU relies on the user profile ACL today; OS keychain or DPAPI-backed storage is still required before public release.

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

### Signed Agent Cards

Local agent registry records now include Ed25519 signature metadata:

```txt
signature_algorithm = "Ed25519"
signature_key_id = "<metadata id>"
signing_public_key_hex = "<public key>"
signature_hex = "<signature>"
```

The signature covers stable agent-card identity fields and capabilities. Presence and last-seen timestamps are not part of the signature because they are live state, not identity.

### Replay Protection

Message request ids and delivered envelope ids are recorded in `security/replay.toml`. A repeated id is rejected before payload decryption or delivery. This gives conU receiver-side dedupe groundwork without pretending the network can provide magical exactly-once delivery.

### Peer Key Agreement Helpers

The security module exposes X25519 key agreement helpers and peer payload encryption helpers for the next relay-backed delivery phase. They derive a symmetric key from local exchange material, peer public material, ordered public keys, and context bytes. The derived shared secret is not returned or printed.

## CLI Audit

Run:

```bash
conu security audit
conu security audit --json
```

The audit reports whether local signing, exchange, storage encryption, replay cache, and key rotation plan are ready. It never displays private keys, shared secrets, plaintext payloads, or decrypted payloads.

## Production Gaps

Phase 11 hardens the current local product surface, but these items still need dedicated future work:

- OS keychain, DPAPI, Secure Enclave, HSM, or user-managed secret backend for private key protection.
- Automated key rotation with multi-key read, re-encryption migration, and old-key retirement.
- Live relay-backed encrypted envelope routing using the peer key agreement helpers.
- Signed remote agent-card exchange over real sessions instead of derived metadata mirrors.
- Permission grants that bind trusted peers to specific local agent actions.
- Encrypted mailbox storage and retention policy.
- CI on Windows, macOS, and Linux with security/privacy regression scans.

## Implementation References Checked

- `chacha20poly1305` 0.10.1 docs for XChaCha20Poly1305 AEAD and 24-byte nonce usage.
- `ed25519-dalek` 2.2.0 docs for Ed25519 signing, verification, and `rand_core` key generation.
- `x25519-dalek` 2.0.1 docs for X25519 static key agreement.
- `sha2` 0.10.9 docs for SHA-256 hashing.
