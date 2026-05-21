# Native Secret Storage

conU stores local signing, exchange, storage, archived key, and relay client
credential secret bytes behind a common secret-field layer.

## Backend Selection

- Windows uses current-user DPAPI and records
  `secretStorageBackend = "windows-dpapi-user"`.
- macOS uses the user Keychain through the native keyring backend and records
  `secretStorageBackend = "macos-keychain-user"`.
- Linux uses Secret Service through `secret-tool` when a user session is
  available and records
  `secretStorageBackend = "linux-secret-service-user"`.
- Non-Windows systems without an available native store can use
  `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE`, which records
  `secretStorageBackend = "user-managed-wrap-key-v1"`.
- If no native store or configured wrap key is available, conU falls back to
  owner-only local files with
  `secretStorageBackend = "filesystem-permissions"`.

Set `CONU_DISABLE_OS_SECRET_BACKEND=1` to force the non-Windows fallback path
for controlled tests or constrained deployments.

## Migration

`conu init`, `conu security audit`, and relay credential read/status paths
migrate older plaintext secret fields to the selected protected backend when
the current backend can read the source secret. A native macOS or Linux backend
takes precedence over the user-managed wrap-key backend when it is available.
Migrating an existing `user-managed-wrap-key-v1` file to native storage still
requires the configured wrap key so conU can decrypt the old field first.

Native backend files store only metadata such as `*_os_secret_ref`,
`*_plaintext_len`, and `contents_displayed = false`. They do not store key
bytes, relay tokens, wrapped blobs, plaintext payloads, or decrypted payloads.

## Platform Smoke

macOS:

```sh
CONU_HOME="$(mktemp -d)"
export CONU_HOME
conu init
conu security audit --json
CONU_TEST_RELAY_TOKEN="replace-with-scoped-token-at-least-24-chars"
printf '%s' "$CONU_TEST_RELAY_TOKEN" | conu relay credential set --stdin --json
unset CONU_TEST_RELAY_TOKEN
conu relay credential status --json
```

Expected audit/status metadata includes
`secretStorageBackend = "macos-keychain-user"`,
`secretsOsProtected = true`, and `contentsDisplayed = false`.

Linux with Secret Service:

```sh
command -v secret-tool
CONU_HOME="$(mktemp -d)"
export CONU_HOME
conu init
conu security audit --json
CONU_TEST_RELAY_TOKEN="replace-with-scoped-token-at-least-24-chars"
printf '%s' "$CONU_TEST_RELAY_TOKEN" | conu relay credential set --stdin --json
unset CONU_TEST_RELAY_TOKEN
conu relay credential status --json
```

Expected audit/status metadata includes
`secretStorageBackend = "linux-secret-service-user"` when `secret-tool` and a
user Secret Service session are available. Headless Linux systems without a
Secret Service session should use the user-managed wrap-key fallback or accept
the owner-only file fallback.

None of these commands should print private keys, relay tokens, protected
blobs, plaintext payloads, or decrypted payloads.
