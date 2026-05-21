# conU Packaging

These files package the current conU app for local developer and early-user installs.

Phase 15 makes installation, startup, service registration, and release validation repeatable. It does not claim the unfinished public internet data plane is complete.

## Release Artifacts

Build a release directory from the repository root:

Windows:

```powershell
.\scripts\build-release.ps1
# If MSVC Build Tools are not installed:
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

macOS/Linux:

```sh
./scripts/build-release.sh
```

The artifact contains:

```txt
bin/conu
bin/conud
bin/conu-relay
bin/conu-mcp
docs/
packaging/
manifest.toml
```

`manifest.toml` records `payload_contents_included = false`; release archives must not contain local conU state, private keys, logs, inboxes, or message payload files.

Release archives intended for npm installation should be named by platform:

```txt
conu-<version>-windows-x64.zip
conu-<version>-linux-x64.tar.gz
conu-<version>-linux-arm64.tar.gz
conu-<version>-macos-x64.zip
conu-<version>-macos-arm64.zip
```

Each archive should have a sibling `.sha256` file. The build scripts create checksum files automatically. Tagged release builds require maintainer signing secrets: Windows binaries are Authenticode-signed before packaging, and macOS binaries are Developer ID-signed and submitted to Apple notarization in ZIP archives. Linux archives currently use SHA-256 files plus GitHub artifact attestations until distro/package-manager signing is introduced.

Validate generated archives before upload:

```sh
python scripts/verify-release-artifacts.py dist
```

The release workflow runs the same verifier before publishing artifacts. It
checks checksums, required binaries, `manifest.toml`, required install/service
templates, and common forbidden local-state paths so developer `CONU_HOME`,
logs, private keys, inboxes, route registries, package `node_modules`, and
vendored npm binaries are not shipped. Tagged release builds also create
GitHub artifact attestations for each platform archive and checksum file.
See `docs/platform-code-signing.md` for signing secrets and verification
commands.

Verify a downloaded archive's provenance when `gh` is available:

```sh
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

## npm Launcher Package

The `npm/conu-cli` package is the intended one-command install wrapper:

```sh
npm install -g @conu/cli
```

It downloads the native release archive from GitHub Releases, verifies the checksum, and exposes `conu`, `conud`, `conu-relay`, and `conu-mcp`.

Local package test:

```sh
CONU_NPM_BINARY_DIR=/absolute/path/to/bin npm install -g ./packaging/npm/conu-cli
```

See `docs/distribution-and-hosting.md` for the publish flow. Tagged releases
publish GitHub Release assets automatically; npm publication is wired through
the release workflow when the repository `NPM_TOKEN` secret is configured.

## Relay Docker Template

Build and run the current relay:

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
  -e CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting \
  -e CONU_RELAY_ABUSE_DIR=/var/lib/conu-relay/abuse \
  conu-relay
```

The current client accepts `ws://` and certificate-valid `wss://` relay endpoints, and the relay has offline scoped credential issuance with manifest upsert/rotate/revoke helpers, account-scoped online issue/rotate/revoke/audit/dashboard snapshots, scoped hosted admin token manifests, admin-gated online tenant lifecycle for one configured relay registry, local/admin-gated hosted account suspension, read-only admin mailbox retention audits, admin-gated mailbox retention purge, live-reloaded scoped credentials, hashed credential manifests with revocation/expiry metadata, configurable connection/frame-rate caps, idle/TTL session policy, same-node session resume with optional metadata-only file-backed session records, metadata-only per-node accounting with optional sent quotas, metadata-only relay abuse counters, local/admin-gated abuse threshold reports with reusable `--thresholds-file` policy files and optional fail-on-threshold exit status, payload-safe local and admin-gated online durable mailbox retention audits with reusable `--retention-policy-file` policy files, confirm-gated local/admin and relay-local scheduled durable mailbox purge, bounded offline mailbox delivery with optional durable ciphertext files for peer-encrypted messages, stream chunks, room events, and signed-card control envelopes, plus a guard that rejects `local-dev-token` on non-loopback binds. Room topic policy remains local metadata on each runtime. The Docker relay itself still speaks plain WebSocket, so public `wss://` requires TLS termination in front of this container. Do not market this template as a managed public relay until distributed hosted monitoring/accounting/abuse workflows beyond single-relay snapshots and threshold reports, distributed multi-instance session migration, distributed hosted mailbox retention orchestration beyond single-relay purge, distributed hosted tenant lifecycle/workflow automation beyond the single-relay account-suspension/scoped admin tenant commands, and hosted multi-tenant permission administration are implemented.

## Windows Current-User Install

From an unpacked artifact:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin
```

This copies binaries to:

```txt
%LOCALAPPDATA%\Programs\conU\bin
```

Add `-InstallService` from an elevated PowerShell session to create a Windows service named `conud`:

```powershell
.\packaging\windows\install.ps1 -SourceBin .\bin -InstallService
```

Uninstall:

```powershell
.\packaging\windows\uninstall.ps1 -RemoveService
```

## Linux systemd

Install binaries into `/usr/local/bin`, then copy `linux/conud.service` to `/etc/systemd/system/conud.service` and edit the `User`, `Group`, and `Environment=CONU_HOME=...` lines.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now conud
systemctl status conud
```

## macOS launchd

Install binaries into `/usr/local/bin`, then edit `macos/com.conu.conud.plist` and replace `/Users/YOU` with the target user's absolute home path before copying it to `~/Library/LaunchAgents/`.

```sh
launchctl load ~/Library/LaunchAgents/com.conu.conud.plist
launchctl start com.conu.conud
```

## Verification

After install:

```sh
conu init
conu security audit
conu doctor
conu start
conu status
```

`conu doctor` should report `ready_for_local_use` once local state, security controls, companion binaries, and payload-safe logs are in place.
