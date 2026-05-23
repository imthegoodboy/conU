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

Each archive should have a sibling `.sha256` file. The build scripts create checksum files automatically. Tagged release builds require maintainer signing secrets and `NPM_TOKEN`: Windows binaries are Authenticode-signed before packaging, macOS binaries are Developer ID-signed and submitted to Apple notarization in ZIP archives, and npm packages are published with provenance after GitHub Release assets exist. Linux archives currently use SHA-256 files plus GitHub artifact attestations until distro/package-manager signing is introduced.

Before tagging, run:

```sh
python scripts/verify-release-versions.py
```

The CI and release package jobs run the same check before package validation. Branch and PR runs verify that every Cargo/npm manifest uses the same version; `v*` tag runs also require the tag version to match.
The same package jobs run `python scripts/check-release-artifact-verifier.py` so checksum format, duplicate path, and forbidden state-path regressions fail before platform artifacts are generated.
They also run `python scripts/check-release-artifact-smoke-preflight.py` so release artifact smoke fixtures fail on missing binary directories, missing binaries, or non-file binary paths before execution.
They also run `python scripts/check-npm-launcher-local-smoke-preflight.py` so npm launcher local-smoke fixtures fail on missing binary directories, missing binaries, or non-file binary paths before an install attempt.

Validate generated archives before upload:

```sh
python scripts/verify-release-artifacts.py dist
python scripts/smoke-release-artifacts.py dist
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

The release workflow runs the same verifier and smoke tests before publishing
artifacts. The verifier streams archive inspection, requires strict checksum
files that name the matching archive, bounds archive/member/manifest sizes and
member counts, checks required binaries, `manifest.toml`, required
install/service templates, and common forbidden local-state paths so
developer `CONU_HOME`, logs, private keys, inboxes, route registries, package
`node_modules`, and vendored npm binaries are not shipped. The archive smoke
extracts the current-platform archive into a temporary directory, requires
every expected extracted binary to be a regular non-symlink file, runs the
packaged `conu init`, `conu security audit --json`, and `conu doctor --json`,
and requires `ready_for_local_use` without displaying payload contents. The npm
launcher smoke installs `packaging/npm/conu-cli` into a temporary npm prefix
with `CONU_NPM_BINARY_DIR` pointed at the archive binaries, requires every
expected binary to be a regular file before copying into `vendor/`, verifies the
copied vendor binaries and npm bin shims, then runs the installed launcher
through the same payload-safe readiness checks. The npm download smoke serves `dist/` from a
temporary localhost HTTP server, installs the package with `CONU_NPM_DIST_BASE`,
and exercises the default HTTPS-or-loopback download policy, bounded
timeout/size behavior, strict `.sha256` archive-name verification with streamed
archive hashing, archive-member count/duplicate/state-path preflight, exact extracted release-root
binary selection, bounded extracted-tree scanning, extraction, and launcher readiness path without
publishing assets.
When a local `dist/` also contains a `conu-<version>-host` archive, the download
smoke treats the platform-named npm asset as canonical and skips the host alias.
Tagged release builds also create GitHub artifact attestations for each platform
archive and checksum file.
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

It downloads the native release archive from GitHub Releases with bounded request time and response sizes, requires a strict checksum line naming that archive, hashes the archive in chunks, bounds extracted-tree entry/depth scanning, requires extracted binaries to come from the expected release `bin/` directory, and exposes `conu`, `conud`, `conu-relay`, and `conu-mcp`. The local `CONU_NPM_BINARY_DIR` override must point at an existing directory containing regular files for every expected binary before the installer copies anything into `vendor/`.

Local package test:

```sh
CONU_NPM_BINARY_DIR=/absolute/path/to/bin npm install -g ./packaging/npm/conu-cli
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

See `docs/distribution-and-hosting.md` for the publish flow. Tagged releases
publish GitHub Release assets automatically and require the repository
`NPM_TOKEN` secret so npm publication cannot silently skip after a GitHub-only
release.

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

The current client accepts `ws://` and certificate-valid `wss://` relay endpoints, and the relay has offline scoped credential issuance with manifest upsert/rotate/revoke helpers, account-scoped online issue/rotate/revoke/audit/dashboard snapshots, scoped hosted admin token manifests with payload-safe local `--admin-token-audit`, payload-safe local `--hosted-readiness` startup/release preflights with reusable retention/threshold policy files, admin-gated online tenant lifecycle for one configured relay registry, local/admin-gated hosted account suspension, payload-safe local/admin-gated session-state audits, read-only admin mailbox retention audits, admin-gated mailbox retention purge, live-reloaded scoped credentials, hashed credential manifests with revocation/expiry metadata, configurable connection/frame-rate caps, idle/TTL session policy, same-node session resume with optional metadata-only file-backed session records, metadata-only per-node accounting with optional sent quotas, metadata-only relay abuse counters, local/admin-gated abuse threshold reports with reusable `--thresholds-file` policy files and optional fail-on-threshold exit status, payload-safe local and admin-gated online durable mailbox retention audits with reusable `--retention-policy-file` policy files, confirm-gated local/admin and relay-local scheduled durable mailbox purge, bounded offline mailbox delivery with optional durable ciphertext files for peer-encrypted messages, stream chunks, room events, and signed-card control envelopes, plus a guard that rejects `local-dev-token` on non-loopback binds. Use `conu-relay --session-audit --session-state-dir <path>` or `conu-relay --admin-session-audit --relay <endpoint> --admin-token-stdin` for session-state counts and timestamp bounds without relay session ids; use `conu-relay --hosted-readiness ... [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] --json --fail-on-warning` before startup or release smoke to combine local store, bind, retention, and threshold checks without printing secrets. Room topic policy remains local metadata on each runtime. The Docker relay itself still speaks plain WebSocket, so public `wss://` requires TLS termination in front of this container. Do not market this template as a managed public relay until distributed hosted monitoring/accounting/abuse workflows beyond single-relay snapshots, threshold reports, and readiness preflights, distributed multi-instance session migration, distributed hosted mailbox retention orchestration beyond single-relay purge, distributed hosted tenant lifecycle/workflow automation beyond the single-relay account-suspension/scoped admin tenant commands, and hosted multi-tenant permission administration are implemented.

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
