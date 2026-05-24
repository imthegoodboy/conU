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

Each archive should have a sibling `.sha256` file. The build scripts create checksum files automatically. Tagged release builds require maintainer signing secrets, `CONU_LINUX_GPG_KEY_FINGERPRINT`, and `NPM_TOKEN`: Windows binaries are Authenticode-signed before packaging, macOS binaries are Developer ID-signed and submitted to Apple notarization in ZIP archives, the tag preflight imports the Linux GPG key, checks the expected full fingerprint, probe-signs a temporary file, verifies no GitHub Release already exists for the tag, and verifies live GitHub Pages repository metadata when the default hosted Linux repository URL is used, generated Homebrew/Scoop/winget/Chocolatey/Debian/RPM package-manager files plus APT/RPM repository metadata are produced from verified release checksums, the imported Linux GPG key is checked again against the expected full fingerprint during publication, generated RPM package payloads are signed before RPM repository metadata is generated, Linux archives plus generated Debian/RPM packages and APT/RPM metadata ZIPs receive detached `.asc` signatures, `conu-linux-gpg-key.asc` is exported with a strict `.sha256` sidecar for signature verification, a signed hosted Linux repository ZIP is generated from those signed assets, a signed hosted Linux repository site ZIP is generated from that bundle plus its sidecars for static HTTPS deployment, signed release update-policy metadata is generated from the final public asset set with auto-apply disabled, the site ZIP is verified and extracted for GitHub Pages deployment when the default repository URL is used, the release publish job refuses to overwrite an existing GitHub Release, npm publication first verifies the public GitHub Release has all expected assets and no duplicate or forbidden state/secret-looking asset names, and npm packages are published with provenance after GitHub Release assets exist. Linux archives use SHA-256 files plus GitHub artifact attestations plus detached signatures; generated Debian packages use SHA-256 sidecars plus detached signatures; generated RPM packages use native RPM signatures plus refreshed SHA-256 sidecars plus detached signatures; generated APT/RPM metadata ZIPs include native repository signatures, refreshed sidecars, and detached signatures; generated hosted Linux repository ZIPs include signed package/repository trees, refreshed sidecars, and detached signatures; generated hosted Linux repository site ZIPs include public endpoint metadata, install snippets, public repository trees, checked `cache-policy.json` and `_headers` files, and detached signatures; generated update-policy JSON includes public release URLs, strict SHA-256 values, signature URLs, npm package versions, a checksum sidecar, and a detached signature.

Before tagging, run:

```sh
python scripts/verify-release-versions.py
```

The CI and release package jobs run the same check before package validation. Branch and PR runs verify that every Cargo/npm manifest uses the same version; `v*` tag runs also require the tag version to match.
The same package jobs run `python scripts/check-release-artifact-verifier.py` so checksum format, duplicate path, and forbidden state-path regressions fail before platform artifacts are generated.
They also run `python scripts/check-release-artifact-smoke-preflight.py` so release artifact smoke fixtures fail on missing binary directories, missing binaries, or non-file binary paths before execution.
They also run `python scripts/check-package-manager-manifests.py` so generated Homebrew/Scoop/winget/Chocolatey/Debian/RPM package-manager and APT/RPM repository metadata regressions fail before package publication paths are used. CI and release package jobs install RPM tooling plus `createrepo-c` so the generated `conu.spec`, optional generated `.rpm` release assets, and RPM repository metadata are checked when package gates run on Ubuntu.
They also run `python scripts/check-linux-signing-secrets-preflight-regression.py` so missing, malformed, mismatched, or unusable Linux GPG signing secrets fail before tagged package publication paths are used.
They also run `python scripts/check-rpm-package-signing.py` so native RPM package signing, fingerprint mismatch handling, sidecar refresh, and signed-package RPM metadata regressions fail before tagged package publication paths are used.
They also run `python scripts/check-linux-release-signing.py` so fingerprint-pinned Linux detached-signing regressions fail before tagged package publication paths are used. CI and release package jobs install `gnupg` for that check.
They also run `python scripts/check-linux-repository-signing.py` so fingerprint-pinned native APT/RPM repository metadata signing, verification, and sidecar-refresh regressions fail before tagged package publication paths are used.
They also run `python scripts/check-hosted-linux-repositories.py` so static hosted APT/YUM bundle regressions fail before tagged package publication paths are used.
They also run `python scripts/check-hosted-linux-repository-site.py`, `python scripts/check-hosted-linux-repository-pages.py`, and `python scripts/check-github-pages-readiness-regression.py` so static hosted repository site, GitHub Pages extraction, and GitHub Pages metadata readiness regressions fail before tagged package publication paths are used.
They also run `python scripts/check-release-update-policy.py` so release update-policy metadata regressions fail before tagged package publication paths are used.
They also run `python scripts/check-github-release-clobber-preflight-regression.py` so existing-release clobber regressions fail before tagged publication paths are used.
They also run `python scripts/check-github-release-assets-published-regression.py` so GitHub Release asset publication metadata regressions fail before tagged npm publication paths are used.
They also run `python scripts/check-linux-gpg-public-key-export.py` so fingerprint-pinned Linux public-key export and verification regressions fail before tagged package publication paths are used.
They also run `python scripts/check-npm-launcher-local-smoke-preflight.py` so npm launcher local-smoke fixtures fail on missing binary directories, missing binaries, or non-file binary paths before an install attempt.
They also run `python scripts/check-npm-publish-preflight.py` and `python scripts/check-npm-publish-preflight-regression.py` so npm publication metadata and fail-closed duplicate-version/token/registry behavior are checked before tagged publish jobs.
Tagged npm publish jobs additionally run `python scripts/check-github-release-assets-published.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"` before npm registry access, requiring the uploaded public GitHub Release to contain the expected archives, checksums, signatures, package-manager files, public-key asset, hosted repository bundle, hosted repository site artifact, and signed update-policy metadata.

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
archive and checksum file, plus detached `.asc` signatures for Linux archives
and generated Linux package/metadata assets.
See `docs/platform-code-signing.md` for signing secrets and verification
commands.

## Package-Manager Manifests

Generate Homebrew, Scoop, winget, Chocolatey, Debian, RPM, and APT/RPM
repository metadata files from the platform archives and strict checksum files:

```sh
python scripts/generate-package-manager-manifests.py dist --output-dir dist --version 0.1.0 --tag v0.1.0
python scripts/generate-package-manager-manifests.py dist --output-dir dist --version 0.1.0 --tag v0.1.0 --build-rpm-packages
python scripts/generate-package-manager-manifests.py dist --output-dir dist --version 0.1.0 --tag v0.1.0 --build-rpm-packages --build-apt-repository-metadata
python scripts/sign-rpm-packages.py dist
python scripts/generate-package-manager-manifests.py dist --output-dir dist --version 0.1.0 --tag v0.1.0 --build-rpm-repository-metadata
python scripts/sign-linux-repository-metadata.py dist
python scripts/sign-linux-release-assets.py dist
python scripts/generate-hosted-linux-repositories.py dist --output-dir dist --version 0.1.0
python scripts/sign-linux-release-assets.py dist --only-hosted-repository-bundles
python scripts/generate-hosted-linux-repository-site.py dist --output-dir dist --version 0.1.0 --base-url https://packages.example.com/conu
python scripts/sign-linux-release-assets.py dist --only-hosted-repository-sites
python scripts/generate-release-update-policy.py dist --output-dir dist --version 0.1.0 --tag v0.1.0 --repo imthegoodboy/conU
python scripts/sign-linux-release-assets.py dist --only-update-policies
python scripts/prepare-hosted-linux-repository-pages.py dist --output-dir dist/hosted-linux-repository-site
python scripts/check-github-pages-readiness.py --repo imthegoodboy/conU
python scripts/check-package-manager-manifests.py
python scripts/check-rpm-package-signing.py
python scripts/check-linux-release-signing.py
python scripts/check-linux-repository-signing.py
python scripts/check-hosted-linux-repositories.py
python scripts/check-hosted-linux-repository-site.py
python scripts/check-hosted-linux-repository-pages.py
python scripts/check-github-release-clobber-preflight.py --repo imthegoodboy/conU --tag v0.1.0
python scripts/check-release-update-policy.py
python scripts/check-github-release-assets-published.py --repo imthegoodboy/conU --tag v0.1.0
python scripts/check-linux-gpg-public-key-export.py
```

The generator writes package-native `conu.rb`, `conu.json`,
`imthegoodboy.conU.yaml`, deterministic `conu.<version>.nupkg`, deterministic
`conu_<version>_amd64.deb` and `conu_<version>_arm64.deb` packages with strict
`.sha256` sidecars, optional `conu-<debian-version>-apt-repository-metadata.zip`
metadata with a strict `.sha256` sidecar, and `conu.spec` using public GitHub
Release URLs, static SHA-256 hashes, install helper code, binary mappings, and
verified Linux release binaries only where the package format requires binaries. When
`--build-rpm-packages` is set, it also builds unsigned `x86_64` and `aarch64`
`.rpm` packages with strict `.rpm.sha256` sidecars. When
`--build-apt-repository-metadata` is set, it also builds deterministic
`Packages`, `Packages.gz`, and `Release` metadata for the generated `.deb`
assets. When `--build-rpm-repository-metadata` is set, it also builds a
`createrepo_c` `repodata/*` bundle for the generated `.rpm` assets without
embedding those RPM packages. Tagged release publication builds RPM packages,
verifies the imported Linux signing-key fingerprint, signs those native RPM
package payloads, refreshes their `.rpm.sha256` sidecars, generates RPM
repository metadata from the signed packages, adds
native APT `InRelease`/`Release.gpg` and RPM `repodata/repomd.xml.asc`
signatures, refreshes the metadata ZIP sidecars, exports
`conu-linux-gpg-key.asc` without private-key material, signs generated Linux
package/metadata assets with detached `.asc` signatures, and uploads
those assets plus a signed `conu-<version>-hosted-linux-repositories.zip` static
APT/YUM hosting bundle and a signed
`conu-<version>-hosted-linux-repository-site.zip` static site artifact so
operators can publish generated repository trees, endpoint metadata, and
install snippets without rewriting metadata or guessing hashes. Tagged
publication then generates `conu-<version>-update-policy.json`, verifies the
referenced release assets and strict sidecars, records public asset URLs,
strict SHA-256 values, signature URLs, npm package versions, and manual
verification rules with auto-apply disabled, writes a strict `.sha256` sidecar,
and detached-signs that policy with `--only-update-policies`.
The regression check validates generated Debian packages with `dpkg-deb` and
builds the generated RPM spec with `rpmbuild` when those native tools are
available, and it opens the APT and RPM metadata bundles to verify package
hashes, compressed metadata, and repository hashes. The RPM package signing
regression verifies native RPM signatures with an ephemeral GPG key and a
throwaway RPM database when RPM signing tools are available. The hosted
repository regression validates the flat APT tree, RPM `repodata/` tree,
embedded package signatures, public key copies, sidecars, deterministic ZIP
layout, and fail-closed handling for missing signatures or unsafe metadata
paths. The hosted repository site regression validates the public site layout,
HTTPS base URL requirement, install snippets, `repository.json`,
`cache-policy.json`, `_headers`, deterministic ZIP metadata, download copies,
and fail-closed handling for missing signatures or unsafe bundle members. The
Pages regression validates strict site ZIP sidecars, detached signature
presence, safe extraction to an empty deployment directory, non-HTTPS metadata
rejection, cache policy rejection, forbidden local-state/secret marker
rejection, and separate repository Pages metadata readiness before GitHub Pages
upload. Custom DNS/TLS endpoint activation, package-manager submission, and
operator proof that the generated cache policy is applied remain future work.
See `packaging/package-managers/README.md`.

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
release. Tagged npm publication also runs the npm publish preflight with a
registry availability check before either package is published, so existing
`@conu/cli` or `@conu/sdk` versions fail before a partial publish starts.

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
