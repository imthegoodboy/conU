# conU Distribution And Hosting

This is the practical path for getting conU onto a user's machine and making two agents talk through a reachable relay.

## Best Distribution Shape

conU should stay a native Rust product. The best public install path is:

```txt
GitHub Release native binaries
  -> npm launcher package for one-command install
  -> optional OS package managers after signing
```

Why this shape:

- Rust binaries keep the CLI, daemon, relay, protocol, crypto, and MCP adapter fast and self-contained.
- GitHub Releases are the source of truth for platform archives and checksums.
- npm gives agents and developers a familiar install command without making conU a JavaScript runtime.
- Homebrew, Scoop, winget, Chocolatey, Debian, RPM, APT/RPM repository metadata, a hosted Linux repository bundle, a hosted Linux repository site artifact, and signed release update-policy metadata are generated from verified release assets and checksums on tagged releases. CI and release package checks also verify the generated APT metadata, build the generated RPM spec, optional RPM release assets, RPM repository metadata, hosted repository bundle, hosted repository site, release update policy, release update download/apply dry-run gate, GitHub Pages extraction prep, custom S3-compatible repository publication, and hosted repository endpoint cache-header regression with native `rpmbuild`/`createrepo_c` when RPM tools are available, and exercise Linux signing-secret preflight, RPM package signing, detached Linux signing, native repository-metadata signing, hosted bundle/site layout checks, live endpoint cache-policy checks, update-policy checks, Pages deployment-safety checks, GitHub Pages setting readiness checks, GitHub Release clobber checks, GitHub Release asset publication checks, and Linux public-key export with ephemeral fingerprint-pinned GPG keys. Tagged release preflight imports the Linux signing key, verifies `CONU_LINUX_GPG_KEY_ID` resolves to `CONU_LINUX_GPG_KEY_FINGERPRINT`, probe-signs a temporary file, verifies no GitHub Release already exists for the tag, verifies default Pages readiness when no custom base URL is set, and requires custom S3 publication settings when `CONU_LINUX_REPOSITORY_BASE_URL` is set. Tagged release publication verifies the imported Linux signing key again, exports `conu-linux-gpg-key.asc` plus a strict `.sha256` sidecar, signs generated RPM packages before generating RPM repository metadata, signs Linux archives and generated Debian/RPM packages with detached `.asc` signatures, adds APT `InRelease`/`Release.gpg` and RPM `repodata/repomd.xml.asc` signatures to repository metadata ZIPs, refreshes their `.sha256` sidecars, signs those final ZIPs with detached `.asc` signatures, builds and signs `conu-<version>-hosted-linux-repositories.zip`, builds and signs `conu-<version>-hosted-linux-repository-site.zip` with static endpoint metadata, install snippets, `cache-policy.json`, and `_headers` Cache-Control rules, then generates and signs `conu-<version>-update-policy.json` with public release URLs, strict SHA-256 values, signature URLs, npm package versions, and auto-apply disabled. Before creating the GitHub Release, the publish job re-checks the tag and refuses to overwrite existing release assets. After upload, the workflow imports the published Linux public key, verifies its fingerprint against `CONU_LINUX_GPG_KEY_FINGERPRINT`, and runs `conu update check --policy-url --gpg-verify`, `conu update download --policy-url --gpg-verify --target linux-x64`, and `conu update apply --policy-url --gpg-verify --target linux-x64 --dry-run` against the public release before npm publication. Before npm publication, the workflow verifies the public GitHub Release has every required archive, checksum, signature, package-manager, public-key, hosted repository bundle, hosted repository site, and update-policy asset, and waits for the Linux repository publication gate, so npm is not touched when release publication or repository deployment is incomplete. When `CONU_LINUX_REPOSITORY_BASE_URL` is not set, the tagged workflow verifies and extracts that signed site ZIP into a static directory and deploys it with GitHub Pages Actions. When `CONU_LINUX_REPOSITORY_BASE_URL` is set, the tagged workflow publishes that verified site directory to the configured S3-compatible bucket/prefix with per-file `Cache-Control` from `cache-policy.json`, then runs endpoint readiness against the live custom HTTPS URL before npm publication.

The target public command is:

```sh
npm install -g @conu/cli
conu init
conu doctor
conu start
```

The npm package under `packaging/npm/conu-cli` is a launcher. It downloads the native release archive for the user's platform, verifies the `.sha256` file, and exposes:

```txt
conu
conud
conu-relay
conu-mcp
```

## Release Asset Names

The npm installer expects these assets for version `0.1.0`:

```txt
conu-0.1.0-windows-x64.zip
conu-0.1.0-linux-x64.tar.gz
conu-0.1.0-linux-arm64.tar.gz
conu-0.1.0-macos-x64.zip
conu-0.1.0-macos-arm64.zip
```

Each archive must have:

```txt
<asset>.sha256
```

The release workflow builds platform-named artifacts and uploads matching checksum files. Tagged release builds run a fail-closed preflight before package checks and platform builds; that preflight requires maintainer-owned signing secrets for Windows Authenticode, macOS Developer ID/notarization, Linux GPG signatures including the expected full key fingerprint, the repository `NPM_TOKEN` used for npm provenance publication, and default GitHub Pages metadata readiness when `CONU_LINUX_REPOSITORY_BASE_URL` is unset. It also imports the configured Linux signing key, verifies the key id resolves to the expected fingerprint, and probe-signs a temporary file before builds. Linux archives use SHA-256 files plus GitHub artifact attestations plus detached `.asc` signatures, generated Debian packages use SHA-256 sidecars plus detached `.asc` signatures, generated RPM packages use native RPM signatures plus refreshed SHA-256 sidecars plus detached `.asc` signatures, generated APT/RPM metadata ZIPs include native repository signatures plus refreshed SHA-256 sidecars and detached `.asc` signatures, and `conu-linux-gpg-key.asc` plus its `.sha256` sidecar is attached so users can compare the public key fingerprint with the published maintainer fingerprint before verifying Linux signatures. Tagged GitHub Release publication also generates package-native `conu.rb`, `conu.json`, `imthegoodboy.conU.yaml`, `conu.<version>.nupkg`, `conu_<version>_amd64.deb`, `conu_<version>_arm64.deb`, `conu-<debian-version>-apt-repository-metadata.zip`, `conu.spec`, `conu-<rpm-version>-1.x86_64.rpm`, `conu-<rpm-version>-1.aarch64.rpm`, `conu-<rpm-version>-rpm-repository-metadata.zip`, `conu-<version>-hosted-linux-repositories.zip`, `conu-<version>-hosted-linux-repository-site.zip`, and `conu-<version>-update-policy.json` files from the verified asset checksums so package-manager metadata, Linux package files, static hosted repository trees, update metadata, and operator install snippets are not hand-edited, then verifies the imported Linux signing key fingerprint again, exports the Linux public key, and signs RPM packages, repository metadata, Linux archives, Linux package/metadata assets, the hosted repository bundle, the hosted repository site artifact, and the update-policy JSON; package gates verify APT/RPM metadata, run native `rpmbuild` validation, and run Linux-signing-secret-preflight, RPM-package-signing, Linux detached-signing, repository-signing, hosted-repository, hosted-repository-site, release-update-policy, GitHub Pages readiness, and public-key-export regressions before those tag paths are used.

## Publishing Flow

1. Update all Cargo package versions, `packaging/npm/conu-cli/package.json`, and `sdk/typescript/package.json` to the same version.
2. Run `python scripts/verify-release-versions.py` locally; on `v*` tag builds the release workflow runs the same verifier and fails before packaging if the tag version does not match.
3. Run the release validation checklist.
4. Tag the release, for example `v0.1.0`.
5. Configure the repository signing secrets, `CONU_LINUX_GPG_KEY_FINGERPRINT`, and `NPM_TOKEN` before creating the tag; the tagged release workflow fails before package checks if any required release secret is missing, malformed, points at the wrong Linux key, or cannot sign with the configured passphrase.
6. Let the `Release Artifacts` GitHub Actions workflow build platform archives, sign Windows binaries, sign and notarize macOS ZIP archives, verify that archives exclude conU state/log/payload paths and include the required install/service templates with strict checksum parsing and bounded streaming archive inspection, smoke-test the unpacked archive, run the package-manager manifest regression, run the Linux signing-secret preflight regression, run the RPM-package-signing regression, run the Linux detached-signing regression, run the Linux repository-signing regression, run the hosted Linux repository bundle regression, run the hosted Linux repository site regression, run the hosted Linux repository Pages regression, run the hosted Linux repository endpoint regression, run the release update-policy regression, run the release update-download/apply dry-run gate regression, run the GitHub Pages readiness regression, run the GitHub Release clobber preflight regression, run the GitHub Release asset publication regression, run the Linux public-key-export regression, run the npm launcher local-smoke preflight regression, smoke-test the npm launcher local install path with an existing regular-file binary directory, and smoke-test the npm launcher download/checksum install path with HTTPS-or-loopback URL enforcement, bounded timeout/size behavior, strict checksum archive-name matching, streamed npm archive hashing, archive-member count/duplicate/state-path preflight, bounded extracted-tree scanning, and exact extracted release-root binary selection, generate GitHub artifact attestations for the archives and `.sha256` files, generate Homebrew, Scoop, winget, Chocolatey, Debian, RPM, and APT/RPM repository metadata from those strict checksums, build RPM release assets with `.rpm.sha256` sidecars, verify the imported Linux signing key fingerprint, sign those RPM package payloads and refresh their sidecars before RPM repository metadata is generated, export `conu-linux-gpg-key.asc` plus its `.sha256` sidecar, add native APT/RPM repository metadata signatures and refreshed metadata ZIP sidecars, create detached `.asc` signatures for Linux archives and Linux package/metadata assets, generate and detached-sign the hosted Linux repository bundle, generate and detached-sign the hosted Linux repository site artifact, generate `conu-<version>-update-policy.json` and detached-sign it, prepare a verified static Pages directory from the signed site artifact, refuse to continue if the GitHub Release already exists for the tag, upload the archives, `.sha256` files, `.asc` signatures, Linux GPG public-key asset, hosted repository bundle, hosted repository site artifact, release update-policy metadata, and generated package-manager files to a new GitHub Release, import the published Linux public key, verify its fingerprint, run public `conu update check`, `conu update download`, and `conu update apply --dry-run` with GPG verification against the uploaded release, deploy the verified static repository site to GitHub Pages when `CONU_LINUX_REPOSITORY_BASE_URL` is not set, run verified npm package content dry-runs that reject unexpected files, local state/build/payload paths, oversized files, and bundled dependencies, run the GitHub Release asset publication preflight against the public tag so missing uploaded assets fail before npm registry access, run the npm publish preflight so public package metadata is present and existing `@conu/cli`/`@conu/sdk` versions fail before either package is published, and publish `@conu/cli` plus `@conu/sdk` with npm provenance after GitHub Release assets are available. Set repository variable `CONU_LINUX_REPOSITORY_BASE_URL` when the static repository will be served from a custom HTTPS URL; otherwise leave it unset so tagged releases default the site metadata to the repository GitHub Pages URL, verify the live Pages setting, and deploy that verified site through GitHub Pages Actions. After a custom endpoint is published, run the endpoint readiness check against that URL before directing package-manager users to it.
For the supported custom S3-compatible repository publisher, set repository
variable `CONU_LINUX_REPOSITORY_BASE_URL` to the public HTTPS URL, set
`CONU_LINUX_REPOSITORY_S3_BUCKET`, optional
`CONU_LINUX_REPOSITORY_S3_PREFIX`, optional
`CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL`, optional
`CONU_LINUX_REPOSITORY_AWS_REGION`, and repository secrets
`CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID` plus
`CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY`. The tagged workflow uploads the
verified extracted site with per-file cache headers and fails before npm
publication if the live endpoint readiness check does not pass. DNS records,
TLS certificates, CDN behavior, and non-S3 hosts remain operator-owned.

7. Test from a clean shell:

```sh
npm install -g @conu/cli
conu doctor
conud --check
conu-relay --check
```

For local package testing without downloading from GitHub Releases:

```sh
CONU_NPM_BINARY_DIR=/absolute/path/to/bin npm install -g ./packaging/npm/conu-cli
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

For a local archive verification pass after running a build script:

```sh
python scripts/verify-release-artifacts.py dist
python scripts/smoke-release-artifacts.py dist
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

For a downloaded release archive, verify the GitHub artifact attestation when `gh` is available:

```sh
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

For platform signing verification commands and the required repository secrets,
see `docs/platform-code-signing.md`.

The verifier streams each archive check, requires a strict checksum line naming
the matching archive, bounds archive/member/manifest sizes plus member counts,
checks required binaries, `manifest.toml` payload flags, required install/service templates, and common forbidden
local-state paths such as `.conu`, `security/`, `messages/`, `runtime/`,
`logs/`, `routes/`, `node_modules/`, and vendored package binaries. The smoke
scripts then require the current-platform archive to expose every expected
binary as a regular non-symlink file before execution, prove the archive starts
from an unpacked install, and prove that the npm launcher package first requires `CONU_NPM_BINARY_DIR` to point
at an existing directory with regular files for every expected binary, can copy
those binaries into `vendor/`, create npm bin shims, download the archive through an HTTPS `CONU_NPM_DIST_BASE` or a
loopback HTTP smoke server with bounded request time and response sizes, require
a strict `.sha256` line naming the archive, stream the archive hash, reject excessive members, duplicate normalized paths, and forbidden state paths before extraction, extract it, bound extracted-tree entry/depth scanning, require either a rootless release layout or the expected `conu-<version>-<platform>/bin/` layout without duplicate binary names elsewhere, and report
`ready_for_local_use` without displaying payload contents.
Before npm publication, `scripts/check-npm-publish-preflight.py` validates
public publish metadata for both npm packages. Tagged publication runs the same
preflight with registry availability checks and a required token-env guard so an
already-published package version or missing npm token fails before any publish
command can create a partial release.
Tagged npm publication first runs
`scripts/check-github-release-assets-published.py --repo <owner/name> --tag v<version>`
against the public GitHub Release metadata, requiring every expected release
asset name, positive uploaded asset metadata, no duplicate asset names, and no
forbidden state/secret-looking asset names before npm registry access starts.

Before package-manager submission, generate manifests from the release assets
instead of editing hashes by hand:

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
conu update check --policy-file dist/conu-0.1.0-update-policy.json --gpg-verify
conu update check --policy-url https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json --gpg-verify
python scripts/prepare-hosted-linux-repository-pages.py dist --output-dir dist/hosted-linux-repository-site
python scripts/publish-hosted-linux-repository-s3.py dist/hosted-linux-repository-site --base-url https://packages.example.com/conu --bucket <bucket> --prefix <prefix> --dry-run
python scripts/check-github-pages-readiness.py --repo imthegoodboy/conU
python scripts/check-github-release-clobber-preflight.py --repo imthegoodboy/conU --tag v0.1.0
python scripts/check-rpm-package-signing.py
python scripts/check-hosted-linux-repositories.py
python scripts/check-hosted-linux-repository-site.py
python scripts/check-hosted-linux-repository-pages.py
python scripts/check-package-manager-manifests.py
```

The generator requires every supported platform archive plus a strict sibling
`.sha256` file naming the archive. It emits package-native `conu.rb`,
`conu.json`, `imthegoodboy.conU.yaml`, `conu.<version>.nupkg`,
`conu_<version>_amd64.deb`, `conu_<version>_arm64.deb`, `.deb.sha256`
sidecars, and `conu.spec` files with public GitHub Release URLs, static
SHA-256 hashes, install helper code, binary mappings, and verified Linux release
binaries only where native package formats require binary payloads. With
`--build-rpm-packages`, it also emits unsigned `x86_64` and `aarch64` RPM
packages with `.rpm.sha256` sidecars; tagged publication signs those RPM
payloads and refreshes their sidecars before RPM repository metadata is
generated. With `--build-apt-repository-metadata`,
it also emits `conu-<debian-version>-apt-repository-metadata.zip` containing
deterministic `Packages`, `Packages.gz`, and `Release` files for the generated
`.deb` assets, plus a `.sha256` sidecar. With
`--build-rpm-repository-metadata`, it also emits
`conu-<rpm-version>-rpm-repository-metadata.zip` containing `repodata/*`
generated by `createrepo_c` for the generated `.rpm` assets without embedding
the RPM packages, plus a `.sha256` sidecar. Tagged release publication then
adds APT `InRelease`/`Release.gpg` and RPM `repodata/repomd.xml.asc`
signatures, refreshes metadata ZIP sidecars, and signs the final ZIPs with
detached `.asc` signatures. Tagged publication then builds a signed
`conu-<version>-hosted-linux-repositories.zip` containing flat `apt/` and
`rpm/` static hosting trees with package signatures, native repository
signatures, public key copies, and strict sidecars. Tagged publication then
builds a signed `conu-<version>-hosted-linux-repository-site.zip` containing
those public repository trees plus `.nojekyll`, `index.html`,
`repository.json`, `cache-policy.json`, `_headers`, `install/conu.list`,
`install/conu.repo`, and `downloads/` copies of the signed hosted bundle,
checksum, and signature for static HTTPS hosting. `cache-policy.json` and
`_headers` keep install metadata, public keys, and package-manager indexes
revalidated while allowing versioned package payloads and signed bundle
downloads to be cached immutably when the operator's static host applies the
rules. Tagged release publication then verifies that site ZIP,
prepares an empty static directory for GitHub Pages, verifies the live
repository Pages setting when the default GitHub Pages base URL is used, and
deploys it when the repository uses that default endpoint. The regression checks
validate generated Debian packages with `dpkg-deb`, build the RPM spec with
`rpmbuild`, check generated RPM assets when those tools are installed, verify
the APT and RPM metadata bundles against the actual package hashes, verify
native RPM package signing with an ephemeral GPG key when RPM signing tools are
available, verify native repository signatures with an ephemeral GPG key, and
validate the hosted repository bundle, site layout, generated cache policy,
live endpoint Cache-Control behavior, S3 publication command/cache metadata,
Pages extraction path, and GitHub Pages repository metadata readiness plus
fail-closed signature/base-URL/path/state-marker checks. They do not read local
conU state, tokens, signing material, or package-manager repository
credentials. Installed clients can run
`conu update check --policy-file <path> [--gpg-verify]` against the generated
`conu-<version>-update-policy.json` plus its `.sha256` and `.asc` sidecars
before publication, or `conu update check --policy-url <https-url>
[--gpg-verify]` against the public GitHub Release policy URL after
publication. Remote mode fetches only the policy JSON, strict checksum sidecar,
and detached signature sidecar with TLS, size, timeout, redirect, and
public-host limits. Both modes validate the policy schema, public URLs, strict
checksum sidecar, detached signature sidecar, false display guards, and
auto-apply-disabled contract before manual update decisions. Operators can then
run `conu update download --policy-url <https-url> --output-dir <dir>
[--target <target>] [--gpg-verify]` to revalidate the policy, download one
selected public platform archive plus `.sha256` and `.asc` sidecars, verify the
archive SHA-256 and optional GPG signature, and write the files without
clobbering existing output. After review, `conu update apply --policy-file
<path>|--policy-url <https-url> --artifact-file <archive> --install-dir <dir>
[--target <target>] [--gpg-verify] --dry-run` revalidates the policy and
downloaded archive, scans the archive with bounded path/link/duplicate-binary
guards, and reports the exact binaries it would install without writing to the
install directory. Rerun with `--confirm` only after stopping running conU
processes and reviewing the dry-run; confirmed apply backs up existing binaries
under the install directory before replacing `conu`, `conud`, `conu-relay`, and
`conu-mcp`. The update commands report only public release metadata and selected
artifact or install paths; they do not print archive contents, signatures, GPG
output, tokens, private keys, local conU state, or payloads. These checks still
do not submit package-manager repository PRs, configure DNS records, provision
certificates, invalidate CDNs, or support non-S3 custom hosts automatically, and
unattended automatic update apply remains disabled by policy.

## User Install Choices

Recommended for normal users after the first public release:

```sh
npm install -g @conu/cli
```

Recommended for Rust developers:

```sh
cargo install --git https://github.com/imthegoodboy/conU --package conu-cli --bin conu --locked
cargo install --git https://github.com/imthegoodboy/conU --package conud --bin conud --locked
cargo install --git https://github.com/imthegoodboy/conU --package conu-relay --bin conu-relay --locked
cargo install --git https://github.com/imthegoodboy/conU --package conu-mcp --bin conu-mcp --locked
```

Recommended for early testers:

```txt
Download the GitHub Release archive
unpack it
run the platform install script in packaging/
run conu doctor
```

## How It Works For A User

On each user's machine:

```txt
agent
  -> conu-mcp / SDK / CLI stdin
  -> local conUD
  -> peer-encrypted relay message, stream chunk, or room event
  -> conu-relay
  -> remote conUD
  -> remote agent inbox
```

The user or agent does this once:

```sh
conu init
conu start
conu agents register agent.local "Local Agent" --kind coding-agent --streams true
conu identity export --json
conu agents export agent.local --json
```

Then the peer's public card is trusted:

```sh
conu peers trust <peer-node-id> "<peer name>" --exchange-key <peer-exchange-key> --relay wss://relay.example.com/conu --signing-key <peer-signing-public-key> --signature <peer-signature> --signature-key-id <peer-signature-key-id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
```

The signing fields come from `conu identity export --json`. They let the importing node verify that the public peer card was not modified between export and trust import. Unsigned imports remain available for older controlled test cards, but hosted/self-hosted production guidance should use signed peer cards. `conu peers policy` stores metadata-only boolean grants; missing policy records deny remote message, stream, room, file, and mailbox surfaces by default.

After signed peer trust and policy are in place, conUD/session sync exchanges signed public agent cards automatically over peer-encrypted relay control envelopes. The relay sees ciphertext and route metadata only. Manual fallback remains available:

```sh
conu agents trust <remote-agent-id> "<remote agent name>" --node <peer-node-id> --kind coding-agent --streams true --signing-key <agent-signing-public-key> --signature <agent-signature> --signature-key-id <agent-signature-key-id>
```

The agent signing fields and capability booleans come from `conu agents export <agent-id> --json`. Manual and automatic imports both verify the agent-card signature and only accept cards whose `nodeId` belongs to an already trusted peer with the same signing public key.

Then an agent can send through conU:

```sh
printf "opaque bytes" | conu messages send agent.local agent.remote --peer <peer-node-id> --stdin
conu streams open agent.local <remote-agent-id-with-streams>
printf "opaque stream bytes" | conu streams write <stream-id> --stdin
```

Stream chunks require the local sender and signed remote target metadata to advertise `streams=true`. conU CLI output shows metadata only. It should never show message text, reasoning, prompt content, private keys, or decrypted bytes.

## Hosting The Relay

The current hostable component is `conu-relay`.

Minimal VPS run:

```sh
mkdir -p /etc/conu-relay
conu-relay --issue-credential node-a-id --token-out /etc/conu-relay/node-a.token --credentials-file /etc/conu-relay/credentials.toml
conu-relay --issue-credential node-b-id --token-out /etc/conu-relay/node-b.token --credentials-file /etc/conu-relay/credentials.toml
export CONU_RELAY_CREDENTIALS_FILE=/etc/conu-relay/credentials.toml
export CONU_RELAY_MAX_CONNECTIONS=512
export CONU_RELAY_MAX_CONNECTIONS_PER_IP=64
export CONU_RELAY_MAX_FRAMES_PER_MINUTE=600
export CONU_RELAY_IDLE_TIMEOUT_SECONDS=120
export CONU_RELAY_SESSION_TTL_SECONDS=3600
export CONU_RELAY_SESSION_STATE_DIR=/var/lib/conu-relay/sessions
export CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE=128
export CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS=3600
export CONU_RELAY_MAILBOX_DIR=/var/lib/conu-relay/mailbox
export CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS=3600
export CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting
export CONU_RELAY_ACCOUNTING_WINDOW_SECONDS=86400
export CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE=10000
export CONU_RELAY_MAX_BYTES_SENT_PER_NODE=1073741824
export CONU_RELAY_ABUSE_DIR=/var/lib/conu-relay/abuse
export CONU_RELAY_ABUSE_WINDOW_SECONDS=86400
conu-relay --serve 0.0.0.0:8787
```

`conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` generates a strong scoped token, writes the raw token to a new file for delivery to that node, and creates or appends only hashed metadata in `credentials.toml`. Omit `--credentials-file` when you intentionally want a hashed manifest entry for manual copy. Use `--replace` to rotate an existing node credential and `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a node revoked. `conu-relay --hash-token` remains available when an operator already has a token and only needs the hash fields.

`CONU_RELAY_CREDENTIALS_FILE` is the preferred self-hosted mode because each node gets its own relay token while the server keeps only a SHA-256 hash, lifecycle status, token length metadata, and optional `expires_at_unix`. The relay reloads this manifest for each new `HELLO` authentication attempt, so a revoked or expired credential is rejected for new sessions without a process restart. Existing authenticated sessions remain governed by idle timeout and max TTL. A missing or invalid manifest fails closed for new sessions until a valid file is restored. `CONU_RELAY_CREDENTIALS` remains available as comma-separated `node-id:token` compatibility config for controlled tests, and server-side `CONU_RELAY_TOKEN` is still available for local or tightly controlled shared-token tests. File credentials override `CONU_RELAY_CREDENTIALS`, which overrides `CONU_RELAY_TOKEN`. Each runtime can set `CONU_RELAY_TOKEN` to its assigned scoped token before `conu start` or `conu relay sync`, or store that client credential with `conu relay credential set --stdin`. The client environment variable wins when both client env and local stored credential are present. For non-loopback binds, every shared or scoped token must be custom and at least 24 characters.

`CONU_RELAY_SESSION_STATE_DIR` persists metadata-only `.session` files per node so a same-node resume hint can survive a relay restart until the session TTL expires. They contain node ids, relay session ids, timestamps, and display guards; they do not contain relay tokens, token hashes, payloads, ciphertext bodies, private keys, or account secrets. Keep this directory on protected relay storage. Inspect local session-state pressure with `conu-relay --session-audit --session-state-dir /var/lib/conu-relay/sessions [--node <node-id>] [--json]`; it reports record counts, active/expired/invalid totals, timestamp bounds, and false display guards without printing session ids. Managed relay operators can query the same metadata from the running relay with `conu-relay --admin-session-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--json]`. The current file-backed session store is a single-writer boundary for self-hosted relays and controlled failover tests; it is not a distributed lock service or multi-region session migration layer.

`CONU_RELAY_MAILBOX_DIR` persists durable `.mailbox` files for peer-encrypted offline envelopes. These files contain route metadata, public key material, ciphertext, and `payload_displayed = false`; they do not contain plaintext message text, stream chunks, room-event plaintext, relay tokens, token hashes, private keys, or session ids. Inspect local retention pressure with `conu-relay --mailbox-audit --mailbox-dir /var/lib/conu-relay/mailbox [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--json]`. Managed relay operators can query the same retention metadata from the running relay with `conu-relay --admin-mailbox-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--json]`. The audits report aggregate file counts, byte totals, queue timestamp bounds, optional expired counts, invalid mailbox-file counts, and false display guards only. To enforce the same retention boundary manually, run `conu-relay --mailbox-purge --mailbox-dir /var/lib/conu-relay/mailbox [--ttl-seconds 3600] [--node <node-id>] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] --dry-run [--json]`, review the aggregate expired counts, then rerun with `--confirm` to delete only expired valid `.mailbox` files. Managed operators can run the same confirm-gated cleanup against a running relay with `conu-relay --admin-mailbox-purge --relay wss://relay.example.com/conu --admin-token-stdin [--ttl-seconds 3600] [--node <node-id>] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] (--dry-run|--confirm) [--json]`. Set `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` when the relay should run the same expired-file cleanup on a local schedule using `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`; this requires `CONU_RELAY_MAILBOX_DIR`, and `0` or an empty value disables it. Purge output does not render stored relay frames, ciphertext bodies, payloads, tokens, token hashes, private keys, or session ids. Retention policy files are metadata-only TOML-style files with `version = "1"`, optional `ttl_seconds` and `node_id`, and false display guards for payload, token, token hash, key material, session id, ciphertext, and contents. CLI `--ttl-seconds` and `--node` values override file defaults, and purge commands still require a TTL from file or CLI plus exactly one of `--dry-run` or `--confirm`. This is a single-relay operator workflow, not distributed hosted retention automation or billing.

`CONU_RELAY_ACCOUNTING_DIR` persists metadata-only `.accounting` files per node. They contain node ids, accounting window start, authenticated session counts, sent/received envelope counts, byte counts, mailbox counts, `payload_displayed = false`, and `token_displayed = false`; they do not contain relay tokens, token hashes, session ids, message text, stream chunks, room-event plaintext, or ciphertext bodies. Set `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE` and/or `CONU_RELAY_MAX_BYTES_SENT_PER_NODE` to reject over-quota sends for a node during the configured accounting window with `UNDELIVERED reason=quota_exceeded`.

`CONU_RELAY_ABUSE_DIR` persists metadata-only `.abuse` files for enforcement outcomes such as admin unauthorized attempts, credential-denied sessions, tenant-denied sessions, rate limits, session expiry, quota-denied forwards, undelivered forwards, and mailbox rejects. They contain aggregate counters, optional node ids, window start, and display guards only; they do not contain raw tokens, token hashes, admin tokens, session ids, payloads, ciphertext bodies, private keys, or arbitrary frame contents. Inspect them with `conu-relay --abuse-audit --abuse-dir /var/lib/conu-relay/abuse [--node <node-id>] [--json]`, or compare local counters against explicit maximums with `conu-relay --abuse-threshold-report --abuse-dir /var/lib/conu-relay/abuse [--node <node-id>] --max-<metric> <count>... [--json] [--fail-on-threshold]`. To inspect a local operator dashboard snapshot across credential, tenant, accounting, and abuse stores, run `conu-relay --hosted-dashboard --credentials-file /etc/conu-relay/credentials.toml --tenants-file /etc/conu-relay/tenants.toml --accounting-dir /var/lib/conu-relay/accounting --abuse-dir /var/lib/conu-relay/abuse [--account <account-id>] [--node <node-id>] [--json]`. Before startup or release smoke, run `conu-relay --hosted-readiness --bind-addr 0.0.0.0:8787 --credentials-file /etc/conu-relay/credentials.toml --admin-tokens-file /etc/conu-relay/admin-tokens.toml --tenants-file /etc/conu-relay/tenants.toml --session-state-dir /var/lib/conu-relay/sessions --mailbox-dir /var/lib/conu-relay/mailbox --accounting-dir /var/lib/conu-relay/accounting --abuse-dir /var/lib/conu-relay/abuse [--account <account-id>] [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--thresholds-file /etc/conu-relay/abuse-thresholds.toml] [--max-<metric> <count>...] [--json] [--fail-on-warning]`; it reports only configured paths, source booleans, counts, threshold checks/exceeded counts, warnings, bind metadata, and false display guards. To inspect a local scoped admin-token manifest before loading it, run `conu-relay --admin-token-audit --admin-tokens-file /etc/conu-relay/admin-tokens.toml --bind-addr 0.0.0.0:8787 [--account <account-id>] [--json]`; it reports scope/account/lifecycle/expiry counts and false display guards without printing admin tokens, token hashes, or manifest contents. To query the same class of counters from a running managed relay, pipe an admin token into `conu-relay --admin-hosted-dashboard --relay wss://relay.example.com/conu --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]`; to evaluate thresholds online, use `conu-relay --admin-abuse-threshold-report --relay wss://relay.example.com/conu --admin-token-stdin [--account <account-id>] [--node <node-id>] --max-<metric> <count>... [--json] [--fail-on-threshold]`. With `--fail-on-threshold`, threshold commands preserve the stdout report and return exit code 3 only when at least one configured threshold is exceeded; with `--fail-on-warning`, readiness also returns exit code 3 when configured abuse thresholds are exceeded. Use `conu-relay --admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, and `--admin-tenant-audit` with `--admin-token-stdin` to update or audit the configured tenant registry on a running relay without shell access to the file; output is tenant/node counts and display guards only. Suspend one hosted account locally with `conu-relay --hosted-account-suspend <account-id> --credentials-file /etc/conu-relay/credentials.toml --tenants-file /etc/conu-relay/tenants.toml [--json]`, or online with `conu-relay --admin-hosted-account-suspend <account-id> --relay wss://relay.example.com/conu --admin-token-stdin [--json]`; both forms revoke tenant metadata before account credential records and report counts/display guards only. Use `conu-relay --admin-session-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--json]` for a read-only online snapshot of configured file-backed session-state metadata. Use `conu-relay --admin-mailbox-audit --relay wss://relay.example.com/conu --admin-token-stdin [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--json]` for a read-only online snapshot of configured durable mailbox retention metadata, and `conu-relay --admin-mailbox-purge --relay wss://relay.example.com/conu --admin-token-stdin [--ttl-seconds 3600] [--node <node-id>] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] (--dry-run|--confirm) [--json]` for confirm-gated online cleanup. `CONU_RELAY_ADMIN_TOKEN` is a full-admin compatibility secret; `CONU_RELAY_ADMIN_TOKENS_FILE` can live-read hashed scoped admin tokens for credential, tenant, dashboard, sessions, mailbox-audit, and mailbox-purge actions, with optional account ids for account-bound operators. Hosted account suspension requires full-admin access or both credential and tenant scopes; hosted abuse threshold reports use dashboard scope, and account-scoped session audits require a node filter plus an active tenant-node record. The current stores, threshold reports, and readiness preflights are single-writer relay-local workflows for self-hosted or controlled managed deployments, not a distributed abuse pipeline, hosted workflow system, alerting service, or hosted dashboard service.

For a controlled multi-relay deployment where metadata stores are available to one operator host, create a guarded fleet manifest and run `conu-relay --hosted-fleet-dashboard --fleet-file /etc/conu-relay/fleet-dashboard.toml [--account <account-id>] [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] [--thresholds-file /etc/conu-relay/abuse-thresholds.toml] [--max-<metric> <count>...] [--json] [--fail-on-retention] [--fail-on-threshold]`. To plan a static response workflow for aggregate fleet abuse threshold breaches, run `conu-relay --hosted-fleet-abuse-response-plan --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] [--thresholds-file /etc/conu-relay/abuse-thresholds.toml] [--max-<metric> <count>...] [--json] [--fail-on-action]`; it reports categories such as admin access, credential/tenant access, traffic pressure, delivery health, and mailbox pressure without changing any relay state. Before tenant workflow mutation, run `conu-relay --hosted-fleet-account-audit <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] [--json] [--fail-on-warning]` to report credential/tenant source coverage and account or node consistency warning categories across local stores. To revoke one compromised account/node credential across local credential manifests without changing tenant metadata, run `conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml --dry-run [--json]`, review the aggregate and per-relay credential counts, then rerun with `--confirm`. To suspend one account or one account node across complete local credential/tenant source pairs, run `conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] --dry-run [--json]`, review the aggregate and per-relay counts, then rerun with `--confirm`. To clean expired durable mailbox files across those manifest-listed local stores, run `conu-relay --hosted-fleet-mailbox-purge --fleet-file /etc/conu-relay/fleet-dashboard.toml [--node <node-id>] [--ttl-seconds 3600] [--retention-policy-file /etc/conu-relay/mailbox-retention.toml] --dry-run [--json]`, review the aggregate and per-relay counts, then rerun with `--confirm`. The manifest uses `version = "1"`, explicit false display guards, and one or more `[[relay]]` entries with `name`, plus optional `credentials_file`, `tenants_file`, `session_state_dir`, `mailbox_dir`, `mailbox_ttl_seconds`, `accounting_dir`, and `abuse_dir`. Relative paths resolve from the manifest directory. Fleet output sums only metadata counters and source paths; when retention is configured it evaluates relay-local mailbox TTL metadata and returns exit code 3 only with `--fail-on-retention` and at least one TTL-checked source with expired records. CLI `--ttl-seconds` overrides all fleet mailbox TTLs for that run, while per-relay `mailbox_ttl_seconds` entries remain source-specific overrides ahead of the policy-file TTL. The fleet account audit command is read-only, may narrow counts and warning categories with `--node`, and returns exit code 3 only with `--fail-on-warning` and at least one warning; the fleet credential revoke command requires explicit dry-run or confirm, preflights all credential sources before confirmed mutation, rejects node/account collisions, and never contacts remote relays; the fleet account suspension command rejects partial credential/tenant entries, preflights all complete sources before confirmed mutation, revokes tenant metadata before credentials in account-wide mode, revokes tenant-node metadata before matching node credentials with `--node`, and never contacts remote relays. The fleet purge command uses the same TTL precedence and deletes only expired valid `.mailbox` files when `--confirm` is supplied. When thresholds are configured the dashboard evaluates aggregate abuse counters and returns exit code 3 only with `--fail-on-threshold` and at least one exceeded limit; the response plan returns exit code 3 only with `--fail-on-action` and at least one recommended action category. These fleet commands do not read or print tokens, token hashes, session ids, payloads, ciphertext bodies, arbitrary frame contents, private keys, mailbox file contents, policy contents, or manifest contents, and they are not hosted billing, remote relay purge, remote tenant control, cross-region retention locking, or adaptive abuse automation services.

For tenant account lifecycle across the same manifest-listed local tenant registries, run `conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml --dry-run [--json]`, review tenant/source counts, then rerun with `--confirm`; revoke uses `conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file /etc/conu-relay/fleet-dashboard.toml --dry-run [--json]` followed by `--confirm`. The tenant account commands require explicit dry-run or confirm, preflight every configured local `tenants_file` before confirmed mutation, create missing tenant files only for confirmed upsert, require the account to exist before revoke, never contact remote relays, and report only account id, counts, paths, mode/status, and display guards.

Threshold commands and hosted readiness can load reusable policy files with `--thresholds-file /etc/conu-relay/abuse-thresholds.toml` when an abuse store is configured. A threshold policy file must contain `version = "1"`, any supported `max_*` keys, and explicit `payload_displayed = false`, `token_displayed = false`, `token_hash_displayed = false`, `key_material_displayed = false`, `session_id_displayed = false`, `ciphertext_displayed = false`, and `contents_displayed = false` guards. CLI `--max-*` values override file defaults for one-off runs.

Open TCP port `8787` only to machines on a trusted private path, then give users:

```txt
ws://<relay-host>:8787
```

For public internet use, put a TLS terminator or reverse proxy with a valid certificate in front of `conu-relay` and give users the TLS endpoint:

```txt
wss://relay.example.com/conu
```

Systemd template:

```txt
packaging/linux/conud.service      local daemon template
```

Relay Docker template:

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

For a managed relay, provide `CONU_RELAY_ADMIN_TOKEN` from your secret manager for full-admin compatibility, or set `CONU_RELAY_ADMIN_TOKENS_FILE` to a protected hashed admin-token manifest for scoped operator tokens, and keep `CONU_RELAY_CREDENTIALS_FILE` enabled. Audit scoped admin-token manifests locally with `conu-relay --admin-token-audit --admin-tokens-file <path> --bind-addr <relay-bind> [--account <id>] [--json]` before loading them into the relay, and run `conu-relay --hosted-readiness ... [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] --json --fail-on-warning` against the configured local stores before startup or release smoke. Optionally set `CONU_RELAY_TENANTS_FILE` to a protected tenant registry file. The online admin commands in `docs/hosted-relay-account-auth.md` issue, rotate, revoke, audit account-scoped node credentials, manage tenant account/node metadata, suspend a single relay-local hosted account, request admin-gated session-state/dashboard snapshots and abuse threshold reports, and run mailbox retention audit/purge by sending only token hash metadata or metadata-only requests to the relay; the tenant commands in the same doc manage account, node, hosted permission, and public key-id metadata without granting local peer policy. Where several local relay stores are available on one operator host, the guarded fleet account audit command can report account-wide or node-scoped credential/tenant consistency warnings, the guarded fleet credential revoke command can dry-run or confirm account/node credential revocation across manifest-listed credential files, and the guarded fleet account suspension command can dry-run or confirm tenant-first account suspension or tenant-node-first node suspension across complete manifest-listed credential/tenant file pairs without remote relay control.

## Current Hosting Limit

The built-in client accepts `ws://` and `wss://` relay endpoints. `wss://` uses the platform certificate verifier, so the relay hostname must match a valid certificate. The bundled `conu-relay` server still listens as plain WebSocket; public TLS belongs in a reverse proxy or load balancer in front of it.

Before running a managed public relay, conU still needs:

- Distributed hosted account control planes and remote tenant lifecycle beyond the current single-relay file-backed account metadata, hosted tenant registry, scoped admin-token manifest and audit, local/admin-gated account suspension, guarded local fleet account/node audit, tenant-node upsert/revoke, account/node suspension, online credential issue/rotate/revoke/audit APIs, online tenant account/node lifecycle, offline `conu-relay --issue-credential` helper, `--revoke-credential`, and live-reloaded credential manifest.
- Managed hosted quotas, distributed abuse monitoring, dashboards, and adaptive response beyond the current self-hosted connection/frame caps, per-node accounting quotas, single-relay metadata-only abuse counters, local `--abuse-threshold-report` reports with optional `--fail-on-threshold`, local `--hosted-dashboard` snapshots, local `--hosted-readiness` preflights, admin-gated online `--admin-abuse-threshold-report` reports with optional `--fail-on-threshold`, and admin-gated online `--admin-hosted-dashboard` snapshots.
- Distributed hosted relay session migration and accounting beyond the current idle-timeout, max-TTL session policy, same-node resume hints, file-backed session records, payload-safe local/admin session-state audits, and authenticated/resumed session counters.
- Managed hosted mailbox retention/accounting dashboards beyond the current self-hosted durable ciphertext files, metadata-only mailbox counters, relay-local and admin-gated online mailbox audit snapshots, confirm-gated local/admin online purge commands, and relay-local scheduled purge policy.
- Hosted dashboard services and distributed permission administration beyond the current single-writer local/admin-gated tenant registry, account suspension, guarded fleet account/node suspension, local/admin-gated single-relay dashboard snapshots, and local peer/room topic policy files.
- Hosted managed key administration and hardware-backed key policy. Windows local key and stored relay credential files wrap secret bytes with current-user DPAPI, macOS uses user Keychain, Linux uses Secret Service when available, and non-Windows operators can still configure `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE` for a user-managed encrypted fallback. Secure Enclave, HSM, and hosted identity/key administration still need dedicated work.

Until those are complete, the best real-world test setup is a self-hosted relay behind TLS on a trusted VPS or a private network relay, using signed peer-card trust, explicit peer policy grants, optional local room topic policy grants, and peer-encrypted messages, stream chunks, and room events only.

## Agent Integration

For most modern agents, the easiest integration is MCP:

```json
{
  "mcpServers": {
    "conu": {
      "command": "conu-mcp",
      "env": {
        "CONU_AGENT_ID": "agent.mybot"
      }
    }
  }
}
```

Agents should use conU like this:

```txt
Register yourself.
List trusted peers and agents.
Send opaque bytes through conU.
Receive only messages addressed to you.
Never expect CLI output to show private message contents.
Treat conU as the road, not the conversation.
```

## Best Next Product Step

For the user install story, finish publishing in this order:

1. Keep release assets and checksums generated by CI.
2. Publish `@conu/cli` after the GitHub Release exists.
3. Put public relay tests behind TLS termination and use `wss://` endpoints.
4. Add distributed account control planes, remote tenant lifecycle/workflow automation beyond guarded local fleet account/node audit, tenant-node upsert/revoke, account/node suspension plus single-relay account suspension/scoped admin tenant commands, distributed monitoring/dashboards/alerting beyond single-relay threshold reports, distributed hosted mailbox retention policy beyond local/admin-gated audit and purge plus local scheduled purge workflows, and distributed multi-instance session migration before opening a managed relay to everyone.
5. Submit generated Homebrew/Scoop/winget/Chocolatey/Debian/RPM files to the appropriate package-manager repositories, configure DNS/TLS/CDN for any custom repository host, use `scripts/publish-hosted-linux-repository-s3.py` for the supported S3-compatible static host path, run `python scripts/check-hosted-linux-repository-endpoint.py --base-url <https-url> --expected-version <version>` against the live endpoint, then exercise `conu update check --policy-url <https-url>`, `conu update download --policy-url <https-url> --output-dir <dir> --target <target>`, and a `conu update apply --policy-url <https-url> --artifact-file <archive> --install-dir <dir> --target <target> --dry-run` against a real signed release before enabling any unattended automatic update flow.
