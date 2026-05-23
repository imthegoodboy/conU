# @conu/cli

This npm package is a thin launcher for the native Rust conU binaries:

- `conu`
- `conud`
- `conu-relay`
- `conu-mcp`

The package does not reimplement conU in JavaScript. On install, it downloads the matching native release archive from GitHub Releases, verifies the `.sha256` file, and places the binaries under the package-local `vendor/` directory.

## Install

Use a supported Node.js LTS line. This package currently accepts Node 22 LTS or
Node 24 LTS and intentionally rejects EOL Node lines.

```sh
npm install -g @conu/cli
conu doctor
```

The expected release asset names are:

```txt
conu-0.1.0-windows-x64.zip
conu-0.1.0-linux-x64.tar.gz
conu-0.1.0-linux-arm64.tar.gz
conu-0.1.0-macos-x64.zip
conu-0.1.0-macos-arm64.zip
```

Each archive must have a sibling checksum file named `<asset>.sha256`.

Tagged GitHub releases are expected to publish these assets before this npm
package is published. The release workflow verifies archive checksums and
rejects local conU state/log/key/payload paths before upload. Tagged release
builds also require Windows Authenticode signing secrets, macOS Developer
ID/notarization secrets, and the repository `NPM_TOKEN` secret. Tagged release
preflight fails before package checks when any required release secret is
missing so npm publication cannot silently skip after a GitHub-only release.
Before attestation/upload, the release workflow also installs this package into
a temporary npm prefix with `CONU_NPM_BINARY_DIR` pointed at the generated
archive binaries, verifies the package-local `vendor/` copies and npm bin
shims, and runs the installed launcher through `conu init`, `conu security audit
--json`, and `conu doctor --json`. A second release smoke serves the generated
archive plus `.sha256` from localhost and installs with `CONU_NPM_DIST_BASE`, so
the default download, checksum verification, archive-member preflight,
extraction, and launcher path are checked before publishing.

## Environment

```txt
CONU_NPM_DIST_BASE        Override the release base URL.
CONU_NPM_BINARY_DIR       Copy binaries from a local directory instead of downloading.
CONU_NPM_SKIP_DOWNLOAD    Skip install download for package publishing checks.
CONU_NPM_ALLOW_UNVERIFIED Allow install when a checksum file is unavailable.
```

The default download base is:

```txt
https://github.com/imthegoodboy/conU/releases/download/v0.1.0
```

## Current Product Limit

The npm package only solves distribution. It does not turn the current relay into a managed public network. Users still run `conu-relay` themselves, configure trusted peer cards, and use reachable `ws://` or certificate-valid `wss://` relay endpoints with live-reloaded scoped credentials or a hashed `CONU_RELAY_CREDENTIALS_FILE`, optional account-scoped online credential admin, scoped hosted admin-token manifests with payload-safe local `conu-relay --admin-token-audit`, admin-gated online tenant lifecycle for one configured relay registry, local/admin-gated hosted account suspension, same-node relay-session resume with optional metadata-only `CONU_RELAY_SESSION_STATE_DIR` records, payload-safe local `conu-relay --session-audit` and admin-gated online `conu-relay --admin-session-audit` snapshots, metadata-only `CONU_RELAY_ACCOUNTING_DIR` counters/quotas, metadata-only `CONU_RELAY_ABUSE_DIR` denial/enforcement counters, local/admin-gated `conu-relay --abuse-threshold-report` reports with reusable `--thresholds-file` policy files and optional `--fail-on-threshold` script exit status, policy-aware local `conu-relay --hosted-readiness` preflights with reusable `--retention-policy-file` and `--thresholds-file` policy files plus optional `--fail-on-warning`, local `conu-relay --hosted-dashboard` snapshots, admin-gated online `conu-relay --admin-hosted-dashboard` snapshots, admin-gated online `conu-relay --admin-abuse-threshold-report` reports, payload-safe local `conu-relay --mailbox-audit` and admin-gated online `conu-relay --admin-mailbox-audit` retention snapshots with reusable `--retention-policy-file` policy files, confirm-gated local `conu-relay --mailbox-purge` and admin-gated online `conu-relay --admin-mailbox-purge` cleanup, optional relay-local `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` cleanup, plus bounded offline mailbox policy for peer-encrypted messages, stream chunks, room events, and signed-card control envelopes. Room topic policy is local runtime metadata, not hosted tenant administration. Set `CONU_RELAY_MAILBOX_DIR` on the relay for durable ciphertext files until distributed hosted dashboards/accounting/abuse workflows beyond single-relay threshold reports and readiness preflights, distributed multi-instance session migration beyond single-relay session-state audits, distributed hosted mailbox retention orchestration beyond single-relay purge, and distributed hosted tenant lifecycle/workflow automation beyond scoped single-relay account suspension/admin tokens are implemented.
