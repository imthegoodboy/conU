# conU Release Checklist

Use this checklist before publishing any conU build.

## Version And Scope

- Confirm the release version in all Cargo packages.
- Confirm `packaging/npm/conu-cli/package.json` has the same version.
- Confirm `sdk/typescript/package.json` has the same version if publishing the TypeScript/JavaScript SDK package.
- Run `python scripts/verify-release-versions.py`; on `v*` tag builds the CI/release package gates also compare the tag version to the Cargo/npm package version.
- Run `python scripts/check-release-artifact-verifier.py`; CI and release package gates use the same regression check to prove release artifact verification fails closed on loose checksums, checksum filename mismatches, duplicate archive paths, and forbidden state paths.
- Run `python scripts/check-release-artifact-smoke-preflight.py`; CI and release package gates use the same regression check to prove archive smoke validation fails closed on missing binary directories, missing binaries, and non-file binary paths before execution.
- Run `python scripts/check-package-manager-manifests.py`; CI and release package gates use the same regression check to prove generated Homebrew/Scoop/winget/Chocolatey/Debian/RPM files plus APT/RPM repository metadata require strict release checksums plus safe Windows and Linux archive layouts, including native Debian package checks with `dpkg-deb`, APT/RPM metadata hash checks, and RPM spec plus optional RPM asset checks with `rpmbuild`/`createrepo_c` when those tools are available.
- Run `python scripts/check-package-manager-submissions.py`; CI and release package gates use the same regression check to prove the package-manager submission bundle lays out generated Homebrew tap, Scoop bucket, winget-pkgs, Chocolatey, Debian, APT, RPM, and Linux signing files under deterministic repository-ready paths, requires strict sidecars/signatures when requested, rejects forbidden output, and writes a strict bundle `.sha256` sidecar.
- Run `python scripts/check-linux-signing-secrets-preflight-regression.py`; CI and release package gates use the same regression check to prove Linux signing secrets fail closed when missing, malformed, fingerprint-mismatched, or unusable for probe signing.
- Run `python scripts/check-platform-signing-secrets-preflight-regression.py`; CI and release package gates use the same regression check to prove Windows/macOS signing secret values fail closed when missing, malformed, unsafe for timestamp/notary identity fields, or unusable as PKCS#12 certificate/private-key material when OpenSSL is available.
- Run `python scripts/set-github-release-secrets-regression.py`; CI and release package gates use the same regression check to prove release secret setup reads local values from the environment, sends them to `gh secret set` through stdin rather than command arguments, and reports only secret names.
- Run `python scripts/check-github-release-secret-readiness.py --repo <owner/name>` before creating a release tag; it reports only configured or missing secret names.
- Run `python scripts/check-github-main-protection.py --repo <owner/name>` before creating a release tag or marking the repository production-ready; it reports whether the default branch has strict required CI checks, force pushes disabled, and branch deletion disabled without printing tokens, logs, or branch-protection API bodies.
- Run `python scripts/check-github-actions-permissions.py --repo <owner/name>` before creating a release tag or marking the repository production-ready; it verifies Actions are enabled, repository Actions admission is restricted to selected actions, the default workflow token is read-only, Actions cannot approve pull requests, GitHub-owned actions are allowed, and only the expected `dtolnay/rust-toolchain@stable` marketplace pattern is allowed.
- Run `python scripts/check-github-workflow-permissions.py` before creating a release tag or marking the repository production-ready; it verifies every workflow declares explicit read-only top-level permissions, rejects unsafe trigger surfaces, and allows write scopes only on the known release jobs that publish attestations, GitHub Releases, Pages, or npm provenance.
- Run `python scripts/check-tagged-release-readiness.py --repo <owner/name> --tag v<version> --npm-registry-check --require-ci --require-default-branch-head` before creating a release tag; it combines live release-secret names, default Pages or custom S3 repository settings, GitHub Release clobber status, package version/tag consistency, optional npm registry conflict checks, the target commit's latest `CI` workflow status, and default branch head matching without printing secret values, release notes, asset URLs, logs, or variable values.
- Run `python scripts/check-rpm-package-signing.py`; CI and release package gates use the same regression check to prove generated RPM package payloads can be signed with the fingerprint-pinned Linux GPG key, verified with native RPM tooling, refreshed with strict `.rpm.sha256` sidecars, used to generate RPM repository metadata, and failed closed on missing or mismatched fingerprint secrets.
- Run `python scripts/check-linux-release-signing.py`; CI and release package gates use the same regression check to prove Linux detached signing selects Linux archives, generated Debian/RPM packages, APT/RPM repository metadata, hosted repository bundles/sites, and update-policy JSON files, verifies generated `.asc` signatures, supports hosted-bundle/site-only and update-policy-only signing, and fails closed when signing secrets are missing or the configured key fingerprint mismatches.
- Run `python scripts/check-linux-repository-signing.py`; CI and release package gates use the same regression check to prove generated APT metadata ZIPs receive valid `InRelease` and `Release.gpg` signatures, generated RPM metadata ZIPs receive valid `repodata/repomd.xml.asc` signatures, `.sha256` sidecars are refreshed, unrelated release assets are not mutated, and missing or mismatched signing fingerprint secrets fail closed.
- Run `python scripts/check-hosted-linux-repositories.py`; CI and release package gates use the same regression check to prove the hosted Linux repository bundle contains signed flat APT and YUM/DNF repository trees, public key copies, strict sidecars, deterministic ZIP metadata, and fail-closed handling for missing signatures or unsafe metadata paths.
- Run `python scripts/check-hosted-linux-repository-site.py`; CI and release package gates use the same regression check to prove the hosted Linux repository site artifact contains public APT/YUM repository trees, endpoint metadata, install snippets, checked `cache-policy.json` and `_headers` Cache-Control rules, signed-bundle downloads, deterministic ZIP metadata, an HTTPS base URL, and fail-closed handling for missing signatures or unsafe bundle paths.
- Run `python scripts/check-hosted-linux-repository-pages.py`; CI and release package gates use the same regression check to prove the hosted Linux repository site ZIP can be checksum/signature preflighted, safely extracted for GitHub Pages, and rejected when it contains unsafe paths, forbidden state/secret markers, non-HTTPS repository metadata, missing sidecars, invalid cache policy files, or a non-empty deployment directory.
- Run `python scripts/check-hosted-linux-repository-endpoint-regression.py`; CI and release package gates use the same regression check to prove live hosted repository endpoint readiness fails closed on insecure URLs, metadata base-URL drift, bad display guards, `_headers` drift, and missing or wrong `Cache-Control` headers.
- Run `python scripts/check-hosted-linux-repository-s3-publication.py`; CI and release package gates use the same regression check to prove custom S3-compatible hosted repository publication maps every extracted site file to exactly one generated cache rule, passes per-object `Cache-Control` and content-type metadata to the AWS CLI, rejects missing bucket/base URL/forbidden text/uncovered files, and keeps npm publication behind the Linux repository publication gate.
- Run `python scripts/check-release-update-policy.py`; CI and release package gates use the same regression check to prove release update-policy metadata requires strict release sidecars, Linux/package/repository/hosted signatures, HTTPS release URLs, matching `v<version>` tags, payload-safe public metadata, and `autoApply=false`.
- Run `conu update check --policy-file dist/conu-<version>-update-policy.json --gpg-verify` after the policy is generated and signed, then after publication run `conu update check --policy-url https://github.com/imthegoodboy/conU/releases/download/v<version>/conu-<version>-update-policy.json --gpg-verify`; the installed CLI check validates the policy schema, strict `.sha256` sidecar, detached `.asc` sidecar, public release URLs, npm package versions, display guards, and auto-apply-disabled contract without downloading update archives or applying an update. To verify the actual selected archive before installation, run `conu update download --policy-url https://github.com/imthegoodboy/conU/releases/download/v<version>/conu-<version>-update-policy.json --output-dir <dir> [--target <target>] [--gpg-verify]`; it revalidates the policy, downloads only one platform archive plus `.sha256` and `.asc` sidecars, verifies the strict SHA-256 sidecar and optional GPG signature, and writes into the chosen directory without clobbering existing files. To dry-run an explicit install, run `conu update apply --policy-url https://github.com/imthegoodboy/conU/releases/download/v<version>/conu-<version>-update-policy.json --artifact-file <dir>/conu-<version>-<target>.<ext> --install-dir <bin-dir> [--target <target>] [--gpg-verify] --dry-run`; it revalidates the policy/archive, scans only bounded safe archive members, stages only the four conU binaries, and reports install paths before any write. Use `--confirm` only after reviewing the dry-run and stopping running conU processes.
- Run `python scripts/check-release-update-download-gate.py`; CI and release package gates use the same regression check to prove tagged GitHub Release publication keeps the post-upload public `conu update check --policy-url --gpg-verify`, `conu update download --policy-url --gpg-verify --target linux-x64`, and `conu update apply --policy-url --gpg-verify --target linux-x64 --dry-run` gate before npm publication.
- Run `python scripts/check-github-pages-readiness.py --repo <owner/name>` before creating a release tag when `CONU_LINUX_REPOSITORY_BASE_URL` is unset; tagged release preflight runs the same live metadata check so default GitHub Pages deployment fails before builds if Pages is not configured for GitHub Actions, HTTPS, the public repository URL, and `main:/` source metadata.
- Run `python scripts/check-hosted-linux-repository-endpoint.py --base-url <https-url> --expected-version <version>` after publishing a custom hosted Linux repository endpoint; it proves the live endpoint serves matching `repository.json`, `cache-policy.json`, `_headers`, and `Cache-Control` headers.
- Run `python scripts/check-github-release-clobber-preflight.py --repo <owner/name> --tag v<version>` before creating a release tag; tagged release preflight and the GitHub Release publication job run the same metadata-only check so an existing release for the tag fails before any automated asset overwrite can happen.
- Run `python scripts/check-github-release-assets-published-regression.py`; CI and release package gates use the same regression check to prove the tagged GitHub Release asset publication preflight fails closed on missing, duplicate, draft, tag-mismatched, incomplete, or forbidden state/secret-looking release assets, including missing update-policy metadata, before npm publication can start.
- Run `python scripts/check-linux-gpg-public-key-export.py`; CI and release package gates use the same regression check to prove the Linux release GPG public key exports as armored public-key material with a strict `.sha256` sidecar, verifies a detached signature from a separate keyring, and fails closed when signing secrets are missing or the imported key fingerprint mismatches.
- Run `python scripts/verify-npm-package-contents.py`; CI, release package checks, and tagged npm publication use the same verifier to reject missing required files, unexpected state/build/payload paths, oversized files, and bundled dependencies.
- Run `python scripts/check-npm-publish-preflight.py`; CI and release package checks validate publish metadata for `@conu/cli` and `@conu/sdk`, and tagged npm publication reruns it with `--registry-check --require-token-env NODE_AUTH_TOKEN` before any package is published.
- Run `python scripts/check-npm-publish-preflight-regression.py`; CI and release package checks use the same regression check to prove existing npm versions, registry failures, and missing publish tokens fail closed.
- Tagged npm publication also runs `python scripts/check-github-release-assets-published.py --repo <owner/name> --tag v<version>` before npm registry access so an incomplete GitHub Release, including a release missing signed update-policy metadata, cannot become a partial npm release.
- Run `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -Toolchain stable-x86_64-pc-windows-gnu` before a release candidate; CI and the release artifact workflow run the same script in `-SmokeOnly` mode on Windows to keep the production smoke/readiness path exercised before artifact builds.
- Confirm `plan.md` reflects the completed phase and known gaps.
- Confirm Phase 14 room claims stay scoped to implemented local metadata/fanout, relay-backed room-event fanout, and local room topic policy behavior. Do not claim hosted multi-tenant room permission administration.
- Confirm relay hosting docs mention `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, `CONU_RELAY_MAX_FRAMES_PER_MINUTE`, `CONU_RELAY_IDLE_TIMEOUT_SECONDS`, `CONU_RELAY_SESSION_TTL_SECONDS`, optional `CONU_RELAY_SESSION_STATE_DIR`, `conu-relay --session-audit`, `conu-relay --admin-session-audit`, `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE`, `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`, optional `CONU_RELAY_MAILBOX_DIR`, `conu-relay --mailbox-audit`, `conu-relay --admin-mailbox-audit`, `conu-relay --admin-mailbox-purge`, optional mailbox `--retention-policy-file` policy files, optional `CONU_RELAY_ACCOUNTING_DIR`, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS`, `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE`, `CONU_RELAY_MAX_BYTES_SENT_PER_NODE`, optional `CONU_RELAY_ABUSE_DIR`, `CONU_RELAY_ABUSE_WINDOW_SECONDS`, `conu-relay --abuse-threshold-report`, `conu-relay --admin-abuse-threshold-report`, optional threshold `--thresholds-file` policy files, optional threshold `--fail-on-threshold` exit code behavior, optional full-admin `CONU_RELAY_ADMIN_TOKEN`, optional scoped `CONU_RELAY_ADMIN_TOKENS_FILE`, `conu-relay --admin-token-audit` for payload-safe scoped admin-token manifest checks, `conu-relay --hosted-readiness` for payload-safe local startup/release preflights with reusable retention/threshold policy files and `--fail-on-warning`, `conu-relay --hosted-fleet-dashboard` for guarded multi-relay metadata aggregation with optional reusable mailbox retention policy gates, optional reusable abuse threshold policy checks, `--fail-on-retention`, and `--fail-on-threshold`, `conu-relay --hosted-fleet-account-audit [--node <node-id>]` for read-only guarded local fleet account or account/node consistency warnings, `conu-relay --hosted-fleet-tenant-upsert` and `conu-relay --hosted-fleet-tenant-revoke` for dry-run/confirm guarded local fleet tenant account lifecycle, `conu-relay --hosted-fleet-account-suspend [--node <node-id>]` for dry-run/confirm guarded local fleet account or account/node suspension, account/action-scoped online credential lifecycle, online tenant lifecycle, hosted account suspension, session-state audits, dashboard snapshots/threshold reports, and online mailbox audit/purge, and optional `CONU_RELAY_TENANTS_FILE` for metadata-only hosted tenant checks.
- Confirm non-loopback relay examples use custom shared or scoped tokens with at least 24 characters, not `local-dev-token`.
- Confirm hosted/self-hosted examples prefer live-reloaded `CONU_RELAY_CREDENTIALS_FILE` where node ids are known, and that manifest examples store `token_sha256_hex`, `token_length`, status/expiry metadata, `payload_displayed = false`, and `token_displayed = false`.
- Confirm credential issuance examples use `conu-relay --issue-credential <node-id> --token-out <path> --credentials-file <path>` where a manifest should be updated, `--replace` for rotation, `conu-relay --revoke-credential <node-id> --credentials-file <path>` for revocation, or `conu-relay --hash-token` without printing raw tokens to docs, logs, or command output.
- Confirm hosted admin examples use `conu-relay --admin-issue-credential`, `--admin-rotate-credential`, `--admin-revoke-credential`, and `--admin-audit-credentials` only with `--admin-token-stdin`, document full-admin and scoped admin-token paths, and show ids/counts/status plus display guards without raw node tokens, token hashes, admin tokens, payloads, or manifest contents.
- Confirm scoped admin-token examples document `scope_sessions`, and that `conu-relay --admin-token-audit` reports only manifest counts/scope/account/expiry metadata while `conu-relay --admin-session-audit` is read-only, requires `--admin-token-stdin`, uses sessions admin scope, reports record counts/timestamp bounds/display guards only, and never prints relay session ids, raw node tokens, token hashes, admin tokens, payloads, ciphertext bodies, private keys, or session-state file contents.
- Confirm hosted tenant examples use local `conu-relay --tenant-upsert`, `--tenant-node-upsert`, `--tenant-node-revoke`, `--tenant-revoke`, `--tenant-audit`, guarded fleet `--hosted-fleet-tenant-upsert`/`--hosted-fleet-tenant-revoke`, and `--hosted-account-suspend`, or admin-gated online `conu-relay --admin-tenant-upsert`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, `--admin-tenant-revoke`, `--admin-tenant-audit`, and `--admin-hosted-account-suspend`, with metadata-only output and no claim that hosted permissions grant local peer policy.
- Confirm runtime relay client examples use either `CONU_RELAY_TOKEN` or `conu relay credential set --stdin`, and `conu relay credential status/clear` never display token material.
- Confirm identity-key rotation examples use `conu security rotate identity --confirm-peer-refresh`, then `conu identity export`, and optionally `conu security retire identity --confirm-peer-refresh-complete` only after peer-card refresh is complete; these commands must never display private signing/exchange keys or DPAPI blobs.
- Confirm non-Windows hardening docs explain `CONU_SECRET_WRAP_KEY_HEX` and `CONU_SECRET_WRAP_KEY_FILE`, and that the configured wrap key is operator-managed, never stored by conU, and never passed on the command line.
- Confirm cross-machine trust examples carry `signingPublicKeyHex`, `signatureHex`, and `signatureKeyId` from `conu identity export --json`, and peer imports reject tampered signed cards.
- Confirm cross-machine relay examples grant only intended surfaces with `conu peers policy` after peer trust and before remote sends/streams.
- Confirm room examples use `conu rooms policy` only for metadata-only per-topic publish/subscribe grants and explain that unconfigured topics still use room membership as the compatibility boundary.
- Confirm remote agent examples prefer automatic encrypted signed agent-card exchange during session sync, and manual fallback imports still carry signed agent-card fields from `conu agents export --json` with an already trusted peer node id and matching signing key.
- Confirm public relay examples use `wss://` when they describe internet-facing traffic, and state that `conu-relay` itself still needs TLS termination in front of it.
- Confirm public internet claims are limited to the current authenticated direct QUIC path for reachable configured endpoints, static direct candidate metadata with explicit NAT-unavailable reporting, daemon-pumped relay message, stream-chunk, room-event, signed-card control, same-node relay-session resume with optional file-backed session state, payload-safe local/admin-gated session-state audits, offline scoped credential issuance plus manifest upsert/rotate/revoke helpers, account-scoped online credential issue/rotate/revoke/audit/dashboard APIs, scoped hosted admin-token manifests and local audits, admin-gated online hosted tenant lifecycle and hosted account suspension for one configured relay registry, guarded local hosted-fleet account/node audit, tenant account upsert/revoke, tenant-node upsert/revoke, and account/node suspension, read-only admin mailbox audit API, confirm-gated admin mailbox purge API with reusable retention policy files, live-reloaded hashed relay credential manifest, metadata-only relay accounting/quotas, metadata-only relay abuse counters and scriptable threshold reports, guarded hosted-fleet abuse response plans, payload-safe local/admin-gated mailbox retention audits, confirm-gated local/admin, guarded local hosted-fleet mailbox, and relay-local scheduled mailbox purge workflows, local/admin-gated single-relay hosted-dashboard snapshots, guarded hosted-fleet-dashboard metadata snapshots with aggregate reusable mailbox retention policy checks and aggregate reusable abuse threshold checks, payload-safe local hosted-readiness preflights with reusable retention/threshold policy files, and bounded offline-mailbox paths unless distributed multi-instance session migration, adaptive hosted abuse automation beyond guarded response plans, remote relay/cross-region hosted mailbox retention orchestration beyond guarded local fleet cleanup, remote/distributed tenant lifecycle/workflow services, and ICE/STUN/TURN-style managed NAT traversal are implemented.

## Build

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -Toolchain stable-x86_64-pc-windows-gnu
python scripts\check-release-artifact-verifier.py
python scripts\check-release-artifact-smoke-preflight.py
python scripts\check-package-manager-manifests.py
python scripts\check-rpm-package-signing.py
python scripts\check-linux-release-signing.py
python scripts\check-linux-repository-signing.py
python scripts\check-hosted-linux-repositories.py
python scripts\check-hosted-linux-repository-site.py
python scripts\check-hosted-linux-repository-pages.py
python scripts\check-hosted-linux-repository-endpoint-regression.py
python scripts\check-hosted-linux-repository-s3-publication.py
python scripts\check-github-pages-readiness.py --repo imthegoodboy/conU
python scripts\check-github-release-clobber-preflight.py --repo imthegoodboy/conU --tag v0.1.0
python scripts\check-release-update-policy.py
python scripts\check-release-update-download-gate.py
conu update check --policy-file dist\conu-0.1.0-update-policy.json --gpg-verify
conu update check --policy-url https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json --gpg-verify
conu update download --policy-url https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json --output-dir dist\update-downloads --target linux-x64 --gpg-verify
conu update apply --policy-url https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json --artifact-file dist\update-downloads\conu-0.1.0-<current-target>.<ext> --install-dir C:\conu\bin --target <current-target> --gpg-verify --dry-run
python scripts\check-linux-gpg-public-key-export.py
python scripts\verify-npm-package-contents.py
python scripts\check-npm-publish-preflight.py
python scripts\check-npm-publish-preflight-regression.py
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64
python scripts\verify-release-artifacts.py dist
python scripts\smoke-release-artifacts.py dist
python scripts\smoke-npm-launcher-local.py dist
python scripts\smoke-npm-launcher-download.py dist
```

macOS/Linux:

```sh
cargo fmt --all -- --check
python scripts/verify-release-versions.py
python scripts/check-release-artifact-verifier.py
python scripts/check-release-artifact-smoke-preflight.py
python scripts/check-package-manager-manifests.py
python scripts/check-rpm-package-signing.py
python scripts/check-linux-release-signing.py
python scripts/check-linux-repository-signing.py
python scripts/check-hosted-linux-repositories.py
python scripts/check-hosted-linux-repository-site.py
python scripts/check-hosted-linux-repository-pages.py
python scripts/check-hosted-linux-repository-endpoint-regression.py
python scripts/check-hosted-linux-repository-s3-publication.py
python scripts/check-github-pages-readiness.py --repo imthegoodboy/conU
python scripts/check-github-release-clobber-preflight.py --repo imthegoodboy/conU --tag v0.1.0
python scripts/check-release-update-policy.py
python scripts/check-linux-gpg-public-key-export.py
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run check --prefix sdk/typescript
npm run check --prefix packaging/npm/conu-cli
python scripts/verify-npm-package-contents.py
python scripts/check-npm-publish-preflight.py
python scripts/check-npm-publish-preflight-regression.py
./scripts/build-release.sh
PACKAGE_SUFFIX=linux-x64 ./scripts/build-release.sh
PACKAGE_SUFFIX=macos-arm64 ./scripts/build-release.sh
python scripts/verify-release-artifacts.py dist
python scripts/smoke-release-artifacts.py dist
python scripts/smoke-npm-launcher-local.py dist
python scripts/smoke-npm-launcher-download.py dist
```

## Smoke

```powershell
.\scripts\smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu
.\scripts\smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu
.\scripts\smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

Manual installed smoke:

```sh
conu init
conu security audit
conu security rotate identity --confirm-peer-refresh
conu identity export
conu security retire identity --confirm-peer-refresh-complete
conu security rotate storage --confirm
conu security retire storage --confirm
conu doctor
conu telemetry snapshot --json
conu start
conu status
conu pair
conu join <code>
conu routes sync
conu identity export
conu connect
conu stop
```

## Privacy And Security

- `conu doctor` reports payload-safe logs.
- `conu logs rotate --max-bytes <bytes> --keep <count>` reports only file names, sizes, rotation counts, and `contentsDisplayed=false`; it must not print log contents.
- `conu telemetry snapshot --json` reports schema `conu.telemetry.snapshot.v1`, its explicit field allowlist, aggregate counters, and `contentsDisplayed=false`; it must not print node ids, agent ids, peer ids, endpoints, paths, log lines, key ids, secrets, or payload bodies.
- `conu security audit` reports initialized local controls, the secret storage backend, and whether local secret bytes are OS-protected. Windows should report `windows-dpapi-user`, macOS should report `macos-keychain-user`, Linux with Secret Service should report `linux-secret-service-user`, and a configured non-Windows user-managed wrap key should report `user-managed-wrap-key-v1` while keeping `secretsOsProtected = false`.
- macOS and Linux native secret storage smoke coverage follows `docs/native-secret-storage.md` where those platform services are available.
- `conu security rotate identity --confirm-peer-refresh` and `conu security retire identity --confirm-peer-refresh-complete` report only key ids, archive counts, refresh/confirmation booleans, compatibility status, and `contentsDisplayed=false`; they must not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- `conu security rotate storage --confirm` reports only old/new key ids and migration counts; it must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu security retire storage --confirm` reports only archived-key, migrated-file, and dependent-file counts; it must not print key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- `conu relay credential status --json` reports configuration/backend/protection status only, with `contentsDisplayed` false and no token fields.
- Hosted relay admin-token manifest audit reports only records, active/revoked/expired totals, account/scope counts, expiry bounds, and display guards, and it does not print raw admin tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, frame contents, or manifest contents.
- Hosted relay readiness preflight reports only configured paths, source booleans, counts, threshold checks/exceeded counts, warning totals, bind metadata, and display guards, and it does not print raw node tokens, admin tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, frame contents, policy contents, or manifest contents.
- Hosted relay admin issue/rotate/revoke/audit commands read admin tokens from stdin, enforce configured full-admin/scoped-admin token boundaries, do not print raw node tokens or token hashes, and report `tokenDisplayed=false` and `contentsDisplayed=false`.
- Hosted fleet credential revoke requires explicit dry-run or confirm, preflights every configured local credential source before mutation, does not contact remote relays, and reports only account/node ids, credential counts, paths, mode/status, and false display guards.
- Hosted fleet tenant account upsert/revoke requires explicit dry-run or confirm, preflights every configured local tenant source before mutation, does not contact remote relays, creates missing tenant files only for confirmed upsert, requires an existing account before revoke, and reports only account id, tenant/node counts, paths, mode/status, and false display guards.
- Hosted relay session-state audit commands read admin tokens from stdin, enforce full-admin/scoped-admin `sessions` scope and account/node boundaries, do not print relay session ids or file contents, and report `sessionIdDisplayed=false`, `tokenDisplayed=false`, and `contentsDisplayed=false`.
- CLI output does not show message text, prompt text, reasoning, file contents, private keys, shared secrets, or raw payload bytes.
- Logs use metadata-only fields such as `payload=not_observed`.
- Relay frames carry ciphertext bodies only; no plaintext payload fields are accepted or logged.
- Release archives do not include `CONU_HOME`, `.conu`, `node.toml`, `security/*.key`, `messages/`, `runtime/`, `logs/`, or `routes/` from a developer machine.
- MCP stdout remains JSON-RPC only.
- `conu_receive_message` and SDK receive APIs return payload bytes only to the addressed local agent by explicit request.
- TypeScript/JavaScript SDK payload helpers pass bytes through stdin and do not put payload contents in argv, logs, or wrapper output.
- TypeScript/JavaScript SDK raw inbox receive is explicit, addressed-agent scoped, and routed through `conu-mcp`/`conu_receive_message` rather than normal metadata listings.
- TypeScript/JavaScript SDK browser-conditioned exports fail closed and do not accept private keys, relay tokens, endpoint secrets, payload bytes, or account credentials.

## Packaging

- Release archive includes `bin/conu`, `bin/conud`, `bin/conu-relay`, and `bin/conu-mcp`.
- Release archive includes docs and the required packaging templates: Windows install/uninstall scripts, Linux systemd unit, macOS launchd plist, Docker relay files, and npm launcher install metadata.
- `manifest.toml` contains `payload_contents_included = false`.
- Release archive has a matching `.sha256` checksum file.
- macOS npm release assets are ZIP archives so Apple notarization can run on the distribution container.
- `scripts/verify-release-artifacts.py dist` passes for every archive, streams archive verification without loading every file body, requires strict `<sha256>  <archive-name>` checksum files, bounds archive/member/manifest sizes and member counts, and rejects duplicate paths, local conU state, logs, private key files, inboxes, route registries, telemetry dumps, node modules, vendored package binaries, and payload-bearing paths.
- `scripts/generate-package-manager-manifests.py dist --output-dir dist --version <version> --tag v<version>` generates package-native `conu.rb`, `conu.json`, `imthegoodboy.conU.yaml`, `conu.<version>.nupkg`, `conu_<version>_amd64.deb`, `conu_<version>_arm64.deb`, `.deb.sha256` sidecars, and `conu.spec` files from platform release assets and strict checksum files; with `--build-rpm-packages`, it also generates unsigned `conu-<rpm-version>-1.x86_64.rpm`, `conu-<rpm-version>-1.aarch64.rpm`, and `.rpm.sha256` sidecars for the later signing step; with `--build-apt-repository-metadata`, it also generates `conu-<debian-version>-apt-repository-metadata.zip` and a `.sha256` sidecar containing deterministic `Packages`, `Packages.gz`, and `Release` files for the generated `.deb` assets; with `--build-rpm-repository-metadata`, it also generates `conu-<rpm-version>-rpm-repository-metadata.zip` and a `.sha256` sidecar containing `createrepo_c` `repodata/*` files for the generated `.rpm` assets without embedding those RPM packages. `scripts/check-package-manager-manifests.py` passes in CI/release package checks, including native `rpmbuild -bb` validation for generated RPM build metadata and RPM release assets when RPM tooling is installed plus APT/RPM metadata hash checks.
- `scripts/sign-rpm-packages.py dist` signs only generated conU RPM packages with native RPM signatures after the imported Linux GPG key id resolves to the configured full maintainer fingerprint, verifies the signatures with a temporary RPM database containing the Linux release public key, and refreshes `.rpm.sha256` sidecars before RPM repository metadata is generated. `scripts/check-rpm-package-signing.py` passes in CI/release package checks when RPM signing tools are available and skips cleanly otherwise.
- `scripts/sign-linux-repository-metadata.py dist` verifies the imported Linux GPG key fingerprint, adds native APT `InRelease` and `Release.gpg` signatures, adds RPM `repodata/repomd.xml.asc`, verifies them, and refreshes the metadata ZIP `.sha256` sidecars before detached ZIP signatures are generated. `scripts/check-linux-repository-signing.py` passes in CI/release package checks.
- `scripts/export-linux-gpg-public-key.py dist` verifies the imported Linux GPG key fingerprint, then exports `conu-linux-gpg-key.asc` plus a strict `.sha256` sidecar from the configured Linux GPG signing key without writing private-key material. `scripts/check-linux-gpg-public-key-export.py` passes in CI/release package checks.
- `scripts/sign-linux-release-assets.py dist` verifies the imported Linux GPG key fingerprint, creates armored detached `.asc` signatures for Linux archives, generated Debian/RPM packages, generated APT/RPM repository metadata ZIPs, hosted repository artifacts, and update-policy JSON files present in `dist`, then verifies each signature before upload. `scripts/sign-linux-release-assets.py dist --only-hosted-repository-bundles` signs only generated hosted repository ZIPs after they are built, `--only-hosted-repository-sites` signs only generated hosted repository site ZIPs, and `--only-update-policies` signs only generated update-policy JSON files. `scripts/check-linux-release-signing.py` passes in CI/release package checks.
- `scripts/generate-hosted-linux-repositories.py dist --output-dir dist --version <version>` builds `conu-<version>-hosted-linux-repositories.zip` from the signed Debian/RPM packages, native APT/RPM repository metadata signatures, public Linux GPG key asset, detached package signatures, and strict sidecars. `scripts/check-hosted-linux-repositories.py` passes in CI/release package checks.
- `scripts/generate-hosted-linux-repository-site.py dist --output-dir dist --version <version> --base-url <https-url>` builds `conu-<version>-hosted-linux-repository-site.zip` from the signed hosted repository bundle, its strict sidecar, and its detached signature. It includes public repository files, `.nojekyll`, `index.html`, `repository.json`, `cache-policy.json`, `_headers`, APT/YUM install snippets, and `downloads/` copies of the signed bundle. `scripts/sign-linux-release-assets.py dist --only-hosted-repository-sites` signs only generated hosted repository site ZIPs after they are built. `scripts/generate-release-update-policy.py dist --output-dir dist --version <version> --tag v<version> --repo <owner/name>` then builds `conu-<version>-update-policy.json` from the final release asset set, strict sidecars, and required signatures, with public URLs, SHA-256 values, signature URLs, npm package versions, and `autoApply=false`; `scripts/sign-linux-release-assets.py dist --only-update-policies` signs only that generated policy. `scripts/prepare-hosted-linux-repository-pages.py dist --output-dir <site-dir>` verifies the site ZIP sidecar/signature, rejects unsafe or payload-bearing members, validates cache policy artifacts, and extracts an empty static directory ready for GitHub Pages or custom static hosting. `scripts/publish-hosted-linux-repository-s3.py <site-dir> --bucket <bucket> --prefix <prefix> --base-url <https-url> --confirm --post-upload-check` publishes that verified site to the supported S3-compatible target with per-object cache headers and then runs the live endpoint readiness check. `scripts/check-github-pages-readiness.py --repo <owner/name>` verifies live repository Pages metadata when the default Pages URL is used. `scripts/check-hosted-linux-repository-endpoint.py --base-url <https-url> --expected-version <version>` verifies a live custom endpoint after the signed site is published. `scripts/check-hosted-linux-repository-site.py`, `scripts/check-hosted-linux-repository-pages.py`, `scripts/check-hosted-linux-repository-endpoint-regression.py`, `scripts/check-hosted-linux-repository-s3-publication.py`, `scripts/check-release-update-policy.py`, and `scripts/check-github-pages-readiness-regression.py` pass in CI/release package checks.
- `scripts/check-github-release-assets-published.py --repo <owner/name> --tag v<version>` passes after GitHub Release publication and before npm publication, proving the public release has every required platform archive, checksum, Linux signature, public-key, package-manager, hosted repository bundle, hosted repository site, and update-policy asset by name with positive uploaded metadata and no duplicate or forbidden state/secret-looking asset names.
- `scripts/check-release-artifact-smoke-preflight.py` passes in CI/release package checks, and `scripts/smoke-release-artifacts.py dist`, `scripts/smoke-npm-launcher-local.py dist`, and `scripts/smoke-npm-launcher-download.py dist` pass on each release build runner before attestation/upload.
- Windows install script copies binaries to a current-user install directory.
- Linux systemd template is present and documents the required user/state path edits.
- macOS launchd template is present and documents the required user/state path edits.
- Docker relay template is present and documents current relay limits and knobs.
- npm launcher package passes `npm run check` from `packaging/npm/conu-cli`; `scripts/check-npm-launcher-local-smoke-preflight.py` proves local smoke fixture failures for missing binary directories, missing binaries, and non-file binary paths; the local npm launcher install smoke first requires `CONU_NPM_BINARY_DIR` to be an existing directory with regular files for every expected binary before copying release binaries into the package vendor directory, and the download install smoke verifies the default HTTPS-or-loopback archive download policy, bounded timeout/size behavior, strict `.sha256` archive-name matching, streamed archive hashing, archive-member count/duplicate/state-path preflight, bounded extracted-tree scanning, exact extracted release-root binary selection, extraction, npm bin shims, and `ready_for_local_use` launcher path.
- `scripts/verify-npm-package-contents.py` passes for `@conu/cli` and `@conu/sdk`, proving the npm dry-run tarballs contain only the expected package files and no local state, build output, vendored native binaries, secrets, or bundled dependencies.
- Local `dist/` directories may include `conu-<version>-host` archives for developer builds; the npm download smoke skips those aliases when the matching platform-named npm asset and checksum are present.
- TypeScript/JavaScript SDK package passes `npm run check --prefix sdk/typescript`.

## Platform Signing

- Repository signing secrets are configured before a `v*` tag release:
  `CONU_WINDOWS_SIGN_CERT_PFX_BASE64`, `CONU_WINDOWS_SIGN_CERT_PASSWORD`,
  `CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64`,
  `CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD`,
  `CONU_MACOS_CODESIGN_IDENTITY`, `CONU_MACOS_NOTARY_APPLE_ID`,
  `CONU_MACOS_NOTARY_TEAM_ID`, `CONU_MACOS_NOTARY_PASSWORD`,
  `CONU_LINUX_GPG_PRIVATE_KEY_BASE64`, `CONU_LINUX_GPG_PASSPHRASE`,
  `CONU_LINUX_GPG_KEY_ID`, and `CONU_LINUX_GPG_KEY_FINGERPRINT`.
- After exporting the required values locally, run
  `python scripts/set-github-release-secrets.py --repo <owner/name> --dry-run --preflight-values --require-openssl`
  to validate Windows/macOS PKCS#12 values and Linux GPG signing values before
  any GitHub writes.
- After that dry run passes, rerun without `--dry-run` to configure the
  repository secrets through GitHub CLI stdin without printing values. If the
  combined preflight fails, run the individual platform or Linux signing
  preflight script directly for a sanitized diagnostic report.
- Tagged release preflight imports the configured Linux GPG private key into a
  temporary keyring, verifies `CONU_LINUX_GPG_KEY_ID` resolves to
  `CONU_LINUX_GPG_KEY_FINGERPRINT`, and probe-signs a temporary file before
  package checks or platform builds run.
- Tagged release preflight also verifies the tag target commit has a completed,
  successful `CI` workflow run before package checks or platform builds run.
- Repository `NPM_TOKEN` is configured before a `v*` tag release so tagged npm
  publication cannot silently skip after GitHub Release assets are created.
- Windows release ZIPs contain Authenticode-signed binaries. Verify after extraction:

```powershell
Get-AuthenticodeSignature .\bin\conu.exe
Get-AuthenticodeSignature .\bin\conud.exe
Get-AuthenticodeSignature .\bin\conu-relay.exe
Get-AuthenticodeSignature .\bin\conu-mcp.exe
```

- macOS release ZIPs contain Developer ID-signed binaries and are submitted to Apple notarization by the release workflow. Verify after extraction:

```sh
codesign --verify --strict --verbose=2 bin/conu
codesign --verify --strict --verbose=2 bin/conud
codesign --verify --strict --verbose=2 bin/conu-relay
codesign --verify --strict --verbose=2 bin/conu-mcp
spctl -a -vv -t exec bin/conu
```

- Linux release tarballs use SHA-256 checksum files, GitHub artifact attestations, and detached `.asc` signatures. Generated Debian packages use SHA-256 sidecars and detached `.asc` signatures. Generated RPM packages use native RPM signatures, refreshed SHA-256 sidecars, and detached `.asc` signatures. Generated APT/RPM metadata ZIPs include native repository signatures plus refreshed SHA-256 sidecars and detached `.asc` signatures. Generated hosted Linux repository bundles include signed `apt/` and `rpm/` static trees, strict sidecars, and their own detached `.asc` signature. Generated hosted Linux repository site artifacts include public endpoint metadata, install snippets, and checked cache policy files plus their own strict sidecar and detached `.asc` signature:

```sh
sha256sum -c conu-linux-gpg-key.asc.sha256
EXPECTED_CONU_LINUX_GPG_FINGERPRINT=<published-40-hex-maintainer-fingerprint>
gpg --show-keys --with-colons conu-linux-gpg-key.asc | awk -F: '/^fpr:/ {print $10; exit}' | grep -Fx "$EXPECTED_CONU_LINUX_GPG_FINGERPRINT"
gpg --import conu-linux-gpg-key.asc
sha256sum -c conu-0.1.0-linux-x64.tar.gz.sha256
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
gpg --verify conu-0.1.0-linux-x64.tar.gz.asc conu-0.1.0-linux-x64.tar.gz
```

- Signing workflows and logs do not print certificates, private keys, signing passwords, GPG private keys, GPG passphrases, npm tokens, relay tokens, local conU state, or payload contents.
- See `docs/platform-code-signing.md` for the full signing policy and secret names.

## GitHub

- CI passed on pull request or equivalent local validation is recorded, including the Rust OS matrix and the package job for `sdk/typescript` plus `packaging/npm/conu-cli`.
- CI and release package jobs run `scripts/verify-release-versions.py` before npm package checks, so package versions must match each other and `v*` tag names before release assets can be built or published.
- CI and release package jobs run `scripts/check-release-artifact-verifier.py` before artifact builds, so release archive verification regressions fail before platform artifacts are generated.
- CI and release package jobs run `scripts/check-release-artifact-smoke-preflight.py` before artifact builds, so release artifact smoke preflight regressions fail before platform artifacts are generated.
- CI and release package jobs install RPM tooling plus `createrepo-c`, `gnupg`, and `openssl`, run `scripts/check-package-manager-manifests.py`, `scripts/check-package-manager-submissions.py`, `scripts/check-linux-signing-secrets-preflight-regression.py`, `scripts/check-platform-signing-secrets-preflight-regression.py`, `scripts/check-rpm-package-signing.py`, `scripts/check-linux-release-signing.py`, `scripts/check-linux-repository-signing.py`, `scripts/check-hosted-linux-repositories.py`, `scripts/check-hosted-linux-repository-site.py`, `scripts/check-hosted-linux-repository-pages.py`, `scripts/check-hosted-linux-repository-endpoint-regression.py`, `scripts/check-hosted-linux-repository-s3-publication.py`, `scripts/check-release-update-policy.py`, `scripts/check-release-update-download-gate.py`, `scripts/check-github-pages-readiness-regression.py`, `scripts/check-tagged-release-readiness-regression.py`, `scripts/check-github-release-assets-published-regression.py`, and `scripts/check-linux-gpg-public-key-export.py` before artifact builds, so generated package-manager manifest, package-manager submission bundle, APT/RPM metadata, RPM spec build, optional RPM asset, Linux signing-secret preflight, Windows/macOS signing-secret value preflight, native RPM package-signing, fingerprint-pinned Linux detached-signing, native Linux repository-signing, hosted Linux repository bundle/site/Pages deployment prep, hosted S3 publication, hosted endpoint cache-header readiness, release update-policy metadata, release update download/apply dry-run gate, GitHub Pages setting readiness, tagged release live-readiness plus target-CI/default-branch reporting, GitHub Release asset publication, and Linux public-key export regressions fail before tag publication paths are used.
- CI, release package checks, and tagged npm publication run `scripts/verify-npm-package-contents.py` so `@conu/cli` and `@conu/sdk` package dry-runs fail closed on missing required files, unexpected files, forbidden state/build/payload paths, oversized files, or bundled dependencies.
- CI and release package checks run `scripts/check-npm-publish-preflight.py` and `scripts/check-npm-publish-preflight-regression.py`; tagged npm publication reruns the preflight with `--registry-check --require-token-env NODE_AUTH_TOKEN` before publishing either package, so an already-published `@conu/cli` or `@conu/sdk` version fails before a partial publish starts.
- npm package checks, content dry-runs, and publication jobs run on Node 24 LTS, and package `engines` accept supported Node LTS lines only. Revisit the range when the next Node LTS line is promoted.
- CI and release workflows use GitHub JavaScript action versions that declare the Node 24 action runtime, avoiding older action-runtime deprecation warnings. Self-hosted runners must be new enough for those actions before release workflows are moved off GitHub-hosted runners.
- Migration-sensitive GitHub-hosted runner labels are explicit: Windows release/CI jobs run on `windows-2025-vs2026` while the Visual Studio 2026 migration is active, macOS arm64 jobs run on `macos-15`, and macOS x64 release jobs run on `macos-15-intel`. Revisit the Windows label after GitHub completes the June 2026 migration.
- After changing CI or release action versions, run the `Release Artifacts` workflow with `workflow_dispatch` on `main`, verify package checks, every platform build, artifact attestations, and artifact uploads pass, and confirm GitHub Release/npm publication jobs skip on the non-tag run while the tagged-release preflight remains fail-closed for missing signing or npm secrets.
- PR body lists validation commands.
- The `Release Artifacts` workflow is green for the release tag, including archive verification, archive install smoke, npm launcher local install smoke, and npm launcher download install smoke with bounded download behavior.
- GitHub Release has platform-named archives plus matching `.sha256` files before npm publishing.
- GitHub Release has generated `conu.rb`, `conu.json`, `imthegoodboy.conU.yaml`, `conu.<version>.nupkg`, `conu_<version>_amd64.deb`, `conu_<version>_arm64.deb`, `.deb.sha256` sidecars, `conu-<debian-version>-apt-repository-metadata.zip` containing `InRelease` and `Release.gpg` plus its refreshed `.sha256` sidecar, `conu.spec`, signed `conu-<rpm-version>-1.x86_64.rpm`, signed `conu-<rpm-version>-1.aarch64.rpm`, refreshed `.rpm.sha256` sidecars, `conu-<rpm-version>-rpm-repository-metadata.zip` containing `repodata/repomd.xml.asc` plus its refreshed `.sha256` sidecar generated from the signed RPM packages, `conu-linux-gpg-key.asc` plus its `.sha256` sidecar, signed `conu-<version>-package-manager-submissions.zip` plus `.sha256` sidecar, `conu-<version>-hosted-linux-repositories.zip` plus `.sha256` and `.asc` sidecars, `conu-<version>-hosted-linux-repository-site.zip` plus `.sha256` and `.asc` sidecars, and detached `.asc` signatures for Linux archives, generated Debian/RPM packages, package-manager submission bundle, and APT/RPM repository metadata ZIPs derived from the same strict release checksums before package-manager submission.
- When `CONU_LINUX_REPOSITORY_BASE_URL` is not set, the tagged release workflow prepares the signed hosted repository site ZIP into a verified static directory and deploys it with GitHub Pages Actions. If a custom repository base URL is configured, set `CONU_LINUX_REPOSITORY_S3_BUCKET`, optional `CONU_LINUX_REPOSITORY_S3_PREFIX`, optional `CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL`, optional `CONU_LINUX_REPOSITORY_AWS_REGION`, and secrets `CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID` plus `CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY`; the tagged workflow publishes the verified site to that S3-compatible target with generated cache headers and runs `scripts/check-hosted-linux-repository-endpoint.py` against the live URL before npm publication. DNS records, certificates, CDN invalidation, and non-S3 static hosts remain operator-owned.
- GitHub artifact attestations exist for every platform archive and checksum file generated by the release workflow.
- Verify a downloaded archive's provenance before install when `gh` is available:

```sh
gh attestation verify ./conu-0.1.0-linux-x64.tar.gz -R imthegoodboy/conU
```

- `@conu/cli` and `@conu/sdk` npm package content verification passes before publication.
- `@conu/cli` and `@conu/sdk` are published only after the matching GitHub Release assets are available; the tagged release preflight requires the repository `NPM_TOKEN` secret for automated npm publication with provenance, and the npm publish conflict preflight confirms both target package versions are absent from npm before any publish command runs.
- Platform signing workflow is implemented for tagged releases: Windows Authenticode, macOS Developer ID signing/notarization, Linux SHA-256 plus GitHub artifact attestations, native RPM package signatures, native APT/RPM repository signatures, and detached GPG `.asc` signatures.
- `plan.md` completion log is updated.
- Issue is closed by PR merge.

## Release Decision

Use one of:

```txt
local_release_ready
needs_fix
blocked
```

Current decision target is `daemon_relay_message_stream_chunk_room_topic_policy_durable_mailbox_session_state_audit_admin_session_state_audit_mailbox_audit_admin_mailbox_audit_mailbox_purge_admin_mailbox_purge_hosted_fleet_mailbox_purge_hosted_fleet_account_audit_hosted_fleet_account_node_audit_hosted_fleet_tenant_account_lifecycle_hosted_fleet_tenant_node_lifecycle_hosted_fleet_account_suspension_hosted_fleet_account_node_suspension_hosted_fleet_abuse_response_plan_mailbox_retention_policy_files_scheduled_mailbox_purge_live_reloaded_hashed_relay_credential_manifest_account_admin_lifecycle_scoped_admin_token_manifest_admin_token_audit_admin_tenant_lifecycle_hosted_account_suspension_tenant_registry_accounting_quotas_abuse_counters_abuse_threshold_reports_hosted_dashboard_snapshot_hosted_relay_readiness_preflight_admin_hosted_dashboard_snapshot_session_resume_session_state_authenticated_direct_quic_log_rotation_identity_key_rotation_and_retirement_storage_key_rotation_and_retirement_windows_dpapi_macos_keychain_linux_secret_service_nonwindows_user_managed_secret_wrap_key_stored_relay_client_credentials_local_capabilities_signed_agent_cards_peer_policy_auto_agent_card_exchange_attested_release_archives_and_platform_signing_workflow_ready_with_known_limits`. Public hosted/internet release remains blocked until distributed multi-instance session migration, distributed hosted dashboards/accounting/adaptive abuse automation beyond single-relay threshold reports, guarded fleet response plans, and readiness preflights, remote relay/cross-region hosted mailbox retention orchestration beyond guarded local fleet cleanup, remote/distributed tenant lifecycle/workflow services beyond guarded local fleet account/node audit, tenant account lifecycle, tenant-node lifecycle, account/node suspension plus scoped single-relay account suspension/admin tokens, tenant-wide hosted dashboard workflow services, and managed NAT traversal are finished.
