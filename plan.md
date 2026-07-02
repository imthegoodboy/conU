# conU Build Plan

This is the living execution plan for conU. Future agents must update this file when a phase is completed or materially changed.

## Update Rules For Agents

At the end of each completed phase, update:

- phase status
- summary of completed work
- files changed
- validation run
- known gaps
- recommended next phase

Do not mark a phase complete unless the implementation exists and validation was attempted. If validation cannot run, record why.

Status values:

```txt
not_started
in_progress
blocked
completed
needs_revision
```

## Current Status

```txt
Current phase: Phase 14 - Rooms, Pub/Sub, And Multi-Agent Sessions
Status: completed
Last updated: 2026-05-30
Note: Phase 14 and Phase 15 are complete for the current local-first app. Post-Phase-15 relay data-plane, CLI polish, daemon relay hardening, distribution/hosting, Phase 14 local rooms/pub-sub, relay abuse-control, reusable daemon relay-session, same-node relay-session resume, public-bind token-guard, `wss://` relay-client, static scoped relay credential/session-policy, offline scoped relay credential issuance, relay credential manifest upsert/rotate/revoke helpers, account-scoped online hosted relay credential issue/rotate/revoke/audit, scoped hosted admin-token manifest RBAC for credential/tenant/dashboard/session/mailbox actions, payload-safe local scoped admin-token manifest audit, payload-safe hosted relay readiness preflight, admin-gated online hosted relay dashboard snapshots, local/admin-gated hosted abuse threshold reports with reusable policy files and optional fail-on-threshold exit status, metadata-only hosted tenant registry, admin-gated online hosted tenant lifecycle, local and admin-gated hosted account suspension, guarded hosted fleet account/node audit, guarded hosted fleet account/node credential revoke, hosted fleet tenant account upsert/revoke, hosted fleet tenant-node upsert/revoke, and guarded hosted fleet account/node suspension, live-reloaded hashed relay credential manifest, relay accounting/quotas, metadata-only relay abuse/dashboard counters, payload-safe hosted relay dashboard snapshots, payload-safe hosted relay readiness preflights, guarded hosted fleet dashboard snapshots with aggregate mailbox retention policy gates and aggregate abuse threshold checks, guarded hosted fleet abuse response plans, guarded hosted fleet mailbox purge orchestration, relay session state storage, payload-safe local/admin-gated relay session-state audit, direct route selection guard, authenticated direct QUIC probing and message/stream-chunk delivery for reachable trusted peers, static direct candidate metadata with NAT-unavailable reporting, payload-safe local log rotation, structured telemetry snapshot, identity-key rotation with peer-card refresh, identity archive retirement after peer-card refresh, storage-key rotation/re-encryption migration, storage-key retirement, relay-backed stream-chunk, relay-backed room-event fanout, room topic policy, bounded offline relay mailbox, durable relay mailbox storage, payload-safe durable mailbox retention audit, admin-gated online durable mailbox retention audit, reusable durable mailbox retention policy files, confirm-gated local, admin-gated online, and guarded hosted fleet durable relay mailbox purge, relay-local scheduled durable relay mailbox purge, durable mailbox FIFO reload ordering, bounded relay sync wait handling, Windows DPAPI secret wrapping, macOS Keychain/Linux Secret Service secret storage, non-Windows user-managed secret wrapping, stored relay client credential, signed peer-card, local capability-enforcement, signed remote agent-card, peer-scoped permission-policy, automatic encrypted signed agent-card exchange, TypeScript/JavaScript SDK wrapper, TypeScript explicit addressed-agent receive helper, TypeScript browser boundary hardening, GitHub CI package-validation passes, release publishing workflow hardening, GitHub artifact attestation release hardening, platform signing/notarization workflow hardening, tagged release preflight hardening, Node LTS package hardening, npm installer download timeout/size hardening, npm download smoke host-archive handling, npm package content verification, release artifact verifier bounds, npm installer strict checksum verification, npm installer extracted binary selection hardening, npm installer extracted-tree traversal bounds, npm installer archive-member preflight hardening, package-manager manifest generation preflight, native RPM package build preflight, unsigned RPM release asset generation, unsigned APT repository metadata generation, unsigned RPM repository metadata generation, Linux detached release signatures, signed Linux repository metadata, Linux GPG public key release asset publication, RPM package payload signing, Linux signing key fingerprint policy, release secret automation, hosted Linux repository bundle generation, hosted Linux repository site artifact generation, default GitHub Pages hosted Linux repository deployment prep, GitHub Pages readiness preflight, hosted Linux repository cache policy artifacts, signed release update policy metadata, tagged public release update download gating, manual release update apply, tagged public release update apply dry-run gating, hosted Linux repository endpoint cache-header readiness, custom S3-compatible hosted Linux repository publication, and verified package-manager submission bundle generation are complete. Public hosted internet readiness remains scoped by the known distributed hosted accounting/dashboards/adaptive abuse automation beyond local/admin-gated single-relay snapshots, guarded fleet snapshots, threshold reports, guarded response plans, and readiness preflights, distributed multi-instance session migration, ICE/STUN/TURN managed direct NAT traversal, managed hosted identity/key administration, remote/distributed tenant lifecycle/workflow automation beyond guarded local fleet account/node audit, fleet credential revoke, fleet tenant account lifecycle, and account/node suspension plus single-relay account suspension/scoped admin tokens, tenant-wide hosted dashboard workflow services, DNS/certificate/CDN provisioning and non-S3 custom repository host automation, unattended automatic update apply, and remote relay/cross-region mailbox retention orchestration beyond guarded local fleet cleanup.
Latest completed hardening addition: release smoke archive root guard is complete; PR #303 merged to `main` at merge commit `f5b13df2fd9ad34f6d5d3db874ed93f4ed2964fd`, Issue #302 is closed, and branch `release-smoke-root-guard` is preserved. Prior completed hardening addition: release archive root guard is complete; PR #301 merged to `main` at merge commit `52221eb28d2230bdebe9b7b22c01d15425167b86`, Issue #300 is closed, and branch `update-archive-root-guard` is preserved. Prior completed hardening addition: Rust update public-host IP guard is complete; PR #299 merged to `main` at merge commit `28ffb06dfcda58929f3449030f4f036a9305c44a`, Issue #298 is closed, and branch `update-ipv6-public-host-guard` is preserved. Prior completed hardening addition: npm download redirect boundary is complete; PR #297 merged to `main` at merge commit `9a9479152f90562a6874c1f3d4f589749aef17f0`, Issue #296 is closed, and branch `npm-download-redirect-boundary` is preserved. Prior completed hardening addition: npm unverified download loopback gate is complete; PR #295 merged to `main` at merge commit `2cbc38fab99eac7a462b8841063e6634e2c10405`, Issue #294 is closed, and branch `npm-unverified-loopback-only` is preserved. Prior completed hardening addition: Release secret env-file readiness gate is complete; PR #293 merged to `main` at merge commit `03ddbf9afab0a118b88469ce0a9a9c7f85681fb8`, Issue #292 is closed, and branch `release-secret-env-file-readiness-gate` is preserved. Prior completed hardening addition: Release secret env-file validation is complete; PR #291 merged to `main` at merge commit `11be300e67bf77c58ca4c446e3865a917d2a0bb9`, Issue #290 is closed, and branch `release-secret-env-file-check` is preserved. Prior completed hardening addition: Release secret env-file-only setup is complete; PR #289 merged to `main` at merge commit `b00d63128f4bf87ae8e7b62ee3eb6c22eb5820af`, Issue #288 is closed, and branch `release-secret-env-file-only` is preserved. Prior completed hardening addition: Release secret env-file template is complete; PR #286 merged to `main` at merge commit `55f1f2bce00f7bf499c19f7c40befa96ef891874`, Issue #285 is closed, and branch `release-secret-template` is preserved. Prior completed hardening addition: Release secret env-file setup is complete; PR #284 merged to `main` at merge commit `53d0f1ce1c0f34a5bceaa1de31be76cb6bd6126b`, Issue #283 is closed, and branch `release-secret-env-file-setup` is preserved. Prior completed hardening addition: Rust `time` Dependabot alert fix is complete; PR #282 merged to `main` at merge commit `6bb587c48ea64cba160abaf6675a6a50863395dd`, Issue #281 is closed, and branch `rust-time-dependabot-alert` is preserved. Prior completed hardening addition: Platform signing secret value preflight is complete; PR #265 merged to `main` at merge commit `b5bcd6db7e3b7a5538931bf27e4b9dcef05e3584`, Issue #264 is closed, and branch `platform-signing-secret-value-preflight` is preserved. Prior completed hardening addition: Tagged release readiness audit is complete; PR #263 merged to `main` at merge commit `09ed3f556d5edbf3d555455192b5da8487158e85`, Issue #262 is closed, and branch `tagged-release-readiness-audit` is preserved. Prior completed hardening addition: Verified package-manager submission bundle is complete; PR #261 merged to `main` at merge commit `0579593bf50cdc31b10db9819d979776014207ce`, Issue #260 is closed, and branch `package-manager-submission-bundle` is preserved. Prior completed hardening addition: Custom S3-compatible hosted Linux repository publication is complete; PR #259 merged to `main` at merge commit `04f4f8eccc3fb441c5057b5fdbc61353bda4591b`, Issue #258 is closed, and branch `custom-linux-repository-s3-publication` is preserved. Prior completed hardening addition: Hosted Linux repository endpoint readiness is complete; PR #257 merged to `main` at merge commit `d94e03e8977a4733e2afaddfe55ef0b6864a36fd`, Issue #256 is closed, and branch `hosted-linux-repository-endpoint-readiness` is preserved. Prior completed hardening addition: Tagged public release update apply dry-run gate is complete; PR #255 merged to `main` at merge commit `5d303b32112689e000525a77a78f2258a99a9bf5`, Issue #254 is closed, and branch `published-update-apply-gate` is preserved. Prior completed hardening addition: Manual release update apply is complete; PR #253 merged to `main` at merge commit `75063c66519c5c04c20d1a5a4662198f17cefde0`, Issue #252 is closed, and branch `manual-update-apply` is preserved. Prior completed hardening addition: Tagged public release update download gate is complete; PR #251 merged to `main` at merge commit `cd1281d5d020ab5e60b082dffba9813df6b8bba2`, Issue #250 is closed, and branch `published-update-download-gate` is preserved. Prior completed hardening addition: Verified release update artifact download is complete; PR #249 merged to `main` at merge commit `4c797fcaeede2502928dda15ca0f5f418db245ac`, Issue #248 is closed, and branch `verified-update-artifact-download` is preserved. Prior completed hardening addition: Remote release update policy HTTPS checks are complete; PR #247 merged to `main` at merge commit `0aee3926c05c45e2f1b168f0fb03808c6dd23a4d`, Issue #246 is closed, and branch `release-update-remote-check` is preserved. Prior completed hardening addition: Installed release update policy checks are complete; PR #245 merged to `main` at merge commit `69d18e56683f6f106da28901f3543d5f932246c4`, Issue #244 is closed, and branch `release-update-client-check` is preserved. Prior completed hardening addition: Release update policy metadata is complete; PR #243 merged to `main` at merge commit `0d8973400230a9386f92a53bce25667e46adecd4`, Issue #242 is closed, and branch `release-update-policy-metadata` is preserved. Prior completed hardening addition: Hosted Linux repository cache policy artifacts are complete; PR #241 merged to `main` at merge commit `2f667a3a3af007ac25acb25fc7b5337a4aaea285`, Issue #240 is closed, and branch `hosted-linux-repository-cache-policy` is preserved. Prior completed hardening addition: GitHub Release clobber safety preflight is complete; PR #239 merged to `main` at merge commit `0a197a42f6181828d0cc481c60a037fddeb1a7b1`, Issue #238 is closed, and branch `github-release-clobber-preflight` is preserved. Prior completed hardening addition: GitHub Release asset publication preflight is complete; PR #237 merged to `main` at merge commit `0c5c2838a4a297454c99470af626e1a34f8ac46a`, Issue #236 is closed, and branch `github-release-assets-preflight` is preserved. Prior completed hardening addition: GitHub Pages readiness preflight is complete; PR #235 merged to `main` at merge commit `7019487232433ad451724b67ae0b15ebe59beaee`, Issue #234 is closed, and branch `github-pages-readiness-preflight` is preserved. Prior completed hardening addition: Hosted Linux repository GitHub Pages deployment prep is complete; PR #233 merged to `main` at merge commit `60a02a47a5399cb3e5043023e369d814b17edc89`, Issue #232 is closed, and branch `linux-repository-pages-deploy` is preserved. Prior completed hardening addition: Hosted Linux repository site artifact generation is complete; PR #231 merged to `main` at merge commit `5b44b9219fa520784cb40e72c75a037877c46c26`, Issue #230 is closed, and branch `hosted-linux-repository-site` is preserved. Prior completed hardening addition: Hosted Linux repository bundle generation is complete; PR #229 merged to `main` at `7a1a03a2d75417f1ec07500ac909817d3957cadc`, Issue #228 is closed, and branch `hosted-linux-repository-bundles` is preserved. Prior completed hardening addition: Linux signing secret preflight is complete; PR #221 merged to `main` at `16445ddd9e5d836d02dbf8edf2dcf6d95befc21d`, Issue #220 is closed, and branch `linux-signing-secret-preflight` is preserved. Prior completed hardening addition: Linux signing key fingerprint policy is complete; PR #219 merged to `main` at `cea2817bba74a297de2912436b03f21b4b3a79e3`, Issue #218 is closed, and branch `linux-gpg-fingerprint-policy` is preserved. Prior completed hardening addition: RPM package payload signing is complete; PR #217 merged to `main` at `d6976db94148a2583bf1fd978b0dba68b45c9b77`, Issue #216 is closed, and branch `rpm-package-payload-signing` is preserved. Prior completed hardening addition: Linux GPG public key release asset is complete; PR #215 merged to `main` at `7f81b682044c8eb5bbdfbe952ef933ecd0295c93`, Issue #214 is closed, and branch `linux-gpg-public-key-release-asset` is preserved. Prior completed hardening addition: signed Linux repository metadata is complete; PR #213 merged to `main` at `ac867bcb3d34ad78acb6d660c3443424b2eb22d7`, Issue #212 is closed, and branch `signed-linux-repository-metadata` is preserved. Prior completed hardening addition: Linux detached release signatures are complete; PR #211 merged to `main` at `a3795510370876f5ef0a27b873f70790f23d3923`, Issue #210 is closed, and branch `linux-detached-signatures` is preserved. Prior completed hardening addition: unsigned RPM repository metadata generation is complete; PR #209 merged to `main` at `9e2a3f475250363997d6006c278c3f4ff2f7b85d`, Issue #208 is closed, and branch `rpm-repository-metadata` is preserved. Prior completed hardening addition: unsigned APT repository metadata generation is complete; PR #207 merged to `main` at `f2f7c993e658b31d4a77c3c45059a12fb2f7c986`, Issue #206 is closed, and branch `apt-repository-metadata` is preserved. Prior completed hardening addition: unsigned RPM release asset generation is complete; PR #205 merged to `main` at `4048a7fab4b454ed28e782b169906fb60d97dce8`, Issue #204 is closed, and branch `rpm-release-assets` is preserved. Prior completed hardening addition: native RPM package build preflight is complete; PR #203 merged to `main` at `98b2ef7a1aba3eb0cc5e6f10fb4e36560105f3d4`, Issue #202 is closed, and branch `rpm-native-build-preflight` is preserved. Prior completed hardening addition: Debian package and RPM spec generation is complete; PR #201 merged to `main` at `4023297af7554bddab1cc6e0d1bb0a4c06e5fc98`, Issue #200 is closed, and branch `linux-package-manager-preflight` is preserved. Prior completed hardening addition: winget and Chocolatey package-manager generation is complete; PR #199 merged to `main` at `e9230e129b5c2ebb1b0f24cc7db0f7b0b79c3176`, Issue #198 is closed, and branch `windows-package-manifest-preflight` is preserved. Prior package-manager manifest generation preflight is complete; PR #197 merged to `main` at `4f4e25dd46bbbce3d00d0227ccdb8edeb80c6f9d`, Issue #196 is closed, and branch `package-manager-manifest-preflight` is preserved. Prior npm publish conflict preflight hardening is complete; PR #195 merged to `main` at `14f73b65808ff204b1e23f3ee1980c1b7c89dcb1`, Issue #194 is closed, and branch `npm-publish-conflict-preflight` is preserved. Prior release artifact smoke binary preflight hardening is complete; PR #193 merged to `main` at `321359293396bd6b95d69c63f1d544afed707c91`, Issue #192 is closed, and branch `release-artifact-smoke-binary-preflight` is preserved. Prior npm launcher local smoke binary preflight hardening is complete in PR #191 on branch `npm-smoke-local-binary-preflight`; PR #191 merged to `main` at `cfa5ba0a9e66a04196987d23919d8b965a832b4d`, Issue #190 is closed, and the branch is preserved. Prior npm installer local binary directory preflight hardening is complete in PR #189 on branch `npm-installer-local-binary-dir-guard`; PR #189 merged to `main` at `0ca33f50bdf82b2e6d44a576f67c6e3fa643f473`, and Issue #188 is closed.
```

Current latest hardening addition: local log rotation file handling hardening is
complete; PR #419 merged to `main` at merge commit
`51c5cbcd051536ea254cf9ea598d1e0af6be3a51`, Issue #418 is closed, and branch
`log-rotation-file-guard` is preserved. Validation:
`cargo fmt --all -- --check`, `git diff --check`, release-version check,
`cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets`,
`cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings`,
and PR CI passed. Local Rust test execution was attempted but this workstation is
missing `dlltool.exe`; PR CI covered Rust on Ubuntu, macOS, and Windows. Prior
completed hardening addition: local secret file symlink hardening is
complete; PR #417 merged to `main` at merge commit
`cea78dc8b03669905c48eaa51850c4d05a0b5106`, Issue #416 is closed, and branch
`secret-file-symlink-guard` is preserved. Prior completed hardening addition:
message delivery receipt collision hardening is
complete; PR #415 merged to `main` at merge commit
`ac78cbe3d5b258269f2c344f07d147b3d323bf88`, Issue #414 is closed, and branch
`message-delivery-receipt-guard` is preserved. Prior completed hardening
addition: pairing invite file collision hardening is
complete; PR #413 merged to `main` at merge commit
`41489fdba3daca1a8b0eecfeecd77b3d5b752c3f`, Issue #412 is closed, and branch
`pairing-invite-collision-guard` is preserved. Prior completed hardening
addition: message IPC marker collision hardening is
complete; PR #411 merged to `main` at merge commit
`7406ac1e403ceb82dc627ec9346f1dc29fb07813`, Issue #410 is closed, and branch
`message-ipc-marker-collision-guard` is preserved. Prior completed hardening
addition: request archive marker collision hardening is
complete; PR #409 merged to `main` at merge commit
`071526f7b671d379b06e3c1d1f04f60ea4360e44`, Issue #408 is closed, and branch
`request-archive-collision-guard` is preserved. Prior completed hardening
addition: release update backup restore read
hardening is complete; PR #407 merged to `main` at merge commit
`95b4c64918491072ecdbd95289c04a621925dc80`, Issue #406 is closed, and branch
`update-backup-restore-read-guard` is preserved. Prior completed hardening
addition: release update binary permission handle hardening
is complete; PR #405 merged to `main` at merge commit
`c62d2c3600b152cf68b159093fc132b4888540c8`, Issue #404 is closed, and branch
`update-binary-permission-handle` is preserved. Prior completed hardening
addition: release update staged source read hardening is
complete; PR #403 merged to `main` at merge commit
`b25710ba87fc8eae128e4e1ee399dd14c95b9c94`, Issue #402 is closed, and branch
`update-staged-source-read-guard` is preserved. Prior completed hardening
addition: release update final install target replacement
hardening is complete; PR #401 merged to `main` at merge commit
`ec95eac694f88e97c1f7f044f879aadb14f203fb`, Issue #400 is closed, and branch
`update-final-target-replacement-guard` is preserved. Prior completed hardening
addition: release update input file read hardening is complete; PR
#399 merged to `main` at merge commit
`ef418a89eff1ea86b861407ce09b384b3401552e`, Issue #398 is closed, and branch
`release-update-input-file-hardening` is preserved. Prior completed hardening
addition: downloaded release update metadata write
hardening is complete; PR #397 merged to `main` at merge commit
`67c24cb605e6b2e7f9fc30eca1b83322c494d74f`, Issue #396 is closed, and branch
`update-download-metadata-create-new` is preserved. Prior completed hardening
addition: release update backup restore hardening is
complete; PR #395 merged to `main` at merge commit
`3d0781aba64b4b50d998985c4bfb8792e458cec7`, Issue #394 is closed, and branch
`update-restore-create-new-hardening` is preserved.
Prior completed hardening addition: release update backup creation hardening is
complete; PR #393 merged to `main` at merge commit
`2132fd92763f43695d20c1b49611511480a48235`, Issue #392 is closed, and branch
`update-backup-create-new-hardening` is preserved.
Prior completed hardening addition: release update file creation hardening is
complete; PR #391 merged to `main` at merge commit
`1d7f0bbb0a59c2b58ba802775cd0da3adad4e327`, Issue #390 is closed, and branch
`update-file-create-new-hardening` is preserved.
Prior completed hardening addition: release update apply rollback error
reporting is complete; PR #389 merged to `main` at merge commit
`70f0044f360072a1cdfc039b59bc6dab54fbee72`, Issue #388 is closed, and branch
`update-apply-rollback-errors` is preserved.
Prior completed hardening addition: release update apply backup preflight
hardening is complete; PR #387 merged to `main` at merge commit
`c1ff1bea2e57a32e3dc61af119215c83c8a6c9ea`, Issue #386 is closed, and branch
`update-apply-backup-preflight` is preserved. Prior completed hardening addition: release update apply temp-target allocation
hardening is complete; PR #385 merged to `main` at merge commit
`0d2ffdeda474d3395909a156bd660d03beeb9fa0`, Issue #384 is closed, and branch
`update-apply-temp-target-allocation` is preserved. Prior completed hardening
addition: release update apply backup-directory allocation hardening is complete;
PR #383 merged to `main` at merge commit
`dc3ce604c5306ac6639032d495331dfaa53d8c98`, Issue #382 is closed, and branch
`update-apply-backup-dir-allocation` is preserved. Prior completed hardening
addition: npm public package metadata gate and update staging temp-dir hardening are
complete; PR #381 merged to `main` at merge commit
`dde91f2f7b78d2ac17421ffaaf3f5d9844106358`, Issue #380 is closed, and branch
`npm-package-public-metadata-gate` is preserved. Prior completed hardening
addition: npm publish package-version consistency gate is complete; PR #379
merged to `main` at merge
commit `5569ccdf1570ec84d46f67433012091c3a1f5f8c`, Issue #378 is closed, and
branch `npm-publish-version-consistency` is preserved. Prior completed
hardening addition: GitHub Release prerelease flag gate is complete; PR #377
merged to `main` at merge commit
`bdc01de58e676be2c0c00e4d9ad2922b0d78d38c`, Issue #376 is closed, and branch
`release-prerelease-flag-gate` is preserved. Prior completed hardening addition:
package-manager manifest private-key block guard is complete; PR #375 merged to
`main` at merge commit
`0961affd951d9449390c5a6ba2d2b683dce4dea2`, Issue #374 is closed, and branch
`package-manifest-private-key-block-guard` is preserved. Prior completed
hardening addition: GitHub Release unexpected asset gate is complete; PR #373
merged to `main` at merge commit
`09aeb820731dc5047808cb873fe95d9f06d6248f`, Issue #372 is closed, and branch
`release-asset-unexpected-gate` is preserved. Prior completed hardening
addition: release update-policy signature private-key armor guard is complete;
PR #371 merged to `main` at merge commit
`0e7347637f96a0bd8de158ca57a1a261a3ddc84d`, Issue #370 is closed, and branch
`update-policy-signature-private-key-guard` is preserved. Prior completed
hardening addition: hosted site signature private-key armor guard is complete;
PR #369 merged to `main` at merge commit
`8253492a22ce3b165f09b2ec8a90d2e4a811a499`, Issue #368 is closed, and branch
`hosted-site-signature-private-key-guard` is preserved. Prior completed hardening
addition: public signature private-key armor guard is complete; PR #367 merged
to `main` at merge commit `cd537113dcda17d51625b53ea5ae91be17a6422c`, Issue
#366 is closed, and branch `public-signature-private-key-guard` is preserved.
Prior completed hardening addition: package-manager submission public-key private armor guard is complete;
PR #365 merged to `main` at merge commit
`082e843f5b6e36a4ab7150b40ab1757c80a36b47`, Issue #364 is closed, and branch
`package-submission-public-key-guard` is preserved. Prior completed hardening addition: release archive secret-file guard is
complete; PR #363 merged to `main` at merge commit
`db76d4504e3e301d16bc30c10a2bce16545c5f31`, Issue #362 is closed, and branch
`release-archive-secret-file-guard` is preserved. Prior completed hardening
addition: release secret env-file permission hardening is complete; PR #361
merged to `main` at merge commit
`e06b94d857460f26616db3faeecbfd366e07e5d2`, Issue #360 is closed, and branch
`release-env-file-permissions` is preserved. Prior completed hardening addition:
npm install target hardening is complete; PR #359 merged to `main` at merge
commit `d5b2dd4605213291dfcfbf665b5dcb59a6803d6f`, Issue #358 is closed, and
branch `npm-install-target-hardening` is preserved. Prior completed hardening
addition: Linux public-key export descriptor-bound IO handling is complete; PR #357 merged
to `main` at merge commit
`a3bc8f02e09d7dab299b282c766c732bb75f64f2`, Issue #356 is closed, and branch
`linux-public-key-descriptor-io` is preserved. Prior completed hardening
addition: release secret env-file descriptor-bound IO handling is complete; PR
#355 merged to `main` at merge commit
`cc611c044c22733eeff9e54af5f708c2ffd47f07`, Issue #354 is closed, and branch
`release-secret-env-file-descriptor-io` is preserved. Prior completed
hardening addition: Linux repository metadata signing descriptor-bound IO
handling is complete; PR #353 merged to `main` at merge commit
`c28f33a3a44a4087639cd212669192d115ae93fd`, Issue #352 is closed, and branch
`linux-repository-signing-descriptor-io` is preserved. Prior completed
hardening addition: RPM package signing descriptor-bound IO handling is
complete; PR #351 merged to `main` at merge commit
`7e4857e32313491238b9b2234a2470f7b6600ae5`, Issue #350 is closed, and branch
`rpm-signing-descriptor-io` is preserved. Prior completed hardening addition:
release artifact verifier descriptor-bound IO handling is complete; PR #349
merged to `main` at merge commit
`8b1cbb0741b0fbeead2713775019474e0718db0d`, Issue #348 is closed, and branch
`release-verifier-descriptor-io` is preserved. Prior completed hardening addition:
release update-policy descriptor-bound IO handling is complete; PR #347 merged
to `main` at merge commit
`3e085bc97b73ac64e88d2d53038ee5f325717556`, Issue #346 is closed, and branch
`update-policy-descriptor-io` is preserved. Prior completed hardening addition:
hosted repository S3 publication descriptor-bound IO handling is complete; PR
#345 merged to `main` at merge commit
`9d615be1bcf94a9c0cba8c8b2ffdece32c7c819e`, Issue #344 is closed, and branch
`hosted-s3-descriptor-io` is preserved. Prior completed hardening addition:
hosted repository Pages descriptor-bound IO handling is complete; PR #343
merged to `main` at merge commit
`18c64454107f70554b66fd7ed49bf81d6b05df4f`, Issue #342 is closed, and branch
`hosted-pages-descriptor-io` is preserved. Prior completed hardening addition:
hosted repository site descriptor-bound IO handling is complete; PR #341 merged
to `main` at merge commit `394d990fb07de28d83636f1cd9458b03f1b0e130`,
Issue #340 is closed, and branch `hosted-site-descriptor-io` is preserved. Prior completed hardening addition:
hosted repository bundle descriptor-bound IO handling is complete; PR #339
merged to `main` at merge commit `7539be6b372fbdc544b85691ac480c30f04a69d4`,
Issue #338 is closed, and branch `hosted-bundle-descriptor-io` is preserved. Prior completed hardening addition:
package-manager manifest descriptor-bound IO handling is complete; PR #337 merged
to `main` at merge commit `dc15b786571bbf69a64845cf7a49d1836d6767a7`,
Issue #336 is closed, and branch `package-manifest-descriptor-io` is preserved. Prior completed hardening addition:
package-manager submission file boundary handling is complete; PR #335 merged
to `main` at merge commit `1a927487116fec85bfcead2f0659605c1093c1db`, Issue
#334 is closed, and branch `package-submission-file-bounds` is preserved. Prior completed hardening addition:
release artifact verifier file boundary handling is complete; PR #333 merged to
`main` at merge commit `4ad9de5cb0cfc47a5aab34ed92e1ee91fbe60754`, Issue #332
is closed, and branch `release-artifact-file-bounds` is preserved. Prior completed hardening addition:
package-manager manifest file boundary handling is complete; PR #331 merged to
`main` at merge commit `eef6b6c7dc7c31b3b7ec7f1d78e77e8c4482c07e`, Issue #330
is closed, and branch `package-manager-manifest-file-bounds` is preserved. Prior
completed hardening addition: hosted repository generator file boundary handling
is complete; PR #329 merged to `main` at merge commit
`4d2a4dfdb3cf885a1be8ccd1cc3a96cc87760c02`, Issue #328 is closed, and branch
`hosted-generator-file-bounds` is preserved. Prior completed hardening addition:
hosted repository Pages preparation input
handling is complete; PR #327 merged to `main` at merge commit
`42c23250c748cd6c20b44e0e1cfc046aa2f46b74`, Issue #326 is closed, and branch
`hosted-pages-input-bounds` is preserved. Prior
completed hardening addition: hosted repository S3 publication metadata input
handling is complete; PR #325 merged to `main` at merge commit
`1774979ea6b03a0d991d200546b70dcf9a616154`, Issue #324 is closed, and branch
`hosted-s3-metadata-input-bounds` is preserved. Prior completed hardening
addition: Linux public-key export output handling is complete; PR #323 merged
to `main` at merge commit `edb55a86abc528efac27984daff8b7fbc2f74e38`, Issue
#322 is closed, and branch `linux-public-key-export-output-bounds` is
preserved. Prior completed hardening addition: RPM package signing file
handling is complete; PR #321 merged to
`main` at merge commit `d66b872f53d85a1bcec32dfe98727d996fc84f5d`, Issue #320
is closed, and branch `rpm-package-signing-file-bounds` is preserved. Prior completed hardening
addition: Linux repository metadata signing file handling is complete; PR #319
merged to `main` at merge commit
`1846e11e3ebe5d15bdd477b21d59271053caf671`, Issue #318 is closed, and branch
`linux-repository-signing-file-bounds` is preserved. Prior completed hardening
addition: Linux release signing file handling is complete; PR #317 merged to
`main` at merge commit `c2017b15ad619a3fccf319f13d15f34167df9051`, Issue #316
is closed, and branch `linux-signing-source-bounds` is preserved. Prior completed hardening addition:
release update-policy source input bounds are complete; PR #315 merged to
`main` at merge commit `1a3892def80d48469065b36832e20286061969f2`, Issue #314
is closed, and branch `update-policy-source-bounds` is preserved. Prior
completed hardening addition: package-manager submission source ingestion bounds are complete; PR #313 merged to
`main` at merge commit `431a763c20dbd9337d00a57c678f15953ae529e1`, Issue #312
is closed, and branch `submission-source-bounds` is preserved. Prior completed
hardening addition: package-manager release archive ingestion bounds are complete; PR #311 merged to
`main` at merge commit `deffe7ba3b6f0cee3fc1938089d02a9ae8894042`, Issue #310
is closed, and branch `package-manager-archive-bounds` is preserved. Prior
completed hardening addition: hosted repository ZIP ingestion bounds are complete; PR #309 merged to
`main` at merge commit `1b098f727b4979976c86b1d722e943838ab0defe`, Issue #308
is closed, and branch `hosted-repository-zip-bounds` is preserved. Prior
completed hardening addition: release smoke manifest read bounds are complete; PR #307 merged to `main` at merge
commit `1551a1afd7e7b3f0c292a3416b1f2638f27c9f7b`, Issue #306 is closed, and branch
`release-smoke-manifest-bounds` is preserved. Prior completed hardening addition:
release smoke extraction bounds are complete; PR #305 merged to `main` at merge
commit `97c425e81fd917b047af0b0e4da07debe829e254`, Issue #304 is closed, and branch
`release-smoke-extract-bounds` is preserved. Prior completed hardening addition:
release smoke archive root guard is complete; PR #303 merged to `main` at merge
commit `f5b13df2fd9ad34f6d5d3db874ed93f4ed2964fd`, Issue #302 is closed, and
branch `release-smoke-root-guard` is preserved. Prior completed hardening
addition: release archive root guard is complete; PR #301 merged to `main` at merge
commit `52221eb28d2230bdebe9b7b22c01d15425167b86`, Issue #300 is closed, and
branch `update-archive-root-guard` is preserved. Prior completed hardening
addition: Rust update public-host IP guard is complete; PR #299 merged to `main` at merge
commit `28ffb06dfcda58929f3449030f4f036a9305c44a`, Issue #298 is closed, and
branch `update-ipv6-public-host-guard` is preserved. Prior completed hardening
addition: npm download redirect boundary is complete; PR #297 merged to `main`
at merge commit `9a9479152f90562a6874c1f3d4f589749aef17f0`, Issue #296 is
closed, and branch `npm-download-redirect-boundary` is preserved. Prior
completed hardening addition: npm unverified download loopback gate is complete; PR #295 merged to
`main` at merge commit `2cbc38fab99eac7a462b8841063e6634e2c10405`, Issue #294
is closed, and branch `npm-unverified-loopback-only` is preserved. Prior
completed hardening addition: Release secret env-file readiness gate is
complete; PR #293 merged to `main` at merge commit
`03ddbf9afab0a118b88469ce0a9a9c7f85681fb8`, Issue #292 is closed, and branch
`release-secret-env-file-readiness-gate` is preserved. Prior completed
hardening addition: Release secret env-file validation is complete; PR #291
merged to `main` at merge commit
`11be300e67bf77c58ca4c446e3865a917d2a0bb9`, Issue #290 is closed, and branch
`release-secret-env-file-check` is preserved. Prior completed hardening
addition: Release secret env-file-only setup is complete; PR #289 merged to
`main` at merge commit `b00d63128f4bf87ae8e7b62ee3eb6c22eb5820af`, Issue #288
is closed, and branch `release-secret-env-file-only` is preserved. Prior
completed hardening addition: Release secret env-file template is complete;
PR #286 merged to `main` at merge commit
`55f1f2bce00f7bf499c19f7c40befa96ef891874`, Issue #285 is closed, and branch
`release-secret-template` is preserved. Prior completed hardening addition:
Release secret env-file setup is complete; PR #284 merged to `main` at merge
commit `53d0f1ce1c0f34a5bceaa1de31be76cb6bd6126b`, Issue #283 is closed, and
branch `release-secret-env-file-setup` is preserved. Prior completed hardening
addition: Rust `time` Dependabot alert fix is complete; PR #282 merged to
`main` at merge commit `6bb587c48ea64cba160abaf6675a6a50863395dd`, Issue #281
is closed, and branch `rust-time-dependabot-alert` is preserved. Prior completed
hardening addition: GitHub repository security readiness is complete; PR #280
merged to `main` at merge commit `5b453e9ba05d1293f96fe560232b47eb13070c92`,
Issue #279 is closed, and branch `github-repository-security-readiness` is
preserved. Prior completed hardening addition: GitHub workflow permissions
readiness is complete; PR #278 merged to `main` at merge commit
`1a8e026d00a44bce85e85788782c432310965ece`, Issue #277 is closed, and branch
`github-workflow-permissions-readiness` is preserved. Prior completed hardening
addition: GitHub Actions permissions readiness is complete; PR #276 merged to
`main` at merge commit `0c074fb4e62fde997bee82a82ec27cc13294b196`, Issue #275
is closed, branch `github-actions-permissions-readiness` is preserved, and live
repository Actions admission is restricted to selected actions with GitHub-owned
actions plus `dtolnay/rust-toolchain@stable`.

## Post Phase 15 - npm Download Redirect Boundary

Status: completed

Goal:

Make npm installer redirects preserve the trust boundary of the original
download request, so public release flows cannot redirect into loopback-only test
servers and loopback smoke flows cannot redirect out to public hosts.

Completed work:

- Issue #296 is closed. PR #297 merged to `main` at merge commit
  `9a9479152f90562a6874c1f3d4f589749aef17f0`, and branch
  `npm-download-redirect-boundary` is preserved.
- Added `validateDownloadRedirect()` to the npm download policy helper.
- Public release downloads may redirect only within the public HTTPS boundary.
- Loopback smoke downloads may redirect only among loopback hosts.
- Redirects that cross public/loopback boundaries, introduce embedded
  credentials, or downgrade public downloads to non-HTTPS targets fail before the
  next request is followed.
- Redirect policy failures use the normal installer error path with sanitized
  URLs.
- Updated the npm package README redirect policy note.

Files changed:

- `packaging/npm/conu-cli/lib/download-policy.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `packaging/npm/conu-cli/scripts/check-download-policy.js`
- `packaging/npm/conu-cli/scripts/check-download-limits.js`
- `packaging/npm/conu-cli/README.md`

Validation:

- `node packaging/npm/conu-cli/scripts/check-download-policy.js` passed.
- `node packaging/npm/conu-cli/scripts/check-download-limits.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #297 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- This change hardens npm redirect handling only; it does not replace release
  checksum, signature, attestation, and tagged release readiness gates.

Next recommendation:

- Configure the real release signing/npm secrets tracked by Issue #274, run the
  full production-readiness gate with live GitHub checks, then run tagged release
  readiness before cutting a production tag.

## Post Phase 15 - npm Unverified Download Loopback Gate

Status: completed

Goal:

Make the npm installer's `CONU_NPM_ALLOW_UNVERIFIED=1` escape hatch enforce its
intended local-test boundary so public release downloads still fail closed when a
checksum sidecar is unavailable.

Completed work:

- Issue #294 is closed. PR #295 merged to `main` at merge commit
  `2cbc38fab99eac7a462b8841063e6634e2c10405`, and branch
  `npm-unverified-loopback-only` is preserved.
- Added `validateUnverifiedDownloadBase()` to the npm download policy helper.
- The npm installer now rejects `CONU_NPM_ALLOW_UNVERIFIED=1` for non-loopback
  download bases before any network request.
- Public HTTPS release downloads remain checksum-required even if the unverified
  environment variable is set.
- Existing loopback smoke/download tests can still use the unverified mode for
  local release fixtures.
- Updated the npm package README environment table.

Files changed:

- `packaging/npm/conu-cli/lib/download-policy.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `packaging/npm/conu-cli/scripts/check-download-policy.js`
- `packaging/npm/conu-cli/scripts/check-download-limits.js`
- `packaging/npm/conu-cli/README.md`

Validation:

- `node packaging/npm/conu-cli/scripts/check-download-policy.js` passed.
- `node packaging/npm/conu-cli/scripts/check-download-limits.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #295 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- This change hardens npm installer checksum bypass behavior only; it does not
  replace the signed release artifact and tagged release readiness gates.

Next recommendation:

- Configure the real release signing/npm secrets tracked by Issue #274, run the
  full production-readiness gate with live GitHub checks, then run tagged release
  readiness before cutting a production tag.

## Post Phase 15 - Release Secret Env-File Readiness Gate

Status: completed

Goal:

Let maintainers include the filled `.env.release` validation in the standard
production-readiness wrapper before uploading real release secrets.

Completed work:

- Issue #292 is closed. PR #293 merged to `main` at merge commit
  `03ddbf9afab0a118b88469ce0a9a9c7f85681fb8`, and branch
  `release-secret-env-file-readiness-gate` is preserved.
- Added optional `-ReleaseSecretEnvFile` support to
  `scripts\verify-production-readiness.ps1`, defaulting from
  `CONU_RELEASE_SECRET_ENV_FILE`.
- When a file path is supplied, the readiness wrapper runs
  `scripts/set-github-release-secrets.py --env-file <path> --check-env-file`.
- Normal readiness runs remain unchanged when no env-file path is provided.
- Updated production readiness and release checklist docs with the wrapper
  option.

Validation:

- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipPackages -SkipSmokes -ReleaseSecretEnvFile <temp full env file>`
  passed, proving the optional wrapper path validates a filled env file.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #293 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- The wrapper env-file gate validates required names and non-empty values only;
  signing material still needs the existing `--preflight-values --require-openssl`
  dry-run before upload.

Next recommendation:

- Generate and fill `.env.release`, run
  `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -ReleaseSecretEnvFile .env.release`,
  then run the strict `--env-file-only --dry-run --preflight-values --require-openssl`
  setup command, upload without `--dry-run`, and run tagged release readiness
  before cutting a production tag.

## Post Phase 15 - Release Secret Env-File Validation

Status: completed

Goal:

Let maintainers validate the filled ignored `.env.release` file locally before
any GitHub CLI lookup, signing-value preflight subprocess, or secret upload.

Completed work:

- Issue #290 is closed. PR #291 merged to `main` at merge commit
  `11be300e67bf77c58ca4c446e3865a917d2a0bb9`, and branch
  `release-secret-env-file-check` is preserved.
- Added `--check-env-file` to `scripts/set-github-release-secrets.py`.
- The new mode requires `--env-file`, validates only the required release
  secret names, rejects missing empty values, and exits before repo inference,
  GitHub CLI secret writes, or platform/Linux value preflights.
- The generated `.env.release` template now includes the validation command
  before the stricter `--env-file-only` dry-run command.
- Updated README, release checklist, distribution/hosting, platform signing,
  and production readiness docs with the local validation step.
- Regression coverage verifies env-file check success, missing-value failure
  even when environment values are present, invalid flag combinations, no
  GitHub/preflight dependency calls, and no secret-value output leakage.

Validation:

- `python -m py_compile scripts/set-github-release-secrets.py scripts/set-github-release-secrets-regression.py scripts/github_release_secrets.py scripts/check-github-release-secret-readiness.py scripts/check-github-release-secret-readiness-regression.py`
  passed.
- `python scripts/set-github-release-secrets-regression.py` passed.
- `python scripts/check-github-release-secret-readiness-regression.py` passed.
- `python scripts/set-github-release-secrets.py --print-env-template` emitted
  the local `--check-env-file` command and required names with empty values
  only.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #291 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- Local OpenSSL, GPG, RPM, and native Windows linker tooling are not fully
  installed on this machine, so the relevant value/tooling checks remain covered
  by CI regressions until a maintainer supplies real secrets and platform
  tooling.

Next recommendation:

- Generate `.env.release`, fill every required value, run
  `python scripts/set-github-release-secrets.py --env-file .env.release --check-env-file`,
  then run
  `python scripts/set-github-release-secrets.py --repo imthegoodboy/conU --env-file .env.release --env-file-only --dry-run --preflight-values --require-openssl`,
  upload without `--dry-run`, and run tagged release readiness with npm
  registry, CI, and default-branch checks before cutting a production tag.

## Post Phase 15 - Release Secret Env-File-Only Setup

Status: completed

Goal:

Prevent generated release-secret env files from being accidentally completed by
stale exported shell variables during production secret setup.

Completed work:

- Issue #288 is closed. PR #289 merged to `main` at merge commit
  `b00d63128f4bf87ae8e7b62ee3eb6c22eb5820af`, and branch
  `release-secret-env-file-only` is preserved.
- Added `--env-file-only` to `scripts/set-github-release-secrets.py`.
- The new mode requires `--env-file`, ignores local environment release-secret
  values, and fails if any required secret value is missing from the file.
- Existing environment-only and env-file-plus-environment setup remains
  available for maintainers who intentionally export values directly.
- Updated the generated `.env.release` template to recommend `--env-file-only`.
- Updated README, release checklist, distribution/hosting, platform signing,
  and production readiness docs with the stricter generated-env-file path.
- Regression coverage verifies strict file-only success, missing-value failure
  even when matching environment variables exist, compatibility fallback for the
  default env-file mode, no secret-value output leakage, and invalid flag
  combinations.

Validation:

- `python -m py_compile scripts/set-github-release-secrets.py scripts/set-github-release-secrets-regression.py scripts/github_release_secrets.py scripts/check-github-release-secret-readiness.py scripts/check-github-release-secret-readiness-regression.py`
  passed.
- `python scripts/set-github-release-secrets-regression.py` passed.
- `python scripts/check-github-release-secret-readiness-regression.py` passed.
- `python scripts/set-github-release-secrets.py --print-env-template` emitted
  the stricter `--env-file-only` dry-run command and required names with empty
  values only.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #289 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- Local OpenSSL, GPG, RPM, and native Windows linker tooling are not fully
  installed on this machine, so the relevant value/tooling checks remain covered
  by CI regressions until a maintainer supplies real secrets and platform
  tooling.

Next recommendation:

- Generate `.env.release`, fill every required value, run
  `python scripts/set-github-release-secrets.py --repo imthegoodboy/conU --env-file .env.release --env-file-only --dry-run --preflight-values --require-openssl`,
  upload without `--dry-run`, then run tagged release readiness with npm
  registry, CI, and default-branch checks before cutting a production tag.

## Post Phase 15 - Release Secret Env-File Template

Status: completed

Goal:

Make release secret setup less error-prone by generating the ignored local
env-file template from the authoritative required-secret list.

Completed work:

- Issue #285 is closed. PR #286 merged to `main` at merge commit
  `55f1f2bce00f7bf499c19f7c40befa96ef891874`, and branch
  `release-secret-template` is preserved.
- Added `--print-env-template` and `--write-env-template` to
  `scripts/set-github-release-secrets.py`.
- Template output contains only comments and required release secret names with
  empty values.
- Template writes use exclusive creation, refuse overwrites, reject missing
  parent directories, and keep template generation separate from setup options.
- Regression coverage verifies rendering, writing, no secret-value leakage,
  empty-template missing-value behavior, parser compatibility, and invalid
  template flag combinations.
- Updated README, release checklist, distribution/hosting, platform signing,
  and production readiness docs with the generated `.env.release` path.

Validation:

- `python -m py_compile scripts/set-github-release-secrets.py scripts/set-github-release-secrets-regression.py scripts/github_release_secrets.py scripts/check-github-release-secret-readiness.py scripts/check-github-release-secret-readiness-regression.py`
  passed.
- `python scripts/set-github-release-secrets-regression.py` passed.
- `python scripts/check-github-release-secret-readiness-regression.py` passed.
- `python scripts/set-github-release-secrets.py --print-env-template` emitted
  only comments plus required names with empty values.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #286 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- Local OpenSSL, GPG, RPM, and native Windows linker tooling are not fully
  installed on this machine, so the relevant value/tooling checks remain covered
  by CI regressions until a maintainer supplies real secrets and platform
  tooling.

Next recommendation:

- Generate `.env.release` from the template command, fill the real release
  secrets tracked by Issue #274, run the dry-run preflight, upload the secrets,
  then run tagged release readiness with npm registry, CI, and
  default-branch checks before cutting a production tag.

## Post Phase 15 - Release Secret Env-File Setup

Status: completed

Goal:

Make the final release-secret handoff safer by letting maintainers preflight
and upload required GitHub release secrets from an ignored local env file
without putting secret values in command arguments or logs.

Completed work:

- Issue #283 is closed. PR #284 merged to `main` at merge commit
  `53d0f1ce1c0f34a5bceaa1de31be76cb6bd6126b`, and branch
  `release-secret-env-file-setup` is preserved.
- Added `--env-file <path>` to `scripts/set-github-release-secrets.py`.
- The env-file parser accepts only required release secret names, supports
  `KEY=VALUE` and `export KEY=VALUE`, rejects malformed, duplicate, unsupported,
  non-regular, non-UTF-8, or oversized files, and reports only names, line
  numbers, and sanitized failure categories.
- Env-file values are passed to signing preflight subprocesses through
  environment variables, while `gh secret set` still receives values through
  stdin only.
- Updated README, release checklist, distribution/hosting, platform signing,
  and production readiness docs with the `.env.release` setup path.

Validation:

- `python -m py_compile scripts/set-github-release-secrets.py scripts/set-github-release-secrets-regression.py scripts/github_release_secrets.py scripts/check-github-release-secret-readiness.py scripts/check-github-release-secret-readiness-regression.py`
  passed.
- `python scripts/set-github-release-secrets-regression.py` passed, including
  env-file parsing, strict key handling, no argv leakage, no output leakage, and
  env-file preflight environment propagation checks.
- `python scripts/check-github-release-secret-readiness-regression.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- `git diff --check` passed.
- PR #284 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secret values before a production `v*` tag can pass.
- Local OpenSSL, GPG, RPM, and native Windows linker tooling are not fully
  installed on this machine, so the relevant value/tooling checks are covered by
  CI regressions here until a maintainer supplies real secrets and platform
  tooling.

Next recommendation:

- Use the safer `.env.release` path to configure the real release secrets
  tracked by Issue #274, then run tagged release readiness with npm registry,
  CI, and default-branch checks before cutting a production tag.

## Post Phase 15 - Rust Time Dependabot Alert Fix

Status: completed

Goal:

Resolve the live Dependabot alert for the transitive Rust `time` dependency
without changing conU runtime behavior.

Completed work:

- Issue #281 is closed. PR #282 merged to `main` at merge commit
  `6bb587c48ea64cba160abaf6675a6a50863395dd`, and branch
  `rust-time-dependabot-alert` is preserved.
- Refreshed `Cargo.lock` so the workspace resolves `time` to patched version
  `0.3.47`.
- Kept the existing `rcgen` dependency declaration unchanged because the
  resolver can select the patched transitive version.
- Verified GitHub Dependabot alert #1 is now `fixed`.

Validation:

- `cargo update -p time --precise 0.3.47` completed with the refreshed lockfile.
- `cargo tree -i time` reports `time v0.3.47` through `rcgen v0.14.7` and
  `yasna v0.5.2`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `git diff --check` passed.
- PR #282 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.
- `python scripts/check-github-repository-security.py --repo imthegoodboy/conU --json`
  reported `ready=true`, zero open Dependabot alerts, zero open secret-scanning
  alerts, and all display guards false after merge.

Known gaps:

- Local `cargo +stable-x86_64-pc-windows-gnu test --workspace` could not link
  because `dlltool.exe` is not installed.
- Local default `cargo test --workspace` could not link because MSVC `link.exe`
  is not installed.
- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.

Next recommendation:

- Wait for post-merge main CI on `6bb587c48ea64cba160abaf6675a6a50863395dd`,
  then configure the real release secrets tracked by Issue #274 and run the full
  production readiness gate before cutting a production tag.

## Post Phase 15 - GitHub Repository Security Readiness

Status: completed

Goal:

Fail production release preparation when repository-level GitHub security
settings or open security-alert counts drift away from release-safe defaults.

Completed work:

- Issue #279 is closed. PR #280 merged to `main` at merge commit
  `5b453e9ba05d1293f96fe560232b47eb13070c92`, and branch
  `github-repository-security-readiness` is preserved.
- Added `scripts/check-github-repository-security.py` to audit Dependabot
  vulnerability alerts, Dependabot security updates, secret scanning, secret
  scanning push protection, open Dependabot alert counts, open secret-scanning
  alert counts, and privacy-safe output guards.
- Added `scripts/check-github-repository-security-regression.py` covering ready
  settings, disabled security features, archived/disabled repository state,
  open-alert failures, unavailable alert counts, optional stricter secret
  scanning policies, and no sentinel leakage.
- Wired the regression into CI Packages, Release Artifacts package checks, and
  `scripts/verify-production-readiness.ps1`.
- Added tagged-release preflight validation for repository security before
  release secret checks, package checks, and platform builds.
- Added `-CheckGitHubRepositorySecurity` to the production readiness script.
- Updated workflow-permissions readiness to allow only `security-events: read`
  on the release preflight job for the repository security metadata check.
- Updated README, release/distribution/production readiness docs, repo memory,
  implementation guardrails, security checklist, and this plan.
- Enabled live Dependabot vulnerability alerts and Dependabot security updates
  for `imthegoodboy/conU`. Secret scanning and push protection were already
  enabled.

Validation:

- `python -m py_compile scripts/check-github-repository-security.py scripts/check-github-repository-security-regression.py scripts/check-github-workflow-permissions.py scripts/check-github-workflow-permissions-regression.py`
  passed.
- `python scripts/check-github-repository-security-regression.py` passed.
- `python scripts/check-github-repository-security.py --repo imthegoodboy/conU --json`
  reported `ready=true`, `dependabotSecurityUpdates=enabled`,
  `vulnerabilityAlertsEnabled=true`, `secretScanning=enabled`,
  `secretScanningPushProtection=enabled`, zero open Dependabot alerts, zero open
  secret-scanning alerts, and all display guards false.
- `python scripts/check-github-workflow-permissions-regression.py` passed.
- `python scripts/check-github-workflow-permissions.py --json` reported
  `ready=true` after adding `security-events: read` to the release preflight job.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubBranchProtection -CheckGitHubActionsPermissions -CheckGitHubWorkflowPermissions -CheckGitHubRepositorySecurity -GitHubRepo imthegoodboy/conU`
  passed locally.
- PR #280 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- Secret scanning non-provider patterns and validity checks are reported but
  not required by default because they are optional stricter GitHub policies.

Next recommendation:

- Configure the real release secrets tracked by Issue #274, then run
  `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -CheckGitHubBranchProtection -CheckGitHubActionsPermissions -CheckGitHubWorkflowPermissions -CheckGitHubRepositorySecurity -CheckTaggedReleaseReadiness -GitHubRepo imthegoodboy/conU -ReleaseTag v<version> -NpmRegistryCheck -RequireTaggedReleaseCi -RequireTaggedReleaseDefaultBranchHead`
  before creating a production tag.

## Post Phase 15 - GitHub Workflow Permissions Readiness

Status: completed

Goal:

Fail production release preparation when GitHub workflow YAML drifts away from
explicit least-privilege permissions or introduces high-risk automation trigger
events.

Completed work:

- Issue #277 is closed. PR #278 merged to `main` at merge commit
  `1a8e026d00a44bce85e85788782c432310965ece`, and branch
  `github-workflow-permissions-readiness` is preserved.
- Added `scripts/check-github-workflow-permissions.py` to audit workflow files
  for explicit top-level `contents: read`, forbidden `pull_request_target` and
  `workflow_run` triggers, known release job write scopes, and privacy-safe
  output guards.
- Added `scripts/check-github-workflow-permissions-regression.py` covering the
  dependency-free parser fallback, missing or shorthand top-level permissions,
  forbidden trigger events, unexpected CI write scopes, missing or extra release
  job permissions, and no sentinel leakage.
- Wired the regression into CI Packages, Release Artifacts package checks, and
  `scripts/verify-production-readiness.ps1`.
- Added tagged-release preflight validation for workflow permissions before
  release secret checks, package checks, and platform builds.
- Added `-CheckGitHubWorkflowPermissions` to the production readiness script.
- Updated README, release/distribution/production readiness docs, repo memory,
  implementation guardrails, security checklist, and this plan.

Validation:

- `python -m py_compile scripts/check-github-workflow-permissions.py scripts/check-github-workflow-permissions-regression.py`
  passed.
- `python scripts/check-github-workflow-permissions-regression.py` passed.
- `python scripts/check-github-workflow-permissions.py --json` reported
  `ready=true` for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`, with only the expected release publication
  jobs carrying write permissions and all display guards false.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`
  passed locally.
- PR #278 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- This readiness gate verifies workflow permission shape and trigger safety; it
  does not replace live repository Actions admission checks or branch protection
  checks, which remain separate readiness gates.

Next recommendation:

- Configure the real release secrets, then run
  `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -CheckGitHubBranchProtection -CheckGitHubActionsPermissions -CheckGitHubWorkflowPermissions -CheckTaggedReleaseReadiness -GitHubRepo imthegoodboy/conU -ReleaseTag v<version> -NpmRegistryCheck -RequireTaggedReleaseCi -RequireTaggedReleaseDefaultBranchHead`
  before creating a production tag.

## Post Phase 15 - GitHub Actions Permissions Readiness

Status: completed

Goal:

Fail production release preparation when repository GitHub Actions admission or
default workflow token settings drift away from the small, known action set
needed by conU CI/release workflows.

Completed work:

- Issue #275 is closed. PR #276 merged to `main` at merge commit
  `0c074fb4e62fde997bee82a82ec27cc13294b196`, and branch
  `github-actions-permissions-readiness` is preserved.
- Added `scripts/check-github-actions-permissions.py` to audit repository
  Actions permissions, workflow token defaults, selected action allowlists, and
  optional SHA-pinning policy without printing tokens, logs, workflow contents,
  payloads, or raw permission API bodies.
- Added `scripts/check-github-actions-permissions-regression.py` covering
  all-actions mode, disabled Actions, write-token defaults, Actions
  pull-request approval, missing/extra/broad selected action patterns, optional
  policy relaxation, optional SHA-pinning requirements, and no sentinel leakage.
- Wired the regression into CI Packages, Release Artifacts package checks, and
  `scripts/verify-production-readiness.ps1`.
- Added tagged-release preflight validation for live GitHub Actions permissions
  before secret checks, package checks, and platform builds.
- Added `-CheckGitHubActionsPermissions` and optional
  `-RequireGitHubActionsShaPinning` to the production readiness script.
- Updated README, release/distribution/production readiness docs, repo memory,
  implementation guardrails, security checklist, and this plan.
- Configured the live repository to selected actions only, with GitHub-owned
  actions allowed, verified marketplace actions disabled, and only
  `dtolnay/rust-toolchain@stable` allowlisted for the existing third-party
  Rust toolchain action. Default workflow token permissions remain read-only,
  and Actions pull-request approval remains disabled.

Validation:

- `python -m py_compile scripts/check-github-actions-permissions.py scripts/check-github-actions-permissions-regression.py`
  passed.
- `python scripts/check-github-actions-permissions-regression.py` passed.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `git diff --check` passed.
- `python scripts/check-github-actions-permissions.py --repo imthegoodboy/conU --json`
  initially reported the expected live failure: repository actions were allowed
  for `all`.
- After live repository hardening,
  `python scripts/check-github-actions-permissions.py --repo imthegoodboy/conU --json`
  reported `ready=true`, `allowedActions=selected`,
  `defaultWorkflowPermissions=read`,
  `canApprovePullRequestReviews=false`, `githubOwnedAllowed=true`,
  `verifiedAllowed=false`, and only `dtolnay/rust-toolchain@stable` in
  `patternsAllowed`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubActionsPermissions`
  passed locally.
- PR #276 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit while the live repository was already restricted to
  selected actions.

Known gaps:

- Repository Actions SHA-pinning is supported as an optional readiness policy,
  but live enforcement is not enabled because the current workflows intentionally
  use GitHub-owned major-version tags and `dtolnay/rust-toolchain@stable`.
- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.

Next recommendation:

- Configure the real release secrets, then run
  `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -CheckGitHubBranchProtection -CheckGitHubActionsPermissions -CheckTaggedReleaseReadiness -GitHubRepo imthegoodboy/conU -ReleaseTag v<version> -NpmRegistryCheck -RequireTaggedReleaseCi -RequireTaggedReleaseDefaultBranchHead`
  before creating a production tag.

## Post Phase 15 - GitHub Main Branch Protection Readiness

Status: completed

Goal:

Add a payload-safe readiness gate for GitHub default branch protection and
enable live `main` branch protection so production release code cannot drift
through unguarded branch mutation.

Completed work:

- Issue #272 is closed. PR #273 merged to `main` at merge commit
  `7367be16fa656d2c936d0f597b5321009f4e4631`, and branch
  `github-main-branch-protection` is preserved.
- Added `scripts/check-github-main-protection.py` to audit branch protection
  metadata without printing tokens, logs, payloads, or branch-protection API
  bodies.
- Added `scripts/check-github-main-protection-regression.py` covering
  unprotected branches, strict required status checks, missing CI contexts,
  force-push/deletion guards, optional PR-review/admin-enforcement checks, and
  no sentinel leakage.
- Wired the regression into CI Packages, Release Artifacts package checks, and
  `scripts/verify-production-readiness.ps1`.
- Added `-CheckGitHubBranchProtection`, optional
  `-GitHubBranchProtectionBranch`, optional `-RequireGitHubBranchPrReviews`,
  and optional `-RequireGitHubBranchAdminEnforcement` to the production
  readiness script.
- Updated README, release/distribution/production readiness docs, repo memory,
  implementation guardrails, security checklist, and this plan.
- Configured live branch protection for `main` with strict required status
  checks for `Packages`, `Rust (ubuntu-latest)`, `Rust (macos-15)`, and
  `Rust (windows-2025-vs2026)`, with force pushes and branch deletion disabled.

Validation:

- `python -m py_compile scripts/check-github-main-protection.py scripts/check-github-main-protection-regression.py`
  passed.
- `python scripts/check-github-main-protection-regression.py` passed.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `git diff --check` passed.
- `python scripts/check-github-main-protection.py --repo imthegoodboy/conU --json`
  initially reported the expected live failure: `main is not protected`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally.
- PR #273 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.
- After merge, live branch protection was applied with GitHub CLI and
  `python scripts/check-github-main-protection.py --repo imthegoodboy/conU --json`
  reported `ready=true`, `strictStatusChecks=true`, no missing status checks,
  `forcePushesAllowed=false`, and `deletionsAllowed=false`.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- PR review and admin-enforcement branch policies are supported by the audit as
  optional stricter checks, but the live protection currently focuses on strict
  CI, no force pushes, and no branch deletion so maintainer emergency/admin
  flows remain possible.

Next recommendation:

- Configure the real release secrets, then run
  `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -CheckGitHubBranchProtection -CheckTaggedReleaseReadiness -GitHubRepo imthegoodboy/conU -ReleaseTag v<version> -NpmRegistryCheck -RequireTaggedReleaseCi -RequireTaggedReleaseDefaultBranchHead`
  before creating a production tag.

## Post Phase 15 - Release Tag Default-Branch Gate

Status: completed

Goal:

Fail production `v*` tag preparation before package checks and platform builds
when the tag target commit does not match the repository default branch head.

Completed work:

- Issue #270 is closed. PR #271 merged to `main` at merge commit
  `55812c419b64a39ac6edabfb4b8a6d2d7b00e901`, and branch
  `release-tag-default-branch-gate` is preserved.
- Added release-branch readiness metadata to
  `scripts/check-tagged-release-readiness.py`, including payload-safe branch
  name, release target SHA, branch head SHA, readiness state, and issue text.
- Added `--require-default-branch-head`, optional `--release-branch`, and
  optional `--release-target-head` to the tagged-release readiness audit.
- Extended `--ci-only` release workflow mode so tagged releases now require
  both a successful target-commit `CI` run and a default-branch head match
  before secret and signing checks run.
- Added `-RequireTaggedReleaseDefaultBranchHead`, optional
  `-TaggedReleaseTargetHead`, and optional `-TaggedReleaseBranch` to
  `scripts/verify-production-readiness.ps1`.
- Extended tagged-release readiness regression coverage for skipped branch
  checks, successful branch metadata, mismatched target/branch SHAs, invalid
  target SHAs, missing branch SHAs, and no sentinel leakage.
- Updated README, release/distribution/production readiness docs, repo memory,
  implementation guardrails, security checklist, and this plan.

Validation:

- `python -m py_compile scripts/check-tagged-release-readiness.py scripts/check-tagged-release-readiness-regression.py`
  passed.
- `python scripts/check-tagged-release-readiness-regression.py` passed.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `git diff --check` passed.
- `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v0.1.0 --ci-only --ci-head d189528c7c2743558b4bfa76b5f0c147682babf1 --require-default-branch-head --json`
  passed against live GitHub metadata for the latest green `main` commit before
  this change.
- `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v0.1.0 --npm-registry-check --require-ci --require-default-branch-head --ci-head d189528c7c2743558b4bfa76b5f0c147682babf1 --json`
  correctly reported CI, default-branch, Pages, npm registry, and
  release-clobber readiness while failing overall because live release secrets
  are still missing.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally.
- PR #271 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- The default-branch gate proves the tag target equals the current default
  branch head; release operators still need to bump versions and create tags
  from the intended reviewed `main` state.

Next recommendation:

- Configure the real release secrets, rerun
  `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v<version> --npm-registry-check --require-ci --require-default-branch-head`,
  and create the production tag only after every live gate reports ready.

## Post Phase 15 - Tagged Release CI Readiness

Status: completed

Goal:

Fail production tag preparation before release package checks and platform
builds when the tag target commit does not have a completed successful `CI`
workflow run.

Completed work:

- Issue #268 is closed. PR #269 merged to `main` at merge commit
  `49b78057ce8be3f116324b8b9b8ac1a4bd57f165`, and branch
  `tagged-release-ci-readiness` is preserved.
- Added CI readiness metadata to `scripts/check-tagged-release-readiness.py`,
  including payload-safe status, conclusion, event, run id, created timestamp,
  workflow name, and target commit SHA.
- Added `--require-ci` for the full pre-tag readiness audit and `--ci-only` for
  release workflow preflight use without requiring GitHub secret-list access.
- Wired tagged `Release Artifacts` workflow preflight to fail before secret and
  signing checks when the tag target commit lacks a completed successful `CI`
  workflow run.
- Added `-RequireTaggedReleaseCi` and optional `-TaggedReleaseCiHead` to
  `scripts/verify-production-readiness.ps1`.
- Extended the tagged-release readiness regression to cover skipped CI checks,
  successful CI metadata, missing CI runs, failed CI runs, in-progress CI runs,
  invalid SHAs, and no leakage from unrelated sensitive payload fields.
- Updated README, distribution/production readiness/release checklist docs,
  repo memory, implementation guardrails, security checklist, and this plan.

Validation:

- `python -m py_compile scripts/check-tagged-release-readiness.py scripts/check-tagged-release-readiness-regression.py`
  passed.
- `python scripts/check-tagged-release-readiness-regression.py` passed.
- `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v0.1.0 --ci-only --ci-head 770dc6e19a7039718a01b38d2661040f40092bb1`
  passed against the latest green `main` CI run available before this change.
- `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v0.1.0 --npm-registry-check --require-ci --ci-head 770dc6e19a7039718a01b38d2661040f40092bb1 --json`
  correctly reported CI, Pages, npm registry, and release-clobber readiness
  while failing overall because live release secrets are still missing.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `git diff --check` passed.
- PR #269 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- The CI readiness gate proves the latest `CI` workflow run for the target
  commit, but it does not replace the dedicated release workflow checks that
  validate signing/notarization and publication behavior.

Next recommendation:

- Configure the real release secrets with
  `python scripts/set-github-release-secrets.py --repo imthegoodboy/conU --dry-run --preflight-values --require-openssl`,
  rerun without `--dry-run`, then run
  `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v<version> --npm-registry-check --require-ci`
  immediately before creating the production tag.

## Post Phase 15 - Release Secret Setup Value Preflight

Status: completed

Goal:

Run local signing-secret value preflights from the GitHub release secret setup
helper before any dry-run output or repository secret upload, so maintainers can
catch malformed Windows/macOS PKCS#12 values and Linux GPG signing values before
storing them in GitHub Actions.

Completed work:

- Issue #266 is closed. PR #267 merged to `main` at merge commit
  `cb2170153992f2b084dbfe44ddb8551853a859e4`, and branch
  `release-secret-setup-value-preflight` is preserved.
- Added `--preflight-values` to `scripts/set-github-release-secrets.py` to run
  platform signing and Linux signing value preflights before dry-run output or
  GitHub writes.
- Added `--require-openssl` for setup flows that must require OpenSSL-backed
  Windows/macOS PKCS#12 parsing.
- Kept GitHub secret values off command arguments and subprocess output; values
  still go to `gh secret set` through stdin only.
- Extended `scripts/set-github-release-secrets-regression.py` to prove both
  value preflights are called, subprocess output is suppressed, failing
  preflights report only exit codes, and secret sentinel values do not leak.
- Updated README, distribution/production readiness/release checklist docs,
  platform signing docs, repo memory, implementation guardrails, security
  checklist, and this plan.

Validation:

- `python -m py_compile scripts/set-github-release-secrets.py scripts/set-github-release-secrets-regression.py scripts/check-platform-signing-secrets-preflight.py scripts/check-linux-signing-secrets-preflight.py scripts/check-platform-signing-secrets-preflight-regression.py scripts/check-linux-signing-secrets-preflight-regression.py`
  passed.
- `python scripts/set-github-release-secrets-regression.py` passed.
- `python scripts/check-platform-signing-secrets-preflight-regression.py` passed
  with OpenSSL fixture coverage skipped locally because OpenSSL is unavailable.
- `python scripts/check-linux-signing-secrets-preflight-regression.py` passed
  with GPG fixture coverage skipped locally because GPG is unavailable.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally.
- `git diff --check` passed.
- PR #267 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- Local Windows validation cannot prove OpenSSL or GPG fixture paths unless
  those tools are installed; CI package checks covered the changed regression
  path, and release jobs cover the tagged secret preflight paths when secrets
  are configured.

Next recommendation:

- Configure the real release secrets with
  `python scripts/set-github-release-secrets.py --repo imthegoodboy/conU --dry-run --preflight-values --require-openssl`,
  rerun without `--dry-run`, then run
  `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v<version> --npm-registry-check`
  immediately before creating the production tag.

## Post Phase 15 - Platform Signing Secret Value Preflight

Status: completed

Goal:

Fail tagged releases before platform builds when Windows Authenticode or macOS
Developer ID signing certificate secrets are missing, malformed, password
mismatched, cert-only, or otherwise unusable as PKCS#12 signing material.

Completed work:

- Issue #264 is closed. PR #265 merged to `main` at merge commit
  `b5bcd6db7e3b7a5538931bf27e4b9dcef05e3584`, and branch
  `platform-signing-secret-value-preflight` is preserved.
- Added `scripts/check-platform-signing-secrets-preflight.py` for strict
  base64 checks, macOS notary field shape checks, timestamp URL checks, and
  optional OpenSSL-required PKCS#12 certificate/private-key parsing.
- Added `scripts/check-platform-signing-secrets-preflight-regression.py` for
  missing-value, malformed-base64, unsafe-field, no-leak, and OpenSSL fixture
  coverage.
- Wired the preflight into tagged release preflight before Linux signing
  validation and wired the regression into CI package checks, release package
  checks, and `scripts/verify-production-readiness.ps1`.
- Updated README, distribution/production readiness/release checklist docs,
  platform signing docs, repo memory, implementation guardrails, security
  checklist, and this plan.

Validation:

- `python -m py_compile scripts/check-platform-signing-secrets-preflight.py scripts/check-platform-signing-secrets-preflight-regression.py scripts/check-tagged-release-readiness.py scripts/check-linux-signing-secrets-preflight.py scripts/verify-release-versions.py`
  passed.
- `python scripts/check-platform-signing-secrets-preflight-regression.py`
  passed locally with OpenSSL parse coverage skipped because OpenSSL is not
  installed on this Windows workstation.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally; Windows workstation skips for unavailable OpenSSL/GPG/RPM
  native tools were clean and expected.
- PR #265 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit. The Linux package job installed OpenSSL and covered
  the PKCS#12 fixture path.

Known gaps:

- The live repository still requires maintainer-owned Windows, macOS, Linux GPG,
  and npm token secrets before a production `v*` tag can pass.
- Local Windows validation cannot prove OpenSSL, GPG, or RPM native paths unless
  those tools are installed; CI/release package jobs cover those paths.

Next recommendation:

- Configure the real GitHub release secrets, run
  `python scripts/check-platform-signing-secrets-preflight.py --require-openssl --json`,
  then run
  `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v<version> --npm-registry-check`
  immediately before creating the next production tag.

## Post Phase 15 - Tagged Release Readiness Audit

Status: completed

Goal:

Provide a single live, payload-safe maintainer audit before creating a
production `v*` tag, so release-secret name presence, default Pages or custom
S3 Linux repository settings, GitHub Release tag clobber status, package
version/tag consistency, and npm target availability are checked together.

Completed work:

- Issue #262 is closed. PR #263 merged to `main` at merge commit
  `09ed3f556d5edbf3d555455192b5da8487158e85`, and branch
  `tagged-release-readiness-audit` is preserved.
- Added `scripts/check-tagged-release-readiness.py` for the combined live audit.
- Added `scripts/check-tagged-release-readiness-regression.py` for payload-safe
  fixture coverage, missing release-secret coverage, default Pages readiness,
  custom S3 repository readiness, optional custom S3 variable validation, tag
  validation, and existing-release clobber failures without leaking unrelated
  release metadata.
- Wired the regression into CI package checks, release package checks, and
  `scripts/verify-production-readiness.ps1`.
- Updated README, distribution/production readiness/release checklist docs,
  repo memory, implementation guardrails, security checklist, and this plan.

Validation:

- `python -m py_compile scripts/check-tagged-release-readiness.py scripts/check-tagged-release-readiness-regression.py scripts/verify-release-versions.py scripts/check-github-pages-readiness.py scripts/check-github-release-clobber-preflight.py scripts/check-npm-publish-preflight.py`
  passed.
- `python scripts/check-tagged-release-readiness-regression.py` passed.
- `python scripts/check-github-release-secret-readiness-regression.py` passed.
- `python scripts/check-github-pages-readiness-regression.py` passed.
- `python scripts/check-github-release-clobber-preflight-regression.py` passed.
- `python scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/verify-release-versions.py` passed.
- Workflow YAML parse passed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally; Windows workstation skips for unavailable GPG/RPM native tools
  were clean and expected.
- `python scripts/check-github-pages-readiness.py --repo imthegoodboy/conU --json`
  passed against live repository Pages metadata.
- `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --json --npm-registry-check`
  failed closed as expected because all required production release secrets are
  missing; default Pages readiness, GitHub Release clobber status, package
  version/tag consistency, and npm target availability passed.
- PR #263 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.

Known gaps:

- The live repository still requires maintainer-owned signing certificates, GPG
  key material, and npm token secrets before a production `v*` tag can pass this
  audit.

Next recommendation:

- Configure the real GitHub release secrets and run
  `python scripts/check-tagged-release-readiness.py --repo imthegoodboy/conU --tag v<version> --npm-registry-check`
  immediately before creating the next production tag.

## Post Phase 15 - Package-Manager Submission Bundle

Status: completed

Goal:

Prepare a deterministic, verified package-manager submission bundle from the
generated Homebrew, Scoop, winget, Chocolatey, Debian, APT, RPM, and Linux
signing outputs so tagged releases publish repository-ready handoff paths
instead of requiring maintainers to assemble submission files by hand.

Completed work:

- Issue #260 is closed. PR #261 merged to `main` at merge commit
  `0579593bf50cdc31b10db9819d979776014207ce`, and branch
  `package-manager-submission-bundle` is preserved.
- Added `scripts/prepare-package-manager-submissions.py` to validate generated
  package-manager outputs, strict `.sha256` sidecars, optional required RPM
  assets, optional required APT/RPM repository metadata, optional required Linux
  detached signatures, public Linux GPG key assets, deterministic ZIP metadata,
  safe archive paths, forbidden secret/state text, and false display guards
  before writing `conu-<version>-package-manager-submissions.zip`.
- Added `scripts/check-package-manager-submissions.py` with generated fixture
  release assets, signed-output fixtures, deterministic bundle checks, strict
  sidecar checks, required-signature failure coverage, checksum mismatch
  coverage, forbidden-output coverage, and optional RPM requirement coverage.
- Extended `scripts/sign-linux-release-assets.py` with
  `--only-package-manager-submissions` so tagged releases can detached-sign the
  submission bundle after it is prepared.
- Extended the Linux release signing regression and GitHub Release asset
  publication preflight to require the signed submission bundle, strict sidecar,
  and detached `.asc` signature before npm registry access.
- Wired the submission-bundle regression into CI package checks, release package
  checks, and `scripts/verify-production-readiness.ps1`.
- Updated tagged release publication to prepare and sign the submission bundle
  after generated Linux package/metadata assets are signed and before hosted
  repository/update-policy publication continues.
- Updated README, distribution/production readiness/release checklist docs,
  packaging docs, package-manager docs, repo memory, implementation guardrails,
  security checklist, and this plan with the new handoff artifact boundary.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/prepare-package-manager-submissions.py`
- `scripts/check-package-manager-submissions.py`
- `scripts/sign-linux-release-assets.py`
- `scripts/check-linux-release-signing.py`
- `scripts/check-github-release-assets-published.py`
- `scripts/check-github-release-assets-published-regression.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/prepare-package-manager-submissions.py scripts/check-package-manager-submissions.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/check-github-release-assets-published.py scripts/check-github-release-assets-published-regression.py`
  passed.
- `python scripts/check-package-manager-submissions.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- `python -c "import yaml, pathlib; [yaml.safe_load(pathlib.Path(p).read_text()) for p in ['.github/workflows/ci.yml','.github/workflows/release.yml']]; print('workflow yaml parse passed')"`
  passed.
- `python scripts/check-linux-release-signing.py` skipped locally because `gpg`
  is unavailable on this Windows workstation; CI/release package checks cover
  the real Linux GPG signing path.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed locally; Windows workstation skips for unavailable GPG/RPM native tools
  were clean and expected.
- PR #261 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on
  Windows, and CodeRabbit.
- Branch `Release Artifacts` passed on run
  https://github.com/imthegoodboy/conU/actions/runs/26382945548, including
  release preflight, package checks, production-readiness smoke, artifact
  attestations/uploads, and all five platform builds.

Known gaps:

- External package-manager repository PRs/submissions still require maintainer
  review and submission outside this repository.
- Local Windows validation cannot prove the real GPG signature path without
  `gpg`; the Linux CI/release package job is expected to cover it.

Next recommendation:

- Continue with real signing/npm secret configuration, the next signed `v*`
  release, npm publication, external package-manager repository submissions,
  managed public relay hosting, distributed hosted dashboards/accounting/adaptive
  abuse automation, distributed multi-instance session migration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, managed hosted key administration, or ICE/STUN/TURN managed
  traversal.

## Post Phase 15 - Custom Hosted Linux Repository S3 Publication

Status: completed

Goal:

Publish the verified signed hosted Linux repository site to a custom
S3-compatible static host with explicit per-object cache headers, then require
a live endpoint readiness check before npm publication continues.

Completed work:

- PR #259 merged this hardening work to `main` at merge commit
  `04f4f8eccc3fb441c5057b5fdbc61353bda4591b`; Issue #258 is closed, and
  branch `custom-linux-repository-s3-publication` is preserved.
- Added `scripts/publish-hosted-linux-repository-s3.py` to validate the
  extracted hosted repository site, custom HTTPS base URL, bucket/prefix,
  optional S3-compatible endpoint, repository metadata, false display guards,
  safe paths, forbidden local-state text, exact cache-policy coverage, and AWS
  CLI upload arguments before publishing.
- Added `scripts/check-hosted-linux-repository-s3-publication.py` with a
  generated hosted-site fixture, dry-run report checks, fake AWS CLI upload
  checks, cache metadata assertions, workflow wiring assertions, and negative
  coverage for missing bucket, URL drift, forbidden text, uncovered cache
  paths, and unsafe endpoint URLs.
- Fixed hosted repository cache-policy coverage for `/.nojekyll`,
  `/apt/README.txt`, and `/rpm/README.txt` across generator, Pages preparer,
  and site regression checks.
- Wired the S3 publication regression into CI, release package checks, and
  `scripts/verify-production-readiness.ps1`.
- Updated tagged release flow so custom repository configuration preflight
  fails closed, the custom S3 publisher runs after GitHub Release publication,
  a Linux repository publication gate requires default Pages or custom S3
  success, and npm publication waits on that gate.
- Updated README, distribution docs, production readiness docs, release
  checklist, packaging docs, package-manager docs, repo memory, implementation
  guardrails, and security checklist to describe the supported custom S3 path
  and remaining operator-owned DNS/TLS/CDN boundary.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/publish-hosted-linux-repository-s3.py`
- `scripts/check-hosted-linux-repository-s3-publication.py`
- `scripts/generate-hosted-linux-repository-site.py`
- `scripts/prepare-hosted-linux-repository-pages.py`
- `scripts/check-hosted-linux-repository-site.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/publish-hosted-linux-repository-s3.py scripts/check-hosted-linux-repository-s3-publication.py`
  passed.
- `python scripts/check-hosted-linux-repository-s3-publication.py` passed.
- `python scripts/check-hosted-linux-repository-site.py` passed.
- `python scripts/check-hosted-linux-repository-pages.py` passed.
- `python scripts/check-hosted-linux-repository-endpoint-regression.py`
  passed.
- `python -c "import yaml, pathlib; [yaml.safe_load(pathlib.Path(p).read_text()) for p in ['.github/workflows/ci.yml','.github/workflows/release.yml']]; print('workflow yaml parse passed')"`
  passed.
- `python scripts/check-release-update-download-gate.py` passed.
- `python scripts/check-github-release-assets-published-regression.py`
  passed.
- `python scripts/check-github-release-clobber-preflight-regression.py`
  passed.
- `python scripts/check-github-pages-readiness-regression.py` passed.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including the new hosted Linux repository S3 publication regression,
  package checks, TypeScript SDK check, npm launcher checks, npm package
  content verification, npm publish preflights, and git diff whitespace check.
- PR #259 CI run `26381806881` passed, including package checks, Rust
  format/check/clippy/test on Ubuntu, macOS, and Windows, and CodeRabbit.
- Branch `Release Artifacts` run `26381810426` passed on
  `custom-linux-repository-s3-publication`, including release package checks,
  production readiness smoke, and all platform archive build/smoke jobs;
  publish, npm, Pages, and custom S3 publication jobs were skipped because this
  was a branch workflow-dispatch run.
- Local GPG/RPM-dependent regressions were skipped by the readiness script
  because `gpg`, `rpmbuild`, `rpmsign`/`rpm`, and `rpmkeys`/`rpm` are
  unavailable on this Windows workstation; CI/Release Artifacts covered those
  Linux signing paths.
- Rust checks were covered by PR #259 CI; local Rust checks were not rerun
  because this branch changes release/readiness Python scripts, workflow
  package gates, docs, and project memory only.

Known gaps:

- Local regression uses a fake AWS CLI and does not publish to a real bucket;
  the tagged release workflow covers real S3-compatible publication when the
  required vars/secrets are configured.
- DNS records, certificates, CDN invalidation, and non-S3 custom repository
  hosts remain operator-owned or future automation.
- Package-manager repository submission and unattended automatic update apply
  remain future work.

Next recommendation:

- Observe the next signed `v*` release with either default GitHub Pages or the
  configured custom S3-compatible repository target, then continue with DNS/TLS
  and CDN provisioning automation, non-S3 static-host publication automation,
  package-manager repository submission, unattended automatic update apply,
  managed public relay hosting, distributed hosted dashboards/accounting/
  adaptive abuse automation, distributed multi-instance session migration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, managed hosted key administration, or ICE/STUN/TURN managed
  traversal.

## Post Phase 15 - Hosted Linux Repository Endpoint Readiness

Status: completed

Goal:

Give operators a live custom HTTPS hosted Linux repository endpoint check that
proves generated endpoint metadata, `cache-policy.json`, `_headers`, and
served `Cache-Control` headers match before package-manager clients are pointed
at a non-default repository URL.

Completed work:

- PR #257 merged this hardening work to `main` at merge commit
  `d94e03e8977a4733e2afaddfe55ef0b6864a36fd`; Issue #256 is closed, and
  branch `hosted-linux-repository-endpoint-readiness` is preserved.
- Added `scripts/check-hosted-linux-repository-endpoint.py` for live endpoint
  readiness. It requires HTTPS by default, rejects credentials/query/fragment
  URLs, verifies `repository.json`, `cache-policy.json`, `_headers` parity,
  false display guards, same-base public repository/download URLs, and live
  `Cache-Control` headers for mutable metadata, repository metadata, and
  immutable release assets.
- Added `scripts/check-hosted-linux-repository-endpoint-regression.py` with a
  generated hosted-site fixture and local HTTP server to prove pass/fail
  behavior for loopback-only test URLs, metadata base URL drift, display-guard
  drift, `_headers` drift, and missing or wrong cache headers.
- Wired the endpoint regression into CI package checks, release package checks,
  and `scripts/verify-production-readiness.ps1`.
- Added `-CheckLinuxRepositoryEndpoint` to the production readiness script so a
  published custom endpoint can be checked with
  `-LinuxRepositoryBaseUrl <https-url>`.
- Updated README, distribution docs, production readiness docs, release
  checklist, packaging docs, package-manager docs, repo memory, implementation
  guardrails, and security checklist to document the live endpoint cache-policy
  proof and payload-safe boundary.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-hosted-linux-repository-endpoint.py`
- `scripts/check-hosted-linux-repository-endpoint-regression.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/check-hosted-linux-repository-endpoint.py scripts/check-hosted-linux-repository-endpoint-regression.py`
  passed.
- `python scripts/check-hosted-linux-repository-endpoint-regression.py` passed.
- `python -c "import yaml, pathlib; [yaml.safe_load(pathlib.Path(p).read_text()) for p in ['.github/workflows/ci.yml','.github/workflows/release.yml']]; print('workflow yaml parse passed')"`
  passed.
- `python scripts/check-hosted-linux-repository-site.py` passed.
- `python scripts/check-hosted-linux-repository-pages.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including the new hosted Linux repository endpoint regression,
  package checks, TypeScript SDK check, npm launcher checks, npm package
  content verification, npm publish preflights, and git diff whitespace check.
- PR #257 CI run `26380519684` passed, including package checks, Rust
  format/check/clippy/test on Ubuntu, macOS, and Windows, and CodeRabbit.
- Branch `Release Artifacts` run `26380612617` passed on
  `hosted-linux-repository-endpoint-readiness`, including release package
  checks, production readiness smoke, and all platform archive build/smoke
  jobs; publish, npm, and Pages jobs were skipped because this was a branch
  workflow-dispatch run.
- Local GPG/RPM-dependent regressions were skipped by the readiness script
  because `gpg`, `rpmbuild`, `rpmsign`/`rpm`, and `rpmkeys`/`rpm` are
  unavailable on this Windows workstation; CI/Release Artifacts must cover
  those Linux signing paths.
- Rust checks were not rerun because this branch changes release/readiness
  Python scripts, workflow package gates, docs, and project memory only.

Known gaps:

- The live endpoint check can prove only a custom endpoint after the signed
  hosted repository site is actually published by an operator; it does not
  automate DNS, TLS, CDN, or object-storage publication.
- Default GitHub Pages deployment remains covered by the existing Pages
  readiness and extraction checks; this new script is for non-default hosted
  repository endpoints.
- Package-manager repository submission and unattended automatic update apply
  remain future work.

Next recommendation:

- Observe the next signed `v*` release and any custom repository endpoint
  activation with the live endpoint readiness command, then continue with
  package-manager repository submission, custom DNS/TLS publication automation,
  managed public relay hosting, distributed hosted dashboards/accounting/
  adaptive abuse automation, distributed multi-instance session migration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, managed hosted key administration, or ICE/STUN/TURN managed
  traversal.

## Post Phase 15 - Tagged Public Release Update Apply Dry-Run Gate

Status: completed

Goal:

Make tagged GitHub Release publication prove the uploaded public update policy,
selected Linux archive download, and manual update apply dry-run path before
npm publication can start.

Completed work:

- PR #255 merged this hardening work to `main` at merge commit
  `5d303b32112689e000525a77a78f2258a99a9bf5`; Issue #254 is closed, and
  branch `published-update-apply-gate` is preserved.
- Extended the tagged `Release Artifacts` post-upload CLI gate so, after
  importing the published Linux public key and checking its fingerprint, it
  runs public `conu update check --policy-url --gpg-verify`, public
  `conu update download --policy-url --target linux-x64 --gpg-verify`, and
  public `conu update apply --policy-url --artifact-file <downloaded
  linux-x64 archive> --install-dir <temp dir> --target linux-x64
  --gpg-verify --dry-run`.
- Kept the gate inside the existing bounded retry loop so short GitHub Release
  asset propagation delays are handled consistently for check, download, and
  apply dry-run.
- Added a temporary apply install directory under `$RUNNER_TEMP` and removed it
  before every retry; dry-run apply must not write the install directory.
- Strengthened `scripts/check-release-update-download-gate.py` so CI/package
  checks assert the public apply dry-run command, temporary install directory,
  cleanup, release-note text, and success/error messages stay present.
- Renamed CI, release, and local readiness step labels from update-download
  only to update download/apply.
- Updated README, distribution, production-readiness, release checklist,
  packaging docs, package-manager docs, repo memory, implementation guardrails,
  and security checklist to document the public check/download/apply dry-run
  release gate.

Files changed:

- `.github/workflows/release.yml`
- `.github/workflows/ci.yml`
- `scripts/check-release-update-download-gate.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/check-release-update-download-gate.py` passed.
- `python scripts/check-release-update-download-gate.py` passed.
- `python -c "import yaml, pathlib; [yaml.safe_load(pathlib.Path(p).read_text()) for p in ['.github/workflows/ci.yml','.github/workflows/release.yml']]; print('workflow yaml parse passed')"`
  passed after fixing CI step indentation.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including the new release update download/apply gate regression,
  package checks, TypeScript SDK check, npm launcher checks, npm package content
  verification, npm publish preflights, and git diff whitespace check.
- PR #255 CI run `26379618433` passed, including package checks, Rust
  format/check/clippy/test on Ubuntu, macOS, and Windows, and CodeRabbit.
- Branch `Release Artifacts` run `26379626386` passed on
  `published-update-apply-gate`, including release package checks, production
  readiness smoke, and all platform archive build/smoke jobs; publish, npm, and
  Pages jobs were skipped because this was a branch workflow-dispatch run.
- Local GPG/RPM-dependent regressions were skipped by the readiness script
  because `gpg`, `rpmbuild`, `rpmsign`/`rpm`, and `rpmkeys`/`rpm` are
  unavailable on this Windows workstation; CI/Release Artifacts must cover
  those Linux signing paths.
- Rust checks were not rerun because this branch changes release workflow,
  regression script, readiness labels, docs, and project memory only.

Known gaps:

- The new apply dry-run gate will execute only on a real signed `v*` release
  after GitHub Release assets are uploaded; branch validation can only assert
  the workflow and regression wiring.
- The post-upload gate proves the linux-x64 archive path with dry-run apply; it
  does not perform confirmed replacement and does not dry-run every platform
  archive.
- `conu update apply` remains manual/consent-gated; unattended automatic update
  orchestration remains future work.

Next recommendation:

- Observe the next signed `v*` release to prove the public
  check/download/apply dry-run gate against real uploaded assets before npm
  publication, then continue with package-manager repository submission,
  custom DNS/TLS/cache-policy activation, managed public relay hosting,
  distributed hosted dashboards/accounting/adaptive abuse automation,
  distributed multi-instance session migration, remote/distributed tenant
  workflows, remote/cross-region mailbox retention orchestration, managed
  hosted key administration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Manual Release Update Apply

Status: completed

Goal:

Give operators a consent-gated way to apply a verified downloaded release
archive after `conu update check` and `conu update download`, without enabling
unattended auto-update behavior.

Completed work:

- PR #253 merged this hardening work to `main` at merge commit
  `75063c66519c5c04c20d1a5a4662198f17cefde0`; Issue #252 is closed, and
  branch `manual-update-apply` is preserved.
- Added `conu update apply --policy-file <path>|--policy-url <https-url>
  --artifact-file <archive> --install-dir <dir> [--target <target>]
  [--gpg-verify] (--dry-run|--confirm) [--json]`.
- The command revalidates the release update policy, selects the current target
  or explicit target, rejects cross-target application, verifies the downloaded
  archive against policy SHA-256 plus strict `.sha256` and `.asc` sidecars, and
  optionally verifies the detached signature with GPG while suppressing verifier
  output.
- Added bounded `.tar.gz` and `.zip` archive scanning that rejects oversized,
  duplicate, unsafe path, link, unexpected binary, and target-mismatched members
  before install.
- The apply path requires `payload_contents_included = false`, stages only
  `conu`, `conud`, `conu-relay`, and `conu-mcp` from `bin/`, supports dry-run
  without writing to the install directory, and requires `--confirm` before
  replacing binaries.
- Confirmed apply backs up existing regular-file binaries under the install
  directory before replacement, rejects symlink/non-file install targets, cleans
  staged temp files on failure, and restores backups if a replacement fails
  after an existing target was removed.
- Added Rust regression coverage for dry-run no-write behavior, confirmed
  install with backup, checksum drift before install, unsafe archive member
  rejection, and required `--dry-run|--confirm`.
- Updated README, distribution, production-readiness, release checklist,
  packaging docs, repo memory, implementation guardrails, and security
  checklist.

Files changed:

- `Cargo.lock`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all` ran and formatted the workspace.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-cli --all-targets`
  passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-cli --all-targets -- -D warnings`
  passed.
- `python -m py_compile scripts/check-release-update-policy.py scripts/check-release-update-download-gate.py`
  passed.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-release-update-download-gate.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including package/readiness, update-policy, update-download gate,
  TypeScript SDK, npm launcher, npm package content, and npm publish preflight
  checks.
- `cargo fmt --all -- --check` passed.
- `git diff --check` passed.
- Local `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli update_apply -- --nocapture`
  could not link because `dlltool.exe` is unavailable on this workstation; local
  default-toolchain `cargo test -p conu-cli update_apply -- --nocapture` also
  could not link because `link.exe` is unavailable. CI must run the focused and
  full Rust test matrix.
- PR #253 CI run `26378669931` passed after a fixture-only follow-up commit,
  including package checks and Rust format/check/clippy/test on Ubuntu, macOS,
  and Windows. Initial PR CI run `26378537628` failed because the unsafe-path
  regression tried to construct an invalid tar fixture; the regression now uses
  a ZIP fixture so the CLI rejection path is tested.
- Branch `Release Artifacts` run `26378752349` passed on
  `manual-update-apply`, including package checks, production-readiness smoke,
  and all platform archive build/smoke/attestation/upload jobs.

Known gaps:

- `conu update apply` is explicit/manual only; generated release policies still
  require `autoApply=false`, and unattended automatic update orchestration
  remains future work.
- Confirmed replacement can fail if the target install directory contains a
  running binary locked by the OS; operators should stop conU processes first or
  use package-manager/native installer flows.
- No real signed `v*` release has exercised check, download, and apply together
  against public uploaded release assets yet.

Next recommendation:

- Run a real signed release dry-run using `conu update check`,
  `conu update download`, and `conu update apply --dry-run` against public
  uploaded release assets before any confirmed production replacement.

## Post Phase 15 - Tagged Public Release Update Download Gate

Status: completed

Goal:

Make a real tagged GitHub Release prove that the uploaded public update policy
and selected release archive can be verified through the conU CLI before npm
publication can start.

Completed work:

- Issue #250 was closed by PR #251; PR #251 merged to `main` at merge commit
  `cd1281d5d020ab5e60b082dffba9813df6b8bba2`, and branch
  `published-update-download-gate` is preserved.
- Added a tagged `Release Artifacts` post-upload gate after `gh release create`
  that downloads the published `conu-linux-gpg-key.asc`, imports it into a
  temporary `GNUPGHOME`, verifies the public-key fingerprint against
  `CONU_LINUX_GPG_KEY_FINGERPRINT`, and then runs public
  `conu update check --policy-url --gpg-verify` plus
  `conu update download --policy-url --target linux-x64 --gpg-verify`.
- The gate retries bounded public verification to tolerate short GitHub Release
  asset propagation delays and writes update download output only under
  `$RUNNER_TEMP`.
- Added `scripts/check-release-update-download-gate.py` to assert the tagged
  workflow keeps the post-upload public update check/download gate and release
  notes text.
- Wired that regression into CI package checks, Release Artifacts package
  checks, and local production-readiness package validation.
- Updated README, distribution, production-readiness, release checklist,
  packaging docs, repo memory, implementation guardrails, and security
  checklist.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-release-update-download-gate.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `python scripts/check-release-update-download-gate.py` passed.
- `python -m py_compile scripts/check-release-update-download-gate.py scripts/check-release-update-policy.py`
  passed.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including the release update download gate regression and package
  readiness checks.
- `git diff --check` passed.
- PR #251 CI passed at commit `9094161d7c09be8eedbe47247de3861f379585c1`
  across package checks and Rust tests on Ubuntu, macOS, and Windows:
  https://github.com/imthegoodboy/conU/actions/runs/26377219064
- Branch `Release Artifacts` run `26377332371` passed at commit
  `9094161d7c09be8eedbe47247de3861f379585c1`:
  https://github.com/imthegoodboy/conU/actions/runs/26377332371
- PR #251 CI passed again at commit
  `7ac482558534fd1907e3c9563b39cd8f31edbf2d` across package checks and Rust
  tests on Ubuntu, macOS, and Windows:
  https://github.com/imthegoodboy/conU/actions/runs/26377507317
- Branch `Release Artifacts` run `26377576635` passed at commit
  `7ac482558534fd1907e3c9563b39cd8f31edbf2d`:
  https://github.com/imthegoodboy/conU/actions/runs/26377576635

Known gaps:

- The new gate only runs on real `v*` tag publication because it requires
  uploaded public GitHub Release assets and maintainer signing secrets.
- No real signed `v*` release has exercised the gate yet.
- Automatic update apply remains future work.

Next recommendation:

- Exercise the new gate during the first real signed `v*` release with signing
  and npm publish secrets configured; automatic update apply remains future
  work.

## Post Phase 15 - Verified Release Update Artifact Download

Status: completed

Goal:

Let installed clients fetch and verify one selected public platform archive
from a signed release update policy without applying or executing the update.

Completed work:

- Issue #248 was closed by PR #249; PR #249 merged to `main` at merge commit
  `4c797fcaeede2502928dda15ca0f5f418db245ac`, and branch
  `verified-update-artifact-download` is preserved.
- Added `conu update download --policy-file <path>|--policy-url <https-url>
  --output-dir <dir> [--target <target>] [--gpg-verify] [--json]`.
- The command revalidates the signed update policy first, defaults to the
  current platform target when detectable, or accepts an explicit public target.
- Remote mode uses the existing bounded HTTPS, TLS, public-host, timeout, size,
  and redirect limits, then downloads exactly one selected archive plus its
  strict `.sha256` and detached `.asc` sidecars.
- The downloader verifies the archive SHA-256 against policy metadata and the
  strict sidecar, validates the detached signature sidecar, optionally verifies
  the artifact with local trusted GPG keys, and suppresses detached signature
  contents and GPG output.
- Final outputs go only to an operator-chosen directory, refuse existing output
  files, and preflight all three final paths before writing any artifact file.
- Text and JSON renderers report public release metadata, selected artifact
  paths, checksum/signature/GPG booleans, bytes, and `updateApplied=false`
  without displaying payloads, secrets, key material, detached signature
  contents, or artifact bytes.
- Added focused Rust regression coverage for successful selected-artifact
  verification, checksum drift before output, existing-sidecar no-partial-write
  behavior, and required `--output-dir`.
- Updated README, distribution, production-readiness, release checklist,
  packaging docs, repo memory, implementation guardrails, and security
  checklist.

Files changed:

- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-cli --all-targets`
  passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-cli --all-targets -- -D warnings`
  passed.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including release/package/hosted repository/update policy,
  TypeScript SDK, npm launcher, npm package content, and npm publish preflight
  checks.
- `git diff --check` passed.
- Local `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli update_download -- --nocapture`
  could not link because `dlltool.exe` is unavailable on this workstation. CI
  must run the focused and full Rust test matrix.
- PR #249 CI passed at commit `5202f953340b31e32fafe1470f5d224e3759ef20`
  across package checks and Rust tests on Ubuntu, macOS, and Windows:
  https://github.com/imthegoodboy/conU/actions/runs/26376412233
- Branch `Release Artifacts` run `26376480062` passed at commit
  `5202f953340b31e32fafe1470f5d224e3759ef20`:
  https://github.com/imthegoodboy/conU/actions/runs/26376480062

Known gaps:

- The command verifies and stages a selected archive only; automatic update
  apply remains future work and must stay gated by operator consent.
- Optional `--gpg-verify` requires local `gpg` plus the trusted public release
  key.
- No real signed `v*` release has exercised `conu update download` against
  public uploaded release assets yet.

Next recommendation:

- Run post-merge main CI and main `Release Artifacts` for this plan update,
  then cut a real signed `v*` release and exercise both `conu update check
  --policy-url` and `conu update download --policy-url` against uploaded assets
  before designing automatic update apply.

## Post Phase 15 - Remote Release Update Policy Check

Status: completed

Goal:

Let installed clients validate published signed release update-policy metadata
from a public HTTPS URL without downloading update artifacts or applying an
update.

Completed work:

- Issue #246 was closed by PR #247; PR #247 merged to `main` at merge commit
  `0aee3926c05c45e2f1b168f0fb03808c6dd23a4d`, and branch
  `release-update-remote-check` is preserved.
- Added `conu update check --policy-url <https-url>` with optional
  `--sha256-url`, `--signature-url`, `--gpg-verify`, and `--json` flags.
- Remote mode fetches only the update-policy JSON, strict `.sha256` sidecar,
  and detached `.asc` sidecar, then reuses the same policy/schema/checksum/GPG
  validation path as local files.
- Remote downloads require HTTPS, certificate validation, public hosts,
  no credentials, no query or fragment on operator-provided URLs, bounded
  redirects, bounded response headers, per-file byte limits, and a 20-second
  read/write timeout.
- Remote output reports the requested public URLs, checksum/signature status,
  release metadata, asset counts, and false display guards only; temporary
  downloaded files are cleaned up and are not shown in JSON output.
- Added Rust regression coverage for downloaded remote policy validation,
  private-host rejection, and local/remote source mixing.
- Hardened downloaded policy sidecar writes to create the target temp
  directory defensively before writing, fixing the first PR CI test failure.
- Updated README, distribution, production-readiness, release checklist,
  packaging docs, repo memory, implementation guardrails, and security
  checklist.

Files changed:

- `Cargo.lock`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-cli --all-targets`
  passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-cli --all-targets -- -D warnings`
  passed.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including package, release, hosted repository, release update-policy,
  TypeScript SDK, npm launcher, and npm publication preflight checks.
- `git diff --check` passed.
- Local `cargo test -p conu-cli update_check -- --nocapture` could not link on
  this Windows workstation because the default MSVC target cannot find
  `link.exe`; a prior GNU-target test attempt also could not link because
  `dlltool.exe` is unavailable. CI must run the full Rust test matrix.
- PR #247 CI passed at commit `01b42134296043bf56f487611cfbe0a716f36a0a`
  across package checks and Rust tests on Ubuntu, macOS, and Windows:
  https://github.com/imthegoodboy/conU/actions/runs/26375670075
- Branch `Release Artifacts` run `26375729075` passed at commit
  `01b42134296043bf56f487611cfbe0a716f36a0a`:
  https://github.com/imthegoodboy/conU/actions/runs/26375729075

Known gaps:

- No real signed `v*` release has exercised `conu update check --policy-url`
  against public uploaded update-policy assets yet.
- Optional `--gpg-verify` requires the operator to have `gpg` and the trusted
  public release key installed locally.
- Remote mode validates signed update metadata only; verified selected-artifact
  download is implemented separately in the section above, while automatic
  update apply remains future work.

Next recommendation:

- Run post-merge main CI and main `Release Artifacts` for this plan update,
  then cut a real signed `v*` release and run both `conu update check
  --policy-url` and `conu update download --policy-url` against published
  assets before adding automatic update apply behavior.

## Post Phase 15 - Release Update Client Check

Status: completed

Goal:

Add an installed CLI command that consumes generated signed release
update-policy metadata and proves the client-side verification boundary without
automatic update application.

Completed work:

- Issue #244 was closed by PR #245 on branch `release-update-client-check`;
  PR #245 merged to `main` at merge commit
  `69d18e56683f6f106da28901f3543d5f932246c4`, and the branch is preserved.
- Added `conu update check --policy-file <path>` with optional
  `--sha256-file`, `--signature-file`, `--gpg-verify`, and `--json` flags.
- The command validates the update-policy JSON schema, semver/tag/channel
  shape, HTTPS public release URLs, strict `.sha256` sidecar, detached `.asc`
  sidecar presence, optional GPG verification, asset metadata arrays, npm
  package versions, false display guards, `autoApply=false`, downgrade denial,
  manual verification, and operator consent.
- Output reports public release metadata, checksum/signature status, asset
  counts, and privacy guards only; it does not fetch, download, install, or
  auto-apply updates.
- Tagged release publication now runs the installed CLI policy check after
  signing the generated update policy.
- Updated distribution, production readiness, release checklist, packaging
  docs, repo memory, implementation guardrails, and security checklist.

Files changed:

- `.github/workflows/release.yml`
- `Cargo.lock`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-cli --all-targets`
  passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-cli --all-targets -- -D warnings`
  passed.
- Workflow YAML parsed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed, including package, release, hosted repository, release update-policy,
  TypeScript SDK, npm launcher, and npm publication preflight checks.
- `git diff --check` passed.
- PR #245 CI passed for packages plus Rust on Ubuntu, macOS, and Windows.
- Branch `Release Artifacts` workflow run `26374877879` passed, including
  production readiness smoke, package checks, platform artifact build/smoke,
  and artifact attestation jobs.
- Local `cargo test -p conu-cli update_check -- --nocapture` could not link on
  this Windows workstation because the default MSVC target lacks `link.exe` and
  the GNU target lacks `dlltool.exe`; CI must run the full Rust test matrix.

Known gaps:

- This local-file mode does not download update artifacts or apply updates.
- Remote policy/sidecar fetch support is implemented separately on branch
  `release-update-remote-check`.
- Optional `--gpg-verify` requires the operator to have `gpg` and the trusted
  public release key installed locally.
- No real signed `v*` release has exercised the installed CLI check against
  public uploaded update-policy assets yet.

Next recommendation:

- Continue with remote policy/sidecar fetch validation and selected-artifact
  verification, then cut a real signed `v*` release and run `conu update check`
  plus `conu update download` against the published policy before adding
  automatic update apply behavior.

## Post Phase 15 - Release Update Policy Metadata

Status: completed

Goal:

Generate a signed, payload-safe release update policy artifact from the final
public release asset set so installers and future update clients can rely on
one strict metadata source instead of ad hoc latest-version checks.

Completed work:

- Issue #242 was closed by PR #243 on branch
  `release-update-policy-metadata`; PR #243 merged to `main` at merge commit
  `0d8973400230a9386f92a53bce25667e46adecd4`, and the branch is preserved.
- Added `scripts/generate-release-update-policy.py` to verify platform
  archives, strict `.sha256` sidecars, Linux/package/repository/hosted
  signatures, matching package versions, semver `v<version>` tags, and HTTPS
  public release URLs before writing `conu-<version>-update-policy.json`.
- The generated policy uses schema `conu.releaseUpdatePolicy.v1`, records
  public asset URLs, SHA-256 values, signature URLs, npm package versions, and
  manual verification rules, and sets `autoApply=false` plus false display
  guards.
- Added `scripts/check-release-update-policy.py` regression coverage for
  deterministic output, missing signatures, checksum drift, insecure release
  URLs, tag mismatch, forbidden text, and policy JSON shape.
- Extended `scripts/sign-linux-release-assets.py` and
  `scripts/check-linux-release-signing.py` with `--only-update-policies`
  signing coverage.
- Extended GitHub Release asset publication preflight so tagged npm publication
  requires the update policy JSON, `.sha256`, and `.asc` assets.
- Wired update-policy checks into CI package checks, Release Artifacts package
  checks, and local production-readiness package validation.
- Updated release/distribution/production-readiness/packaging docs, repo
  memory, implementation guardrails, and privacy/security checklist.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/generate-release-update-policy.py`
- `scripts/check-release-update-policy.py`
- `scripts/sign-linux-release-assets.py`
- `scripts/check-linux-release-signing.py`
- `scripts/check-github-release-assets-published.py`
- `scripts/check-github-release-assets-published-regression.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/generate-release-update-policy.py scripts/check-release-update-policy.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/check-github-release-assets-published.py scripts/check-github-release-assets-published-regression.py scripts/generate-hosted-linux-repository-site.py scripts/check-hosted-linux-repository-site.py scripts/prepare-hosted-linux-repository-pages.py scripts/check-hosted-linux-repository-pages.py` passed.
- `python scripts/check-release-update-policy.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- `python scripts/check-linux-release-signing.py` skipped cleanly because `gpg`
  is unavailable on this workstation.
- Workflow YAML parsed for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed, including the new release update-policy regression.
- `git diff --check` passed.
- PR #243 CI passed across package checks and Rust on Ubuntu, Windows, and
  macOS; CodeRabbit reported success.
- Branch `Release Artifacts` workflow_dispatch passed on
  `release-update-policy-metadata` run `26374127041`.

Known gaps:

- No real signed `v*` release has generated, signed, uploaded, and consumed this
  update policy yet, so tag-time production publication remains unexercised.
- conU includes installed `conu update check` and `conu update download`
  verification commands, while automatic update apply remains future work.
- Real signing/notarization/GPG/npm secrets, a real signed tag, npm
  publication, package-manager repository submissions, custom DNS/TLS/cache
  policy proof, and managed distributed hosted relay services remain external
  or future blockers.

Next recommendation:

- Continue with real signing/npm secret configuration, a signed `v*` release,
  npm publication, package-manager repository submissions, custom DNS/TLS
  endpoint activation with generated cache policy application, automatic update
  apply behavior beyond signed-policy and selected-artifact verification,
  managed public relay hosting, distributed hosted dashboards/accounting/adaptive abuse automation,
  distributed multi-instance session migration, remote/distributed tenant
  workflows, remote/cross-region mailbox retention orchestration, managed
  hosted key administration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Hosted Linux Repository Cache Policy

Status: completed

Goal:

Make the generated hosted Linux repository site carry checked cache policy
artifacts so custom static endpoints have a concrete, validated policy for
fresh package-manager metadata and immutable versioned downloads.

Completed work:

- Issue #240 was closed by PR #241 on branch
  `hosted-linux-repository-cache-policy`; PR #241 merged to `main` at merge
  commit `2f667a3a3af007ac25acb25fc7b5337a4aaea285`, and the branch is
  preserved.
- Added generated `cache-policy.json` metadata with schema
  `conu.hostedLinuxRepository.cachePolicy.v1`, cache rules for mutable site
  metadata, package-manager indexes, and immutable versioned package/download
  assets, plus false display guards.
- Added generated `_headers` Cache-Control rules for static hosts that support
  header files, and linked both cache artifacts from `repository.json`.
- Extended hosted site and Pages regressions so missing cache artifacts, unsafe
  cache metadata, forbidden display markers, and drift between `_headers` and
  `cache-policy.json` fail before deployment prep.
- Updated release/distribution/production-readiness/packaging docs, repo
  memory, implementation guardrails, and privacy/security checklist.

Files changed:

- `scripts/generate-hosted-linux-repository-site.py`
- `scripts/check-hosted-linux-repository-site.py`
- `scripts/prepare-hosted-linux-repository-pages.py`
- `scripts/check-hosted-linux-repository-pages.py`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/generate-hosted-linux-repository-site.py scripts/check-hosted-linux-repository-site.py scripts/prepare-hosted-linux-repository-pages.py scripts/check-hosted-linux-repository-pages.py` passed.
- `python scripts/check-hosted-linux-repository-site.py` passed.
- `python scripts/check-hosted-linux-repository-pages.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed, including hosted repository site and Pages regressions.
- `git diff --check` passed.
- PR #241 CI passed across package checks and Rust on Ubuntu, Windows, and
  macOS; CodeRabbit reported success.
- Branch `Release Artifacts` workflow_dispatch passed on
  `hosted-linux-repository-cache-policy` run `26373242767`.
- Post-merge main CI passed on run `26373409330`.
- Post-merge main `Release Artifacts` workflow_dispatch passed on run
  `26373411697`.

Known gaps:

- No real signed `v*` release has been cut with this generated cache policy
  artifact yet, so tag-time public release publication has not exercised it
  against production release assets.
- Custom DNS/TLS endpoint activation and proof that the operator host applies
  the generated cache policy remain external deployment steps.
- Real signing/notarization/GPG/npm secrets, a real signed tag, npm
  publication, package-manager repository submissions, auto-update, and managed
  distributed hosted relay services remain external or future blockers.

Next recommendation:

- Continue with real signing/npm secret configuration, a signed `v*` release,
  npm publication, package-manager repository submissions, custom DNS/TLS
  endpoint activation with generated cache policy application, auto-update,
  managed public relay hosting, distributed hosted dashboards/accounting/
  adaptive abuse automation, distributed multi-instance session migration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, managed hosted key administration, or ICE/STUN/TURN managed
  traversal.

## Post Phase 15 - GitHub Release Clobber Safety Preflight

Status: completed

Goal:

Fail tagged release publication before any automated asset overwrite when a
GitHub Release already exists for the tag.

Completed work:

- Issue #238 was closed by PR #239 on branch
  `github-release-clobber-preflight`; PR #239 merged to `main` at merge commit
  `0a197a42f6181828d0cc481c60a037fddeb1a7b1`, and the branch is preserved.
- Added `scripts/check-github-release-clobber-preflight.py` to query GitHub
  Release metadata through `gh api`, treat 404/not-found as an unpublished tag,
  fail when a release already exists for the tag unless an explicit maintainer
  recovery flag is used, and report only tag/existence/draft/prerelease/asset
  count metadata without printing release bodies, download URLs, or CLI stderr.
- Added `scripts/check-github-release-clobber-preflight-regression.py` with
  fixture coverage for absent releases, existing public releases, existing draft
  releases, tag mismatch, fixture JSON null handling, sanitized non-404 `gh`
  failures, invalid JSON, and output that omits unrelated release body/download
  URL sentinels.
- Wired the regression into CI package checks, Release Artifacts package checks,
  and local production-readiness package checks.
- Wired tagged `Release Tag Preflight` and the `github-release` publication job
  to run the live clobber preflight, and removed the normal `gh release upload
  --clobber` path so an existing GitHub Release fails instead of overwriting
  assets.
- Updated release/distribution/production-readiness/packaging docs, repo
  memory, implementation guardrails, and privacy/security checklist.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-github-release-clobber-preflight.py`
- `scripts/check-github-release-clobber-preflight-regression.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/check-github-release-clobber-preflight.py scripts/check-github-release-clobber-preflight-regression.py scripts/github_release_secrets.py` passed.
- `python scripts/check-github-release-clobber-preflight-regression.py` passed.
- `python scripts/check-github-release-clobber-preflight.py --repo imthegoodboy/conU --tag v0.1.0` passed against live GitHub metadata because no `v0.1.0` release exists.
- Workflow YAML parsed with Python/PyYAML for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed, including the new GitHub Release clobber regression.
- `git diff --check` passed.
- PR #239 CI passed across package checks and Rust on Ubuntu, Windows, and
  macOS; CodeRabbit reported success/skipped.
- Branch `Release Artifacts` workflow_dispatch passed on
  `github-release-clobber-preflight`.
- Post-merge main CI passed on run `26372693882`.
- Post-merge main `Release Artifacts` workflow_dispatch passed on run
  `26372698051`.

Known gaps:

- No real signed `v*` GitHub Release exists in this repository yet, so the
  workflow-level live preflight has not run during a true tagged release.
- Real signing/notarization/GPG/npm secrets, a real signed tag, npm
  publication, package-manager repository submissions, custom DNS/TLS/cache
  policy, auto-update, and managed distributed hosted relay services remain
  external or future blockers.

Next recommendation:

- Continue with real signing/npm secret configuration, a signed `v*` release,
  npm publication, package-manager repository submissions, custom DNS/TLS/cache
  policy, auto-update, managed public relay hosting, distributed hosted
  dashboards/accounting/adaptive abuse automation, distributed multi-instance
  session migration, remote/distributed tenant workflows, remote/cross-region
  mailbox retention orchestration, managed hosted key administration, or
  ICE/STUN/TURN managed traversal.

## Post Phase 15 - GitHub Release Asset Publication Preflight

Status: completed

Goal:

Fail tagged npm publication before npm registry access when the public GitHub
Release is incomplete, draft-only, tag-mismatched, duplicated, or contains
state/secret-looking asset names.

Completed work:

- Issue #236 was closed by PR #237 on branch
  `github-release-assets-preflight`; PR #237 merged to `main` at merge commit
  `0c5c2838a4a297454c99470af626e1a34f8ac46a`, and the branch is preserved.
- Added `scripts/check-github-release-assets-published.py` to load GitHub
  Release metadata through `gh api`, paginate the full release asset list by
  release id, and verify the required platform archives, strict checksum
  sidecars, Linux detached signatures, generated package-manager assets, Linux
  public-key asset, hosted Linux repository bundle, and hosted Linux repository
  site assets before npm publication.
- Added `scripts/check-github-release-assets-published-regression.py` with
  fixture coverage for expected asset names, missing assets, duplicate names,
  draft releases, tag mismatches, bad size/state metadata, forbidden
  state/secret-looking names, paginated asset loading, and output that omits
  unrelated release body/download URL fields.
- Wired the regression into CI package checks, Release Artifacts package checks,
  and local production-readiness package checks.
- Wired tagged `npm-publish` to run the live GitHub Release asset publication
  preflight after npm package-content verification and before npm registry
  conflict checks or publish commands.
- Updated release/distribution/production-readiness/packaging docs, repo
  memory, implementation guardrails, and privacy/security checklist.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-github-release-assets-published.py`
- `scripts/check-github-release-assets-published-regression.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts/check-github-release-assets-published.py scripts/check-github-release-assets-published-regression.py scripts/github_release_secrets.py` passed.
- `python scripts/check-github-release-assets-published-regression.py` passed.
- Workflow YAML parsed with Python/PyYAML for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml`.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed, including the new GitHub Release asset publication regression.
- `git diff --check` passed.
- PR #237 CI passed across package checks and Rust on Ubuntu, Windows, and
  macOS.
- Branch `Release Artifacts` workflow_dispatch passed on
  `github-release-assets-preflight`.

Known gaps:

- No real `v*` GitHub Release exists in this repository yet, so the live
  publication preflight has not been exercised against an actual public release.
  It is wired to run on tagged npm publication after the GitHub Release job.
- Real signing/notarization/GPG/npm secrets, a real signed tag, npm
  publication, package-manager repository submissions, custom DNS/TLS/cache
  policy, auto-update, and managed distributed hosted relay services remain
  external or future blockers.

Next recommendation:

- Run post-merge main CI and main Release Artifacts verification, then continue
  with real signing/npm secret configuration, a signed `v*` release, npm
  publication, package-manager repository submissions, custom DNS/TLS/cache
  policy, auto-update, managed public relay hosting, distributed hosted
  dashboards/accounting/adaptive abuse automation, distributed multi-instance
  session migration, remote/distributed tenant workflows, remote/cross-region
  mailbox retention orchestration, managed hosted key administration, or
  ICE/STUN/TURN managed traversal.

## Post Phase 15 - GitHub Release Secret Automation

Status: completed

Goal:

Make the maintainer-owned release secret blocker visible and easier to clear
without printing or passing secret values in command arguments.

Completed work:

- Issue #222 was closed by PR #223 on branch
  `release-secret-readiness-audit`; PR #223 merged to `main` at merge commit
  `fbe39b8732ceaa5152049c3488b56ec4751d7f70`, and the branch is preserved.
- Added `scripts/check-github-release-secret-readiness.py` to audit required
  GitHub repository secret names through GitHub CLI metadata without reading or
  printing values.
- Issue #224 was closed by PR #225 on branch `release-secret-setup-tooling`;
  PR #225 merged to `main` at merge commit
  `bcf166938fa8d3dc1a544c296d8a2b90ef46f459`, and the branch is preserved.
- Added `scripts/set-github-release-secrets.py` to read all required release
  secret values from local environment variables and send them to
  `gh secret set` over stdin, not command arguments.
- Follow-up Issue #226 was closed by PR #227 on branch
  `release-secret-readiness-cli-fix`; PR #227 merged to `main` at merge commit
  `6c688653193e87f0c107ba66fdba0fb0d60582e6`, and the branch is preserved.
  This restored direct readiness CLI execution and added a `main()` regression.
- Shared required release secret metadata in `scripts/github_release_secrets.py`.
- Wired readiness/setup regressions into CI, Release Artifacts package checks,
  and local production-readiness package checks.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/github_release_secrets.py`
- `scripts/check-github-release-secret-readiness.py`
- `scripts/check-github-release-secret-readiness-regression.py`
- `scripts/set-github-release-secrets.py`
- `scripts/set-github-release-secrets-regression.py`
- `scripts/verify-production-readiness.ps1`
- `docs/release-checklist.md`
- `plan.md`

Known gaps:

- The actual signing certificates, Apple notarization credentials, Linux GPG
  private key/passphrase/key id/fingerprint, and `NPM_TOKEN` are not present in
  the repository secrets or local environment on this machine, so a real signed
  `v*` release remains externally blocked until the maintainer provides them.
- This does not publish npm packages, submit package-manager repository PRs, or
  host APT/RPM repositories.

Validation:

- `python -m py_compile scripts/github_release_secrets.py scripts/check-github-release-secret-readiness.py scripts/check-github-release-secret-readiness-regression.py scripts/set-github-release-secrets.py scripts/set-github-release-secrets-regression.py` passed.
- `python scripts/check-github-release-secret-readiness-regression.py` passed.
- `python scripts/set-github-release-secrets-regression.py` passed.
- `python scripts/set-github-release-secrets.py --repo imthegoodboy/conU --dry-run`
  with fake local environment values passed and printed only secret names.
- `python scripts/check-github-release-secret-readiness.py --repo imthegoodboy/conU`
  correctly failed because all 13 required repository secret names are missing.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- Workflow YAML parsed with Python/PyYAML.
- `git diff --check` passed.
- PR #223 CI, PR #225 CI, post-merge main CI, and post-merge Release Artifacts
  workflow runs passed where applicable.

## Post Phase 15 - Linux Signing Secret Preflight

Status: completed

Goal:

Fail tagged releases before package checks and platform builds when Linux GPG
signing secrets are missing, malformed, point to the wrong maintainer key, or
cannot produce a detached signature with the configured passphrase.

Completed work:

- Issue #220 was closed by PR #221 on branch
  `linux-signing-secret-preflight`; PR #221 merged to `main` at merge commit
  `16445ddd9e5d836d02dbf8edf2dcf6d95befc21d`, and the branch is preserved.
- Added `scripts/check-linux-signing-secrets-preflight.py` to import the
  configured Linux GPG private key into a temporary keyring, verify the key id
  resolves to `CONU_LINUX_GPG_KEY_FINGERPRINT`, and probe-sign/verify a
  temporary file without writing release artifacts.
- Added `scripts/check-linux-signing-secrets-preflight-regression.py` to cover
  success, missing secrets, strict base64 failure, invalid fingerprint,
  fingerprint mismatch, and wrong-passphrase failure.
- Wired the regression into CI, Release Artifacts package checks, and local
  production-readiness package checks.
- Wired tagged `Release Tag Preflight` to checkout the repo only for `v*` tags,
  install `gnupg`, and run the Linux signing-secret preflight before package
  checks or builds.
- Updated release, distribution, packaging, repo memory, guardrail,
  security-checklist, and plan docs.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-linux-signing-secrets-preflight.py`
- `scripts/check-linux-signing-secrets-preflight-regression.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`, `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- The real maintainer fingerprint still has to be chosen, configured as the
  repository secret, and published in a stable user-facing location before a
  real `v*` release.
- This does not publish to keyservers, rotate maintainer keys, host APT/RPM
  repositories, submit package-manager repository PRs, publish npm packages, or
  perform a real tagged release.

Validation:

- `python -m py_compile scripts/check-linux-signing-secrets-preflight.py scripts/check-linux-signing-secrets-preflight-regression.py scripts/linux_gpg_common.py` passed.
- `python -m py_compile scripts/linux_gpg_common.py scripts/check-linux-signing-secrets-preflight.py scripts/check-linux-signing-secrets-preflight-regression.py scripts/sign-rpm-packages.py scripts/check-rpm-package-signing.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/sign-linux-repository-metadata.py scripts/check-linux-repository-signing.py scripts/export-linux-gpg-public-key.py scripts/check-linux-gpg-public-key-export.py scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py scripts/verify-release-versions.py scripts/verify-release-artifacts.py scripts/verify-npm-package-contents.py scripts/check-release-artifact-verifier.py scripts/check-release-artifact-smoke-preflight.py scripts/check-npm-launcher-local-smoke-preflight.py scripts/check-npm-publish-preflight.py scripts/check-npm-publish-preflight-regression.py` passed.
- Workflow YAML parsed with Python/PyYAML.
- `python scripts/check-linux-signing-secrets-preflight-regression.py` skipped
  cleanly on native Windows because `gpg` is unavailable.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-signing-secrets-preflight-regression.py'`
  passed with real GPG import, fingerprint, probe-signing, and failure cases.
- `python scripts/check-package-manager-manifests.py` and
  `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'`
  passed.
- Native Windows GPG/RPM signing checks skipped cleanly because `gpg`,
  `rpmbuild`, `rpmsign`/`rpm`, and `rpmkeys`/`rpm` are unavailable locally:
  `python scripts/check-linux-release-signing.py`,
  `python scripts/check-linux-repository-signing.py`,
  `python scripts/check-linux-gpg-public-key-export.py`, and
  `python scripts/check-rpm-package-signing.py`.
- WSL real-GPG regressions passed:
  `python3 scripts/check-linux-release-signing.py`,
  `python3 scripts/check-linux-repository-signing.py`, and
  `python3 scripts/check-linux-gpg-public-key-export.py`; WSL
  `python3 scripts/check-rpm-package-signing.py` skipped cleanly because native
  RPM signing tools are unavailable.
- `python scripts/verify-release-versions.py`,
  `python scripts/check-release-artifact-verifier.py`,
  `python scripts/check-release-artifact-smoke-preflight.py`,
  `python scripts/verify-npm-package-contents.py`,
  `python scripts/check-npm-publish-preflight.py`,
  `python scripts/check-npm-publish-preflight-regression.py`, and
  `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` and
  `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out
  after 15 minutes without output, so targeted diff review plus PR CI and branch
  `Release Artifacts` gates covered final review.
- PR #221 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26363122839>.
- Branch `Release Artifacts` passed on `linux-signing-secret-preflight`:
  <https://github.com/imthegoodboy/conU/actions/runs/26363127535>.

Next:

- Continue with hosted APT/RPM repository publication, package-manager
  repository submission, npm package publication, auto-update policy,
  maintainer fingerprint publication once the real key is chosen, managed
  public relay hosting, distributed hosted dashboards/adaptive abuse automation,
  distributed multi-instance session migration, managed hosted identity/key
  administration, remote/distributed tenant workflows, remote/cross-region
  mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Hosted Linux Repository Pages Deployment

Status: completed

Goal:

Publish the signed hosted Linux repository site through a release workflow path
when the repository uses the default GitHub Pages URL, while keeping custom
operator URLs as explicit external deployments.

Completed work:

- Issue #232 was closed by PR #233 on branch
  `linux-repository-pages-deploy`; PR #233 merged to `main` at merge commit
  `60a02a47a5399cb3e5043023e369d814b17edc89`, and the branch is preserved.
- Added `scripts/prepare-hosted-linux-repository-pages.py` to verify a hosted
  Linux repository site ZIP, its strict `.sha256` sidecar, and its detached
  `.asc` signature before extracting it to an empty static directory.
- The Pages preparer rejects unsafe paths, duplicate ZIP members, unsupported
  member types, forbidden local-state path segments, unexpected members,
  missing repository files, malformed or non-HTTPS `repository.json` metadata,
  mismatched embedded hosted-bundle checksums, and private-key/token/payload/
  ciphertext marker strings in text files.
- Added `scripts/check-hosted-linux-repository-pages.py` with fixture coverage
  for successful extraction, missing sidecar, missing signature, unsafe member
  path, forbidden text marker, insecure repository URL, and non-empty output
  directory failures.
- Wired the Pages regression into CI package checks, Release Artifacts package
  checks, and the local production-readiness package gate.
- Wired tagged release publication to prepare and upload a verified static site
  artifact after the signed hosted repository site ZIP is generated.
- Added a tag-only `Deploy Linux Repository Pages` job using
  `actions/configure-pages@v6`, `actions/upload-pages-artifact@v5`, and
  `actions/deploy-pages@v5` when `CONU_LINUX_REPOSITORY_BASE_URL` is not set.
- Updated distribution, release, packaging, repo-memory, guardrail, security,
  and plan docs to describe default GitHub Pages deployment and remaining
  custom DNS/TLS/cache responsibility.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/prepare-hosted-linux-repository-pages.py`
- `scripts/check-hosted-linux-repository-pages.py`
- `scripts/verify-production-readiness.ps1`
- `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- Real tagged deployment still requires all release signing, notarization, Linux
  GPG, and npm secrets to be configured before the `v*` release workflow can
  reach the Pages job.
- Repository GitHub Pages must stay configured for the Actions source for
  automatic default Pages deployment; follow-up Issue #234 on branch
  `github-pages-readiness-preflight` adds live metadata preflight coverage for
  that external repository setting. Custom repository URLs set through
  `CONU_LINUX_REPOSITORY_BASE_URL` still require operator-owned DNS/TLS/cache
  publishing outside this workflow.
- Package-manager repository submission, npm package publication, auto-update
  policy, and the broader managed public relay work remain separate blockers.

Validation:

- `python -m py_compile scripts/prepare-hosted-linux-repository-pages.py scripts/check-hosted-linux-repository-pages.py` passed.
- `python scripts/check-hosted-linux-repository-pages.py` passed.
- `python scripts/check-hosted-linux-repository-site.py` passed.
- Workflow YAML parsed with Python/PyYAML.
- `python scripts/check-package-manager-manifests.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed.
- `git diff --check` passed.
- PR #233 CI passed: package checks, Rust Ubuntu, Rust Windows, Rust macOS,
  and CodeRabbit.
- Branch `Release Artifacts` passed on `linux-repository-pages-deploy`:
  package checks, production readiness smoke, all platform build/verify/smoke
  jobs, attestations, and artifact uploads passed.
- Post-merge main CI passed on closeout commit
  `856545d6b8881224ce641a796dcda579830e50d7`, including package checks with
  hosted Linux repository Pages regression plus Rust Ubuntu, Rust Windows, and
  Rust macOS.
- Post-merge non-tag `Release Artifacts` passed on `main` run `26370134251`:
  package checks with hosted Linux repository Pages regression, production
  readiness smoke, all platform build/verify/smoke jobs, attestations, and
  artifact uploads passed. Publish GitHub Release, Deploy Linux Repository
  Pages, and Publish npm Packages skipped because this was not a tag run.

Next:

- Continue with real release secret configuration, package publication, custom
  DNS/TLS/cache policy, package-manager submission, auto-update policy, or
  managed public relay hardening.

## Post Phase 15 - GitHub Pages Readiness Preflight

Status: completed

Goal:

Make the default hosted Linux repository GitHub Pages repository setting
visible and fail-closed before tagged release builds when the repository uses
the default Pages endpoint.

Completed work:

- Issue #234 was closed by PR #235 on branch
  `github-pages-readiness-preflight`; PR #235 merged to `main` at merge commit
  `7019487232433ad451724b67ae0b15ebe59beaee`, and the branch is preserved.
- Configured repository GitHub Pages through GitHub CLI/API for
  `build_type=workflow`, HTTPS enforcement, public serving, and
  `https://imthegoodboy.github.io/conU/`.
- Added `scripts/check-github-pages-readiness.py` to audit live GitHub Pages
  metadata or fixture JSON without reading repository secrets, token values,
  signing material, or private payloads.
- Added `scripts/check-github-pages-readiness-regression.py` to cover ready
  metadata, legacy build type, disabled HTTPS, non-public Pages, URL mismatch,
  source drift, custom HTTPS repository URL handling, default-URL misuse through
  `CONU_LINUX_REPOSITORY_BASE_URL`, and loader/main behavior.
- Wired the regression into CI package checks, Release Artifacts package
  checks, and local production-readiness package checks.
- Wired tagged `Release Tag Preflight` to run the live Pages metadata check
  when `CONU_LINUX_REPOSITORY_BASE_URL` is unset, before package checks and
  platform builds.
- Added optional local production-readiness live check support through
  `scripts/verify-production-readiness.ps1 -CheckGitHubPages`.
- Updated release/distribution/production-readiness/packaging docs, repo
  memory, guardrails, security checklist, and plan docs.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-github-pages-readiness.py`
- `scripts/check-github-pages-readiness-regression.py`
- `scripts/verify-production-readiness.ps1`
- `docs/`, `packaging/`, `.agents/`, and `plan.md`

Validation:

- `python -m py_compile scripts/check-github-pages-readiness.py scripts/check-github-pages-readiness-regression.py`
  passed.
- `python scripts/check-github-pages-readiness-regression.py` passed.
- `python scripts/check-github-pages-readiness.py --repo imthegoodboy/conU`
  passed against live GitHub Pages metadata.
- `python scripts/check-github-pages-readiness.py --repo imthegoodboy/conU --linux-repository-base-url https://packages.example.com/conu`
  passed the custom HTTPS URL path.
- Workflow YAML parsed with Python/PyYAML.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes -CheckGitHubPages -GitHubRepo imthegoodboy/conU`
  passed, including the new regression and live Pages readiness check.
- PR #235 CI passed: package checks with the new GitHub Pages readiness
  regression plus Rust Ubuntu, Rust Windows, Rust macOS, and CodeRabbit.
- Branch `Release Artifacts` passed on `github-pages-readiness-preflight` run
  `26370915438`: release preflight non-tag smoke mode, package checks with the
  new regression, production readiness smoke, all platform build/verify/smoke
  jobs, attestations, and artifact uploads passed. Publish GitHub Release,
  Deploy Linux Repository Pages, and Publish npm Packages skipped because this
  was not a tag run.
- Post-merge main CI passed on merge commit
  `7019487232433ad451724b67ae0b15ebe59beaee` run `26371085714`, including
  Packages plus Rust Ubuntu, Rust Windows, and Rust macOS.
- Post-merge main non-tag `Release Artifacts` passed on run `26371172686`,
  including release preflight non-tag smoke mode, package checks with the new
  regression, production readiness smoke, all platform build/verify/smoke jobs,
  attestations, and artifact uploads. Publish GitHub Release, Deploy Linux
  Repository Pages, and Publish npm Packages skipped because this was not a tag
  run.

Known gaps:

- This preflight verifies the GitHub Pages repository metadata, not a completed
  deployed site for a future tag. The real deployment still requires a signed
  `v*` release and all release/npm/signing secrets.
- Custom repository URLs configured through `CONU_LINUX_REPOSITORY_BASE_URL`
  are treated as operator-owned HTTPS hosting and still need external
  DNS/TLS/cache operations outside this workflow.
- Package-manager repository submission, npm package publication, auto-update
  policy, and broader managed public relay readiness remain separate blockers.

Next:

- Continue with real release secret configuration, a signed `v*` release, npm
  publication, package-manager repository submission, custom DNS/TLS/cache
  policy for non-default endpoints, auto-update policy, or managed public relay
  hardening.

## Post Phase 15 - Hosted Linux Repository Site Artifact

Status: completed

Goal:

Generate a signed static-site artifact for operator-hosted Linux package
repositories so a maintainer can extract one ZIP onto a static HTTPS endpoint
and serve APT/YUM repository trees, endpoint metadata, install snippets, and
signed-bundle downloads without hand-editing hashes or repository metadata.

Completed work:

- Issue #230 was closed by PR #231 on branch
  `hosted-linux-repository-site`; PR #231 merged to `main` at merge commit
  `5b44b9219fa520784cb40e72c75a037877c46c26`, and the branch is preserved.
- Added `scripts/generate-hosted-linux-repository-site.py` to build
  `conu-<version>-hosted-linux-repository-site.zip` from the signed hosted
  repository bundle, its strict `.sha256` sidecar, and its detached `.asc`
  signature.
- The generated site ZIP contains deterministic public `apt/` and `rpm/`
  trees from the bundle, `.nojekyll`, `README.txt`, `index.html`,
  `repository.json`, `install/conu.list`, `install/conu.repo`, and
  `downloads/` copies of the signed hosted repository bundle plus sidecars.
- The generator requires an explicit absolute HTTPS base URL through
  `--base-url` or `CONU_LINUX_REPOSITORY_BASE_URL`, rejects params/query/
  fragment URLs, validates hosted bundle paths and required public signature
  members, verifies the bundle checksum sidecar, and scans generated text for
  private-key, token, token-hash, payload, and ciphertext markers.
- Added `scripts/check-hosted-linux-repository-site.py` to validate
  deterministic ZIP layout, install snippets, `repository.json`, download
  copies, HTTPS base URL enforcement, missing-signature rejection, and unsafe
  hosted-bundle path rejection.
- Extended `scripts/sign-linux-release-assets.py` with
  `--only-hosted-repository-sites`, and extended
  `scripts/check-linux-release-signing.py` to prove the site-only signing mode
  signs only hosted repository site ZIPs.
- Wired the hosted repository site regression into CI, Release Artifacts
  package checks, and local production-readiness package checks.
- Wired tagged release publication to generate the site after the hosted bundle
  is signed, using repository variable `CONU_LINUX_REPOSITORY_BASE_URL` when
  set or the repository GitHub Pages URL as the fallback, then detached-sign the
  site artifact before GitHub Release upload.
- Updated distribution, release, packaging, repo-memory, guardrail, security,
  and plan docs to describe the signed site artifact and the remaining real
  DNS/TLS/static hosting deployment gap.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/generate-hosted-linux-repository-site.py`
- `scripts/check-hosted-linux-repository-site.py`
- `scripts/sign-linux-release-assets.py`
- `scripts/check-linux-release-signing.py`
- `scripts/verify-production-readiness.ps1`
- `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- Real static hosting deployment still requires maintainer-owned DNS/TLS/cache
  configuration and extraction/publishing of the generated site artifact.
- Package-manager repository submission, npm package publication, auto-update
  policy, real signing/notarization/npm secrets, and the broader managed public
  relay work remain separate blockers.

Validation:

- `python -m py_compile scripts/generate-hosted-linux-repository-site.py scripts/check-hosted-linux-repository-site.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py` passed.
- `python scripts/check-hosted-linux-repository-site.py` passed.
- `python scripts/check-hosted-linux-repositories.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- `python scripts/check-linux-release-signing.py` skipped cleanly on native
  Windows because `gpg` is unavailable.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'`
  passed with real GPG, including hosted-site-only signing mode.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed.
- Workflow YAML parsed with Python/PyYAML.
- `git diff --check` passed.
- PR #231 CI passed: package checks, Rust Ubuntu, Rust Windows, Rust macOS,
  and CodeRabbit.
- Branch `hosted-linux-repository-site` was preserved after merge.
- Post-merge main CI passed on closeout commit `7f2af94f8dfc596c5c12e81b8abc143313867a27`.
- Post-merge non-tag `Release Artifacts` passed on `main` after rerunning a
  transient Windows artifact-attestation failure; package checks, production
  readiness smoke, all platform build/verify/smoke jobs, attestations, and
  artifact uploads passed.

Next:

- Continue with real DNS/TLS/static hosting deployment, package-manager
  repository submission, npm package publication, auto-update policy,
  maintainer fingerprint publication once the real key is chosen, managed
  public relay hosting, distributed hosted dashboards/adaptive abuse
  automation, distributed multi-instance session migration, managed hosted
  identity/key administration, remote/distributed tenant workflows,
  remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN
  managed traversal.

## Post Phase 15 - Hosted Linux Repository Bundles

Status: completed

Goal:

Generate a static hosted Linux repository bundle from the signed release
assets so tagged releases can publish APT/YUM-ready repository trees without
rewriting package metadata by hand.

Completed work:

- Issue #228 was closed by PR #229 on branch
  `hosted-linux-repository-bundles`; PR #229 merged to `main` at merge commit
  `7a1a03a2d75417f1ec07500ac909817d3957cadc`, and the branch is preserved.
- Added `scripts/generate-hosted-linux-repositories.py` to build
  `conu-<version>-hosted-linux-repositories.zip` from already signed Debian
  packages, signed RPM packages, signed APT/RPM repository metadata, detached
  package signatures, strict SHA-256 sidecars, and `conu-linux-gpg-key.asc`.
- Added `scripts/check-hosted-linux-repositories.py` to validate deterministic
  bundle layout, flat APT metadata, RPM `repodata/` references, public key
  copies, embedded package signatures, strict sidecars, unsafe ZIP path
  rejection, missing-signature rejection, and private-key rejection.
- Extended Linux release detached signing with
  `--only-hosted-repository-bundles` so the release workflow can sign the
  hosted bundle after it embeds the previously generated package and repository
  signatures.
- Wired hosted repository regression coverage into CI, Release Artifacts
  package checks, and local production-readiness package checks.
- Wired tagged release publication to generate the hosted repository bundle
  after Linux package/metadata signatures exist, then detached-sign the bundle
  before GitHub Release upload.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/generate-hosted-linux-repositories.py`
- `scripts/check-hosted-linux-repositories.py`
- `scripts/sign-linux-release-assets.py`
- `scripts/check-linux-release-signing.py`
- `scripts/verify-production-readiness.ps1`
- `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- The generated bundle still needs an operator-owned static hosting endpoint,
  DNS/TLS, cache policy, and package-manager source documentation before users
  can install from hosted APT/YUM URLs.
- Package-manager repository submission, npm package publication, auto-update
  policy, real signing/notarization/npm secrets, and the broader managed public
  relay work remain separate blockers.

Validation:

- `python -m py_compile scripts/generate-hosted-linux-repositories.py scripts/check-hosted-linux-repositories.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py` passed.
- `python scripts/check-hosted-linux-repositories.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- `python scripts/check-linux-release-signing.py` skipped cleanly on native
  Windows because `gpg` is unavailable.
- `python scripts/check-linux-repository-signing.py` skipped cleanly on native
  Windows because `gpg` is unavailable.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'`
  passed with real GPG, including hosted-bundle-only signing mode.
- `powershell -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes`
  passed.
- Workflow YAML parsed with Python/PyYAML.
- `git diff --check` passed.
- PR #229 CI passed: package checks, Rust Ubuntu, Rust Windows, Rust macOS,
  and CodeRabbit.

Next:

- Continue with operator-hosted APT/RPM endpoint publication docs/scripts,
  package-manager repository submission, npm package publication,
  auto-update policy, maintainer fingerprint publication once the real key is
  chosen, managed public relay hosting, distributed hosted dashboards/adaptive
  abuse automation, distributed multi-instance session migration, managed
  hosted identity/key administration, remote/distributed tenant workflows,
  remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN
  managed traversal.

## Post Phase 15 - Linux Signing Key Fingerprint Policy

Status: completed

Goal:

Require Linux release signing and public-key export steps to prove the imported
maintainer GPG key id resolves to the expected full primary fingerprint before
producing RPM package signatures, native repository metadata signatures,
detached Linux `.asc` signatures, or the Linux public-key release asset.

Completed work:

- Issue #218 was closed by PR #219 on branch
  `linux-gpg-fingerprint-policy`; PR #219 merged to `main` at merge commit
  `cea2817bba74a297de2912436b03f21b4b3a79e3`, and the branch is preserved.
- Added shared Linux GPG fingerprint helpers under `scripts/` and wired them
  into RPM package signing, Linux detached signing, repository metadata signing,
  and public-key export.
- Updated signing regressions to set the expected full fingerprint and prove
  mismatched fingerprints fail closed.
- Wired tagged release preflight and Linux signing/export steps to require
  `CONU_LINUX_GPG_KEY_FINGERPRINT`.
- Updated release, distribution, packaging, user install, repo memory,
  guardrail, security-checklist, and plan docs.

Files changed:

- `.github/workflows/release.yml`
- `scripts/linux_gpg_common.py`
- `scripts/sign-rpm-packages.py`
- `scripts/sign-linux-release-assets.py`
- `scripts/sign-linux-repository-metadata.py`
- `scripts/export-linux-gpg-public-key.py`
- `scripts/check-rpm-package-signing.py`
- `scripts/check-linux-release-signing.py`
- `scripts/check-linux-repository-signing.py`
- `scripts/check-linux-gpg-public-key-export.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`, `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- The actual maintainer fingerprint still has to be chosen, configured as the
  repository secret, and published in a stable user-facing location before a
  real `v*` release.
- This does not publish to keyservers, rotate maintainer keys, host APT/RPM
  repositories, submit package-manager repository PRs, or publish npm packages.

Validation:

- `python -m py_compile scripts/linux_gpg_common.py scripts/sign-rpm-packages.py scripts/check-rpm-package-signing.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/sign-linux-repository-metadata.py scripts/check-linux-repository-signing.py scripts/export-linux-gpg-public-key.py scripts/check-linux-gpg-public-key-export.py scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- Windows signing checks skipped cleanly because `gpg`, `rpmbuild`,
  `rpmsign`/`rpm`, and `rpmkeys`/`rpm` are unavailable locally:
  `python scripts/check-linux-release-signing.py`,
  `python scripts/check-linux-repository-signing.py`,
  `python scripts/check-linux-gpg-public-key-export.py`, and
  `python scripts/check-rpm-package-signing.py`.
- WSL real-GPG regressions passed:
  `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'`,
  `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-repository-signing.py'`, and
  `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-gpg-public-key-export.py'`.
- WSL `python3 scripts/check-rpm-package-signing.py` skipped cleanly because
  native RPM signing tools are unavailable; WSL
  `python3 scripts/check-package-manager-manifests.py` passed.
- Workflow YAML parsed with Python/PyYAML.
- `python scripts/verify-release-versions.py`,
  `python scripts/check-release-artifact-verifier.py`,
  `python scripts/check-release-artifact-smoke-preflight.py`,
  `python scripts/verify-npm-package-contents.py`,
  `python scripts/check-npm-publish-preflight.py`,
  `python scripts/check-npm-publish-preflight-regression.py`, and
  `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` and
  `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` reported no
  actionable bugs in staged, unstaged, or untracked changes.
- PR #219 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26361581918>.
- Branch `Release Artifacts` passed on `linux-gpg-fingerprint-policy`:
  <https://github.com/imthegoodboy/conU/actions/runs/26361585211>.

Next:

- Continue with hosted APT/RPM repository publication, package-manager
  repository submission, npm package publication, auto-update policy,
  maintainer fingerprint publication once the real key is chosen, managed
  public relay hosting, distributed hosted dashboards/adaptive abuse automation,
  distributed multi-instance session migration, managed hosted identity/key
  administration, remote/distributed tenant workflows, remote/cross-region
  mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - RPM Package Payload Signing

Status: completed

Goal:

Sign generated conU RPM package payload assets during tagged GitHub Release
publication, refresh their strict `.rpm.sha256` sidecars, and generate RPM
repository metadata from the signed RPM packages.

Completed work:

- Issue #216 was closed by PR #217 on branch
  `rpm-package-payload-signing`; PR #217 merged to `main` at merge commit
  `d6976db94148a2583bf1fd978b0dba68b45c9b77`, and the branch is preserved.
- Added `scripts/sign-rpm-packages.py` to import the existing Linux GPG signing
  private key into a temporary `GNUPGHOME`, sign only generated conU RPM assets,
  verify native RPM signatures with a temporary RPM database containing the
  exported public key, and refresh `.rpm.sha256` sidecars after signing.
- Added `scripts/check-rpm-package-signing.py` to build fixture RPM packages
  when native RPM tooling is available, sign them with an ephemeral GPG key,
  verify native RPM signatures, prove `.rpm.sha256` sidecars are refreshed, and
  prove RPM repository metadata is generated from signed package digests. It
  skips cleanly when `rpmbuild`/`rpmsign`/`rpmkeys` are unavailable locally.
- Reordered tagged GitHub Release publication so RPM packages are built first,
  signed second, and RPM repository metadata is generated from the signed
  packages before repository metadata signing and detached Linux asset signing.
- Wired CI, Release Artifacts package checks, local production-readiness checks,
  release docs, package-manager docs, repo memory, guardrails, and the
  privacy/security checklist.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/sign-rpm-packages.py`
- `scripts/check-rpm-package-signing.py`
- `scripts/generate-package-manager-manifests.py`
- `scripts/check-package-manager-manifests.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`, `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- Local Windows and WSL validation skip native RPM package signing because
  `rpmbuild`, `rpmsign`, and `rpmkeys` are not installed in those environments;
  GitHub Actions package jobs install RPM tooling and must exercise that path.
- This does not host APT/RPM repositories, submit package-manager repository
  PRs, publish npm packages, add auto-update policy, or define maintainer key
  fingerprint trust policy outside release assets.

Validation:

- `python -m py_compile scripts/sign-rpm-packages.py scripts/check-rpm-package-signing.py scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/sign-linux-repository-metadata.py scripts/check-linux-repository-signing.py scripts/export-linux-gpg-public-key.py scripts/check-linux-gpg-public-key-export.py scripts/verify-release-versions.py scripts/verify-release-artifacts.py scripts/verify-npm-package-contents.py scripts/check-release-artifact-verifier.py scripts/check-release-artifact-smoke-preflight.py scripts/check-npm-launcher-local-smoke-preflight.py scripts/check-npm-publish-preflight.py scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed.
- `python scripts/check-rpm-package-signing.py` skipped cleanly because native
  Windows lacks `gpg`, `rpmbuild`, `rpmsign` or `rpm`, and `rpmkeys` or `rpm`.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-rpm-package-signing.py'` skipped cleanly because WSL lacks `rpmbuild`, `rpmsign` or `rpm`, and `rpmkeys` or `rpm`.
- Native Windows GPG checks skipped cleanly because `gpg` is unavailable:
  `python scripts/check-linux-release-signing.py`,
  `python scripts/check-linux-repository-signing.py`, and
  `python scripts/check-linux-gpg-public-key-export.py`.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'` passed.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-repository-signing.py'` passed.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-gpg-public-key-export.py'` passed.
- `python scripts/verify-release-versions.py`, `python scripts/check-release-artifact-verifier.py`, `python scripts/check-release-artifact-smoke-preflight.py`, `python scripts/verify-npm-package-contents.py`, `python scripts/check-npm-publish-preflight.py`, `python scripts/check-npm-publish-preflight-regression.py`, and `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` and `npm run check --prefix packaging/npm/conu-cli` passed.
- Workflow YAML parsed with Python/PyYAML.
- `git diff --check` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- PR #217 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26360412181>.
- Branch `Release Artifacts` passed on `rpm-package-payload-signing`:
  <https://github.com/imthegoodboy/conU/actions/runs/26360478097>.

Next:

- Continue with hosted APT/RPM repository publication, package-manager
  repository submission, npm package publication, auto-update policy,
  maintainer key fingerprint trust policy, managed public relay hosting,
  distributed hosted dashboards/adaptive abuse automation, distributed
  multi-instance session migration, managed hosted identity/key administration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Linux GPG Public Key Release Asset

Status: completed

Goal:

Publish the Linux release GPG public key as a GitHub Release asset so users can
verify detached Linux `.asc` signatures plus native APT/RPM repository metadata
signatures from release assets without exposing private-key material.

Completed work:

- Issue #214 was closed by PR #215 on branch
  `linux-gpg-public-key-release-asset`; PR #215 merged to `main` at merge
  commit `7f81b682044c8eb5bbdfbe952ef933ecd0295c93`, and the branch is
  preserved.
- Added `scripts/export-linux-gpg-public-key.py` to import the existing Linux GPG
  signing private key into a temporary `GNUPGHOME`, export only
  `conu-linux-gpg-key.asc`, and write a strict `.sha256` sidecar.
- Added `scripts/check-linux-gpg-public-key-export.py` to use an ephemeral GPG
  key, verify the exported asset is armored public-key material, prove it can
  verify a detached signature from a separate keyring, prove the sidecar is
  strict, and prove missing signing secrets fail closed.
- Wired CI, Release Artifacts package checks, tagged GitHub Release publication,
  local production-readiness checks, release docs, repo memory, guardrails, and
  the privacy/security checklist.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/export-linux-gpg-public-key.py`
- `scripts/check-linux-gpg-public-key-export.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`, `docs/`, `packaging/`, `.agents/`, and `plan.md`

Known gaps:

- This does not publish to keyservers, configure hosted package repositories,
  submit package-manager repository PRs, sign RPM package payloads, publish npm
  packages, or define key-fingerprint trust policy outside the release assets.
- The public-key asset helps users verify signatures, but users still need a
  trusted way to decide whether that public key belongs to the maintainer.

Validation:

- `python -m py_compile scripts/export-linux-gpg-public-key.py scripts/check-linux-gpg-public-key-export.py scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/sign-linux-repository-metadata.py scripts/check-linux-repository-signing.py scripts/verify-release-versions.py scripts/verify-release-artifacts.py scripts/verify-npm-package-contents.py scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py scripts/check-release-artifact-verifier.py scripts/check-release-artifact-smoke-preflight.py scripts/check-npm-launcher-local-smoke-preflight.py scripts/check-npm-publish-preflight.py scripts/check-npm-publish-preflight-regression.py` passed.
- Native Windows GPG checks skipped cleanly because `gpg` is unavailable:
  `python scripts/check-linux-gpg-public-key-export.py`,
  `python scripts/check-linux-repository-signing.py`, and
  `python scripts/check-linux-release-signing.py`.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-gpg-public-key-export.py'` passed.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-repository-signing.py'` passed.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'` passed.
- `python scripts/check-package-manager-manifests.py` and the WSL package-manager regression passed.
- `python scripts/verify-release-versions.py`, `python scripts/check-release-artifact-verifier.py`, `python scripts/check-release-artifact-smoke-preflight.py`, `python scripts/verify-npm-package-contents.py`, `python scripts/check-npm-publish-preflight.py`, `python scripts/check-npm-publish-preflight-regression.py`, and `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` and `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- Workflow YAML parsed with Python/PyYAML.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` reported no blocking correctness, security, or maintainability issues.
- PR #215 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26358405755>.
- Branch `Release Artifacts` passed on `linux-gpg-public-key-release-asset`:
  <https://github.com/imthegoodboy/conU/actions/runs/26358407693>.

Next:

- Continue with package-manager repository submission, hosted APT/RPM
  repository publication, RPM package payload signing, managed public relay
  hosting, distributed hosted dashboards/adaptive abuse automation, distributed
  multi-instance session migration, managed hosted identity/key administration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Signed Linux Repository Metadata

Status: completed

Goal:

Add native APT and RPM repository metadata signatures to the generated metadata
ZIPs during tagged GitHub Release publication, while keeping repository
hosting, package-manager submission, and RPM package payload signing as
explicit future work.

Completed work:

- Issue #212 was closed by PR #213 on branch
  `signed-linux-repository-metadata`; PR #213 merged to `main` at merge commit
  `ac867bcb3d34ad78acb6d660c3443424b2eb22d7`, and the branch is preserved.
- Added `scripts/sign-linux-repository-metadata.py` to import the maintainer GPG
  private key into a temporary `GNUPGHOME`, verify the existing metadata ZIP
  `.sha256` sidecars, add APT `InRelease` and `Release.gpg` signatures over
  `Release`, add RPM `repodata/repomd.xml.asc` over `repodata/repomd.xml`,
  verify each signature, and refresh the metadata ZIP `.sha256` sidecars.
- Added `scripts/check-linux-repository-signing.py` with an ephemeral GPG-key
  regression that verifies native repository signatures, proves metadata ZIP
  sidecars are updated, proves unrelated release assets are not mutated, and
  proves missing signing secrets fail closed.
- Wired CI package checks, Release Artifacts package checks, tagged GitHub
  Release publication, local production-readiness checks, release docs, repo
  memory, guardrails, and the privacy/security checklist.

Known gaps:

- This does not host an APT/YUM/DNF repository, submit package-manager
  repository PRs, sign RPM package payloads, configure repository publication
  credentials, publish npm packages, or add auto-update policy.
- The generated RPM packages remain unsigned payload assets until a dedicated
  RPM package-signing slice is implemented.

Validation:

- `python -m py_compile scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/sign-linux-repository-metadata.py scripts/check-linux-repository-signing.py scripts/verify-release-versions.py scripts/verify-release-artifacts.py scripts/verify-npm-package-contents.py scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py scripts/check-release-artifact-verifier.py scripts/check-release-artifact-smoke-preflight.py scripts/check-npm-launcher-local-smoke-preflight.py scripts/check-npm-publish-preflight.py scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-linux-repository-signing.py` skipped cleanly on native
  Windows because `gpg` is unavailable.
- `python scripts/check-linux-release-signing.py` skipped cleanly on native
  Windows because `gpg` is unavailable.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-repository-signing.py'` passed with real GPG signature generation and verification.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'` passed.
- `python scripts/check-package-manager-manifests.py` passed on Windows.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed.
- `python scripts/verify-release-versions.py` passed.
- `python scripts/check-release-artifact-verifier.py` passed.
- `python scripts/check-release-artifact-smoke-preflight.py` passed.
- `python scripts/verify-npm-package-contents.py` passed.
- `python scripts/check-npm-publish-preflight.py` passed.
- `python scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- Workflow YAML parsed with Python/PyYAML.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out
  locally after five minutes without reported findings; a targeted manual diff
  review was done instead.
- PR #213 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26357412336>.
- Branch `Release Artifacts` passed on `signed-linux-repository-metadata`:
  <https://github.com/imthegoodboy/conU/actions/runs/26357416088>.

Next:

- Continue with package-manager repository submission, hosted repository
  publication, RPM package payload signing, managed public relay hosting,
  distributed hosted dashboards/adaptive abuse automation, distributed
  multi-instance session migration, managed hosted identity/key administration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Linux Detached Release Signatures

Status: completed

Goal:

Generate armored detached GPG signatures for Linux release archives, generated
Debian/RPM packages, and generated APT/RPM repository metadata during tagged
GitHub Release publication.

Completed work:

- Issue #210 was closed by PR #211 on branch `linux-detached-signatures`; PR
  #211 merged to `main` at merge commit
  `a3795510370876f5ef0a27b873f70790f23d3923`, and the branch is preserved.
- Added `scripts/sign-linux-release-assets.py` to sign only Linux release
  archives, generated Debian/RPM package assets, and generated APT/RPM
  repository metadata ZIPs from maintainer-provided GPG secrets, then verify
  each signature before upload.
- Added `scripts/check-linux-release-signing.py` to generate an ephemeral GPG
  key, exercise detached-signature creation and verification, prove non-Linux
  and checksum/manifest assets are not signed, and prove missing signing secrets
  fail closed.
- Wired CI package checks, Release Artifacts package checks, tagged release
  secret preflight, GitHub Release asset signing, local production-readiness
  checks, release docs, repo memory, guardrails, and the privacy/security
  checklist.

Known gaps:

- This does not add native APT `InRelease`/`Release.gpg` publication, native RPM
  package signing, RPM repository signing, hosted package repositories,
  package-manager submission, or auto-update policy.
- This does not replace GitHub artifact attestations or strict `.sha256`
  sidecars; it adds detached signatures beside the existing release assets.

Validation:

- `python -m py_compile scripts/sign-linux-release-assets.py scripts/check-linux-release-signing.py scripts/verify-release-versions.py scripts/verify-release-artifacts.py scripts/verify-npm-package-contents.py scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py scripts/check-release-artifact-verifier.py scripts/check-release-artifact-smoke-preflight.py scripts/check-npm-launcher-local-smoke-preflight.py scripts/check-npm-publish-preflight.py scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-linux-release-signing.py` skipped cleanly on native
  Windows because `gpg` is unavailable.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-linux-release-signing.py'` passed with real GPG signature generation and verification.
- `python scripts/verify-release-versions.py` passed.
- `python scripts/check-release-artifact-verifier.py` passed.
- `python scripts/check-release-artifact-smoke-preflight.py` passed.
- `python scripts/check-package-manager-manifests.py` passed on Windows.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed.
- `python scripts/verify-npm-package-contents.py` passed.
- `python scripts/check-npm-publish-preflight.py` passed.
- `python scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- Workflow YAML parsed with Python/PyYAML.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out
  locally after five minutes without reported findings; a targeted manual diff
  review was done instead.
- PR #211 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26355691204>.
- Branch `Release Artifacts` passed on `linux-detached-signatures`:
  <https://github.com/imthegoodboy/conU/actions/runs/26355693381>.

Next:

- Continue with signed APT/RPM repository publication, package-manager
  repository submission, managed public relay hosting, distributed hosted
  dashboards/adaptive abuse automation, distributed multi-instance session
  migration, managed hosted identity/key administration, remote/distributed
  tenant workflows, remote/cross-region mailbox retention orchestration, or
  ICE/STUN/TURN managed traversal.

## Post Phase 15 - RPM Repository Metadata Bundle

Status: completed

Goal:

Generate unsigned RPM/YUM/DNF repository metadata from the verified generated
conU RPM assets during tagged release publication.

Completed work:

- Issue #208 was closed by PR #209 on branch `rpm-repository-metadata`; PR #209
  merged to `main` at merge commit `9e2a3f475250363997d6006c278c3f4ff2f7b85d`,
  and the branch is preserved.
- Added an explicit `--build-rpm-repository-metadata` generator mode that uses
  standard `createrepo_c` repository tooling for generated `.rpm` release
  assets.
- The bundle contains `README.txt` and `repodata/*` for generated `x86_64` and
  `aarch64` RPM release assets, plus a strict `.sha256` sidecar. It does not
  embed `.rpm` package payloads.
- Wired CI/release package jobs to install `createrepo-c` and wired tagged
  GitHub Release publication to generate the RPM metadata bundle alongside the
  APT metadata bundle and unsigned RPM assets.
- Extended package-manager regression coverage to verify RPM repository
  metadata hashes, package references, payload safety, deterministic metadata
  output, and absence of embedded RPM payloads where native RPM tooling is
  installed.
- Updated package-manager, release, distribution, production-readiness, repo
  memory, guardrail, and security checklist docs with the unsigned RPM metadata
  scope.

Known gaps:

- This does not sign RPM packages or RPM repository metadata.
- This does not host a YUM/DNF repository, submit package-manager repository
  PRs, configure package-manager credentials, add native APT/RPM repository
  signing, or implement auto-update policy.

Validation:

- `python -m py_compile scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py` passed.
- `python scripts/check-package-manager-manifests.py` passed on Windows.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed.
- `python scripts/verify-release-versions.py` passed.
- `python scripts/check-release-artifact-verifier.py` passed.
- `python scripts/check-release-artifact-smoke-preflight.py` passed.
- `python scripts/verify-npm-package-contents.py` passed.
- `python scripts/check-npm-publish-preflight.py` passed.
- `python scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out
  locally after four minutes without findings; a targeted manual review pass was
  done instead.
- PR #209 CI passed: <https://github.com/imthegoodboy/conU/actions/runs/26353877083>.
- Branch `Release Artifacts` passed on `rpm-repository-metadata`:
  <https://github.com/imthegoodboy/conU/actions/runs/26353884362>.

Next:

- Continue with signed APT/RPM repository publication, package-manager
  repository submission, managed public relay
  hosting, distributed hosted dashboards/adaptive abuse automation, distributed
  multi-instance session migration, managed hosted identity/key administration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - APT Repository Metadata Bundle

Status: completed

Goal:

Generate deterministic unsigned APT repository metadata from the verified conU
Debian package assets during tagged release publication.

Completed work:

- Issue #206 was closed by PR #207 on branch `apt-repository-metadata`; PR #207
  merged to `main` at merge commit `f2f7c993e658b31d4a77c3c45059a12fb2f7c986`,
  and the branch is preserved.
- Added an explicit `--build-apt-repository-metadata` package-generator mode for
  an unsigned `conu-<debian-version>-apt-repository-metadata.zip` bundle.
- The bundle contains deterministic `Packages`, `Packages.gz`, `Release`, and
  README files for the generated `amd64` and `arm64` `.deb` release assets, plus
  a strict `.sha256` sidecar.
- Wired tagged GitHub Release publication to generate the APT metadata bundle
  alongside generated package-manager files and unsigned RPM assets.
- Extended package-manager regression coverage to open the metadata ZIP, verify
  `Packages.gz`, compare APT package hashes and sizes against the generated
  `.deb` bytes, verify `Release` hashes, and prove deterministic output.
- Updated package-manager, release, distribution, production-readiness, repo
  memory, guardrail, and security checklist docs with the unsigned APT metadata
  scope.

Known gaps:

- This does not sign APT metadata with `InRelease` or `Release.gpg`.
- This does not host an APT repository, submit package-manager repository PRs,
  configure package-manager credentials, sign RPM packages, add detached Linux
  package signatures, or implement auto-update policy.

Validation:

- `python -m py_compile scripts/generate-package-manager-manifests.py scripts/check-package-manager-manifests.py` passed.
- `python scripts/check-package-manager-manifests.py` passed.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed, including native Debian package checks under WSL Ubuntu.
- `python scripts/verify-release-versions.py` passed.
- `python scripts/check-release-artifact-verifier.py` passed.
- `python scripts/check-release-artifact-smoke-preflight.py` passed.
- `python scripts/verify-npm-package-contents.py` passed.
- `python scripts/check-npm-publish-preflight.py` passed.
- `python scripts/check-npm-publish-preflight-regression.py` passed.
- `python scripts/check-npm-launcher-local-smoke-preflight.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` reported no actionable correctness, security, or privacy findings.
- PR #207 CI passed: <https://github.com/imthegoodboy/conU/actions/runs/26352850271>.
- Branch `Release Artifacts` passed on `apt-repository-metadata`: <https://github.com/imthegoodboy/conU/actions/runs/26352852602>.

Next:

- Continue with signed APT/RPM repository publication, detached Linux package
  signatures, package-manager repository submission, managed public relay
  hosting, distributed hosted dashboards/adaptive abuse automation, distributed
  multi-instance session migration, managed hosted identity/key administration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Hosted Fleet Tenant Account Lifecycle

Status: completed

Goal:

Add guarded local fleet tenant account upsert/revoke commands for controlled operators managing several local tenant registries from one manifest.

Completed work:

- Issue #153 was closed by PR #154 on branch `fleet-tenant-account-lifecycle`; PR #154 merged to `main` at merge commit `d06425bb2458d4f39392155cb520ff34e9e77289`.
- Added `conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]` and `conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]`.
- Reused the guarded hosted fleet manifest for configured local `tenants_file` sources only.
- Preflights every configured tenant registry before confirmed mutation, allows confirmed upsert to create missing tenant files, requires the account to exist before revoke, never contacts remote relays, and reports only account id, tenant/node counts, paths, mode/status, and display guards.
- Updated README, architecture, hosted relay, production/readiness, distribution/hosting, SDK/MCP, release checklist, security docs, repo memory, guardrails, security checklist, and plan docs.
- Issue #155 was closed by PR #156 on branch `relay-counter-window-ci-fix`; PR #156 merged to `main` at merge commit `061bf5192d9dc218c335f70dab52e1155ee1d010` after stabilizing relay quota/accounting/abuse tests that could cross a wall-clock counter-window boundary on Windows CI.
- Local and remote branches were intentionally preserved: `fleet-tenant-account-lifecycle` and `relay-counter-window-ci-fix`.

Files changed:

- `crates/conu-relay/src/main.rs`
- `crates/conu-relay/src/lib.rs`
- `README.md`
- `architecture.md`
- `docs/hosted-relay-account-auth.md`
- `docs/production-readiness.md`
- `docs/distribution-and-hosting.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- `codex review --uncommitted` reported no actionable correctness, security, or privacy issues.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_tenant_account_lifecycle_parser_report_and_renderers_are_metadata_only -- --nocapture` is blocked locally because `dlltool.exe` is not installed while compiling `getrandom`/`windows-sys`.
- PR #154 CI passed on Packages, Rust macOS, Rust Ubuntu, and Rust Windows: <https://github.com/imthegoodboy/conU/actions/runs/26324659510>.
- The first PR #154 merge run exposed a pre-existing relay counter-window test flake on Windows when the test crossed a minute boundary: <https://github.com/imthegoodboy/conU/actions/runs/26324723070>.
- PR #156 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26325010004>.
- Main CI passed after PR #156 merged: <https://github.com/imthegoodboy/conU/actions/runs/26325079473>.
- `Release Artifacts` smoke passed on `main`, including package checks, platform builds, artifact verification, and attestations in unsigned smoke mode: <https://github.com/imthegoodboy/conU/actions/runs/26325123480>.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_abuse_records_denials_without_secret_material --lib -- --nocapture` is blocked locally because `dlltool.exe` is not installed while compiling `getrandom`/`windows-sys`; GitHub Windows CI covered this path.

Known gaps:

- This is guarded local tenant-registry orchestration only. It is not remote relay mutation, distributed tenant lifecycle automation, distributed locking, hosted billing, adaptive abuse automation, or managed identity/key administration.

Next:

- Continue the remaining hosted/distributed product gaps: distributed hosted accounting dashboards, adaptive abuse automation, distributed multi-instance session migration, ICE/STUN/TURN managed direct NAT traversal, managed hosted identity/key administration, remote/distributed tenant lifecycle workflow automation, tenant-wide hosted dashboard workflow services, and remote relay/cross-region mailbox retention orchestration.

## Post Phase 15 - Production Readiness Verification Gate

Status: completed

Goal:

Turn the release-candidate validation baseline into one executable production-readiness gate so maintainers and future agents can verify formatting, Rust/package checks, local smoke flows, relay delivery, and hosted-readiness preflights from a single command.

Completed work:

- Issue #158 tracks the production readiness verification gate, and PR #159 carries the implementation.
- Added `scripts/verify-production-readiness.ps1` with a full release-candidate mode and a CI-friendly `-SmokeOnly` mode.
- The full gate runs formatting, Rust check/clippy/test/build, Python compile, release version consistency, TypeScript SDK check, npm launcher check, local smoke, identity archive retirement smoke, relay daemon smoke, hosted-readiness fixture validation, and `git diff --check`.
- The hosted-readiness fixture builds temporary credential, tenant, scoped admin-token, mailbox retention, accounting, abuse, and threshold stores, runs `conu-relay --hosted-readiness --json --fail-on-warning`, requires `status=ready` with zero warnings, and checks that fixture token material is not displayed.
- CI now runs `scripts/verify-production-readiness.ps1 -SmokeOnly` on the Windows Rust job so the production smoke/readiness path stays covered without duplicating the full Rust matrix on every OS.
- Updated README, production readiness docs, and release checklist to make the executable gate the release-candidate entry point.

Files changed:

- `.github/workflows/ci.yml`
- `README.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `scripts/verify-production-readiness.ps1`
- `plan.md`

Validation:

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipPackages -SkipSmokes` passed.
- PowerShell parser validation for `scripts\verify-production-readiness.ps1` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `git diff --check` passed.
- Local linked runtime tests and full `-SmokeOnly` execution are still blocked on this machine by missing `dlltool.exe`/MSVC linker support for linked test binaries; PR Windows CI is expected to cover the new smoke gate with a current build.

Known gaps:

- This gate makes the existing release-candidate baseline executable; it does not itself implement distributed hosted dashboards, adaptive abuse automation, distributed multi-instance session migration, ICE/STUN/TURN managed direct NAT traversal, managed hosted identity/key administration, remote/distributed tenant lifecycle workflow automation, tenant-wide hosted dashboard workflow services, or remote relay/cross-region mailbox retention orchestration.

Next:

- Continue closing the hosted/distributed product gaps, using `scripts/verify-production-readiness.ps1` as the release-candidate gate for future production-affecting changes.

## Post Phase 15 - Release Workflow Readiness Gate

Status: completed

Goal:

Require release artifact workflow runs to pass the same Windows production-readiness smoke gate before platform artifact build jobs start.

Completed work:

- Issue #160 tracks release workflow enforcement for the production-readiness smoke path, and PR #161 carries the implementation.
- Added a `Production Readiness Smoke` job to `.github/workflows/release.yml` that runs `scripts/verify-production-readiness.ps1 -SmokeOnly` on `windows-2025-vs2026` after release preflight.
- Made release artifact build jobs depend on both package checks and the production-readiness smoke job.
- Updated the release checklist to state that the release artifact workflow runs the smoke/readiness gate before artifact builds.

Validation:

- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('release workflow yaml parse ok')"` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipPackages -SkipSmokes` passed.
- `git diff --check` passed.
- PR #161 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26326169760>.
- Branch `Release Artifacts` workflow dispatch passed on `release-workflow-readiness-gate`, including the new `Production Readiness Smoke` job before platform artifact builds: <https://github.com/imthegoodboy/conU/actions/runs/26326231693>.

Known gaps:

- This workflow gate covers release artifact readiness enforcement; it does not add new hosted/distributed runtime features.

Next:

- PR #161 has been merged. Continue hosted/distributed production-readiness gaps.

## Post Phase 15 - Release Artifact Install Smoke

Status: completed

Goal:

Prove each generated release archive is not only structurally valid, but also executable as an unpacked install on the platform that built it.

Completed work:

- Issue #162 tracks packaged release archive smoke testing, and PR #163 carries the implementation.
- Added `scripts/smoke-release-artifacts.py` to extract current-platform release archives into a temporary directory, run packaged `conu init`, `conu security audit --json`, and `conu doctor --json`, and require `ready_for_local_use` plus false content-display guards.
- Wired the release artifact workflow to run the smoke test after structural artifact verification and before provenance attestation/upload.
- Updated packaging and release checklist docs with the new archive smoke command.

Files changed:

- `.github/workflows/release.yml`
- `docs/release-checklist.md`
- `packaging/README.md`
- `scripts/smoke-release-artifacts.py`
- `plan.md`

Validation:

- `python -m py_compile scripts\smoke-release-artifacts.py scripts\verify-release-artifacts.py scripts\verify-release-versions.py` passed.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('release workflow yaml parse ok')"` passed.
- `git diff --check` passed.
- Temporary Windows-style archive smoke using local debug binaries passed with `packaged conu doctor is ready_for_local_use`.
- PR #163 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26326838911>.
- Branch `Release Artifacts` workflow dispatch passed on `release-artifact-install-smoke`, including `Smoke release artifact install` on windows-x64, linux-x64, linux-arm64, macos-arm64, and macos-x64 artifact builds before attestation/upload: <https://github.com/imthegoodboy/conU/actions/runs/26326897480>.

Known gaps:

- This proves unpacked artifact executability for the current runner platform; it does not add OS package-manager installers, managed hosted account/key administration, distributed hosted services, or browser-native protocol support.

Next:

- PR #163 has been merged. Continue hosted/distributed production-readiness gaps.

## Post Phase 15 - npm Launcher Local Install Smoke

Status: completed

Goal:

Prove the public `@conu/cli` npm launcher path can install generated release binaries locally and invoke the packaged CLI from the installed package.

Completed work:

- Issue #164 tracks npm launcher local install smoke testing, and branch `npm-launcher-local-install-smoke` carries the implementation.
- Added `scripts/smoke-npm-launcher-local.py` to extract current-platform release archives, install `packaging/npm/conu-cli` into a temporary npm prefix with `CONU_NPM_BINARY_DIR` pointed at the archive `bin/` directory, verify vendor binaries and npm bin shims, run installed launcher wrappers, and require `conu doctor --json` to report `ready_for_local_use` with false content-display guards.
- Wired the release artifact workflow to run the npm launcher smoke after unpacked archive smoke and before provenance attestation/upload.
- Updated packaging, distribution, production-readiness, npm package, README, and release checklist docs with the new smoke command and release workflow gate.

Files changed:

- `.github/workflows/release.yml`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `scripts/smoke-npm-launcher-local.py`
- `plan.md`

Validation:

- `python -m py_compile scripts\smoke-npm-launcher-local.py scripts\smoke-release-artifacts.py scripts\verify-release-artifacts.py scripts\verify-release-versions.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('release workflow yaml parse ok')"` passed.
- `git diff --check` passed.
- Temporary Windows-style archive smoke using local debug binaries passed with `npm launcher install is ready_for_local_use`.
- PR #165 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26327779678>.
- Branch `Release Artifacts` workflow dispatch passed on `npm-launcher-local-install-smoke`, including `Smoke npm launcher local install` on windows-x64, linux-x64, linux-arm64, macos-arm64, and macos-x64 artifact builds before attestation/upload: <https://github.com/imthegoodboy/conU/actions/runs/26327894908>.

Known gaps:

- This proves the local npm launcher install path against generated archive binaries. It does not publish the npm package, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- After PR #165 lands and main CI plus main `Release Artifacts` are green, continue the hosted/distributed production-readiness gaps.

## Post Phase 15 - npm Launcher Download Install Smoke

Status: completed

Goal:

Prove the public `@conu/cli` default install path can download a generated release archive, verify its sibling `.sha256`, extract it, install native binaries into the package vendor directory, and invoke the packaged CLI from the installed package.

Completed work:

- Issue #166 tracks npm launcher download/checksum install smoke testing, and branch `npm-launcher-download-smoke` carries the implementation.
- Added `scripts/smoke-npm-launcher-download.py` to serve generated release artifacts from a temporary localhost HTTP server, install `packaging/npm/conu-cli` into a temporary npm prefix with `CONU_NPM_DIST_BASE` pointed at that server, require the default npm installer to report a download-backed native install, and reuse the installed launcher readiness checks from `scripts/smoke-npm-launcher-local.py`.
- Wired the release artifact workflow to run the download/checksum npm launcher smoke after local npm launcher smoke and before provenance attestation/upload.
- Updated packaging, distribution, production-readiness, npm package, README, and release checklist docs with the new smoke command and release workflow gate.

Files changed:

- `.github/workflows/release.yml`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `scripts/smoke-npm-launcher-download.py`
- `plan.md`

Validation:

- `python -m py_compile scripts\smoke-npm-launcher-download.py scripts\smoke-npm-launcher-local.py scripts\smoke-release-artifacts.py scripts\verify-release-artifacts.py scripts\verify-release-versions.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('release workflow yaml parse ok')"` passed.
- `git diff --check` passed.
- Temporary Windows-style archive download smoke using local debug binaries and a localhost artifact server passed with `npm launcher download install verified checksum`.
- PR #167 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26329302953>.
- Branch `Release Artifacts` workflow dispatch passed on `npm-launcher-download-smoke`, including `Smoke npm launcher download install` on windows-x64, linux-x64, linux-arm64, macos-arm64, and macos-x64 artifact builds before attestation/upload: <https://github.com/imthegoodboy/conU/actions/runs/26329384904>.

Known gaps:

- This proves the checksum-backed npm download installer path against generated archive binaries served locally. It does not publish the npm package, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- After PR #167 lands and main CI plus main `Release Artifacts` are green, continue the hosted/distributed production-readiness gaps.

## Post Phase 15 - npm Installer Safe Archive Preflight

Status: completed

Goal:

Harden the public `@conu/cli` npm installer so a checksum-verified but malformed release archive still fails before extraction if it contains unsafe member paths or unsupported link entries.

Completed work:

- Issue #168 tracks npm installer archive preflight hardening, and branch `npm-installer-safe-archive-preflight` carries the implementation.
- Added `packaging/npm/conu-cli/lib/archive-preflight.js` to inspect archive members before extraction, reject absolute paths, Windows drive paths, parent traversal, newline/control path separators, symlinks, hardlinks, and unsupported member types, and fall back to PowerShell ZIP inspection on Windows when needed.
- Wired `packaging/npm/conu-cli/scripts/install.js` to run the preflight immediately before `tar` or PowerShell extraction.
- Added `packaging/npm/conu-cli/scripts/check-archive-preflight.js` and extended `npm run check --prefix packaging/npm/conu-cli` so package checks cover safe and unsafe member fixtures.
- Updated npm/package, production-readiness, release-checklist, packaging, and implementation-guardrail docs with the archive-member preflight requirement.

Files changed:

- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `packaging/npm/conu-cli/lib/archive-preflight.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/check-archive-preflight.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `plan.md`

Validation:

- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm pack --dry-run` from `packaging/npm/conu-cli` passed and included the new preflight module/script without vendored binaries.
- `node --check packaging\npm\conu-cli\lib\archive-preflight.js`, `node --check packaging\npm\conu-cli\scripts\check-archive-preflight.js`, and `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `git diff --check` passed.
- Temporary Windows-style archive download smoke using local debug binaries and a localhost artifact server passed with `npm launcher download install verified checksum`.

Known gaps:

- This hardens npm installer extraction for verified release archives. It does not publish the npm package, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Open PR for issue #168, run PR CI and branch `Release Artifacts`, then merge without deleting branches if checks stay green.

## Post Phase 15 - npm Installer HTTPS Download Policy

Status: completed

Goal:

Harden the public `@conu/cli` npm installer so native release archive downloads require HTTPS, while preserving loopback HTTP for local and CI release artifact smoke servers.

Completed work:

- Issue #170 tracks npm installer download URL policy hardening, and branch `npm-installer-https-download-policy` carries the implementation.
- Added `packaging/npm/conu-cli/lib/download-policy.js` to reject non-HTTPS download URLs unless they target loopback hosts, reject embedded URL credentials, and fail closed on unsupported or invalid URL schemes.
- Wired `packaging/npm/conu-cli/scripts/install.js` to validate every archive/checksum request URL, including redirects, before selecting `http` or `https`.
- Kept download error URLs payload-safe by omitting query strings and fragments from rendered failure messages.
- Added `packaging/npm/conu-cli/scripts/check-download-policy.js` and extended `npm run check --prefix packaging/npm/conu-cli` so package checks cover HTTPS, loopback HTTP, remote HTTP, credential-bearing, and invalid URL cases.
- Updated npm/package, distribution, production-readiness, release-checklist, README, and implementation-guardrail docs with the HTTPS-or-loopback download requirement.

Files changed:

- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `packaging/npm/conu-cli/lib/download-policy.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/check-download-policy.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `plan.md`

Validation:

- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm pack --dry-run` from `packaging/npm/conu-cli` passed and included the new download policy module/script without vendored binaries.
- `node --check packaging\npm\conu-cli\lib\download-policy.js`, `node --check packaging\npm\conu-cli\scripts\check-download-policy.js`, and `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `git diff --check` passed.
- Temporary Windows-style archive download smoke using local debug binaries and a localhost artifact server passed with `npm launcher download install verified checksum`.
- Negative npm install smoke with remote plain-HTTP `CONU_NPM_DIST_BASE=http://example.com/conu-test?token=secret` failed closed with the expected HTTPS policy error before download and did not display query material.

Known gaps:

- This hardens npm installer transport for release archive downloads. It does not publish the npm package, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Run local validation, open PR for issue #170, run PR CI and branch `Release Artifacts`, then merge without deleting branches if checks stay green.

## Post Phase 15 - npm Installer Download Bounds

Status: completed

Goal:

Harden the public `@conu/cli` npm installer so native archive and checksum downloads cannot hang indefinitely or consume unbounded disk/memory before checksum verification and archive preflight.

Completed work:

- Issue #172 tracks npm installer download timeout and size hardening, and branch `npm-installer-download-bounds` carries the implementation.
- Added `packaging/npm/conu-cli/lib/download-limits.js` with default per-request timeout, native archive byte limit, checksum response byte limit, and positive-integer environment override parsing.
- Reworked `packaging/npm/conu-cli/scripts/install.js` to set a timeout on every archive/checksum request, enforce `Content-Length` and streaming byte counts, write archive bytes through counted file writes instead of an unbounded pipe, and delete partial archive files on failure.
- Preserved payload-safe download errors by continuing to render sanitized URLs without query strings or fragments for size and timeout failures.
- Added `packaging/npm/conu-cli/scripts/check-download-limits.js` and extended `npm run check --prefix packaging/npm/conu-cli` so package checks cover default/override parsing, invalid limit values, oversized archive responses, oversized checksum responses, request timeout failures, and query-string redaction.
- Updated npm/package, distribution, production-readiness, release-checklist, README, user-install, repo memory, guardrail, and security checklist docs with the bounded download requirement.

Files changed:

- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `packaging/npm/conu-cli/lib/download-limits.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/check-download-limits.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `plan.md`

Validation:

- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm pack --dry-run` from `packaging/npm/conu-cli` passed and included `lib/download-limits.js` plus `scripts/check-download-limits.js` without vendored binaries.
- `node --check packaging\npm\conu-cli\lib\download-limits.js`, `node --check packaging\npm\conu-cli\scripts\check-download-limits.js`, `node --check packaging\npm\conu-cli\scripts\install.js`, and `node --check packaging\npm\conu-cli\scripts\check-download-policy.js` passed.
- `git diff --check` passed.
- Temporary current-platform archive download smoke using the local Windows release archive passed with `npm launcher download install verified checksum`.
- Raw `python scripts\smoke-npm-launcher-download.py dist` against the existing local `dist/` was not used as the pass criterion because this workspace contains both `conu-0.1.0-host.zip` and `conu-0.1.0-windows-x64.zip`; the npm installer correctly downloaded the platform-named asset while the host archive expectation differed. The isolated current-platform dist smoke passed.

Known gaps:

- This hardens npm installer download resource bounds only. It does not publish the npm package, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- PR #173 has been merged. Continue the remaining hosted/distributed production-readiness gaps without deleting preserved branches.

## Post Phase 15 - npm Download Smoke Host Archive Handling

Status: completed

Goal:

Make the documented npm download smoke command reliable when a local `dist/` contains both a developer `conu-<version>-host` archive and the platform-named archive that the npm installer actually downloads.

Completed work:

- Issue #174 tracks npm download smoke host-archive handling, and branch `npm-download-smoke-host-archives` carries the implementation.
- Updated `scripts/smoke-npm-launcher-download.py` to derive the canonical npm asset name from the `@conu/cli` package version plus the current platform.
- The smoke now skips a current-platform `target = "host"` archive when the matching platform-named npm asset and checksum exist, while still failing clearly if a current-platform archive uses a name the npm installer cannot download.
- Updated packaging and release-checklist docs so maintainers know local host archive aliases are skipped by the npm download smoke.

Files changed:

- `docs/release-checklist.md`
- `packaging/README.md`
- `scripts/smoke-npm-launcher-download.py`
- `plan.md`

Validation:

- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/` containing both `conu-0.1.0-host.zip` and `conu-0.1.0-windows-x64.zip`; it skipped the host alias and verified the platform-named npm download install.
- `python -m py_compile scripts\smoke-npm-launcher-download.py scripts\smoke-npm-launcher-local.py` passed.
- `git diff --check` passed.

Known gaps:

- This fixes local release-smoke robustness only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- PR #175 has been merged. Continue the remaining hosted/distributed production-readiness gaps without deleting preserved branches.

## Post Phase 15 - npm Package Content Verification

Status: completed

Goal:

Fail CI, release package checks, and tagged npm publication before publish if the public `@conu/cli` or `@conu/sdk` npm dry-run tarballs lose required files or include unexpected local state, build output, vendored binaries, secrets, oversized entries, or bundled dependencies.

Completed work:

- Issue #176 was closed by PR #177 on branch `npm-pack-content-verifier`; PR #177 merged to `main` at merge commit `d220c2561f450efbc32a5e5452917ca5a031ff94`.
- Added `scripts/verify-npm-package-contents.py` to run `npm pack --dry-run --json` for both npm packages, require the reviewed exact file sets, compare package names/versions against `package.json`, reject forbidden state/build/payload/secret path names, enforce package/file byte bounds, and reject bundled dependencies.
- Wired the verifier into PR CI package checks, Release Artifacts package checks, tagged npm publication preflight, and the full local `scripts/verify-production-readiness.ps1` package gate.
- Updated release, distribution, production-readiness, repo memory, guardrail, and security-checklist docs with the deterministic npm package-content gate.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `scripts/verify-npm-package-contents.py`
- `scripts/verify-production-readiness.ps1`
- `plan.md`

Validation:

- `python -m py_compile scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `python -c "import yaml, pathlib; [yaml.safe_load(pathlib.Path(p).read_text()) for p in ['.github/workflows/ci.yml', '.github/workflows/release.yml']]; print('workflow yaml parse ok')"` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` reported no actionable correctness, security, or privacy issues.
- PR #177 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26336711349>.
- Branch `Release Artifacts` workflow_dispatch run passed on `npm-pack-content-verifier`, including package checks with npm package content verification, production readiness smoke, and platform builds for `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64`: <https://github.com/imthegoodboy/conU/actions/runs/26336725204>. The first attempt hit a transient macOS x64 `actions/checkout@v6` credential fetch failure; rerunning failed jobs passed on attempt 2.
- Refreshed PR #177 CI passed after the final plan update: <https://github.com/imthegoodboy/conU/actions/runs/26337345059>.
- Refreshed branch `Release Artifacts` workflow_dispatch run passed after the final plan update: <https://github.com/imthegoodboy/conU/actions/runs/26337347166>.
- Main CI passed after PR #177 merged: <https://github.com/imthegoodboy/conU/actions/runs/26337455770>.
- Main `Release Artifacts` workflow_dispatch run passed after PR #177 merged: <https://github.com/imthegoodboy/conU/actions/runs/26337463904>.

Known gaps:

- This verifies package dry-run contents only. It does not publish npm packages, configure signing/npm secrets, add OS package-manager installers, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- PR #177 has been merged. Continue the remaining hosted/distributed production-readiness gaps without deleting preserved branches.

## Post Phase 15 - Release Artifact Verifier Bounds

Status: completed

Goal:

Harden release artifact verification so archive checks stream file content, read only the manifest body, fail closed on loose or mismatched checksum files, and enforce explicit archive/member/manifest size plus member-count limits before upload, attestation, or npm publication.

Completed work:

- Issue #178 tracks release artifact verifier bounds, and PR #179 on branch `release-artifact-verifier-bounds` carries the implementation.
- Reworked `scripts/verify-release-artifacts.py` to stream archive hashing, require strict `<sha256>  <archive-name>` checksum files, bound checksum file size, archive size, member size, total uncompressed bytes, member count, and manifest size, reject duplicate normalized paths, and avoid reading non-manifest archive bodies into memory.
- Added `scripts/check-release-artifact-verifier.py` regression fixtures for valid ZIP/tar archives, pre-hash archive byte limits, checksum filename mismatches, loose checksum files, duplicate normalized paths, encrypted ZIP members, corrupt ZIP member data, forbidden state files, forbidden state directories, and data-bearing ZIP directory entries.
- Wired the regression check into PR CI package checks, Release Artifacts package checks, and the full local `scripts/verify-production-readiness.ps1` package gate.
- Updated release, distribution, production-readiness, packaging, repo memory, guardrail, and security-checklist docs with the bounded streaming verifier and strict checksum requirement.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `scripts/check-release-artifact-verifier.py`
- `scripts/verify-release-artifacts.py`
- `scripts/verify-production-readiness.ps1`
- `plan.md`

Validation:

- `python -m py_compile scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py scripts\verify-release-versions.py scripts\verify-npm-package-contents.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-release-artifacts.py dist` passed.
- `python -c "import yaml, pathlib; [yaml.safe_load(pathlib.Path(p).read_text()) for p in ['.github/workflows/ci.yml', '.github/workflows/release.yml']]; print('workflow yaml parse ok')"` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` reported no actionable correctness, security, or privacy issues.
- PR #179 CI passed on Packages, Rust Ubuntu, Rust Windows, and Rust macOS after rerunning a transient macOS checkout failure: <https://github.com/imthegoodboy/conU/actions/runs/26339080644>.
- Branch `Release Artifacts` passed on `release-artifact-verifier-bounds`, including package checks, production-readiness smoke, five platform builds, artifact verification, install/download smoke, and attestations/uploads in unsigned smoke mode: <https://github.com/imthegoodboy/conU/actions/runs/26339087342>.

Known gaps:

- This hardens release artifact verification only. It does not publish a release tag, publish npm packages, configure signing/npm secrets, add OS package-manager installers, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue the remaining hosted/distributed production-readiness gaps without deleting preserved branches.

## Post Phase 15 - npm Installer Strict Checksum Verification

Status: completed

Goal:

Align the public `@conu/cli` npm installer with release artifact checksum policy by requiring strict checksum files that name the downloaded archive and hashing archives in chunks before extraction.

Completed work:

- Issue #180 tracks npm installer strict checksum verification, and branch `npm-installer-strict-checksum` carries the implementation.
- Added `packaging/npm/conu-cli/lib/checksum.js` with strict SHA-256 checksum parsing, archive-name matching, and chunked file hashing.
- Reworked `packaging/npm/conu-cli/scripts/install.js` to reject loose or wrong-archive checksum files before extraction and avoid full archive reads during SHA-256 verification.
- Added `packaging/npm/conu-cli/scripts/check-checksum-verification.js` and extended `check-download-limits.js` so package checks cover strict checksum parsing, wrong archive names, checksum mismatch, and no `readFileSync` use during verification.
- Updated npm package content allowlists and release/distribution/production-readiness/packaging/security docs with the stricter npm install checksum behavior.

Files changed:

- `packaging/npm/conu-cli/lib/checksum.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/check-checksum-verification.js`
- `packaging/npm/conu-cli/scripts/check-download-limits.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `scripts/verify-npm-package-contents.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `plan.md`

Validation:

- `node --check packaging\npm\conu-cli\lib\checksum.js` passed.
- `node --check packaging\npm\conu-cli\scripts\check-checksum-verification.js` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `node --check packaging\npm\conu-cli\scripts\check-download-limits.js` passed.
- `node packaging\npm\conu-cli\scripts\check-checksum-verification.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python scripts\verify-npm-package-contents.py --package @conu/cli` passed.
- `python -m py_compile scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/`, skipping the host alias and verifying the platform-named npm download install checksum.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` reported no actionable correctness, security, or privacy issues.
- PR #181 CI passed on Packages, Rust Ubuntu, Rust Windows, Rust macOS, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26339928311>.
- Branch `Release Artifacts` passed on `npm-installer-strict-checksum`, including package checks, production-readiness smoke, five platform builds, artifact verification, install/download smoke, and attestations/uploads in unsigned smoke mode: <https://github.com/imthegoodboy/conU/actions/runs/26339931798>.

Known gaps:

- This hardens npm installer checksum verification only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue the remaining hosted/distributed production-readiness gaps without deleting preserved branches.

## Post Phase 15 - npm Installer Extracted Binary Selection

Status: completed

Goal:

Make the public `@conu/cli` npm installer fail closed after extraction by selecting native binaries only from the expected release layout instead of recursively accepting the first matching filename anywhere in the archive tree.

Completed work:

- Issue #182 was closed by PR #183 on branch `npm-installer-extract-root-guard`; PR #183 merged to `main` at merge commit `bc1a9599350ba91c705c93e7f774e55736cd2dac`.
- Added `packaging/npm/conu-cli/lib/extract-selection.js` to detect either the rootless Windows release layout or the expected `conu-<version>-<platform>/` release root, require `manifest.toml`, require each expected `bin/<binary>` file, and reject duplicate/misplaced binary names elsewhere in the extracted tree.
- Reworked `packaging/npm/conu-cli/scripts/install.js` so downloaded archives install binaries from exact release-root `bin/` paths after checksum verification and archive-member preflight.
- Added `packaging/npm/conu-cli/scripts/check-extract-selection.js` and wired it into `npm run check --prefix packaging/npm/conu-cli` with rooted, rootless, missing-manifest, ambiguous-root, misplaced-binary, and duplicate-binary fixtures.
- Updated npm package content allowlists and release/distribution/production-readiness/packaging/security docs with the stricter extracted binary selection policy.

Files changed:

- `packaging/npm/conu-cli/lib/extract-selection.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/check-extract-selection.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `scripts/verify-npm-package-contents.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `plan.md`

Validation:

- `node --check packaging\npm\conu-cli\lib\extract-selection.js` passed.
- `node --check packaging\npm\conu-cli\scripts\check-extract-selection.js` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `node packaging\npm\conu-cli\scripts\check-extract-selection.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python scripts\verify-npm-package-contents.py --package @conu/cli` passed.
- `python -m py_compile scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/`, skipping the host alias and verifying the platform-named npm download install checksum and extraction path.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` timed out locally after 304 seconds on the first run; the retry failed inside the nested review sandbox with repeated `windows sandbox: spawn setup refresh` errors, so manual scoped diff review plus GitHub CI/release gates are required before merge.
- `codex review --uncommitted` reported no actionable correctness, security, or privacy issues.
- `codex review --uncommitted` reported no actionable correctness, security, or privacy issues.
- `codex review --uncommitted` timed out twice locally after 124 seconds and 304 seconds; manual scoped diff review plus GitHub CI/release gates were used instead.
- PR #183 CI passed on Packages, Rust Ubuntu, Rust Windows, Rust macOS, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26341086181>.
- Branch `Release Artifacts` passed on `npm-installer-extract-root-guard`, including package checks, production-readiness smoke, five platform builds, artifact verification, install/download smoke, and attestations/uploads in unsigned smoke mode: <https://github.com/imthegoodboy/conU/actions/runs/26341149968>.
- Main CI passed after PR #183 merged: <https://github.com/imthegoodboy/conU/actions/runs/26341267324>.
- Main `Release Artifacts` passed after PR #183 merged: <https://github.com/imthegoodboy/conU/actions/runs/26341336236>.
- Local and remote branches were intentionally preserved: `npm-installer-extract-root-guard`.

Known gaps:

- This hardens npm installer extraction only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- PR #183 has been merged for issue #182 without deleting branches. Continue the remaining hosted/distributed production-readiness gaps.

## Post Phase 15 - npm Installer Extracted Tree Bounds

Status: completed

Goal:

Harden the public `@conu/cli` npm installer after archive extraction by bounding extracted-tree traversal and collecting binary-name matches in one scan before selecting release-root binaries.

Completed work:

- Issue #184 tracks bounded npm installer extracted-tree selection, and PR #185 on branch `npm-installer-extract-bounds` carries the implementation.
- Added default extracted-tree bounds to `packaging/npm/conu-cli/lib/extract-selection.js`: 10,000 entries and depth 64.
- Reworked binary matching to scan the extracted tree once for all expected binary filenames instead of recursively scanning once per binary.
- Preserved the existing fail-closed release-root policy: require either the rootless Windows layout or the expected `conu-<version>-<platform>/` release root, require `manifest.toml`, require exact `bin/<binary>` files, and reject duplicate or misplaced binary names elsewhere.
- Extended `packaging/npm/conu-cli/scripts/check-extract-selection.js` with regression fixtures for entry-count overflow, depth overflow, and invalid bound options.
- Updated README, user install, release/distribution/production-readiness/packaging/security docs, repo memory, guardrails, and this plan with the bounded extracted-tree behavior.

Files changed:

- `packaging/npm/conu-cli/lib/extract-selection.js`
- `packaging/npm/conu-cli/scripts/check-extract-selection.js`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `node --check packaging\npm\conu-cli\lib\extract-selection.js` passed.
- `node --check packaging\npm\conu-cli\scripts\check-extract-selection.js` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `node packaging\npm\conu-cli\scripts\check-extract-selection.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python scripts\verify-npm-package-contents.py --package @conu/cli` passed.
- `python -m py_compile scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/`, skipping the host alias and verifying the platform-named npm download install checksum and extraction path.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` exited 0 and reported no actionable correctness, security, or privacy issues.

Known gaps:

- This hardens npm installer extraction traversal and binary selection only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- After PR #185 and main verification gates pass without deleting branches, continue the remaining hosted/distributed production-readiness gaps.

## Post Phase 15 - npm Installer Archive Member Preflight

Status: completed

Goal:

Make the public `@conu/cli` npm installer fail closed during archive-member preflight before extraction when a downloaded archive has too many members, duplicate normalized paths, or local conU state paths.

Completed work:

- Issue #186 tracks npm installer archive-member preflight hardening, and PR #187 on branch `npm-installer-archive-preflight-bounds` carries the implementation.
- Added a 10,000 member limit to `packaging/npm/conu-cli/lib/archive-preflight.js`, aligned with the release artifact verifier's member-count boundary.
- Normalized archive member paths before extraction and rejected duplicate normalized paths such as `bin/conu` and `bin/./conu`.
- Rejected forbidden local state/build/package paths before extraction, including `.conu`, `.git`, `logs`, `messages`, `node_modules`, `routes`, `runtime`, `security`, `sessions`, `streams`, `target`, `vendor`, `node.toml`, `runtime.toml`, and `trust.toml`.
- Extended `packaging/npm/conu-cli/scripts/check-archive-preflight.js` with member-count, duplicate-path, and forbidden-state-path regression fixtures.
- Updated README, user install, release/distribution/production-readiness/packaging/security docs, repo memory, guardrails, and this plan with the stricter archive-member preflight behavior.

Files changed:

- `packaging/npm/conu-cli/lib/archive-preflight.js`
- `packaging/npm/conu-cli/scripts/check-archive-preflight.js`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `node --check packaging\npm\conu-cli\lib\archive-preflight.js` passed.
- `node --check packaging\npm\conu-cli\scripts\check-archive-preflight.js` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `node packaging\npm\conu-cli\scripts\check-archive-preflight.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python scripts\verify-npm-package-contents.py --package @conu/cli` passed.
- `python -m py_compile scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/`, skipping the host alias and verifying the platform-named npm download install checksum and extraction path.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` exited 0 and reported no actionable correctness, security, or privacy issues in the smoke preflight, regression check, workflow wiring, or docs.

Known gaps:

- This hardens npm installer archive preflight only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- After PR #187 and main verification gates pass without deleting branches, continue the remaining hosted/distributed production-readiness gaps.

## Post Phase 15 - npm Installer Local Binary Directory Preflight

Status: completed

Goal:

Make the public `@conu/cli` npm installer fail closed for `CONU_NPM_BINARY_DIR` overrides unless the override points at an existing directory containing regular files for every expected native binary.

Completed work:

- Issue #188 was closed by PR #189 on branch `npm-installer-local-binary-dir-guard`; PR #189 merged to `main` at merge commit `0ca33f50bdf82b2e6d44a576f67c6e3fa643f473`.
- Added `packaging/npm/conu-cli/lib/local-binary-dir.js` so local override installs resolve the source directory once, require it to be an existing directory, and preflight every expected binary as a regular file before copying.
- Reworked `packaging/npm/conu-cli/scripts/install.js` so the local override path preflights all source binaries before any package-local `vendor/` writes.
- Added `packaging/npm/conu-cli/scripts/check-local-binary-dir.js` with fixtures for valid layouts, missing source directories, file-as-directory source paths, missing binaries, and directory entries named as binaries.
- Wired the local binary directory fixture into `npm run check --prefix packaging/npm/conu-cli`.
- Updated npm package content allowlists and release/distribution/production-readiness/packaging/security docs with the stricter local override behavior.

Files changed:

- `packaging/npm/conu-cli/lib/local-binary-dir.js`
- `packaging/npm/conu-cli/scripts/check-local-binary-dir.js`
- `packaging/npm/conu-cli/scripts/install.js`
- `packaging/npm/conu-cli/package.json`
- `scripts/verify-npm-package-contents.py`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `node --check packaging\npm\conu-cli\lib\local-binary-dir.js` passed.
- `node --check packaging\npm\conu-cli\scripts\check-local-binary-dir.js` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js` passed.
- `node packaging\npm\conu-cli\scripts\check-local-binary-dir.js` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python scripts\verify-npm-package-contents.py --package @conu/cli` passed.
- `python -m py_compile scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/`, skipping the host alias and verifying the platform-named npm download install checksum and extraction path.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` exited 0 and reported no actionable correctness, security, or privacy issues.
- PR #189 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26343166490>.
- Branch `Release Artifacts` workflow dispatch passed on `npm-installer-local-binary-dir-guard`, including package checks, production readiness smoke, platform builds, artifact verification, local npm launcher install smoke, download npm launcher install smoke, and artifact attestations: <https://github.com/imthegoodboy/conU/actions/runs/26343169446>.
- Main CI passed after PR #189 merged: <https://github.com/imthegoodboy/conU/actions/runs/26343273867>.
- Main `Release Artifacts` workflow dispatch passed after PR #189 merged, including package checks, production readiness smoke, platform builds, artifact verification, local npm launcher install smoke, download npm launcher install smoke, and artifact attestations: <https://github.com/imthegoodboy/conU/actions/runs/26343283496>.

Known gaps:

- This hardens npm installer local override preflight only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue the remaining hosted/distributed production-readiness gaps while preserving the `npm-smoke-local-binary-preflight` and `npm-installer-local-binary-dir-guard` branches.

## Post Phase 15 - Package-Manager Manifest Generation

Status: completed

Goal:

Generate package-manager manifests from verified release assets and strict checksum files so Homebrew/Scoop publication does not depend on hand-edited hashes or local paths.

Completed work:

- Issue #196 tracked package-manager manifest generation hardening, and PR #197 on branch `package-manager-manifest-preflight` merged to `main` at `4f4e25dd46bbbce3d00d0227ccdb8edeb80c6f9d`; Issue #196 is closed, and the branch is preserved.
- Added `scripts/generate-package-manager-manifests.py` to read platform release archives plus strict sibling `.sha256` files and generate package-native `conu.rb` plus `conu.json` manifests with public GitHub Release URLs, static SHA-256 hashes, package metadata, and binary mappings.
- Added Windows archive layout detection so generated Scoop manifests handle both current rootless release ZIPs and rooted `conu-<version>-windows-x64/` ZIPs without guessing.
- Added `scripts/check-package-manager-manifests.py` with regression coverage for successful generation, package-native Homebrew/Scoop filenames, Homebrew-compatible license and `conu-mcp` stdin-closed smoke testing, semver prerelease plus build metadata, rooted/rootless Windows layouts, missing checksum files, wrong checksum archive names, checksum mismatches, and forbidden local/secret output literals.
- Wired the regression into CI package checks, Release Artifacts package checks, and `scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes`.
- Wired tagged GitHub Release publication to generate package-manager manifests after downloaded release assets are verified and before `gh release upload`.
- Added `packaging/package-managers/README.md` and updated release/distribution/production-readiness/packaging docs, repo memory, guardrails, and security checklist with the generated-manifest policy.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/generate-package-manager-manifests.py`
- `scripts/check-package-manager-manifests.py`
- `scripts/verify-production-readiness.ps1`
- `packaging/package-managers/README.md`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\generate-package-manager-manifests.py scripts\check-package-manager-manifests.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\verify-npm-package-contents.py` passed.
- `python scripts\check-package-manager-manifests.py` passed, including the corrupt
  Linux tarball fail-closed regression.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed, exercising the optional `dpkg-deb` native package metadata/content checks under WSL Ubuntu.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text()); yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('workflow yaml parse ok')"` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-release-artifact-smoke-preflight.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\check-npm-publish-preflight.py` passed.
- `python scripts\check-npm-publish-preflight-regression.py` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` passed after fixing Homebrew license, filename, semver, and `conu-mcp` formula-test issues.
- PR #197 CI passed: <https://github.com/imthegoodboy/conU/actions/runs/26346662573>.
- Branch `Release Artifacts` passed: <https://github.com/imthegoodboy/conU/actions/runs/26346722152>.
- Main CI passed after merge: <https://github.com/imthegoodboy/conU/actions/runs/26346817022>.
- Main `Release Artifacts` passed after merge: <https://github.com/imthegoodboy/conU/actions/runs/26346869834>.

Known gaps:

- This generates release-attached Homebrew and Scoop manifests only. It does not submit to a Homebrew tap or Scoop bucket, add winget/Chocolatey/apt/rpm packages, add detached Linux package signatures, configure package-manager repository credentials, publish npm packages, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue with signing/npm secret configuration, package-manager repository submission, winget/Chocolatey/apt/rpm packaging, detached Linux package signatures, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal while preserving the `package-manager-manifest-preflight`, `npm-publish-conflict-preflight`, `release-artifact-smoke-binary-preflight`, `npm-smoke-local-binary-preflight`, and `npm-installer-local-binary-dir-guard` branches.

## Post Phase 15 - Windows Package-Manager Manifest Preflight

Status: completed

Goal:

Extend release-attached package-manager generation to winget and Chocolatey so
Windows package metadata is derived from the same verified release assets and
strict `.sha256` files as Homebrew and Scoop.

Completed work:

- PR #199 merged to `main` at
  `e9230e129b5c2ebb1b0f24cc7db0f7b0b79c3176`, Issue #198 is closed, and
  branch `windows-package-manifest-preflight` is preserved.
- Extended `scripts/generate-package-manager-manifests.py` to validate release
  tags, generate `imthegoodboy.conU.yaml` winget singleton manifests, and
  generate deterministic `conu.<version>.nupkg` Chocolatey packages
  containing `conu.nuspec` plus `tools/chocolateyInstall.ps1`.
- Reused the verified Windows release ZIP and strict checksum path for winget
  installer metadata and Chocolatey `Install-ChocolateyZipPackage` arguments;
  no Windows binaries or archive contents are embedded in the generated package
  metadata.
- Added Chocolatey uninstall cleanup for generated command shims and extracted
  ZIP package files through `tools/chocolateyUninstall.ps1`.
- Kept rooted/rootless Windows archive layout handling for Scoop, winget nested
  portable file mappings, and Chocolatey install-script binary discovery.
- Extended `scripts/check-package-manager-manifests.py` with rootless/rooted
  winget and Chocolatey assertions, deterministic Chocolatey package
  generation, strict tag validation, and forbidden-output checks over package
  member bodies.
- Updated release/distribution/production-readiness/packaging docs, release
  notes, repo memory, guardrails, and security checklist with the expanded
  Homebrew/Scoop/winget/Chocolatey policy.

Files changed:

- `.github/workflows/release.yml`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `scripts/generate-package-manager-manifests.py`
- `scripts/check-package-manager-manifests.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\generate-package-manager-manifests.py scripts\check-package-manager-manifests.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\verify-npm-package-contents.py` passed.
- `python scripts\check-package-manager-manifests.py` passed.
- `winget validate target\package-manager-echkng5k\out\imthegoodboy.conU.yaml` passed on a generated rootless fixture.
- `choco install conu --source target\package-manager-echkng5k\out --version 0.1.0 --noop --force --yes --limit-output` loaded the generated rootless `conu.0.1.0.nupkg`; Chocolatey printed the expected non-elevated-shell warning and did not execute the install script in noop mode.
- `winget validate` and `choco install --noop` also passed on a generated rooted Windows ZIP fixture under `%TEMP%`.
- `choco install conu --source <generated prerelease fixture> --noop --yes --no-color --limit-output --timeout=30 --pre` loaded `conu.1.2.3-rc.1+build.5.nupkg`.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text()); yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('workflow yaml parse ok')"` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-release-artifact-smoke-preflight.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\check-npm-publish-preflight.py` passed.
- `python scripts\check-npm-publish-preflight-regression.py` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` accepted one release-verifier collision finding; fixed by changing Chocolatey output from `.zip` to `conu.<version>.nupkg`.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` accepted one Chocolatey shim-uninstall finding; fixed by adding `tools/chocolateyUninstall.ps1`.
- Final `codex review -c sandbox_mode="danger-full-access" --uncommitted` reported no actionable correctness, security, or maintainability issues.
- PR #199 CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26348300403>.
- Branch `Release Artifacts` passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26348365177>.
- Post-merge `main` CI passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26348482406>.
- Post-merge `main` `Release Artifacts` passed:
  <https://github.com/imthegoodboy/conU/actions/runs/26348548561>.

Known gaps:

- This generates release-attached package-manager metadata only. It does not
  submit to package-manager repositories, add apt/rpm packages, add detached
  Linux package signatures, configure package-manager credentials, publish npm
  packages, configure signing/npm secrets, implement managed public relay
  hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue with signing/npm secret configuration, package-manager repository
  submission, apt/rpm packaging, detached Linux package signatures, managed
  public relay hosting, distributed hosted dashboards/adaptive abuse automation,
  distributed multi-instance session migration, managed hosted identity/key
  administration, remote/distributed tenant workflows, remote/cross-region
  mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 - Linux Package-Manager Artifact Preflight

Status: completed

Goal:

Extend release-attached package-manager generation to deterministic Debian
packages and RPM build metadata so Linux package distribution is derived from
the same verified release assets and strict `.sha256` files as the existing
Homebrew/Scoop/winget/Chocolatey path.

Completed work:

- Issue #200 was closed by PR #201 on branch
  `linux-package-manager-preflight`; PR #201 merged to `main` at merge commit
  `4023297af7554bddab1cc6e0d1bb0a4c06e5fc98`, and the remote branch is
  preserved.
- Extended `scripts/generate-package-manager-manifests.py` to read rooted or
  rootless Linux release tarballs, extract only the four expected release
  binaries, and generate deterministic `conu_<version>_amd64.deb` and
  `conu_<version>_arm64.deb` packages with strict `.sha256` sidecars.
- Added generated Debian control metadata, `md5sums`, minimal package docs, and
  a `/usr/bin/conud` systemd service example without embedding local state,
  tokens, or package repository credentials.
- Added generated `conu.spec` RPM build metadata for `x86_64` and `aarch64`
  that references the verified Linux release archive URLs and SHA-256 values.
- Extended `scripts/check-package-manager-manifests.py` to assert deterministic
  Debian packages, package checksums, Debian metadata/binary modes, rooted and
  rootless Linux tarball handling, RPM source/hash architecture guards, and
  forbidden-output checks.
- Added corrupt Linux tarball fail-closed coverage and optional native
  `dpkg-deb` metadata/content validation when the Debian package tool is
  available, so Ubuntu CI/WSL checks the generated `.deb` files with the platform
  package tool.
- Updated release/distribution/production-readiness/packaging docs, release
  notes, repo memory, guardrails, and security checklist with the expanded
  Homebrew/Scoop/winget/Chocolatey/Debian/RPM policy.

Files changed:

- `.github/workflows/release.yml`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `scripts/generate-package-manager-manifests.py`
- `scripts/check-package-manager-manifests.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\generate-package-manager-manifests.py scripts\check-package-manager-manifests.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\verify-npm-package-contents.py` passed.
- `python scripts\check-package-manager-manifests.py` passed, including the
  corrupt Linux tarball fail-closed regression.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed, exercising the optional `dpkg-deb` native package metadata/content checks under WSL Ubuntu.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text()); yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('workflow yaml parse ok')"` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-release-artifact-smoke-preflight.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\check-npm-publish-preflight.py` passed.
- `python scripts\check-npm-publish-preflight-regression.py` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` first found
  a corrupt Linux tarball traceback path; the extractor and regression were
  fixed, and the final rerun reported no actionable correctness, security, or
  maintainability issues.
- PR #201 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and
  CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26350412878>.
- Branch `Release Artifacts` passed on `linux-package-manager-preflight`,
  including package checks, production-readiness smoke, platform builds, artifact
  verification, smoke installs, download smoke, and attestations in unsigned
  smoke mode: <https://github.com/imthegoodboy/conU/actions/runs/26350470981>.
- Main CI passed after PR #201 merged:
  <https://github.com/imthegoodboy/conU/actions/runs/26350569350>.
- `Release Artifacts` passed on `main` after PR #201 merged:
  <https://github.com/imthegoodboy/conU/actions/runs/26350629699>.
- Local Windows `dpkg-deb` and `rpmbuild` commands are not installed. Debian
  package validation is covered by deterministic Python parser/regression checks
  and the WSL/Ubuntu `dpkg-deb` check above; RPM validation is currently covered
  by spec text checks and needs native RPM build validation before any `.rpm`
  package is published.

Known gaps:

- This generates release-attached Debian packages and RPM build metadata only.
  It does not submit to package-manager repositories, generate signed apt/yum
  repository metadata, build native `.rpm` packages, add detached Linux package
  signatures, configure package-manager credentials, publish npm packages,
  configure signing/npm secrets, implement managed public relay hosting, or
  close the known distributed hosted runtime gaps.

Next:

- Continue the remaining distribution and hosted-product gaps: native `.rpm`
  package build/signing, signed apt/yum repository metadata, repository
  submissions, package-manager credentials, managed public relay hosting,
  distributed hosted dashboards/adaptive abuse automation, distributed
  multi-instance session migration, managed hosted identity/key administration,
  remote/distributed tenant workflows, remote/cross-region mailbox retention
  orchestration, and ICE/STUN/TURN managed traversal.

## Post Phase 15 - Native RPM Package Build Preflight

Status: completed

Goal:

Verify generated RPM build metadata with native RPM tooling in CI and release
package checks before tag publication paths rely on the generated `conu.spec`.

Completed work:

- Issue #202 was closed by PR #203 on branch `rpm-native-build-preflight`;
  PR #203 merged to `main` at merge commit
  `98b2ef7a1aba3eb0cc5e6f10fb4e36560105f3d4`, and the branch is preserved.
- Extended `scripts/check-package-manager-manifests.py` so generated Linux
  release fixture archives include the docs/package files referenced by the RPM
  `%doc` section.
- Added optional native `rpmbuild -bb` validation for generated `conu.spec`
  files on `x86_64` and `aarch64`, including rooted and rootless release archive
  layouts.
- Added optional `rpm -qip` and `rpm -qlp` checks for generated temporary RPMs
  when the `rpm` query tool is available.
- Updated CI and release package jobs to install RPM tooling before running the
  package-manager regression.
- Updated release, packaging, distribution, production-readiness, repo memory,
  guardrail, and security checklist docs to describe the native RPM spec build
  preflight without claiming signed `.rpm` publication or RPM repository
  support.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-package-manager-manifests.py`
- `docs/release-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\check-package-manager-manifests.py scripts\generate-package-manager-manifests.py` passed.
- `python scripts\check-package-manager-manifests.py` passed on Windows; native
  RPM validation was skipped because `rpmbuild` is not installed locally.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && python3 scripts/check-package-manager-manifests.py'` passed under WSL Ubuntu; this covered native `dpkg-deb` checks, while native RPM validation was skipped because WSL does not have RPM tooling installed.
- Workflow YAML parsing for `.github/workflows/ci.yml` and
  `.github/workflows/release.yml` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-release-artifact-smoke-preflight.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\check-npm-publish-preflight.py` passed.
- `python scripts\check-npm-publish-preflight-regression.py` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` reported no
  actionable correctness, security, or privacy issues.
- PR #203 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and
  CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26351189383>.
- Branch `Release Artifacts` passed on `rpm-native-build-preflight`, including
  package checks with RPM tooling, production-readiness smoke, platform builds,
  artifact verification, smoke installs, download smoke, and attestations in
  unsigned smoke mode:
  <https://github.com/imthegoodboy/conU/actions/runs/26351245488>.
- Main CI passed after PR #203 merged:
  <https://github.com/imthegoodboy/conU/actions/runs/26351328300>.
- Main `Release Artifacts` passed after PR #203 merged:
  <https://github.com/imthegoodboy/conU/actions/runs/26351386555>.

Known gaps:

- This preflight builds temporary RPMs from verified fixture archives and
  generated specs only. It does not publish signed `.rpm` assets, generate
  yum/dnf repository metadata, submit to package-manager repositories, add
  detached Linux package signatures, publish npm packages, configure signing/npm
  secrets, implement managed public relay hosting, or close the known
  distributed hosted runtime gaps.

Next:

- Continue with signed `.rpm` publication, signed apt/yum repository metadata,
  package-manager repository submissions, package-manager credentials, detached
  Linux package signatures, managed public relay hosting, distributed hosted
  dashboards/adaptive abuse automation, distributed multi-instance session
  migration, managed hosted identity/key administration, remote/distributed
  tenant workflows, remote/cross-region mailbox retention orchestration, or
  ICE/STUN/TURN managed traversal while preserving the
  `rpm-native-build-preflight` branch.

## Post Phase 15 - RPM Release Asset Generation

Status: completed

Goal:

Publish unsigned native RPM assets from verified Linux release archives during
tagged GitHub Release publication, while keeping RPM signing and yum/dnf
repository metadata as explicit future work.

Completed work:

- Issue #204 was closed by PR #205 on branch `rpm-release-assets`; PR #205
  merged to `main` at merge commit
  `4048a7fab4b454ed28e782b169906fb60d97dce8`, and the branch is preserved.
- Added `--build-rpm-packages` to
  `scripts/generate-package-manager-manifests.py` so release publication can
  build unsigned `x86_64` and `aarch64` RPM packages from the generated
  `conu.spec` when native `rpmbuild` is installed.
- Added strict RPM output filenames and `.rpm.sha256` sidecars derived from the
  generated package bytes.
- Reused the same `rpmbuild` command path from the package-manager regression,
  with a fixed empty `%{?dist}` suffix and disabled RPM post-install binary
  mutation so prebuilt release binaries are packaged as-is.
- Updated the tagged GitHub Release job to install RPM tooling and call the
  generator with `--build-rpm-packages` before `gh release upload dist/*`.
- Updated release, packaging, distribution, platform-signing,
  production-readiness, repo-memory, guardrail, and security checklist docs to
  distinguish unsigned RPM asset publication from future RPM signing and
  repository metadata.

Files changed:

- `.github/workflows/release.yml`
- `scripts/generate-package-manager-manifests.py`
- `scripts/check-package-manager-manifests.py`
- `docs/release-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/platform-code-signing.md`
- `docs/production-readiness.md`
- `packaging/README.md`
- `packaging/package-managers/README.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation so far:

- `python -m py_compile scripts\generate-package-manager-manifests.py scripts\check-package-manager-manifests.py` passed.
- `python scripts\check-package-manager-manifests.py` passed on Windows; native
  RPM validation was skipped because `rpmbuild` is not installed locally.
- `wsl.exe sh -lc 'cd /mnt/c/Users/parth/Desktop/conU && command -v rpmbuild || true && python3 scripts/check-package-manager-manifests.py'` passed under WSL Ubuntu; native RPM validation was skipped because RPM tooling is not installed there.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-release-artifact-smoke-preflight.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `python scripts\check-npm-publish-preflight.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python scripts\check-npm-publish-preflight-regression.py` passed.
- `python scripts\check-npm-launcher-local-smoke-preflight.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review -c sandbox_mode="danger-full-access" --uncommitted` was
  attempted twice and timed out before reporting findings.
- PR #205 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and
  CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26352100147>.
- Branch `Release Artifacts` passed on `rpm-release-assets`, including release
  preflight, package checks with RPM tooling, production-readiness smoke,
  platform builds, artifact verification, smoke installs, download smoke,
  attestations, and artifact uploads in unsigned smoke mode:
  <https://github.com/imthegoodboy/conU/actions/runs/26352103131>.

Known gaps:

- This publishes unsigned RPM assets only. It does not add RPM package signing,
  yum/dnf repository metadata, package-manager repository submissions, detached
  Linux package signatures, package-manager credentials, npm publication,
  hosted public relay services, distributed hosted runtime automation, or
  managed NAT traversal.
- Local Windows and WSL validation did not exercise native RPM generation
  because `rpmbuild` is not installed in either local environment; PR CI and the
  branch `Release Artifacts` package job exercised the RPM path on Ubuntu.

Next:

- Continue with RPM package signing, signed apt/yum repository metadata,
  package-manager repository submissions, package-manager credentials, detached
  Linux package signatures, managed public relay hosting, distributed hosted
  dashboards/adaptive abuse automation, distributed multi-instance session
  migration, managed hosted identity/key administration, remote/distributed
  tenant workflows, remote/cross-region mailbox retention orchestration, or
  ICE/STUN/TURN managed traversal while preserving the `rpm-release-assets`
  branch.

## Post Phase 15 - npm Publish Conflict Preflight

Status: completed

Goal:

Fail tagged npm publication before any package is published when public publish metadata is incomplete, the npm token is missing, registry availability checks fail, or either target `@conu/*` package version already exists.

Completed work:

- Issue #194 tracked npm publish conflict preflight hardening, and PR #195 on branch `npm-publish-conflict-preflight` merged to `main` at `14f73b65808ff204b1e23f3ee1980c1b7c89dcb1`; Issue #194 is closed, and the branch is preserved.
- Added `scripts/check-npm-publish-preflight.py` to validate `@conu/cli` and `@conu/sdk` publish metadata, optional npm-token environment presence, and optional npm registry version availability.
- Added `scripts/check-npm-publish-preflight-regression.py` with fail-closed coverage for missing package versions, existing package versions, registry failures, and missing publish tokens.
- Wired the preflight and regression into CI package checks, Release Artifacts package checks, and `scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes`.
- Wired tagged npm publication to run `scripts/check-npm-publish-preflight.py --registry-check --require-token-env NODE_AUTH_TOKEN` before either `npm publish` command, so an existing `@conu/cli` or `@conu/sdk` version fails before partial publication starts.
- Made npm package publish metadata explicit by adding `license` to `@conu/cli` and repository/homepage/bugs metadata to `@conu/sdk`.
- Updated README, distribution, production-readiness, release checklist, packaging docs, repo memory, guardrails, and security checklist with the npm publish conflict preflight gate.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/check-npm-publish-preflight.py`
- `scripts/check-npm-publish-preflight-regression.py`
- `scripts/verify-production-readiness.ps1`
- `packaging/npm/conu-cli/package.json`
- `sdk/typescript/package.json`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\check-npm-publish-preflight.py scripts\check-npm-publish-preflight-regression.py` passed.
- `python scripts\check-npm-publish-preflight.py` passed.
- `python scripts\check-npm-publish-preflight-regression.py` passed.
- `python scripts\check-npm-publish-preflight.py --registry-check` passed against the live npm registry for `@conu/cli@0.1.0` and `@conu/sdk@0.1.0`.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text()); yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('workflow yaml parse ok')"` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` exited 0 and reported no actionable correctness, security, or privacy issues.
- PR #195 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26345132738>.
- Branch `Release Artifacts` workflow dispatch passed on `npm-publish-conflict-preflight`, including package checks, production readiness smoke, platform builds, artifact verification, local npm launcher install smoke, download npm launcher install smoke, and artifact attestations: <https://github.com/imthegoodboy/conU/actions/runs/26345135820>.
- Main CI passed after PR #195 merged: <https://github.com/imthegoodboy/conU/actions/runs/26345242821>.
- Main `Release Artifacts` workflow dispatch passed after PR #195 merged, including package checks, production readiness smoke, platform builds, artifact verification, local npm launcher install smoke, download npm launcher install smoke, and artifact attestations: <https://github.com/imthegoodboy/conU/actions/runs/26345255905>.

Known gaps:

- This hardens npm publish conflict preflight only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal while preserving the `npm-publish-conflict-preflight`, `release-artifact-smoke-binary-preflight`, `npm-smoke-local-binary-preflight`, and `npm-installer-local-binary-dir-guard` branches.

## Post Phase 15 - Release Artifact Smoke Binary Preflight

Status: completed

Goal:

Make the release artifact smoke fail before execution when extracted archive binaries are missing, when the extracted `bin/` directory is missing, or when a required binary path is not a regular file.

Completed work:

- Issue #192 tracked release artifact smoke binary preflight hardening, and PR #193 on branch `release-artifact-smoke-binary-preflight` merged to `main` at `321359293396bd6b95d69c63f1d544afed707c91`; Issue #192 is closed, and the branch is preserved.
- Tightened `scripts/smoke-release-artifacts.py` so `verify_archive_binaries` requires the extracted `bin/` directory to exist and every expected binary path to be a regular non-symlink file before chmod or execution.
- Added `scripts/check-release-artifact-smoke-preflight.py` with regression fixtures for valid layouts, missing binary directories, missing binaries, and directory entries named as binaries.
- Wired the new regression check into CI package checks, release package checks, and `scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes`.
- Updated README, distribution, production-readiness, release checklist, packaging docs, repo memory, guardrails, and security checklist with the release artifact smoke preflight gate.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/smoke-release-artifacts.py`
- `scripts/check-release-artifact-smoke-preflight.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\smoke-release-artifacts.py scripts\check-release-artifact-smoke-preflight.py scripts\check-release-artifact-verifier.py scripts\verify-release-artifacts.py scripts\verify-release-versions.py scripts\verify-npm-package-contents.py scripts\check-npm-launcher-local-smoke-preflight.py` passed.
- `python scripts\check-release-artifact-smoke-preflight.py` passed.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text()); yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('workflow yaml parse ok')"` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-npm-launcher-local-smoke-preflight.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\verify-release-artifacts.py dist` passed against the mixed local `dist/`.
- `python scripts\smoke-release-artifacts.py dist` passed against the mixed local `dist/`, smoke-testing both the host archive alias and the platform-named Windows archive.
- `python scripts\smoke-npm-launcher-local.py dist` passed against the mixed local `dist/`.
- `python scripts\smoke-npm-launcher-download.py dist` first hit a transient local Windows `EBUSY` while copying over `packaging/npm/conu-cli/vendor/windows-x64/conu.exe`; a rerun passed, skipping the host alias and verifying the platform-named npm download install checksum and extraction path.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- `codex review --uncommitted` exited 0 and reported no actionable correctness, security, or privacy issues.
- PR #193 CI passed on Packages, Rust macOS, Rust Ubuntu, Rust Windows, and CodeRabbit: <https://github.com/imthegoodboy/conU/actions/runs/26344385346>.
- Branch `Release Artifacts` workflow dispatch passed on `release-artifact-smoke-binary-preflight`, including package checks, production readiness smoke, platform builds, artifact verification, release artifact install smoke, npm launcher local/download smoke, and artifact attestations: <https://github.com/imthegoodboy/conU/actions/runs/26344386957>.
- Main CI passed after PR #193 merged: <https://github.com/imthegoodboy/conU/actions/runs/26344537737>.
- Main `Release Artifacts` workflow dispatch passed after PR #193 merged, including package checks, production readiness smoke, platform builds, artifact verification, release artifact install smoke, npm launcher local/download smoke, and artifact attestations: <https://github.com/imthegoodboy/conU/actions/runs/26344547494>.

Known gaps:

- This hardens release artifact smoke fixture validation only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue the remaining hosted/distributed production-readiness gaps while preserving the `release-artifact-smoke-binary-preflight`, `npm-smoke-local-binary-preflight`, and `npm-installer-local-binary-dir-guard` branches.

## Post Phase 15 - npm Launcher Local Smoke Binary Preflight

Status: completed

Goal:

Make the release npm launcher local smoke fail before npm install when extracted archive binaries are missing, when the extracted `bin/` directory is missing, or when a required binary path is not a regular file.

Completed work:

- Issue #190 tracked npm launcher local smoke binary preflight hardening, and PR #191 on branch `npm-smoke-local-binary-preflight` merged to `main` at `cfa5ba0a9e66a04196987d23919d8b965a832b4d`; Issue #190 is closed, and the branch is preserved.
- Tightened `scripts/smoke-npm-launcher-local.py` so `verify_archive_binaries` requires the extracted `bin/` directory to exist and every expected binary path to be a regular non-symlink file before setting `CONU_NPM_BINARY_DIR`.
- Added `scripts/check-npm-launcher-local-smoke-preflight.py` with regression fixtures for valid layouts, missing binary directories, missing binaries, and directory entries named as binaries.
- Wired the new regression check into CI package checks, release package checks, and `scripts/verify-production-readiness.ps1 -SkipRust -SkipSmokes`.
- Updated README, distribution, production-readiness, release checklist, packaging docs, repo memory, guardrails, and security checklist with the new release-smoke preflight gate.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/smoke-npm-launcher-local.py`
- `scripts/check-npm-launcher-local-smoke-preflight.py`
- `scripts/verify-production-readiness.ps1`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\smoke-npm-launcher-local.py scripts\smoke-npm-launcher-download.py scripts\check-npm-launcher-local-smoke-preflight.py scripts\verify-npm-package-contents.py scripts\verify-release-versions.py scripts\verify-release-artifacts.py scripts\check-release-artifact-verifier.py` passed.
- `python scripts\check-npm-launcher-local-smoke-preflight.py` passed.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/ci.yml').read_text()); yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text()); print('workflow yaml parse ok')"` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm run check --prefix sdk/typescript` passed.
- `python scripts\verify-release-versions.py` passed.
- `python scripts\check-release-artifact-verifier.py` passed.
- `python scripts\verify-npm-package-contents.py` passed.
- `python scripts\smoke-npm-launcher-local.py dist` passed against the mixed local `dist/`, smoke-testing both the host archive alias and the platform-named Windows archive.
- `python scripts\smoke-npm-launcher-download.py dist` passed against the mixed local `dist/`, skipping the host alias and verifying the platform-named npm download install checksum and extraction path.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-production-readiness.ps1 -SkipRust -SkipSmokes` passed.
- `git diff --check` passed.
- PR #191 CI passed: https://github.com/imthegoodboy/conU/actions/runs/26343725630
- Branch `Release Artifacts` passed: https://github.com/imthegoodboy/conU/actions/runs/26343727056
- Main CI after merge passed on `cfa5ba0a9e66a04196987d23919d8b965a832b4d`: https://github.com/imthegoodboy/conU/actions/runs/26343879820
- Main `Release Artifacts` after merge passed on `cfa5ba0a9e66a04196987d23919d8b965a832b4d`: https://github.com/imthegoodboy/conU/actions/runs/26343889783

Known gaps:

- This hardens release smoke fixture validation only. It does not publish npm packages, add OS package-manager installers, configure signing/npm secrets, implement managed public relay hosting, or close the known distributed hosted runtime gaps.

Next:

- Continue the remaining hosted/distributed production-readiness gaps while preserving the `npm-smoke-local-binary-preflight` and `npm-installer-local-binary-dir-guard` branches.

## Phase 0 - Project Memory

Status: completed

Goal:

Create the shared architecture, rules, skill memory, and phase plan future agents must follow.

Deliverables:

- `architecture.md`
- `plan.md`
- `.agents/AGENTS.md`
- `.agents/repo/ABOUT.md`
- `.agents/Rules/SKILL.MD`
- `.agents/Pr/SKILL.MD`
- `.agents/skills/conu-builder/SKILL.md`
- `.agents/skills/conu-builder/references/*`
- `.agents/skills/conu-repo-steward/*`
- `.agents/skills/conu-phase-keeper/*`
- `.agents/skills/conu-pr-guardian/*`
- `.agents/skills/conu-security-guardian/*`

Completion checklist:

- [x] Architecture document exists.
- [x] Agent rules exist.
- [x] Repo-local conU builder skill exists.
- [x] Repo overview exists.
- [x] Repo steward skill exists.
- [x] Phase keeper skill exists.
- [x] PR guardian skill exists.
- [x] Security guardian skill exists.
- [x] Phase plan exists.
- [x] User approves moving into implementation.

Validation:

- Documentation reviewed manually.
- Repo-local skill validated with `quick_validate.py`.
- Additional repo skills validated with `quick_validate.py`.

Known gaps:

- No Rust code exists yet.
- No cargo validation can run until Rust is installed and project is scaffolded.

Next:

- Phase 1 completed after user approval.

## Phase 1 - Rust Workspace Scaffold

Status: completed

Goal:

Create the Rust workspace foundation for the CLI, daemon, protocol, and relay.

Deliverables:

- `Cargo.toml` workspace
- `crates/conu-cli`
- `crates/conud`
- `crates/conu-protocol`
- `crates/conu-core`
- `crates/conu-relay`
- `.gitignore`
- baseline README if needed

Validation:

- `cargo fmt`
- `cargo check`
- `cargo test`

Exit criteria:

- [x] Workspace compiles.
- [x] CLI binary starts with the GNU Rust toolchain.
- [x] Shared protocol crate builds.

Completed work:

- Created root Cargo workspace.
- Added compile-ready crates for CLI, daemon, core, protocol, and relay.
- Added std-only Phase 1 binaries so local validation works without MSVC Build Tools.
- Added opaque protocol payload primitives with Debug redaction.
- Added component manifest and product-law invariant in `conu-core`.
- Added README and `.gitignore`.
- Created GitHub issue #1 for this phase.

Files changed:

- `.gitignore`
- `Cargo.toml`
- `Cargo.lock`
- `.gitignore`
- `README.md`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/lib.rs`
- `crates/conu-protocol/Cargo.toml`
- `crates/conu-protocol/src/lib.rs`
- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/main.rs`
- `crates/conud/Cargo.toml`
- `crates/conud/src/main.rs`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed with the default MSVC Rust toolchain.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- components` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conud -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --check` passed.

Known gaps:

- Default MSVC `cargo test` and `cargo run` fail locally because Visual Studio C++ Build Tools / `link.exe` are not installed.
- Phase 1 intentionally avoids clap, Tokio, tracing, and serde until linker support or CI validation is available.
- No real daemon, IPC, relay networking, or persistent state exists yet.

Next:

- Start Phase 2: CLI identity and dashboard.

## Phase 2 - CLI Identity And Dashboard

Status: completed

Goal:

Build the first advanced CLI shell with ASCII identity, status layout, and production command structure.

Commands:

```txt
conu
conu init
conu status
conu agents
conu pair
conu join <code>
conu connect
conu watch
```

Exit criteria:

- [x] CLI renders cleanly on Windows terminals.
- [x] No private payload contents are displayed.
- [x] Commands have helpful structured output.

Completed work:

- Created GitHub issue #3 for Phase 2.
- Created and pushed branch `codex/phase-2-cli-dashboard`.
- Refactored `conu-cli` into a testable library plus thin binary adapter.
- Added ASCII dashboard for `conu`.
- Added command shell for `init`, `status`, `agents`, `peers`, `pair`, `join <code>`, `connect`, `watch`, `components`, and reserved `start`.
- Added text and JSON status/agent outputs where useful.
- Kept Phase 3+ behavior honest: no persistent identity, trust store, IPC, relay, or real daemon state is created in Phase 2.
- Added tests for command registration, dashboard rendering, status JSON, join usage, unknown command handling, and watch content privacy.
- Updated README and repo overview for the completed CLI shell.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `plan.md`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli --` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- agents` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- pair` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- join 482913` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- connect` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- watch` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- peers --json` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- start` passed.

Known gaps:

- No real local identity is created; that remains Phase 3.
- No real daemon lifecycle is implemented; that remains Phase 4.
- No real local agent registration exists; that remains Phase 5.
- Pairing/join are command-shape previews only; trust creation remains Phase 7.
- Watch shows a static transport view only; live animation remains Phase 10.

Next:

- Start Phase 3: local identity, config, trust store skeleton, and safe state path resolution.

## Phase 3 - Local Identity And Persistent State

Status: completed

Goal:

Create local node identity, config, trust store, and data directory.

Deliverables:

- node id generation
- local config file
- trust store skeleton
- agent registry persistence
- state path resolution

Exit criteria:

- [x] `conu init` creates local identity.
- [x] `conu status` reads identity and config.
- [x] Re-running init is safe.

Completed work:

- Created GitHub issue #5 for Phase 3.
- Created and pushed branch `codex/phase-3-local-identity`.
- Added std-only local state management in `conu-core`.
- Added safe state path resolution with `CONU_HOME`, Windows `%APPDATA%\conU`, and Unix `$HOME/.conu` fallback.
- Added idempotent creation of `node.toml`, `config.toml`, `trust.toml`, `agents/registry.toml`, and future runtime directories.
- Added `conu init` integration that creates or repairs Phase 3 state without overwriting existing files.
- Added `conu status` and `conu status --json` integration that reads persisted identity/config/trust/registry readiness.
- Added `conu agents --json` registry readiness metadata while keeping actual registration reserved for Phase 5.
- Added tests for local state creation, idempotency, missing-state reads, CLI status, JSON shape, and watch payload privacy.
- Updated README, repo overview, and implementation guardrails.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `plan.md`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed a second time and preserved the same node id.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- agents --json` passed with isolated `CONU_HOME`.

Known gaps:

- Phase 3 node id is a local identifier only, not a cryptographic identity or authentication credential.
- No private keys, signed identities, encrypted mailbox, or key storage exists yet; those remain Phase 11 hardening work.
- No real daemon lifecycle exists yet; that remains Phase 4.
- No local agent registration exists yet; that remains Phase 5.
- Trust store and agent registry are skeleton files only until pairing/registration phases.

Next:

- Start Phase 4: conUD daemon skeleton with runtime state, health/status detection, graceful shutdown, and payload-safe logs.

## Phase 4 - conUD Daemon Skeleton

Status: completed

Goal:

Create the local runtime daemon that will own routing, sessions, identity, and agent connections.

Deliverables:

- daemon process
- runtime state machine
- graceful shutdown
- local health endpoint or IPC ping
- daemon logs without payloads

Exit criteria:

- [x] `conu start` launches runtime.
- [x] `conu status` detects runtime.
- [x] Runtime can restart cleanly.

Completed work:

- Created GitHub issue #7 for Phase 4.
- Created and pushed branch `codex/phase-4-conud-daemon`.
- Added std-only `conu_core::runtime` lifecycle module.
- Added runtime heartbeat/status metadata under `runtime/status.toml`.
- Added local process lock handling with stale heartbeat replacement.
- Added graceful shutdown request handling through `runtime/stop.request`.
- Added payload-safe runtime log lines under `logs/conud.log`.
- Updated `conud` with `--serve`, `--once`, `--status`, and enhanced `--check`.
- Wired `conu start` to launch `conud --serve`.
- Added `conu stop` for graceful shutdown.
- Updated `conu status`, `conu status --json`, and dashboard output to detect local runtime state.
- Added tests for runtime acquire, already-running guard, stop request, stopped cleanup, stale replacement, CLI runtime status, start already-running path, and stop request path.
- Updated README, repo overview, and implementation guardrails.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conud -p conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- init` passed with isolated `CONU_HOME`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- start` launched `conud --serve` with isolated `CONU_HOME` and `CONUD_EXE`.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status` detected the running daemon.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` reported running runtime metadata.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- stop` requested graceful shutdown and observed stopped state.
- `cargo +stable-x86_64-pc-windows-gnu run -p conud -- --once` passed.
- Smoke log review confirmed only metadata lines with `payload=not_observed`.

Known gaps:

- Phase 4 health is file-backed heartbeat metadata, not real IPC.
- `conu start` needs an installed/sibling `conud` binary or `CONUD_EXE` in development.
- There is no local agent registration yet; that remains Phase 5.
- There is no message routing, transport encryption session, relay, or remote discovery yet.
- Runtime logs are std-only text metadata and do not yet have rotation or structured logging.

Next:

- Start Phase 5: local IPC transport and agent registration with payload-safe agent registry updates.

## Phase 5 - Local IPC And Agent Registration

Status: completed

Goal:

Let local agents register with conUD through a local gateway.

Deliverables:

- [x] local IPC transport
- [x] register agent request
- [x] agent card model
- [x] presence heartbeat
- [x] `conu agents` local list

Exit criteria:

- [x] A sample local agent can register.
- [x] CLI lists local registered agents.
- [x] Agent identity persists.

Completed work:

- Created GitHub issue #9 for Phase 5.
- Created and pushed branch `codex/phase-5-local-ipc-agents`.
- Added std-only `conu_core::agents` local gateway and registry module.
- Added file-backed IPC directories under `runtime/ipc/inbox`, `runtime/ipc/processed`, and `runtime/ipc/rejected`.
- Added metadata-only registration request submission and processing.
- Added presence heartbeat submission and processing for registered local agents.
- Persisted local agent records in `agents/registry.toml` with id, display name, node id, kind, presence, last seen time, and capability booleans.
- Integrated conUD serve loop and `conud --process-ipc` with gateway request processing.
- Updated `conu agents`, `conu agents --json`, `conu agents register`, and `conu agents heartbeat`.
- Updated `conu status` and dashboard output with local IPC and local agent count.
- Added payload-safe `logs/agents.log` metadata lines with `payload=not_observed`.
- Hardened rejected IPC request errors so arbitrary request contents are not echoed into rejection reasons.
- Updated README, repo overview, builder guardrails, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conud -p conu-cli` passed.
- Direct binary smoke passed with isolated `CONU_HOME`: `conu init`, `conu start`, `conu agents register agent.codex "Codex Desktop" --kind coding-agent`, `conu agents heartbeat agent.codex --presence busy`, `conu status --json`, and `conu stop`.
- Smoke follow-up confirmed `conu agents --json` showed `presence: busy`.
- Smoke log review confirmed `logs/agents.log` contains only metadata lines with `payload=not_observed`.
- `conud --process-ipc` passed after daemon stop with no pending requests.
- Explicit process check confirmed no `conud` process remained running after smoke.

Known gaps:

- Phase 5 IPC is file-backed for reliability and visibility; it is not yet named pipes, Unix sockets, or binary framed IPC.
- The gateway only supports registration and presence. Message send/receive starts in Phase 6.
- Agent capabilities are basic booleans only; policy grants and signed agent cards arrive in later trust/security phases.
- There is no remote discovery or relay integration yet.

Next:

- Start Phase 6: local opaque envelope messaging with sender/receiver validation, local inbox, and delivery metadata that never displays payload contents.

## Phase 6 - Opaque Envelope Messaging

Status: completed

Goal:

Implement local opaque message envelopes and local send/receive routing.

Deliverables:

- [x] envelope type
- [x] message id
- [x] sender/receiver validation
- [x] local inbox
- [x] delivery receipt skeleton

Exit criteria:

- [x] One local agent can send an opaque payload to another local agent.
- [x] CLI can show delivery metadata without showing payload.

Completed work:

- Created GitHub issue #11 for Phase 6.
- Created and pushed branch `codex/phase-6-opaque-messaging`.
- Added std-only `conu_core::messages` local message routing module.
- Added file-backed message request queue under `runtime/ipc/messages/`.
- Added recipient inbox storage under `messages/inbox/<agent-id>/`.
- Added metadata-only delivery receipts under `messages/receipts/`.
- Added sender and recipient validation against the local registered agent registry.
- Added `conu messages send <from-agent> <to-agent> --stdin`.
- Added `conu messages inbox <agent-id>` and JSON output.
- Added `conu messages receipts` and JSON output.
- Wired conUD serve loop, `conud --once`, and `conud --process-ipc` to process local message requests.
- Added payload-safe `logs/messages.log` metadata lines with `payload=not_observed`.
- Ensured processed and rejected message request markers do not keep or display payload contents.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/Cargo.toml`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conud -p conu-cli` passed.
- Live isolated `CONU_HOME` smoke passed: `conu init`, `conu start`, two `conu agents register` calls, `conu messages send agent.sender agent.receiver --stdin`, `conu messages inbox agent.receiver --json`, `conu messages receipts --json`, `conu stop`, and `conud --process-ipc`.
- Smoke confirmed delivery status `delivered`, recipient inbox metadata, `delivered_local` receipt metadata, and `logs/messages.log` with `payload=not_observed`.
- Explicit process check confirmed no `conud` process remained running after smoke.

Known gaps:

- Phase 6 is local-only; there is no remote relay, remote discovery, pairing, streams, rooms, or pub/sub yet.
- Message payload bytes are stored as opaque local recipient-inbox envelope data, not displayed or logged. Encryption hardening and encrypted mailbox storage remain Phase 11 work.
- The CLI can submit from stdin and list metadata, but SDK/MCP receive APIs arrive in Phase 12.
- File-backed message IPC is intentionally simple; named pipes, Unix sockets, and binary framed IPC remain future production upgrades.

Next:

- Start Phase 7: pairing and trust records between runtimes, including code lifecycle, trust entry persistence, and revocation/listing groundwork.

## Phase 7 - Pairing And Trust

Status: completed

Goal:

Create the trust-forming flow between runtimes.

Deliverables:

- [x] `conu pair`
- [x] `conu join <code>`
- [x] pairing code lifecycle
- [x] trust entry
- [x] peer revocation command if needed

Exit criteria:

- [x] Pairing creates trusted peer records.
- [x] Trust can be listed and revoked.

Completed work:

- Created GitHub issue #13 for Phase 7.
- Created and pushed branch `codex/phase-7-pairing-trust`.
- Added std-only `conu_core::trust` local pairing and trust store module.
- Added local pairing invitation persistence under `pairing/invites/` and consumed invitations under `pairing/used/`.
- Added `conu pair` to create a six-digit local pairing invitation with expiration.
- Added `conu join <code>` to consume a local invitation and write a trusted peer record.
- Added `conu peers` and `conu peers --json` for trust listing.
- Added `conu peers revoke <peer-node-id>` for revocation.
- Updated status/dashboard output to count trusted peers.
- Stored `pairing_code_hash` in `trust.toml` instead of raw used pairing codes.
- Derived peer ids and display names from a hash suffix instead of the raw pairing code.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/trust.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-cli` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, `conu pair`, `conu join <code>`, `conu peers --json`, and `conu peers revoke <peer-node-id> --json`.
- Smoke confirmed peer output does not expose the raw used pairing code and `trust.toml` stores `pairing_code_hash`.

Known gaps:

- Phase 7 pairing is local-only trust groundwork; cross-machine rendezvous requires the Phase 8 relay service plus Phase 9 session/discovery wiring.
- Pairing invitations are file-backed and not cryptographically signed yet.
- Trust records are persistent metadata, but full permission grants, key exchange, and signed peer verification arrive in later security phases.
- Remote agent discovery over trusted peers starts in Phase 9.

Next:

- Start Phase 8: WebSocket relay MVP for hosted rendezvous and opaque forwarding groundwork.

## Phase 8 - WebSocket Relay MVP

Status: completed

Goal:

Make conU work across the internet through a relay-first transport.

Deliverables:

- [x] relay service crate
- [x] runtime relay frame contract
- [x] relay session auth
- [x] peer rendezvous groundwork
- [x] opaque metadata forwarding path

Exit criteria:

- [x] Two runtime sessions can connect through relay in tests.
- [x] Relay forwards only opaque envelope metadata.
- [x] Relay output and tests do not expose payloads.

Completed work:

- Created GitHub issue #15 for Phase 8.
- Created and pushed branch `codex/phase-8-websocket-relay`.
- Added shared `conu_core::relay` frame types for `HELLO`, `FORWARD`, `PING`, `WELCOME`, `ENVELOPE`, `SENT`, `UNDELIVERED`, `PONG`, and `ERROR`.
- Added metadata-only relay rendering/parsing that rejects plaintext payload fields.
- Added a std-only WebSocket relay service in `crates/conu-relay`.
- Added relay session token authentication through `HELLO`.
- Added connected-peer forwarding from one runtime session to another using node id, envelope id, and byte count only.
- Added `conu-relay --serve [addr]`, `--check`, `--help`, and `CONU_RELAY_TOKEN`.
- Fixed Windows accepted-socket behavior by returning nonblocking listener streams to blocking mode before frame reads.
- Updated CLI/status wording to show the relay service is available while remote sessions/discovery remain future work.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract for the relay MVP.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-cli -- status --json` passed.
- Privacy scan reviewed relay payload/token terms; matches were limited to negative tests, placeholder frame documentation, and existing opaque local storage internals.

Known gaps:

- Phase 8 relay is plain local WebSocket for MVP validation, not TLS-hosted WSS.
- conUD does not yet own a relay client, remote session manager, reconnect loop, or route selection.
- Relay authentication is a shared token suitable for local/dev deployment only; signed node identity and key exchange remain security-hardening work.
- Relay forwards metadata only and does not store offline mailbox messages.
- Remote agent discovery over trusted peers begins in Phase 9.

Next:

- Start Phase 9: remote discovery and sessions through trusted peers, with conUD-owned relay client integration and metadata-only presence sync.

## Phase 9 - Remote Discovery And Sessions

Status: completed

Goal:

Let paired runtimes discover allowed remote agents and maintain sessions.

Deliverables:

- [x] remote agent cards
- [x] presence sync mirror
- [x] session manager
- [x] reconnect metadata loop
- [x] route metadata

Exit criteria:

- [x] `conu agents` shows trusted remote agents after conUD/session sync.
- [x] Presence and visibility metadata propagates from trusted peer session state.
- [x] Sessions retain route/reconnect metadata for later live networking.

Completed work:

- Created GitHub issue #17 for Phase 9.
- Created and pushed branch `codex/phase-9-remote-sessions`.
- Added `conu_core::sessions` for remote runtime session metadata, trusted remote agent mirrors, and payload-safe session logs.
- Added `sessions/registry.toml` and `agents/remote.toml` state paths.
- Added conUD-owned session sync in the runtime serve loop, `conud --once`, and `conud --process-ipc`.
- Added `conu sessions`, `conu sessions --json`, `conu sessions sync`, and `conu sessions sync --json`.
- Updated `conu agents`, `conu agents --json`, `conu connect`, `conu status`, and dashboard output to include remote session/agent visibility.
- Ensured revoked peers are not visible as active remote agents after session sync.
- Added tests for session sync, remote agent visibility, revoked peer removal, and payload-safe session logs.
- Updated README, repo overview, builder guardrails, repo map, and agent gateway contract.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all` passed.
- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `git diff --check` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, `conu pair`, `conu join <code>`, `conu sessions sync`, `conu agents --json`, `conu sessions --json`, and `conud --process-ipc`.
- Privacy scan reviewed payload/token terms; matches were limited to negative tests, placeholder frame documentation, original product examples, and existing opaque local storage internals.

Known gaps:

- Phase 9 remote agent cards are derived from trusted peer metadata; full relay-backed card exchange remains later work.
- Session state is metadata-only and file-backed; no live stream, relay client connection, backoff timer, or network retry loop is active yet.
- Reconnect attempts are recorded as metadata groundwork but not driven by real transport failure events.
- Signed remote agent cards, permission grants, and encrypted session key exchange remain security-hardening work.
- Streams and CLI watch animation begin in Phase 10.

Next:

- Start Phase 10: stream ids, stream lifecycle metadata, backpressure counters, and payload-safe watch animation.

## Phase 10 - Streams And Watch Animation

Status: completed

Goal:

Add stream support and the private CLI animation showing agent traffic flow.

Deliverables:

- [x] stream ids
- [x] stream open/write/close
- [x] backpressure windows
- [x] watch event bus
- [x] CLI animation

Exit criteria:

- [x] Agents can open streams.
- [x] `conu watch` shows traffic metadata only.
- [x] No payload text appears in watch output.

Completed work:

- Created GitHub issue #19 for Phase 10.
- Created and pushed branch `codex/phase-10-streams-watch`.
- Added `conu_core::streams` for stream lifecycle metadata, opaque chunk byte counts, backpressure validation, watch events, and payload-safe stream logs.
- Added `streams/registry.toml`, `streams/events.toml`, and `logs/streams.log` state surfaces.
- Added `conu streams`, `conu streams --json`, `conu streams open`, `conu streams write --stdin`, and `conu streams close`.
- Updated the CLI binary so `streams write --stdin` reads stdin like message send.
- Updated `conu watch` to render private stream flow, route, stream id, event type, open stream count, packet count, and byte count without payload contents.
- Updated `conu status`, `conu connect`, help text, README, repo overview, builder guardrails, repo map, CLI experience reference, and agent gateway contract.
- Added tests for stream lifecycle, backpressure rejection, target visibility, binary stdin routing, CLI stream flow, and watch privacy.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/cli-experience.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/streams.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `git diff --check` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, two `conu agents register` calls, two `conud --process-ipc` calls, `conu streams open`, `conu streams write <stream-id> --stdin`, `conu watch`, `conu streams close`, and `conu streams --json`.
- Privacy scan reviewed payload/token terms; matches were limited to negative tests, placeholder frame documentation, original product examples, and existing opaque local storage internals.

Known gaps:

- Phase 10 streams record metadata and byte counts only; they do not yet move encrypted chunk bytes over a live relay transport.
- Stream chunks are accepted from stdin and counted, but conU-owned stream storage intentionally does not persist chunk contents.
- Watch animation is static CLI rendering over the event bus, not a continuously refreshing TUI yet.
- End-to-end stream encryption, signed stream peers, and replay protection begin in Phase 11.

Next:

- Start Phase 11: encryption hardening, signed cards, replay protection, encrypted storage, and key rotation planning.

## Phase 11 - Encryption Hardening

Status: completed

Goal:

Make payload and session security production-grade.

Deliverables:

- peer key exchange
- signed agent cards
- replay protection
- encrypted payload storage
- key rotation plan

Exit criteria:

- [x] Payloads are encrypted before conU-owned local storage and peer encryption helpers exist for relay transit.
- [x] Trust verification is explicit through signed local agent cards and X25519 public exchange material.
- [x] Revoked peers remain excluded by the Phase 9 session mirror and replayed local message ids are rejected.

Completed work:

- Created GitHub issue #22 for Phase 11.
- Created branch `codex/phase-11-encryption-hardening`.
- Added `conu_core::security` for Ed25519 signing, X25519 key agreement, XChaCha20Poly1305 encrypted storage, replay cache, security audit, and local key rotation plan generation.
- Added local security state under `security/`.
- Updated `conu init` to create local security keys and `conu security audit` to report payload-safe readiness.
- Encrypted new local message request and recipient inbox payload storage with authenticated metadata.
- Added replay protection for local message request ids and envelope ids.
- Added Ed25519 signatures to new/updated local agent registry records.
- Added peer encryption/key-agreement helpers for the later live relay-backed data path.
- Added docs for security hardening and production readiness.
- Updated future-agent guardrails, repo overview, gateway contract, security checklist, and repo map.

Files changed:

- `Cargo.lock`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `.agents/about/how_it_will_work.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/security.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `git diff --check` passed.
- Isolated `CONU_HOME` smoke passed: `conu init`, `conu security audit --json`, two signed `conu agents register` flows, `conud --process-ipc`, `conu messages send --stdin`, `conu messages inbox --json`, encrypted field scan, signature field scan, and plaintext payload scan.
- Privacy scan confirmed `Review this code` remains only in artificial negative tests and the smoke payload was not present in conU-owned state.
- Initial default `cargo check --workspace --all-targets` failed because the local MSVC linker is not installed and new crypto dependencies compile build scripts. This matches the existing Windows toolchain gap; use the GNU toolchain until MSVC Build Tools or CI are configured.

Known gaps:

- Local private key files are protected by filesystem permissions/profile ACL only; production release still needs OS keychain, DPAPI, Secure Enclave, HSM, or user-managed secret backend support.
- Automated key rotation, multi-key reads, and storage re-encryption migration are documented but not implemented.
- Remote session mirrors do not yet exchange signed remote agent cards over a live transport.
- Relay-backed encrypted remote data-plane delivery is not active yet; Phase 11 provides the key agreement and encryption helpers for that next transport phase.
- Capability grants and full permission policy remain future work.

Next:

- Start Phase 12: SDK and MCP adapter so agents can call register, peers, send, receive, stream, and security-safe receive APIs without learning conU internals.

## Phase 12 - SDK And MCP Adapter

Status: completed

Goal:

Give agents a simple way to use conU.

Deliverables:

- Rust SDK
- Python SDK
- TypeScript SDK, completed by the post-Phase-15 wrapper pass below
- MCP adapter exposing conU communication tools
- examples for local agents

Exit criteria:

- [x] Agent can call register, peers, send, receive, stream.
- [x] MCP-capable agents can use conU as tools.

Completed work:

- Created GitHub issue #26 for Phase 12.
- Created branch `codex/phase-12-sdk-mcp-adapter`.
- Added `crates/conu-sdk`, a Rust SDK wrapping existing `conu-core` gateway, message, trust, session, stream, runtime, state, and security surfaces.
- Added explicit addressed-agent receive API through `ConuClient::receive_message_bytes`.
- Added `crates/conu-mcp`, a newline-delimited JSON-RPC MCP stdio adapter exposing conU as tools.
- Added MCP tools for status, security audit, register, presence, process queued, list agents, list peers, send message, receive message, open stream, write stream, and close stream.
- Added payload-safe MCP behavior: list/send/status/stream results are metadata-only, while `conu_receive_message` returns `payloadHex` only when `includePayload` is true.
- Added optional `CONU_AGENT_ID` binding so one `conu-mcp` stdio server can be scoped to one local agent.
- Added stdlib Python wrapper SDK under `sdk/python/conu_sdk`.
- Added Rust and Python local-agent examples.
- Updated README, user install guide, production/security docs, repo memory, agent gateway contract, implementation guardrails, repo map, and security checklist.
- Checked current MCP transport docs and aligned the adapter with stdio JSON-RPC messages delimited by newlines.

Files changed:

- `Cargo.toml`
- `Cargo.lock`
- `README.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `docs/production-readiness.md`
- `docs/security-hardening.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/SKILL.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-core/src/lib.rs`
- `crates/conu-sdk/Cargo.toml`
- `crates/conu-sdk/src/lib.rs`
- `crates/conu-sdk/examples/local_agents.rs`
- `crates/conu-mcp/Cargo.toml`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-mcp/src/main.rs`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `examples/python/local_agent_pair.py`

Validation:

- `cargo fmt` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-sdk --example local_agents` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-mcp` stdio `tools/list` smoke passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- Python SDK smoke passed with local `target/debug/conu.exe` and `target/debug/conud.exe`.
- Default `cargo check --workspace` still fails locally because the active MSVC toolchain cannot find `link.exe`; GNU toolchain validation passed.

Known gaps:

- Superseded by the post-Phase-15 TypeScript SDK wrapper pass below; TypeScript/JavaScript agents now have a dependency-free Node wrapper around installed `conu`/`conud` binaries.
- MCP adapter is stdio-only; no HTTP MCP transport is implemented.
- SDK/MCP local receive returns payload bytes only for local addressed inboxes; real remote data-plane delivery remains future work.
- Capability grants and richer permission policy are not complete yet.
- Packaging and installer support remain Phase 15.

Next:

- Start Phase 13: direct transport and NAT upgrade, including route selection, relay fallback integration in conUD, and live encrypted data-plane delivery groundwork.

## Phase 13 - Direct Transport And NAT Upgrade

Status: completed

Goal:

Move beyond relay-only networking.

Deliverables:

- [x] direct QUIC candidate route records
- [x] direct route attempt/probe metadata
- [x] relay fallback
- [x] route quality scoring
- [x] NAT profile config and hole-punching research notes
- [ ] live QUIC socket transport

Exit criteria:

- [x] Direct route candidate is recorded when a valid direct endpoint is configured; later production guard keeps relay selected until live direct transport exists.
- [x] Relay fallback keeps route selection reliable when direct is unavailable.

Completed work:

- Added `conu_core::routes`, a conUD-owned route manager that builds direct QUIC candidates and relay WebSocket fallback candidates for trusted peers only.
- Added route scoring by NAT profile, deterministic selected-route lookup, relay fallback flags, route probe history, and payload-safe route logs.
- Added route state layout under `routes/registry.toml`, `routes/probes.toml`, and `logs/routes.log`.
- Integrated route sync into `conu sessions sync`, conUD runtime processing, stream route labels for remote agents, Rust SDK, Python SDK wrapper, and MCP.
- Added CLI commands: `conu routes`, `conu routes sync`, and `conu routes probes`, with text and JSON output.
- Updated `conu status`, dashboard, and `conu connect` to show selected direct/relay/fallback route metadata.
- Updated docs and future-agent skills to explain Phase 13 route behavior, config, validation, and privacy boundaries.

Files changed:

- `crates/conu-core/src/routes.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conud/src/main.rs`
- `sdk/python/conu_sdk/__init__.py`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `.agents/repo/ABOUT.md`
- `.agents/Pr/SKILL.MD`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`

Validation:

- `cargo fmt` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- Python wrapper route smoke passed with local `target/debug/conu.exe`.
- Isolated CLI smoke passed with `CONU_HOME` under `%TEMP%`: `conu init`, `conu pair`, `conu join`, `conu routes sync --json`, `conu routes --json`, and `conu status --json`.
- `git diff --check` passed.
- Privacy scan reviewed payload-looking strings; new route files, logs, CLI, SDK, MCP, and docs remained metadata-only.

Known gaps:

- Real QUIC packet transport is not implemented yet; Phase 13 records `direct-quic` route candidates, and the later direct route selection guard keeps relay selected until direct transport exists.
- NAT traversal is config/profile based; live ICE-style candidate gathering, STUN/TURN, and hole punching remain future transport work.
- Route probes are metadata/config probes with latency estimates, not real RTT measurements.
- conUD still does not own live relay-backed encrypted message or stream-chunk delivery.
- Direct endpoint config is manual today.

Next:

- Start Phase 14: rooms, pub/sub, and multi-agent session metadata, while keeping live direct QUIC and relay-backed encrypted data-plane delivery as future transport hardening.

## Phase 14 - Rooms, Pub/Sub, And Multi-Agent Sessions

Status: completed

Goal:

Support shared spaces and multiple agents in one session.

Deliverables:

- [x] rooms
- [x] membership-based local subscriptions
- [x] publish/subscribe topics
- [x] room presence through participant metadata
- [x] group stream/room metadata in CLI status, dashboard, connect, and watch

Exit criteria:

- [x] Trusted agents can join a room.
- [x] Events route to subscribed local agents.
- [x] CLI shows room flow without payloads.

Completed work:

- Added `conu_core::rooms` with room registry, participants, topics, payload-safe event bus, metadata logs, and backpressure limits.
- Added local room event fanout: publishing to a room delivers encrypted-at-rest event envelopes to joined local participants' message inboxes while room registry/event/log surfaces keep only metadata.
- Added `conu rooms`, `conu rooms create`, `conu rooms join`, `conu rooms publish --stdin`, and `conu rooms events` with text and JSON output.
- Fixed the real CLI binary stdin path so `conu rooms publish --stdin` reads payload bytes outside unit tests.
- Added `conu connect local` and `conu connect room` flows, plus a richer ASCII dashboard/watch view with rooms, room events, local deliveries, routes, streams, relay queue state, and payload privacy markers.
- Added room APIs to the Rust SDK, Python wrapper SDK, and MCP adapter.
- Updated user docs, release checklist, repo memory, README, and tests for rooms/pub-sub behavior.

Files changed:

- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `docs/observability.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `plan.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-cli/src/main.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `sdk/python/conu_sdk/__init__.py`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Release archive inspection passed, including all binaries plus `docs/sdk-and-mcp.md` and `docs/internet-relay-test.md`, and excluding local conU state/log/security/message directories.
- `git diff --check` passed.
- Direct binary room smoke passed with isolated `CONU_HOME`: `conu init`, agent registration, `conud --process-ipc`, `conu rooms create`, `conu rooms join --json`, real stdin `conu rooms publish --stdin --json`, `conu rooms events`, `conu messages inbox --json`, payload-text scan across conU-owned state, and rejected nonlocal publisher spoof without payload echo.

Known gaps:

- Superseded by the post-Phase-15 relay-backed room event fanout pass below: joined trusted remote room participants now receive peer-encrypted relay room-event envelopes.
- Superseded by the post-Phase-15 room topic policy pass below: unconfigured topics keep room membership as the compatibility boundary, while configured room/topic pairs require explicit publish/subscribe grants.
- Relay-backed stream-chunk routing, hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, offline mailbox, and OS-backed key storage remain future hardening work.
- Public managed online release remains blocked until the hosted relay/TLS/auth/session work is complete.

Next recommendation:

- Prioritize hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, and then remote room fanout/stream-chunk routing before advertising conU as a managed public internet service.

## Phase 15 - Packaging And Production Readiness

Status: completed

Goal:

Prepare conU for real users.

Deliverables:

- [x] Windows build
- [x] macOS build path
- [x] Linux build path
- [x] installer strategy
- [x] service installation templates
- [x] config docs
- [x] security review checklist
- [x] observability setup

Exit criteria:

- [x] User can install, start, pair, and connect agents for local-first usage.
- [x] Logs and telemetry guidance are payload-safe.
- [x] Release checklist exists.

Completed work:

- Created GitHub issue #30 for Phase 15 and worked on `codex/phase-15-production-readiness`.
- Added `conu doctor` and `conu doctor --json` for local readiness, companion-binary discovery, security readiness, runtime health, release gates, and payload-safe log scanning.
- Added toolchain-aware release build scripts for Windows PowerShell and macOS/Linux shell workflows.
- Added local smoke script for install/start/message/route/doctor validation, including native exit-code checks and a `localInstallReady=true` doctor gate.
- Added packaging templates for Windows current-user install/uninstall plus optional service creation, Linux systemd, and macOS launchd.
- Added GitHub CI and release artifact workflows.
- Added release checklist and observability docs.
- Updated README, user install guide, production readiness docs, repo memory, guardrails, repo map, and security checklist.
- Kept Phase 14 rooms/pub-sub explicitly not started.

Files changed:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.gitignore`
- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conud/src/main.rs`
- `docs/observability.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/linux/conud.service`
- `packaging/macos/com.conu.conud.plist`
- `packaging/windows/install.ps1`
- `packaging/windows/uninstall.ps1`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `scripts/smoke-local.ps1`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and asserted `conu doctor --json` reported `releaseGates.localInstallReady = true` in an isolated `CONU_HOME`.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed and created `dist/conu-0.1.0-host.zip`.
- `target\release\conu.exe doctor --json` passed and reported shipped companion binaries without displaying payload contents.
- `git diff --check` passed.
- Privacy scan reviewed payload-looking terms; matches are existing negative tests, storage field names, and SDK/MCP input contracts, not Phase 15 runtime output, logs, docs, or release artifacts.

Known gaps:

- Phase 14 rooms/pub-sub remains not started.
- Release artifacts are unsigned and not notarized.
- Windows service script requires an elevated shell for service creation.
- Linux/macOS service templates require user/path edits before installation.
- Public hosted internet readiness remains blocked by live encrypted remote data-plane delivery, real direct QUIC transport, remote signed agent-card exchange, capability policy, and OS-backed key storage.

Next:

- Return to Phase 14 rooms, pub/sub, and multi-agent sessions, or harden signed installers/OS key storage if the product priority stays packaging.

## Post Phase 15 Audit - Production Polish

Status: completed

Goal:

Audit the whole repo after Phase 15, fix small maintainability issues, and raise the validation bar without starting Phase 14 feature work.

Completed work:

- Created GitHub issue #32 for the final audit and production polish pass.
- Updated the CLI crate header so it describes the current control-room surface instead of stale Phase 13 wording.
- Boxed the `RuntimeError::AlreadyRunning` status payload to keep runtime error results small.
- Moved the test-only runtime nanosecond helper before the test module for cleaner module layout.
- Simplified MCP JSON-RPC notification handling with `?` while preserving notification behavior.
- Refactored status rendering through a `StatusView` to avoid long argument lists.
- Tightened a CLI test helper to accept `&Path` instead of `&PathBuf`.
- Added clippy with `-D warnings` to CI, release checklist, production readiness docs, README development commands, and PR guardrails.

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.
- Privacy scan reviewed payload-looking terms; matches are existing negative tests, storage field names, and SDK/MCP input contracts.

Known gaps:

- No Phase 14 rooms/pub-sub implementation was started in this audit.
- Public hosted internet readiness remains blocked by the known Phase 15 release blockers.

## Post Phase 15 Internet Data-Plane And CLI Polish

Status: completed

Goal:

Make conU testable over a reachable WebSocket relay for one-shot peer-encrypted agent messages, while improving the CLI control-room flow and keeping all payload surfaces private.

Completed work:

- Created GitHub issue #34 and branch `codex/internet-data-plane-cli-polish`.
- Extended the shared relay frame contract to carry peer-encrypted opaque bodies while still rejecting plaintext payload fields.
- Added a std-only relay WebSocket client in `conu_core::relay`.
- Added manual public peer-card export/import with `conu identity export` and `conu peers trust`.
- Added relay-backed remote message queueing with `conu messages send --peer <peer-node-id> --stdin`.
- Added `conu relay sync --wait-ms <ms>` for explicit outbound flush and inbound receive over the relay.
- Delivered inbound relay envelopes to the addressed local agent inbox after verifying the sender exchange public key against local trust.
- Added relay queue counters and a richer ASCII `conu watch` transport view.
- Exposed peer-card, remote send, and relay sync helpers through the Rust SDK, Python wrapper, and MCP adapter.
- Added `docs/internet-relay-test.md` and updated user, SDK/MCP, production, security, release, README, and future-agent docs.

Files changed:

- `Cargo.toml` lock/dependency metadata as needed by existing workspace updates.
- `README.md`
- `docs/internet-relay-test.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `docs/security-hardening.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/trust.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `crates/conu-sdk/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `sdk/python/conu_sdk/__init__.py`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed, including a two-home relay E2E test that sends and receives a peer-encrypted message through `conu-relay`.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed and created `dist/conu-0.1.0-host.zip`.
- `git diff --check` passed.
- Targeted CLI remote queue test passed and confirmed the relay outbox stores encrypted fields without literal payload text.
- Privacy scan reviewed payload-looking strings; matches are artificial negative tests, docs examples, or encrypted field names, not runtime log/CLI payload leakage.

Known gaps:

- Superseded by the `wss://` relay-client pass below: relay clients now accept `ws://` and certificate-valid `wss://`; public `wss://` still requires TLS termination in front of `conu-relay`.
- Superseded by the daemon relay production hardening pass below: conUD now owns bounded relay sync windows when configured.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- For user testing, run `docs/internet-relay-test.md` locally or over a reachable `ws://` relay.
- For product hardening, add a conUD-owned relay pump with reconnect/backoff, then stream-chunk routing and hosted relay auth/TLS strategy.

## Post Phase 15 Daemon Relay Production Hardening

Status: completed

Goal:

Move the relay message path beyond manual MVP sync by letting conUD own bounded relay send/receive windows while preserving payload opacity and adding daemon-level end-to-end smoke coverage.

Completed work:

- Created GitHub issue #36 and branch `codex/relay-daemon-production-hardening`.
- Added `relay_auto_sync = true` to new local config files.
- Added conUD runtime processing reports and a daemon relay pump that runs when a relay endpoint or trusted relay peer is configured.
- Added relay pump retry/backoff behavior so relay connection failures do not crash conUD or block local IPC forever.
- Kept relay pump logs metadata-only with `payload=not_observed` in runtime logs and encrypted-body-only relay delivery logs.
- Added `scripts/smoke-relay-daemon.ps1`, which starts a local relay, two isolated conUD runtimes, registers two agents, sends a peer-encrypted remote message without manual `conu relay sync`, waits for delivery, and scans conU-owned state for payload leaks.
- Hardened Windows daemon launching by routing `conu start` through a no-window background start path.
- Updated README, user guide, internet relay test, production readiness, SDK/MCP docs, release checklist, observability docs, repo memory, guardrails, repo map, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `docs/internet-relay-test.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/observability.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/state.rs`
- `crates/conud/src/main.rs`
- `scripts/smoke-relay-daemon.ps1`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery without manual sync.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu` passed and created `dist/conu-0.1.0-host.zip`.
- `git diff --check` passed.

Known gaps:

- Superseded by the reusable daemon relay-session pass below: conUD now keeps a relay WebSocket session alive across serve ticks when the endpoint is stable.
- Superseded by the `wss://` relay-client pass below: public `wss://` now has client support, while the plain relay server still needs hosted TLS termination in front of it.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, direct QUIC sockets, NAT traversal, signed remote agent-card exchange, capability policy, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- Run full validation, merge the daemon relay hardening branch, then choose between Phase 14 rooms/pub-sub or deeper hosted relay auth/TLS/session-policy work.

## Post Phase 15 Distribution And Hosting

Status: completed

Goal:

Make the user install and relay hosting story concrete without overstating the current public-network readiness.

Completed work:

- Created GitHub issue #38 and branch `codex/distribution-hosting-npm`.
- Added `docs/distribution-and-hosting.md` explaining how users install conU, how agents use it, how to self-host the current relay, and why Rust native binaries plus an npm launcher is the best first public distribution path.
- Added npm package template `packaging/npm/conu-cli` with launcher shims for `conu`, `conud`, `conu-relay`, and `conu-mcp`.
- Added npm postinstall downloader that selects the platform release asset, requires SHA-256 verification by default, supports local binary-dir testing, and keeps protocol behavior in Rust.
- Added Docker relay hosting template under `packaging/docker`.
- Updated release scripts to create platform-suffixed artifacts and matching `.sha256` files.
- Updated GitHub release workflow to build/upload `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` artifacts.
- Updated README, user guide, packaging docs, production readiness, release checklist, internet relay test, repo memory, repo map, implementation guardrails, and security checklist.
- Kept public-hosting guidance honest: the current client supported `ws://` at this point; managed public relay still required `wss://`, hosted auth/TLS policy, hosted quotas/monitoring, hosted session policy/resume, stream-chunk routing, offline mailbox, capability policy, signed remote cards, and OS-backed key storage.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/.npmignore`
- `packaging/npm/conu-cli/README.md`
- `packaging/npm/conu-cli/bin/conu.js`
- `packaging/npm/conu-cli/bin/conud.js`
- `packaging/npm/conu-cli/bin/conu-relay.js`
- `packaging/npm/conu-cli/bin/conu-mcp.js`
- `packaging/npm/conu-cli/lib/platform.js`
- `packaging/npm/conu-cli/lib/run.js`
- `packaging/npm/conu-cli/package.json`
- `packaging/npm/conu-cli/scripts/install.js`
- `.github/workflows/release.yml`
- `.gitignore`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `node --check packaging\npm\conu-cli\scripts\install.js`, `node --check packaging\npm\conu-cli\lib\platform.js`, and `node --check packaging\npm\conu-cli\lib\run.js` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `npm pack --dry-run` passed and confirmed the npm tarball includes only launcher/package files, not vendored binaries.
- npm installer local binary-dir smoke passed and launched `conu 0.1.0`.
- npm installer HTTP smoke passed against `dist/conu-0.1.0-windows-x64.zip`, verified the `.sha256`, extracted the archive, and launched `conu 0.1.0`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `dist/conu-0.1.0-windows-x64.zip.sha256`.
- Release archive listing confirmed `docs/distribution-and-hosting.md`, `packaging/docker/relay.Dockerfile`, and `packaging/npm/conu-cli/package.json` are included without conU state/log/security-key paths.
- `git diff --check` passed.
- Privacy scan reviewed payload/secret terms in docs, packaging, and agent memory; new matches are warnings, placeholder env examples, or metadata-only policy text.

Known gaps:

- `@imthegoodboy/conu` is the public npm launcher package; npm registry similarity policy blocks the bare `conu` package name even though the installed command is `conu`.
- GitHub Release assets must be attached before users can run `npm install -g @imthegoodboy/conu` successfully.
- Release artifacts are checksummed but not signed/notarized.
- The relay host path remains controlled self-hosting over reachable `ws://`, not a managed public relay network.
- Hosted relay auth/rate limits, hosted session policy/resume, stream-chunk routing, offline mailbox, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- Phase 14 rooms/pub-sub remains not started.

Next recommendation:

- Publish the first GitHub Release with platform artifacts/checksums, then publish `@imthegoodboy/conu`; after that, prioritize hosted relay auth/session policy before advertising a public managed relay.

## Post Phase 15 Relay Abuse Controls

Status: completed

Goal:

Reduce the self-hosted relay's production risk by adding basic in-process abuse controls while preserving relay blindness and payload-safe outputs.

Completed work:

- Added `RelayLimits` to `crates/conu-relay` with configurable total connection, per-IP connection, and per-session frame-rate caps.
- Enforced connection caps before WebSocket handshake processing so unauthenticated TCP sessions cannot grow without bound inside one relay process.
- Enforced per-session frame-rate checks before parsing frame contents, returning a generic `rate_limited` error without echoing arbitrary frame text.
- Changed relay client tracking to store session ids and avoid stale same-node disconnect cleanup removing a newer session mapping.
- Added relay CLI environment knobs: `CONU_RELAY_MAX_CONNECTIONS`, `CONU_RELAY_MAX_CONNECTIONS_PER_IP`, and `CONU_RELAY_MAX_FRAMES_PER_MINUTE`.
- Added a regression test confirming rate-limit errors stay metadata-only and do not echo payload-looking frame contents.
- Updated README, user install, hosting, Docker, production-readiness, release-checklist, repo memory, guardrails, gateway contract, and security checklist docs.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.

Known gaps:

- Relay abuse controls are local in-process caps, not hosted account quotas, distributed rate limits, abuse analytics, or adaptive banning.
- Relay authentication remains shared-token local/dev auth; public managed hosting still needs stronger auth, token rotation, TLS strategy, and operational policy.
- Superseded by the `wss://` relay-client pass below: the built-in client now supports certificate-valid `wss://`, while public deployments still need TLS termination in front of the plain relay server.
- Hosted session resume/policy, stream-chunk routing, offline mailbox delivery, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.

Next recommendation:

- Prioritize hosted relay auth/TLS and hosted session resume/policy before advertising conU as a public managed relay network.

## Post Phase 15 Reusable Daemon Relay Sessions

Status: completed

Goal:

Move conUD's relay path from repeated short WebSocket windows to a reusable daemon-owned relay session while preserving the manual one-shot sync command and relay payload opacity.

Completed work:

- Added `RelayRuntimePump` in `conu_core::relay_delivery` to hold a relay WebSocket client, endpoint, and session id across daemon ticks.
- Wired `RuntimeLease::serve_until_stop` to use the reusable relay pump while keeping `conu relay sync` and `conud --once` on the existing one-shot path.
- Reconnects now happen when the relay endpoint changes or the relay session fails; disabling relay auto-sync disconnects the reusable pump.
- Kept relay logs and runtime logs metadata-only and did not add relay session ids, tokens, or payload contents to log surfaces.
- Added a relay E2E regression test that opens a daemon-style relay pump, sends two peer-encrypted messages across ticks, and verifies the receiver kept the same relay session id.
- Updated README, user guide, SDK/MCP docs, production readiness, packaging notes, release checklist, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-relay/src/lib.rs`
- `plan.md`

Validation:

- Targeted relay/runtime tests passed during implementation: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` and `cargo +stable-x86_64-pc-windows-gnu test -p conu-core runtime::tests::process_once_keeps_relay_idle_without_relay_config`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.

Known gaps:

- The reusable daemon relay session is local runtime behavior; it is not hosted account/session resume, distributed session migration, or managed relay policy.
- Superseded by the `wss://` relay-client pass below: the built-in client now supports certificate-valid `wss://`, while public deployments still need TLS termination in front of the plain relay server.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.

Next recommendation:

- Prioritize hosted relay auth/session policy before advertising conU as a public managed relay network.

## Post Phase 15 Public Relay Token Guard

Status: completed

Goal:

Prevent accidental public exposure of the relay with the default local development token while keeping loopback development and local smoke tests simple.

Completed work:

- Added relay bind-address classification in `crates/conu-relay` to distinguish loopback binds from exposed binds.
- Kept `local-dev-token` valid for loopback binds such as `127.0.0.1`.
- Rejected non-loopback relay binds such as `0.0.0.0:8787` when the token is `local-dev-token`.
- Rejected non-loopback relay binds when the custom token is shorter than 24 characters.
- Kept relay auth errors generic and avoided echoing rejected token values.
- Updated `conu-relay --help`, internet relay test docs, user guide, Docker/package docs, production readiness, release checklist, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `plan.md`

Validation:

- Targeted relay validation passed during implementation: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- Stale unsafe-token scans passed: no public-bind docs/package examples still use `CONU_RELAY_TOKEN=replace-me` or `CONU_RELAY_TOKEN=replace-with-a-shared-test-token`; remaining `local-dev-token` references are loopback guidance.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.

Known gaps:

- This is a local configuration guard, not hosted account auth, token rotation, scoped credentials, mTLS, or signed relay sessions.
- Superseded by the `wss://` relay-client pass below: the built-in client now supports certificate-valid `wss://`, while public deployments still need TLS termination in front of the plain relay server.
- Relay-backed stream-chunk routing, offline mailbox delivery, hosted relay auth/TLS policy, hosted quotas/monitoring, hosted session resume/policy, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.

Next recommendation:

- Prioritize stronger hosted relay auth/session policy before advertising conU as a public managed relay network.

## Post Phase 15 WSS Relay Client Support

Status: completed

Goal:

Allow conUD and manual relay sync to connect to certificate-valid `wss://` relay endpoints while preserving local `ws://` development, relay payload opacity, and the existing plain `conu-relay` server deployment model.

Completed work:

- Added TLS-capable relay client streams in `conu_core::relay` while keeping the relay frame parser and WebSocket framing metadata-only.
- Extended relay endpoint parsing to accept `ws://` and `wss://`, with default ports `80` and `443` respectively.
- Added certificate-validated `wss://` connection support through platform TLS via `native-tls`.
- Pinned `native-tls` and Windows `schannel` versions so the repository's current `stable-x86_64-pc-windows-gnu` validation does not require missing `dlltool.exe` or `gcc.exe`.
- Updated relay delivery config validation and manual peer-card trust validation to accept `wss://` endpoints.
- Updated CLI peer-trust usage text to advertise `ws://host:port|wss://host/path`.
- Updated README, internet relay test, distribution/hosting, user guide, production readiness, release checklist, packaging docs, repo memory, guardrails, gateway contract, and security checklist.
- Kept the server-side `conu-relay` scope honest: it still listens as plain WebSocket; public `wss://` requires TLS termination in front of it.

Files changed:

- `Cargo.lock`
- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/trust.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted WSS tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay::tests::endpoint_parser`.
- Targeted relay config validation passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::relay_endpoint_validation_accepts_wss`.
- Targeted trust validation passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core trust::tests::manual_peer_card_accepts_wss_relay_endpoint`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Stale docs scan found no remaining live ws-only relay-client claims or live statements that TLS relay clients are still future work.
- `git diff --check` passed.

Known gaps:

- `wss://` support is client-side only. The bundled relay server still needs a reverse proxy or load balancer for TLS termination.
- Superseded by the scoped relay credential/session-policy pass below: static per-node relay credentials and idle/TTL policy now exist, while managed account auth, credential rotation/revocation, distributed quotas, hosted monitoring, and hosted session resume/accounting remain future work.
- Superseded by the relay stream-chunk pass below: relay-backed stream chunks now move as peer-encrypted envelopes, while remote room fanout, offline mailbox delivery, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- The Windows TLS dependency is pinned to preserve the current GNU validation path; revisit the pin when the project moves to a toolchain/CI path that can consume newer Windows TLS bindings without local binutils gaps.

Next recommendation:

- Continue with managed hosted relay account auth, credential rotation/revocation, session resume/accounting, stream-chunk routing, offline mailbox, and OS-backed key storage before advertising conU as a managed public relay network.

## Post Phase 15 Scoped Relay Credentials And Session Policy

Status: completed

Goal:

Move the current self-hosted relay beyond a single shared server token by adding static per-node credentials, configurable authenticated-session policy, token-safe comparisons, and payload-safe documentation while keeping the local shared-token path compatible.

Completed work:

- Added `RelayAuth`, `RelayCredential`, and redacted Debug output in `crates/conu-relay`.
- Kept `RelayConfig::new(bind, token)` for shared-token compatibility and added `RelayConfig::with_scoped_credentials`.
- Added token-safe authorization comparisons for shared and scoped relay credentials.
- Added `RelaySessionPolicy` with configurable idle timeout and max session TTL.
- Wired `conu-relay --serve` to read `CONU_RELAY_CREDENTIALS`, `CONU_RELAY_IDLE_TIMEOUT_SECONDS`, and `CONU_RELAY_SESSION_TTL_SECONDS`.
- Kept `CONU_RELAY_TOKEN` as the shared-token server mode and as the runtime client token env var.
- Preserved the loopback-only `local-dev-token` guard and applied the public-bind minimum token length to scoped credentials.
- Added regression tests for scoped credential authorization, public scoped dev-token rejection, redacted config/credential Debug output, and session TTL expiry without payload echo.
- Updated README, hosting docs, internet relay test docs, production readiness, release checklist, SDK/MCP docs, packaging docs, repo memory, implementation guardrails, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted scoped auth test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay scoped_credentials_accept_only_matching_node_token`.
- Targeted relay session TTL test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_session_ttl_expires_without_echoing_payloads`.
- Targeted redaction test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_config_debug_redacts_tokens`.
- Full relay crate tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Stale code/docs scans found no `config.auth_token` relay test references and no live docs still saying hosted relay auth/session policy is entirely future work.
- `git diff --check` passed.

Known gaps:

- Static scoped credentials are not managed hosted accounts, dynamic token issuance, token rotation, revocation, mTLS, or signed relay sessions.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.
- Hosted relay session resume/accounting, distributed quotas, hosted mailbox accounting/quotas, hosted monitoring, and adaptive abuse response remain future work.
- Superseded by the relay stream-chunk pass below: relay-backed stream chunks now move as peer-encrypted envelopes, while remote room fanout, offline mailbox delivery, direct QUIC, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- `wss://` support remains client-side; the bundled relay server still needs a reverse proxy or load balancer for TLS termination.

Next recommendation:

- Prioritize hosted relay account/credential lifecycle work, hosted session resume/accounting, offline mailbox delivery, and OS-backed key storage before public managed relay claims.

## Post Phase 15 Relay Stream-Chunk Delivery

Status: completed

Goal:

Move stream writes for trusted remote agents from metadata-only local counters to relay-backed peer-encrypted stream-chunk delivery while preserving payload opacity and honest public-hosting limits.

Completed work:

- Added relay envelope kind metadata for `message` and `stream_chunk`, including stream id validation for stream chunks and rejection of stream ids on normal message frames.
- Added relay outbox support for peer-encrypted stream chunks with stream-specific authenticated data and metadata-only `.relay` request files.
- Wired `conu streams write` so remote streams on relay routes queue peer-encrypted chunks to the trusted peer instead of only counting local bytes.
- Delivered inbound stream chunks as addressed inbox envelopes with `kind = "stream_chunk"`, `stream_id`, metadata-only receipts, encrypted-at-rest payload storage, and `delivered_relay_stream` status.
- Updated message inbox, receipt, and log metadata so stream chunks are visible by kind and stream id without displaying bytes.
- Added relay E2E coverage proving a stream chunk moves through a live relay between two isolated conU homes and arrives as an encrypted inbox envelope.
- Reduced relay frame enum size and constructor argument width so the workspace stays clippy-clean under `-D warnings`.
- Updated README, user/install docs, hosting docs, release checklist, SDK/MCP docs, security docs, packaging docs, repo memory, repo map, implementation guardrails, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay frame stream-kind test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay::tests::stream_chunk_frame_carries_stream_metadata_only`.
- Targeted stream inbox metadata test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core messages::tests::remote_stream_chunk_delivers_kind_and_stream_metadata`.
- Targeted stream outbox encryption test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core streams::tests::remote_stream_write_queues_peer_encrypted_chunk_without_payload`.
- Targeted relay request consistency test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::relay_request_rejects_type_kind_mismatch`.
- Targeted relay E2E stream test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_delivers_peer_encrypted_stream_chunk_between_two_state_homes`.
- Targeted relay metadata-forwarding regression passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_forwards_metadata_between_two_runtime_sessions`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and created `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- Stale docs scan found no remaining live outdated stream-route claims.
- `git diff --check` passed.

Known gaps:

- Relay stream chunks are point-in-time peer-encrypted envelopes, not full bidirectional direct stream sessions.
- Direct QUIC sockets, NAT traversal, and direct stream transport remain future work.
- Superseded by the offline and durable relay mailbox passes below: bounded offline relay mailbox delivery with optional durable ciphertext files now exists, while remote room fanout, hosted mailbox accounting, managed hosted relay accounts, credential rotation/revocation, hosted session resume/accounting, hosted quotas/monitoring, capability policy, signed remote agent-card exchange, and OS-backed key storage remain future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting, OS-backed key storage, and remote room fanout before public managed relay claims.

## Post Phase 15 Offline Relay Mailbox

Status: completed

Goal:

Let the self-hosted relay hold peer-encrypted message and stream-chunk envelopes for temporarily offline trusted nodes, without giving the relay plaintext payload access or claiming durable hosted mailbox behavior.

Completed work:

- Added `RelayMailboxPolicy` with configurable per-node envelope cap and envelope TTL.
- Added bounded in-memory relay mailbox queues keyed by target node id.
- Mailboxed peer-encrypted `message` and `stream_chunk` forwards when the target node is offline and the frame carries a ciphertext body.
- Drained queued envelopes immediately after the target node authenticates with `HELLO`.
- Preserved `UNDELIVERED reason=peer_offline` for metadata-only forwards and `UNDELIVERED reason=mailbox_full` when the bounded queue cannot accept another envelope.
- Added relay env vars `CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE` and `CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS`.
- Added regression coverage for offline mailbox delivery, per-node mailbox bounds, TTL expiry, and payload-safe errors.
- Updated README, user/install docs, hosting docs, production/readiness docs, release checklist, packaging docs, repo memory, implementation guardrails, agent gateway contract, and security checklist so public claims describe the in-memory limit honestly.

Files changed:

- `README.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted mailbox policy tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_offline_mailbox -- --nocapture`.
- Targeted offline E2E relay mailbox test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_mailboxes_peer_encrypted_message_until_receiver_connects -- --nocapture`.
- Full relay crate tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- Stale docs scan found no remaining live claims that offline mailbox delivery is unimplemented; older phase history still records earlier limitations.
- `git diff --check` passed.

Known gaps:

- Superseded by the durable relay mailbox pass below: `CONU_RELAY_MAILBOX_DIR` now persists queued peer-encrypted envelopes across relay restarts, while hosted mailbox accounting, managed retention policy, and session resume integration remain future work.
- Relay mailbox delivery is only for peer-encrypted relay envelopes; the relay still must not accept plaintext payloads.
- Remote room fanout, direct QUIC sockets, NAT traversal, capability policy, signed remote agent-card exchange, managed hosted accounts, credential rotation/revocation, hosted quotas/monitoring, and OS-backed key storage remain future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting, OS-backed key storage, and remote room fanout before public managed relay claims.

## Post Phase 15 Durable Relay Mailbox

Status: completed

Goal:

Make self-hosted relay offline mailbox delivery survive relay process restarts while preserving payload opacity and avoiding managed public-relay claims.

Completed work:

- Added `RelayMailboxStorage` with memory-only default behavior and optional file-backed storage.
- Added `CONU_RELAY_MAILBOX_DIR` to `conu-relay --serve` so operators can persist peer-encrypted mailbox envelopes on disk.
- Loaded valid persisted mailbox entries when a relay starts, pruned expired entries by mailbox TTL, and removed invalid or expired entries without echoing contents.
- Enforced the current per-node mailbox cap while loading persisted entries, removing excess stored envelope files without echoing contents.
- Persisted only rendered relay `ENVELOPE` metadata plus ciphertext body fields and `payload_displayed = false`; no plaintext payload fields are accepted or stored.
- Removed stored mailbox files after successful drain to the target node.
- Added a relay restart regression proving a peer-encrypted offline envelope survives relay restart, is delivered after the target authenticates, and does not store or output private payload text.
- Updated Docker relay image/template to create `/var/lib/conu-relay/mailbox`, default `CONU_RELAY_MAILBOX_DIR` inside the container, and document a persistent volume mount.
- Updated README, internet relay test docs, hosting docs, production readiness, release checklist, SDK/MCP docs, packaging docs, repo memory, implementation guardrails, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted durable relay restart test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_mailbox_survives_relay_restart_without_payloads -- --nocapture`.
- Targeted durable mailbox load-cap test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_mailbox_load_respects_current_cap_without_payloads -- --nocapture`.
- Targeted mailbox policy tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_offline_mailbox -- --nocapture`.
- Full relay crate tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.
- Docker image build was not run because Docker is not installed in this Windows environment.

Known gaps:

- Durable relay mailbox storage is self-hosted filesystem storage, not managed hosted mailbox accounting, quotas, or retention dashboards.
- Relay mailbox persistence still stores relay-visible metadata, public key material, and ciphertext; it must not be marketed as hiding metadata from the relay.
- Superseded by the Windows DPAPI secret wrapping pass below for local Windows private-key bytes; hosted relay account auth, credential rotation/revocation, hosted session resume/accounting, hosted quotas/monitoring, remote room fanout, direct QUIC sockets, NAT traversal, capability policy, signed remote agent-card exchange, and non-Windows OS-backed key storage remain future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting/quotas, non-Windows OS-backed key storage, and remote room fanout before public managed relay claims.

## Post Phase 15 Windows DPAPI Secret Wrapping

Status: completed

Goal:

Reduce local private-key exposure on supported Windows installs by wrapping conU-owned local signing, exchange, and storage secret bytes with the OS user secret backend while preserving older state compatibility and payload opacity.

Completed work:

- Added Windows current-user DPAPI wrapping for local Ed25519 signing secret bytes, X25519 exchange secret bytes, and XChaCha20Poly1305 storage key bytes.
- Kept migration-compatible reads for existing plaintext-hex key files and migrated those files to DPAPI-wrapped fields during `ensure_security_state`.
- Added security audit fields for `secretStorageBackend` and `secretsOsProtected` without exposing private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- Added regression coverage for new wrapped key files, plaintext-key migration, CLI audit redaction, and MCP audit redaction.
- Updated README, security hardening docs, production readiness docs, install guide, release checklist, SDK/MCP docs, distribution docs, repo memory, implementation guardrails, agent gateway contract, and security checklist.

Files changed:

- `Cargo.lock`
- `README.md`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `scripts/smoke-relay-daemon.ps1`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted security key creation test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::security_state_creates_key_material_without_plaintext_payloads -- --nocapture`.
- Targeted plaintext migration test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::existing_plaintext_secret_files_are_read_and_migrated_when_supported -- --nocapture`.
- Focused security module tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security -- --nocapture`.
- Focused CLI security audit test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security -- --nocapture`.
- Focused MCP audit redaction test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp security_audit_tool_reports_backend_without_secret_material -- --nocapture`.
- Manual isolated audit run confirmed `secretStorageBackend = "windows-dpapi-user"`, `secretsOsProtected = true`, wrapped key files contain `*_dpapi_hex`, and CLI JSON does not expose private key fields.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and recreated `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.

Known gaps:

- DPAPI support covers Windows current-user local secrets only; Linux/macOS still need platform keychain, Secure Enclave, HSM, or user-managed secret backend integration.
- Superseded by the storage-key rotation, storage-key retirement, and identity-key rotation passes below for local key lifecycle operations; hosted managed identity/key administration remains future work.
- Superseded by the relay credential storage pass below: runtime clients can now use `CONU_RELAY_TOKEN` or store a local relay credential, while managed hosted credential lifecycle and non-Windows keychain support remain future work.
- Hosted relay account auth, credential rotation/revocation, hosted session resume/accounting, hosted mailbox accounting/quotas, remote room fanout, direct QUIC sockets, NAT traversal, capability policy, and signed remote agent-card exchange remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, capability policy, signed remote agent-card exchange, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Relay Credential Storage

Status: completed

Goal:

Let runtime clients store a scoped relay token in conU local security state instead of relying only on process environment, while preserving token opacity across CLI, logs, tests, and docs.

Completed work:

- Added `security/relay-credential.key` to local state paths for an optional runtime relay client token.
- Added relay credential store/read/status/clear helpers that use the same secret-field backend as other security files: current-user DPAPI on Windows and owner-only local file fallback on non-Windows.
- Kept `CONU_RELAY_TOKEN` as the runtime override, then fall back to the stored credential, then `local-dev-token` for loopback tests.
- Added `conu relay credential set --stdin`, `status`, and `clear` with JSON/text output that reports configured/backend/protection status but never displays token material.
- Updated relay delivery so daemon and manual sync paths resolve tokens through environment, stored credential, then loopback default.
- Added regression tests for storage redaction, runtime token precedence, and CLI stdin/status behavior.
- Updated README, security hardening docs, install guide, hosting docs, production readiness, release checklist, SDK/MCP docs, repo memory, guardrails, repo map, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/security.rs`
- `crates/conu-core/src/state.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `scripts/smoke-identity-retirement.ps1`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay credential storage test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::relay_credential_storage_hides_token_and_reports_backend -- --nocapture`.
- Targeted relay token precedence test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::relay_token_prefers_env_then_stored_credential_without_echoing_secret -- --nocapture`.
- Focused CLI relay credential test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli relay_credential_cli_uses_stdin_and_never_prints_token -- --nocapture`.
- Focused security module tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security -- --nocapture`.
- Focused relay delivery tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery.
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Profile release -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed and recreated `dist/conu-0.1.0-windows-x64.zip` plus `.sha256`.
- `git diff --check` passed.
- Docker image build was not run because Docker is not installed in this Windows environment.

Known gaps:

- Stored relay client credentials are local runtime configuration, not managed hosted account auth, dynamic credential issuance, token rotation, revocation, or tenant accounting.
- Non-Windows stored relay credentials still use owner-only local files until platform keychain, Secure Enclave, HSM, or user-managed secret backend support lands.
- Hosted relay session resume/accounting, hosted mailbox accounting/quotas, remote room fanout, direct QUIC sockets, NAT traversal, capability policy, and signed remote agent-card exchange remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle, capability policy, signed remote agent-card exchange, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Signed Peer Cards

Status: completed

Goal:

Add cryptographic integrity checks to manual public peer-card exchange so cross-machine trust imports can detect modified node id, exchange key, display name, or relay endpoint fields without exposing private keys or payloads.

Completed work:

- Added Ed25519 signature fields to exported `PeerCard` values using the existing local node signing key.
- Added peer-card canonicalization and signature verification in `trust_peer_card`; tampered signed cards are rejected before trust storage.
- Stored public peer-card signature metadata in `trust.toml` and exposed payload-safe `peerCardSigned` status through CLI and MCP peer surfaces.
- Kept unsigned peer-card imports as legacy controlled-test compatibility while preferring signed cards in docs and examples.
- Added CLI flags for signed peer-card import: `--signing-key`, `--signature`, `--signature-key-id`, and optional `--signature-algorithm`.
- Updated Python SDK trust helper and MCP `conu_export_identity`/`conu_trust_peer` tool fields for signed peer-card exchange.
- Updated README, install guide, relay test guide, hosting docs, security hardening docs, SDK/MCP docs, production readiness, release checklist, repo memory, guardrails, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/trust.rs`
- `crates/conu-mcp/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted trust tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core trust -- --nocapture`.
- Targeted CLI peer test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli peers -- --nocapture`.
- Targeted MCP metadata test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp route_tools_return_metadata_only -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed signed peer-card trust plus daemon-owned relay delivery.

Known gaps:

- Signed peer cards are local/manual trust setup integrity, not a managed hosted account identity system, certificate transparency log, revocation service, or web-of-trust.
- Remote agent-card exchange over real sessions is still future work; current remote agents are still metadata mirrors or explicit local trust artifacts.
- Peer-scoped permission grants, hosted relay account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize signed remote agent-card exchange, peer-scoped permission policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Local Capability Enforcement

Status: completed

Goal:

Make agent capability booleans user-visible and enforce them in the core message, stream, and room routing paths without exposing payload contents.

Completed work:

- Added explicit `conu agents register` capability flags for `messages`, `streams`, `rooms`, `files`, and `presence`, preserving message/presence defaults.
- Enforced local recipient capabilities for inbound remote messages, stream chunks, and room event fanout.
- Enforced stream capability on local stream source/target agents, remote stream target metadata, and relay-backed stream chunk submission.
- Enforced room capability on room create, join, publish, and local room-event recipients.
- Updated the Python wrapper registration API to pass explicit capability booleans.
- Added regression coverage for stream source/target capability denial, relay stream sender denial, room create/join denial, inbound stream/room delivery denial, and CLI capability persistence.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening docs, production readiness, release checklist, repo memory, guardrails, agent gateway contract, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/messages.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted stream tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core streams`.
- Targeted room tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core rooms`.
- Targeted message tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core messages`.
- Targeted relay stream capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core relay_delivery::tests::remote_stream_chunk_requires_sender_stream_capability`.
- Targeted CLI capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli agents_register_persists_explicit_capabilities`.
- Targeted MCP room capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp room_tools_keep_publish_payload_safe`.
- Targeted relay stream E2E capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_delivers_peer_encrypted_stream_chunk_between_two_state_homes`.
- Targeted SDK room capability test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk sdk_room_flow_returns_metadata_only`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed and confirmed daemon-owned relay delivery after capability enforcement.
- `git diff --check` passed.

Known gaps:

- Capability enforcement is now backed by manual signed remote agent-card import for trusted peers; automatic live agent-card exchange and peer-scoped permission grants remain future work.
- Superseded by later passes below: relay-backed room fanout and room topic policy are now implemented. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize peer-scoped permission policy, automatic live agent-card exchange, managed hosted relay account/credential lifecycle, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Signed Remote Agent Cards

Status: completed

Goal:

Add a verified remote agent-card exchange path so remote agent capability metadata can be imported from a trusted peer's signed public agent card instead of relying only on placeholder mirrors.

Completed work:

- Added `SignedAgentCard` export and verification helpers in `conu_core::agents`.
- Added `trust_remote_agent_card` in `conu_core::sessions`, including signature verification, trusted-peer node/signing-key binding, cross-peer agent-id collision checks, and preservation of imported signed cards during session sync.
- Added `conu agents export` and `conu agents trust` CLI commands with JSON/text output that stays payload-safe.
- Exposed signed agent-card export/import through the Rust SDK, Python wrapper SDK, and MCP tools.
- Added regression coverage for signed-card export, import, session sync preservation, tamper rejection, trusted-peer signing-key mismatch rejection, CLI, SDK, and MCP paths.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening docs, production readiness, release checklist, repo memory, guardrails, agent gateway contract, Python SDK docs, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted core signed-card tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core signed`.
- Targeted CLI signed-card test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli signed_agent_card_cli_export_and_import_verifies_without_payloads`.
- Targeted SDK signed-card test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk signed_remote_agent_cards`.
- Targeted MCP signed-card test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp signed_agent_card_tools_export_and_trust_metadata_only`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Signed remote agent cards are manual public card exchange after peer trust; automatic live agent-card distribution over sessions remains future work.
- Superseded by the peer-scoped permission policy pass below: trusted peers now require explicit local policy grants before remote message, stream, or room surfaces are accepted.
- Superseded by later passes below: relay-backed room fanout and room topic policy are now implemented. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize automatic live agent-card exchange, remote room fanout/per-topic policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Peer-Scoped Permission Policy

Status: completed

Goal:

Add a local default-deny peer policy layer so trusting a peer establishes identity, while explicit metadata-only grants authorize messages, streams, rooms, files, and mailbox surfaces.

Completed work:

- Added `conu_core::policy` with `PeerPolicyRecord`, `PeerPolicyUpdate`, `PeerPermission`, `policy.toml` persistence, trusted-peer validation, default-deny effective policy reads, and payload-safe record rendering.
- Enforced peer policy on relay-backed outbound and inbound message envelopes, relay-backed stream chunks, remote stream opens/writes, and remote room participant visibility.
- Added `conu peers policy` CLI read/list/update flows with JSON/text output and updated help/next-command guidance.
- Exposed peer policy through the Rust SDK, Python wrapper SDK, and MCP `conu_set_peer_policy` tool.
- Updated relay E2E helpers and `scripts/smoke-relay-daemon.ps1` so relay flows grant scoped message/stream policy after peer-card trust.
- Updated README, architecture, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening, production readiness, release checklist, repo memory, guardrails, gateway contract, Python SDK docs, and the security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/policy.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `scripts/smoke-relay-daemon.ps1`
- `sdk/python/README.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/Pr/SKILL.MD`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted CLI peer-policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli peer_policy_cli_sets_scoped_grants_without_payloads`.
- Targeted SDK peer-policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk sdk_sets_peer_policy_metadata_only`.
- Targeted MCP peer-policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp peer_policy_tool_sets_scoped_grants_without_payloads`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed with explicit peer policy grants before remote delivery.
- `git diff --check` passed.

Known gaps:

- Peer policy is local file-backed policy, not hosted multi-tenant permission administration.
- File and mailbox policy bits are stored for forward compatibility; no active file-transfer or user-controlled remote mailbox surface is implemented yet.
- Superseded by the automatic signed agent-card exchange pass below: session sync now exchanges signed public agent cards over peer-encrypted relay control envelopes for signed trusted peers with policy grants.
- Superseded by later passes below: relay-backed room fanout and room topic policy are now implemented. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize remote room fanout/per-topic policy, managed hosted relay account/credential lifecycle, direct transport, and non-Windows keychain support before public managed relay claims.

## Post Phase 15 Automatic Signed Agent-Card Exchange

Status: completed

Goal:

Remove the manual signed-agent-card exchange requirement for normal trusted relay sessions by sending signed local agent cards as encrypted control-plane relay envelopes during session sync.

Completed work:

- Added metadata render/parse helpers for signed agent cards in `conu_core::agents`.
- Added `agent_card` relay envelope kind and a ciphertext-only relay frame path for signed-card control envelopes.
- Added session-sync queuing of signed local agent cards for signed trusted peers that have at least one peer policy grant.
- Added inbound automatic card import in relay delivery, using the existing signature verification, trusted-node binding, signing-key match, and cross-peer collision checks before replacing placeholder remote-agent records.
- Kept relay-visible data to node ids, agent ids, envelope ids, byte counts, public exchange key material, and ciphertext.
- Added core and relay E2E coverage proving encrypted card queuing and two-node automatic signed-card import.
- Updated the relay daemon smoke to trust signed peer cards and keep the explicit peer policy grant step.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening, production readiness, release checklist, repo memory, guardrails, gateway contract, Python SDK docs, and security checklist.

Files changed:

- `README.md`
- `crates/conu-core/src/agents.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/sessions.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `scripts/smoke-relay-daemon.ps1`
- `sdk/python/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted core automatic-card queue test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core session_sync_queues_signed_agent_cards_without_payloads`.
- Targeted relay automatic-card E2E test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_exchanges_signed_agent_cards_during_session_sync`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed with signed peer-card trust, explicit peer policy grants, daemon relay delivery, and payload leak checks.
- `git diff --check` passed.

Known gaps:

- Automatic signed-card exchange requires signed peer-card trust, at least one local peer policy grant, and a relay route/pump; manual signed-card import remains the fallback for daemonless or unsigned controlled tests.
- The relay control envelope is still relay-routed, not direct QUIC.
- Superseded by the remote room fanout and room topic policy passes below: relay-backed room events now fan out to joined trusted remote agents, and configured topics require explicit publish/subscribe grants. Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, multi-tenant hosted permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle next, then direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Relay-Backed Room Event Fanout

Status: completed

Goal:

Move room publishes for joined trusted remote participants from metadata-only representation to relay-backed peer-encrypted event delivery while preserving payload opacity and default-deny room policy.

Completed work:

- Added a `room_event` relay envelope kind and ciphertext-only relay frame constructor.
- Added peer-encrypted remote room event outbox queuing with room event packets that keep room id, topic, event id, and event bytes inside the encrypted body rather than relay-visible frame metadata.
- Added room publish fanout to joined trusted remote participants when remote signed agent metadata advertises `rooms=true` and peer policy grants `rooms=true`.
- Added inbound relay room event delivery to the addressed local agent inbox as encrypted-at-rest `kind = "event"` envelopes, with payload-safe room event metadata recorded locally after delivery.
- Kept room publish responses metadata-only while reporting both local and remote delivery counts.
- Added core relay-outbox privacy coverage and relay E2E coverage for two-node peer-encrypted room event delivery.
- Updated the relay daemon smoke setup to grant room policy and register room-capable smoke agents.
- Updated README, install guide, relay test guide, hosting docs, SDK/MCP docs, security hardening, production readiness, release checklist, repo memory, guardrails, gateway contract, repo map, and security checklist.

Files changed:

- `README.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay frame privacy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core room_event_frame_carries_ciphertext_only`.
- Targeted core remote-room outbox privacy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core room_publish_queues_remote_relay_events_without_payloads`.
- Targeted relay room E2E test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_delivers_peer_encrypted_room_event_between_two_state_homes`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed with signed peer-card trust, explicit peer policy grants including rooms, daemon relay delivery, and payload leak checks.
- `git diff --check` passed.

Known gaps:

- Superseded by the room topic policy pass below: configured room/topic pairs now require explicit publish/subscribe grants; unconfigured topics retain the room membership boundary for compatibility. Hosted multi-tenant room permission administration remains future work.
- Relay room events are point-in-time peer-encrypted envelopes, not direct QUIC room sessions.
- Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle next, then hosted accounting, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Room Topic Policy

Status: completed

Goal:

Add metadata-only per-topic room publish/subscribe authorization across local room publishes, local fanout, relay fanout, and inbound relay room-event delivery without exposing payload bytes.

Completed work:

- Added `rooms/policy.toml` state path support and a metadata-only `RoomTopicPolicyRecord` with room id, agent id, topic, publish/subscribe booleans, timestamps, and `payload_displayed = false`.
- Added `RoomTopicPolicyUpdate`, list/read/set core APIs, and `conu rooms policy` text/JSON CLI surfaces.
- Added Rust SDK, Python SDK, and MCP room topic policy methods/tools.
- Enforced configured topic policy on local publish, local subscriber fanout, remote subscriber fanout, and inbound relay room-event delivery.
- Preserved compatibility for unconfigured topics: room membership remains the subscription boundary until any policy record exists for that exact room/topic.
- Added local core tests for allowed subscriber fanout, denied publisher behavior, and inbound relay publish denial.
- Added CLI, SDK, MCP, and relay E2E coverage proving metadata-only topic grants and relay denial without leaking room-event payloads.
- Updated README, install guide, relay test guide, SDK/MCP docs, security hardening, production readiness, release checklist, architecture, repo memory, guardrails, gateway contract, repo map, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-core/src/rooms.rs`
- `crates/conu-core/src/state.rs`
- `crates/conu-mcp/src/lib.rs`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-sdk/src/lib.rs`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `sdk/python/conu_sdk/__init__.py`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted core room topic policy tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core room_topic_policy -- --nocapture`.
- Targeted CLI room policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli rooms_policy_cli_sets_topic_grants_without_payloads -- --nocapture`.
- Targeted SDK room topic policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-sdk sdk_room_topic_policy_controls_publish_and_subscribe -- --nocapture`.
- Targeted MCP room topic policy test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-mcp room_topic_policy_tool_sets_grants_without_payloads -- --nocapture`.
- Targeted relay room topic denial test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_rejects_room_event_when_inbound_topic_policy_denies_sender -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Unconfigured room topics intentionally keep the existing membership boundary for compatibility; strict default-deny for every new topic would need an explicit room-level strict-mode migration.
- Room topic policy is local file-backed administration only, not hosted multi-tenant permission management.
- Relay room events are still point-in-time peer-encrypted envelopes, not direct QUIC room sessions.
- Hosted account/credential lifecycle, hosted accounting, direct QUIC sockets, NAT traversal, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay account/credential lifecycle and hosted accounting next, then direct QUIC/NAT traversal, hosted multi-tenant permission administration, non-Windows keychain support, and optional strict room topic default-deny mode.

## Post Phase 15 Relay Credential Manifest Lifecycle

Status: completed

Goal:

Move self-hosted relay credential lifecycle beyond raw static server tokens by adding a token-safe manifest with per-node hashed credentials, revocation, and expiry metadata while preserving the existing relay protocol and local compatibility paths.

Completed work:

- Added hashed scoped relay credentials through `RelayCredential::from_sha256_hex`, with token-safe constant-time hash comparisons and redacted Debug output.
- Added `RelayCredentialStatus` with `active` and `revoked` lifecycle states, plus optional `expires_at_unix` denial for expired credentials.
- Added `CONU_RELAY_CREDENTIALS_FILE` support in `conu-relay --serve`; the file path overrides `CONU_RELAY_CREDENTIALS`, which still overrides shared `CONU_RELAY_TOKEN`.
- Added a versioned `[[credential]]` manifest parser that accepts `node_id`, `token_sha256_hex`, `token_length`, `status`, optional `expires_at_unix`, and token/payload display guards.
- Added `conu-relay --hash-token`, which reads a token from stdin and prints only `token_sha256_hex`, `token_length`, and `token_displayed = false`.
- Extended the public-bind guard to hashed credentials by rejecting the `local-dev-token` hash and token length metadata under 24 characters for non-loopback binds.
- Added relay tests for hashed credential acceptance, manifest revocation/expiry, public-bind rejection without hash echo, and manifest display-guard validation.
- Updated relay hosting, Docker, npm, install, production-readiness, release-checklist, architecture, repo memory, guardrail, gateway-contract, and security-checklist docs to describe the manifest as self-hosted lifecycle hardening rather than managed hosted account auth.

Files changed:

- `Cargo.lock`
- `README.md`
- `architecture.md`
- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay credential tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay credential -- --nocapture`.
- Focused relay check passed: `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --hash-token` with stdin passed and printed only hash/length/display metadata.
- `git diff --check` passed.

Known gaps:

- This is self-hosted static manifest lifecycle, not managed hosted account auth, tenant identity, or online credential issuance.
- Superseded by the live credential manifest reload pass below: manifest revocation/expiry now affects new `HELLO` authentications without relay restart; no admin API, audit log, hosted account auth, or hosted credential issuance service exists yet.
- Token hashes reduce raw server-side token storage but remain brute-forceable if operators choose weak tokens; public binds still require custom tokens with at least 24 characters.
- Hosted relay quotas/accounting, hosted mailbox accounting, hosted session resume/accounting, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize hosted relay accounting/quotas and session accounting next, then direct QUIC/NAT traversal, hosted multi-tenant permission administration, non-Windows keychain support, and managed hosted account APIs.

## Post Phase 15 Relay Accounting And Quotas

Status: completed

Goal:

Add payload-safe self-hosted relay accounting and per-node quota enforcement so operators can track usage and cap abuse without inspecting message, stream, room-event, or signed-card payloads.

Completed work:

- Added `RelayAccountingPolicy` with a configurable accounting window plus optional per-node sent-envelope and sent-byte quotas.
- Added `RelayAccountingStorage` with optional file-backed accounting under `CONU_RELAY_ACCOUNTING_DIR`.
- Added metadata-only per-node accounting records with authenticated session counts, sent/received envelope counts, byte counters, mailbox counters, `payload_displayed = false`, and `token_displayed = false`.
- Wired the relay hub to record authenticated sessions, accepted online forwards, accepted mailbox forwards, receiver counters, and persisted accounting files without storing tokens, token hashes, payload text, ciphertext bodies, or frame bodies.
- Added quota denial before forwarding; over-quota sends return `UNDELIVERED reason=quota_exceeded` without echoing payload or token material.
- Added env knobs: `CONU_RELAY_ACCOUNTING_DIR`, `CONU_RELAY_ACCOUNTING_WINDOW_SECONDS`, `CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE`, and `CONU_RELAY_MAX_BYTES_SENT_PER_NODE`.
- Updated Docker defaults to create and persist `/var/lib/conu-relay/accounting`.
- Updated README, hosting docs, install guide, Docker/npm docs, production-readiness, release checklist, architecture, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Targeted relay accounting tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay accounting -- --nocapture`.
- Focused relay check passed: `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets`.
- Focused relay clippy passed: `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is self-hosted relay accounting, not hosted billing, tenant management, distributed dashboards, adaptive abuse response, or a managed account service.
- Accounting files contain metadata counters and node ids; operators should treat them as usage metadata, not payload-private from the relay operator.
- Quotas apply per relay process/accounting file window and do not yet coordinate across a horizontally scaled relay fleet.
- Superseded by the relay session resume semantics pass below for same-process same-node reconnects; distributed hosted session state, distributed hosted accounting dashboards, managed hosted mailbox retention policy, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize direct QUIC/NAT traversal or managed hosted account APIs next, then distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Relay Session Resume Semantics

Status: completed

Goal:

Add payload-safe relay session resume semantics for same-process daemon reconnects without turning self-hosted relay state into a managed hosted session service.

Completed work:

- Extended the relay frame contract so `HELLO` can carry an optional `resume=<session-id>` hint and `WELCOME` reports `resumed=<true|false>`, while legacy `WELCOME` frames still parse as `resumed = false`.
- Added relay-side same-node validation for resume hints. A resume id is accepted only when it belongs to the authenticated node and the node does not already have an active client; cross-node or stale active-session attempts get a new session id instead.
- Updated `RelayRuntimePump` to remember the prior session id only for the same endpoint after disconnects and to redact active/resume session ids from Debug output.
- Added `sessions_resumed` to metadata-only relay accounting files with backward-compatible reads for older accounting files.
- Added protocol, relay, accounting, and daemon pump regression coverage for resume round trips, cross-node resume rejection, resumed-session accounting, and Debug redaction.
- Updated README, hosting docs, production readiness, release checklist, SDK/MCP boundaries, install guide, packaging docs, architecture, repo memory, guardrails, gateway contract, and security checklist.

Files changed:

- `README.md`
- `architecture.md`
- `crates/conu-core/src/relay.rs`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused core resume tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core resume -- --nocapture`.
- Focused relay resume tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay resume -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Resume hints are same-process and same-endpoint only; conUD does not persist relay session ids across daemon restarts.
- Session ids are relay metadata visible on the wire to the relay process. They are not stored in relay accounting files and Debug/runtime log surfaces should not display them.
- This is not distributed hosted session migration, multi-region relay state, hosted billing/accounting, managed account auth, online credential issuance APIs, adaptive abuse response, or hosted tenant administration.
- Direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize direct QUIC/NAT traversal or managed hosted relay account/credential lifecycle next, then distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Live Relay Credential Manifest Reload

Status: completed

Goal:

Reduce self-hosted relay credential lifecycle downtime by applying hashed manifest revocation and expiry to new relay sessions without restarting `conu-relay`, while keeping token and payload material out of logs, errors, docs, and relay storage.

Completed work:

- Added a live-reloaded `RelayAuth::ScopedCredentialsFile` mode that stores only the manifest path and bind address in relay config.
- Added `RelayConfig::with_scoped_credentials_file`, which validates the initial manifest at startup and then reloads the manifest on each new `HELLO` authentication attempt.
- Kept `CONU_RELAY_CREDENTIALS_FILE` precedence over `CONU_RELAY_CREDENTIALS` and shared `CONU_RELAY_TOKEN`, but changed the environment path to use the live-reloaded file mode.
- Added fail-closed behavior for missing, unreadable, invalid, duplicate-node, revoked, expired, weak public-bind, or malformed live manifest updates. Existing authenticated sessions remain governed by idle timeout and max TTL.
- Added credential manifest regression coverage for revoking a token without relay restart, fail-closed invalid manifest updates, and token/hash redaction in responses and Debug output.
- Updated README, hosting docs, internet test docs, production readiness, release checklist, user guide, SDK/MCP boundaries, packaging docs, repo memory, implementation guardrails, gateway contract, security checklist, and repo map.

Files changed:

- `README.md`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused credential tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay credential -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is live self-hosted manifest reload, not managed hosted account auth, tenant lifecycle, online credential issuance APIs, hosted audit logs, hosted revocation workflows, or a hosted admin service.
- Manifest updates should use atomic replacement. Invalid or missing manifests fail closed for new sessions until a valid manifest is restored.
- Existing authenticated sessions are not forcibly disconnected by manifest edits; configure idle timeout and max TTL for revocation latency bounds.
- Direct QUIC/NAT traversal, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize direct QUIC/NAT traversal or managed hosted account/credential issuance APIs next, then hosted audit/admin controls, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.

## Post Phase 15 Direct Route Selection Guard

Status: completed

Goal:

Keep the production route manager honest by preventing configured direct QUIC metadata from becoming a selected delivery route before a real direct data plane exists.

Completed work:

- Changed route sync so valid configured `quic://` and `udp://` endpoints are still recorded and NAT-scored, but remain `unavailable` with `direct_quic_transport_inactive`.
- Kept relay selected for trusted-peer delivery when direct transport is inactive, preserving relay-backed remote stream chunk delivery instead of opening streams on an unusable direct route label.
- Added CLI route text output for failure reasons so users can see why a direct candidate was not selected without inspecting payloads.
- Updated route, stream, and CLI tests for inactive direct candidates, relay selection, payload-safe probe history, and relay-backed remote stream chunks.
- Updated README, direct-route docs, production readiness, user guide, SDK/MCP docs, release checklist, and future-agent guardrails to describe direct candidates as inactive metadata until real QUIC/NAT transport lands.

Files changed:

- `crates/conu-core/src/routes.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused route tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core routes -- --nocapture`.
- Focused remote stream test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core streams::tests::remote_stream_write_queues_peer_encrypted_chunk_without_payload -- --nocapture`.
- Focused CLI route tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli routes_sync -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed after formatting.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is a selection guard, not direct QUIC implementation. Real QUIC sockets, peer authentication over direct transport, ICE-style candidate exchange, STUN/TURN, NAT hole punching, and direct stream byte routing remain future work.
- Direct endpoint probes remain metadata-only route records; they do not validate that a QUIC peer is reachable or authenticated.
- Relay remains the only active remote data-plane path for peer-encrypted one-shot messages, stream chunks, room events, and signed-card control envelopes.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Implement a real authenticated direct QUIC/NAT traversal data plane before allowing direct routes to become selected, or prioritize managed hosted account/credential issuance APIs if hosted relay readiness is more urgent.

## Post Phase 15 Payload-Safe Log Rotation

Status: completed

Goal:

Add a production maintenance path for long-running local deployments to rotate conU metadata logs without reading, printing, classifying, uploading, or otherwise exposing log contents.

Completed work:

- Added `conu_core::observability` with `LogRotationPolicy`, `LogRotationReport`, and `rotate_logs`, rotating active `.log` files by byte threshold while keeping a bounded number of `.log.N` archives.
- Added `conu logs rotate [--max-bytes <bytes>] [--keep <count>] [--json]` with payload-safe text/JSON reports containing only log filenames, byte sizes, rotated booleans, archive-removal counts, and `contentsDisplayed=false`.
- Updated `conu doctor` log scanning to include rotated `.log.N` archives, so rotation cannot hide a payload leak from the readiness scanner.
- Added core and CLI regression coverage for archive bounds, no-content reporting, and doctor detection of payload text in rotated archives.
- Updated README, observability docs, production readiness, release checklist, user guide, repo memory, repo map, builder guardrails, and security checklist.

Files changed:

- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/observability.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/observability.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused observability tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core observability -- --nocapture`.
- Focused CLI log tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli logs -- --nocapture`.
- Focused doctor tests passed during the CLI log test and full workspace test, including rotated archive scanning.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is local file rotation only, not a structured telemetry exporter, hosted log pipeline, retention dashboard, or alerting system.
- Rotation uses local active `.log` files in `CONU_HOME`; relay-host operating-system log management remains the host operator's responsibility.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted multi-tenant permission administration, real direct QUIC/NAT traversal, managed hosted identity/key administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize structured telemetry with field allowlists, managed hosted account/credential issuance APIs, or direct QUIC/NAT traversal next, depending on whether local release hardening or hosted-relay readiness is more urgent.

## Post Phase 15 Storage-Key Rotation Migration

Status: completed

Summary:

- Added `security/storage-keys/` as the archived local storage-key ring.
- Added multi-key storage payload reads so encrypted-at-rest local payload files can remain readable after active storage-key rotation.
- Added `conu security rotate storage --confirm [--json]` to archive the old storage key, create a new active storage key, and re-encrypt conU-owned encrypted-at-rest message queue and inbox payload files.
- Kept rotation output payload-safe: only key ids, file counts, archive counts, and `contentsDisplayed=false`; no key bytes, DPAPI blobs, plaintext payloads, or decrypted payloads.
- Updated security, release, user, and future-agent docs to move storage-key migration tooling from a blocker to an implemented local hardening control.

Files changed:

- `crates/conu-core/src/state.rs`
- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused storage rotation tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_rotation_reencrypts_local_payload_files`.
- Focused archived old-key read test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_archive_keeps_old_payloads_readable_after_rotation`.
- Focused older archived-key migration retry test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_rotation_migrates_older_archived_key_payloads`.
- Focused CLI storage rotation test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_rotate_storage_requires_confirmation_and_hides_payloads`.
- Focused security suites passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security -- --nocapture` and `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Storage-key rotation currently migrates local encrypted-at-rest message queue and inbox files. Relay durable mailbox ciphertext is peer-encrypted and intentionally not re-encrypted by local storage-key rotation.
- Superseded by the storage-key retirement pass below: unused archived storage keys can now be deleted after local queue/inbox dependency scanning.
- Superseded by the identity-key rotation pass below: local signing/exchange keys can be rotated with explicit peer-card refresh requirements.
- Non-Windows local secret storage still needs platform keychain, Secure Enclave, HSM, or a user-managed secret backend before high-security public release claims.

Next recommendation:

- Prioritize structured telemetry with payload-safe field allowlists, managed hosted account/credential issuance APIs, or direct QUIC/NAT traversal.

## Post Phase 15 Storage-Key Retirement

Status: completed

Summary:

- Added `conu security retire storage --confirm [--json]` to remove archived storage keys only when no scanned local encrypted-at-rest message queue or inbox payload still references them.
- Added core retirement reporting for archived keys scanned, retired keys, retained keys, scanned files, dependent files, and `contentsDisplayed=false`.
- Kept dependent archived keys readable and retained when local queue/inbox payload metadata still references them.
- Updated security, release, user, and future-agent docs to move old storage-key retirement from a known gap to an implemented local hardening control.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused unused-archive retirement test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_retirement_removes_unused_archives_after_migration`.
- Focused dependent-archive retention test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::storage_key_retirement_retains_archives_with_dependencies`.
- Focused CLI retirement test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_retire_storage_requires_confirmation_and_hides_payloads`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Retirement scans conU-owned local message queue and inbox payload metadata only; relay durable mailbox ciphertext is peer-encrypted and intentionally outside local storage-key retirement.
- Superseded by the identity-key rotation pass below: local signing/exchange keys can be rotated with explicit peer-card refresh requirements.
- Non-Windows local secret storage still needs platform keychain, Secure Enclave, HSM, or a user-managed secret backend before high-security public release claims.

Next recommendation:

- Prioritize managed hosted account/credential issuance APIs, hosted telemetry/dashboard pipelines, or direct QUIC/NAT traversal.

## Post Phase 15 Structured Telemetry Snapshot

Status: completed

Summary:

- Added `conu telemetry snapshot [--json]` for local structured telemetry with schema `conu.telemetry.snapshot.v1`.
- Added `TELEMETRY_FIELD_ALLOWLIST` in `conu_core::observability` and wired CLI output to report only allowlisted aggregate counters.
- Telemetry covers local state readiness, runtime health, local/remote agent counts, sessions, streams, rooms, selected routes, relay queue counts, log scan counts, and security readiness booleans.
- Kept telemetry payload-safe: no node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, private keys, shared secrets, auth tokens, plaintext payloads, decrypted payloads, or ciphertext bodies.
- Updated docs and future-agent memory to move local structured telemetry from a known gap to an implemented local hardening control while leaving hosted telemetry pipelines/dashboards as future work.

Files changed:

- `crates/conu-core/src/observability.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `architecture.md`
- `docs/observability.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused telemetry CLI tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli telemetry_snapshot -- --nocapture`.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Telemetry is local CLI snapshot output only; there is no hosted telemetry collector, OTLP exporter, retention policy engine, alerting, or distributed dashboard.
- The log privacy scan remains a guardrail for known forbidden terms, not a substitute for code review or a comprehensive DLP engine.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted multi-tenant permission administration, direct transport, managed hosted identity/key administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted account APIs, online credential issuance/rotation workflows beyond the offline helper, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, managed hosted identity/key administration, or non-Windows keychain support.

## Post Phase 15 Offline Relay Credential Issuance

Status: completed

Summary:

- Added `conu-relay --issue-credential <node-id> --token-out <path> [--expires-at-unix <seconds>] [--json]` for offline scoped relay credential issuance.
- Added `IssuedRelayCredential`, token generation, manifest-entry rendering, and token-file writing in `conu-relay`.
- Kept the secret split explicit: the raw generated token is written only to a new token file, while stdout reports only node id, token path, token length, optional expiry, display guards, and the hashed manifest entry.
- Kept manifest compatibility with the live-reloaded `CONU_RELAY_CREDENTIALS_FILE` parser, including `token_sha256_hex`, `token_length`, `status`, optional `expires_at_unix`, `payload_displayed = false`, and `token_displayed = false`.
- Updated relay hosting, Docker, internet test, security, production-readiness, release-checklist, architecture, and future-agent docs to describe offline issuance as self-hosted lifecycle hardening, not managed hosted account auth.

Files changed:

- `crates/conu-relay/Cargo.toml`
- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `architecture.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused issuance tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay issued_relay -- --nocapture`.
- Command smoke passed: `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --issue-credential node.issue --token-out <temp> --json`; the token file was non-empty and stdout did not contain the raw token.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is offline self-hosted credential issuance, not hosted account auth, online issuance APIs, tenant lifecycle, hosted audit logs, online token rotation, or a hosted admin service.
- Issued token files are explicit local secret artifacts; operators still need secure delivery and lifecycle practices outside conU.
- Managed hosted account auth, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, managed hosted identity/key administration, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted account APIs, online credential rotation/revocation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, managed hosted identity/key administration, or non-Windows keychain support.

## Post Phase 15 Relay Credential Manifest Operations

Status: completed

Summary:

- Added helper-driven self-hosted relay credential manifest updates through `upsert_issued_relay_credential_in_file` and `revoke_relay_credential_in_file`.
- Extended `conu-relay --issue-credential` with `--credentials-file` and `--replace` so operators can create, append, or rotate hashed manifest entries without hand-editing.
- Added `conu-relay --revoke-credential <node-id> --credentials-file <path>` to mark a scoped credential revoked without displaying raw tokens, token hashes, payloads, or manifest contents.
- Preserved the existing live-reload manifest shape while parsing and rendering `created_at_unix` / `updated_at_unix` metadata and enforcing token/payload display guards.
- Updated relay hosting, Docker, internet test, security, production-readiness, release-checklist, SDK/MCP, and future-agent docs to prefer helper-driven manifest lifecycle operations for self-hosted relays.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused manifest reload/revoke tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay credential_manifest -- --nocapture`.
- Focused issuance/upsert tests passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay issued_relay_credential -- --nocapture`.
- Relay credential lifecycle command smoke passed: `conu-relay --issue-credential node.smoke --token-out <temp> --credentials-file <temp> --json`, duplicate issue without `--replace`, then `conu-relay --revoke-credential node.smoke --credentials-file <temp> --json`; stdout and manifest did not contain the raw token, duplicate issue did not create a token file, and the manifest ended revoked.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- This is self-hosted offline manifest lifecycle tooling, not managed hosted account auth, tenant identity, online issuance APIs, hosted audit logs, hosted revocation workflows, or a hosted admin service.
- Issued token files are still explicit local secret artifacts; operators remain responsible for secure delivery to the intended node.
- Managed hosted account auth, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, managed hosted identity/key administration, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted account APIs, online credential issuance/rotation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, managed hosted identity/key administration, or non-Windows keychain support.

## Post Phase 15 Identity-Key Rotation

Status: completed

Summary:

- Added `conu security rotate identity --confirm-peer-refresh [--json]` for explicit local Ed25519 signing-key and X25519 exchange-key rotation.
- Archived the previous signing and exchange private keys under `security/identity-keys/` using the same secret-field backend as active key files: current-user DPAPI on Windows and owner-only secret files on non-Windows.
- Generated fresh active signing/exchange key material and reported old/new key ids, archive counts, peer-card refresh requirements, signed-agent-card refresh requirements, and `contentsDisplayed=false`.
- Kept archived exchange keys available for decrypting peer envelopes addressed to the previous public exchange key during the peer-card refresh window.
- Updated the key-rotation plan and public docs so local identity-key rotation is implemented while hosted managed identity/key administration and non-Windows keychain integration remain future work.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused identity-key rotation core test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core identity_key_rotation_archives_old_exchange_key_without_secret_output -- --nocapture`.
- Focused identity-key rotation CLI test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_rotate_identity_requires_peer_refresh_and_hides_keys -- --nocapture`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- Manual isolated identity rotation smoke passed: initialized a fresh `CONU_HOME`, ran `conu security rotate identity --confirm-peer-refresh --json`, verified no secret/DPAPI/private/plaintext markers in output, and verified `conu identity export --json` produced new public signing and exchange material.
- `git diff --check` passed.

Known gaps:

- Peer-card refresh distribution is explicit and local through `conu identity export`; there is no hosted managed key-publication, revocation, or account administration service.
- Superseded by the identity archive-retirement pass below: archived identity keys can now be removed after operators confirm peer-card refresh is complete.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize non-Windows OS-backed secret storage, managed hosted account/key administration, or real direct QUIC/NAT traversal depending on the next release target.

## Post Phase 15 Identity Archive Retirement

Status: completed

Summary:

- Added `conu security retire identity --confirm-peer-refresh-complete [--json]` for explicitly deleting archived old identity signing/exchange keys after refreshed public peer cards have been redistributed.
- Added `IdentityKeyRetirementReport` with archive counts, peer-card refresh confirmation, old-key decrypt compatibility status, and `contentsDisplayed=false`.
- Kept the command payload-safe: it reports counts and booleans only, and does not print private keys, DPAPI blobs, shared secrets, plaintext payloads, or decrypted payloads.
- Preserved the active signing/exchange keys while deleting archived old identity keys from `security/identity-keys/`; after retirement, peer envelopes encrypted to the old exchange public key no longer decrypt locally.
- Updated README, security hardening docs, production readiness docs, release checklist, user guide, repo memory, guardrails, repo map, and security checklist.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-cli/src/lib.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- Focused identity archive-retirement core test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-core identity_key_retirement_removes_archives_after_refresh_confirmation -- --nocapture`.
- Focused identity archive-retirement CLI test passed: `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli security_retire_identity_requires_refresh_confirmation_and_hides_keys -- --nocapture`.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check` passed in `packaging/npm/conu-cli`.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Peer-card refresh distribution is still explicit and local through `conu identity export`; there is no hosted managed key-publication, revocation, or account administration service.
- Identity archive retirement intentionally removes old-key decrypt compatibility for envelopes addressed to old exchange public keys; operators must run it only after refresh is complete.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize non-Windows OS-backed secret storage, managed hosted identity/key administration, or real direct QUIC/NAT traversal depending on the next release target.

## Post Phase 15 TypeScript SDK Wrapper

Status: completed

Summary:

- Added `sdk/typescript`, a dependency-free Node 18+ TypeScript/JavaScript wrapper package named `@conu/sdk` around installed `conu` and `conud` binaries.
- Added typed wrappers for status, security audit, identity/storage rotation and retirement, agent registration/presence/cards, peer trust/policy, route sync/listing, local and remote messages, relay sync/credential status/set/clear, streams, rooms, room topic policy, telemetry snapshot, log rotation, and queued processing.
- Kept payload-bearing helpers on stdin-only command paths for message, remote message, stream write, room publish, and relay credential set. The smoke test asserts private payload/token bytes are passed as process input and are not present in argv.
- Added a local TypeScript example that registers two agents, sends opaque bytes, processes queued work, and prints metadata only with `contentsDisplayed=false`.
- Updated public docs, release checklists, security docs, repo memory, guardrails, and SDK/MCP docs so TypeScript is no longer described as future work.
- Aligned the TypeScript and Python signed-agent-card helper default signature algorithm with the current core/CLI `Ed25519` contract.

Files changed:

- `sdk/typescript/package.json`
- `sdk/typescript/src/index.js`
- `sdk/typescript/src/index.d.ts`
- `sdk/typescript/test/smoke.mjs`
- `sdk/typescript/README.md`
- `examples/typescript/local_agent_pair.mjs`
- `sdk/python/conu_sdk/__init__.py`
- `README.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/security-hardening.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-local.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-identity-retirement.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed.
- `git diff --check` passed.

Known gaps:

- Superseded by the post-Phase-15 TypeScript explicit receive helper pass below; JavaScript agents now have `receiveMessageBytes()` for addressed local inbox bytes.
- The TypeScript package wraps local installed binaries; it is not a browser-native SDK, hosted API client, or direct protocol implementation.
- Package publishing is not done in this pass; release publication still depends on signed/package release decisions and matching version management.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Superseded by the later TypeScript explicit receive helper pass; after that, prioritize managed hosted relay/account work, browser-native protocol support, or package publication.

## Post Phase 15 GitHub CI Package Validation

Status: completed

Summary:

- Added a dedicated GitHub Actions package-validation job that installs Node 20 and runs the TypeScript SDK package check plus the npm native launcher package check on every push and pull request.
- Kept Python wrapper compile coverage in the existing Rust OS matrix.
- Stabilized durable relay mailbox reload ordering by persisting a nanosecond enqueue sequence and using it when applying current mailbox caps, preserving FIFO behavior even when several envelopes share the same millisecond timestamp.
- Fixed relay sync wait handling so one-shot sync continues polling through the caller's bounded wait instead of returning on the first empty read timeout.
- Updated production-readiness docs, release checklist, repo memory, and implementation guardrails so package checks are part of the expected CI gate rather than only local release practice.

Files changed:

- `.github/workflows/ci.yml`
- `crates/conu-core/src/relay_delivery.rs`
- `crates/conu-relay/src/lib.rs`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay --lib relay_file_backed_mailbox_load_respects_current_cap_without_payloads` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay --lib relay_delivers_peer_encrypted_message_between_two_state_homes` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `git diff --check` passed locally.

Known gaps:

- The CI package job validates syntax and package install logic only; it does not publish `@conu/sdk` or `@conu/cli`.
- GitHub Release asset publication, npm publication, signed installers, managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Open a PR for package CI validation and let GitHub prove the new job, then prioritize managed hosted relay/account work after the TypeScript receive-helper pass below.

## Post Phase 15 TypeScript Explicit Receive Helper

Status: completed

Summary:

- Added `mcpBin` support to the dependency-free TypeScript/JavaScript SDK wrapper so it can call installed `conu-mcp` for explicit MCP tool paths.
- Added `receiveMessage(agentId, envelopeId, { includePayload })` for addressed-agent receive metadata and `receiveMessageBytes(agentId, envelopeId)` for explicit raw inbox bytes.
- Kept normal inbox/list/send/status helpers metadata-only; payload bytes are returned only through the explicit receive helper and only after the MCP `conu_receive_message` path verifies the envelope belongs to the addressed local agent.
- Updated the TypeScript smoke test, local TypeScript example, public docs, security docs, release checklist, repo memory, and gateway contract to remove the previous TypeScript receive-helper gap.

Files changed:

- `sdk/typescript/src/index.js`
- `sdk/typescript/src/index.d.ts`
- `sdk/typescript/test/smoke.mjs`
- `sdk/typescript/README.md`
- `examples/typescript/local_agent_pair.mjs`
- `README.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.

Known gaps:

- TypeScript still wraps local installed binaries and `conu-mcp`; it is not a browser-native SDK, hosted API client, or direct protocol implementation.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, signed package publishing, and non-Windows keychain support remain future work.

Next recommendation:

- Prioritize managed hosted relay/account work, npm/release publication, browser-native protocol support, or non-Windows OS-backed key storage depending on the next release target.

## Post Phase 15 Release Publishing Workflow

Status: completed

Summary:

- Added `scripts/verify-release-artifacts.py` to validate release archives and checksum files before upload.
- The verifier checks required binaries, `manifest.toml`, `payload_contents_included = false`, matching SHA-256 files, and rejects common local-state or payload-bearing paths such as `.conu`, `security/`, `messages/`, `runtime/`, `logs/`, `routes/`, `node_modules/`, `target/`, and vendored npm binaries.
- Hardened `.github/workflows/release.yml` with a package-check job, npm dry-runs for `@conu/cli` and `@conu/sdk`, archive verification on every platform build, automatic GitHub Release asset upload for `v*` tags, and optional npm publication with provenance when `NPM_TOKEN` is configured.
- Updated distribution, packaging, release checklist, production readiness, repo memory, and security guardrails so release publication is no longer a manual-only path.

Files changed:

- `.github/workflows/release.yml`
- `scripts/verify-release-artifacts.py`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.
- `npm pack --dry-run --json` passed locally in `packaging/npm/conu-cli`.
- `python -m py_compile scripts/verify-release-artifacts.py` passed locally.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())"` passed locally.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed locally.
- `python scripts\verify-release-artifacts.py dist` passed locally against the generated Windows archive.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.

Known gaps:

- Platform code signing/notarization is not implemented; current release trust is CI-built archives, SHA-256 checksums, GitHub Release assets, and npm provenance when `NPM_TOKEN` is configured.
- npm publication still requires maintainers to configure the repository `NPM_TOKEN` secret before a tagged release that should publish packages.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support remain future work.

Next recommendation:

- Add platform code signing/notarization or prioritize managed hosted relay/account work depending on the next public release target.

## Post Phase 15 Non-Windows User-Managed Secret Wrapping

Status: completed

Summary:

- Added a non-Windows `user-managed-wrap-key-v1` secret backend selected by `CONU_SECRET_WRAP_KEY_HEX` or `CONU_SECRET_WRAP_KEY_FILE`.
- The backend wraps local signing, exchange, storage, archived key, and stored relay credential secret fields with XChaCha20Poly1305 and per-secret AAD while keeping the wrap key external to conU-owned state.
- Security-state ensure now migrates older plaintext-hex key files and stored relay credential files to encrypted `*_wrapped_hex` fields when the wrap key is configured.
- `conu security audit` and relay credential status continue to report backend/protection metadata only; no key bytes, tokens, wrapped blobs, plaintext payloads, or decrypted payloads are printed.
- Updated security, production readiness, install, release, repo memory, and security guardrail docs to distinguish this encrypted fallback from native macOS Keychain/Linux Secret Service/HSM support.

Files changed:

- `crates/conu-core/src/security.rs`
- `README.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `docs/distribution-and-hosting.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core security::tests::relay_credential_storage_hides_token_and_reports_backend` passed locally during implementation.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-core --all-targets -- -D warnings` passed locally during implementation.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py scripts\verify-release-artifacts.py` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- Isolated `CONU_HOME` smoke passed locally: `conu init` then `conu security audit --json` reported backend/protection metadata and `contentsDisplayed=false` without key bytes or token material.
- `git diff --check` passed locally.
- Default `cargo check --workspace --all-targets` was attempted and failed locally because the MSVC linker `link.exe` is not installed on this machine; the repo guardrails already require the GNU toolchain in this environment.

Known gaps:

- Native non-Windows OS keychain, Secure Enclave, HSM, or hosted key administration is not implemented; the new fallback requires operators to provide and protect the wrap key outside conU.
- Losing the external wrap key makes user-managed wrapped local secret files unreadable until restored from the operator's secret store.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and platform code signing remain future work.

Next recommendation:

- Add native macOS Keychain/Linux Secret Service or HSM-backed storage when choosing a platform-specific hardening track, or move to managed hosted relay/account work.

## Post Phase 15 Release Artifact Attestation Hardening

Status: completed

Summary:

- Added GitHub artifact attestation generation to the release build matrix for platform archives and matching `.sha256` files.
- Added a second verifier pass in the GitHub Release publication job after build artifacts are downloaded and before release upload.
- Strengthened `scripts/verify-release-artifacts.py` so every archive must include the required Windows, Linux, macOS, Docker, and npm packaging templates in addition to binaries, checksums, and `manifest.toml`.
- Updated release, distribution, packaging, production-readiness, repo memory, and guardrail docs with artifact attestation verification guidance and the stronger release trust boundary.

Files changed:

- `.github/workflows/release.yml`
- `scripts/verify-release-artifacts.py`
- `README.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed locally.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())"` passed locally.
- Synthetic release verifier positive/negative cases passed locally, including rejection when a required packaging template was missing.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed locally.
- `python scripts\verify-release-artifacts.py dist` passed locally against the generated Windows release archive.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.
- `npm pack --dry-run --json` passed locally in `packaging/npm/conu-cli`.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.

Known gaps:

- Platform-native code signing and notarization are still not implemented; artifact attestations improve provenance but do not replace OS trust prompts or signed installers.
- npm publication still requires maintainers to configure the repository `NPM_TOKEN` secret before a tagged release that should publish packages.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, hosted telemetry/dashboards, direct transport, hosted multi-tenant permission administration, and native non-Windows keychain support remain future work.

Next recommendation:

- Add platform code signing/notarization when release certificates are available, or prioritize managed hosted relay/account work for public network readiness.

## Post Phase 15 TypeScript Browser Boundary Hardening

Status: completed

Summary:

- Added a browser-conditioned `@conu/sdk` export that fails closed with `browserSupport.supported = false` and `BrowserUnsupportedError` instead of bundling the Node local-binary wrapper into browser apps.
- Added an explicit `@conu/sdk/browser` subpath for browser-boundary detection without accepting private keys, relay tokens, endpoint secrets, payload bytes, or account credentials.
- Updated the TypeScript package description, README, smoke test, and package check so the Node wrapper and browser boundary are validated together.
- Added `docs/browser-native-typescript.md` to document future browser-native protocol requirements around hosted auth, browser key handling, payload opacity, explicit receive semantics, and package naming.
- Updated SDK/MCP, install guide, production readiness, release checklist, repo memory, and security guardrails to distinguish the Node wrapper from future browser-native support.

Files changed:

- `sdk/typescript/package.json`
- `sdk/typescript/src/browser.js`
- `sdk/typescript/src/browser.d.ts`
- `sdk/typescript/test/smoke.mjs`
- `sdk/typescript/README.md`
- `docs/browser-native-typescript.md`
- `docs/sdk-and-mcp.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `docs/release-checklist.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `npm run check --prefix sdk/typescript` passed locally.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py scripts\verify-release-artifacts.py` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.

Known gaps:

- This is a browser-boundary hardening pass, not browser-native protocol transport.
- Browser-native support still requires hosted account auth, short-lived scoped browser credentials, reviewed browser key handling, and `wss://` or direct transport semantics that preserve peer trust and policy checks.
- Managed hosted account auth, online credential issuance APIs, distributed hosted session/accounting state, direct transport, hosted multi-tenant permission administration, native non-Windows keychain support, and platform code signing remain future work.

Next recommendation:

- Prioritize managed hosted relay/account auth before implementing a real browser-native TypeScript protocol package, or move to direct transport if relay independence is more urgent.

## Post Phase 15 Native Non-Windows Secret Storage

Status: completed

Summary:

- Added native macOS user Keychain support for the shared conU secret-field backend through the target-gated `keyring` crate.
- Added Linux Secret Service support through `secret-tool` when a user Secret Service session is available.
- Kept Windows on current-user DPAPI and kept the non-Windows user-managed XChaCha20Poly1305 wrap-key fallback for systems without native secret storage.
- Added native OS-secret reference fields that store only references and plaintext lengths in conU files; key bytes, relay tokens, protected blobs, plaintext payloads, and decrypted payloads stay out of files and CLI output.
- Added migration coverage for plaintext local signing, exchange, storage, and relay credential files into native OS-secret references with an in-memory native-store test backend for macOS/Linux CI.
- Added `docs/native-secret-storage.md` with backend selection, migration rules, and macOS/Linux smoke commands.

Files changed:

- `crates/conu-core/src/security.rs`
- `crates/conu-core/Cargo.toml`
- `Cargo.lock`
- `docs/native-secret-storage.md`
- `docs/security-hardening.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/user-install-and-agent-guide.md`
- `docs/distribution-and-hosting.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py scripts\verify-release-artifacts.py` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-core --target x86_64-apple-darwin --tests` passed locally, validating the target-gated macOS Keychain/keyring compile path.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-core --target x86_64-unknown-linux-gnu --tests` was attempted locally but blocked by the existing OpenSSL cross-compilation sysroot/pkg-config requirement on Windows; the GitHub Ubuntu job should validate this path natively.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.

Known gaps:

- Linux native Secret Service requires `secret-tool` and a user Secret Service session. Headless systems without that service use the user-managed wrap-key fallback or owner-only file fallback.
- Existing `user-managed-wrap-key-v1` files can migrate to native macOS/Linux storage only when the operator still provides the wrap key needed to decrypt the existing wrapped field.
- Secure Enclave, HSM, hosted managed key administration, managed hosted account auth, online credential issuance APIs, distributed hosted state/accounting, direct transport, hosted multi-tenant permission administration, and platform package-manager signing remain future work.

Next recommendation:

- Prioritize managed hosted relay/account auth and online credential issuance before public hosted relay claims, or move to direct transport if relay independence is more urgent.

## Post Phase 15 Platform Signing And Notarization

Status: completed

Summary:

- Added tagged-release signing gates for Windows Authenticode and macOS Developer ID signing/notarization while preserving unsigned manual `workflow_dispatch` and local smoke builds when signing secrets are absent.
- Added Windows release-script support for decoding a maintainer PFX from repository secrets, signing each `.exe` with SHA-256 Authenticode and timestamping, verifying signatures, then generating the release ZIP/checksum.
- Added macOS release-script support for Developer ID signing with hardened runtime/timestamps, notarizing ZIP distribution archives through `notarytool`, and switching macOS npm release assets from `.tar.gz` to `.zip`.
- Kept Linux release policy explicit: SHA-256 checksum files plus GitHub artifact attestations until detached/distro package signatures are introduced.
- Updated npm asset resolution, release verifier ZIP handling, release workflow secret wiring, release notes, release checklist, distribution docs, repo memory, and security guardrails without adding any payload or local-state inspection.

Files changed:

- `.github/workflows/release.yml`
- `scripts/build-release.ps1`
- `scripts/build-release.sh`
- `scripts/verify-release-artifacts.py`
- `packaging/npm/conu-cli/lib/platform.js`
- `docs/platform-code-signing.md`
- `docs/release-checklist.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/npm/conu-cli/README.md`
- `README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `python -m py_compile scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed locally.
- `python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())"` passed locally.
- `npm run check --prefix packaging/npm/conu-cli` passed locally.
- `npm run check --prefix sdk/typescript` passed locally.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu -PackageSuffix windows-x64` passed locally and produced an unsigned manual platform ZIP/checksum with the expected manifest signing booleans.
- `powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu` passed locally and produced an unsigned manual host ZIP/checksum.
- `python scripts\verify-release-artifacts.py dist` passed locally against both generated Windows archives.
- `node -e "Object.defineProperty(process, 'platform', { value: 'darwin' }); Object.defineProperty(process, 'arch', { value: 'arm64' }); const p = require('./packaging/npm/conu-cli/lib/platform'); if (p.assetName('0.1.0') !== 'conu-0.1.0-macos-arm64.zip') { throw new Error(p.assetName('0.1.0')); } console.log(p.assetName('0.1.0'));"` passed locally.
- `bash -n scripts/build-release.sh` passed locally.
- `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally.
- `npm pack --dry-run --json` passed locally in `packaging/npm/conu-cli`.
- `npm pack --dry-run --json` passed locally in `sdk/typescript`.

Known gaps:

- Actual release signing still requires maintainers to configure the repository signing secrets before creating a `v*` tag.
- Linux detached signatures and distro/package-manager signatures are documented as the next packaging layer, not implemented in this pass.
- One-click OS installers, package-manager publishing, auto-update, managed hosted account auth, online credential issuance APIs, distributed hosted state/accounting, direct transport, hosted multi-tenant permission administration, and hosted managed key administration remain future work.

Next recommendation:

- Configure the Windows and macOS signing secrets before the next tagged release, then prioritize managed hosted relay account auth or authenticated direct QUIC/NAT transport.

## Post Phase 15 Authenticated Direct QUIC/NAT Transport

Status: completed

Completed work:

- Added authenticated direct QUIC listener/client support for reachable trusted peer endpoints.
- Added peer-encrypted direct probe, message, and stream-chunk frames that authenticate with existing trusted peer-card exchange keys.
- Updated route sync so direct is selected only after a live authenticated QUIC probe succeeds; failed probes record `direct_quic_probe_failed` and keep relay selected.
- Preserved relay fallback for direct message and stream-chunk send failures without weakening local capability or peer policy checks.
- Added signed peer-card direct endpoint support and legacy signed-card compatibility when no direct endpoint is claimed.
- Exposed direct endpoint fields through CLI identity/trust/peer output, MCP, Python SDK, and TypeScript SDK wrapper options.
- Updated direct transport, route, production readiness, SDK/MCP, user guide, release checklist, README, repo memory, and guardrail docs.

Files changed:

- `Cargo.lock`
- `crates/conu-core/Cargo.toml`
- `crates/conu-core/src/lib.rs`
- `crates/conu-core/src/direct_transport.rs`
- `crates/conu-core/src/routes.rs`
- `crates/conu-core/src/runtime.rs`
- `crates/conu-core/src/streams.rs`
- `crates/conu-core/src/trust.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `sdk/python/conu_sdk/__init__.py`
- `sdk/typescript/src/index.js`
- `sdk/typescript/src/index.d.ts`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/hosted-relay-account-auth.md`
- `docs/release-checklist.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all` and `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli` passed locally after the final CLI fallback cleanup.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `git diff --check` passed locally.

Known gaps:

- Direct QUIC requires a reachable configured UDP endpoint. ICE-style candidate gathering, STUN/TURN, UDP hole punching, and hosted direct-candidate rendezvous remain future work.
- The local Windows GNU validation path needs `w64devkit` on `PATH` and `rust-lld` as the linker because Quinn/ring native build scripts require a C compiler.
- Direct stream chunks are point-in-time encrypted envelopes, not long-lived application stream sessions with end-to-end flow negotiation yet.

Next recommendation:

- Run full workspace validation and CI, then continue with distributed hosted session/accounting state, hosted dashboards/abuse workflows, hosted tenant administration, or managed direct NAT traversal.

## Post Phase 15 Distributed Relay State/Accounting Foundation

Status: completed

Completed work:

- Added `RelaySessionStorage` with memory-only and file-backed modes.
- Added `CONU_RELAY_SESSION_STATE_DIR` for metadata-only per-node session records across relay restarts.
- Kept cross-node resume attempts on the new-session path and preserved relay accounting files without session ids.
- Updated relay hosting, production readiness, internet test, package, Docker, repo memory, and guardrail docs to distinguish single-writer file-backed state from hosted distributed migration/dashboards.
- Added restart coverage proving file-backed session state can resume the same node without storing tokens, token hashes, payload text, ciphertext bodies, or private keys.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `architecture.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/user-install-and-agent-guide.md`
- `docs/sdk-and-mcp.md`
- `docs/hosted-relay-account-auth.md`
- `docs/release-checklist.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/docker/relay.Dockerfile`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_file_backed_session_state_survives_restart_without_payloads` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay relay_resumes_same_node_session_and_accounts_metadata_only` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.
- `git diff --check` passed locally.

Known gaps:

- File-backed relay session state is a single-writer storage boundary, not a distributed lock service or multi-region migration layer.
- Hosted dashboards, abuse response, tenant lifecycle, managed permission administration, and managed direct NAT traversal remain future work.
- Default Windows MSVC validation still requires `link.exe`; local Windows validation uses the GNU toolchain path.

Next recommendation:

- Run full workspace validation and CI, then merge this branch for issue #64 before starting managed direct NAT traversal or hosted tenant administration.

## Post Phase 15 Managed Direct NAT Rendezvous Foundation

Status: completed

Completed work:

- Added static direct candidate metadata to route records and probes: `candidate_source`, `candidate_kind`, and `rendezvous_state`.
- Added `nat_traversal_unavailable` reporting so route sync distinguishes reachable configured endpoints, failed static probes, missing traversal support, relay-only profiles, and relay fallback.
- Kept direct selection gated on live authenticated QUIC probes and preserved relay fallback for failed, missing, invalid, or disabled direct routes.
- Sanitized invalid direct endpoints as `quic://invalid` and derived route ids from sanitized display endpoints instead of rejected endpoint strings.
- Exposed candidate metadata and NAT-unavailable counts through CLI route JSON/text output and MCP route tools.
- Updated direct transport, production readiness, user guide, SDK/MCP, release checklist, repo memory, and future-agent guardrails to describe the supported static candidate boundary and unsupported ICE/STUN/TURN behavior.

Files changed:

- `crates/conu-core/src/routes.rs`
- `crates/conu-cli/src/lib.rs`
- `crates/conu-mcp/src/lib.rs`
- `README.md`
- `docs/direct-transport-and-routes.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all` and `cargo fmt --all -- --check` passed locally.
- `git diff --check` passed locally.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core routes::tests` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-cli routes_sync` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.

Known gaps:

- This is static host-candidate metadata and honest NAT-unavailable reporting, not ICE-style candidate gathering, STUN/TURN negotiation, UDP hole punching, or hosted direct-candidate rendezvous.
- Direct QUIC still requires a reachable configured UDP endpoint and a trusted peer-card key for the authenticated probe.
- Distributed hosted dashboards/accounting, hosted tenant administration, distributed multi-instance session migration, and managed hosted identity/key administration remain future work.

Next recommendation:

- Open the PR for issue #65, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 Hosted Tenant Admin Foundation

Status: completed

Completed work:

- Added a metadata-only hosted tenant registry file for `conu-relay` with tenant account status, hosted node status, hosted permission booleans, optional public signing/exchange key ids, timestamps, and display guards.
- Added `conu-relay --tenant-upsert`, `--tenant-revoke`, `--tenant-node-upsert`, `--tenant-node-revoke`, and `--tenant-audit` for single-writer tenant lifecycle administration without raw tokens, token hashes, private keys, payloads, ciphertext bodies, or manifest contents in output.
- Added optional `CONU_RELAY_TENANTS_FILE` relay configuration. When configured with `CONU_RELAY_ADMIN_TOKEN` and `CONU_RELAY_CREDENTIALS_FILE`, online issue/rotate and new runtime `HELLO` sessions fail closed when tenant or node metadata is missing or revoked.
- Kept hosted tenant permissions as operator-side metadata only. Local conUD peer policy, agent capabilities, room topic policy, trust, and peer encryption remain the delivery authority.
- Kept admin credential revoke available after tenant/node revocation so operators can clean up credential metadata.
- Updated hosted relay docs, hosting docs, production readiness, release checklist, user guide, SDK/MCP notes, repo memory, and future-agent guardrails for the tenant registry boundary.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/internet-relay-test.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-repo-steward/references/repo-map.md`
- `plan.md`

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed locally with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay tenant_ -- --nocapture` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed locally with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed locally with the same GNU environment.
- `npm run check --prefix sdk\typescript` passed locally.
- `npm run check --prefix packaging\npm\conu-cli` passed locally.
- `python -m py_compile sdk\python\conu_sdk\__init__.py` passed locally.
- `git diff --check` passed locally.
- Tenant CLI smoke passed locally for `--tenant-upsert`, `--tenant-node-upsert`, and `--tenant-audit`, with JSON output reporting `tokenDisplayed=false`, `keyMaterialDisplayed=false`, `payloadDisplayed=false`, and `contentsDisplayed=false`.

Known gaps:

- The hosted tenant registry is a single-writer file-backed foundation, not a distributed tenant lifecycle, dashboard, RBAC, billing, or abuse workflow service.
- Hosted key administration stores only public key ids; no hosted private-key custody, HSM, Secure Enclave, or managed key rotation service exists.
- Existing authenticated sessions are still bounded by relay idle timeout and max TTL; tenant revocation gates new `HELLO` sessions and admin issue/rotate.
- Distributed hosted dashboards/accounting, hosted mailbox retention workflows, distributed multi-instance migration, ICE/STUN/TURN managed traversal, and full hosted identity/key administration remain future work.

Next recommendation:

- Open the PR for issue #66, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 - Hosted Relay Dashboard Snapshot

Status: completed

Goal:

Give hosted or self-hosted relay operators a single payload-safe snapshot command that summarizes credential, tenant, accounting, and abuse stores without exposing relay secrets, payload material, ciphertext bodies, or session ids.

Completed work:

- Created GitHub issue #72 for the dashboard snapshot slice.
- Added public `RelayAccountingAudit` and `audit_relay_accounting_dir` support so relay accounting files can be summarized without exposing tokens, token hashes, session ids, payloads, ciphertext bodies, or private key material.
- Added `conu-relay --hosted-dashboard` with optional `--credentials-file`, `--tenants-file`, `--accounting-dir`, `--abuse-dir`, `--account`, `--node`, and `--json` flags.
- Kept dashboard output aggregate-only: credential counts, tenant/node counts, accounting counters, abuse counters, configured paths, optional filters, and false display guards.
- Added renderer/parser privacy coverage and accounting audit coverage.
- Updated hosted relay docs, distribution/hosting docs, production readiness, release checklist, user guide, SDK/MCP notes, packaging docs, repo memory, architecture notes, and future-agent guardrails.

Files changed:

- `crates/conu-relay/src/lib.rs`
- `crates/conu-relay/src/main.rs`
- `README.md`
- `architecture.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_dashboard -- --nocapture` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay accounting_audit -- --nocapture` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU environment.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --hosted-dashboard --credentials-file <temp>\credentials.toml --tenants-file <temp>\tenants.toml --accounting-dir <temp>\accounting --abuse-dir <temp>\abuse --account account.prod --node node.hosted --json` passed and returned `tokenDisplayed=false`, `tokenHashDisplayed=false`, `sessionIdDisplayed=false`, `ciphertextDisplayed=false`, and `contentsDisplayed=false`.
- `git diff --check` passed.

Known gaps:

- The hosted dashboard snapshot is single-relay and file-backed. It is not distributed dashboard storage, a hosted UI, RBAC, alert routing, tenant suspension, billing, or adaptive abuse response.
- Accounting, abuse, tenant, and credential stores are still single-writer local files; distributed hosted accounting, tenant lifecycle, and multi-instance session migration remain future work.
- Hosted key administration still stores only public key ids; no hosted private-key custody, HSM, Secure Enclave, or managed key rotation service exists.
- Managed direct NAT traversal still needs ICE/STUN/TURN-style candidate gathering, hosted direct-candidate rendezvous, and UDP hole punching beyond the current static direct candidate metadata.

Next recommendation:

- Open the PR for issue #72, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 - Hosted Abuse Threshold Report

Status: completed

Goal:

Give hosted/self-hosted relay operators a payload-safe threshold report that compares relay abuse counters against explicit operator maximums without adding adaptive enforcement or distributed alerting.

Completed work:

- Created GitHub issue #92 for the hosted abuse threshold report slice.
- Added local `conu-relay --abuse-threshold-report --abuse-dir <path> [--node <node-id>] --max-<metric> <count>... [--json]` for `CONU_RELAY_ABUSE_DIR` counters.
- Added admin-gated `conu-relay --admin-abuse-threshold-report --relay <endpoint> --admin-token-stdin [--account <account-id>] [--node <node-id>] --max-<metric> <count>... [--json]`, reusing the existing dashboard admin request and dashboard scope.
- Supported threshold maximums for admin unauthorized, admin failed, unauthorized sessions, credential denied sessions, tenant denied sessions, rate limited sessions, session expired, quota denied forwards, undelivered forwards, mailbox rejected forwards, and malformed client frames.
- Rendered text/JSON reports with `ok` or `threshold_exceeded` status, checked/exceeded counts, count/max/exceeded metadata per metric, source/relay/path/filter metadata, and false display guards.
- Added parser, threshold, and renderer privacy tests for local and admin report forms.
- Updated hosted relay docs, distribution/hosting docs, production readiness, release checklist, SDK/MCP notes, user guide, packaging docs, repo memory, and future-agent guardrails.

Files changed:

- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay abuse_threshold -- --nocapture` passed with the same GNU environment.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help | Select-String -Pattern 'abuse-threshold|admin-abuse-threshold|threshold-report'` passed.
- `target\debug\conu-relay.exe --abuse-threshold-report --abuse-dir <temp> --max-admin-unauthorized 0 --json` passed and returned `status="ok"`, `thresholdChecks=1`, `thresholdExceeded=0`, and false display guards.

Known gaps:

- The threshold reports are single-relay reporting workflows over existing metadata counters. They do not implement distributed hosted dashboards, alert routing, adaptive enforcement, tenant-wide workflow automation, or billing.
- Admin threshold reports require dashboard admin scope and inherit the current account-scoped dashboard behavior where global accounting and abuse counters are suppressed without a node filter.
- Abuse, accounting, tenant, and credential stores are still single-writer relay-local storage.

Next recommendation:

- Open the PR for issue #92, wait for CI, merge if green, and preserve both local and remote feature branches.

## Post Phase 15 - Abuse Threshold Fail-On-Threshold Mode

Status: completed

Goal:

Make local and admin-gated hosted abuse threshold reports scriptable for CI, cron, and operator monitoring without adding adaptive enforcement or distributed alerting.

Completed work:

- Created GitHub issue #94 for the fail-on-threshold report slice.
- Added optional `--fail-on-threshold` to `conu-relay --abuse-threshold-report`.
- Added optional `--fail-on-threshold` to `conu-relay --admin-abuse-threshold-report`.
- Preserved normal stdout report rendering and default success exit behavior.
- Added exit code 3 only when `--fail-on-threshold` is set and one or more configured thresholds are exceeded.
- Kept admin threshold reports behind `--admin-token-stdin` and the existing dashboard admin scope.
- Added parser and report-exit tests for local and admin threshold forms.
- Updated hosted relay docs, distribution/hosting docs, production readiness, release checklist, user guide, SDK/MCP notes, packaging docs, repo memory, and future-agent security/build guardrails.

Files changed:

- `crates/conu-relay/src/main.rs`
- `README.md`
- `docs/hosted-relay-account-auth.md`
- `docs/distribution-and-hosting.md`
- `docs/production-readiness.md`
- `docs/release-checklist.md`
- `docs/sdk-and-mcp.md`
- `docs/security-hardening.md`
- `docs/user-install-and-agent-guide.md`
- `packaging/README.md`
- `packaging/docker/README.md`
- `packaging/npm/conu-cli/README.md`
- `.agents/repo/ABOUT.md`
- `.agents/skills/conu-builder/references/agent-gateway-contract.md`
- `.agents/skills/conu-builder/references/implementation-guardrails.md`
- `.agents/skills/conu-security-guardian/references/privacy-security-checklist.md`
- `plan.md`

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay abuse_threshold -- --nocapture` passed with the same GNU environment.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU environment.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed with the same GNU environment.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--fail-on-threshold` is documented.
- Local threshold CLI smoke passed against a temporary `.abuse` file: `--fail-on-threshold` returned exit code 3 with `status=threshold_exceeded`, and the same report without the flag returned exit code 0 while preserving `status=threshold_exceeded`.

Known gaps:

- The fail-on-threshold flag is a local process exit mode only. It is not distributed alerting, adaptive abuse response, tenant-wide workflow automation, or hosted dashboard storage.
- Abuse, accounting, tenant, credential, mailbox, and dashboard stores are still single-relay storage boundaries.
- Admin threshold reports still inherit dashboard scope and the existing account-scoped dashboard behavior where global accounting and abuse counters are suppressed without a node filter.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Abuse Threshold Policy Files (Completed)

Objective: let self-hosted and managed relay operators reuse payload-safe threshold limits across local/admin abuse threshold reports without adding adaptive enforcement, alerting, distributed dashboards, or tenant-wide workflow automation.

Current status:

- Created GitHub issue #96 for reusable abuse threshold policy files.
- Created branch `codex/abuse-threshold-policy-file` from `main`.
- Added `--thresholds-file <path>` to local `conu-relay --abuse-threshold-report`.
- Added `--thresholds-file <path>` to admin-gated `conu-relay --admin-abuse-threshold-report`.
- Added metadata-only policy parsing with `version = "1"`, supported `max_*` threshold keys, and required false display guards for payload, token, token hash, key material, session id, ciphertext, and contents.
- Kept CLI `--max-*` values as one-run overrides over policy-file defaults.
- Kept the existing requirement that at least one threshold must be supplied by file or CLI.
- Added parser and CLI override tests for local/admin threshold reports.
- Updated docs, package notes, repo memory, release checklist, and security guardrails.
- Merged PR #97 and closed issue #96.
- Preserved local and remote branch `codex/abuse-threshold-policy-file`.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay abuse_threshold -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--thresholds-file` is documented.
- Local policy-file threshold smoke passed against a temporary `.abuse` directory: without `--fail-on-threshold` it returned exit code 0 with `status=threshold_exceeded`, and with `--fail-on-threshold` it returned exit code 3 while preserving stdout.

Known gaps:

- Threshold policy files are local/admin single-relay reporting inputs only. They are not distributed alerting, adaptive enforcement, tenant-wide workflow automation, hosted dashboard storage, or managed policy distribution.

## Post Phase 15 Mailbox Retention Policy Files (Completed)

Objective: let self-hosted and managed relay operators reuse payload-safe mailbox retention TTL/node settings across local and admin audit/purge commands without adding distributed retention orchestration, hosted policy distribution, billing, or adaptive automation.

Current status:

- Created GitHub issue #99 for reusable mailbox retention policy files.
- Created branch `codex/mailbox-retention-policy-file` from `main`.
- Added `--retention-policy-file <path>` to local `conu-relay --mailbox-audit`.
- Added `--retention-policy-file <path>` to local `conu-relay --mailbox-purge`.
- Added `--retention-policy-file <path>` to admin-gated `conu-relay --admin-mailbox-audit`.
- Added `--retention-policy-file <path>` to admin-gated `conu-relay --admin-mailbox-purge`.
- Added metadata-only policy parsing with `version = "1"`, optional `ttl_seconds`, optional `node_id`, and required false display guards for payload, token, token hash, key material, session id, ciphertext, and contents.
- Kept CLI `--ttl-seconds` and `--node` values as one-run overrides over policy-file defaults.
- Kept purge safety behavior: purge commands still require a retention TTL from file or CLI and exactly one of `--dry-run` or `--confirm`.
- Added parser and CLI override tests for local/admin mailbox audit and purge commands.
- Updated docs, package notes, repo memory, release checklist, and security guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all` passed during implementation.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay mailbox -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `git diff --check` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--retention-policy-file` is documented.
- Local mailbox policy-file smoke passed against a temporary mailbox directory: `--mailbox-audit` and `--mailbox-purge --dry-run` loaded `ttl_seconds` and `node_id` from the policy file, returned JSON metadata, and kept every display guard false.

Known gaps:

- Retention policy files are local/admin single-relay command inputs only. They are not distributed policy distribution, tenant-wide retention orchestration, hosted workflow automation, billing, or adaptive cleanup.

Next recommendation:

- Open and merge a PR for issue #99 while preserving the local and remote feature branch. Then continue with distributed hosted mailbox retention orchestration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Relay Session-State Audit (Completed)

Objective: let self-hosted and managed relay operators inspect metadata-only same-node relay session resume records locally or through the running relay admin control plane without adding distributed session migration, distributed locking, hosted analytics, or a new tenant-wide workflow service.

Current status:

- Created GitHub issue #101 for payload-safe relay session-state audit.
- Created branch `codex/session-state-audit` from `main`.
- Added local `conu-relay --session-audit --session-state-dir <path> [--node <node-id>] [--json]`.
- Added admin-gated `conu-relay --admin-session-audit --relay <endpoint> --admin-token-stdin [--node <node-id>] [--json]`.
- Added relay admin `session_audit` frames and `RelayAdminResult` session-state counters/timestamp bounds.
- Added `scope_sessions = true` to hashed hosted admin-token manifests while preserving full-admin compatibility.
- Kept account-scoped session audit constrained to an explicit node filter plus an active tenant-node record.
- Reports record counts, active/expired/invalid counts, oldest created timestamp, newest last-seen timestamp, next active expiry timestamp, and false display guards only.
- Does not print relay session ids, raw node tokens, token hashes, admin tokens, payloads, ciphertext bodies, private keys, arbitrary frame contents, or session-state file contents.
- Updated README, hosted relay docs, distribution/user guides, release checklist, packaging docs, repo memory, and security/build guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-core admin_frames_round_trip_with_debug_redaction -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay session -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--session-audit` and `--admin-session-audit` are documented.
- Local `conu-relay --session-audit --session-state-dir <temp> --node node.smoke --json` smoke passed against a temporary valid `.session` file and confirmed no relay session id was rendered.
- `git diff --check` passed.

Known gaps:

- The session-state audit is a single-relay metadata view over file-backed same-node resume records. It is not distributed multi-instance session migration, a distributed lock service, hosted analytics, billing, or tenant-wide workflow automation.
- Admin session audit returns `session_state_unavailable` when the running relay is configured for memory-only session state.

Next recommendation:

- Continue with distributed multi-instance session migration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Admin-Token Manifest Audit (Completed)

Objective: let self-hosted and managed relay operators inspect scoped hosted admin-token manifest boundaries locally without exposing raw admin tokens, token hashes, manifest contents, payloads, key material, session ids, ciphertext bodies, or frame contents.

Current status:

- Created GitHub issue #103 for payload-safe hosted admin-token manifest audit.
- Created branch `codex/admin-token-audit` from `main`.
- Added local `conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <account-id>] [--json]`.
- Added `HostedAdminTokenAudit` and `audit_hosted_admin_tokens_file` for record counts, active/revoked/expired totals, account-scoped/global records, unique account counts, expiring-record counts, expiry bounds, and per-scope counts.
- Kept the command local and metadata-only; it does not print raw admin tokens, token hashes, private keys, relay session ids, payloads, ciphertext bodies, arbitrary frame contents, or manifest contents.
- Kept `--bind-addr` parsing to host:port-style characters so invalid secret-bearing values fail without echoing the submitted string.
- Extended scoped admin-token manifest display guards to accept and require false `key_material_displayed`, `session_id_displayed`, and `ciphertext_displayed` keys when present, in addition to the existing payload/token/token-hash/content guards.
- Updated README, architecture, hosted relay docs, production readiness docs, release checklist, package notes, repo memory, and security/build guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all` passed during implementation.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay admin_token -- --nocapture` passed.
- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed.
- `target\debug\conu-relay.exe --help` smoke confirmed `--admin-token-audit` is documented.
- Local `conu-relay --admin-token-audit --admin-tokens-file <temp> --bind-addr 0.0.0.0:8787 --account account.prod --json` smoke passed and confirmed neither the raw admin token nor token hash was rendered.
- `git diff --check` passed.

Known gaps:

- The admin-token manifest audit is a local single-relay operator check. It is not distributed RBAC administration, hosted identity/key management, tenant-wide workflow automation, adaptive abuse response, billing, or a managed hosted control plane.

Next recommendation:

- Open and merge a PR for issue #103 while preserving the local and remote feature branch. Then continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Relay Readiness Preflight (Completed)

Objective: give self-hosted and managed relay operators one payload-safe local preflight before startup or release smoke that combines configured credential, scoped admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks without exposing secrets or payload material.

Current status:

- Created GitHub issue #105 for payload-safe hosted relay readiness preflight.
- Created branch `codex/hosted-relay-readiness` from `main`.
- Added `conu-relay --hosted-readiness [--bind-addr <addr>] [--credentials-file <path>] [--tenants-file <path>] [--admin-tokens-file <path>] [--session-state-dir <path>] [--mailbox-dir <path>] [--ttl-seconds <seconds>] [--accounting-dir <path>] [--abuse-dir <path>] [--account <account-id>] [--node <node-id>] [--json] [--fail-on-warning]`.
- Reused existing local audit boundaries for hosted credentials, hosted tenants, hosted admin-token manifests, relay session state, durable mailbox retention, relay accounting, and relay abuse counters.
- Kept output metadata-only: configured paths, configured-source booleans, aggregate counts, warning count, bind metadata, optional account/node filters, and false display guards only.
- Added exit code 3 for `--fail-on-warning` after preserving stdout when warnings exist.
- Updated README, architecture, hosted relay docs, production readiness docs, distribution/hosting docs, release checklist, package notes, SDK/user guides, repo memory, and security/build guardrails.

Validation:

- `cargo +stable-x86_64-pc-windows-gnu fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed with `PATH` including `C:\Users\parth\Downloads\llama\w64devkit\bin` and `RUSTFLAGS=-C linker=rust-lld`.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed with the same GNU linker path.
- `cargo +stable-x86_64-pc-windows-gnu test --workspace` passed with the same GNU linker path.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay --bin conu-relay hosted_readiness_parser_and_renderers_are_metadata_only -- --nocapture` passed.
- `python -m py_compile sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `cargo +stable-x86_64-pc-windows-gnu build -p conu-relay` passed with the GNU linker path.
- Local `target\debug\conu-relay.exe --hosted-readiness ... --json` smoke passed against temporary credential, tenant, session, mailbox, accounting, and abuse paths.
- Local `target\debug\conu-relay.exe --hosted-readiness ... --json --fail-on-warning` smoke preserved stdout and returned exit code 3 when admin-token readiness warnings existed.
- `git diff --check` passed.

Known gaps:

- Hosted readiness is a local single-relay preflight over configured files/directories. It is not distributed hosted monitoring, adaptive abuse response, tenant-wide workflow automation, distributed mailbox retention orchestration, distributed session migration, billing, or a managed hosted control plane.

Next recommendation:

- Open and merge a PR for issue #105 while preserving the local and remote feature branch. Then continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 GitHub Actions Node 24 Runtime Hardening (Completed)

Objective: remove GitHub Actions Node 20 action-runtime deprecation warnings from CI and release workflows before GitHub-hosted runners force JavaScript actions to Node 24.

Current status:

- Created GitHub issue #107 for GitHub Actions Node 24 runtime hardening.
- Created branch `codex/actions-node24-runtime` from `main`.
- Merged PR #108 and preserved the local and remote feature branch.
- Confirmed `actions/checkout` latest release `v6.0.2` declares `using: node24` in `action.yml`.
- Confirmed `actions/setup-node` latest release `v6.4.0` declares `using: node24` in `action.yml`.
- Updated `.github/workflows/ci.yml` from `actions/checkout@v4` and `actions/setup-node@v4` to v6.
- Updated `.github/workflows/release.yml` from `actions/checkout@v4` and `actions/setup-node@v4` to v6.
- Updated the release checklist to keep CI/release action runtimes on Node 24-compatible versions.

Validation:

- `gh api repos/actions/checkout/releases/latest --jq '.tag_name'` returned `v6.0.2`.
- `gh api repos/actions/setup-node/releases/latest --jq '.tag_name'` returned `v6.4.0`.
- `gh api repos/actions/checkout/contents/action.yml?ref=v6.0.2 --jq '.content'` decoded to an action with `using: node24`.
- `gh api repos/actions/setup-node/contents/action.yml?ref=v6.4.0 --jq '.content'` decoded to an action with `using: 'node24'`.
- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- `rg -n "actions/(checkout|setup-node)@v4|actions/(checkout|setup-node)@v5" .github/workflows` returned no matches.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `git diff --check` passed.

Known gaps:

- This update only hardens JavaScript action runtime compatibility. It does not change the package test Node version matrix, release signing secrets, or hosted/distributed product gaps.

Next recommendation:

- Continue with release workflow hardening, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Release Artifact Action Runtime Hardening (Completed)

Objective: keep release artifact upload/download/provenance steps on GitHub JavaScript action versions that declare the Node 24 action runtime and preserve release artifact integrity checks.

Current status:

- Created GitHub issue #109 for release artifact action runtime hardening.
- Created branch `codex/release-actions-node24` from `main`.
- Confirmed `actions/upload-artifact` latest release `v7.0.1` declares `using: 'node24'` in `action.yml`.
- Confirmed `actions/download-artifact` latest release `v8.0.1` declares `using: 'node24'` in `action.yml`.
- Confirmed `actions/attest` latest release `v4.1.0` declares `using: node24` in `action.yml`.
- Updated `.github/workflows/release.yml` artifact provenance/upload/download steps to `actions/attest@v4.1.0`, `actions/upload-artifact@v7.0.1`, and `actions/download-artifact@v8.0.1`.
- Updated the release checklist with the self-hosted runner caveat for Node 24-runtime GitHub actions.

Validation:

- `gh api repos/actions/upload-artifact/releases/latest --jq '.tag_name'` returned `v7.0.1`.
- `gh api repos/actions/download-artifact/releases/latest --jq '.tag_name'` returned `v8.0.1`.
- `gh api repos/actions/attest/releases/latest --jq '.tag_name'` returned `v4.1.0`.
- Decoded upstream `action.yml` files for all three action versions declare Node 24 runtimes.
- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- `rg -n "actions/(upload-artifact|download-artifact)@v4|actions/attest@v4$" .github/workflows` returned no matches.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `git diff --check` passed.

Known gaps:

- This update hardens release action runtime compatibility only. It does not configure signing secrets, publish a release tag, or change the known hosted/distributed product gaps.

Next recommendation:

- Issue #109 was closed by PR #110, and `codex/release-actions-node24` remains preserved locally and on origin. Continue with release workflow smoke validation, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Release Workflow Smoke Validation (Completed)

Objective: prove the Node 24 release action updates by running the multi-platform release workflow on `main` without publishing a GitHub Release or npm packages.

Current status:

- Created GitHub issue #111 for release workflow smoke validation.
- Created branch `codex/release-workflow-smoke-record` from `main`.
- Ran `gh workflow run release.yml --ref main`, which created workflow run `https://github.com/imthegoodboy/conU/actions/runs/26264867145`.
- The `Release Artifacts` workflow completed successfully on `main` for the package checks plus `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` build jobs.
- The non-tag `workflow_dispatch` run skipped `Publish GitHub Release` and `Publish npm Packages` as expected, so no release or npm package was published.
- Uploaded artifacts were present for `conu-windows-x64`, `conu-linux-x64`, `conu-linux-arm64`, `conu-macos-arm64`, and `conu-macos-x64`.
- Updated the release checklist so future CI or release action-version changes require a `workflow_dispatch` smoke run before tagging.

Validation:

- Post-merge CI run `https://github.com/imthegoodboy/conU/actions/runs/26264717227` completed successfully on `main` after PR #110.
- `gh run view 26264867145 --json status,conclusion,url,workflowName,displayTitle,headBranch,event,createdAt,updatedAt` reported `status=completed` and `conclusion=success`.
- `gh api repos/imthegoodboy/conU/actions/runs/26264867145/artifacts` showed all five platform artifacts present and not expired.
- Release workflow jobs passed for package checks, `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64`; release and npm publication jobs were skipped on the non-tag run.

Known gaps:

- This smoke validates manual multi-platform artifact builds, checksums, artifact attestations, and uploads after the Node 24 action updates. A real tagged release still needs configured Windows/macOS signing secrets, GitHub Release publication, npm provenance publication, and final tag-run verification. It does not change the known hosted/distributed product gaps.

Next recommendation:

- Issue #111 was closed by PR #112, and `codex/release-workflow-smoke-record` remains preserved locally and on origin. Continue with GitHub Actions runner-image migration hardening, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 GitHub Actions Runner Image Pinning (Completed)

Objective: remove GitHub-hosted runner image migration warnings and make CI/release platform labels explicit before the June 2026 Windows/macOS hosted-runner migrations.

Current status:

- Created GitHub issue #113 for runner-image pinning.
- Created branch `codex/pin-actions-runner-images` from `main`.
- Observed post-merge CI run `https://github.com/imthegoodboy/conU/actions/runs/26265143809` reporting the GitHub notice that `windows-latest` requests are being redirected to `windows-2025-vs2026` by June 15, 2026.
- Verified the May 14, 2026 GitHub Actions changelog: `windows-latest`/`windows-2025` migrate to Visual Studio 2026 by June 15, 2026, and `macos-latest` begins migrating to macOS 26 on June 15, 2026.
- Verified the `actions/runner-images` label table includes `windows-2025-vs2026`, `macos-15`, and `macos-15-intel`.
- Updated `.github/workflows/ci.yml` to run Rust CI on `ubuntu-latest`, `windows-2025-vs2026`, and `macos-15`.
- Updated `.github/workflows/release.yml` so `windows-x64` uses `windows-2025-vs2026` and `macos-arm64` uses `macos-15`; `macos-x64` already used `macos-15-intel`.
- Updated the release checklist with the explicit runner labels and the reminder to revisit the Windows label after the June 2026 migration completes.
- User preference captured for future work: create new branches without the `codex/` prefix. Existing preserved `codex/*` branches are not deleted.

Validation:

- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- `rg -n "windows-latest|macos-latest" .github/workflows` returned no matches.
- `npm run check --prefix sdk\typescript` passed.
- `npm run check --prefix packaging\npm\conu-cli` passed.
- `git diff --check` passed.
- PR #114 CI passed: Packages, CodeRabbit, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run `https://github.com/imthegoodboy/conU/actions/runs/26265326440` completed successfully.
- The branch release smoke passed package checks plus `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` builds; `Publish GitHub Release` and `Publish npm Packages` skipped on the non-tag branch run.

Known gaps:

- This runner-image update does not configure release signing secrets, publish a release tag, publish npm packages, or change the known hosted/distributed product gaps.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Node LTS Package Hardening (Completed)

Objective: keep npm package checks, publication jobs, and package engine metadata on currently supported Node.js LTS lines.

Current status:

- Created GitHub issue #115 for Node LTS package hardening.
- Created branch `node-lts-package-hardening` from `main` without a `codex/` prefix, per user preference.
- Verified the official Node.js release table on 2026-05-22: Node 24 and Node 22 are LTS; Node 20, Node 18, and Node 16 are EOL.
- Updated CI and release package jobs to use Node 24.
- Updated `@conu/sdk` and `@conu/cli` package `engines` to accept Node 22 LTS or Node 24 LTS and reject EOL Node lines.
- Updated npm package docs, SDK/MCP docs, and the release checklist with the supported Node LTS requirement.
- Opened and merged PR #116 to close issue #115.

Validation:

- `node --version` reported `v24.14.1`.
- `npm --version` reported `11.11.0`.
- Python YAML parse passed for `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- Stale reference scan passed for `node-version: 20`, old package engine ranges, `Node 18+`, and `Node 20` in current workflow/package docs.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `npm pack --dry-run --json` passed for `sdk/typescript`.
- `npm pack --dry-run --json` passed for `packaging/npm/conu-cli`.
- `git diff --check` passed.
- PR #116 CI run `https://github.com/imthegoodboy/conU/actions/runs/26266048350` completed successfully: Packages, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run `https://github.com/imthegoodboy/conU/actions/runs/26266054245` completed successfully.
- The branch release smoke passed package checks plus `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64` builds with artifact attestations/uploads; `Publish GitHub Release` and `Publish npm Packages` skipped on the non-tag branch run.
- PR #116 was merged into `main` on 2026-05-22, issue #115 was closed, local and remote `node-lts-package-hardening` branches were preserved, and post-merge CI run `https://github.com/imthegoodboy/conU/actions/runs/26266342419` completed successfully.

Known gaps:

- This package-runtime update does not configure release signing secrets, publish a release tag, publish npm packages, or change the known hosted/distributed product gaps.

Next recommendation:

- Revisit the Node engine range when the next Node LTS line is promoted, and continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Hosted Readiness Policy Files (Completed)

Objective: make `conu-relay --hosted-readiness` reuse the same metadata-only mailbox retention and abuse threshold policy files already supported by the dedicated relay audit/report commands.

Current status:

- Created GitHub issue #117 for hosted readiness policy-file reuse.
- Created branch `hosted-readiness-policy-files` from `main` without a `codex/` prefix, per user preference.
- Added `--retention-policy-file <path>` to hosted readiness when `--mailbox-dir` is configured.
- Reused mailbox retention policy merge semantics so policy `ttl_seconds` and `node_id` apply to the readiness mailbox audit, with CLI `--ttl-seconds` and `--node` overrides.
- Added `--thresholds-file <path>` and inline `--max-* <count>` threshold options to hosted readiness when `--abuse-dir` is configured.
- Reused abuse threshold policy merge semantics so CLI `--max-*` values override policy-file defaults.
- Added threshold checks/exceeded counts to hosted readiness text/JSON output, kept display guard aggregation payload-safe, and made exceeded thresholds contribute to warning status and `--fail-on-warning`.
- Updated README, hosted relay docs, distribution/hosting docs, production readiness docs, release checklist, SDK/MCP docs, Docker/package docs, and user install docs.

Validation so far:

- `cargo fmt --all -- --check` passed.
- `git diff --check` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- Local Rust compile/test was blocked on this Windows environment because the default MSVC target could not find `link.exe` and the GNU toolchain could not find `dlltool.exe`.
- PR #118 CI run `https://github.com/imthegoodboy/conU/actions/runs/26267121539` completed successfully: Packages, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- PR #118 was merged into `main` on 2026-05-22, issue #117 was closed, and local/remote `hosted-readiness-policy-files` branches were preserved.

Known gaps:

- This readiness-policy update does not add distributed hosted dashboards/adaptive abuse workflows, distributed mailbox retention orchestration, distributed tenant workflow services, distributed multi-instance session migration, managed hosted identity/key administration, release signing secrets, release tags, or npm publication.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Tagged Release Preflight Hardening (Completed)

Objective: prevent `v*` tag releases from creating a partial GitHub-only release when required signing or npm publication secrets are incomplete.

Current status:

- Created GitHub issue #120 for fail-closed tagged release publish secrets.
- Created branch `release-tag-preflight-hardening` from `main` without a `codex/` prefix, per user preference.
- Added a `Release Tag Preflight` job to `.github/workflows/release.yml`.
- The preflight requires Windows Authenticode secrets, macOS Developer ID/notarization secrets, and `NPM_TOKEN` before `v*` tag package checks or platform builds can start.
- Kept manual `workflow_dispatch` release smoke runs available without signing or npm secrets on non-tag refs.
- Changed tagged npm publish steps from warning-and-skip to fail-closed when `NPM_TOKEN` is missing.
- Updated release, distribution, signing, packaging, and npm launcher docs to describe the strict tagged-release behavior.
- Opened PR #121 to close issue #120.
- PR #121 CI passed across Packages plus Rust on `ubuntu-latest`, `windows-2025-vs2026`, and `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run passed with release preflight, package checks, all five platform builds, artifact verification, attestations, uploads, and expected non-tag skips for GitHub Release/npm publication.

Validation so far:

- `cargo fmt --all -- --check` passed.
- Python YAML parse passed for `.github/workflows/release.yml` and `.github/workflows/ci.yml`.
- Basic workflow text checks passed for tabs, `release-preflight`, and the package job dependency.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `git diff --check` passed.
- Default MSVC `cargo check --workspace --all-targets` was blocked locally because `link.exe` is not installed.
- GNU `cargo +stable-x86_64-pc-windows-gnu test --workspace` was blocked locally because `dlltool.exe` is not installed.
- PR #121 CI run `https://github.com/imthegoodboy/conU/actions/runs/26267680993` completed successfully: Packages, Rust on `ubuntu-latest`, Rust on `windows-2025-vs2026`, and Rust on `macos-15`.
- Branch `Release Artifacts` workflow_dispatch run `https://github.com/imthegoodboy/conU/actions/runs/26267754923` completed successfully: Release Tag Preflight, Package Checks, and platform builds for `windows-x64`, `linux-x64`, `linux-arm64`, `macos-arm64`, and `macos-x64`.

Known gaps:

- This hardening does not configure repository signing secrets or `NPM_TOKEN`; `gh secret list` showed no repository secrets configured in this environment, so a real `v*` tag would correctly fail at the new preflight until maintainers add them.
- This hardening does not publish a release tag, publish npm packages, add OS package-manager distribution, or change the known hosted/distributed product gaps.

Next recommendation:

- Configure release signing secrets plus `NPM_TOKEN` before the next real `v*` tag, then continue with distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal. Preserve local and remote work branches.

## Post Phase 15 Release Version Consistency Gate (Completed)

Objective: prevent a release tag, native archive, or npm package publication from using inconsistent Cargo/npm package versions.

Current status:

- Created GitHub issue #122 for release tag and package version consistency.
- Created branch `release-version-consistency-gate` from `main` without a `codex/` prefix, per user preference.
- Added `scripts/verify-release-versions.py` to validate all conU Cargo crate versions, `@conu/cli`, and `@conu/sdk` share one semver-like version.
- The verifier also compares `v*` tag names against the package version when `GITHUB_REF_TYPE=tag`/`GITHUB_REF_NAME` or `CONU_RELEASE_TAG` is present.
- Wired the verifier into the CI package job and the `Release Artifacts` package gate before npm checks/dry-runs.
- Updated README, distribution, production-readiness, release checklist, and packaging docs with the automated version gate.
- Opened PR #123 for the gate and linked it to issue #122.

Validation:

- `python scripts\verify-release-versions.py` passed.
- `GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v0.1.0 python scripts\verify-release-versions.py` passed.
- `GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v9.9.9 python scripts\verify-release-versions.py` failed as expected with a tag/package mismatch.
- `CONU_RELEASE_TAG=0.1.0 python scripts\verify-release-versions.py` failed as expected with a clean non-`v` tag error.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py sdk\python\conu_sdk\__init__.py examples\python\local_agent_pair.py` passed.
- Python YAML parse passed for `.github/workflows/release.yml` and `.github/workflows/ci.yml`.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `git diff --check` passed.
- PR #123 CI passed across Packages plus Rust on Ubuntu, Windows, and macOS: https://github.com/imthegoodboy/conU/actions/runs/26268247436
- Branch `Release Artifacts` smoke passed across release preflight, package checks, attestations/uploads, and five platform builds: https://github.com/imthegoodboy/conU/actions/runs/26268351380
- Default MSVC `cargo check --workspace --all-targets` was blocked locally because `link.exe` is not installed.
- GNU `cargo +stable-x86_64-pc-windows-gnu test --workspace` was blocked locally because `dlltool.exe` is not installed.

Known gaps:

- This version gate does not publish a release tag, publish npm packages, configure signing/npm secrets, or change the known hosted/distributed product gaps.

Next recommendation:

- Merge PR #123 without deleting local or remote work branches, then continue with tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Dashboard Snapshot (Completed)

Objective: give controlled multi-relay operators a payload-safe fleet-level dashboard snapshot without claiming hosted billing, distributed alerting, or adaptive abuse automation.

Current status:

- Created GitHub issue #124 for hosted fleet dashboard snapshots.
- Created branch `hosted-fleet-dashboard` from `main` without a `codex/` prefix, per user preference.
- Added `conu-relay --hosted-fleet-dashboard --fleet-file <path> [--account <account-id>] [--node <node-id>] [--json]`.
- Added a versioned fleet manifest parser with required false display guards and `[[relay]]` entries for optional credential, tenant, session-state, mailbox, accounting, and abuse metadata stores.
- The fleet command resolves relative source paths from the manifest directory, reuses the existing payload-safe audit functions, and returns only relay names, source paths, aggregate counters, filters, and display guards.
- Updated README, architecture, relay hosting docs, release checklist, security docs, user guide, repo memory, and implementation guardrails to describe the fleet dashboard boundary.
- Merged PR #125 and closed issue #124 while preserving the `hosted-fleet-dashboard` branch.

Validation:

- `cargo fmt --all` passed after implementation.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `cargo fmt --all -- --check` passed.
- `git diff --check` passed.
- PR #125 CI passed across Packages plus Rust on Ubuntu, Windows, and macOS: https://github.com/imthegoodboy/conU/actions/runs/26269521890
- Branch `Release Artifacts` smoke passed across release preflight, package checks, attestations/uploads, and five platform builds: https://github.com/imthegoodboy/conU/actions/runs/26269402546
- Post-merge main CI passed: https://github.com/imthegoodboy/conU/actions/runs/26269603066
- Post-merge main `Release Artifacts` smoke passed: https://github.com/imthegoodboy/conU/actions/runs/26269682067
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_dashboard_parser_and_renderers_are_metadata_only` was blocked locally because `dlltool.exe` is not installed.

Known gaps:

- This is a manifest-driven local/operator aggregate over available relay-local metadata stores. It is not hosted billing, distributed alerting, adaptive abuse response, distributed retention orchestration, a managed analytics service, or distributed session migration.

Next recommendation:

- Continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Dashboard Threshold Policy (Completed)

Objective: make controlled multi-relay fleet snapshots scriptable by applying the existing guarded abuse threshold policy format to aggregate fleet abuse counters without creating adaptive enforcement or exposing relay contents.

Current status:

- Created GitHub issue #126 for hosted fleet dashboard abuse threshold policy.
- Created branch `fleet-dashboard-threshold-policy` from `main` without a `codex/` prefix, per user preference.
- Extended `conu-relay --hosted-fleet-dashboard --fleet-file <path>` with `--thresholds-file <path>`, inline `--max-*` overrides, and `--fail-on-threshold`.
- The fleet command now evaluates thresholds only against aggregate abuse counters from configured fleet `abuse_dir` stores, preserves stdout, and returns exit code 3 only when `--fail-on-threshold` is set and at least one configured limit is exceeded.
- Threshold policy files reuse the existing metadata-only `version = "1"` format and required false display guards; CLI overrides still win for one-off runs.
- The command fails closed when threshold evaluation is requested but no fleet relay supplies an `abuse_dir`.
- Output remains limited to relay names, source paths, filters, aggregate counters, threshold check/exceeded metadata, and false display guards.
- Updated README, architecture, relay hosting docs, production/security/release docs, user guide, repo memory, and implementation guardrails to describe the new fleet threshold boundary.
- Opened PR #127 to close issue #126.

Validation:

- `cargo fmt --all` passed after implementation.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_dashboard_parser_and_renderers_are_metadata_only` was blocked locally because `dlltool.exe` is not installed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` was blocked locally by the same missing `dlltool.exe` linker dependency.
- PR #127 CI passed across Packages plus Rust on Ubuntu, Windows, and macOS: https://github.com/imthegoodboy/conU/actions/runs/26270473795
- Branch `Release Artifacts` smoke passed across release preflight, package checks, attestations/uploads, and five platform builds at the current PR head: https://github.com/imthegoodboy/conU/actions/runs/26270567039

Known gaps:

- This is a fleet-level aggregate threshold gate over relay-local metadata stores. It is not distributed alert routing, adaptive abuse response, hosted billing, distributed retention orchestration, distributed session migration, or tenant-wide workflow automation.
- Full local runtime/test proof for this Windows workstation still depends on installing `dlltool.exe`; GitHub CI covered the test path.

Next recommendation:

- Merge PR #127 without deleting local or remote work branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Dashboard Mailbox Retention Policy (Completed)

Objective: make controlled multi-relay fleet snapshots scriptable for durable mailbox retention pressure by reusing the existing guarded mailbox retention policy format without adding remote purge, adaptive cleanup, distributed retention orchestration, or payload exposure.

Current status:

- Created GitHub issue #128 for fleet mailbox retention policy gates.
- Created branch `fleet-mailbox-retention-policy` from `main` without a `codex/` prefix, per user preference.
- Opened PR #129 to close issue #128 without deleting local or remote branches.
- Extended `conu-relay --hosted-fleet-dashboard --fleet-file <path>` with `--retention-policy-file <path>`, `--ttl-seconds <seconds>`, and `--fail-on-retention`.
- Fleet retention policy files reuse the existing metadata-only `version = "1"` mailbox retention policy format with optional `ttl_seconds`, optional `node_id`, and required false display guards.
- Hosted fleet dashboards now apply a mailbox retention node filter only to mailbox metadata scans. CLI `--node` still remains the global source filter and overrides policy-file mailbox node defaults.
- CLI `--ttl-seconds` overrides all fleet mailbox TTLs for one run; per-relay manifest `mailbox_ttl_seconds` values remain source-specific overrides ahead of policy-file TTL defaults.
- Output adds effective mailbox retention node, policy path, TTL metadata, aggregate expired mailbox records/bytes, retention check counts, exceeded source counts, and existing false display guards only.
- `--fail-on-retention` preserves stdout and returns exit code 3 only when at least one TTL-checked fleet mailbox source reports expired durable records.
- The command fails closed when retention evaluation is requested but the fleet manifest has no mailbox source, or when `--fail-on-retention` is requested without any effective TTL.
- Updated README, architecture, relay hosting docs, production/security/release docs, SDK/MCP boundaries, user guide, repo memory, and implementation/security guardrails.

Validation:

- `cargo fmt --all` passed after implementation.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- GitHub PR CI passed for commit `3e039743b2b6261fe660dd5c4bea1e235b334541`: https://github.com/imthegoodboy/conU/actions/runs/26271673595
- Branch Release Artifacts smoke passed for commit `3e039743b2b6261fe660dd5c4bea1e235b334541`: https://github.com/imthegoodboy/conU/actions/runs/26271801283
- PR #129 status checks are clean, including CodeRabbit `Review skipped` success.
- Security review retained payload-safe behavior. The new gate reads configured local mailbox metadata only, reports counts/bytes/TTL/status/filter metadata, does not purge files, does not call remote relays, and does not print mailbox contents, manifest contents, policy contents, tokens, token hashes, session ids, payloads, ciphertext, or frame bodies.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_dashboard_parser_and_renderers_are_metadata_only` was blocked locally because `dlltool.exe` is not installed.
- `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` was blocked locally by the same missing `dlltool.exe` linker dependency.

Known gaps:

- This is a read-only fleet-level retention gate over relay-local durable mailbox metadata stores. It is not remote purge, distributed lock coordination, hosted billing, adaptive cleanup, managed alerting, tenant-wide retention orchestration, or distributed retention automation.
- Full local runtime/test proof for this Windows workstation still depends on installing `dlltool.exe`; GitHub CI covered the test path.

Next recommendation:

- Merge PR #129 without deleting local or remote work branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration beyond read-only fleet gates, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Mailbox Purge Orchestration (Completed)

Objective: make expired durable mailbox cleanup scriptable across guarded local hosted-fleet manifests without contacting remote relays, introducing distributed locks, adding cross-region retention services, or exposing payload, mailbox, policy, or manifest contents.

Current status:

- Issue: https://github.com/imthegoodboy/conU/issues/130
- PR: https://github.com/imthegoodboy/conU/pull/131
- Branch: `fleet-mailbox-purge-orchestration` (plain branch name, no `codex/` prefix)
- Added local `conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]`.
- Reuses the existing guarded hosted fleet manifest parser and existing mailbox purge core, so the command works over manifest-listed local `mailbox_dir` stores only.
- Requires exactly one of `--dry-run` or `--confirm`, requires at least one fleet `mailbox_dir`, and requires an effective TTL for every mailbox source before confirmed cleanup can delete from any source.
- TTL precedence is CLI `--ttl-seconds`, then per-relay `mailbox_ttl_seconds`, then policy-file `ttl_seconds`; CLI `--node` overrides policy-file `node_id`.
- Dry-run deletes nothing. Confirmed mode deletes only expired valid `.mailbox` files through the existing purge path and leaves invalid records untouched.
- Text/JSON output reports only aggregate and per-relay counts, paths, TTL/filter metadata, mode, and false display guards. It does not print tokens, token hashes, admin tokens, private keys, session ids, payloads, ciphertext bodies, frame contents, mailbox file contents, retention policy contents, or manifest contents.

Validation status:

- `cargo fmt --all` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- GitHub PR CI passed for commit `7bde741d3b8fabcb42a1b44285f693d2a4b1ba87`: https://github.com/imthegoodboy/conU/actions/runs/26273372458
- Branch Release Artifacts smoke passed for commit `7bde741d3b8fabcb42a1b44285f693d2a4b1ba87`: https://github.com/imthegoodboy/conU/actions/runs/26273385354
- PR #131 status checks are clean, including CodeRabbit success.
- Local `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_mailbox_purge_parser_and_renderers_are_metadata_only` and `cargo +stable-x86_64-pc-windows-gnu run -p conu-relay -- --help` were blocked because `dlltool.exe` is not installed; GitHub Windows CI should cover the targeted test/run path after PR push.
- Security review retained payload-safe behavior. The command validates every manifest-listed mailbox source and effective TTL before confirmed deletion, deletes only expired valid `.mailbox` files through the existing purge path, does not contact remote relays, and does not print mailbox contents, manifest contents, policy contents, tokens, token hashes, session ids, payloads, ciphertext, or frame bodies.

Known gaps:

- This is guarded local manifest/local store orchestration only. It is not remote relay purge, distributed retention locking, cross-region retention, adaptive cleanup, managed billing, alerting, or tenant-wide hosted retention automation.

Next recommendation:

- Merge PR #131 without deleting local or remote work branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Post Phase 15 Hosted Fleet Credential Revoke (Completed)

Objective: make compromised account/node credential revocation scriptable across guarded local hosted-fleet manifests without tenant metadata mutation, remote relay contact, distributed locks, or secret/payload exposure.

Current status:

- Issue: https://github.com/imthegoodboy/conU/issues/149
- PR: https://github.com/imthegoodboy/conU/pull/150 (merged 2026-05-22, merge commit `7f5426617a3aad2691491a9c097079da0f2d8df9`)
- Branch: `fleet-credential-revoke` (plain branch name, no `codex/` prefix)
- Added local `conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]`.
- Reuses the existing guarded hosted fleet manifest parser and existing account/node credential manifest revoke core across configured local `credentials_file` sources only.
- Requires exactly one of `--dry-run` or `--confirm`, at least one credentials source, and valid account/node ids.
- Preflights every credential source before confirmed mutation, requires exactly one target account/node credential in every source, rejects node ownership collisions and duplicate node records, and dry-run mutates nothing.
- Confirmed mode revokes only account/node credential records through the local manifest helper. It does not revoke tenant metadata, contact remote relays, coordinate distributed locks, or provide managed tenant workflow automation.
- Text/JSON output reports only aggregate and per-relay credential counts, paths, account/node ids, mode/status, and false display guards. It does not print raw node tokens, token hashes, admin tokens, private keys, public key ids, relay session ids, payloads, ciphertext bodies, frame contents, manifest contents, or policy contents.
- Updated README, architecture, hosted relay, production/readiness, distribution/hosting, SDK/MCP, user guide, release/security docs, repo memory, guardrails, security checklist, and plan docs.

Validation status:

- `cargo fmt --all` passed.
- `cargo fmt --all -- --check` passed.
- `cargo +stable-x86_64-pc-windows-gnu check -p conu-relay --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-relay --all-targets -- -D warnings` passed.
- `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets` passed.
- `cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings` passed.
- `npm run check --prefix sdk/typescript` passed.
- `npm run check --prefix packaging/npm/conu-cli` passed.
- `python -m py_compile scripts\verify-release-versions.py scripts\verify-release-artifacts.py` passed.
- `python scripts\verify-release-versions.py` passed.
- `git diff --check` passed.
- `codex review --uncommitted` initially found a same-node/different-account collision gap; the preflight and test were fixed, and the rerun reported no actionable correctness or security issues.
- `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_credential_revoke_parser_report_and_renderers_are_metadata_only -- --nocapture` was blocked locally because `dlltool.exe` is not installed while compiling `getrandom`/`windows-sys`.
- PR #150 CI passed for commit `977281d5e15ebc8fc61d5d73c62871878b5f3c36`, including Packages, Rust on Ubuntu, Rust on Windows, Rust on macOS, and CodeRabbit `Review skipped` success.
- PR #150 merged, issue #149 closed, and the local/remote `fleet-credential-revoke` branches were preserved.
- Main CI passed on merge commit `7f5426617a3aad2691491a9c097079da0f2d8df9`: https://github.com/imthegoodboy/conU/actions/runs/26300625865
- Main `Release Artifacts` smoke passed on merge commit `7f5426617a3aad2691491a9c097079da0f2d8df9`, including release preflight, package checks, attestations/uploads, and all five platform builds: https://github.com/imthegoodboy/conU/actions/runs/26300659920

Known gaps:

- This is guarded local credential-store orchestration only. It is not remote relay credential mutation, tenant metadata lifecycle, distributed tenant workflow automation, distributed locking, hosted billing, adaptive abuse automation, or managed identity/key administration.
- Full local runtime/test proof for this Windows workstation may still depend on installing `dlltool.exe`; GitHub CI should cover the runtime test path after PR push if local linking is blocked.

Next recommendation:

- Continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet credential and tenant metadata tools, distributed multi-instance session migration, managed hosted identity/key administration, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.

## Phase Completion Log

Add entries here when a phase is completed.

```txt
2026-05-10 - Phase 0 started. Architecture and agent memory created. Waiting for user approval before implementation.
2026-05-10 - Phase 0 completed. User approved implementation and Phase 1 started.
2026-05-10 - Phase 1 completed. Rust workspace scaffold created and validated with cargo fmt/check/test plus binary smoke commands using stable-x86_64-pc-windows-gnu. Next: Phase 2 CLI identity and dashboard.
2026-05-10 - Phase 2 completed. CLI dashboard and command shell created with payload-safe outputs, tests, and smoke validation. Next: Phase 3 local identity and persistent state.
2026-05-10 - Phase 3 completed. Local identity and persistent state added with idempotent init, status reads, tests, and isolated CONU_HOME smoke validation. Next: Phase 4 conUD daemon skeleton.
2026-05-10 - Phase 4 completed. conUD daemon skeleton added with start/stop, runtime heartbeat status, stale restart handling, payload-safe logs, tests, and isolated CONU_HOME process smoke. Next: Phase 5 local IPC and agent registration.
2026-05-10 - Phase 5 completed. File-backed local IPC gateway added with metadata-only agent registration, presence heartbeat, persisted local agent registry, conUD processing, CLI listing, tests, docs, and isolated CONU_HOME smoke validation. Next: Phase 6 opaque envelope messaging.
2026-05-10 - Phase 6 completed. Local opaque envelope messaging added with stdin submission, registered sender/receiver validation, recipient inboxes, metadata-only receipts/logs, conUD processing, tests, docs, and isolated CONU_HOME smoke validation. Next: Phase 7 pairing and trust.
2026-05-10 - Phase 7 completed. Local pairing invitations, join-to-trust, peer listing, revocation, pairing code hash storage, tests, docs, and isolated CONU_HOME smoke validation added. Next: Phase 8 WebSocket relay MVP.
2026-05-10 - Phase 8 completed. std-only WebSocket relay service, shared relay frame contract, token-authenticated sessions, metadata-only connected-peer forwarding, tests, docs, and relay binary smoke validation added. Next: Phase 9 remote discovery and sessions.
2026-05-10 - Phase 9 completed. conUD-owned remote session mirror, trusted remote agent cards, `conu sessions`, remote visibility in agents/status/connect, tests, docs, and isolated CONU_HOME smoke validation added. Next: Phase 10 streams and watch animation.
2026-05-10 - Phase 10 completed. Stream lifecycle metadata, stdin-only opaque stream writes, backpressure checks, watch event bus, private watch animation, tests, docs, and isolated CONU_HOME smoke validation added. Next: Phase 11 encryption hardening.
2026-05-10 - Phase 11 completed. Local security module added with Ed25519 signed agent cards, X25519 peer key agreement helpers, XChaCha20Poly1305 encrypted-at-rest message storage, replay protection, `conu security audit`, tests, docs, and GNU-toolchain validation. Next: Phase 12 SDK and MCP adapter.
2026-05-11 - Phase 12 completed. Rust SDK, MCP stdio adapter, Python wrapper SDK, local agent examples, explicit addressed-agent receive API, tests, docs, and GNU-toolchain validation added. Next: Phase 13 direct transport and NAT upgrade.
2026-05-11 - Phase 13 completed. conUD-owned direct/relay route manager, NAT-profile scoring, relay fallback selection, route probes/logs, CLI route commands, SDK/Python/MCP route tools, docs, skills, and GNU-toolchain validation added. Next: Phase 14 rooms, pub/sub, and multi-agent sessions.
2026-05-11 - Phase 15 completed as a user-directed skip-ahead. Added doctor readiness checks, release/smoke scripts, packaging templates, CI/release workflows, release checklist, observability docs, strict local-install smoke validation, and GNU-toolchain release validation. Phase 14 remains not started.
2026-05-11 - Post Phase 15 audit completed. Added clippy-clean polish across runtime, CLI, MCP, CI, and docs while preserving payload privacy and leaving Phase 14 not started.
2026-05-11 - Post Phase 15 internet data-plane and CLI polish completed. Added public peer-card trust, peer-encrypted relay message queueing, explicit relay sync, richer watch animation, SDK/Python/MCP remote helpers, relay E2E tests, and internet relay test docs. Phase 14 remains not started.
2026-05-11 - Post Phase 15 daemon relay production hardening completed. Added conUD-owned relay pump, retry/backoff, relay daemon smoke script, Windows start hardening, docs/skill updates, and daemon-owned remote message validation. Phase 14 remains not started.
2026-05-11 - Post Phase 15 distribution and hosting completed. Added native npm launcher package template, platform release artifact naming/checksums, Docker relay hosting template, distribution/hosting docs, release workflow updates, and installer validation. Phase 14 remains not started.
2026-05-13 - Phase 14 completed after the Phase 15 skip-ahead. Added local rooms/pub-sub metadata, encrypted-at-rest local room event fanout, room CLI/SDK/Python/MCP surfaces, connect/dashboard/watch polish, docs, and GNU-toolchain validation. Next: hosted relay TLS/auth, hosted session policy, remote room fanout, and stream-chunk routing.
2026-05-20 - Post Phase 15 relay abuse controls completed. Added configurable relay total connection, per-IP connection, and per-session frame-rate caps; generic metadata-only rate-limit errors; same-node session cleanup hardening; docs/skill updates; and GNU-toolchain release validation. Next: hosted relay auth/TLS and reusable daemon relay sessions.
2026-05-20 - Post Phase 15 reusable daemon relay sessions completed. Added daemon-owned relay session reuse across serve ticks, reconnect-on-failure behavior, endpoint-change handling, relay E2E session-reuse coverage, docs/skill updates, and validation. Next then: hosted relay auth/TLS policy, `wss://`, stream-chunk routing, and hosted session resume.
2026-05-20 - Post Phase 15 public relay token guard completed. Added non-loopback relay bind rejection for `local-dev-token` and short tokens, docs/skill updates, stale-token doc scans, and full release validation. Next then: `wss://`, stronger hosted relay auth/session policy, stream-chunk routing, and OS-backed key storage.
2026-05-20 - Post Phase 15 WSS relay client support completed. Added certificate-validated `wss://` relay client support, endpoint validation across relay delivery and peer-card trust, CLI/docs updates, Windows GNU-compatible TLS dependency pins, and full release validation. Next: stronger hosted relay auth/session policy, stream-chunk routing, offline mailbox, and OS-backed key storage.
2026-05-20 - Post Phase 15 scoped relay credentials and session policy completed. Added static per-node relay credentials, token-safe authorization, idle timeout and max session TTL controls, redacted auth Debug output, docs/skill updates, focused relay auth/session tests, and full release validation. Next: stream-chunk routing, managed hosted account/credential lifecycle, hosted session resume/accounting, and OS-backed key storage.
2026-05-21 - Post Phase 15 relay stream-chunk delivery completed. Added relay envelope kind/stream metadata, peer-encrypted stream chunk outbox and delivery, inbox/receipt stream metadata, live relay E2E coverage, docs/skill updates, and full release validation. Next: hosted relay account/credential lifecycle, hosted session resume/accounting, offline mailbox, OS-backed key storage, and remote room fanout.
2026-05-21 - Post Phase 15 offline relay mailbox completed. Added bounded in-memory relay mailbox delivery for peer-encrypted message and stream-chunk envelopes, mailbox cap/TTL env controls, mailbox TTL regression coverage, docs/skill updates, and GNU-toolchain validation. Next: hosted account/credential lifecycle, hosted session resume/accounting, durable hosted mailbox storage/accounting, OS-backed key storage, and remote room fanout.
2026-05-21 - Post Phase 15 durable relay mailbox completed. Added optional `CONU_RELAY_MAILBOX_DIR` file-backed ciphertext envelope persistence, relay restart mailbox delivery coverage, Docker mailbox volume defaults/docs, docs/skill updates, and GNU-toolchain validation. Next: hosted account/credential lifecycle, hosted session resume/accounting, hosted mailbox accounting/quotas, OS-backed key storage, and remote room fanout.
2026-05-21 - Post Phase 15 Windows DPAPI secret wrapping completed. Added current-user DPAPI wrapping for local signing/exchange/storage secret bytes, migration-compatible reads for older plaintext-hex key files, audit/backend reporting without secret material, CLI/MCP redaction coverage, docs/skill updates, and GNU-toolchain release validation. Next: managed hosted relay account/credential lifecycle, relay credential storage, capability policy, signed remote agent-card exchange, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay credential storage completed. Added local runtime relay client credential storage, DPAPI-backed token fields on Windows, `conu relay credential set/status/clear`, env-over-stored token resolution, docs/skill updates, and GNU-toolchain release validation. Next: managed hosted relay account/credential lifecycle, capability policy, signed remote agent-card exchange, and non-Windows keychain support.
2026-05-21 - Post Phase 15 signed peer cards completed. Added Ed25519-signed public peer-card export, signed-card verification on trust import, trust-store signature metadata, CLI/MCP/Python signed-card fields, tamper regression coverage, docs/skill updates, and GNU-toolchain validation. Next: signed remote agent-card exchange, capability policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 local capability enforcement completed. Added explicit agent capability registration flags, core enforcement for messages/streams/rooms, stream/room denial tests, docs/skill updates, and GNU-toolchain targeted validation. Next: signed remote agent-card exchange, peer-scoped permission policy, managed hosted relay account/credential lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 signed remote agent cards completed. Added signed public agent-card export/import for trusted peers, session-sync preservation of signed remote cards, tamper and collision checks, CLI/SDK/Python/MCP surfaces, docs/skill updates, and GNU-toolchain validation. Next: peer-scoped permission policy, automatic live agent-card exchange, managed hosted relay account/credential lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 peer-scoped permission policy completed. Added default-deny peer policy records, `conu peers policy`, SDK/Python/MCP policy controls, relay message/stream and remote room policy enforcement, docs/skill updates, and full GNU-toolchain validation. Next: automatic live agent-card exchange, remote room fanout/per-topic policy, managed hosted relay lifecycle, and non-Windows keychain support.
2026-05-21 - Post Phase 15 automatic signed agent-card exchange completed. Added peer-encrypted relay control envelopes for signed local agent cards, session-sync queueing for signed trusted peers with policy grants, inbound verification/import, relay E2E coverage, docs/skill updates, and full GNU-toolchain validation. Next: remote room fanout/per-topic policy, managed hosted relay lifecycle, direct transport, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay-backed room event fanout completed. Added `room_event` relay envelopes, peer-encrypted room event packets with room id/topic hidden from relay frames, remote room publish fanout with `rooms=true` peer policy and agent capability checks, inbound encrypted-at-rest event delivery, docs/skill updates, and full GNU-toolchain validation. Next: per-topic room policy, managed hosted relay lifecycle, direct transport, and non-Windows keychain support.
2026-05-21 - Post Phase 15 room topic policy completed. Added metadata-only per-topic room publish/subscribe grants, `conu rooms policy`, SDK/Python/MCP topic policy surfaces, local and relay inbound enforcement, docs/skill updates, and targeted GNU-toolchain validation. Next: managed hosted relay lifecycle/accounting, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay credential manifest lifecycle completed. Added hashed self-hosted relay credential manifests with active/revoked status, optional expiry, token-safe hash generation, public-bind guard coverage, docs/skill updates, and full GNU-toolchain validation. Next: hosted relay accounting/quotas, session accounting, direct transport, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay accounting and quotas completed. Added metadata-only per-node relay accounting files, authenticated-session/sent/received/mailbox counters, optional sent-envelope and sent-byte quotas, quota denial coverage, docs/skill updates, and GNU-toolchain validation. Next: hosted session resume semantics, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay session resume semantics completed. Added optional HELLO resume hints and WELCOME resumed status, same-node relay validation with cross-node fallback to a new session, daemon pump same-endpoint resume after same-process disconnects, sessions_resumed accounting, docs/skill updates, and full GNU-toolchain validation. Next: direct QUIC/NAT traversal, managed hosted relay account lifecycle, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 live relay credential manifest reload completed. Added live-reloaded `CONU_RELAY_CREDENTIALS_FILE` auth for new HELLO sessions, fail-closed invalid manifest updates, revoke-without-restart coverage, token/hash redaction checks, docs/skill updates, and validation. Next: direct QUIC/NAT traversal, managed hosted relay account/credential issuance APIs, hosted audit/admin controls, distributed hosted session/accounting state, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 direct route selection guard completed. Configured direct QUIC/UDP endpoints now remain inactive metadata with `direct_quic_transport_inactive`, relay stays selected for remote delivery, remote stream chunks continue over relay, docs/skills were updated, and full validation passed. Next: real authenticated direct QUIC/NAT traversal data plane or managed hosted account/credential issuance APIs.
2026-05-21 - Post Phase 15 payload-safe log rotation completed. Added `conu logs rotate` and core observability rotation for local metadata logs, bounded `.log.N` archives, doctor scanning for rotated archives, docs/skill updates, and full validation. Next: storage-key rotation migration tooling, structured telemetry allowlists, managed hosted credential issuance, direct QUIC/NAT traversal, hosted multi-tenant permission administration, and non-Windows keychain support.
2026-05-21 - Post Phase 15 storage-key rotation migration completed. Added archived storage-key ring reads, `conu security rotate storage --confirm`, local encrypted-at-rest message queue/inbox re-encryption, payload-safe rotation reports, docs/skill updates, and full validation. Next: old storage-key retirement, structured telemetry allowlists, managed hosted credential issuance, direct QUIC/NAT traversal, hosted multi-tenant permission administration, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 storage-key retirement completed. Added `conu security retire storage --confirm`, unused archived storage-key deletion after local queue/inbox dependency scanning, dependent-key retention, payload-safe retirement reports, docs/skill updates, and validation. Next: structured telemetry allowlists, managed hosted credential issuance, direct QUIC/NAT traversal, hosted multi-tenant permission administration, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 structured telemetry snapshot completed. Added `conu telemetry snapshot`, `conu.telemetry.snapshot.v1`, explicit allowlisted aggregate telemetry fields, payload-safe JSON/text output, privacy regression tests, docs/skill updates, and full validation. Next: managed hosted credential issuance, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, hosted multi-tenant permission administration, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 offline relay credential issuance completed. Added `conu-relay --issue-credential`, strong offline scoped token generation, raw-token file output with hashed manifest stdout, manifest compatibility tests, docs/skill updates, and full validation. Next: managed hosted account APIs, online credential rotation/revocation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 relay credential manifest operations completed. Added `conu-relay --issue-credential --credentials-file`, `--replace`, and `--revoke-credential` for self-hosted manifest upsert/rotation/revocation without raw-token output, token-safe manifest lifecycle tests, docs/skill updates, and full validation. Next: managed hosted account APIs, online credential issuance/rotation workflows, hosted telemetry/dashboard pipelines, direct QUIC/NAT traversal, identity-key rotation, and non-Windows keychain support.
2026-05-21 - Post Phase 15 identity-key rotation completed. Added `conu security rotate identity --confirm-peer-refresh`, archived old signing/exchange keys with secret-backend protection, refreshed active peer-card material, old exchange-key decrypt compatibility during refresh, payload-safe CLI/JSON reports, docs/skill updates, and validation. Next: managed hosted identity/key administration, non-Windows keychain support, direct QUIC/NAT traversal, and managed hosted account APIs.
2026-05-21 - Post Phase 15 identity archive retirement completed. Added `conu security retire identity --confirm-peer-refresh-complete`, payload-safe archive retirement reports, active-key preservation with old-key decrypt compatibility removal after refresh, docs/skill updates, and validation. Next: managed hosted identity/key administration, non-Windows keychain support, direct QUIC/NAT traversal, and managed hosted account APIs.
2026-05-21 - Post Phase 15 TypeScript SDK wrapper completed. Added dependency-free `@conu/sdk` wrapper around installed `conu`/`conud`, stdin-only payload helpers, TypeScript declarations, smoke tests, a local example, docs/skill updates, and full validation. Next then: TypeScript receive helper or managed hosted relay/account work.
2026-05-21 - Post Phase 15 GitHub CI package validation completed. Added a Node 20 package job for `sdk/typescript` and `packaging/npm/conu-cli`, documented package checks as a CI gate, stabilized durable relay mailbox FIFO reload ordering and relay sync bounded-wait handling exposed by GitHub CI, and validated package/Python/Rust checks locally. Next then: TypeScript receive helper or managed hosted relay/account work.
2026-05-21 - Post Phase 15 TypeScript explicit receive helper completed. Added MCP-backed `receiveMessage()` and `receiveMessageBytes()` to the TypeScript SDK wrapper, kept normal metadata surfaces payload-safe, updated docs/skills/examples, and validated package/Python/fmt checks locally. Next: managed hosted relay/account work, npm/release publication, browser-native protocol support, or non-Windows keychain support.
2026-05-21 - Post Phase 15 release publishing workflow completed. Added release archive verification, package dry-runs, tag-driven GitHub Release asset upload, optional npm provenance publication, docs/skill updates, and local archive validation. Next: platform code signing/notarization, managed hosted relay/account work, or non-Windows keychain support.
2026-05-21 - Post Phase 15 non-Windows user-managed secret wrapping completed. Added `CONU_SECRET_WRAP_KEY_HEX`/`CONU_SECRET_WRAP_KEY_FILE` encrypted secret-field wrapping for non-Windows local keys and stored relay credentials, migration from plaintext-hex fields when configured, docs/skill updates, and GNU-toolchain validation. Next: native macOS Keychain/Linux Secret Service/HSM support or managed hosted relay/account work.
2026-05-21 - Post Phase 15 release artifact attestation hardening completed. Added GitHub artifact attestations for release archives/checksums, a publish-job verifier pass, required packaging-template archive checks, docs/skill updates, and full GNU-toolchain/package/release validation. Next: platform code signing/notarization or managed hosted relay/account work.
2026-05-21 - Post Phase 15 TypeScript browser boundary hardening completed. Added fail-closed browser-conditioned `@conu/sdk` exports, browser-native design docs, package/check coverage, docs/skill updates, and GNU-toolchain/package validation. Next: managed hosted relay/account auth before real browser-native protocol support, or direct transport if relay independence is more urgent.
2026-05-21 - Post Phase 15 native non-Windows secret storage completed. Added macOS Keychain and Linux Secret Service secret backends, native OS-secret reference files, migration/readback coverage, docs/smoke guidance, and full GNU-toolchain validation with macOS target compile coverage. Next: managed hosted relay/account auth, direct transport, or platform code signing.
2026-05-21 - Post Phase 15 platform signing and notarization completed. Added Windows Authenticode and macOS Developer ID/notarization release workflow gates, macOS ZIP asset naming for npm, Linux checksum plus GitHub-attestation policy docs, release verifier updates, docs/skill updates, and full GNU-toolchain/package/release validation. Next: configure signing secrets before the next tag, then prioritize managed hosted account auth or direct QUIC/NAT transport.
2026-05-21 - Post Phase 15 hosted relay account auth completed. Added account-scoped relay credential metadata, admin WebSocket frames, `CONU_RELAY_ADMIN_TOKEN`, online issue/rotate/revoke/audit commands with admin-token stdin, raw node-token local-only issuance after relay confirmation, fail-closed revoked/expired/missing credential behavior, token/hash redaction coverage, docs/skill updates, full GNU-toolchain validation, package checks, relay daemon smoke, and admin CLI smoke. Next: distributed hosted session/accounting state, hosted dashboards/abuse workflows, hosted tenant administration, direct QUIC/NAT transport, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 authenticated direct QUIC/NAT transport completed. Added Quinn-based direct listener/client support, trusted-peer encrypted probes, direct message and stream-chunk delivery, route selection only after live authenticated probes, relay fallback preservation, direct endpoint peer-card/SDK/MCP surfaces, docs/skill updates, and GNU-toolchain core validation. Next: distributed hosted session/accounting state, hosted dashboards/abuse workflows, hosted tenant administration, managed direct NAT traversal, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 distributed relay state/accounting foundation completed. Added metadata-only file-backed relay session state through `CONU_RELAY_SESSION_STATE_DIR`, relay restart same-node resume validation, cross-node resume fallback preservation, docs/skill/package updates, and full GNU-toolchain/package validation. Next: hosted dashboards/abuse workflows, managed direct NAT traversal, hosted tenant administration, distributed multi-instance session migration, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 managed direct NAT rendezvous foundation completed. Added static direct candidate source/kind/rendezvous metadata, explicit `nat_traversal_unavailable` reporting, invalid endpoint secret sanitization, CLI/MCP route surfaces, docs/skill updates, and full GNU-toolchain/package validation. Next: hosted dashboards/abuse workflows, ICE/STUN/TURN managed traversal, hosted tenant administration, distributed multi-instance session migration, and managed hosted identity/key administration.
2026-05-21 - Post Phase 15 hosted tenant admin foundation completed. Added `CONU_RELAY_TENANTS_FILE`, metadata-only tenant/node lifecycle commands, hosted permission and public key-id metadata, fail-closed admin issue/rotate and new-session authorization, docs/skill updates, CLI smoke, and full GNU-toolchain/package validation. Next: hosted dashboards/abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted relay abuse dashboard foundation completed. Added `CONU_RELAY_ABUSE_DIR`, metadata-only `.abuse` denial/enforcement counters, `conu-relay --abuse-audit`, payload-safe per-node/global audit output, credential/tenant deny, quota, rate-limit, session-expiry, mailbox-reject, and malformed-frame coverage, docs/skill updates, and GNU-toolchain targeted validation. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted relay dashboard snapshot completed. Added public metadata-only accounting audit support and `conu-relay --hosted-dashboard` to combine credential, tenant, accounting, and abuse summaries with account/node filters and JSON/text output without tokens, token hashes, session ids, private keys, payloads, ciphertext bodies, or frame contents. Updated docs/skills/plan and full GNU-toolchain/package validation passed. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 durable relay mailbox retention audit completed. Added public metadata-only durable mailbox audit support and `conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--json]` for file counts, byte totals, queue timestamp bounds, optional expired counts, invalid mailbox-file counts, and false display guards without printing stored frames, ciphertext bodies, tokens, token hashes, session ids, private keys, or payloads. Updated docs/skills/plan and full GNU-toolchain/package validation passed, including a CLI smoke against a temporary mailbox directory. Next: mailbox purge workflows, distributed hosted dashboards/adaptive abuse workflows, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 durable relay mailbox retention purge completed. Added `conu-relay --mailbox-purge --mailbox-dir <path> --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]`, dry-run and confirm-gated deletion of expired valid `.mailbox` files, aggregate metadata/reporting, display guards, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI smoke against a temporary mailbox directory. Next: relay-local scheduled mailbox retention purge, distributed hosted dashboards/adaptive abuse workflows, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 relay-local scheduled mailbox retention purge completed. Added `CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS` for opt-in relay-local expired valid `.mailbox` cleanup using the offline envelope TTL, required durable mailbox storage for scheduled purge, left invalid and display-guard-failed files untouched, updated docs/skills/plan, and completed full GNU-toolchain/package validation plus CLI help/config smoke. Next: distributed hosted dashboards/adaptive abuse workflows, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated hosted dashboard snapshot completed. Added `conu-relay --admin-hosted-dashboard --relay <endpoint> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]`, a relay admin `dashboard` control-plane action, metadata-only credential/tenant/accounting/abuse counters from the running relay, token-safe admin output, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI help smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay snapshots, distributed hosted mailbox retention orchestration, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated mailbox retention audit completed. Added `conu-relay --admin-mailbox-audit --relay <endpoint> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--json]`, a relay admin `mailbox_audit` control-plane action, metadata-only durable mailbox node/file/byte/timestamp/expiry counters from the running relay, token-safe admin output, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI help smoke. Next: distributed hosted mailbox retention orchestration beyond read-only single-relay audits, distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated mailbox retention purge completed. Added `conu-relay --admin-mailbox-purge --relay <endpoint> --admin-token-stdin --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]`, a relay admin `mailbox_purge` control-plane action, dry-run and confirm-gated expired valid `.mailbox` cleanup from the running relay, aggregate-only retention/purge counters, token-safe admin output, docs/skills/plan updates, full GNU-toolchain/package validation, and CLI help smoke. Next: distributed hosted mailbox retention orchestration beyond single-relay purge, distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 admin-gated hosted tenant lifecycle completed. Added relay admin `tenant_upsert`, `tenant_revoke`, `tenant_node_upsert`, `tenant_node_revoke`, and `tenant_audit` control-plane actions plus `conu-relay --admin-tenant-upsert`, `--admin-tenant-revoke`, `--admin-tenant-node-upsert`, `--admin-tenant-node-revoke`, and `--admin-tenant-audit` with `--admin-token-stdin`; online tenant updates modify only the configured relay tenant registry, return tenant/node/policy counts and display guards only, preserve hosted permission metadata as separate from local peer policy, fail closed for missing or revoked tenant records, and do not print admin tokens, raw node tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, frame contents, or manifest contents. Updated docs/skills/plan and validated with GNU `fmt`, workspace `check`, `clippy -D warnings`, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, and CLI help smoke. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant lifecycle/RBAC workflows beyond single-relay admin commands, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 scoped hosted admin-token RBAC completed. Added live-read `CONU_RELAY_ADMIN_TOKENS_FILE` hashed admin-token records with optional account ids, active/revoked status, optional expiry, and credentials/tenants/dashboard/mailbox-audit/mailbox-purge scopes while preserving `CONU_RELAY_ADMIN_TOKEN` as the full-admin compatibility path. Online admin requests now fail closed with `admin_scope_denied` for valid tokens outside their action or account boundary, account-scoped dashboard snapshots avoid global accounting/abuse counters without a node filter, account-scoped mailbox audit/purge requires an active tenant node, and admin outputs still avoid admin tokens, raw node tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, frame contents, and manifest contents. Updated docs/skills/plan and added scoped manifest coverage for credential, tenant, dashboard, mailbox-audit, and mailbox-purge paths. Validation passed with GNU `fmt`, workspace `check`, `clippy -D warnings`, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, and CLI help smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay snapshots, distributed tenant lifecycle/workflow automation beyond scoped single-relay admin tokens, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted account suspension workflow completed. Added relay admin `account_suspend`, `conu-relay --hosted-account-suspend`, and `conu-relay --admin-hosted-account-suspend` so one configured relay can revoke hosted tenant metadata first and then all credential records for that account while returning only account, credential, tenant, node, policy, path/endpoint, and display-guard metadata. Scoped admin tokens require both credentials and tenants scopes for this workflow; full-admin compatibility remains available. Updated docs/skills/plan and validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, workspace tests, Python compile, TypeScript/package checks, npm launcher check, diff check, conu-relay build, CLI help smoke, and a local hosted account-suspend CLI smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay snapshots, distributed tenant lifecycle/workflow automation beyond single-relay account suspension/scoped admin tokens, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 hosted abuse threshold report completed. Added local `conu-relay --abuse-threshold-report` and admin-gated `conu-relay --admin-abuse-threshold-report` over metadata-only abuse counters, with explicit max thresholds, count/max/exceeded JSON/text output, dashboard-scope admin authorization, payload-safe display guards, docs/skills/plan updates, targeted threshold tests, full GNU workspace validation, Python/package checks, diff check, conu-relay build, CLI help smoke, and local JSON threshold smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 abuse threshold fail-on-threshold mode completed. Added optional `--fail-on-threshold` to local and admin-gated abuse threshold reports, preserving stdout report output and returning exit code 3 only when configured thresholds are exceeded; updated docs/skills/plan and validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, focused threshold tests, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, CLI help smoke, and local exit-code smoke. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 abuse threshold policy files completed. Added reusable metadata-only `--thresholds-file` support to local and admin-gated abuse threshold reports, required versioned policy files with false display guards, kept CLI `--max-*` overrides and `--fail-on-threshold` behavior, updated docs/skills/plan, validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, focused threshold tests, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, CLI help smoke, and local policy-file exit-code smoke. PR #97 merged, issue #96 closed, and local/remote feature branches were preserved. Next: distributed hosted dashboards/adaptive abuse workflows beyond single-relay threshold reports, distributed tenant lifecycle/workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 mailbox retention policy files completed. Added reusable metadata-only `--retention-policy-file` support to local/admin mailbox audit and purge commands, required versioned policy files with optional `ttl_seconds`, optional `node_id`, and false display guards, kept CLI `--ttl-seconds`/`--node` overrides plus existing dry-run/confirm purge safety, updated docs/skills/plan, and validated with GNU `fmt --check`, workspace `check`, `clippy -D warnings`, focused mailbox tests, workspace tests, Python compile, TypeScript/package checks, diff check, conu-relay build, CLI help smoke, and local policy-file audit/purge smoke. Next: distributed hosted mailbox retention orchestration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, or ICE/STUN/TURN managed traversal.
2026-05-21 - Post Phase 15 relay session-state audit completed. Added payload-safe local `--session-audit` and admin-gated `--admin-session-audit`, relay admin `session_audit` frames, `scope_sessions` scoped admin-token RBAC, account-scoped node/tenant guardrails, docs/skills/plan updates, full GNU workspace validation, Python/package checks, conu-relay build, CLI help smoke, local session-audit smoke, and diff check. Next: distributed multi-instance session migration, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted admin-token manifest audit completed. Added payload-safe local `conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <id>] [--json]`, metadata-only admin-token audit structs/counts, host:port-only bind parser hardening, stricter false display guard support for key material/session id/ciphertext markers, docs/skills/plan updates, full GNU workspace validation, Python/package checks, conu-relay build, CLI help smoke, local admin-token audit smoke, and diff check. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted relay readiness preflight completed. Added payload-safe local `conu-relay --hosted-readiness` to combine credential, admin-token, tenant, session-state, mailbox, accounting, abuse, and bind checks with JSON/text output, warning counts, display guards, and optional `--fail-on-warning` exit code 3 after preserving stdout. Updated docs/skills/plan and validated with GNU fmt/check/clippy/workspace tests, focused readiness test, Python compile, TypeScript/package checks, conu-relay build, local readiness/fail-on-warning smoke, and diff check. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 GitHub Actions Node 24 runtime hardening completed. Updated CI and release workflows to `actions/checkout@v6` and `actions/setup-node@v6`, confirmed both current action releases declare Node 24 runtimes, updated release checklist, and validated YAML parse, package checks, no stale v4/v5 action references, and diff check. Next: release workflow hardening, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 release artifact action runtime hardening completed. Updated release artifact provenance/upload/download steps to `actions/attest@v4.1.0`, `actions/upload-artifact@v7.0.1`, and `actions/download-artifact@v8.0.1` after confirming those upstream action metadata files declare Node 24 runtimes. Updated release checklist with the self-hosted runner caveat and validated YAML parse, package checks, no stale artifact action references, and diff check. Next: release workflow smoke, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 release workflow smoke validation completed. Ran `Release Artifacts` through `workflow_dispatch` on `main` after the Node 24 action updates; package checks and all five platform artifact builds passed, artifact uploads were present, GitHub Release/npm publication jobs skipped as expected on the non-tag run, and post-merge CI was green. Next: tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 GitHub Actions runner image pinning completed. Pinned CI/release Windows jobs to `windows-2025-vs2026`, pinned macOS arm64 jobs to `macos-15`, kept macOS x64 release on `macos-15-intel`, removed floating Windows/macOS workflow labels, updated release checklist, validated local workflow/package checks, passed PR CI on the explicit labels, and passed a branch `Release Artifacts` smoke run across all five platform builds. Next: revisit the Windows label after GitHub completes the June 2026 migration, tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 Node LTS package hardening completed. Moved CI/release npm package jobs to Node 24, restricted `@conu/sdk` and `@conu/cli` package engines to Node 22 or Node 24 LTS, documented the supported LTS policy, validated local package checks/dry-runs, passed PR CI, passed a branch `Release Artifacts` smoke run across all five platform builds, merged PR #116, closed issue #115, and preserved local/remote branches. Next: revisit the Node engine range when the next Node LTS line is promoted, tagged release signing/publication verification when release secrets are configured, distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted readiness policy files completed. Added `--retention-policy-file`, `--thresholds-file`, and inline `--max-*` support to payload-safe local `conu-relay --hosted-readiness`, reused existing metadata-only retention/threshold policy parsers and CLI override semantics, added threshold checks/exceeded counts to text/JSON output, made exceeded thresholds contribute to warnings and `--fail-on-warning`, updated docs/plan, validated local fmt/diff/Python/package checks, passed PR #118 CI across Packages plus Rust on Ubuntu/Windows/macOS, merged PR #118, closed issue #117, and preserved local/remote branches. Next: distributed hosted dashboards/adaptive abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 tagged release preflight hardening completed. Added a fail-closed `Release Tag Preflight` for `v*` releases requiring Windows signing, macOS signing/notarization, and `NPM_TOKEN` before package checks/builds, changed tagged npm publish steps from warning-and-skip to errors, preserved unsigned non-tag workflow_dispatch smoke builds, updated release docs/plan, passed local workflow/package/Rust GNU checks with documented local linker blockers, passed PR #121 CI, and passed a branch `Release Artifacts` smoke run across preflight, package checks, attestations/uploads, and five platform builds. Next: configure release signing secrets plus `NPM_TOKEN` before the next real tag, then continue hosted/distributed product gaps.
2026-05-22 - Post Phase 15 release version consistency gate completed. Added `scripts/verify-release-versions.py` for shared Cargo/npm package version checks and `v*` tag-to-package-version enforcement, wired it into CI and Release Artifacts package gates before npm checks/dry-runs, updated release/package docs, validated local good and fail-closed tag paths, passed PR #123 CI, and passed a branch `Release Artifacts` smoke across release preflight, package checks, attestations/uploads, and five platform builds. Next: configure release signing secrets plus `NPM_TOKEN` before the next real tag, then continue hosted/distributed product gaps.
2026-05-22 - Post Phase 15 hosted fleet dashboard snapshot completed. Added `conu-relay --hosted-fleet-dashboard --fleet-file <path>` for guarded multi-relay metadata aggregation across credential, tenant, session-state, mailbox, accounting, and abuse stores; required versioned manifest false display guards; kept output to relay names, source paths, filters, aggregate counters, and display guards; updated docs/skills/plan; passed local GNU workspace check/clippy, package/Python checks, PR #125 CI, and a branch `Release Artifacts` smoke across all five platform builds. Next: adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet dashboard threshold policy completed. Added reusable `--thresholds-file`, inline `--max-*`, and `--fail-on-threshold` support to `conu-relay --hosted-fleet-dashboard`, evaluating only aggregate fleet abuse counters and returning exit code 3 only when requested and exceeded; preserved stdout and payload-safe output boundaries, updated docs/skills/plan, and passed local GNU check/clippy, workspace check/clippy, package/Python checks, version gate, diff check, PR #127 CI, and a branch `Release Artifacts` smoke across all five platform builds. Local targeted test/run smoke remained blocked by missing `dlltool.exe`; GitHub Windows CI covered the test path. Next: merge PR #127 without deleting branches, then adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet dashboard mailbox retention policy completed. Added reusable `--retention-policy-file`, `--ttl-seconds`, and `--fail-on-retention` support to `conu-relay --hosted-fleet-dashboard`, reused metadata-only durable mailbox retention policy files with required false display guards, preserved CLI `--node` as the global source filter, added aggregate retention status/count/byte reporting, failed closed for missing mailbox sources or missing effective TTL under fail-on-retention, updated docs/skills/plan, and kept output payload-safe. GitHub PR CI and branch Release Artifacts smoke passed; local Rust runtime/test execution remains blocked on this Windows workstation until `dlltool.exe` is installed. Next: merge PR #129 without deleting branches, then continue with adaptive hosted abuse workflows, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration beyond read-only fleet gates, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet abuse response plan completed. Added `conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path> [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-action]`, reusing the guarded fleet manifest and metadata-only threshold policy parser to map aggregate fleet abuse threshold breaches to static operator categories (`admin_access`, `credential_tenant_access`, `traffic_pressure`, `delivery_health`, and `mailbox_pressure`) without mutating tenants, credentials, relay config, mailbox files, or remote relays. Output remains aggregate/per-relay metadata only with false display guards and no tokens, token hashes, session ids, payloads, ciphertext bodies, frame contents, manifest contents, or policy contents. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, Python compile, release version gate, and `git diff --check`; targeted Rust test/run smoke remains blocked locally by missing `dlltool.exe`, so PR CI must cover runtime tests. Next: open and merge PR for issue #132 without deleting branches, then continue with distributed hosted dashboards/adaptive abuse automation beyond guarded response plans, distributed tenant workflow automation, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet account suspension completed. Added `conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]` for guarded local account suspension across manifest-listed credential/tenant stores. The command reuses the hosted fleet manifest, rejects partial credential/tenant source entries, preflights every complete local source before confirmed mutation, revokes tenant metadata before account credential records, never contacts remote relays, and reports only aggregate/per-relay account, credential, tenant, node, policy, path, mode, and display-guard metadata. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, and `git diff --check`; targeted Rust test/run smoke remains blocked locally by missing `dlltool.exe`, so PR CI covered runtime tests. PR #135 merged, issue #134 closed, main CI and main `Release Artifacts` smoke passed, and the local/remote `fleet-account-suspension` branches were preserved. Next: continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet account audit/suspension, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet account audit completed. Added `conu-relay --hosted-fleet-account-audit <account-id> --fleet-file <path> [--json] [--fail-on-warning]` for read-only credential/tenant consistency checks across the guarded fleet manifest. The command reports per-relay/aggregate credential and tenant counts, source coverage, warning categories, paths, and display guards only; it does not mutate files, contact remote relays, print manifest contents, or expose tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, or frame contents. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, and `git diff --check`; targeted Rust runtime test remains blocked locally by missing `dlltool.exe`, so PR CI covered runtime tests. PR #139 merged, issue #138 closed, branch and main CI passed, branch and main `Release Artifacts` smoke passed, and the local/remote `fleet-account-audit` branches were preserved. Next: continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet account audit/suspension, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet account node audit completed. Added optional `--node <node-id>` support to `conu-relay --hosted-fleet-account-audit <account-id> --fleet-file <path> [--node <node-id>] [--json] [--fail-on-warning]`, reusing the guarded fleet manifest for read-only account/node credential and tenant-node consistency checks before tenant workflow mutation. The command now reports the selected node filter in text/JSON output, narrows credential and tenant-node counts when requested, and adds node-specific warning categories without mutating files, contacting remote relays, printing manifest contents, or exposing tokens, token hashes, private keys, session ids, payloads, ciphertext bodies, or frame contents. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, and `git diff --check`; targeted Rust runtime test remains blocked locally by missing `dlltool.exe`, so PR CI covered runtime tests. PR #141 merged, issue #140 closed, branch and main CI passed, branch and main `Release Artifacts` smoke passed, and the local/remote `fleet-account-node-audit` branches were preserved. Next: continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet account/node audit and account suspension, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet account node suspension completed. Added optional `--node <node-id>` support to `conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file <path> [--node <node-id>] (--dry-run|--confirm) [--json]`, preserving account-wide behavior while adding node-scoped dry-run/confirm output. The command validates the node filter, rejects partial credential/tenant sources, preflights every complete local source before confirmed mutation, revokes tenant metadata before account credentials in account-wide mode, revokes tenant-node metadata before matching node credentials in node mode, never contacts remote relays, and reports only aggregate/per-relay account, node, credential, tenant, policy, path, mode, and display-guard metadata. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, `git diff --check`, and `codex review --uncommitted`; the focused Rust runtime test `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_account_suspend_parser_report_and_renderers_are_metadata_only -- --nocapture` remains blocked locally because `dlltool.exe` is missing while compiling `getrandom`/`windows-sys`, so PR CI covered runtime tests. PR #144 merged, issue #143 closed, branch and main CI passed, branch and main `Release Artifacts` smoke passed, and the local/remote `fleet-account-node-suspension` branches were preserved. Next: continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet account/node audit and suspension, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet tenant-node lifecycle completed. Added guarded local `conu-relay --hosted-fleet-tenant-node-upsert <account-id> <node-id> --fleet-file <path> ... (--dry-run|--confirm) [--json]` and `conu-relay --hosted-fleet-tenant-node-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]`, reusing the hosted fleet manifest across configured local `tenants_file` sources. The workflow requires explicit dry-run or confirm, preflights every tenant source before confirmed mutation, rejects missing/inactive accounts and node ownership collisions, never contacts remote relays, and reports only aggregate/per-relay tenant-node counts, requested permission booleans, key-id presence booleans, paths, mode/status, and display guards. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, `git diff --check`, and `codex review --uncommitted`; the focused Rust runtime test `cargo +stable-x86_64-pc-windows-gnu test -p conu-relay hosted_fleet_tenant_node_lifecycle_parser_report_and_renderers_are_metadata_only -- --nocapture` remains blocked locally because `dlltool.exe` is missing while compiling `getrandom`/`windows-sys`, so PR #147 CI covered runtime tests on Ubuntu, macOS, and Windows. PR #147 merged, issue #146 closed, branch and main CI passed, main `Release Artifacts` smoke passed, and the local/remote `fleet-tenant-node-lifecycle` branches were preserved. Next: continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-22 - Post Phase 15 hosted fleet credential revoke completed. Added guarded local `conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]`, reusing the hosted fleet manifest across configured local `credentials_file` sources. The command requires explicit dry-run or confirm, preflights every credential source before confirmed mutation, requires exactly one target account/node credential in every source, rejects node ownership collisions and duplicate node records, never contacts remote relays, and reports only aggregate/per-relay credential counts, paths, account/node ids, mode/status, and display guards. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, `git diff --check`, and `codex review --uncommitted`; the focused Rust runtime test remains blocked locally because `dlltool.exe` is missing while compiling `getrandom`/`windows-sys`, so PR #150 CI covered runtime tests on Ubuntu, macOS, and Windows. PR #150 merged, issue #149 closed, main CI passed, main `Release Artifacts` smoke passed, and the local/remote `fleet-credential-revoke` branches were preserved. Next: continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet credential and tenant metadata tools, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-23 - Post Phase 15 hosted fleet tenant account lifecycle completed. Added guarded local `conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]` and `conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]`, reusing the hosted fleet manifest across configured local `tenants_file` sources. The workflow requires explicit dry-run or confirm, preflights every tenant source before confirmed mutation, allows confirmed upsert to create missing tenant files, requires the account to exist before revoke, never contacts remote relays, and reports only aggregate/per-relay tenant account counts, paths, mode/status, and display guards. Updated README, architecture, production/readiness, distribution/hosting, hosted relay, SDK/MCP, release checklist, security docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with `cargo fmt --all -- --check`, GNU relay/workspace `check`, GNU relay/workspace `clippy -D warnings`, TypeScript/package checks, npm launcher check, Python compile, release version gate, `git diff --check`, and `codex review --uncommitted`; the focused Rust runtime test remains blocked locally because `dlltool.exe` is missing while compiling `getrandom`/`windows-sys`, so PR #154 CI must cover runtime tests. Next: merge PR #154 without deleting branches, then continue with distributed hosted dashboards/adaptive abuse automation, remote/distributed tenant workflow automation beyond guarded local fleet tenant lifecycle, distributed multi-instance session migration, managed hosted identity/key administration, distributed hosted mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-23 - Post Phase 15 release artifact verifier bounds completed. Reworked release artifact verification to stream checksum hashing and archive inspection, read only manifest bodies, enforce explicit archive/checksum/member/manifest/count/uncompressed-size limits, require strict checksum archive-name matching, reject duplicate normalized paths, encrypted/corrupt ZIP members, unsupported members, forbidden state paths, and data-bearing ZIP directories, and added fail-closed regression fixtures wired into CI, Release Artifacts package checks, and the full production-readiness package gate. Updated release, distribution, production-readiness, packaging, repo memory, guardrail, security checklist, and plan docs. Local validation passed with Python compile, release version gate, verifier regression checks, existing dist artifact verification, workflow YAML parse, npm package verifier, TypeScript/package checks, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review --uncommitted`. PR #179 CI passed after rerunning a transient macOS checkout failure, branch `Release Artifacts` passed, and the local/remote `release-artifact-verifier-bounds` branches were preserved. Next: continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-23 - Post Phase 15 npm installer strict checksum verification completed. Added a shared npm checksum helper that requires strict SHA-256 lines naming the downloaded archive, hashes archives in chunks before extraction, and rejects loose, wrong-archive, extra-content, bad-digest, and mismatched checksum files. Extended npm launcher package checks and download-limit smoke coverage, updated npm package content allowlists, and updated release/distribution/production-readiness/packaging/security docs. Local validation passed with Node syntax checks, checksum fixture checks, npm launcher package check, npm package dry-run content verification, TypeScript SDK check, local npm download smoke against `dist`, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review --uncommitted`. PR #181 CI and branch `Release Artifacts` passed, and the local/remote `npm-installer-strict-checksum` branches were preserved. Next: continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-23 - Post Phase 15 npm installer extracted binary selection completed. Added a shared npm extraction-selection helper that requires either the rootless Windows release layout or the expected `conu-<version>-<platform>/` release root, requires `manifest.toml`, installs only exact `bin/<binary>` paths, and rejects duplicate or misplaced binary names elsewhere in the extracted tree. Wired rooted/rootless/misplaced/duplicate regression fixtures into `npm run check --prefix packaging/npm/conu-cli`, updated npm package content allowlists, and updated release/distribution/production-readiness/packaging/security docs. Local validation passed with Node syntax checks, extraction fixture checks, npm launcher package check, npm package dry-run content verification, TypeScript SDK check, local npm download smoke against `dist`, production-readiness `-SkipRust -SkipSmokes`, and `git diff --check`; `codex review --uncommitted` timed out twice locally, so manual scoped diff review plus PR #183 CI and branch `Release Artifacts` smoke covered the review gates. PR #183 merged without deleting branches, main CI and main `Release Artifacts` passed, and the `npm-installer-extract-root-guard` branch was preserved. Next: continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 npm installer extracted tree bounds completed. Added bounded post-extraction tree traversal to the npm installer binary-selection helper with a 10,000 entry limit, depth 64 limit, one-pass expected binary-name collection, and fail-closed regression fixtures for entry overflow, depth overflow, and invalid bounds. Preserved rootless/rooted release-root selection, exact `bin/<binary>` installs, and duplicate/misplaced binary rejection. Updated README, user install, release/distribution/production-readiness/packaging/security docs, repo memory, guardrails, and plan docs. Local validation passed with Node syntax checks, extraction fixture checks, npm launcher package check, npm package dry-run content verification, TypeScript SDK check, local npm download smoke against `dist`, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review --uncommitted`. PR #185 carries the implementation on branch `npm-installer-extract-bounds`; branches must be preserved after merge. Next: after PR #185 and main verification gates pass, continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 npm installer archive-member preflight completed. Added npm installer archive-member preflight checks for more than 10,000 members, duplicate normalized paths, and forbidden local state/build/package paths before extraction. Added fail-closed regression fixtures for excessive members, duplicate paths, `.conu`/`security` state paths, and `runtime/node.toml`, and updated README, user install, release/distribution/production-readiness/packaging/security docs, repo memory, guardrails, and plan docs. Local validation passed with Node syntax checks, archive preflight fixture checks, npm launcher package check, npm package dry-run content verification, TypeScript SDK check, local npm download smoke against `dist`, production-readiness `-SkipRust -SkipSmokes`, and `git diff --check`; `codex review --uncommitted` timed out once and then failed inside the nested review sandbox, so manual scoped diff review plus PR CI/release gates must cover review. PR #187 carries the implementation on branch `npm-installer-archive-preflight-bounds`; branches must be preserved after merge. Next: after PR #187 and main verification gates pass, continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 release artifact smoke binary preflight completed and merged. PR #193 merged to `main` at `321359293396bd6b95d69c63f1d544afed707c91`, Issue #192 is closed, and branch `release-artifact-smoke-binary-preflight` is preserved. Added explicit release artifact smoke preflight checks that require the extracted `bin/` directory and every expected binary path to be a regular non-symlink file before chmod or execution. Added `scripts/check-release-artifact-smoke-preflight.py`, wired it into CI package checks, Release Artifacts package checks, and the full production-readiness package gate, and updated README, release/distribution/production-readiness/packaging docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, release artifact smoke preflight regression, workflow YAML parse, release version gate, release artifact verifier regression, npm local-smoke preflight regression, npm package content verification, npm launcher check, TypeScript SDK check, existing `dist` artifact verification, release artifact smoke, npm launcher local smoke, rerun npm launcher download smoke after a transient Windows `EBUSY`, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review --uncommitted`. PR CI, branch `Release Artifacts`, main CI, and main `Release Artifacts` all passed. Next: continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 npm publish conflict preflight completed and merged. PR #195 merged to `main` at `14f73b65808ff204b1e23f3ee1980c1b7c89dcb1`, Issue #194 is closed, and branch `npm-publish-conflict-preflight` is preserved. Added `scripts/check-npm-publish-preflight.py` for npm package publish metadata, optional token-env, and optional live registry availability checks; added `scripts/check-npm-publish-preflight-regression.py` for duplicate-version, registry-failure, and missing-token behavior; wired both into CI package checks, Release Artifacts package checks, and the production-readiness package gate; wired tagged npm publication to run the registry/token preflight before either package is published; and updated npm package metadata plus README, release/distribution/production-readiness/packaging docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, workflow YAML parse, release version gate, npm package content verification, npm publish metadata preflight, npm publish preflight regression, live npm registry availability for `@conu/cli@0.1.0` plus `@conu/sdk@0.1.0`, npm launcher check, TypeScript SDK check, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review --uncommitted`. PR #195 CI, branch `Release Artifacts`, main CI, and main `Release Artifacts` all passed. Next: continue with signing/npm secret configuration, OS package-manager publishing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 package-manager manifest generation completed and merged. PR #197 merged to `main` at `4f4e25dd46bbbce3d00d0227ccdb8edeb80c6f9d`, Issue #196 is closed, and branch `package-manager-manifest-preflight` is preserved. Added `scripts/generate-package-manager-manifests.py` to generate package-native Homebrew and Scoop manifests from platform release assets plus strict sibling `.sha256` files after recomputing archive hashes, added `scripts/check-package-manager-manifests.py` for rooted/rootless Windows ZIP, Homebrew-compatible license/name/test output, semver prerelease plus build metadata, missing checksum, wrong checksum archive-name, checksum mismatch, and forbidden output regressions, wired the regression into CI, Release Artifacts package checks, and the production-readiness package gate, wired tagged GitHub Release publication to upload generated `conu.rb` and `conu.json` after release asset verification, and updated release/distribution/production-readiness/packaging docs plus repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, package-manager regression, workflow YAML parse, release version gate, release artifact verifier regression, release artifact smoke preflight regression, npm package content verification, npm launcher check, TypeScript SDK check, npm publish preflight, npm publish preflight regression, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review --uncommitted`; PR #197 CI, branch `Release Artifacts`, main CI, and main `Release Artifacts` all passed. Next: continue with signing/npm secret configuration, package-manager repository submission, winget/Chocolatey/apt/rpm packaging, detached Linux package signatures, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 Windows package-manager manifest preflight completed and merged. PR #199 merged to `main` at `e9230e129b5c2ebb1b0f24cc7db0f7b0b79c3176`, Issue #198 is closed, and branch `windows-package-manifest-preflight` is preserved. Extended package-manager manifest generation to produce winget singleton YAML and deterministic Chocolatey `conu.<version>.nupkg` packages from the verified Windows release ZIP plus strict sibling `.sha256`, added tag validation, rooted/rootless Windows archive handling, Chocolatey install/uninstall scripts with shim cleanup, package body forbidden-output scans, and rootless/rooted/prerelease regression coverage. Updated release/distribution/production-readiness/packaging docs, release notes, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, package-manager regression, winget validation, Chocolatey noop install checks for rootless/rooted/prerelease packages, workflow YAML parse, release version gate, release artifact verifier/smoke regressions, npm package content verification, npm launcher and TypeScript SDK checks, npm publish preflight checks, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and final `codex review -c sandbox_mode="danger-full-access" --uncommitted`; PR #199 CI, branch `Release Artifacts`, post-merge main CI, and post-merge main `Release Artifacts` all passed. Next: continue with signing/npm secret configuration, package-manager repository submission, apt/rpm packaging, detached Linux package signatures, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 unsigned APT repository metadata generation completed and merged. PR #207 merged to `main` at `f2f7c993e658b31d4a77c3c45059a12fb2f7c986`, Issue #206 is closed, and branch `apt-repository-metadata` is preserved. Added explicit `--build-apt-repository-metadata` generation for deterministic unsigned `conu-<debian-version>-apt-repository-metadata.zip` bundles containing `Packages`, `Packages.gz`, `Release`, and README files for generated `.deb` assets plus a strict `.sha256` sidecar; wired tagged GitHub Release publication to upload the bundle with package-manager outputs and unsigned RPM assets; and updated release/distribution/production-readiness/packaging docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, package-manager regression on Windows and WSL Ubuntu, release version gate, release artifact verifier/smoke preflight regressions, npm package content verification, npm publish preflight/regression, npm launcher local-smoke preflight regression, TypeScript/package checks, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and `codex review -c sandbox_mode="danger-full-access" --uncommitted`; PR #207 CI and branch `Release Artifacts` passed. Next: continue with signed APT/RPM repository publication, package-manager repository submission, detached Linux package signatures, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 unsigned RPM repository metadata generation completed and merged. PR #209 merged to `main` at `9e2a3f475250363997d6006c278c3f4ff2f7b85d`, Issue #208 is closed, and branch `rpm-repository-metadata` is preserved. Added explicit `--build-rpm-repository-metadata` generation for unsigned `conu-<rpm-version>-rpm-repository-metadata.zip` bundles containing `README.txt` and `createrepo_c` `repodata/*` for generated `x86_64` and `aarch64` RPM release assets plus a strict `.sha256` sidecar, without embedding RPM payloads. Wired CI/release package jobs to install `createrepo-c`, wired tagged GitHub Release publication to upload the bundle with package-manager outputs and unsigned APT/RPM assets, and updated release/distribution/production-readiness/packaging docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, package-manager regression on Windows and WSL Ubuntu, release version gate, release artifact verifier/smoke preflight regressions, npm package content verification, npm publish preflight/regression, npm launcher local-smoke preflight regression, TypeScript/package checks, production-readiness `-SkipRust -SkipSmokes`, `git diff --check`, and targeted manual review after `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out; PR #209 CI and branch `Release Artifacts` passed. Next: continue with signed APT/RPM repository publication, package-manager repository submission, detached Linux package signatures, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 Linux detached release signatures completed and merged. PR #211 merged to `main` at `a3795510370876f5ef0a27b873f70790f23d3923`, Issue #210 is closed, and branch `linux-detached-signatures` is preserved. Added `scripts/sign-linux-release-assets.py` to create and verify armored detached `.asc` signatures for Linux archives, generated Debian/RPM packages, and generated APT/RPM repository metadata ZIPs from maintainer-provided GPG secrets in a temporary keyring. Added `scripts/check-linux-release-signing.py` with an ephemeral GPG-key regression that verifies generated signatures, proves non-Linux/checksum/manifest assets are not signed, and proves missing signing secrets fail closed. Wired CI package checks, Release Artifacts package checks, tagged release secret preflight, GitHub Release asset signing, local production-readiness checks, README, release/distribution/production-readiness/packaging/user docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, Windows signing-regression skip when `gpg` is unavailable, WSL signing regression with real GPG, package-manager regression on Windows and WSL Ubuntu, release version gate, release artifact verifier/smoke preflight regressions, npm package content verification, npm publish preflight/regression, npm launcher local-smoke preflight regression, TypeScript/package checks, production-readiness `-SkipRust -SkipSmokes`, workflow YAML parse, `git diff --check`, and targeted manual review after `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out; PR #211 CI and branch `Release Artifacts` passed. Next: continue with signed APT/RPM repository publication, package-manager repository submission, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 signed Linux repository metadata completed and merged. PR #213 merged to `main` at `ac867bcb3d34ad78acb6d660c3443424b2eb22d7`, Issue #212 is closed, and branch `signed-linux-repository-metadata` is preserved. Added `scripts/sign-linux-repository-metadata.py` to add and verify native APT `InRelease` and `Release.gpg` signatures plus RPM `repodata/repomd.xml.asc` signatures from maintainer-provided GPG secrets in a temporary keyring, then refresh the metadata ZIP `.sha256` sidecars before detached ZIP signing. Added `scripts/check-linux-repository-signing.py` with an ephemeral GPG-key regression that verifies native signatures, proves metadata ZIP sidecars are updated, proves unrelated release assets are not mutated, and proves missing signing secrets fail closed. Wired CI package checks, Release Artifacts package checks, tagged GitHub Release publication before detached Linux asset signing, local production-readiness checks, release/distribution/production-readiness/packaging docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, Windows GPG-regression skips when `gpg` is unavailable, WSL repository-signing and release-signing regressions with real GPG, package-manager regression on Windows and WSL Ubuntu, release version gate, release artifact verifier/smoke preflight regressions, npm package content verification, npm publish preflight/regression, npm launcher local-smoke preflight regression, TypeScript/package checks, production-readiness `-SkipRust -SkipSmokes`, workflow YAML parse, `git diff --check`, and targeted manual review after `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out; PR #213 CI and branch `Release Artifacts` passed. Next: continue with package-manager repository submission, hosted repository publication, RPM package payload signing, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-24 - Post Phase 15 RPM package payload signing completed and merged. PR #217 merged to `main` at `d6976db94148a2583bf1fd978b0dba68b45c9b77`, Issue #216 is closed, and branch `rpm-package-payload-signing` is preserved. Added native RPM package payload signing for generated conU RPM release assets, refreshed `.rpm.sha256` sidecars after signing, generated RPM repository metadata from the signed package bytes, and wired regression coverage into CI, Release Artifacts, local production-readiness checks, release docs, packaging docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, package-manager regression on Windows and WSL Ubuntu, local clean skips for RPM signing when native tooling is unavailable, WSL GPG release/repository/public-key checks with real GPG, release version/artifact/npm/package checks, TypeScript and npm launcher checks, production-readiness `-SkipRust -SkipSmokes`, workflow YAML parse, and `git diff --check`; `codex review -c sandbox_mode="danger-full-access" --uncommitted` timed out locally, so manual scoped review plus PR CI and branch `Release Artifacts` covered review gates. PR #217 CI and branch `Release Artifacts` passed. Next: continue with hosted APT/RPM repository publication, package-manager repository submission, npm package publication, auto-update policy, maintainer key fingerprint trust policy, managed public relay hosting, distributed hosted dashboards/adaptive abuse automation, distributed multi-instance session migration, managed hosted identity/key administration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, or ICE/STUN/TURN managed traversal.
2026-05-25 - Post Phase 15 GitHub Release asset publication preflight completed and merged. PR #237 merged to `main` at `0c5c2838a4a297454c99470af626e1a34f8ac46a`, Issue #236 is closed, and branch `github-release-assets-preflight` is preserved. Added a metadata-only GitHub Release asset publication preflight that paginates release assets by release id and verifies required platform archives, checksum sidecars, Linux detached signatures, generated package-manager files, public Linux GPG key assets, hosted Linux repository bundles, and hosted repository site artifacts before tagged npm publication can access npm. Added fixture regressions for missing, duplicate, draft, tag-mismatched, bad size/state, forbidden state/secret-looking asset names, paginated asset loading, and output that omits unrelated release body/download URL fields. Wired CI, Release Artifacts, local production-readiness, tagged npm publish, docs, repo memory, guardrails, security checklist, and plan updates. Local validation passed with Python compile, regression, workflow YAML parse, production-readiness `-SkipRust -SkipSmokes`, and `git diff --check`; PR #237 CI and branch `Release Artifacts` passed. Next: run post-merge main CI and main Release Artifacts, then continue with real signing/npm secret configuration, a signed `v*` release, npm publication, package-manager repository submissions, custom DNS/TLS/cache policy, auto-update, managed public relay hosting, distributed hosted dashboards/accounting/adaptive abuse automation, distributed multi-instance session migration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, managed hosted key administration, or ICE/STUN/TURN managed traversal.
2026-05-25 - Post Phase 15 hosted Linux repository cache policy artifacts completed and merged. PR #241 merged to `main` at `2f667a3a3af007ac25acb25fc7b5337a4aaea285`, Issue #240 is closed, and branch `hosted-linux-repository-cache-policy` is preserved. Added generated `cache-policy.json` plus `_headers` Cache-Control rules to the hosted repository site artifact, linked them from `repository.json`, and validated mutable metadata, package-manager index, and immutable versioned package/download cache classes during Pages prep. Added regression coverage for missing cache artifacts, invalid display guards, forbidden markers, and `_headers`/`cache-policy.json` drift. Local validation passed with Python compile, hosted site and Pages regressions, production-readiness `-SkipRust -SkipSmokes`, and `git diff --check`; PR #241 CI, branch `Release Artifacts`, post-merge main CI, and post-merge main `Release Artifacts` passed. Next: continue with real signing/npm secret configuration, a signed `v*` release, npm publication, package-manager repository submissions, custom DNS/TLS endpoint activation with generated cache policy application, auto-update, managed public relay hosting, distributed hosted dashboards/accounting/adaptive abuse automation, distributed multi-instance session migration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, managed hosted key administration, or ICE/STUN/TURN managed traversal.
2026-05-25 - Post Phase 15 package-manager submission bundle completed and merged. PR #261 merged to `main` at `0579593bf50cdc31b10db9819d979776014207ce`, Issue #260 is closed, and branch `package-manager-submission-bundle` is preserved. Added deterministic `conu-<version>-package-manager-submissions.zip` generation with strict checksum sidecars, safe repository-ready paths, signed-target validation for `.asc` files, public Linux signing handoff files, forbidden secret/payload literal guards, and false display guards. Wired regression coverage into CI package checks, Release Artifacts package checks, tagged release preparation/signing, GitHub Release asset publication preflight, production-readiness checks, release/package docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, package-manager submission regression, package-manager manifest regression, GitHub Release asset publication regression, workflow YAML parse, production-readiness `-SkipRust -SkipSmokes`, and `git diff --check`; local Windows GPG/RPM native-tool checks skipped cleanly where unavailable. PR #261 CI passed, and branch `Release Artifacts` run https://github.com/imthegoodboy/conU/actions/runs/26382945548 passed. Next: continue with real signing/npm secret configuration, the next signed `v*` release, npm publication, external package-manager repository submissions, managed public relay hosting, distributed hosted dashboards/accounting/adaptive abuse automation, distributed multi-instance session migration, remote/distributed tenant workflows, remote/cross-region mailbox retention orchestration, managed hosted key administration, or ICE/STUN/TURN managed traversal.
2026-05-25 - Post Phase 15 GitHub workflow permissions readiness completed and merged. PR #278 merged to `main` at `1a8e026d00a44bce85e85788782c432310965ece`, Issue #277 is closed, and branch `github-workflow-permissions-readiness` is preserved. Added a payload-safe workflow permissions readiness audit for explicit top-level `contents: read`, forbidden high-risk trigger events, and expected release job write scopes; added dependency-free parser fallback and regression coverage; wired the gate into CI, release preflight, production readiness checks, docs, repo memory, guardrails, security checklist, and plan docs. Local validation passed with Python compile, workflow-permissions regression, workflow-permissions JSON readiness, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #278 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real signing/npm secrets tracked by Issue #274, then run full production readiness with branch protection, Actions admission, workflow permissions, and tagged release readiness before cutting a production `v*` tag.
2026-05-25 - Post Phase 15 GitHub repository security readiness completed and merged. PR #280 merged to `main` at `5b453e9ba05d1293f96fe560232b47eb13070c92`, Issue #279 is closed, and branch `github-repository-security-readiness` is preserved. Added a payload-safe live repository security readiness audit for Dependabot vulnerability alerts/security updates, secret scanning, push protection, open Dependabot alert counts, open secret-scanning alert counts, and false display guards; added regression coverage; wired the gate into CI, release preflight, production readiness checks, docs, repo memory, guardrails, security checklist, and plan docs; and enabled live Dependabot vulnerability alerts/security updates for `imthegoodboy/conU`. Local validation passed with Python compile, repository-security regression, repository-security JSON readiness, workflow-permissions regression/JSON readiness, workflow YAML parse, production-readiness `-SkipRust -SkipSmokes -CheckGitHubBranchProtection -CheckGitHubActionsPermissions -CheckGitHubWorkflowPermissions -CheckGitHubRepositorySecurity -GitHubRepo imthegoodboy/conU`, and `git diff --check`; PR #280 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real signing/npm secrets tracked by Issue #274, then run full production readiness with branch protection, Actions admission, workflow permissions, repository security, and tagged release readiness before cutting a production `v*` tag.
2026-05-25 - Post Phase 15 Rust `time` Dependabot alert fix completed and merged. PR #282 merged to `main` at `6bb587c48ea64cba160abaf6675a6a50863395dd`, Issue #281 is closed, and branch `rust-time-dependabot-alert` is preserved. Refreshed `Cargo.lock` so the transitive Rust `time` dependency resolves to patched `0.3.47` through the existing `rcgen`/`yasna` dependency graph. Local validation passed with `cargo update -p time --precise 0.3.47`, `cargo tree -i time`, `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets`, and `git diff --check`; local test linking was blocked by missing Windows linker tools (`dlltool.exe` for GNU and `link.exe` for MSVC). PR #282 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. GitHub marks Dependabot alert #1 fixed, and repository security readiness reports zero open Dependabot and secret-scanning alerts. Next: wait for post-merge main CI on `6bb587c48ea64cba160abaf6675a6a50863395dd`, then configure real signing/npm secrets tracked by Issue #274 and run the full production readiness gate before cutting a production tag.
2026-05-25 - Post Phase 15 release secret env-file setup completed and merged. PR #284 merged to `main` at `53d0f1ce1c0f34a5bceaa1de31be76cb6bd6126b`, Issue #283 is closed, and branch `release-secret-env-file-setup` is preserved. Added strict `--env-file <path>` support to `scripts/set-github-release-secrets.py` so maintainers can use an ignored `.env.release` `KEY=VALUE` file for release-secret dry-runs, value preflights, and GitHub secret upload without putting secret values in argv or output. The parser accepts only required release secret names, rejects malformed/duplicate/unsupported/non-regular/non-UTF-8/oversized files, passes env-file values to preflight subprocesses through environment variables, and still sends `gh secret set` values through stdin only. Updated README, release checklist, distribution/hosting, platform signing, production readiness docs, and this plan. Local validation passed with Python compile, release-secret setup regression, release-secret readiness regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #284 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: use the `.env.release` path to configure the real signing/npm secrets tracked by Issue #274, then run tagged release readiness with npm registry, CI, and default-branch checks before cutting a production tag.
2026-05-25 - Post Phase 15 release secret env-file template completed and merged. PR #286 merged to `main` at `55f1f2bce00f7bf499c19f7c40befa96ef891874`, Issue #285 is closed, and branch `release-secret-template` is preserved. Added `--print-env-template` and `--write-env-template` to generate an ignored `.env.release` template from the authoritative required-secret list with empty values only, exclusive-create writes, overwrite refusal, missing-parent rejection, and invalid flag-combination guards. Updated README, release checklist, distribution/hosting, platform signing, production readiness docs, and this plan. Local validation passed with Python compile, release-secret setup regression, release-secret readiness regression, template print smoke, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #286 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure the real signing/npm secrets tracked by Issue #274 using the generated `.env.release` path, then run tagged release readiness with npm registry, CI, and default-branch checks before cutting a production tag.
2026-05-25 - Post Phase 15 release secret env-file-only setup completed and merged. PR #289 merged to `main` at `b00d63128f4bf87ae8e7b62ee3eb6c22eb5820af`, Issue #288 is closed, and branch `release-secret-env-file-only` is preserved. Added `--env-file-only` to `scripts/set-github-release-secrets.py` so generated `.env.release` setup can require every secret value to come from the ignored file and fail missing entries even when stale shell variables exist, while preserving the existing mixed env/env-file mode for intentional environment-driven setup. Updated the generated template, README, release checklist, distribution/hosting, platform signing, production readiness docs, and this plan. Local validation passed with Python compile, release-secret setup regression, release-secret readiness regression, template print smoke, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #289 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure the real signing/npm secrets tracked by Issue #274 using the generated `.env.release --env-file-only` path, then run tagged release readiness with npm registry, CI, and default-branch checks before cutting a production tag.
2026-05-25 - Post Phase 15 release secret env-file validation completed and merged. PR #291 merged to `main` at `11be300e67bf77c58ca4c446e3865a917d2a0bb9`, Issue #290 is closed, and branch `release-secret-env-file-check` is preserved. Added `--check-env-file` to validate a filled ignored `.env.release` locally before GitHub CLI lookup, signing-value preflight subprocesses, or secret upload, while reporting only required secret names/counts and missing-name lists. Updated the generated template, README, release checklist, distribution/hosting, platform signing, production readiness docs, and this plan. Local validation passed with Python compile, release-secret setup regression, release-secret readiness regression, template print smoke, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #291 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure the real signing/npm secrets tracked by Issue #274 using the generated `.env.release --check-env-file` then `--env-file-only` path, upload them, and run tagged release readiness before cutting a production tag.
2026-05-25 - Post Phase 15 release secret env-file readiness gate completed and merged. PR #293 merged to `main` at `03ddbf9afab0a118b88469ce0a9a9c7f85681fb8`, Issue #292 is closed, and branch `release-secret-env-file-readiness-gate` is preserved. Added optional `-ReleaseSecretEnvFile` / `CONU_RELEASE_SECRET_ENV_FILE` support to `scripts\verify-production-readiness.ps1`, running the local env-file validation gate when a filled file is supplied while leaving normal readiness runs unchanged. Updated production readiness and release checklist docs. Local validation passed with a temporary full env-file fixture through the readiness wrapper, the standard production-readiness package gate with workflow-permissions readiness, and `git diff --check`; PR #293 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure the real signing/npm secrets tracked by Issue #274, include `.env.release` in the readiness wrapper, run strict value preflights and upload, then run tagged release readiness before cutting a production tag.
2026-05-25 - Post Phase 15 npm unverified download loopback gate completed and merged. PR #295 merged to `main` at `2cbc38fab99eac7a462b8841063e6634e2c10405`, Issue #294 is closed, and branch `npm-unverified-loopback-only` is preserved. Added `validateUnverifiedDownloadBase()` and wired the npm installer to reject `CONU_NPM_ALLOW_UNVERIFIED=1` for non-loopback download bases before any network request, while preserving loopback smoke behavior. Local validation passed with npm download-policy and download-limit checks, `npm run check --prefix packaging/npm/conu-cli`, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #295 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, run full live production readiness, and run tagged release readiness before cutting a production tag.
2026-05-25 - Post Phase 15 npm download redirect boundary completed and merged. PR #297 merged to `main` at `9a9479152f90562a6874c1f3d4f589749aef17f0`, Issue #296 is closed, and branch `npm-download-redirect-boundary` is preserved. Added npm redirect policy validation so public release downloads may redirect only within the public HTTPS boundary and loopback smoke downloads may redirect only among loopback hosts, rejecting boundary crossings before the next request while preserving sanitized error output. Local validation passed with npm download-policy and download-limit checks, `npm run check --prefix packaging/npm/conu-cli`, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #297 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, run full live production readiness, and run tagged release readiness before cutting a production tag.
2026-05-25 - Post Phase 15 Rust update public-host IP guard completed and merged. PR #299 merged to `main` at `28ffb06dfcda58929f3449030f4f036a9305c44a`, Issue #298 is closed, and branch `update-ipv6-public-host-guard` is preserved. Hardened the installed release update client's shared public-IP predicate so remote update policy and artifact downloads reject non-global IPv4 ranges, IPv6 unique-local/link-local/site-local/documentation/special ranges, and IPv4-mapped or IPv4-compatible private forms before any network fetch. Local validation passed with `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets`, `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-cli --all-targets -- -D warnings`, WSL `cargo test -p conu-cli update_`, WSL `cargo test -p conu-cli`, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #299 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, run full live production readiness, and run tagged release readiness before cutting a production tag.
2026-05-25 - Post Phase 15 release archive root guard completed and merged. PR #301 merged to `main` at `52221eb28d2230bdebe9b7b22c01d15425167b86`, Issue #300 is closed, and branch `update-archive-root-guard` is preserved. Hardened `conu update apply` and `scripts/verify-release-artifacts.py` so release archives may be rootless or use only the exact expected `conu-<version>-<target>` root, rejecting unexpected `conu-*` roots and mixed rooted/rootless layouts before staging, installation, or release upload. Local validation passed with Python compile, release artifact verifier regression, `cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets`, `cargo +stable-x86_64-pc-windows-gnu clippy -p conu-cli --all-targets -- -D warnings`, WSL `cargo test -p conu-cli update_apply_`, WSL `cargo test -p conu-cli`, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #301 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, run full live production readiness, and run tagged release readiness before cutting a production tag.
2026-05-25 - Post Phase 15 release smoke archive root guard completed and merged. PR #303 merged to `main` at `f5b13df2fd9ad34f6d5d3db874ed93f4ed2964fd`, Issue #302 is closed, and branch `release-smoke-root-guard` is preserved. Hardened `scripts/smoke-release-artifacts.py` and `scripts/smoke-npm-launcher-local.py` so direct release smoke, npm local smoke, and npm download smoke enforce the exact expected archive root derived from the archive filename, reject unexpected `conu-*` roots, and reject mixed rooted/rootless layouts before executing packaged binaries. Added preflight regressions for rooted manifests, unexpected manifest roots, mixed root styles, and unexpected extracted roots. Local validation passed with Python compile, release artifact smoke preflight regression, npm launcher local smoke preflight regression, release artifact verifier regression, `npm run check --prefix packaging/npm/conu-cli`, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #303 CI passed for Packages, Rust on Ubuntu, Rust on macOS, Rust on Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, run full live production readiness, and run tagged release readiness before cutting a production tag.
2026-05-29 - Post Phase 15 release smoke extraction bounds completed and merged. PR #305 merged to `main` at `97c425e81fd917b047af0b0e4da07debe829e254`, Issue #304 is closed, and branch `release-smoke-extract-bounds` is preserved. Hardened direct release and npm launcher smoke extraction to reject excessive members, oversized members, total uncompressed overage, duplicate normalized paths, encrypted ZIP members, unsupported ZIP types, and data-bearing directories before packaged binaries execute. Validation passed locally with Python compile, focused smoke preflight regressions, release verifier regression, npm launcher check, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #305 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-29 - Post Phase 15 release smoke manifest read bounds completed and merged. PR #307 merged to `main` at `1551a1afd7e7b3f0c292a3416b1f2638f27c9f7b`, Issue #306 is closed, and branch `release-smoke-manifest-bounds` is preserved. Hardened early `manifest.toml` archive reads with member-count, size, total-byte, duplicate-path, root-style, encrypted-ZIP, and unsupported-entry checks before smoke extraction. Local validation passed with Python compile, focused smoke preflight regressions, release verifier regression, npm launcher check, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #307 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-29 - Post Phase 15 hosted repository ZIP ingestion bounds completed and merged. PR #309 merged to `main` at `1b098f727b4979976c86b1d722e943838ab0defe`, Issue #308 is closed, and branch `hosted-repository-zip-bounds` is preserved. Hardened hosted repository bundle/site generation, Pages preparation, and repository metadata signing ZIP reads with member-count, per-member size, total-uncompressed size, encrypted-member, and unsupported-type checks before loading or extracting bytes. Local validation passed with Python compile, hosted repository/site/Pages regressions, Linux repository signing ingestion preflights with GPG unavailable for the signing subtest, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #309 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-29 - Post Phase 15 package-manager release archive ingestion bounds completed and merged. PR #311 merged to `main` at `deffe7ba3b6f0cee3fc1938089d02a9ae8894042`, Issue #310 is closed, and branch `package-manager-archive-bounds` is preserved. Hardened package-manager manifest generation to reject oversized release archives, excessive archive members, oversized members, total uncompressed overage, encrypted ZIP members, unsupported ZIP/TAR members, duplicate paths, unsafe roots, and mixed rooted/rootless layouts before generating package-manager artifacts. Local validation passed with Python compile, package-manager manifest/submission regressions, release verifier regression, release smoke preflight regression, npm launcher check, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #311 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-29 - Post Phase 15 package-manager submission source ingestion bounds completed and merged. PR #313 merged to `main` at `431a763c20dbd9337d00a57c678f15953ae529e1`, Issue #312 is closed, and branch `submission-source-bounds` is preserved. Hardened package-manager submission bundle preparation to enforce aggregate source-byte bounds, stream selected source artifacts into deterministic ZIP output, and reject encrypted or unsupported Chocolatey ZIP members before generating repository-ready submission bundles. Local validation passed with Python compile, package-manager submission/manifest regressions, GitHub Release asset publication regression, release verifier regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #313 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 release update-policy source input bounds completed and merged. PR #315 merged to `main` at `1a3892def80d48469065b36832e20286061969f2`, Issue #314 is closed, and branch `update-policy-source-bounds` is preserved. Hardened release update-policy generation to reject symlinked source assets, checksum sidecars, and detached signatures; enforce per-file and aggregate source-byte bounds; and cap generated text metadata before public update metadata is produced. Local validation passed with Python compile, release update-policy regression, release update download/apply gate, tagged-release readiness regression, GitHub Release asset publication regression, release artifact verifier regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #315 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 Linux release signing file handling completed and merged. PR #317 merged to `main` at `c2017b15ad619a3fccf319f13d15f34167df9051`, Issue #316 is closed, and branch `linux-signing-source-bounds` is preserved. Hardened Linux release signing to reject symlinked, non-regular, empty, oversized, and aggregate-oversized signable release assets before GPG runs, and to reject unsafe existing detached-signature output paths plus validate generated signature files. Local validation passed with Python compile, Linux release signing regression, Linux signing-secret/RPM/repository signing regressions with local tool skips where unavailable, GitHub Release asset publication regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #317 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 Linux repository metadata signing file handling completed and merged. PR #319 merged to `main` at `1846e11e3ebe5d15bdd477b21d59271053caf671`, Issue #318 is closed, and branch `linux-repository-signing-file-bounds` is preserved. Hardened native APT/RPM repository metadata signing to reject symlinked, non-regular, empty, oversized, and aggregate-oversized metadata bundles before GPG work, validate checksum sidecar inputs/outputs, cap generated signature files, and rewrite signed ZIP/sidecar outputs through bounded temporary files. Local validation passed with Python compile, Linux repository signing regression, adjacent Linux signing/GPG/RPM regressions with local tool skips where unavailable, GitHub Release asset publication regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #319 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 RPM package signing file handling completed and merged. PR #321 merged to `main` at `d66b872f53d85a1bcec32dfe98727d996fc84f5d`, Issue #320 is closed, and branch `rpm-package-signing-file-bounds` is preserved. Hardened native RPM package signing to reject symlinked, non-regular, empty, oversized, and aggregate-oversized RPM package assets before RPM/GPG work, validate checksum sidecar inputs/outputs, validate package files before and after native signing, and refresh checksum sidecars through bounded temporary files. Local validation passed with Python compile, RPM package signing regression, package-manager manifest regression, adjacent Linux signing/GPG/repository regressions with local tool skips where unavailable, GitHub Release asset publication regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #321 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 Linux public-key export output handling completed and merged. PR #323 merged to `main` at `edb55a86abc528efac27984daff8b7fbc2f74e38`, Issue #322 is closed, and branch `linux-public-key-export-output-bounds` is preserved. Hardened Linux GPG public-key export to reject unsafe existing output and sidecar paths before GPG work, cap exported public-key and checksum sidecar bytes, reject private-key material before writing public release assets, and write the public key plus sidecar through bounded temporary files. Local validation passed with Python compile, Linux GPG public-key export regression, adjacent Linux release/repository/RPM signing regressions with local tool skips where unavailable, GitHub Release asset publication regression, release update-policy regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #323 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 hosted repository S3 publication metadata input handling completed and merged. PR #325 merged to `main` at `1774979ea6b03a0d991d200546b70dcf9a616154`, Issue #324 is closed, and branch `hosted-s3-metadata-input-bounds` is preserved. Hardened custom hosted Linux repository S3 publication to bound `repository.json` and `cache-policy.json` reads, reject symlinked/non-regular site metadata and symlinked site entries, and reject unsafe Cache-Control values before `aws s3 cp` metadata is built. Local validation passed with Python compile, hosted Linux repository S3 publication regression, hosted endpoint/bundle/site/Pages regressions, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #325 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 hosted repository Pages preparation input handling completed and merged. PR #327 merged to `main` at `42c23250c748cd6c20b44e0e1cfc046aa2f46b74`, Issue #326 is closed, and branch `hosted-pages-input-bounds` is preserved. Hardened Pages preparation to reject symlinked, missing, non-regular, and oversized site ZIP/checksum/signature inputs plus symlinked output directories before checksum/signature reads or extraction. Local validation passed with Python compile, hosted Linux repository Pages regression, hosted repository site/bundle/endpoint/S3 regressions, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #327 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 hosted repository generator file boundary handling completed and merged. PR #329 merged to `main` at `4d2a4dfdb3cf885a1be8ccd1cc3a96cc87760c02`, Issue #328 is closed, and branch `hosted-generator-file-bounds` is preserved. Hardened hosted repository bundle and site generation to reject symlinked dist/output directories, symlinked/non-regular source assets, checksum sidecars, detached signatures, output ZIPs, and output sidecars before public hosted artifacts are read or written. Local validation passed with Python compile, hosted repository bundle/site/Pages/endpoint/S3 regressions, package-manager manifest/submission regressions, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #329 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 package-manager manifest file boundary handling completed and merged. PR #331 merged to `main` at `eef6b6c7dc7c31b3b7ec7f1d78e77e8c4482c07e`, Issue #330 is closed, and branch `package-manager-manifest-file-bounds` is preserved. Hardened package-manager manifest generation to reject symlinked/non-regular dist and output directories, release archives, checksum sidecars, generated manifests/packages/metadata, output sidecars, and existing RPM package inputs before reading or writing package-manager artifacts. Local validation passed with Python compile, package-manager manifest/submission regressions, hosted repository bundle/site regressions, release artifact verifier/smoke/npm smoke preflights, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #331 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 release artifact verifier file boundary handling completed and merged. PR #333 merged to `main` at `4ad9de5cb0cfc47a5aab34ed92e1ee91fbe60754`, Issue #332 is closed, and branch `release-artifact-file-bounds` is preserved. Hardened release artifact verification to reject symlinked dist directories plus symlinked/non-regular release archives and checksum sidecars before hashing or archive scanning. Local validation passed with Python compile, release artifact verifier/smoke regressions, npm launcher smoke preflight, package-manager manifest/submission regressions, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #333 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit.
2026-05-30 - Post Phase 15 package-manager submission file boundary handling completed and merged. PR #335 merged to `main` at `1a927487116fec85bfcead2f0659605c1093c1db`, Issue #334 is closed, and branch `package-submission-file-bounds` is preserved. Hardened package-manager submission bundle preparation to reject symlinked/non-regular source and output boundaries, use descriptor-bound source reads, output ZIP writes, checksum sidecar writes, and bundle hashing, and cap generated submission artifacts before release package-manager handoff. Local validation passed with Python compile, package-manager submission regression, package-manager manifest/release verifier/hosted repository regressions, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #335 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, then run live tagged release readiness before cutting a production tag.
2026-05-30 - Post Phase 15 package-manager manifest descriptor-bound IO completed and merged. PR #337 merged to `main` at `dc15b786571bbf69a64845cf7a49d1836d6767a7`, Issue #336 is closed, and branch `package-manifest-descriptor-io` is preserved. Hardened package-manager manifest generation to use descriptor-bound release archive reads, checksum reads, generated manifest/package writes, Chocolatey ZIP writes, checksum sidecar writes, and generated RPM package copies after existing symlink/non-regular path checks. Local validation passed with Python compile, package-manager manifest/submission regressions, release verifier, hosted repository regressions, GitHub Release asset publication regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #337 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, then run live tagged release readiness before cutting a production tag.
2026-05-30 - Post Phase 15 Linux public-key export descriptor-bound IO completed and merged. PR #357 merged to `main` at `a3bc8f02e09d7dab299b282c766c732bb75f64f2`, Issue #356 is closed, and branch `linux-public-key-descriptor-io` is preserved. Hardened Linux public-key export hashing and generated temp public-key/sidecar writes through descriptor-bound regular-file handles, with regressions for directory, oversized, and symlinked hash sources. Local validation passed with Python compile, Linux GPG public-key export regression with local GPG skip for the live key path, adjacent release/signing regressions with local tool skips, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #357 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, then run live tagged release readiness before cutting a production tag.
2026-05-30 - Post Phase 15 npm install target hardening completed and merged. PR #359 merged to `main` at `d5b2dd4605213291dfcfbf665b5dcb59a6803d6f`, Issue #358 is closed, and branch `npm-install-target-hardening` is preserved. Hardened npm native binary installation to reject symlink/non-regular sources, unsafe install directories, and symlink/non-file targets, then install through checked temp siblings. Local validation passed with Node syntax checks, install target regression, npm launcher check, npm package content verification, TypeScript SDK check, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #359 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, then run live tagged release readiness before cutting a production tag.
2026-05-30 - Post Phase 15 release secret env-file permission hardening completed and merged. PR #361 merged to `main` at `e06b94d857460f26616db3faeecbfd366e07e5d2`, Issue #360 is closed, and branch `release-env-file-permissions` is preserved. Hardened the release-secret setup path to reject POSIX `.env.release` files that allow group or other access before parsing signing/npm secret values, with descriptor re-checks after reading and Windows-compatible behavior. Local validation passed with Python compile, release-secret setup/readiness regressions, tagged-release readiness regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #361 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, then run live tagged release readiness before cutting a production tag.
2026-05-30 - Post Phase 15 release archive secret-file guard completed and merged. PR #363 merged to `main` at `db76d4504e3e301d16bc30c10a2bce16545c5f31`, Issue #362 is closed, and branch `release-archive-secret-file-guard` is preserved. Hardened release archive verification to reject `.env`, `.env.*`, `.npmrc`, and key/cert/token-looking archive members before public release artifacts are accepted, with regressions for env and signing-material members. Local validation passed with Python compile, release artifact verifier regression, production-readiness `-SkipRust -SkipSmokes -CheckGitHubWorkflowPermissions`, and `git diff --check`; PR #363 CI passed for Packages, Rust Ubuntu/macOS/Windows, and CodeRabbit. Next: configure real release signing/npm secrets tracked by Issue #274, then run live tagged release readiness before cutting a production tag.
2026-07-02 - Post Phase 15 terminal chat selector release prep completed. Added a top-level Chat entry and prompt-based local chat rows so users can run `conu chat <from-agent> <to-agent>` from the terminal selector while scriptable `--stdin` chat remains available for agents; bumped Cargo/npm packages to `0.1.3`. Changed files: `crates/conu-cli/src/lib.rs`, `crates/conu-cli/src/main.rs`, Cargo/npm version manifests, and `Cargo.lock`. Validation passed with GNU `cargo fmt --all -- --check`, GNU workspace tests, GNU workspace `clippy --workspace --all-targets -- -D warnings`, local isolated CLI smoke for setup/connect/chat/wait/receive/reply/history with payload leak checks, release-version check, npm publish preflight registry check, npm CLI package check, TypeScript SDK check, smoke-output privacy check, deployment asset check, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.3`, and run online npm install smoke.
2026-07-02 - Post Phase 15 inbox overview release prep completed. Added metadata-only `conu inbox` and `conu inbox --json` overview output across local agents while keeping `conu inbox <agent-id>` for per-agent metadata; bumped Cargo/npm packages to `0.1.4`. Changed files: `crates/conu-cli/src/lib.rs`, Cargo/npm version manifests, and `Cargo.lock`. Validation passed with GNU `cargo fmt --all -- --check`, GNU `cargo check --workspace --all-targets`, GNU `cargo clippy --workspace --all-targets -- -D warnings`, GNU `cargo test --workspace`, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, isolated CLI setup/chat/inbox/history/receive smoke with payload leak checks, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.4`, and run online npm install smoke.
2026-07-02 - Post Phase 15 dashboard next-action release prep completed. Replaced hardcoded dashboard demo-agent next actions with state-aware setup, local chat/send, inbox/history/wait, room, remote-send, and connect/watch commands based on registered local/remote agents and rooms; bumped Cargo/npm packages to `0.1.5`. Changed files: `crates/conu-cli/src/lib.rs`, Cargo/npm version manifests, and `Cargo.lock`. Validation passed with GNU `cargo fmt --all -- --check`, GNU `cargo check --workspace --all-targets`, GNU `cargo clippy --workspace --all-targets -- -D warnings`, GNU `cargo test --workspace`, focused dashboard/connect/chat tests, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, isolated CLI dashboard/setup/send/inbox smoke with payload leak checks, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.5`, and run online npm install smoke.
2026-07-02 - Post Phase 15 nested messages help release prep completed. Added focused successful help output for `conu messages send|inbox|history|reply|wait|receive|receipts --help` so agent-facing long-form commands are as discoverable as the top-level aliases; bumped Cargo/npm packages to `0.1.6`. Changed files: `crates/conu-cli/src/lib.rs`, Cargo/npm version manifests, and `Cargo.lock`. Validation passed with GNU `cargo fmt --all -- --check`, GNU `cargo check --workspace --all-targets`, GNU `cargo clippy --workspace --all-targets -- -D warnings`, GNU `cargo test --workspace`, focused command-help and agent messenger tests, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, direct CLI nested-help smoke, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.6`, and run online npm install smoke.
2026-07-02 - Post Phase 15 relay credential help release prep completed. Added successful focused help output for `conu relay credential set|status|clear --help` with token-safe guidance, expanded command-help regression coverage, and bumped Cargo/npm packages to `0.1.7`. Validation passed with GNU `cargo fmt --all -- --check`, GNU workspace check, GNU `clippy --workspace --all-targets -- -D warnings`, GNU workspace tests, npm CLI package check, TypeScript SDK check, release-version check, smoke-output privacy check, deployment asset check, nested-help matrix smoke, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.7`, and run online npm install smoke.
2026-07-02 - Post Phase 15 CLI quick-help and runtime status retry release prep completed. Simplified default `conu --help` into a quick start guide while preserving the full command list at `conu help commands`, cleaned the top-level menu duplicate connect rows by surfacing inbox/status, and made runtime status reads retry transient daemon heartbeat rewrites without retrying non-regular or missing control files; bumped Cargo/npm packages to `0.1.8`. Validation passed with GNU `cargo fmt --all -- --check`, GNU workspace check, GNU `clippy --workspace --all-targets -- -D warnings`, GNU workspace tests, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, isolated CLI UX/send/receive smoke, relay daemon smoke, production-readiness `-SmokeOnly`, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.8`, and run online npm install smoke.
2026-07-02 - Post Phase 15 agent ready command release prep completed. Added short top-level `conu ready <agent-id> <display-name>` as a tested alias over `conu agents prepare`, preserving metadata-only output while making agent self-registration, ready presence, optional stream setup, and room setup easier for scripts and agents; bumped Cargo/npm packages to `0.1.9`. Validation passed with GNU `cargo fmt --all -- --check`, GNU workspace check, GNU `clippy --workspace --all-targets -- -D warnings`, GNU workspace tests, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, production-readiness `-SmokeOnly`, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.9`, and run online npm install smoke.
2026-07-02 - Post Phase 15 latest receive command release prep completed. Added `conu receive <agent-id> --latest --output <file> [--process-ipc]` and matching `conu messages receive` support so agents can wait for and write the newest inbox payload in one payload-safe command; bumped Cargo/npm packages to `0.1.10`. Validation passed with GNU fmt/check/clippy/workspace tests, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, production-readiness `-SmokeOnly`, isolated byte-for-byte latest receive smoke, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.10`, and run online npm install smoke.
2026-07-02 - Post Phase 15 agent pull command release prep completed. Added `conu pull <agent-id> --dir <directory> [--process-ipc]` and matching `conu messages pull` support so agents can wait for the next inbox payload and write it to a generated local file without printing contents or local paths; bumped Cargo/npm packages to `0.1.11`. Validation passed with GNU fmt/check/clippy/workspace tests, npm CLI package check, TypeScript SDK check, release-version check, npm publish preflight registry check, smoke-output privacy check, deployment asset check, production-readiness `-SmokeOnly`, isolated byte-for-byte pull smoke, and `git diff --check`. Known gaps: no platform signing/notarization secrets were added; this simple-launch release remains scoped to existing unsigned launch behavior. Next: merge through protected `main`, publish `@imthegoodboy/conu@0.1.11`, and run online npm install smoke.
```
