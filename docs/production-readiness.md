# conU Production Readiness

This document tracks what is ready, what is intentionally local-only, and what must be finished before a real public release.

For hands-on install and agent usage instructions, see `docs/user-install-and-agent-guide.md`.

## Ready In The Current Repo

- Rust workspace for CLI, runtime daemon, core, protocol, and relay.
- `conu init`, status, start, stop, and dashboard.
- File-backed local agent gateway for registration and presence.
- Local message delivery between registered agents.
- Encrypted-at-rest conU-owned local message payload storage.
- Signed local agent cards.
- Local pairing/trust records with revocation.
- Metadata-only relay frame contract and standalone WebSocket relay MVP.
- Peer-card exchange and daemon-pumped relay-backed peer-encrypted one-shot message delivery.
- Remote session and remote agent metadata mirror for trusted peers.
- Stream lifecycle metadata, backpressure counters, and private watch animation.
- Direct QUIC candidate scoring, NAT profile labels, route probes, and relay fallback selection.
- Replay protection for local message request and envelope ids.
- Rust SDK for local agent registration, messaging, receive, peer, security, and stream calls.
- Python stdlib wrapper SDK around installed `conu` and `conud` binaries.
- MCP stdio adapter exposing conU as JSON-RPC tools for MCP-capable agents.
- `conu doctor` local readiness and payload-safe log scanner.
- Cross-platform release build scripts under `scripts/`.
- Windows install/uninstall scripts and Windows service creation path.
- Linux systemd and macOS launchd service templates.
- GitHub CI and release artifact workflows.
- Release checklist and observability docs.
- Payload-safe logs, receipts, watch output, and CLI JSON.
- Phase 11 security audit command, Phase 12 SDK/MCP receive path, Phase 13 route manager, and Phase 15 packaging layer.

## Still Local Or Groundwork

- File-backed IPC is reliable for development, but not yet a production named-pipe/socket transport.
- Remote sessions are still metadata mirrors; manual peer-card exchange is the current cross-machine trust path.
- The relay-backed data plane supports one-shot peer-encrypted messages through the conUD relay pump when a relay or trusted relay peer is configured. Explicit `conu relay sync` remains for manual flush/debug flows. Stream byte routing, persistent relay sessions, hosted relay auth/TLS, and offline mailbox delivery are not active yet.
- Direct transport is route metadata only. Real QUIC sockets, ICE-style candidate exchange, and NAT hole punching are not active yet.
- Stream writes count bytes and emit events. They do not persist or relay chunk bytes yet.
- Pairing is local trust-store groundwork, not full cross-machine rendezvous.
- MCP is stdio-only. HTTP MCP transport, auth, and remote MCP hosting are intentionally not implemented.
- Packaging is unsigned and local-first. Code signing, notarization, package-manager publishing, and auto-update are not implemented.
- TypeScript SDK remains future work.

## Release Blockers

- Live relay-backed encrypted stream routing, persistent relay sessions, hosted retry policy, and offline mailbox delivery.
- Real direct QUIC transport with peer authentication and NAT traversal.
- Remote signed agent-card exchange and verification.
- Capability grants and user-visible permission policy.
- SDK permission policy hardening before public package distribution.
- OS-backed private key storage.
- Key rotation migration tooling.
- Signed installer/package publishing for Windows, macOS, and Linux.
- Log rotation and structured telemetry exporter with payload-safe field allowlists only.
- Rate limits and bounded queues for public relay operation.
- Security review of relay auth, replay cache behavior, and storage migration.

## Validation Baseline

Before merging production-affecting work, run:

```bash
cargo fmt --all -- --check
cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
cargo +stable-x86_64-pc-windows-gnu test --workspace
python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py
powershell -ExecutionPolicy Bypass -File scripts/smoke-relay-daemon.ps1 -Toolchain stable-x86_64-pc-windows-gnu
conu doctor --json
git diff --check
```

On Windows machines without Visual Studio C++ Build Tools, the default MSVC toolchain can fail when dependencies compile build scripts. Use `stable-x86_64-pc-windows-gnu` until MSVC Build Tools or CI are configured.

## Privacy Baseline

Every release candidate must confirm:

- CLI output does not show message text, prompt text, reasoning, file contents, private keys, or shared secrets.
- SDK/MCP list, send, status, receipt, and stream outputs stay metadata-only.
- SDK/MCP receive APIs return payload bytes only to the addressed local agent by explicit request.
- Logs use `payload=not_observed` or metadata-only equivalents.
- Route registry, route probes, and route logs contain route metadata only.
- Relay frames reject plaintext payload fields.
- Relay message frames may carry ciphertext bodies only after local trust verifies the sender public exchange key.
- Message and mailbox storage use encrypted payload fields.
- Tests use artificial negative strings only to prove they do not leak.

## Release Artifacts

Build artifacts with:

```powershell
.\scripts\build-release.ps1
# On Windows without MSVC Build Tools:
.\scripts\build-release.ps1 -Toolchain stable-x86_64-pc-windows-gnu
```

or:

```sh
./scripts/build-release.sh
```

Each artifact must include only binaries, docs, packaging templates, and `manifest.toml`. It must not include developer state directories, keys, logs, inboxes, route files, or payload-bearing test output.

## Local Release Decision

Current status is `daemon_relay_message_ready_with_known_limits`.

This means a developer can install, initialize, start conUD, pair locally, exchange public peer cards, send a peer-encrypted one-shot message through a reachable `ws://` relay without manual per-message sync, run readiness checks, and inspect payload-safe logs. It does not mean conU is ready as a hosted public internet network with managed auth, TLS, offline mailbox storage, stream byte routing, persistent relay sessions, or direct QUIC.
