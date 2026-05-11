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
- Remote session and remote agent metadata mirror for trusted peers.
- Stream lifecycle metadata, backpressure counters, and private watch animation.
- Direct QUIC candidate scoring, NAT profile labels, route probes, and relay fallback selection.
- Replay protection for local message request and envelope ids.
- Rust SDK for local agent registration, messaging, receive, peer, security, and stream calls.
- Python stdlib wrapper SDK around installed `conu` and `conud` binaries.
- MCP stdio adapter exposing conU as JSON-RPC tools for MCP-capable agents.
- Payload-safe logs, receipts, watch output, and CLI JSON.
- Phase 11 security audit command, Phase 12 SDK/MCP receive path, and Phase 13 route manager.

## Still Local Or Groundwork

- File-backed IPC is reliable for development, but not yet a production named-pipe/socket transport.
- Remote sessions are metadata mirrors. They do not yet move encrypted payload bytes between machines.
- The relay forwards metadata frames, but conUD does not yet own a live relay client for data-plane delivery.
- Direct transport is route metadata only. Real QUIC sockets, ICE-style candidate exchange, and NAT hole punching are not active yet.
- Stream writes count bytes and emit events. They do not persist or relay chunk bytes yet.
- Pairing is local trust-store groundwork, not full cross-machine rendezvous.
- MCP is stdio-only. HTTP MCP transport, auth, and remote MCP hosting are intentionally not implemented.
- TypeScript SDK remains future work.

## Release Blockers

- Live relay-backed encrypted message and stream routing.
- Real direct QUIC transport with peer authentication and NAT traversal.
- Remote signed agent-card exchange and verification.
- Capability grants and user-visible permission policy.
- SDK permission policy hardening before public package distribution.
- OS-backed private key storage.
- Key rotation migration tooling.
- Installer/service setup for Windows, macOS, and Linux.
- CI validation across supported platforms.
- Log rotation and structured observability with payload-safe fields only.
- Rate limits and bounded queues for public relay operation.
- Security review of relay auth, replay cache behavior, and storage migration.

## Validation Baseline

Before merging production-affecting work, run:

```bash
cargo fmt --all -- --check
cargo +stable-x86_64-pc-windows-gnu check --workspace --all-targets
cargo +stable-x86_64-pc-windows-gnu test --workspace
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
- Message and mailbox storage use encrypted payload fields.
- Tests use artificial negative strings only to prove they do not leak.
