# conU Repo Map

## Current Planning Files

```txt
architecture.md
  target architecture and protocol direction

plan.md
  living phase plan and completion log

.agents/
  future-agent memory, rules, and skills
```

## Rust Workspace

```txt
crates/conu-cli
  CLI commands, ASCII dashboard, relay credential control flow, connect/rooms control flow, stream/watch animation, payload-safe telemetry snapshot, user control flow

crates/conud
  daemon process, local gateway/message/session processing, relay pump, session manager, runtime lifecycle

crates/conu-core
  local state, security keys/encryption/signatures/replay/identity-key rotation and archive retirement/storage-key rotation and retirement, local relay client credential storage, runtime lifecycle, agent registry, signed agent-card exchange, local message routing, room/pub-sub fanout metadata and topic policy, relay-backed remote message, stream-chunk, room-event, same-node relay session resume, and bounded durable mailbox delivery, stream metadata, route selection, payload-safe log rotation and telemetry allowlist, trust store, peer policy store, relay frame contract, remote session mirror

crates/conu-protocol
  envelopes, agent cards, control-plane messages, data-plane messages

crates/conu-relay
  small plain WebSocket relay service, offline scoped credential issuance, helper-driven manifest upsert/rotate/revoke, session auth/resume, metadata-only file-backed session state, live-reloaded hashed scoped credential manifests, metadata-only accounting/quotas, blind ciphertext forwarding, relay/bootstrap groundwork

crates/conu-sdk
  Rust agent-facing SDK over registration, presence, peers, peer cards, routes, local/remote messages, optional relay sync, receive, streams, rooms, and security audit

crates/conu-mcp
  MCP stdio adapter exposing conU tools over newline-delimited JSON-RPC

sdk/python/conu_sdk
  stdlib Python wrapper around installed conu and conud binaries

sdk/typescript
  dependency-free TypeScript/JavaScript wrapper around installed conu and conud binaries

examples/python
  Python local-agent integration examples

examples/typescript
  TypeScript/JavaScript local-agent integration examples

scripts
  release build, local smoke, and relay-daemon smoke scripts

packaging
  Windows install scripts, Linux systemd and macOS launchd service templates, Docker relay template, and npm native launcher package

.github/workflows
  CI and release artifact workflows
```

## Placement Rule

If a file is meant to guide future agents, put it under `.agents/`. If it is product architecture, update `architecture.md`. If it is execution status, update `plan.md`.
