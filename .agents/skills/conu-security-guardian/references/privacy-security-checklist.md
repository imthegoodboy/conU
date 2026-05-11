# Privacy And Security Checklist

## Payload Opacity

- Payload content is opaque to conU runtime surfaces unless the local agent intentionally handles it.
- CLI does not print payload text.
- SDK and MCP list/send/status/stream outputs do not print payload text.
- Logs do not include payload text.
- Metrics do not include payload text.
- Route registry, probe history, and route logs include only metadata.
- Tests do not normalize leaking payload contents as expected behavior.

## Identity And Trust

- Node identity is generated locally.
- Agent identity is bound to a trusted node.
- Pairing is explicit.
- Manual peer-card trust must import only public node id, display name, public exchange key, and relay endpoint.
- Trust is revocable.
- Discovery is scoped by trust and policy.

## Permissions

- Agent actions require grants where appropriate.
- Sending, streaming, subscribing, room joining, file transfer, and mailbox use are separately controllable.
- "Full access" means full communication within trust boundaries, not raw system access.
- SDK/MCP receive APIs return payload bytes only to the addressed local agent and only after an explicit receive request.

## Relay

- Relay forwards opaque envelopes.
- Relay logs metadata only.
- Relay cannot impersonate a peer.
- Relay fallback does not weaken trust checks.
- Relay message delivery must decrypt only after the sender exchange public key matches the trusted peer card.
- Relay frames may carry ciphertext bodies, never plaintext payload fields.
- The conUD relay pump may retry, count, and route envelopes, but runtime logs must stay metadata-only and must not include relay tokens or plaintext payloads.

## Storage

- Trust store avoids plaintext secrets when possible.
- Message request and inbox files use encrypted-at-rest payload fields.
- Mailbox stores encrypted envelopes when mailbox delivery is implemented.
- Relay outbox stores peer-encrypted envelope bodies, not plaintext payloads.
- Logs are payload-safe.
- Config does not store private keys.
- Security key files remain local-only and must not appear in CLI output, logs, docs examples, or tests except artificial field-name checks.

## Replay And Signatures

- Local agent cards are signed and signature verification fails on tampering.
- Replay cache rejects duplicate message request and envelope ids before duplicate delivery.
- Revoked peers must not remain visible or routeable.

## Routes

- Direct routes are selected only for trusted peers.
- Relay fallback does not weaken trust checks.
- Direct endpoint config must not contain tokens, private keys, or payload material.
- Route failure reasons stay generic and must not echo arbitrary payload-bearing input.

## Packaging And Doctor

- Release archives do not include local state, private keys, logs, inboxes, message stores, routes, or payload-bearing files.
- `conu doctor` reports readiness and scan counts only; it must not print log contents.
- CI and release workflows upload binaries/docs/templates only.
- Service templates must not bake in developer-specific secrets, tokens, or private paths beyond editable placeholders.
- npm packaging must verify release checksums by default and must not package or inspect local `CONU_HOME` state.
- Docker relay templates must keep relay tokens in environment/configuration, not committed files.

## CLI Watch

- Shows route, latency, bytes, packet count, stream count, presence.
- Never shows message text, prompt text, reasoning, file contents, or tool output.

## MCP Adapter

- stdout contains only valid MCP JSON-RPC messages.
- Tool schemas do not encourage plaintext payload logging.
- `conu_receive_message` returns metadata by default.
- `payloadHex` is returned only for explicit addressed-agent receive calls.
- When `CONU_AGENT_ID` is set, the MCP server rejects attempts to act as another local agent.
