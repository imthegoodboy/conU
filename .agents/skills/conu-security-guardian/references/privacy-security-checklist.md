# Privacy And Security Checklist

## Payload Opacity

- Payload content is opaque to conU runtime surfaces unless the local agent intentionally handles it.
- CLI does not print payload text.
- Logs do not include payload text.
- Metrics do not include payload text.
- Tests do not normalize leaking payload contents as expected behavior.

## Identity And Trust

- Node identity is generated locally.
- Agent identity is bound to a trusted node.
- Pairing is explicit.
- Trust is revocable.
- Discovery is scoped by trust and policy.

## Permissions

- Agent actions require grants where appropriate.
- Sending, streaming, subscribing, room joining, file transfer, and mailbox use are separately controllable.
- "Full access" means full communication within trust boundaries, not raw system access.

## Relay

- Relay forwards opaque envelopes.
- Relay logs metadata only.
- Relay cannot impersonate a peer.
- Relay fallback does not weaken trust checks.

## Storage

- Trust store avoids plaintext secrets when possible.
- Message request and inbox files use encrypted-at-rest payload fields.
- Mailbox stores encrypted envelopes when mailbox delivery is implemented.
- Logs are payload-safe.
- Config does not store private keys.
- Security key files remain local-only and must not appear in CLI output, logs, docs examples, or tests except artificial field-name checks.

## Replay And Signatures

- Local agent cards are signed and signature verification fails on tampering.
- Replay cache rejects duplicate message request and envelope ids before duplicate delivery.
- Revoked peers must not remain visible or routeable.

## CLI Watch

- Shows route, latency, bytes, packet count, stream count, presence.
- Never shows message text, prompt text, reasoning, file contents, or tool output.
