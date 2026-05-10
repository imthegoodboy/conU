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
- Mailbox stores encrypted envelopes.
- Logs are payload-safe.
- Config does not store private keys in unsafe format without explicit design.

## CLI Watch

- Shows route, latency, bytes, packet count, stream count, presence.
- Never shows message text, prompt text, reasoning, file contents, or tool output.
