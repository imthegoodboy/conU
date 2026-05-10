# Threat Model

## Assets

- agent message payloads
- agent memory and reasoning
- node private keys
- agent identities
- trust store
- session keys
- pairing codes
- relay routing metadata

## Main Threats

- relay reads payloads
- CLI accidentally prints private message content
- logs capture payloads during debugging
- untrusted peer discovers private agent
- revoked peer keeps communicating
- replayed envelope causes duplicate side effect
- fake agent identity impersonates trusted agent
- local malware reads keys from disk
- mailbox stores plaintext content

## Required Mitigations

- opaque encrypted envelopes
- explicit pairing
- signed identities and agent cards
- scoped discovery
- revocable trust
- idempotency keys and replay protection
- payload-safe logs and telemetry
- encrypted mailbox storage
- secure local key storage strategy
