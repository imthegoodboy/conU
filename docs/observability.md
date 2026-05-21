# conU Observability

conU observability exists to debug the road without reading the conversation.

```txt
Agents own the conversation.
conU owns the connection.
```

## Allowed Fields

Logs, metrics, and future traces may include:

- event name
- node id
- agent id
- peer node id
- route id
- transport label
- stream id
- envelope id
- receipt id
- byte count
- packet/chunk count
- queue count
- route score
- latency estimate
- runtime pid
- delivery state
- disconnect or rejection reason
- `payload=not_observed`

## Forbidden Fields

Logs, metrics, traces, CLI output, release artifacts, and screenshots must not include:

- message text
- prompt text
- model reasoning
- memory contents
- tool output
- file contents
- private keys
- shared secrets
- auth tokens
- plaintext payload bytes
- decrypted payload bytes

## Current Log Files

```txt
logs/conud.log       runtime events
logs/agents.log      local agent registry events
logs/messages.log    local delivery events
logs/sessions.log    remote session sync events
logs/streams.log     stream lifecycle events
logs/rooms.log       room/pub-sub metadata events
logs/routes.log      route sync events
logs/relay-delivery.log relay send/receive events
logs/*.log.N          rotated metadata log archives
```

All current log files are local text metadata logs. They do not include payload contents.

## Log Rotation

`conu logs rotate` rotates active `.log` files in the current state directory when they exceed a configured byte threshold:

```txt
conu logs rotate --max-bytes 1048576 --keep 5
conu logs rotate --max-bytes 1048576 --keep 5 --json
```

Rotation uses only file names, file sizes, and archive indexes. It does not read or print log contents. Archives are named like `messages.log.1`, `messages.log.2`, and so on up to the configured keep count.

## Doctor Check

`conu doctor` scans `.log` files and rotated `.log.N` archives in the active conU state directory for known payload-leak terms and reports:

```txt
logs
  payload safe
  scanned files
  issues
```

This is a guardrail, not a substitute for code review. New observability fields must still be reviewed with the security guardian before merge.

## Structured Telemetry

`conu telemetry snapshot` exports a local, payload-safe telemetry snapshot:

```txt
conu telemetry snapshot
conu telemetry snapshot --json
```

The JSON output includes schema `conu.telemetry.snapshot.v1`, a `fieldAllowlist`, aggregate state/runtime/agent/session/stream/room/route/relay/log/security counters, and:

```json
{
  "privacy": {
    "fieldAllowlistOnly": true,
    "contentsDisplayed": false
  }
}
```

The snapshot deliberately excludes node ids, agent ids, peer ids, endpoints, file paths, log lines, key ids, private keys, shared secrets, auth tokens, plaintext payloads, decrypted payloads, and ciphertext bodies. It may scan local log files for known forbidden terms, but it reports only `payloadSafe`, `scannedFiles`, and `issues`.

Allowed telemetry fields are defined in `conu_core::observability::TELEMETRY_FIELD_ALLOWLIST`.

## Future Hosted Telemetry

When OpenTelemetry-style exports are added, the exporter must:

- use an allowlist of fields
- default to local-only/off
- exclude payload and secret fields at type level
- include tests that reject forbidden keys
- document retention, redaction, and user controls
