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
logs/routes.log      route sync events
```

All current log files are local text metadata logs. They do not include payload contents.

## Doctor Check

`conu doctor` scans `.log` files in the active conU state directory for known payload-leak terms and reports:

```txt
logs
  payload safe
  scanned files
  issues
```

This is a guardrail, not a substitute for code review. New observability fields must still be reviewed with the security guardian before merge.

## Future Structured Telemetry

When OpenTelemetry-style exports are added, the exporter must:

- use an allowlist of fields
- default to local-only/off
- exclude payload and secret fields at type level
- include tests that reject forbidden keys
- document retention, redaction, and user controls
