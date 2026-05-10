# CLI Experience

The conU CLI should feel like a live network control room for agents.

## Show

- ASCII conU identity.
- local runtime state.
- local agents.
- trusted remote agents.
- pairing and join flow.
- connection status.
- transport animation.
- route, latency, stream count, packet count.
- private payload marker.

## Never Show

- message contents.
- prompt text.
- model reasoning.
- private payloads.
- hidden memory.
- remote tool internals.

## Example Watch View

```txt
conU watch

transport view
  codex-desktop  == encrypted stream ==>  claude-laptop
  route         metadata-relay
  stream        stream_abc
  event         chunk
  open streams  1
  packets       3
  bytes         814
  contents      not displayed

animation
  [agent] >>> private packets >>> [agent]
```

## Design Rule

Animate the road, not the conversation.
