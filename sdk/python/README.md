# conU Python SDK

This wrapper lets Python-based agents call an installed `conu` and `conud`
binary without parsing terminal UI by hand.

```python
from conu_sdk import ConuClient

client = ConuClient(home=".conu-agent")
client.init()
client.register_agent("agent.alpha", "Alpha")
client.register_agent("agent.beta", "Beta")
client.process_queued()

sent = client.send_message("agent.alpha", "agent.beta", b"private bytes")
waited = client.wait_for_message("agent.beta", process_ipc=True)
print(sent["payloadBytes"], waited["status"])
```

The wrapper does not log or print payloads. Message payload bytes are sent to
`conu messages send --stdin`; metadata commands use `--json`.

`register_agent()` defaults to message and presence capability only. Pass
`streams=True` and/or `rooms=True` before using stream or room helpers.

Use `export_agent_card(agent_id)` to get public signed agent-card metadata for a
trusted peer. Use `trust_agent_card(card)` after the peer node itself has been
trusted; it verifies through the CLI, requires the card signing key to match the
trusted peer card, and returns metadata only. With signed peer-card trust and
peer policy grants in place, conUD/session sync can exchange the same signed
agent cards automatically over encrypted relay control envelopes; the manual
helpers remain useful for daemonless fallback.

Use `peer_policies()` to list explicit peer grants and
`set_peer_policy(peer_node_id, messages=True, streams=True, rooms=True)` after
peer trust to grant only the remote surfaces an agent should use. Missing policy
records deny remote message, stream, room, file, and mailbox surfaces by
default. Remote room publishes use peer-encrypted relay room-event envelopes
when the joined remote agent advertises `rooms=True` and peer policy grants
rooms.

Use `room_topic_policies()` and
`set_room_topic_policy(room_id, agent_id, topic, publish=True, subscribe=True)`
to configure metadata-only room topic grants. Unconfigured topics use room
membership as the compatibility boundary; once any policy exists for a
room/topic, that topic requires explicit publish and subscribe grants.
