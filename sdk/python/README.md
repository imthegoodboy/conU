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
print(sent["payloadBytes"])
```

The wrapper does not log or print payloads. Message payload bytes are sent to
`conu messages send --stdin`; metadata commands use `--json`.
