from __future__ import annotations

import os
import tempfile

from conu_sdk import ConuClient


def main() -> None:
    home = os.path.join(tempfile.gettempdir(), "conu-python-example")
    client = ConuClient(home=home)

    client.init()
    client.register_agent("agent.python.alice", "Alice Python Agent")
    client.register_agent("agent.python.bob", "Bob Python Agent")
    client.process_queued()

    result = client.send_message(
        "agent.python.alice",
        "agent.python.bob",
        b"example private payload",
    )
    client.process_queued()

    print(f"queued request {result['requestId']}")
    print(f"opaque bytes {result['payloadBytes']}")
    print("payload contents were not displayed by conU")


if __name__ == "__main__":
    main()
