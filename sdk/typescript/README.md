# conU TypeScript SDK

This dependency-free package lets TypeScript and JavaScript agents call an
installed `conu` and `conud` binary without parsing terminal UI by hand.

```ts
import { ConuClient } from "@conu/sdk";

const client = new ConuClient({ home: ".conu-agent" });
client.init();
client.registerAgent("agent.alpha", "Alpha", { streams: true, rooms: true });
client.registerAgent("agent.beta", "Beta", { streams: true, rooms: true });
client.processQueued();

const sent = client.sendMessage("agent.alpha", "agent.beta", "private bytes");
console.log(sent.payloadBytes);
```

The SDK does not log or print payloads. Message, stream, room, and relay
credential bytes are passed to conU through stdin. List, send, route, room,
security, relay, telemetry, and status methods return JSON metadata from the
CLI.

The wrapper follows the CLI metadata boundary for inbox listing and does not
add a raw payload receive helper yet. Use the Rust SDK or MCP explicit receive
path when an addressed local agent needs inbox bytes.

Useful calls include:

- `registerAgent()`, `heartbeat()`, `agents()`
- `identityExport()`, `trustPeer()`, `setPeerPolicy()`
- `exportAgentCard()`, `trustAgentCard()`
- `sendMessage()`, `sendRemoteMessage()`, `inbox()`, `receipts()`
- `openStream()`, `writeStream()`, `closeStream()`
- `createRoom()`, `joinRoom()`, `publishRoomEvent()`, `setRoomTopicPolicy()`
- `relaySync()`, `setRelayCredential()`, `relayCredentialStatus()`
- `securityAudit()`, `rotateIdentity()`, `retireIdentityArchives()`,
  `rotateStorage()`, `retireStorage()`
- `telemetrySnapshot()`, `rotateLogs()`

`registerAgent()` defaults to message and presence capability only. Pass
`streams: true` or `rooms: true` before using stream and room helpers so core
routing can enforce explicit local capabilities.

Run the local package check:

```powershell
npm run check --prefix sdk/typescript
```
