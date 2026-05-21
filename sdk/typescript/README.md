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
client.processQueued();
const inbox = client.inbox("agent.beta");
const payload = client.receiveMessageBytes("agent.beta", inbox.entries[0].envelopeId);
console.log({ sentBytes: sent.payloadBytes, receivedBytes: payload.byteLength });
```

The SDK does not log or print payloads. Message, stream, room, and relay
credential bytes are passed to conU through stdin. List, send, route, room,
security, relay, telemetry, and status methods return JSON metadata from the
CLI.

The wrapper follows the CLI metadata boundary for inbox listing. Raw inbox bytes
are returned only through the explicit `receiveMessageBytes(agentId,
envelopeId)` helper, which calls the MCP receive path for an envelope present in
that addressed local agent's inbox.

Useful calls include:

- `registerAgent()`, `heartbeat()`, `agents()`
- `identityExport()`, `trustPeer()`, `setPeerPolicy()`
- `exportAgentCard()`, `trustAgentCard()`
- `sendMessage()`, `sendRemoteMessage()`, `inbox()`, `receiveMessageBytes()`,
  `receipts()`
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
