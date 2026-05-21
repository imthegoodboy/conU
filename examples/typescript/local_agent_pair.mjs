import { ConuClient } from "../../sdk/typescript/src/index.js";

const client = new ConuClient({ home: ".conu-typescript-example" });

client.init();
client.registerAgent("agent.alpha", "Alpha", { streams: true, rooms: true });
client.registerAgent("agent.beta", "Beta", { streams: true, rooms: true });
client.processQueued();

const sent = client.sendMessage("agent.alpha", "agent.beta", Buffer.from("private bytes"));
client.processQueued();
const inbox = client.inbox("agent.beta");
const firstEnvelopeId = Array.isArray(inbox.entries) ? inbox.entries[0]?.envelopeId : undefined;
const received = firstEnvelopeId
  ? client.receiveMessageBytes("agent.beta", firstEnvelopeId)
  : Buffer.alloc(0);

console.log(
  JSON.stringify(
    {
      sentEnvelopeId: sent.envelopeId,
      inboxEntries: Array.isArray(inbox.entries) ? inbox.entries.length : 0,
      receivedBytes: received.byteLength,
      contentsDisplayed: false,
    },
    null,
    2,
  ),
);
