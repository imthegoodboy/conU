import { ConuClient } from "../../sdk/typescript/src/index.js";

const client = new ConuClient({ home: ".conu-typescript-example" });

client.init();
client.registerAgent("agent.alpha", "Alpha", { streams: true, rooms: true });
client.registerAgent("agent.beta", "Beta", { streams: true, rooms: true });
client.processQueued();

const sent = client.sendMessage("agent.alpha", "agent.beta", Buffer.from("private bytes"));
client.processQueued();
const inbox = client.inbox("agent.beta");

console.log(
  JSON.stringify(
    {
      sentEnvelopeId: sent.envelopeId,
      inboxEntries: Array.isArray(inbox.entries) ? inbox.entries.length : 0,
      contentsDisplayed: false,
    },
    null,
    2,
  ),
);
