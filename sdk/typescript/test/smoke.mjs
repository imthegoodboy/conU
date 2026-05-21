import assert from "node:assert/strict";
import { ConuClient, ConuError } from "../src/index.js";

const calls = [];
const client = new ConuClient({
  conuBin: "conu-test",
  conudBin: "conud-test",
  mcpBin: "conu-mcp-test",
  home: "C:/tmp/conu-ts-sdk",
  runner({ binary, args, input, env }) {
    calls.push({ binary, args, input, env });
    if (binary === "conu-mcp-test") {
      const request = JSON.parse(Buffer.from(input).toString("utf8").trim());
      const includePayload = request.params.arguments.includePayload === true;
      const body = {
        envelopeId: request.params.arguments.envelopeId,
        fromAgentId: "agent.alpha",
        toAgentId: request.params.arguments.agentId,
        payloadBytes: 13,
        payloadReturned: includePayload,
        contentsDisplayed: false,
      };
      if (includePayload) {
        body.payloadHex = Buffer.from("private bytes").toString("hex");
        body.payloadEncoding = "hex";
      }
      return {
        args: [binary, ...args],
        stdout: JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          result: {
            content: [{ type: "text", text: JSON.stringify(body) }],
            isError: false,
          },
        }),
        stderr: "",
        code: 0,
      };
    }
    return {
      args: [binary, ...args],
      stdout: JSON.stringify({ ok: true, command: args.join(" "), contentsDisplayed: false }),
      stderr: "",
      code: 0,
    };
  },
});

const sent = client.sendMessage("agent.alpha", "agent.beta", Buffer.from("private bytes"));
assert.equal(sent.ok, true);
assert.deepEqual(calls.at(-1).args, [
  "messages",
  "send",
  "agent.alpha",
  "agent.beta",
  "--stdin",
  "--json",
]);
assert.equal(calls.at(-1).input.toString("utf8"), "private bytes");
assert.ok(!calls.at(-1).args.includes("private bytes"));
assert.equal(calls.at(-1).env.CONU_HOME, "C:/tmp/conu-ts-sdk");

const metadata = client.receiveMessage("agent.beta", "env.local.1");
assert.equal(metadata.payloadReturned, false);
assert.deepEqual(calls.at(-1).args, []);
let mcpRequest = JSON.parse(calls.at(-1).input.toString("utf8").trim());
assert.equal(mcpRequest.method, "tools/call");
assert.equal(mcpRequest.params.name, "conu_receive_message");
assert.equal(mcpRequest.params.arguments.agentId, "agent.beta");
assert.equal(mcpRequest.params.arguments.envelopeId, "env.local.1");
assert.equal(mcpRequest.params.arguments.includePayload, false);

const received = client.receiveMessageBytes("agent.beta", "env.local.1");
assert.equal(Buffer.from(received).toString("utf8"), "private bytes");
assert.deepEqual(calls.at(-1).args, []);
mcpRequest = JSON.parse(calls.at(-1).input.toString("utf8").trim());
assert.equal(mcpRequest.params.arguments.includePayload, true);
assert.ok(!calls.at(-1).args.includes("private bytes"));

client.setRelayCredential("secret relay token");
assert.deepEqual(calls.at(-1).args, [
  "relay",
  "credential",
  "set",
  "--stdin",
  "--json",
]);
assert.equal(calls.at(-1).input.toString("utf8"), "secret relay token");
assert.ok(!calls.at(-1).args.includes("secret relay token"));

client.registerAgent("agent.alpha", "Alpha", { streams: true, rooms: true });
assert.deepEqual(calls.at(-1).args, [
  "agents",
  "register",
  "agent.alpha",
  "Alpha",
  "--kind",
  "local-agent",
  "--messages",
  "true",
  "--streams",
  "true",
  "--rooms",
  "true",
  "--files",
  "false",
  "--presence",
  "true",
  "--json",
]);

client.setPeerPolicy("node.peer", { messages: true, streams: false, rooms: true });
assert.deepEqual(calls.at(-1).args, [
  "peers",
  "policy",
  "node.peer",
  "--json",
  "--messages",
  "true",
  "--streams",
  "false",
  "--rooms",
  "true",
]);

client.trustAgentCard({
  agentId: "agent.remote",
  displayName: "Remote",
  nodeId: "node.peer",
  signingPublicKeyHex: "aa",
  signatureHex: "bb",
  signatureKeyId: "key-1",
});
assert.deepEqual(calls.at(-1).args, [
  "agents",
  "trust",
  "agent.remote",
  "Remote",
  "--node",
  "node.peer",
  "--kind",
  "remote-agent",
  "--signing-key",
  "aa",
  "--signature",
  "bb",
  "--signature-key-id",
  "key-1",
  "--signature-algorithm",
  "Ed25519",
  "--messages",
  "true",
  "--streams",
  "false",
  "--rooms",
  "false",
  "--files",
  "false",
  "--presence",
  "true",
  "--json",
]);

client.retireIdentityArchives();
assert.deepEqual(calls.at(-1).args, [
  "security",
  "retire",
  "identity",
  "--confirm-peer-refresh-complete",
  "--json",
]);

const failing = new ConuClient({
  runner() {
    return { args: ["conu"], stdout: "", stderr: "safe metadata error", code: 2 };
  },
});
assert.throws(() => failing.status(), ConuError);
