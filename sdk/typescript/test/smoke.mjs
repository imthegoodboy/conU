import assert from "node:assert/strict";
import { ConuClient, ConuError } from "../src/index.js";

const calls = [];
const client = new ConuClient({
  conuBin: "conu-test",
  conudBin: "conud-test",
  home: "C:/tmp/conu-ts-sdk",
  runner({ binary, args, input, env }) {
    calls.push({ binary, args, input, env });
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
