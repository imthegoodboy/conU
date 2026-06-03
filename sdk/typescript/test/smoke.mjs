import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ConuClient, ConuError } from "../src/index.js";
import {
  BrowserUnsupportedError,
  ConuClient as BrowserConuClient,
  browserSupport,
} from "../src/browser.js";

assert.deepEqual(browserSupport, {
  supported: false,
  packageKind: "node-wrapper",
  reason:
    "@conu/sdk currently wraps local conu/conud/conu-mcp binaries and is not browser-native.",
  safeNextStep:
    "Use @conu/sdk from Node.js, or wait for a future browser-native protocol package.",
  contentsDisplayed: false,
});
assert.throws(() => new BrowserConuClient(), BrowserUnsupportedError);
assert.ok(!browserSupport.reason.includes("token"));
assert.ok(!browserSupport.reason.includes("payload"));

const nodeDeclarations = readFileSync(new URL("../src/index.d.ts", import.meta.url), "utf8");
for (const field of ["contentsDisplayed", "argsRedacted", "stdioRedacted"]) {
  assert.ok(
    nodeDeclarations.includes(`${field}?: boolean;`),
    `TypeScript declarations should expose CommandResult.${field}`,
  );
}

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

const secretEndpoint = "wss://user:secret@relay.example.com/conu?token=private#fragment";
const endpointFailing = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner({ binary, args }) {
    return {
      args: [binary, ...args],
      stdout: "stdout with private fixture",
      stderr: `stderr with ${secretEndpoint}`,
      code: 2,
    };
  },
});

assert.throws(
  () =>
    endpointFailing.trustPeer("node.peer", "Peer", "aa", {
      relayEndpoint: secretEndpoint,
    }),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);

const throwingRunner = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner({ binary, args, input }) {
    throw new Error(
      `runner leaked ${binary} ${args.join(" ")} ${input?.toString("utf8")} ${secretEndpoint}`,
    );
  },
});

assert.throws(
  () => throwingRunner.sendMessage("agent.alpha", "agent.beta", "private bytes"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private bytes"));
    assert.equal(error.message, "conU command failed before execution: conu-test.exe [arguments redacted]");
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.stdout, "");
    assert.equal(error.result.stderr, "");
    assert.equal(error.result.code, 1);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);

let invalidArgumentRunnerCalled = false;
const invalidArgumentClient = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner() {
    invalidArgumentRunnerCalled = true;
    throw new Error("runner should not execute for invalid command argument");
  },
});
const invalidArgument = {
  toString() {
    throw new Error(`argument conversion leaked ${secretEndpoint}`);
  },
};

assert.throws(
  () =>
    invalidArgumentClient.trustPeer("node.peer", "Peer", "aa", {
      relayEndpoint: invalidArgument,
    }),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command argument could not be encoded: conu-test.exe [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(invalidArgumentRunnerCalled, false);

let invalidMcpArgumentRunnerCalled = false;
const invalidMcpArgumentClient = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner() {
    invalidMcpArgumentRunnerCalled = true;
    throw new Error("runner should not execute for invalid MCP argument");
  },
});

assert.throws(
  () => invalidMcpArgumentClient.receiveMessage(invalidArgument, "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command argument could not be encoded: conu-mcp-test [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(invalidMcpArgumentRunnerCalled, false);

let invalidLowLevelArgumentRunnerCalled = false;
const invalidLowLevelArgumentClient = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner() {
    invalidLowLevelArgumentRunnerCalled = true;
    throw new Error("runner should not execute for invalid low-level command argument");
  },
});

assert.throws(
  () => invalidLowLevelArgumentClient.run("C:/tools/conu-test.exe", ["status", invalidArgument]),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command argument could not be encoded: conu-test.exe [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(invalidLowLevelArgumentRunnerCalled, false);

let poisonedLowLevelArgumentRunnerCalled = false;
const poisonedLowLevelArgumentClient = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner() {
    poisonedLowLevelArgumentRunnerCalled = true;
    throw new Error("runner should not execute for poisoned low-level command arguments");
  },
});
const poisonedLowLevelArgs = [];
Object.defineProperty(poisonedLowLevelArgs, 0, {
  get() {
    throw new Error(`argument getter leaked ${secretEndpoint}`);
  },
});
poisonedLowLevelArgs.length = 1;

assert.throws(
  () => poisonedLowLevelArgumentClient.run("C:/tools/conu-test.exe", poisonedLowLevelArgs),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command argument could not be encoded: conu-test.exe [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(poisonedLowLevelArgumentRunnerCalled, false);

let invalidLowLevelBinaryRunnerCalled = false;
const invalidLowLevelBinaryClient = new ConuClient({
  runner() {
    invalidLowLevelBinaryRunnerCalled = true;
    throw new Error("runner should not execute for invalid low-level command binary");
  },
});
const invalidBinary = {
  toString() {
    throw new Error(`binary conversion leaked ${secretEndpoint}`);
  },
};

assert.throws(
  () =>
    new ConuClient({
      conuBin: invalidBinary,
      runner() {
        throw new Error("runner should not execute for invalid constructor binary");
      },
    }),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command binary could not be encoded: conu [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);

assert.throws(
  () =>
    new ConuClient({
      mcpBin: "",
      runner() {
        throw new Error("runner should not execute for empty constructor binary");
      },
    }),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command binary could not be encoded: conu [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);

assert.throws(
  () => invalidLowLevelBinaryClient.run(invalidBinary, ["status"]),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command binary could not be encoded: conu [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(invalidLowLevelBinaryRunnerCalled, false);

let emptyLowLevelBinaryRunnerCalled = false;
const emptyLowLevelBinaryClient = new ConuClient({
  runner() {
    emptyLowLevelBinaryRunnerCalled = true;
    throw new Error("runner should not execute for empty low-level command binary");
  },
});

assert.throws(
  () => emptyLowLevelBinaryClient.run("", ["status"]),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU command binary could not be encoded: conu [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(emptyLowLevelBinaryRunnerCalled, false);

let invalidPayloadRunnerCalled = false;
const invalidPayloadClient = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner() {
    invalidPayloadRunnerCalled = true;
    throw new Error("runner should not execute for invalid payload");
  },
});
const invalidPayload = {
  toString() {
    throw new Error(`payload conversion leaked ${secretEndpoint}`);
  },
};

assert.throws(
  () => invalidPayloadClient.sendMessage("agent.alpha", "agent.beta", invalidPayload),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.equal(
      error.message,
      "conU stdin payload could not be encoded: conu-test.exe [arguments redacted]",
    );
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.stdout, "");
    assert.equal(error.result.stderr, "");
    assert.equal(error.result.code, 1);
    assert.equal(error.result.contentsDisplayed, false);
    assert.equal(error.result.argsRedacted, true);
    assert.equal(error.result.stdioRedacted, true);
    return true;
  },
);
assert.equal(invalidPayloadRunnerCalled, false);

for (const runner of [
  () => null,
  () => ({
    args: ["conu-test", "status", secretEndpoint],
    stdout: "stdout with private fixture",
    stderr: "stderr with private fixture",
    get code() {
      throw new Error(`runner result leaked ${secretEndpoint}`);
    },
  }),
]) {
  const malformedRunner = new ConuClient({
    conuBin: "C:/tools/conu-test.exe",
    runner,
  });

  assert.throws(
    () => malformedRunner.status(),
    (error) => {
      assert.ok(error instanceof ConuError);
      const rendered = JSON.stringify({
        message: error.message,
        result: error.result,
      });
      assert.ok(!rendered.includes("secret"));
      assert.ok(!rendered.includes("token=private"));
      assert.ok(!rendered.includes("relay.example.com"));
      assert.ok(!rendered.includes("private fixture"));
      assert.equal(
        error.message,
        "conU command returned invalid runner result: conu-test.exe [arguments redacted]",
      );
      assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
      assert.equal(error.result.stdout, "");
      assert.equal(error.result.stderr, "");
      assert.equal(error.result.code, 1);
      assert.equal(error.result.contentsDisplayed, false);
      assert.equal(error.result.argsRedacted, true);
      assert.equal(error.result.stdioRedacted, true);
      return true;
    },
  );
}

for (const mcpFailureMode of ["protocol", "tool"]) {
  const mcpFailing = new ConuClient({
    mcpBin: "conu-mcp-test",
    runner({ binary }) {
      const body =
        mcpFailureMode === "protocol"
          ? {
              jsonrpc: "2.0",
              id: 1,
              error: {
                code: -32602,
                message: `MCP protocol error with ${secretEndpoint}`,
              },
            }
          : {
              jsonrpc: "2.0",
              id: 1,
              result: {
                content: [{ type: "text", text: `MCP tool error with ${secretEndpoint}` }],
                isError: true,
              },
            };
      return {
        args: [binary],
        stdout: JSON.stringify(body),
        stderr: "stderr with private fixture",
        code: 0,
      };
    },
  });

  assert.throws(
    () => mcpFailing.receiveMessage("agent.beta", "env.local.1"),
    (error) => {
      assert.ok(error instanceof ConuError);
      const rendered = JSON.stringify({
        message: error.message,
        result: error.result,
      });
      assert.ok(!rendered.includes("secret"));
      assert.ok(!rendered.includes("token=private"));
      assert.ok(!rendered.includes("relay.example.com"));
      assert.ok(!rendered.includes("private fixture"));
      assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
      assert.equal(error.result.contentsDisplayed, false);
      return true;
    },
  );
}

const mcpMalformed = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: `malformed MCP result with ${secretEndpoint}`,
      }),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => mcpMalformed.receiveMessage("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const mcpMissingText = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [{ type: "resource", text: `MCP content with ${secretEndpoint}` }],
          isError: false,
        },
      }),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => mcpMissingText.receiveMessage("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU MCP tool response did not include text content");
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const receiveMissingPayloadHex = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                payloadReturned: true,
                note: `private fixture with ${secretEndpoint}`,
              }),
            },
          ],
          isError: false,
        },
      }),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => receiveMissingPayloadHex.receiveMessageBytes("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU receive response did not include payloadHex");
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const receiveInvalidPayloadHex = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                payloadHex: secretEndpoint,
                payloadReturned: true,
              }),
            },
          ],
          isError: false,
        },
      }),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => receiveInvalidPayloadHex.receiveMessageBytes("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU receive response included invalid payloadHex");
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const commandJsonMalformed = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: `not json with ${secretEndpoint}`,
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => commandJsonMalformed.status(),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU command returned invalid JSON");
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const commandJsonNonObject = new ConuClient({
  conuBin: "C:/tools/conu-test.exe",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify([`array item with ${secretEndpoint}`]),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => commandJsonNonObject.status(),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU command returned invalid JSON");
    assert.deepEqual(error.result.args, ["conu-test.exe", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const mcpJsonMalformed = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [{ type: "text", text: `not json with ${secretEndpoint}` }],
          isError: false,
        },
      }),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => mcpJsonMalformed.receiveMessage("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU MCP tool returned invalid JSON");
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const mcpJsonNonObject = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify([`array item with ${secretEndpoint}`]),
            },
          ],
          isError: false,
        },
      }),
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => mcpJsonNonObject.receiveMessage("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU MCP tool returned invalid JSON");
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);

const mcpProtocolJsonMalformed = new ConuClient({
  mcpBin: "conu-mcp-test",
  runner({ binary }) {
    return {
      args: [binary],
      stdout: `not json with ${secretEndpoint}`,
      stderr: "stderr with private fixture",
      code: 0,
    };
  },
});

assert.throws(
  () => mcpProtocolJsonMalformed.receiveMessage("agent.beta", "env.local.1"),
  (error) => {
    assert.ok(error instanceof ConuError);
    const rendered = JSON.stringify({
      message: error.message,
      result: error.result,
    });
    assert.ok(!rendered.includes("secret"));
    assert.ok(!rendered.includes("token=private"));
    assert.ok(!rendered.includes("relay.example.com"));
    assert.ok(!rendered.includes("private fixture"));
    assert.equal(error.message, "conU MCP response was invalid JSON");
    assert.deepEqual(error.result.args, ["conu-mcp-test", "[arguments redacted]"]);
    assert.equal(error.result.contentsDisplayed, false);
    return true;
  },
);
