import { spawnSync } from "node:child_process";

export class ConuError extends Error {
  constructor(message, result) {
    super(message);
    this.name = "ConuError";
    this.result = result;
  }
}

export class ConuClient {
  constructor(options = {}) {
    this.conuBin = String(options.conuBin ?? "conu");
    this.conudBin = String(options.conudBin ?? "conud");
    this.mcpBin = String(options.mcpBin ?? "conu-mcp");
    this.cwd = options.cwd === undefined ? undefined : String(options.cwd);
    this.env = { ...process.env, ...(options.env ?? {}) };
    if (options.home !== undefined && options.home !== null) {
      this.env.CONU_HOME = String(options.home);
    }
    this.runner = options.runner ?? defaultRunner;
  }

  init() {
    return this.runConu(["init"]);
  }

  securityAudit() {
    return this.runJson(this.conuBin, ["security", "audit", "--json"]);
  }

  rotateIdentity() {
    return this.runJson(this.conuBin, [
      "security",
      "rotate",
      "identity",
      "--confirm-peer-refresh",
      "--json",
    ]);
  }

  retireIdentityArchives() {
    return this.runJson(this.conuBin, [
      "security",
      "retire",
      "identity",
      "--confirm-peer-refresh-complete",
      "--json",
    ]);
  }

  rotateStorage() {
    return this.runJson(this.conuBin, [
      "security",
      "rotate",
      "storage",
      "--confirm",
      "--json",
    ]);
  }

  retireStorage() {
    return this.runJson(this.conuBin, [
      "security",
      "retire",
      "storage",
      "--confirm",
      "--json",
    ]);
  }

  status() {
    return this.runJson(this.conuBin, ["status", "--json"]);
  }

  agents() {
    return this.runJson(this.conuBin, ["agents", "--json"]);
  }

  exportAgentCard(agentId) {
    return this.runJson(this.conuBin, ["agents", "export", agentId, "--json"]);
  }

  trustAgentCard(card) {
    const capabilities = isRecord(card.capabilities) ? card.capabilities : {};
    return this.runJson(this.conuBin, [
      "agents",
      "trust",
      String(card.agentId),
      String(card.displayName),
      "--node",
      String(card.nodeId),
      "--kind",
      String(card.kind ?? "remote-agent"),
      "--signing-key",
      String(card.signingPublicKeyHex),
      "--signature",
      String(card.signatureHex),
      "--signature-key-id",
      String(card.signatureKeyId),
      "--signature-algorithm",
      String(card.signatureAlgorithm ?? "Ed25519"),
      "--messages",
      boolArg(cardBool(capabilities, "messages", true)),
      "--streams",
      boolArg(cardBool(capabilities, "streams", false)),
      "--rooms",
      boolArg(cardBool(capabilities, "rooms", false)),
      "--files",
      boolArg(cardBool(capabilities, "files", false)),
      "--presence",
      boolArg(cardBool(capabilities, "presence", true)),
      "--json",
    ]);
  }

  peers() {
    return this.runJson(this.conuBin, ["peers", "--json"]);
  }

  peerPolicies() {
    return this.runJson(this.conuBin, ["peers", "policy", "--json"]);
  }

  setPeerPolicy(peerNodeId, options = {}) {
    const args = ["peers", "policy", peerNodeId, "--json"];
    pushOptionalBool(args, "--messages", options.messages);
    pushOptionalBool(args, "--streams", options.streams);
    pushOptionalBool(args, "--rooms", options.rooms);
    pushOptionalBool(args, "--files", options.files);
    pushOptionalBool(args, "--mailbox", options.mailbox);
    return this.runJson(this.conuBin, args);
  }

  identityExport() {
    return this.runJson(this.conuBin, ["identity", "export", "--json"]);
  }

  trustPeer(peerNodeId, displayName, exchangePublicKeyHex, options = {}) {
    const args = [
      "peers",
      "trust",
      peerNodeId,
      displayName,
      "--exchange-key",
      exchangePublicKeyHex,
      "--json",
    ];
    if (options.relayEndpoint !== undefined) {
      args.push("--relay", String(options.relayEndpoint));
    }
    if (options.directQuicEndpoint !== undefined) {
      args.push("--direct", String(options.directQuicEndpoint));
    }
    if (options.signingPublicKeyHex !== undefined) {
      args.push("--signing-key", String(options.signingPublicKeyHex));
    }
    if (options.signatureHex !== undefined) {
      args.push("--signature", String(options.signatureHex));
    }
    if (options.signatureKeyId !== undefined) {
      args.push("--signature-key-id", String(options.signatureKeyId));
    }
    if (options.signatureAlgorithm !== undefined) {
      args.push("--signature-algorithm", String(options.signatureAlgorithm));
    }
    return this.runJson(this.conuBin, args);
  }

  syncRoutes() {
    return this.runJson(this.conuBin, ["routes", "sync", "--json"]);
  }

  routes() {
    return this.runJson(this.conuBin, ["routes", "--json"]);
  }

  routeProbes() {
    return this.runJson(this.conuBin, ["routes", "probes", "--json"]);
  }

  rooms() {
    return this.runJson(this.conuBin, ["rooms", "--json"]);
  }

  roomEvents() {
    return this.runJson(this.conuBin, ["rooms", "events", "--json"]);
  }

  inbox(agentId) {
    return this.runJson(this.conuBin, ["messages", "inbox", agentId, "--json"]);
  }

  receiveMessage(agentId, envelopeId, options = {}) {
    return this.callMcpTool("conu_receive_message", {
      agentId: String(agentId),
      envelopeId: String(envelopeId),
      includePayload: Boolean(options.includePayload),
    });
  }

  receiveMessageBytes(agentId, envelopeId) {
    const received = this.receiveMessage(agentId, envelopeId, { includePayload: true });
    if (typeof received.payloadHex !== "string") {
      throw new Error("conU receive response did not include payloadHex");
    }
    return hexToBuffer(received.payloadHex);
  }

  receipts() {
    return this.runJson(this.conuBin, ["messages", "receipts", "--json"]);
  }

  registerAgent(agentId, displayName, options = {}) {
    return this.runJson(this.conuBin, [
      "agents",
      "register",
      agentId,
      displayName,
      "--kind",
      String(options.kind ?? "local-agent"),
      "--messages",
      boolArg(options.messages ?? true),
      "--streams",
      boolArg(options.streams ?? false),
      "--rooms",
      boolArg(options.rooms ?? false),
      "--files",
      boolArg(options.files ?? false),
      "--presence",
      boolArg(options.presence ?? true),
      "--json",
    ]);
  }

  heartbeat(agentId, presence = "ready") {
    return this.runJson(this.conuBin, [
      "agents",
      "heartbeat",
      agentId,
      "--presence",
      presence,
      "--json",
    ]);
  }

  sendMessage(fromAgentId, toAgentId, payload) {
    return this.runJson(
      this.conuBin,
      ["messages", "send", fromAgentId, toAgentId, "--stdin", "--json"],
      toBuffer(payload),
    );
  }

  sendRemoteMessage(fromAgentId, toAgentId, peerNodeId, payload) {
    return this.runJson(
      this.conuBin,
      [
        "messages",
        "send",
        fromAgentId,
        toAgentId,
        "--peer",
        peerNodeId,
        "--stdin",
        "--json",
      ],
      toBuffer(payload),
    );
  }

  createRoom(roomId, displayName, agentId) {
    return this.runJson(this.conuBin, [
      "rooms",
      "create",
      roomId,
      displayName,
      "--agent",
      agentId,
      "--json",
    ]);
  }

  joinRoom(roomId, agentId) {
    return this.runJson(this.conuBin, ["rooms", "join", roomId, agentId, "--json"]);
  }

  publishRoomEvent(roomId, fromAgentId, topic, payload) {
    return this.runJson(
      this.conuBin,
      ["rooms", "publish", roomId, fromAgentId, topic, "--stdin", "--json"],
      toBuffer(payload),
    );
  }

  roomTopicPolicies() {
    return this.runJson(this.conuBin, ["rooms", "policy", "--json"]);
  }

  setRoomTopicPolicy(roomId, agentId, topic, options = {}) {
    const args = ["rooms", "policy", roomId, agentId, topic, "--json"];
    pushOptionalBool(args, "--publish", options.publish);
    pushOptionalBool(args, "--subscribe", options.subscribe);
    return this.runJson(this.conuBin, args);
  }

  connectLocal(fromAgentId, toAgentId, kind = "message") {
    return this.runJson(this.conuBin, [
      "connect",
      "local",
      fromAgentId,
      toAgentId,
      "--kind",
      kind,
      "--json",
    ]);
  }

  connectRoom(roomId, agentId) {
    return this.runJson(this.conuBin, ["connect", "room", roomId, agentId, "--json"]);
  }

  relaySync(waitMs = 1000) {
    return this.runJson(this.conuBin, [
      "relay",
      "sync",
      "--wait-ms",
      String(waitMs),
      "--json",
    ]);
  }

  relayCredentialStatus() {
    return this.runJson(this.conuBin, ["relay", "credential", "status", "--json"]);
  }

  setRelayCredential(token) {
    return this.runJson(
      this.conuBin,
      ["relay", "credential", "set", "--stdin", "--json"],
      toBuffer(token),
    );
  }

  clearRelayCredential() {
    return this.runJson(this.conuBin, ["relay", "credential", "clear", "--json"]);
  }

  openStream(fromAgentId, toAgentId, kind = "message") {
    return this.runJson(this.conuBin, [
      "streams",
      "open",
      fromAgentId,
      toAgentId,
      "--kind",
      kind,
      "--json",
    ]);
  }

  writeStream(streamId, payload) {
    return this.runJson(
      this.conuBin,
      ["streams", "write", streamId, "--stdin", "--json"],
      toBuffer(payload),
    );
  }

  closeStream(streamId) {
    return this.runJson(this.conuBin, ["streams", "close", streamId, "--json"]);
  }

  telemetrySnapshot() {
    return this.runJson(this.conuBin, ["telemetry", "snapshot", "--json"]);
  }

  rotateLogs(options = {}) {
    const args = ["logs", "rotate", "--json"];
    if (options.maxBytes !== undefined) {
      args.push("--max-bytes", String(options.maxBytes));
    }
    if (options.keep !== undefined) {
      args.push("--keep", String(options.keep));
    }
    return this.runJson(this.conuBin, args);
  }

  processQueued() {
    return this.run(this.conudBin, ["--process-ipc"]);
  }

  runConu(args, input) {
    return this.run(this.conuBin, args, input);
  }

  runJson(binary, args, input) {
    const result = this.run(binary, args, input);
    return JSON.parse(result.stdout);
  }

  callMcpTool(name, argumentsValue = {}) {
    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: argumentsValue,
      },
    };
    const result = this.run(
      this.mcpBin,
      [],
      Buffer.from(`${JSON.stringify(request)}\n`, "utf8"),
    );
    const response = parseMcpResponse(result.stdout);
    if (response.error) {
      throw new ConuError(`conU MCP tool failed: ${safeMcpError(response.error)}`, result);
    }
    const toolResult = response.result;
    if (!isRecord(toolResult)) {
      throw new ConuError("conU MCP response did not include a tool result", result);
    }
    if (toolResult.isError === true) {
      throw new ConuError(`conU MCP tool failed: ${toolText(toolResult)}`, result);
    }
    return JSON.parse(toolText(toolResult));
  }

  run(binary, args = [], input) {
    const result = this.runner({
      binary,
      args,
      input,
      cwd: this.cwd,
      env: this.env,
    });
    if (result.code !== 0) {
      throw new ConuError(`conU command failed (${result.code}): ${binary} ${args.join(" ")}`, result);
    }
    return result;
  }
}

function defaultRunner({ binary, args, input, cwd, env }) {
  const completed = spawnSync(binary, args, {
    input,
    cwd,
    env,
    encoding: "buffer",
    windowsHide: true,
  });
  if (completed.error) {
    const result = {
      args: [binary, ...args],
      stdout: "",
      stderr: completed.error.message,
      code: typeof completed.status === "number" ? completed.status : 1,
    };
    throw new ConuError(`conU command failed: ${completed.error.message}`, result);
  }
  return {
    args: [binary, ...args],
    stdout: decode(completed.stdout),
    stderr: decode(completed.stderr),
    code: typeof completed.status === "number" ? completed.status : 1,
  };
}

function decode(value) {
  if (value === null || value === undefined) {
    return "";
  }
  return Buffer.from(value).toString("utf8");
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  return Buffer.from(String(value), "utf8");
}

function boolArg(value) {
  return value ? "true" : "false";
}

function pushOptionalBool(args, flag, value) {
  if (value !== undefined && value !== null) {
    args.push(flag, boolArg(Boolean(value)));
  }
}

function cardBool(values, key, defaultValue) {
  const value = values[key];
  return typeof value === "boolean" ? value : defaultValue;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseMcpResponse(stdout) {
  const line = String(stdout)
    .split(/\r?\n/)
    .map((value) => value.trim())
    .find((value) => value.length > 0);
  if (line === undefined) {
    throw new Error("conU MCP response was empty");
  }
  return JSON.parse(line);
}

function toolText(toolResult) {
  const content = Array.isArray(toolResult.content) ? toolResult.content : [];
  const text = content.find((item) => isRecord(item) && item.type === "text")?.text;
  if (typeof text !== "string") {
    throw new Error("conU MCP tool response did not include text content");
  }
  return text;
}

function safeMcpError(error) {
  if (isRecord(error) && typeof error.message === "string") {
    return error.message;
  }
  return "unknown MCP error";
}

function hexToBuffer(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("conU receive response included invalid payloadHex");
  }
  return Buffer.from(hex, "hex");
}
