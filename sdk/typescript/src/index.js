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
    const safeOptions = constructorOptions(options);
    this.conuBin = constructorBinary(safeOptions.conuBin, "conu");
    this.conudBin = constructorBinary(safeOptions.conudBin, "conud");
    this.mcpBin = constructorBinary(safeOptions.mcpBin, "conu-mcp");
    this.cwd = constructorStringOption(safeOptions.cwd, this.conuBin, "cwd", true);
    this.env = constructorEnv(safeOptions.env, this.conuBin);
    if (safeOptions.home !== undefined && safeOptions.home !== null) {
      this.env.CONU_HOME = constructorStringOption(safeOptions.home, this.conuBin, "home", false);
    }
    this.runner = safeOptions.runner ?? defaultRunner;
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
    return this.runJson(this.conuBin, [
      "agents",
      "export",
      commandArg(agentId, this.conuBin),
      "--json",
    ]);
  }

  trustAgentCard(card) {
    const capabilities = isRecord(card.capabilities) ? card.capabilities : {};
    return this.runJson(this.conuBin, [
      "agents",
      "trust",
      commandArg(card.agentId, this.conuBin),
      commandArg(card.displayName, this.conuBin),
      "--node",
      commandArg(card.nodeId, this.conuBin),
      "--kind",
      commandArg(card.kind ?? "remote-agent", this.conuBin),
      "--signing-key",
      commandArg(card.signingPublicKeyHex, this.conuBin),
      "--signature",
      commandArg(card.signatureHex, this.conuBin),
      "--signature-key-id",
      commandArg(card.signatureKeyId, this.conuBin),
      "--signature-algorithm",
      commandArg(card.signatureAlgorithm ?? "Ed25519", this.conuBin),
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
    const args = ["peers", "policy", commandArg(peerNodeId, this.conuBin), "--json"];
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
      commandArg(peerNodeId, this.conuBin),
      commandArg(displayName, this.conuBin),
      "--exchange-key",
      commandArg(exchangePublicKeyHex, this.conuBin),
      "--json",
    ];
    if (options.relayEndpoint !== undefined) {
      args.push("--relay", commandArg(options.relayEndpoint, this.conuBin));
    }
    if (options.directQuicEndpoint !== undefined) {
      args.push("--direct", commandArg(options.directQuicEndpoint, this.conuBin));
    }
    if (options.signingPublicKeyHex !== undefined) {
      args.push("--signing-key", commandArg(options.signingPublicKeyHex, this.conuBin));
    }
    if (options.signatureHex !== undefined) {
      args.push("--signature", commandArg(options.signatureHex, this.conuBin));
    }
    if (options.signatureKeyId !== undefined) {
      args.push("--signature-key-id", commandArg(options.signatureKeyId, this.conuBin));
    }
    if (options.signatureAlgorithm !== undefined) {
      args.push("--signature-algorithm", commandArg(options.signatureAlgorithm, this.conuBin));
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
    return this.runJson(this.conuBin, [
      "messages",
      "inbox",
      commandArg(agentId, this.conuBin),
      "--json",
    ]);
  }

  waitForMessage(agentId, options = {}) {
    const args = [
      "messages",
      "wait",
      commandArg(agentId, this.conuBin),
      "--timeout-ms",
      commandArg(options.timeoutMs ?? 30000, this.conuBin),
      "--interval-ms",
      commandArg(options.intervalMs ?? 250, this.conuBin),
      "--json",
    ];
    if (options.afterEnvelopeId !== undefined && options.afterEnvelopeId !== null) {
      args.push("--after", commandArg(options.afterEnvelopeId, this.conuBin));
    }
    if (options.processIpc) {
      args.push("--process-ipc");
    }
    return this.runJson(this.conuBin, args);
  }

  receiveMessage(agentId, envelopeId, options = {}) {
    return this.callMcpTool("conu_receive_message", {
      agentId: commandArg(agentId, this.mcpBin),
      envelopeId: commandArg(envelopeId, this.mcpBin),
      includePayload: Boolean(options.includePayload),
    });
  }

  receiveMessageBytes(agentId, envelopeId) {
    const received = this.receiveMessage(agentId, envelopeId, { includePayload: true });
    if (typeof received.payloadHex !== "string") {
      throw new ConuError(
        "conU receive response did not include payloadHex",
        resultForError({ code: 1 }, this.mcpBin),
      );
    }
    return hexToBuffer(received.payloadHex, this.mcpBin);
  }

  receipts() {
    return this.runJson(this.conuBin, ["messages", "receipts", "--json"]);
  }

  registerAgent(agentId, displayName, options = {}) {
    return this.runJson(this.conuBin, [
      "agents",
      "register",
      commandArg(agentId, this.conuBin),
      commandArg(displayName, this.conuBin),
      "--kind",
      commandArg(options.kind ?? "local-agent", this.conuBin),
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
      commandArg(agentId, this.conuBin),
      "--presence",
      commandArg(presence, this.conuBin),
      "--json",
    ]);
  }

  sendMessage(fromAgentId, toAgentId, payload) {
    return this.runJson(
      this.conuBin,
      [
        "messages",
        "send",
        commandArg(fromAgentId, this.conuBin),
        commandArg(toAgentId, this.conuBin),
        "--stdin",
        "--json",
      ],
      toBuffer(payload, this.conuBin),
    );
  }

  sendRemoteMessage(fromAgentId, toAgentId, peerNodeId, payload) {
    return this.runJson(
      this.conuBin,
      [
        "messages",
        "send",
        commandArg(fromAgentId, this.conuBin),
        commandArg(toAgentId, this.conuBin),
        "--peer",
        commandArg(peerNodeId, this.conuBin),
        "--stdin",
        "--json",
      ],
      toBuffer(payload, this.conuBin),
    );
  }

  createRoom(roomId, displayName, agentId) {
    return this.runJson(this.conuBin, [
      "rooms",
      "create",
      commandArg(roomId, this.conuBin),
      commandArg(displayName, this.conuBin),
      "--agent",
      commandArg(agentId, this.conuBin),
      "--json",
    ]);
  }

  joinRoom(roomId, agentId) {
    return this.runJson(this.conuBin, [
      "rooms",
      "join",
      commandArg(roomId, this.conuBin),
      commandArg(agentId, this.conuBin),
      "--json",
    ]);
  }

  publishRoomEvent(roomId, fromAgentId, topic, payload) {
    return this.runJson(
      this.conuBin,
      [
        "rooms",
        "publish",
        commandArg(roomId, this.conuBin),
        commandArg(fromAgentId, this.conuBin),
        commandArg(topic, this.conuBin),
        "--stdin",
        "--json",
      ],
      toBuffer(payload, this.conuBin),
    );
  }

  roomTopicPolicies() {
    return this.runJson(this.conuBin, ["rooms", "policy", "--json"]);
  }

  setRoomTopicPolicy(roomId, agentId, topic, options = {}) {
    const args = [
      "rooms",
      "policy",
      commandArg(roomId, this.conuBin),
      commandArg(agentId, this.conuBin),
      commandArg(topic, this.conuBin),
      "--json",
    ];
    pushOptionalBool(args, "--publish", options.publish);
    pushOptionalBool(args, "--subscribe", options.subscribe);
    return this.runJson(this.conuBin, args);
  }

  connectLocal(fromAgentId, toAgentId, kind = "message") {
    return this.runJson(this.conuBin, [
      "connect",
      "local",
      commandArg(fromAgentId, this.conuBin),
      commandArg(toAgentId, this.conuBin),
      "--kind",
      commandArg(kind, this.conuBin),
      "--json",
    ]);
  }

  connectRoom(roomId, agentId) {
    return this.runJson(this.conuBin, [
      "connect",
      "room",
      commandArg(roomId, this.conuBin),
      commandArg(agentId, this.conuBin),
      "--json",
    ]);
  }

  relaySync(waitMs = 1000) {
    return this.runJson(this.conuBin, [
      "relay",
      "sync",
      "--wait-ms",
      commandArg(waitMs, this.conuBin),
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
      toBuffer(token, this.conuBin),
    );
  }

  clearRelayCredential() {
    return this.runJson(this.conuBin, ["relay", "credential", "clear", "--json"]);
  }

  openStream(fromAgentId, toAgentId, kind = "message") {
    return this.runJson(this.conuBin, [
      "streams",
      "open",
      commandArg(fromAgentId, this.conuBin),
      commandArg(toAgentId, this.conuBin),
      "--kind",
      commandArg(kind, this.conuBin),
      "--json",
    ]);
  }

  writeStream(streamId, payload) {
    return this.runJson(
      this.conuBin,
      ["streams", "write", commandArg(streamId, this.conuBin), "--stdin", "--json"],
      toBuffer(payload, this.conuBin),
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
      args.push("--max-bytes", commandArg(options.maxBytes, this.conuBin));
    }
    if (options.keep !== undefined) {
      args.push("--keep", commandArg(options.keep, this.conuBin));
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
    return parseJsonForSdk(result.stdout, binary, "conU command returned invalid JSON");
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
    const response = parseMcpResponse(result.stdout, this.mcpBin);
    if (response.error) {
      throw new ConuError(
        `conU MCP tool failed: ${safeMcpError(response.error)}`,
        resultForError({ code: 1 }, this.mcpBin),
      );
    }
    const toolResult = response.result;
    if (!isRecord(toolResult)) {
      throw new ConuError(
        "conU MCP response did not include a tool result",
        resultForError({ code: 1 }, this.mcpBin),
      );
    }
    if (toolResult.isError === true) {
      throw new ConuError(
        "conU MCP tool failed: [details redacted]",
        resultForError({ code: 1 }, this.mcpBin),
      );
    }
    return parseJsonForSdk(
      toolText(toolResult, this.mcpBin),
      this.mcpBin,
      "conU MCP tool returned invalid JSON",
    );
  }

  run(binary, args = [], input) {
    const safeBinary = normalizeCommandBinary(binary);
    const safeArgs = normalizeCommandArgs(args, safeBinary);
    let result;
    try {
      result = this.runner({
        binary: safeBinary,
        args: safeArgs,
        input,
        cwd: this.cwd,
        env: this.env,
      });
    } catch (_error) {
      throw new ConuError(
        `conU command failed before execution: ${safeCommandForError(safeBinary)}`,
        resultForError({ code: 1 }, safeBinary),
      );
    }
    result = normalizeRunnerResult(result, safeBinary);
    if (result.code !== 0) {
      const safeResult = resultForError(result, safeBinary);
      throw new ConuError(
        `conU command failed (${safeResult.code}): ${safeCommandForError(safeBinary)}`,
        safeResult,
      );
    }
    return result;
  }
}

function constructorOptions(options) {
  if (options === undefined) {
    return {};
  }
  if (!isRecord(options)) {
    throw constructorOptionError("options", "conu");
  }
  try {
    return {
      conuBin: options.conuBin,
      conudBin: options.conudBin,
      mcpBin: options.mcpBin,
      cwd: options.cwd,
      env: options.env,
      home: options.home,
      runner: options.runner,
    };
  } catch (_error) {
    throw constructorOptionError("options", "conu");
  }
}

function constructorBinary(binary, fallback) {
  if (binary === undefined || binary === null) {
    return fallback;
  }
  return normalizeCommandBinary(binary);
}

function constructorStringOption(value, binary, name, optional) {
  if (value === undefined || value === null) {
    if (optional) {
      return undefined;
    }
    throw constructorOptionError(name, binary);
  }
  try {
    if (typeof value === "string" && value.trim().length > 0) {
      return value;
    }
  } catch (_error) {
    // Fall through to the redacted constructor option error below.
  }
  throw constructorOptionError(name, binary);
}

function constructorEnv(env, binary) {
  const safeEnv = { ...process.env };
  if (env === undefined || env === null) {
    return safeEnv;
  }
  try {
    if (!isRecord(env)) {
      throw new TypeError("environment overrides must be an object");
    }
    for (const [key, value] of Object.entries(env)) {
      if (key.length === 0 || key.includes("=") || key.includes("\0")) {
        throw new TypeError("environment variable name is invalid");
      }
      if (value === undefined) {
        safeEnv[key] = undefined;
      } else if (typeof value === "string") {
        safeEnv[key] = value;
      } else {
        throw new TypeError("environment variable value must be a string or undefined");
      }
    }
    return safeEnv;
  } catch (_error) {
    throw constructorOptionError("environment", binary);
  }
}

function constructorOptionError(name, binary) {
  return new ConuError(
    `conU constructor ${name} could not be encoded: ${safeCommandForError(binary)}`,
    resultForError({ code: 1 }, binary),
  );
}

function normalizeCommandBinary(binary) {
  if (typeof binary === "string" && binary.trim().length > 0) {
    return binary;
  }
  throw new ConuError(
    `conU command binary could not be encoded: ${safeCommandForError(binary)}`,
    resultForError({ code: 1 }, binary),
  );
}

function normalizeCommandArgs(args, binary) {
  const safeArgs = [];
  try {
    if (!Array.isArray(args)) {
      throw new TypeError("command arguments must be an array");
    }
    for (let index = 0; index < args.length; index += 1) {
      safeArgs.push(commandArg(args[index], binary));
    }
  } catch (error) {
    if (error instanceof ConuError) {
      throw error;
    }
    throw new ConuError(
      `conU command argument could not be encoded: ${safeCommandForError(binary)}`,
      resultForError({ code: 1 }, binary),
    );
  }
  return safeArgs;
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
    const result = resultForError({
      args: [binary, ...args],
      stdout: "",
      stderr: "",
      code: typeof completed.status === "number" ? completed.status : 1,
    }, binary);
    const reason = typeof completed.error.code === "string" ? completed.error.code : "spawn_error";
    throw new ConuError(
      `conU command failed before execution (${reason}): ${safeCommandForError(binary)}`,
      result,
    );
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

function commandArg(value, binary) {
  try {
    if (typeof value === "string") {
      return value;
    }
    if (
      typeof value === "number"
      || typeof value === "boolean"
      || typeof value === "bigint"
    ) {
      return String(value);
    }
  } catch (_error) {
    // Fall through to the redacted SDK boundary error below.
  }
  throw new ConuError(
    `conU command argument could not be encoded: ${safeCommandForError(binary)}`,
    resultForError({ code: 1 }, binary),
  );
}

function toBuffer(value, binary) {
  try {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    if (value instanceof Uint8Array) {
      return Buffer.from(value);
    }
    if (typeof value === "string") {
      return Buffer.from(value, "utf8");
    }
  } catch (_error) {
    // Fall through to the redacted SDK boundary error below.
  }
  throw new ConuError(
    `conU stdin payload could not be encoded: ${safeCommandForError(binary)}`,
    resultForError({ code: 1 }, binary),
  );
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

function normalizeRunnerResult(result, binary) {
  if (!isRecord(result)) {
    throw new ConuError(
      `conU command returned invalid runner result: ${safeCommandForError(binary)}`,
      resultForError({ code: 1 }, binary),
    );
  }
  try {
    return {
      args: Array.isArray(result.args) ? result.args.map((value) => String(value)) : [],
      stdout: typeof result.stdout === "string" ? result.stdout : decode(result.stdout),
      stderr: typeof result.stderr === "string" ? result.stderr : decode(result.stderr),
      code: typeof result.code === "number" ? result.code : 1,
    };
  } catch (_error) {
    throw new ConuError(
      `conU command returned invalid runner result: ${safeCommandForError(binary)}`,
      resultForError({ code: 1 }, binary),
    );
  }
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseMcpResponse(stdout, binary) {
  const line = String(stdout)
    .split(/\r?\n/)
    .map((value) => value.trim())
    .find((value) => value.length > 0);
  if (line === undefined) {
    throw new ConuError(
      "conU MCP response was empty",
      resultForError({ code: 1 }, binary),
    );
  }
  return parseJsonForSdk(line, binary, "conU MCP response was invalid JSON");
}

function toolText(toolResult, binary) {
  const content = Array.isArray(toolResult.content) ? toolResult.content : [];
  const text = content.find((item) => isRecord(item) && item.type === "text")?.text;
  if (typeof text !== "string") {
    throw new ConuError(
      "conU MCP tool response did not include text content",
      resultForError({ code: 1 }, binary),
    );
  }
  return text;
}

function safeMcpError(error) {
  if (isRecord(error) && typeof error.code === "number") {
    return `code ${error.code}`;
  }
  return "unknown MCP error";
}

function parseJsonForSdk(text, binary, message) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (_error) {
    throw new ConuError(message, resultForError({ code: 1 }, binary));
  }
  if (!isRecord(value)) {
    throw new ConuError(message, resultForError({ code: 1 }, binary));
  }
  return value;
}

function resultForError(result, binary) {
  return {
    args: [safeBinaryName(binary), "[arguments redacted]"],
    stdout: "",
    stderr: "",
    code: typeof result?.code === "number" ? result.code : 1,
    contentsDisplayed: false,
    argsRedacted: true,
    stdioRedacted: true,
  };
}

function safeCommandForError(binary) {
  return `${safeBinaryName(binary)} [arguments redacted]`;
}

function safeBinaryName(binary) {
  const value = typeof binary === "string" ? binary.trim() : "conu";
  if (value.includes("://") || /[@?#]/.test(value)) {
    return "conu";
  }
  const base = value.split(/[\\/]/).filter(Boolean).at(-1) ?? "conu";
  return base.replace(/[^\w.-]/g, "_") || "conu";
}

function hexToBuffer(hex, binary) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new ConuError(
      "conU receive response included invalid payloadHex",
      resultForError({ code: 1 }, binary),
    );
  }
  return Buffer.from(hex, "hex");
}
