export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export interface CommandResult {
  args: string[];
  stdout: string;
  stderr: string;
  code: number;
}

export interface RunnerInput {
  binary: string;
  args: string[];
  input?: Uint8Array;
  cwd?: string;
  env: Record<string, string | undefined>;
}

export type CommandRunner = (input: RunnerInput) => CommandResult;

export interface ConuClientOptions {
  conuBin?: string;
  conudBin?: string;
  mcpBin?: string;
  home?: string;
  env?: Record<string, string | undefined>;
  cwd?: string;
  runner?: CommandRunner;
}

export interface AgentCapabilityOptions {
  messages?: boolean;
  streams?: boolean;
  rooms?: boolean;
  files?: boolean;
  presence?: boolean;
}

export interface RegisterAgentOptions extends AgentCapabilityOptions {
  kind?: string;
}

export interface PeerPolicyOptions {
  messages?: boolean;
  streams?: boolean;
  rooms?: boolean;
  files?: boolean;
  mailbox?: boolean;
}

export interface RoomTopicPolicyOptions {
  publish?: boolean;
  subscribe?: boolean;
}

export interface TrustPeerOptions {
  relayEndpoint?: string;
  signingPublicKeyHex?: string;
  signatureHex?: string;
  signatureKeyId?: string;
  signatureAlgorithm?: string;
}

export interface RotateLogOptions {
  maxBytes?: number;
  keep?: number;
}

export interface ReceiveMessageOptions {
  includePayload?: boolean;
}

export interface SignedAgentCard {
  agentId: string;
  displayName: string;
  nodeId: string;
  kind?: string;
  capabilities?: AgentCapabilityOptions;
  signingPublicKeyHex: string;
  signatureHex: string;
  signatureKeyId: string;
  signatureAlgorithm?: string;
}

export class ConuError extends Error {
  result: CommandResult;
  constructor(message: string, result: CommandResult);
}

export class ConuClient {
  constructor(options?: ConuClientOptions);
  init(): CommandResult;
  securityAudit(): JsonObject;
  rotateIdentity(): JsonObject;
  retireIdentityArchives(): JsonObject;
  rotateStorage(): JsonObject;
  retireStorage(): JsonObject;
  status(): JsonObject;
  agents(): JsonObject;
  exportAgentCard(agentId: string): JsonObject;
  trustAgentCard(card: SignedAgentCard): JsonObject;
  peers(): JsonObject;
  peerPolicies(): JsonObject;
  setPeerPolicy(peerNodeId: string, options?: PeerPolicyOptions): JsonObject;
  identityExport(): JsonObject;
  trustPeer(
    peerNodeId: string,
    displayName: string,
    exchangePublicKeyHex: string,
    options?: TrustPeerOptions,
  ): JsonObject;
  syncRoutes(): JsonObject;
  routes(): JsonObject;
  routeProbes(): JsonObject;
  rooms(): JsonObject;
  roomEvents(): JsonObject;
  inbox(agentId: string): JsonObject;
  receiveMessage(agentId: string, envelopeId: string, options?: ReceiveMessageOptions): JsonObject;
  receiveMessageBytes(agentId: string, envelopeId: string): Uint8Array;
  receipts(): JsonObject;
  registerAgent(agentId: string, displayName: string, options?: RegisterAgentOptions): JsonObject;
  heartbeat(agentId: string, presence?: string): JsonObject;
  sendMessage(fromAgentId: string, toAgentId: string, payload: Uint8Array | string): JsonObject;
  sendRemoteMessage(
    fromAgentId: string,
    toAgentId: string,
    peerNodeId: string,
    payload: Uint8Array | string,
  ): JsonObject;
  createRoom(roomId: string, displayName: string, agentId: string): JsonObject;
  joinRoom(roomId: string, agentId: string): JsonObject;
  publishRoomEvent(
    roomId: string,
    fromAgentId: string,
    topic: string,
    payload: Uint8Array | string,
  ): JsonObject;
  roomTopicPolicies(): JsonObject;
  setRoomTopicPolicy(
    roomId: string,
    agentId: string,
    topic: string,
    options?: RoomTopicPolicyOptions,
  ): JsonObject;
  connectLocal(fromAgentId: string, toAgentId: string, kind?: string): JsonObject;
  connectRoom(roomId: string, agentId: string): JsonObject;
  relaySync(waitMs?: number): JsonObject;
  relayCredentialStatus(): JsonObject;
  setRelayCredential(token: Uint8Array | string): JsonObject;
  clearRelayCredential(): JsonObject;
  openStream(fromAgentId: string, toAgentId: string, kind?: string): JsonObject;
  writeStream(streamId: string, payload: Uint8Array | string): JsonObject;
  closeStream(streamId: string): JsonObject;
  telemetrySnapshot(): JsonObject;
  rotateLogs(options?: RotateLogOptions): JsonObject;
  processQueued(): CommandResult;
  runConu(args: string[], input?: Uint8Array): CommandResult;
  runJson(binary: string, args: string[], input?: Uint8Array): JsonObject;
  callMcpTool(name: string, argumentsValue?: JsonObject): JsonObject;
  run(binary: string, args?: string[], input?: Uint8Array): CommandResult;
}
