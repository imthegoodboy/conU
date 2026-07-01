//! MCP stdio adapter for conU.
//!
//! The adapter exposes conU as MCP tools over newline-delimited JSON-RPC on
//! stdin/stdout. Tool outputs are metadata-only unless an addressed local agent
//! explicitly calls `conu_receive_message` with `includePayload: true`.

use std::path::PathBuf;
use std::time::Duration;

use conu_sdk::{
    Capabilities, ConuClient, PeerCard, PeerPolicyUpdate, Presence, Room, RoomBusEvent, Route,
    SdkError, SignedAgentCard, Stream, TopicPolicy, TopicPolicyUpdate,
};
use serde_json::{Map, Value, json};

const JSONRPC_VERSION: &str = "2.0";
const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Minimal MCP server that dispatches conU tools.
#[derive(Debug, Clone)]
pub struct McpServer {
    client: ConuClient,
    bound_agent_id: Option<String>,
}

impl McpServer {
    /// Use the default conU state home.
    pub fn new() -> Self {
        Self {
            client: ConuClient::new(),
            bound_agent_id: bound_agent_from_env(),
        }
    }

    /// Use a specific conU state home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            client: ConuClient::with_home(home),
            bound_agent_id: None,
        }
    }

    /// Use a specific conU state home and bind the server to one local agent id.
    pub fn with_home_and_agent(home: impl Into<PathBuf>, agent_id: impl Into<String>) -> Self {
        Self {
            client: ConuClient::with_home(home),
            bound_agent_id: Some(agent_id.into()),
        }
    }

    /// Handle one newline-delimited JSON-RPC message.
    pub fn handle_line(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let response = match serde_json::from_str::<Value>(line) {
            Ok(message) => self.handle_message(message),
            Err(_) => Some(error_response(Value::Null, -32700, "parse error")),
        }?;

        Some(response.to_string())
    }

    fn handle_message(&self, message: Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(error_response(Value::Null, -32600, "invalid request"));
        };
        let id = object.get("id").cloned();
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return id.map(|id| error_response(id, -32600, "missing method"));
        };

        if matches!(id, Some(Value::Null)) {
            return Some(error_response(
                Value::Null,
                -32600,
                "request id must not be null",
            ));
        }
        let id = id?;

        let result = match method {
            "initialize" => Ok(self.initialize_result()),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tools() })),
            "tools/call" => self.call_tool(object.get("params")),
            _ => Err(jsonrpc_error(-32601, "method not found")),
        };

        Some(match result {
            Ok(result) => json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "result": result
            }),
            Err(error) => json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "error": error
            }),
        })
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "conu-mcp",
                "version": env!("CARGO_PKG_VERSION")
            }
        })
    }

    fn call_tool(&self, params: Option<&Value>) -> Result<Value, Value> {
        let params = params
            .and_then(Value::as_object)
            .ok_or_else(|| jsonrpc_error(-32602, "tools/call requires params"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| jsonrpc_error(-32602, "tools/call requires a tool name"))?;
        let arguments_value = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let arguments = arguments_value
            .as_object()
            .ok_or_else(|| jsonrpc_error(-32602, "tool arguments must be an object"))?;

        let result = match self.dispatch_tool(name, arguments) {
            Ok(value) => tool_success(value),
            Err(error) => tool_failure(error),
        };

        Ok(result)
    }

    fn dispatch_tool(&self, name: &str, args: &Map<String, Value>) -> Result<Value, String> {
        match name {
            "conu_status" => self.tool_status(),
            "conu_security_audit" => self.tool_security_audit(),
            "conu_register_agent" => self.tool_register_agent(args),
            "conu_prepare_agent" => self.tool_prepare_agent(args),
            "conu_set_presence" => self.tool_set_presence(args),
            "conu_process_queued" => self.tool_process_queued(),
            "conu_sync_routes" => self.tool_sync_routes(),
            "conu_list_routes" => self.tool_list_routes(args),
            "conu_list_agents" => self.tool_list_agents(args),
            "conu_export_agent_card" => self.tool_export_agent_card(args),
            "conu_trust_agent_card" => self.tool_trust_agent_card(args),
            "conu_list_peers" => self.tool_list_peers(),
            "conu_export_identity" => self.tool_export_identity(),
            "conu_trust_peer" => self.tool_trust_peer(args),
            "conu_set_peer_policy" => self.tool_set_peer_policy(args),
            "conu_send_message" => self.tool_send_message(args),
            "conu_send_remote_message" => self.tool_send_remote_message(args),
            "conu_relay_sync" => self.tool_relay_sync(args),
            "conu_receive_message" => self.tool_receive_message(args),
            "conu_open_stream" => self.tool_open_stream(args),
            "conu_write_stream" => self.tool_write_stream(args),
            "conu_close_stream" => self.tool_close_stream(args),
            "conu_create_room" => self.tool_create_room(args),
            "conu_join_room" => self.tool_join_room(args),
            "conu_list_rooms" => self.tool_list_rooms(),
            "conu_publish_room_event" => self.tool_publish_room_event(args),
            "conu_list_room_events" => self.tool_list_room_events(),
            "conu_set_room_topic_policy" => self.tool_set_room_topic_policy(args),
            "conu_list_room_topic_policies" => self.tool_list_room_topic_policies(),
            _ => Err(format!("unknown conU tool: {name}")),
        }
    }

    fn tool_status(&self) -> Result<Value, String> {
        let snapshot = self.client.state_snapshot().map_err(safe_sdk_error)?;
        let runtime = self.client.runtime_status().map_err(safe_sdk_error)?;
        let agents = self
            .client
            .list_agents()
            .unwrap_or_else(|_| conu_sdk::AgentDirectory {
                local: Vec::new(),
                remote: Vec::new(),
            });

        Ok(json!({
            "initialized": snapshot.is_initialized(),
            "nodeId": snapshot.node.as_ref().map(|node| node.node_id.as_str()),
            "runtime": runtime.state.as_str(),
            "localEndpoint": runtime.local_endpoint,
            "localAgents": agents.local.len(),
            "remoteAgents": agents.remote.len(),
            "contentsDisplayed": false
        }))
    }

    fn tool_security_audit(&self) -> Result<Value, String> {
        let audit = self.client.security_audit().map_err(safe_sdk_error)?;
        Ok(json!({
            "initialized": audit.initialized,
            "identitySigningKey": audit.identity_signing_key,
            "identityExchangeKey": audit.identity_exchange_key,
            "storageKey": audit.storage_key,
            "replayCache": audit.replay_cache,
            "keyRotationPlan": audit.key_rotation_plan,
            "localPayloadEncryption": audit.local_payload_encryption,
            "signedAgentCards": audit.signed_agent_cards,
            "peerKeyExchange": audit.peer_key_exchange,
            "secretStorageBackend": audit.secret_storage_backend,
            "secretsOsProtected": audit.secrets_os_protected,
            "contentsDisplayed": audit.contents_displayed
        }))
    }

    fn tool_register_agent(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let display_name = required_string(args, "displayName")?;
        let kind = optional_string(args, "kind")?.unwrap_or_else(|| "local-agent".to_string());
        let capabilities = capabilities_from_args(args)?;
        let submission = self
            .client
            .register_agent_with_capabilities(&agent_id, &display_name, &kind, capabilities)
            .map_err(safe_sdk_error)?;
        let process = if optional_bool(args, "process", true)? {
            Some(self.client.process_queued().map_err(safe_sdk_error)?)
        } else {
            None
        };

        Ok(json!({
            "status": if process.is_some() { "processed" } else { "queued" },
            "agentId": agent_id,
            "requestId": submission.request_id,
            "processed": process.as_ref().map(|report| report.agents.processed),
            "rejected": process.as_ref().map(|report| report.agents.rejected),
            "contentsDisplayed": false
        }))
    }

    fn tool_prepare_agent(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let display_name = required_string(args, "displayName")?;
        let kind = optional_string(args, "kind")?.unwrap_or_else(|| "local-agent".to_string());
        let capabilities = prepared_capabilities_from_args(args)?;
        let presence = match optional_string(args, "presence")? {
            Some(value) => presence_from_str(&value)?,
            None => Presence::Ready,
        };
        let connect_to_agent_id = optional_string(args, "connectToAgentId")?;
        let stream_kind = optional_string(args, "streamKind")?.unwrap_or_else(|| "message".into());
        let room_id = optional_string(args, "roomId")?;
        let room_display_name = optional_string(args, "roomDisplayName")?;

        if matches!(connect_to_agent_id.as_deref(), Some(peer_id) if peer_id == agent_id) {
            return Err("connectToAgentId must be different from agentId".to_string());
        }

        let registration = self
            .client
            .register_agent_with_capabilities(&agent_id, &display_name, &kind, capabilities.clone())
            .map_err(safe_sdk_error)?;
        let registration_processed = self.client.process_queued().map_err(safe_sdk_error)?;
        let presence_submission = if capabilities.presence {
            Some(
                self.client
                    .set_presence(&agent_id, presence)
                    .map_err(safe_sdk_error)?,
            )
        } else {
            None
        };
        let presence_processed = if presence_submission.is_some() {
            Some(self.client.process_queued().map_err(safe_sdk_error)?)
        } else {
            None
        };
        let mut registered_agents = registration_processed.agents.registered_agents.clone();
        let mut heartbeat_agents = registration_processed.agents.heartbeat_agents.clone();
        if let Some(report) = presence_processed.as_ref() {
            registered_agents.extend(report.agents.registered_agents.clone());
            heartbeat_agents.extend(report.agents.heartbeat_agents.clone());
        }
        let processed_agents = registration_processed.agents.processed
            + presence_processed
                .as_ref()
                .map(|report| report.agents.processed)
                .unwrap_or(0);
        let rejected_agents = registration_processed.agents.rejected
            + presence_processed
                .as_ref()
                .map(|report| report.agents.rejected)
                .unwrap_or(0);
        let messages_delivered = registration_processed.messages.delivered
            + presence_processed
                .as_ref()
                .map(|report| report.messages.delivered)
                .unwrap_or(0);
        let sessions_synced = registration_processed.sessions.sessions_synced
            + presence_processed
                .as_ref()
                .map(|report| report.sessions.sessions_synced)
                .unwrap_or(0);

        let stream = if let Some(to_agent_id) = connect_to_agent_id {
            Some(self.prepare_agent_stream(&agent_id, &to_agent_id, &stream_kind)?)
        } else {
            None
        };
        let room = if let Some(room_id) = room_id {
            let display_name = room_display_name.unwrap_or_else(|| room_id.clone());
            Some(self.prepare_agent_room(&agent_id, &room_id, &display_name)?)
        } else {
            None
        };

        Ok(json!({
            "status": "ready",
            "agentId": agent_id,
            "displayName": display_name,
            "kind": kind,
            "capabilities": capabilities_to_json(&capabilities),
            "presence": if capabilities.presence { Some(presence.as_str()) } else { None },
            "registrationRequestId": registration.request_id,
            "presenceRequestId": presence_submission.map(|submission| submission.request_id),
            "processed": {
                "agents": processed_agents,
                "rejected": rejected_agents,
                "registeredAgents": registered_agents,
                "heartbeatAgents": heartbeat_agents,
                "messagesDelivered": messages_delivered,
                "sessionsSynced": sessions_synced
            },
            "stream": stream,
            "room": room,
            "contentsDisplayed": false
        }))
    }

    fn tool_set_presence(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let presence = presence_from_args(args)?;
        let submission = self
            .client
            .set_presence(&agent_id, presence)
            .map_err(safe_sdk_error)?;
        let process = if optional_bool(args, "process", true)? {
            Some(self.client.process_queued().map_err(safe_sdk_error)?)
        } else {
            None
        };

        Ok(json!({
            "status": if process.is_some() { "processed" } else { "queued" },
            "agentId": agent_id,
            "presence": presence.as_str(),
            "requestId": submission.request_id,
            "processed": process.as_ref().map(|report| report.agents.processed),
            "rejected": process.as_ref().map(|report| report.agents.rejected),
            "contentsDisplayed": false
        }))
    }

    fn tool_process_queued(&self) -> Result<Value, String> {
        let report = self.client.process_queued().map_err(safe_sdk_error)?;
        Ok(json!({
            "agents": {
                "processed": report.agents.processed,
                "rejected": report.agents.rejected,
                "registeredAgents": report.agents.registered_agents,
                "heartbeatAgents": report.agents.heartbeat_agents
            },
            "messages": {
                "delivered": report.messages.delivered,
                "rejected": report.messages.rejected,
                "envelopeIds": report.messages.envelope_ids
            },
            "sessions": {
                "sessionsSynced": report.sessions.sessions_synced,
                "remoteAgentsSynced": report.sessions.remote_agents_synced,
                "connected": report.sessions.connected,
                "reconnecting": report.sessions.reconnecting,
                "offline": report.sessions.offline
            },
            "contentsDisplayed": false
        }))
    }

    fn tool_sync_routes(&self) -> Result<Value, String> {
        let report = self.client.sync_routes().map_err(safe_sdk_error)?;
        Ok(json!({
            "status": "synced",
            "peers": report.peers,
            "candidates": report.candidates,
            "directAttempts": report.direct_attempts,
            "directAvailable": report.direct_available,
            "selectedDirect": report.selected_direct,
            "selectedRelay": report.selected_relay,
            "relayFallbacks": report.relay_fallbacks,
            "natTraversalUnavailable": report.nat_traversal_unavailable,
            "probesRecorded": report.probes_recorded,
            "contentsDisplayed": false
        }))
    }

    fn tool_list_routes(&self, args: &Map<String, Value>) -> Result<Value, String> {
        if optional_bool(args, "sync", false)? {
            self.client.sync_routes().map_err(safe_sdk_error)?;
        }
        let routes = self.client.list_routes().map_err(safe_sdk_error)?;
        Ok(json!({
            "routes": routes.iter().map(route_to_json).collect::<Vec<_>>(),
            "contentsDisplayed": false
        }))
    }

    fn tool_list_agents(&self, args: &Map<String, Value>) -> Result<Value, String> {
        if optional_bool(args, "process", false)? {
            self.client.process_queued().map_err(safe_sdk_error)?;
        }
        let directory = self.client.list_agents().map_err(safe_sdk_error)?;

        Ok(json!({
            "local": directory.local.iter().map(|agent| json!({
                "agentId": &agent.agent_id,
                "displayName": &agent.display_name,
                "kind": &agent.kind,
                "presence": agent.presence.as_str(),
                "nodeId": &agent.node_id,
                "lastSeenUnix": agent.last_seen_unix,
                "capabilities": capabilities_to_json(&agent.capabilities),
                "agentCardSigned": agent.signature_hex.is_some()
            })).collect::<Vec<_>>(),
            "remote": directory.remote.iter().map(|agent| json!({
                "agentId": &agent.agent_id,
                "displayName": &agent.display_name,
                "kind": &agent.kind,
                "presence": agent.presence.as_str(),
                "nodeId": &agent.node_id,
                "peerNodeId": &agent.peer_node_id,
                "lastSeenUnix": agent.last_seen_unix,
                "capabilities": capabilities_to_json(&agent.capabilities),
                "agentCardSigned": agent.agent_card_signed()
            })).collect::<Vec<_>>(),
            "contentsDisplayed": false
        }))
    }

    fn tool_export_agent_card(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let card = self
            .client
            .export_agent_card(&agent_id)
            .map_err(safe_sdk_error)?;

        Ok(signed_agent_card_to_json(&card))
    }

    fn tool_trust_agent_card(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let card = SignedAgentCard {
            agent_id: required_string(args, "agentId")?,
            display_name: required_string(args, "displayName")?,
            node_id: required_string(args, "nodeId")?,
            kind: required_string(args, "kind")?,
            capabilities: capabilities_from_args(args)?,
            signature_algorithm: optional_string(args, "signatureAlgorithm")?
                .unwrap_or_else(|| "ed25519-v1".to_string()),
            signature_key_id: required_string(args, "signatureKeyId")?,
            signing_public_key_hex: required_string(args, "signingPublicKeyHex")?,
            signature_hex: required_string(args, "signatureHex")?,
        };
        let agent = self
            .client
            .trust_remote_agent_card(card)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "trusted_remote_agent",
            "agentId": agent.agent_id,
            "nodeId": agent.node_id,
            "peerNodeId": agent.peer_node_id,
            "capabilities": capabilities_to_json(&agent.capabilities),
            "agentCardSigned": agent.agent_card_signed(),
            "contentsDisplayed": false
        }))
    }

    fn tool_list_peers(&self) -> Result<Value, String> {
        let peers = self.client.list_peers().map_err(safe_sdk_error)?;
        Ok(json!({
            "peers": peers.iter().map(|peer| json!({
                "peerNodeId": &peer.peer_node_id,
                "displayName": &peer.display_name,
                "status": peer.status.as_str(),
                "source": &peer.source,
                "exchangeKeyTrusted": peer.exchange_public_key_hex.is_some(),
                "peerCardSigned": peer.signature_hex.is_some(),
                "relayEndpoint": peer.relay_endpoint.as_deref(),
                "directQuicEndpoint": peer.direct_quic_endpoint.as_deref(),
                "createdAtUnix": peer.created_at_unix,
                "updatedAtUnix": peer.updated_at_unix
            })).collect::<Vec<_>>(),
            "contentsDisplayed": false
        }))
    }

    fn tool_export_identity(&self) -> Result<Value, String> {
        let card = self.client.export_peer_card().map_err(safe_sdk_error)?;
        Ok(json!({
            "nodeId": card.node_id,
            "displayName": card.display_name,
            "exchangePublicKeyHex": card.exchange_public_key_hex,
            "relayEndpoint": card.relay_endpoint,
            "directQuicEndpoint": card.direct_quic_endpoint,
            "signingPublicKeyHex": card.signing_public_key_hex,
            "signatureAlgorithm": card.signature_algorithm,
            "signatureKeyId": card.signature_key_id,
            "signatureHex": card.signature_hex,
            "peerCardSigned": card.signature_hex.is_some(),
            "contentsDisplayed": false
        }))
    }

    fn tool_trust_peer(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let card = PeerCard {
            node_id: required_string(args, "peerNodeId")?,
            display_name: required_string(args, "displayName")?,
            exchange_public_key_hex: required_string(args, "exchangePublicKeyHex")?,
            relay_endpoint: optional_string(args, "relayEndpoint")?
                .unwrap_or_else(|| "ws://127.0.0.1:8787".to_string()),
            direct_quic_endpoint: optional_string(args, "directQuicEndpoint")?,
            signing_public_key_hex: optional_string(args, "signingPublicKeyHex")?,
            signature_algorithm: optional_string(args, "signatureAlgorithm")?,
            signature_key_id: optional_string(args, "signatureKeyId")?,
            signature_hex: optional_string(args, "signatureHex")?,
        };
        let peer = self.client.trust_peer_card(card).map_err(safe_sdk_error)?;

        Ok(json!({
            "status": peer.status.as_str(),
            "peerNodeId": peer.peer_node_id,
            "displayName": peer.display_name,
            "exchangeKeyTrusted": peer.exchange_public_key_hex.is_some(),
            "peerCardSigned": peer.signature_hex.is_some(),
            "relayEndpoint": peer.relay_endpoint,
            "directQuicEndpoint": peer.direct_quic_endpoint,
            "contentsDisplayed": false
        }))
    }

    fn tool_set_peer_policy(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let peer_node_id = required_string(args, "peerNodeId")?;
        let update = PeerPolicyUpdate {
            messages: optional_bool_arg(args, "messages")?,
            streams: optional_bool_arg(args, "streams")?,
            rooms: optional_bool_arg(args, "rooms")?,
            files: optional_bool_arg(args, "files")?,
            mailbox: optional_bool_arg(args, "mailbox")?,
        };
        let policy = self
            .client
            .set_peer_policy(&peer_node_id, update)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "updated",
            "peerNodeId": policy.peer_node_id,
            "policy": {
                "messages": policy.messages,
                "streams": policy.streams,
                "rooms": policy.rooms,
                "files": policy.files,
                "mailbox": policy.mailbox
            },
            "updatedAtUnix": policy.updated_at_unix,
            "contentsDisplayed": false
        }))
    }

    fn tool_send_message(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let from_agent_id = required_string(args, "fromAgentId")?;
        self.ensure_agent_allowed(&from_agent_id)?;
        let to_agent_id = required_string(args, "toAgentId")?;
        let payload = payload_from_args(args)?;
        let submission = self
            .client
            .send_message_bytes(&from_agent_id, &to_agent_id, payload)
            .map_err(safe_sdk_error)?;
        let process = if optional_bool(args, "process", true)? {
            Some(self.client.process_queued().map_err(safe_sdk_error)?)
        } else {
            None
        };

        Ok(json!({
            "status": if process.is_some() { "processed" } else { "queued" },
            "requestId": submission.request_id,
            "fromAgentId": from_agent_id,
            "toAgentId": to_agent_id,
            "payloadBytes": submission.payload_bytes,
            "delivered": process.as_ref().map(|report| report.messages.delivered),
            "rejected": process.as_ref().map(|report| report.messages.rejected),
            "envelopeIds": process
                .as_ref()
                .map(|report| report.messages.envelope_ids.clone())
                .unwrap_or_default(),
            "contentsDisplayed": false
        }))
    }

    fn tool_send_remote_message(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let from_agent_id = required_string(args, "fromAgentId")?;
        self.ensure_agent_allowed(&from_agent_id)?;
        let to_agent_id = required_string(args, "toAgentId")?;
        let peer_node_id = required_string(args, "peerNodeId")?;
        let payload = payload_from_args(args)?;
        let submission = self
            .client
            .send_remote_message_bytes(&from_agent_id, &to_agent_id, &peer_node_id, payload)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "queued_remote",
            "requestId": submission.request_id,
            "envelopeId": submission.envelope_id,
            "fromAgentId": from_agent_id,
            "toAgentId": to_agent_id,
            "peerNodeId": submission.peer_node_id,
            "payloadBytes": submission.payload_bytes,
            "contentsDisplayed": false
        }))
    }

    fn tool_relay_sync(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let wait_ms = optional_u64(args, "waitMs", 1000)?;
        let report = self
            .client
            .relay_sync(Duration::from_millis(wait_ms.min(60_000)))
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "synced",
            "endpoint": report.endpoint,
            "connected": report.connected,
            "queued": report.queued,
            "sent": report.sent,
            "received": report.received,
            "undelivered": report.undelivered,
            "rejected": report.rejected,
            "contentsDisplayed": false
        }))
    }

    fn tool_receive_message(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let envelope_id = required_string(args, "envelopeId")?;
        let include_payload = optional_bool(args, "includePayload", false)?;
        let inbox = self
            .client
            .inbox_metadata(&agent_id)
            .map_err(safe_sdk_error)?;
        let entry = inbox
            .iter()
            .find(|entry| entry.envelope_id == envelope_id)
            .ok_or_else(|| {
                "message envelope was not found in the addressed agent inbox".to_string()
            })?;
        let mut result = json!({
            "envelopeId": &entry.envelope_id,
            "fromAgentId": &entry.from_agent_id,
            "toAgentId": &entry.to_agent_id,
            "receiptId": &entry.receipt_id,
            "deliveredAtUnix": entry.delivered_at_unix,
            "payloadBytes": entry.payload_bytes,
            "payloadReturned": false,
            "contentsDisplayed": false
        });

        if include_payload {
            let payload = self
                .client
                .receive_message_bytes(&agent_id, &envelope_id)
                .map_err(safe_sdk_error)?;
            result["payloadHex"] = Value::String(hex_encode(&payload));
            result["payloadEncoding"] = Value::String("hex".to_string());
            result["payloadReturned"] = Value::Bool(true);
        }

        Ok(result)
    }

    fn tool_open_stream(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let from_agent_id = required_string(args, "fromAgentId")?;
        self.ensure_agent_allowed(&from_agent_id)?;
        let to_agent_id = required_string(args, "toAgentId")?;
        let kind = optional_string(args, "kind")?.unwrap_or_else(|| "message".to_string());
        let report = self
            .client
            .open_stream(&from_agent_id, &to_agent_id, &kind)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "stream": stream_to_json(&report.stream),
            "contentsDisplayed": false
        }))
    }

    fn tool_write_stream(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let stream_id = required_string(args, "streamId")?;
        self.ensure_stream_owned(&stream_id)?;
        let payload = payload_from_args(args)?;
        let report = self
            .client
            .write_stream_bytes(&stream_id, payload)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "stream": stream_to_json(&report.stream),
            "event": {
                "eventId": report.event.event_id,
                "eventType": report.event.event_type,
                "payloadBytes": report.event.payload_bytes,
                "createdAtUnix": report.event.created_at_unix
            },
            "contentsDisplayed": false
        }))
    }

    fn tool_close_stream(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let stream_id = required_string(args, "streamId")?;
        self.ensure_stream_owned(&stream_id)?;
        let report = self
            .client
            .close_stream(&stream_id)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "stream": stream_to_json(&report.stream),
            "event": {
                "eventId": report.event.event_id,
                "eventType": report.event.event_type,
                "payloadBytes": report.event.payload_bytes,
                "createdAtUnix": report.event.created_at_unix
            },
            "contentsDisplayed": false
        }))
    }

    fn tool_create_room(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let room_id = required_string(args, "roomId")?;
        let display_name = required_string(args, "displayName")?;
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let report = self
            .client
            .create_room(&room_id, &display_name, &agent_id)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "created",
            "room": room_to_json(&report.room),
            "contentsDisplayed": false
        }))
    }

    fn tool_join_room(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let room_id = required_string(args, "roomId")?;
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let report = self
            .client
            .join_room(&room_id, &agent_id)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": if report.joined { "joined" } else { "already_joined" },
            "room": room_to_json(&report.room),
            "contentsDisplayed": false
        }))
    }

    fn tool_list_rooms(&self) -> Result<Value, String> {
        let rooms = self.client.list_rooms().map_err(safe_sdk_error)?;

        Ok(json!({
            "rooms": rooms.iter().map(room_to_json).collect::<Vec<_>>(),
            "contentsDisplayed": false
        }))
    }

    fn tool_publish_room_event(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let room_id = required_string(args, "roomId")?;
        let from_agent_id = required_string(args, "fromAgentId")?;
        self.ensure_agent_allowed(&from_agent_id)?;
        let topic = required_string(args, "topic")?;
        let payload = payload_from_args(args)?;
        let report = self
            .client
            .publish_room_event_bytes(&room_id, &from_agent_id, &topic, payload)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "published",
            "roomId": report.room.room_id,
            "eventsPublished": report.room.events_published,
            "bytesPublished": report.room.bytes_published,
            "localDeliveries": report.local_deliveries,
            "remoteDeliveries": report.remote_deliveries,
            "event": room_event_to_json(&report.event),
            "contentsDisplayed": false
        }))
    }

    fn tool_list_room_events(&self) -> Result<Value, String> {
        let events = self.client.list_room_events().map_err(safe_sdk_error)?;

        Ok(json!({
            "events": events.iter().map(room_event_to_json).collect::<Vec<_>>(),
            "contentsDisplayed": false
        }))
    }

    fn tool_set_room_topic_policy(&self, args: &Map<String, Value>) -> Result<Value, String> {
        let room_id = required_string(args, "roomId")?;
        let agent_id = required_string(args, "agentId")?;
        self.ensure_agent_allowed(&agent_id)?;
        let topic = required_string(args, "topic")?;
        let update = TopicPolicyUpdate {
            publish: optional_bool_arg(args, "publish")?,
            subscribe: optional_bool_arg(args, "subscribe")?,
        };
        let policy = self
            .client
            .set_room_topic_policy(&room_id, &agent_id, &topic, update)
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "status": "updated",
            "policy": room_topic_policy_to_json(&policy),
            "contentsDisplayed": false
        }))
    }

    fn tool_list_room_topic_policies(&self) -> Result<Value, String> {
        let policies = self
            .client
            .list_room_topic_policies()
            .map_err(safe_sdk_error)?;

        Ok(json!({
            "topicPolicies": policies
                .iter()
                .map(room_topic_policy_to_json)
                .collect::<Vec<_>>(),
            "contentsDisplayed": false
        }))
    }

    fn tools(&self) -> Vec<Value> {
        vec![
            tool(
                "conu_status",
                "Read conU node, runtime, and agent counts.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_security_audit",
                "Read conU security-control status without exposing keys or payloads.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_register_agent",
                "Register the calling agent with conU's local gateway.",
                schema(
                    json!({
                        "agentId": { "type": "string" },
                        "displayName": { "type": "string" },
                        "kind": { "type": "string" },
                        "process": { "type": "boolean" },
                        "capabilities": capability_schema()
                    }),
                    vec!["agentId", "displayName"],
                ),
            ),
            tool(
                "conu_prepare_agent",
                "Register one local agent, mark it ready, and optionally prepare a stream or room for that agent.",
                schema(
                    json!({
                        "agentId": { "type": "string" },
                        "displayName": { "type": "string" },
                        "kind": { "type": "string" },
                        "capabilities": capability_schema(),
                        "presence": { "type": "string", "enum": ["ready", "busy", "idle", "offline"] },
                        "connectToAgentId": { "type": "string" },
                        "streamKind": { "type": "string" },
                        "roomId": { "type": "string" },
                        "roomDisplayName": { "type": "string" }
                    }),
                    vec!["agentId", "displayName"],
                ),
            ),
            tool(
                "conu_set_presence",
                "Publish a local agent presence heartbeat.",
                schema(
                    json!({
                        "agentId": { "type": "string" },
                        "presence": { "type": "string", "enum": ["ready", "busy", "idle", "offline"] },
                        "process": { "type": "boolean" }
                    }),
                    vec!["agentId", "presence"],
                ),
            ),
            tool(
                "conu_process_queued",
                "Process queued conU gateway work once.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_sync_routes",
                "Probe and score direct/relay routes for trusted peers.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_list_routes",
                "List direct QUIC and relay route candidates without payloads.",
                schema(json!({ "sync": { "type": "boolean" } }), vec![]),
            ),
            tool(
                "conu_list_agents",
                "List local and trusted remote agent metadata.",
                schema(json!({ "process": { "type": "boolean" } }), vec![]),
            ),
            tool(
                "conu_export_agent_card",
                "Export a signed public local agent card for a trusted peer.",
                schema(
                    json!({
                        "agentId": { "type": "string" }
                    }),
                    vec!["agentId"],
                ),
            ),
            tool(
                "conu_trust_agent_card",
                "Trust a signed remote agent card from an already trusted peer.",
                schema(
                    json!({
                        "agentId": { "type": "string" },
                        "displayName": { "type": "string" },
                        "nodeId": { "type": "string" },
                        "kind": { "type": "string" },
                        "capabilities": capability_schema(),
                        "signingPublicKeyHex": { "type": "string" },
                        "signatureAlgorithm": { "type": "string" },
                        "signatureKeyId": { "type": "string" },
                        "signatureHex": { "type": "string" }
                    }),
                    vec![
                        "agentId",
                        "displayName",
                        "nodeId",
                        "kind",
                        "capabilities",
                        "signingPublicKeyHex",
                        "signatureKeyId",
                        "signatureHex",
                    ],
                ),
            ),
            tool(
                "conu_list_peers",
                "List trusted and revoked peer metadata.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_export_identity",
                "Export this node's public peer card for cross-machine trust.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_trust_peer",
                "Trust a remote node from its public peer card.",
                schema(
                    json!({
                        "peerNodeId": { "type": "string" },
                        "displayName": { "type": "string" },
                        "exchangePublicKeyHex": { "type": "string" },
                        "relayEndpoint": { "type": "string" },
                        "directQuicEndpoint": { "type": "string" },
                        "signingPublicKeyHex": { "type": "string" },
                        "signatureAlgorithm": { "type": "string" },
                        "signatureKeyId": { "type": "string" },
                        "signatureHex": { "type": "string" }
                    }),
                    vec!["peerNodeId", "displayName", "exchangePublicKeyHex"],
                ),
            ),
            tool(
                "conu_set_peer_policy",
                "Grant or revoke communication surfaces for a trusted peer.",
                schema(
                    json!({
                        "peerNodeId": { "type": "string" },
                        "messages": { "type": "boolean" },
                        "streams": { "type": "boolean" },
                        "rooms": { "type": "boolean" },
                        "files": { "type": "boolean" },
                        "mailbox": { "type": "boolean" }
                    }),
                    vec!["peerNodeId"],
                ),
            ),
            tool(
                "conu_send_message",
                "Queue an opaque message. The response reports metadata and byte counts only.",
                schema(
                    json!({
                        "fromAgentId": { "type": "string" },
                        "toAgentId": { "type": "string" },
                        "payloadText": { "type": "string" },
                        "payloadHex": { "type": "string" },
                        "process": { "type": "boolean" }
                    }),
                    vec!["fromAgentId", "toAgentId"],
                ),
            ),
            tool(
                "conu_send_remote_message",
                "Queue a peer-encrypted remote message for relay delivery.",
                schema(
                    json!({
                        "fromAgentId": { "type": "string" },
                        "toAgentId": { "type": "string" },
                        "peerNodeId": { "type": "string" },
                        "payloadText": { "type": "string" },
                        "payloadHex": { "type": "string" }
                    }),
                    vec!["fromAgentId", "toAgentId", "peerNodeId"],
                ),
            ),
            tool(
                "conu_relay_sync",
                "Connect to the relay once, flush outbound remote messages, and receive inbound envelopes.",
                schema(json!({ "waitMs": { "type": "integer" } }), vec![]),
            ),
            tool(
                "conu_receive_message",
                "Read message metadata, and optionally return payloadHex to the addressed local agent.",
                schema(
                    json!({
                        "agentId": { "type": "string" },
                        "envelopeId": { "type": "string" },
                        "includePayload": { "type": "boolean" }
                    }),
                    vec!["agentId", "envelopeId"],
                ),
            ),
            tool(
                "conu_open_stream",
                "Open a metadata-tracked stream between visible agents.",
                schema(
                    json!({
                        "fromAgentId": { "type": "string" },
                        "toAgentId": { "type": "string" },
                        "kind": { "type": "string" }
                    }),
                    vec!["fromAgentId", "toAgentId"],
                ),
            ),
            tool(
                "conu_write_stream",
                "Record one opaque stream chunk by byte count.",
                schema(
                    json!({
                        "streamId": { "type": "string" },
                        "payloadText": { "type": "string" },
                        "payloadHex": { "type": "string" }
                    }),
                    vec!["streamId"],
                ),
            ),
            tool(
                "conu_close_stream",
                "Close a metadata-tracked stream.",
                schema(
                    json!({ "streamId": { "type": "string" } }),
                    vec!["streamId"],
                ),
            ),
            tool(
                "conu_create_room",
                "Create a room bus owned by a registered local agent.",
                schema(
                    json!({
                        "roomId": { "type": "string" },
                        "displayName": { "type": "string" },
                        "agentId": { "type": "string" }
                    }),
                    vec!["roomId", "displayName", "agentId"],
                ),
            ),
            tool(
                "conu_join_room",
                "Join a visible local or trusted remote agent to a room.",
                schema(
                    json!({
                        "roomId": { "type": "string" },
                        "agentId": { "type": "string" }
                    }),
                    vec!["roomId", "agentId"],
                ),
            ),
            tool(
                "conu_list_rooms",
                "List room metadata without payload contents.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_publish_room_event",
                "Publish an opaque event to a room. The response reports metadata and byte counts only.",
                schema(
                    json!({
                        "roomId": { "type": "string" },
                        "fromAgentId": { "type": "string" },
                        "topic": { "type": "string" },
                        "payloadText": { "type": "string" },
                        "payloadHex": { "type": "string" }
                    }),
                    vec!["roomId", "fromAgentId", "topic"],
                ),
            ),
            tool(
                "conu_list_room_events",
                "List payload-safe room events.",
                schema(json!({}), vec![]),
            ),
            tool(
                "conu_set_room_topic_policy",
                "Set one agent's metadata-only publish/subscribe grants for a room topic.",
                schema(
                    json!({
                        "roomId": { "type": "string" },
                        "agentId": { "type": "string" },
                        "topic": { "type": "string" },
                        "publish": { "type": "boolean" },
                        "subscribe": { "type": "boolean" }
                    }),
                    vec!["roomId", "agentId", "topic"],
                ),
            ),
            tool(
                "conu_list_room_topic_policies",
                "List explicit room topic policy records without payload contents.",
                schema(json!({}), vec![]),
            ),
        ]
    }

    fn ensure_agent_allowed(&self, agent_id: &str) -> Result<(), String> {
        match self.bound_agent_id.as_deref() {
            Some(bound) if bound != agent_id => {
                Err("this conu-mcp server is bound to a different local agent id".to_string())
            }
            _ => Ok(()),
        }
    }

    fn prepare_agent_stream(
        &self,
        from_agent_id: &str,
        to_agent_id: &str,
        kind: &str,
    ) -> Result<Value, String> {
        let existing = self
            .client
            .list_streams()
            .map_err(safe_sdk_error)?
            .into_iter()
            .find(|stream| {
                stream.from_agent_id == from_agent_id
                    && stream.to_agent_id == to_agent_id
                    && stream.kind == kind
                    && stream.state.as_str() == "open"
            });
        let (stream, created) = if let Some(stream) = existing {
            (stream, false)
        } else {
            let report = self
                .client
                .open_stream(from_agent_id, to_agent_id, kind)
                .map_err(safe_sdk_error)?;
            (report.stream, true)
        };

        Ok(json!({
            "created": created,
            "stream": stream_to_json(&stream),
            "contentsDisplayed": false
        }))
    }

    fn prepare_agent_room(
        &self,
        agent_id: &str,
        room_id: &str,
        display_name: &str,
    ) -> Result<Value, String> {
        let existing = self
            .client
            .list_rooms()
            .map_err(safe_sdk_error)?
            .into_iter()
            .find(|room| room.room_id == room_id);
        let (room, created) = if let Some(room) = existing {
            (room, false)
        } else {
            let report = self
                .client
                .create_room(room_id, display_name, agent_id)
                .map_err(safe_sdk_error)?;
            (report.room, true)
        };
        let agent_present = room
            .participants
            .iter()
            .any(|participant| participant.agent_id == agent_id);
        let (room, agent_joined) = if agent_present {
            (room, false)
        } else {
            let report = self
                .client
                .join_room(room_id, agent_id)
                .map_err(safe_sdk_error)?;
            (report.room, report.joined)
        };

        Ok(json!({
            "created": created,
            "agentJoined": agent_joined,
            "agentPresent": true,
            "room": room_to_json(&room),
            "contentsDisplayed": false
        }))
    }

    fn ensure_stream_owned(&self, stream_id: &str) -> Result<(), String> {
        let Some(bound_agent_id) = self.bound_agent_id.as_deref() else {
            return Ok(());
        };
        let stream = self
            .client
            .list_streams()
            .map_err(safe_sdk_error)?
            .into_iter()
            .find(|stream| stream.stream_id == stream_id)
            .ok_or_else(|| "stream is not known".to_string())?;

        if stream.from_agent_id == bound_agent_id {
            Ok(())
        } else {
            Err(
                "this conu-mcp server cannot write or close a stream owned by another local agent"
                    .to_string(),
            )
        }
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema
    })
}

fn schema(properties: Value, required: Vec<&str>) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn capability_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "messages": { "type": "boolean" },
            "streams": { "type": "boolean" },
            "rooms": { "type": "boolean" },
            "files": { "type": "boolean" },
            "presence": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

fn tool_success(result: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
            }
        ],
        "isError": false
    })
}

fn tool_failure(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

fn jsonrpc_error(code: i64, message: &str) -> Value {
    json!({
        "code": code,
        "message": message
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": jsonrpc_error(code, message)
    })
}

fn required_string(args: &Map<String, Value>, key: &'static str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing required argument: {key}"))
}

fn optional_string(args: &Map<String, Value>, key: &'static str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_string()))
        }
        Some(Value::String(_)) => Ok(None),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn optional_bool(
    args: &Map<String, Value>,
    key: &'static str,
    default: bool,
) -> Result<bool, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

fn optional_bool_arg(args: &Map<String, Value>, key: &'static str) -> Result<Option<bool>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

fn optional_u64(args: &Map<String, Value>, key: &'static str, default: u64) -> Result<u64, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("{key} must be an unsigned integer")),
        Some(_) => Err(format!("{key} must be an unsigned integer")),
    }
}

fn presence_from_args(args: &Map<String, Value>) -> Result<Presence, String> {
    let value = required_string(args, "presence")?;
    presence_from_str(&value)
}

fn presence_from_str(value: &str) -> Result<Presence, String> {
    match value {
        "ready" => Ok(Presence::Ready),
        "busy" => Ok(Presence::Busy),
        "idle" => Ok(Presence::Idle),
        "offline" => Ok(Presence::Offline),
        _ => Err("presence must be ready, busy, idle, or offline".to_string()),
    }
}

fn capabilities_from_args(args: &Map<String, Value>) -> Result<Capabilities, String> {
    capabilities_from_args_with_default(args, Capabilities::basic())
}

fn prepared_capabilities_from_args(args: &Map<String, Value>) -> Result<Capabilities, String> {
    let mut capabilities = Capabilities::basic();
    capabilities.messages = true;
    capabilities.streams = true;
    capabilities.rooms = true;
    capabilities.files = false;
    capabilities.presence = true;
    capabilities_from_args_with_default(args, capabilities)
}

fn capabilities_from_args_with_default(
    args: &Map<String, Value>,
    mut capabilities: Capabilities,
) -> Result<Capabilities, String> {
    let Some(value) = args.get("capabilities") else {
        return Ok(capabilities);
    };
    let Some(values) = value.as_object() else {
        return Err("capabilities must be an object".to_string());
    };

    if let Some(value) = values.get("messages").and_then(Value::as_bool) {
        capabilities.messages = value;
    }
    if let Some(value) = values.get("streams").and_then(Value::as_bool) {
        capabilities.streams = value;
    }
    if let Some(value) = values.get("rooms").and_then(Value::as_bool) {
        capabilities.rooms = value;
    }
    if let Some(value) = values.get("files").and_then(Value::as_bool) {
        capabilities.files = value;
    }
    if let Some(value) = values.get("presence").and_then(Value::as_bool) {
        capabilities.presence = value;
    }

    Ok(capabilities)
}

fn payload_from_args(args: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let text = optional_string(args, "payloadText")?;
    let hex = optional_string(args, "payloadHex")?;
    match (text, hex) {
        (Some(_), Some(_)) => Err("provide payloadText or payloadHex, not both".to_string()),
        (Some(value), None) => Ok(value.into_bytes()),
        (None, Some(value)) => hex_decode(&value),
        (None, None) => Err("missing payloadText or payloadHex".to_string()),
    }
}

fn capabilities_to_json(capabilities: &Capabilities) -> Value {
    json!({
        "messages": capabilities.messages,
        "streams": capabilities.streams,
        "rooms": capabilities.rooms,
        "files": capabilities.files,
        "presence": capabilities.presence
    })
}

fn signed_agent_card_to_json(card: &SignedAgentCard) -> Value {
    json!({
        "agentId": &card.agent_id,
        "displayName": &card.display_name,
        "nodeId": &card.node_id,
        "kind": &card.kind,
        "capabilities": capabilities_to_json(&card.capabilities),
        "signatureAlgorithm": &card.signature_algorithm,
        "signatureKeyId": &card.signature_key_id,
        "signingPublicKeyHex": &card.signing_public_key_hex,
        "signatureHex": &card.signature_hex,
        "agentCardSigned": true,
        "contentsDisplayed": false
    })
}

fn stream_to_json(stream: &Stream) -> Value {
    json!({
        "streamId": &stream.stream_id,
        "fromAgentId": &stream.from_agent_id,
        "toAgentId": &stream.to_agent_id,
        "kind": &stream.kind,
        "state": stream.state.as_str(),
        "route": &stream.route,
        "chunksWritten": stream.chunks_written,
        "bytesWritten": stream.bytes_written,
        "backpressureWindow": stream.backpressure_window,
        "openedAtUnix": stream.opened_at_unix,
        "updatedAtUnix": stream.updated_at_unix
    })
}

fn room_to_json(room: &Room) -> Value {
    json!({
        "roomId": &room.room_id,
        "displayName": &room.display_name,
        "state": room.state.as_str(),
        "createdByAgentId": &room.created_by_agent_id,
        "participants": room.participants.iter().map(|participant| json!({
            "agentId": &participant.agent_id,
            "scope": participant.scope.as_str(),
            "joinedAtUnix": participant.joined_at_unix
        })).collect::<Vec<_>>(),
        "topics": &room.topics,
        "eventsPublished": room.events_published,
        "bytesPublished": room.bytes_published,
        "createdAtUnix": room.created_at_unix,
        "updatedAtUnix": room.updated_at_unix,
        "contentsDisplayed": false
    })
}

fn room_event_to_json(event: &RoomBusEvent) -> Value {
    json!({
        "eventId": &event.event_id,
        "roomId": &event.room_id,
        "topic": &event.topic,
        "fromAgentId": &event.from_agent_id,
        "eventType": &event.event_type,
        "route": &event.route,
        "payloadBytes": event.payload_bytes,
        "createdAtUnix": event.created_at_unix,
        "contentsDisplayed": false
    })
}

fn room_topic_policy_to_json(policy: &TopicPolicy) -> Value {
    json!({
        "roomId": &policy.room_id,
        "agentId": &policy.agent_id,
        "topic": &policy.topic,
        "publish": policy.publish,
        "subscribe": policy.subscribe,
        "updatedAtUnix": policy.updated_at_unix,
        "contentsDisplayed": false
    })
}

fn route_to_json(route: &Route) -> Value {
    json!({
        "routeId": &route.route_id,
        "peerNodeId": &route.peer_node_id,
        "displayName": &route.display_name,
        "transport": route.transport.as_str(),
        "endpoint": &route.endpoint,
        "state": route.state.as_str(),
        "score": route.score,
        "latencyMs": route.latency_ms,
        "directAttempted": route.direct_attempted,
        "relayFallback": route.relay_fallback,
        "natProfile": route.nat_profile.as_str(),
        "candidateSource": &route.candidate_source,
        "candidateKind": &route.candidate_kind,
        "rendezvousState": &route.rendezvous_state,
        "failureReason": route.failure_reason.as_deref(),
        "updatedAtUnix": route.updated_at_unix,
        "contentsDisplayed": false
    })
}

fn safe_sdk_error(error: SdkError) -> String {
    error.to_string()
}

fn bound_agent_from_env() -> Option<String> {
    std::env::var("CONU_AGENT_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if (value.len() & 1) == 1 {
        return Err("payloadHex must have an even number of characters".to_string());
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("payloadHex must contain only hex characters".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn initialize_advertises_tools_capability() {
        let server = McpServer::with_home(test_home("init"));
        let response = request(&server, 1, "initialize", json!({}));

        assert_eq!(
            response["result"]["protocolVersion"],
            Value::String(MCP_PROTOCOL_VERSION.to_string())
        );
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_includes_agent_message_and_stream_tools() {
        let server = McpServer::with_home(test_home("tools"));
        let response = request(&server, 1, "tools/list", json!({}));
        let body = response.to_string();

        assert!(body.contains("conu_register_agent"));
        assert!(body.contains("conu_prepare_agent"));
        assert!(body.contains("conu_security_audit"));
        assert!(body.contains("conu_send_message"));
        assert!(body.contains("conu_receive_message"));
        assert!(body.contains("conu_open_stream"));
        assert!(body.contains("conu_create_room"));
        assert!(body.contains("conu_publish_room_event"));
        assert!(body.contains("conu_set_room_topic_policy"));
        assert!(body.contains("conu_list_room_topic_policies"));
        assert!(body.contains("conu_sync_routes"));
        assert!(body.contains("conu_list_routes"));
        assert!(body.contains("conu_export_agent_card"));
        assert!(body.contains("conu_trust_agent_card"));
        assert!(body.contains("conu_set_peer_policy"));
    }

    #[test]
    fn route_tools_return_metadata_only() {
        let server = McpServer::with_home(test_home("routes"));
        let sync = call_tool(&server, 1, "conu_sync_routes", json!({}));
        let routes = call_tool(
            &server,
            2,
            "conu_list_routes",
            json!({
                "sync": true
            }),
        );
        let sync_json: Value = serde_json::from_str(&tool_text(&sync)).expect("sync json");
        let routes_json: Value = serde_json::from_str(&tool_text(&routes)).expect("routes json");
        let body = format!("{sync_json}\n{routes_json}");

        assert_eq!(sync_json["contentsDisplayed"], Value::Bool(false));
        assert_eq!(routes_json["contentsDisplayed"], Value::Bool(false));
        assert_eq!(routes_json["routes"], json!([]));
        assert!(!body.contains("private message contents"));
    }

    #[test]
    fn signed_agent_card_tools_export_and_trust_metadata_only() {
        let alice = McpServer::with_home(test_home("signed-agent-card-alice"));
        let bob = McpServer::with_home(test_home("signed-agent-card-bob"));
        let bob_identity = call_tool(&bob, 1, "conu_export_identity", json!({}));
        let bob_identity_json: Value =
            serde_json::from_str(&tool_text(&bob_identity)).expect("bob identity json");

        call_tool(
            &alice,
            2,
            "conu_trust_peer",
            json!({
                "peerNodeId": bob_identity_json["nodeId"].clone(),
                "displayName": bob_identity_json["displayName"].clone(),
                "exchangePublicKeyHex": bob_identity_json["exchangePublicKeyHex"].clone(),
                "relayEndpoint": bob_identity_json["relayEndpoint"].clone(),
                "signingPublicKeyHex": bob_identity_json["signingPublicKeyHex"].clone(),
                "signatureAlgorithm": bob_identity_json["signatureAlgorithm"].clone(),
                "signatureKeyId": bob_identity_json["signatureKeyId"].clone(),
                "signatureHex": bob_identity_json["signatureHex"].clone()
            }),
        );
        call_tool(
            &bob,
            3,
            "conu_register_agent",
            json!({
                "agentId": "agent.bob",
                "displayName": "Bob",
                "kind": "test-agent",
                "capabilities": {
                    "messages": true,
                    "streams": true,
                    "rooms": true,
                    "files": false,
                    "presence": true
                },
                "process": true
            }),
        );

        let exported = call_tool(
            &bob,
            4,
            "conu_export_agent_card",
            json!({ "agentId": "agent.bob" }),
        );
        let card_json: Value =
            serde_json::from_str(&tool_text(&exported)).expect("agent card json");
        let trusted = call_tool(
            &alice,
            5,
            "conu_trust_agent_card",
            json!({
                "agentId": card_json["agentId"].clone(),
                "displayName": card_json["displayName"].clone(),
                "nodeId": card_json["nodeId"].clone(),
                "kind": card_json["kind"].clone(),
                "capabilities": card_json["capabilities"].clone(),
                "signingPublicKeyHex": card_json["signingPublicKeyHex"].clone(),
                "signatureAlgorithm": card_json["signatureAlgorithm"].clone(),
                "signatureKeyId": card_json["signatureKeyId"].clone(),
                "signatureHex": card_json["signatureHex"].clone()
            }),
        );
        let agents = call_tool(&alice, 6, "conu_list_agents", json!({}));
        let trusted_json: Value =
            serde_json::from_str(&tool_text(&trusted)).expect("trusted agent json");
        let agents_json: Value = serde_json::from_str(&tool_text(&agents)).expect("agents json");
        let body = format!("{exported}\n{trusted}\n{agents}");

        assert_eq!(card_json["agentCardSigned"], Value::Bool(true));
        assert_eq!(card_json["contentsDisplayed"], Value::Bool(false));
        assert_eq!(
            trusted_json["agentId"],
            Value::String("agent.bob".to_string())
        );
        assert_eq!(trusted_json["agentCardSigned"], Value::Bool(true));
        assert_eq!(trusted_json["capabilities"]["streams"], Value::Bool(true));
        assert_eq!(trusted_json["capabilities"]["rooms"], Value::Bool(true));
        assert_eq!(
            agents_json["remote"][0]["agentCardSigned"],
            Value::Bool(true)
        );
        assert!(!body.contains("private message contents"));
        assert!(!body.contains("Review this code"));
    }

    #[test]
    fn peer_policy_tool_sets_scoped_grants_without_payloads() {
        let alice = McpServer::with_home(test_home("peer-policy-alice"));
        let bob = McpServer::with_home(test_home("peer-policy-bob"));
        let bob_identity = call_tool(&bob, 1, "conu_export_identity", json!({}));
        let bob_identity_json: Value =
            serde_json::from_str(&tool_text(&bob_identity)).expect("bob identity json");
        call_tool(
            &alice,
            2,
            "conu_trust_peer",
            json!({
                "peerNodeId": bob_identity_json["nodeId"].clone(),
                "displayName": bob_identity_json["displayName"].clone(),
                "exchangePublicKeyHex": bob_identity_json["exchangePublicKeyHex"].clone(),
                "relayEndpoint": bob_identity_json["relayEndpoint"].clone(),
                "signingPublicKeyHex": bob_identity_json["signingPublicKeyHex"].clone(),
                "signatureAlgorithm": bob_identity_json["signatureAlgorithm"].clone(),
                "signatureKeyId": bob_identity_json["signatureKeyId"].clone(),
                "signatureHex": bob_identity_json["signatureHex"].clone()
            }),
        );

        let policy = call_tool(
            &alice,
            3,
            "conu_set_peer_policy",
            json!({
                "peerNodeId": bob_identity_json["nodeId"].clone(),
                "messages": true,
                "streams": true,
                "rooms": false
            }),
        );
        let policy_json: Value = serde_json::from_str(&tool_text(&policy)).expect("policy json");

        assert_eq!(policy_json["contentsDisplayed"], Value::Bool(false));
        assert_eq!(policy_json["policy"]["messages"], Value::Bool(true));
        assert_eq!(policy_json["policy"]["streams"], Value::Bool(true));
        assert_eq!(policy_json["policy"]["rooms"], Value::Bool(false));
        assert!(!policy.to_string().contains("private message contents"));
    }

    #[test]
    fn security_audit_tool_reports_backend_without_secret_material() {
        let server = McpServer::with_home(test_home("security-audit"));
        let response = call_tool(&server, 1, "conu_security_audit", json!({}));
        let audit_json: Value = serde_json::from_str(&tool_text(&response)).expect("audit json");
        let body = audit_json.to_string();

        assert_eq!(audit_json["contentsDisplayed"], Value::Bool(false));
        assert!(audit_json["secretStorageBackend"].is_string());
        assert!(audit_json["secretsOsProtected"].is_boolean());
        assert!(!body.contains("secret_key_hex"));
        assert!(!body.contains("dpapi_hex"));
        assert!(!body.contains("private message contents"));
    }

    #[test]
    fn prepare_agent_sets_default_collaboration_surfaces_metadata_only() {
        let server = McpServer::with_home(test_home("prepare-agent"));
        call_tool(
            &server,
            1,
            "conu_prepare_agent",
            json!({
                "agentId": "agent.peer",
                "displayName": "Peer Agent"
            }),
        );

        let prepared = call_tool(
            &server,
            2,
            "conu_prepare_agent",
            json!({
                "agentId": "agent.worker",
                "displayName": "Worker Agent",
                "connectToAgentId": "agent.peer",
                "roomId": "room.workshop",
                "roomDisplayName": "Workshop"
            }),
        );
        let repeated = call_tool(
            &server,
            3,
            "conu_prepare_agent",
            json!({
                "agentId": "agent.worker",
                "displayName": "Worker Agent",
                "connectToAgentId": "agent.peer",
                "roomId": "room.workshop",
                "roomDisplayName": "Workshop"
            }),
        );
        let prepared_json: Value =
            serde_json::from_str(&tool_text(&prepared)).expect("prepared json");
        let repeated_json: Value =
            serde_json::from_str(&tool_text(&repeated)).expect("repeated json");
        let body = format!("{prepared}\n{repeated}");

        assert_eq!(prepared_json["status"], Value::String("ready".to_string()));
        assert_eq!(
            prepared_json["agentId"],
            Value::String("agent.worker".to_string())
        );
        assert_eq!(prepared_json["capabilities"]["messages"], Value::Bool(true));
        assert_eq!(prepared_json["capabilities"]["streams"], Value::Bool(true));
        assert_eq!(prepared_json["capabilities"]["rooms"], Value::Bool(true));
        assert_eq!(prepared_json["capabilities"]["presence"], Value::Bool(true));
        assert_eq!(prepared_json["processed"]["rejected"], Value::from(0));
        assert_eq!(
            prepared_json["processed"]["heartbeatAgents"][0],
            Value::String("agent.worker".to_string())
        );
        assert_eq!(prepared_json["stream"]["created"], Value::Bool(true));
        assert_eq!(
            prepared_json["stream"]["stream"]["fromAgentId"],
            Value::String("agent.worker".to_string())
        );
        assert_eq!(
            prepared_json["stream"]["stream"]["toAgentId"],
            Value::String("agent.peer".to_string())
        );
        assert_eq!(prepared_json["room"]["created"], Value::Bool(true));
        assert_eq!(prepared_json["room"]["agentPresent"], Value::Bool(true));
        assert_eq!(
            prepared_json["room"]["room"]["participants"][0]["agentId"],
            Value::String("agent.worker".to_string())
        );
        assert_eq!(prepared_json["contentsDisplayed"], Value::Bool(false));
        assert_eq!(repeated_json["stream"]["created"], Value::Bool(false));
        assert_eq!(repeated_json["room"]["created"], Value::Bool(false));
        assert!(!body.contains("private message contents"));
        assert!(!body.contains("payloadText"));
    }

    #[test]
    fn message_tool_flow_keeps_send_and_metadata_reads_payload_safe() {
        let server = McpServer::with_home(test_home("message-flow"));
        call_tool(
            &server,
            1,
            "conu_register_agent",
            json!({
                "agentId": "agent.sender",
                "displayName": "Sender"
            }),
        );
        call_tool(
            &server,
            2,
            "conu_register_agent",
            json!({
                "agentId": "agent.receiver",
                "displayName": "Receiver"
            }),
        );
        let send = call_tool(
            &server,
            3,
            "conu_send_message",
            json!({
                "fromAgentId": "agent.sender",
                "toAgentId": "agent.receiver",
                "payloadText": "private message contents"
            }),
        );
        let send_response = send.to_string();
        assert!(!send_response.contains("private message contents"));

        let send_text = tool_text(&send);
        let send_payload: Value = serde_json::from_str(&send_text).expect("send tool text json");
        let envelope_id = send_payload["envelopeIds"][0]
            .as_str()
            .expect("envelope id")
            .to_string();
        let metadata = call_tool(
            &server,
            4,
            "conu_receive_message",
            json!({
                "agentId": "agent.receiver",
                "envelopeId": envelope_id
            }),
        );
        let metadata_text = tool_text(&metadata);

        assert!(metadata_text.contains("\"payloadReturned\": false"));
        assert!(!metadata_text.contains("private message contents"));
    }

    #[test]
    fn room_tools_keep_publish_payload_safe() {
        let server = McpServer::with_home(test_home("rooms"));
        call_tool(
            &server,
            1,
            "conu_register_agent",
            json!({
                "agentId": "agent.codex",
                "displayName": "Codex",
                "capabilities": { "rooms": true }
            }),
        );
        call_tool(
            &server,
            2,
            "conu_register_agent",
            json!({
                "agentId": "agent.hermes",
                "displayName": "Hermes",
                "capabilities": { "rooms": true }
            }),
        );
        call_tool(
            &server,
            3,
            "conu_create_room",
            json!({
                "roomId": "room.dev",
                "displayName": "Dev Room",
                "agentId": "agent.codex"
            }),
        );
        call_tool(
            &server,
            4,
            "conu_join_room",
            json!({
                "roomId": "room.dev",
                "agentId": "agent.hermes"
            }),
        );
        let publish = call_tool(
            &server,
            5,
            "conu_publish_room_event",
            json!({
                "roomId": "room.dev",
                "fromAgentId": "agent.hermes",
                "topic": "build",
                "payloadText": "private message contents"
            }),
        );
        let events = call_tool(&server, 6, "conu_list_room_events", json!({}));
        let publish_text = tool_text(&publish);
        let events_text = tool_text(&events);

        assert!(publish_text.contains("\"payloadBytes\": 24"));
        assert!(publish_text.contains("\"localDeliveries\": 1"));
        assert!(events_text.contains("\"topic\": \"build\""));
        assert!(!publish.to_string().contains("private message contents"));
        assert!(!events.to_string().contains("private message contents"));
    }

    #[test]
    fn room_topic_policy_tool_sets_grants_without_payloads() {
        let server = McpServer::with_home(test_home("room-topic-policy"));
        call_tool(
            &server,
            1,
            "conu_register_agent",
            json!({
                "agentId": "agent.codex",
                "displayName": "Codex",
                "capabilities": { "rooms": true }
            }),
        );
        call_tool(
            &server,
            2,
            "conu_register_agent",
            json!({
                "agentId": "agent.hermes",
                "displayName": "Hermes",
                "capabilities": { "rooms": true }
            }),
        );
        call_tool(
            &server,
            3,
            "conu_create_room",
            json!({
                "roomId": "room.dev",
                "displayName": "Dev Room",
                "agentId": "agent.codex"
            }),
        );
        call_tool(
            &server,
            4,
            "conu_join_room",
            json!({
                "roomId": "room.dev",
                "agentId": "agent.hermes"
            }),
        );
        let policy = call_tool(
            &server,
            5,
            "conu_set_room_topic_policy",
            json!({
                "roomId": "room.dev",
                "agentId": "agent.hermes",
                "topic": "build",
                "publish": true,
                "subscribe": false
            }),
        );
        let policies = call_tool(&server, 6, "conu_list_room_topic_policies", json!({}));
        let policy_json: Value = serde_json::from_str(&tool_text(&policy)).expect("policy json");
        let policies_json: Value =
            serde_json::from_str(&tool_text(&policies)).expect("policies json");
        let body = format!("{policy}\n{policies}");

        assert_eq!(policy_json["contentsDisplayed"], Value::Bool(false));
        assert_eq!(policy_json["policy"]["publish"], Value::Bool(true));
        assert_eq!(policy_json["policy"]["subscribe"], Value::Bool(false));
        assert_eq!(policies_json["topicPolicies"][0]["topic"], "build");
        assert!(!body.contains("private message contents"));
    }

    #[test]
    fn receive_payload_returns_hex_only_when_requested() {
        let server = McpServer::with_home(test_home("receive-payload"));
        call_tool(
            &server,
            1,
            "conu_register_agent",
            json!({ "agentId": "agent.sender", "displayName": "Sender" }),
        );
        call_tool(
            &server,
            2,
            "conu_register_agent",
            json!({ "agentId": "agent.receiver", "displayName": "Receiver" }),
        );
        let send = call_tool(
            &server,
            3,
            "conu_send_message",
            json!({
                "fromAgentId": "agent.sender",
                "toAgentId": "agent.receiver",
                "payloadText": "private message contents"
            }),
        );
        let send_payload: Value =
            serde_json::from_str(&tool_text(&send)).expect("send text parses");
        let envelope_id = send_payload["envelopeIds"][0]
            .as_str()
            .expect("envelope id");
        let received = call_tool(
            &server,
            4,
            "conu_receive_message",
            json!({
                "agentId": "agent.receiver",
                "envelopeId": envelope_id,
                "includePayload": true
            }),
        );
        let text = tool_text(&received);

        assert!(text.contains("\"payloadReturned\": true"));
        assert!(text.contains("\"payloadEncoding\": \"hex\""));
        assert!(text.contains("70726976617465206d65737361676520636f6e74656e7473"));
        assert!(!text.contains("private message contents"));
    }

    #[test]
    fn prepare_agent_respects_bound_agent_id() {
        let home = test_home("prepare-bound-agent");
        let bound = McpServer::with_home_and_agent(home, "agent.runner");
        let blocked = call_tool(
            &bound,
            1,
            "conu_prepare_agent",
            json!({
                "agentId": "agent.other",
                "displayName": "Other Agent"
            }),
        );
        let allowed = call_tool(
            &bound,
            2,
            "conu_prepare_agent",
            json!({
                "agentId": "agent.runner",
                "displayName": "Runner Agent"
            }),
        );
        let allowed_json: Value = serde_json::from_str(&tool_text(&allowed)).expect("allowed json");

        assert_eq!(blocked["result"]["isError"], Value::Bool(true));
        assert!(tool_text(&blocked).contains("bound to a different local agent id"));
        assert_eq!(allowed_json["status"], Value::String("ready".to_string()));
        assert_eq!(
            allowed_json["agentId"],
            Value::String("agent.runner".to_string())
        );
        assert_eq!(allowed_json["processed"]["rejected"], Value::from(0));
        assert_eq!(
            allowed_json["processed"]["heartbeatAgents"][0],
            Value::String("agent.runner".to_string())
        );
        assert_eq!(allowed_json["contentsDisplayed"], Value::Bool(false));
        assert!(!blocked.to_string().contains("private message contents"));
        assert!(!allowed.to_string().contains("private message contents"));
    }

    #[test]
    fn bound_server_cannot_act_as_another_agent() {
        let home = test_home("bound-agent");
        let setup = McpServer::with_home(home.clone());
        call_tool(
            &setup,
            1,
            "conu_register_agent",
            json!({ "agentId": "agent.sender", "displayName": "Sender" }),
        );
        call_tool(
            &setup,
            2,
            "conu_register_agent",
            json!({ "agentId": "agent.receiver", "displayName": "Receiver" }),
        );
        let bound = McpServer::with_home_and_agent(home, "agent.sender");
        let blocked = call_tool(
            &bound,
            3,
            "conu_send_message",
            json!({
                "fromAgentId": "agent.receiver",
                "toAgentId": "agent.sender",
                "payloadText": "private message contents"
            }),
        );

        assert_eq!(blocked["result"]["isError"], Value::Bool(true));
        assert!(tool_text(&blocked).contains("bound to a different local agent id"));
        assert!(!blocked.to_string().contains("private message contents"));
    }

    fn request(server: &McpServer, id: u64, method: &str, params: Value) -> Value {
        let line = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        })
        .to_string();
        let response = server.handle_line(&line).expect("response");
        serde_json::from_str(&response).expect("response parses")
    }

    fn call_tool(server: &McpServer, id: u64, name: &str, arguments: Value) -> Value {
        request(
            server,
            id,
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments
            }),
        )
    }

    fn tool_text(response: &Value) -> String {
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text")
            .to_string()
    }

    fn test_home(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        env::temp_dir().join(format!("conu-mcp-test-{label}-{}-{nonce}", process::id()))
    }
}
