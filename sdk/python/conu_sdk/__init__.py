"""Small Python SDK wrapper for the conU CLI.

The wrapper never logs or prints payloads. Payload bytes are passed through
stdin for send/write operations, and command output is returned to the caller.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConuError(RuntimeError):
    """Raised when a conU command exits unsuccessfully."""


@dataclass(frozen=True)
class CommandResult:
    """Result of one conU subprocess call."""

    args: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int


class ConuClient:
    """Agent-facing Python wrapper around `conu` and `conud` binaries."""

    def __init__(
        self,
        conu_bin: str | Path = "conu",
        conud_bin: str | Path = "conud",
        mcp_bin: str | Path = "conu-mcp",
        home: str | Path | None = None,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> None:
        self.conu_bin = str(conu_bin)
        self.conud_bin = str(conud_bin)
        self.mcp_bin = str(mcp_bin)
        self.cwd = None if cwd is None else str(cwd)
        self.env = os.environ.copy()
        if env:
            self.env.update(env)
        if home is not None:
            self.env["CONU_HOME"] = str(home)

    def init(self) -> CommandResult:
        return self._run_conu("init")

    def security_audit(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "security", "audit", "--json")

    def rotate_identity(self) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "security",
            "rotate",
            "identity",
            "--confirm-peer-refresh",
            "--json",
        )

    def retire_identity_archives(self) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "security",
            "retire",
            "identity",
            "--confirm-peer-refresh-complete",
            "--json",
        )

    def rotate_storage(self) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "security",
            "rotate",
            "storage",
            "--confirm",
            "--json",
        )

    def retire_storage(self) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "security",
            "retire",
            "storage",
            "--confirm",
            "--json",
        )

    def status(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "status", "--json")

    def agents(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "agents", "--json")

    def export_agent_card(self, agent_id: str) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "agents", "export", agent_id, "--json")

    def trust_agent_card(self, card: dict[str, Any]) -> dict[str, Any]:
        capabilities = card.get("capabilities", {})
        args = [
            "agents",
            "trust",
            str(card["agentId"]),
            str(card["displayName"]),
            "--node",
            str(card["nodeId"]),
            "--kind",
            str(card.get("kind", "remote-agent")),
            "--signing-key",
            str(card["signingPublicKeyHex"]),
            "--signature",
            str(card["signatureHex"]),
            "--signature-key-id",
            str(card["signatureKeyId"]),
            "--signature-algorithm",
            str(card.get("signatureAlgorithm", "Ed25519")),
            "--messages",
            _bool_arg(_card_bool(capabilities, "messages", True)),
            "--streams",
            _bool_arg(_card_bool(capabilities, "streams", False)),
            "--rooms",
            _bool_arg(_card_bool(capabilities, "rooms", False)),
            "--files",
            _bool_arg(_card_bool(capabilities, "files", False)),
            "--presence",
            _bool_arg(_card_bool(capabilities, "presence", True)),
            "--json",
        ]
        return self._run_json(self.conu_bin, *args)

    def peers(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "peers", "--json")

    def peer_policies(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "peers", "policy", "--json")

    def set_peer_policy(
        self,
        peer_node_id: str,
        messages: bool | None = None,
        streams: bool | None = None,
        rooms: bool | None = None,
        files: bool | None = None,
        mailbox: bool | None = None,
    ) -> dict[str, Any]:
        args = ["peers", "policy", peer_node_id, "--json"]
        if messages is not None:
            args.extend(["--messages", _bool_arg(messages)])
        if streams is not None:
            args.extend(["--streams", _bool_arg(streams)])
        if rooms is not None:
            args.extend(["--rooms", _bool_arg(rooms)])
        if files is not None:
            args.extend(["--files", _bool_arg(files)])
        if mailbox is not None:
            args.extend(["--mailbox", _bool_arg(mailbox)])
        return self._run_json(self.conu_bin, *args)

    def identity_export(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "identity", "export", "--json")

    def trust_peer(
        self,
        peer_node_id: str,
        display_name: str,
        exchange_public_key_hex: str,
        relay_endpoint: str | None = None,
        direct_quic_endpoint: str | None = None,
        signing_public_key_hex: str | None = None,
        signature_hex: str | None = None,
        signature_key_id: str | None = None,
        signature_algorithm: str | None = None,
    ) -> dict[str, Any]:
        args = [
            "peers",
            "trust",
            peer_node_id,
            display_name,
            "--exchange-key",
            exchange_public_key_hex,
            "--json",
        ]
        if relay_endpoint is not None:
            args.extend(["--relay", relay_endpoint])
        if direct_quic_endpoint is not None:
            args.extend(["--direct", direct_quic_endpoint])
        if signing_public_key_hex is not None:
            args.extend(["--signing-key", signing_public_key_hex])
        if signature_hex is not None:
            args.extend(["--signature", signature_hex])
        if signature_key_id is not None:
            args.extend(["--signature-key-id", signature_key_id])
        if signature_algorithm is not None:
            args.extend(["--signature-algorithm", signature_algorithm])
        return self._run_json(self.conu_bin, *args)

    def sync_routes(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "routes", "sync", "--json")

    def routes(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "routes", "--json")

    def route_probes(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "routes", "probes", "--json")

    def rooms(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "rooms", "--json")

    def room_events(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "rooms", "events", "--json")

    def inbox(self, agent_id: str) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "messages", "inbox", agent_id, "--json")

    def receive_message(
        self,
        agent_id: str,
        envelope_id: str,
        include_payload: bool = False,
    ) -> dict[str, Any]:
        return self._call_mcp_tool(
            "conu_receive_message",
            {
                "agentId": str(agent_id),
                "envelopeId": str(envelope_id),
                "includePayload": bool(include_payload),
            },
        )

    def receive_message_bytes(self, agent_id: str, envelope_id: str) -> bytes:
        received = self.receive_message(agent_id, envelope_id, include_payload=True)
        payload_hex = received.get("payloadHex")
        if not isinstance(payload_hex, str):
            raise ConuError(
                f"conU receive response did not include payloadHex: "
                f"{_safe_command_for_error(self.mcp_bin)}"
            )
        return _hex_to_bytes(payload_hex, self.mcp_bin)

    def receipts(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "messages", "receipts", "--json")

    def register_agent(
        self,
        agent_id: str,
        display_name: str,
        kind: str = "local-agent",
        messages: bool = True,
        streams: bool = False,
        rooms: bool = False,
        files: bool = False,
        presence: bool = True,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "agents",
            "register",
            agent_id,
            display_name,
            "--kind",
            kind,
            "--messages",
            _bool_arg(messages),
            "--streams",
            _bool_arg(streams),
            "--rooms",
            _bool_arg(rooms),
            "--files",
            _bool_arg(files),
            "--presence",
            _bool_arg(presence),
            "--json",
        )

    def heartbeat(self, agent_id: str, presence: str = "ready") -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "agents",
            "heartbeat",
            agent_id,
            "--presence",
            presence,
            "--json",
        )

    def send_message(
        self,
        from_agent_id: str,
        to_agent_id: str,
        payload: bytes | bytearray | memoryview | str,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "messages",
            "send",
            from_agent_id,
            to_agent_id,
            "--stdin",
            "--json",
            input_bytes=_to_bytes(payload),
        )

    def send_remote_message(
        self,
        from_agent_id: str,
        to_agent_id: str,
        peer_node_id: str,
        payload: bytes | bytearray | memoryview | str,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "messages",
            "send",
            from_agent_id,
            to_agent_id,
            "--peer",
            peer_node_id,
            "--stdin",
            "--json",
            input_bytes=_to_bytes(payload),
        )

    def create_room(
        self,
        room_id: str,
        display_name: str,
        agent_id: str,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "rooms",
            "create",
            room_id,
            display_name,
            "--agent",
            agent_id,
            "--json",
        )

    def join_room(self, room_id: str, agent_id: str) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "rooms",
            "join",
            room_id,
            agent_id,
            "--json",
        )

    def publish_room_event(
        self,
        room_id: str,
        from_agent_id: str,
        topic: str,
        payload: bytes | bytearray | memoryview | str,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "rooms",
            "publish",
            room_id,
            from_agent_id,
            topic,
            "--stdin",
            "--json",
            input_bytes=_to_bytes(payload),
        )

    def room_topic_policies(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "rooms", "policy", "--json")

    def set_room_topic_policy(
        self,
        room_id: str,
        agent_id: str,
        topic: str,
        publish: bool | None = None,
        subscribe: bool | None = None,
    ) -> dict[str, Any]:
        args = ["rooms", "policy", room_id, agent_id, topic, "--json"]
        if publish is not None:
            args.extend(["--publish", _bool_arg(publish)])
        if subscribe is not None:
            args.extend(["--subscribe", _bool_arg(subscribe)])
        return self._run_json(self.conu_bin, *args)

    def connect_local(
        self,
        from_agent_id: str,
        to_agent_id: str,
        kind: str = "message",
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "connect",
            "local",
            from_agent_id,
            to_agent_id,
            "--kind",
            kind,
            "--json",
        )

    def connect_room(self, room_id: str, agent_id: str) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "connect",
            "room",
            room_id,
            agent_id,
            "--json",
        )

    def relay_sync(self, wait_ms: int = 1000) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "relay",
            "sync",
            "--wait-ms",
            str(wait_ms),
            "--json",
        )

    def relay_credential_status(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "relay", "credential", "status", "--json")

    def set_relay_credential(
        self,
        token: bytes | bytearray | memoryview | str,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "relay",
            "credential",
            "set",
            "--stdin",
            "--json",
            input_bytes=_to_bytes(token),
        )

    def clear_relay_credential(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "relay", "credential", "clear", "--json")

    def open_stream(
        self,
        from_agent_id: str,
        to_agent_id: str,
        kind: str = "message",
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "streams",
            "open",
            from_agent_id,
            to_agent_id,
            "--kind",
            kind,
            "--json",
        )

    def write_stream(
        self,
        stream_id: str,
        payload: bytes | bytearray | memoryview | str,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "streams",
            "write",
            stream_id,
            "--stdin",
            "--json",
            input_bytes=_to_bytes(payload),
        )

    def close_stream(self, stream_id: str) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "streams",
            "close",
            stream_id,
            "--json",
        )

    def telemetry_snapshot(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "telemetry", "snapshot", "--json")

    def rotate_logs(
        self,
        max_bytes: int | None = None,
        keep: int | None = None,
    ) -> dict[str, Any]:
        args = ["logs", "rotate", "--json"]
        if max_bytes is not None:
            args.extend(["--max-bytes", str(max_bytes)])
        if keep is not None:
            args.extend(["--keep", str(keep)])
        return self._run_json(self.conu_bin, *args)

    def process_queued(self) -> CommandResult:
        return self._run(self.conud_bin, "--process-ipc")

    def _run_conu(self, *args: str, input_bytes: bytes | None = None) -> CommandResult:
        return self._run(self.conu_bin, *args, input_bytes=input_bytes)

    def _run_json(
        self,
        binary: str,
        *args: str,
        input_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        result = self._run(binary, *args, input_bytes=input_bytes)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ConuError(
                f"conU command returned invalid JSON: {_safe_command_for_error(binary)}"
            ) from None

    def _call_mcp_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {},
            },
        }
        result = self._run(
            self.mcp_bin,
            input_bytes=(json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        response = _parse_mcp_response(result.stdout, self.mcp_bin)
        error = response.get("error")
        if error is not None:
            raise ConuError(
                f"conU MCP tool failed: {_safe_mcp_error(error)}: "
                f"{_safe_command_for_error(self.mcp_bin)}"
            )
        tool_result = response.get("result")
        if not isinstance(tool_result, dict):
            raise ConuError(
                f"conU MCP response did not include a tool result: "
                f"{_safe_command_for_error(self.mcp_bin)}"
            )
        if tool_result.get("isError") is True:
            raise ConuError(
                f"conU MCP tool failed: [details redacted]: "
                f"{_safe_command_for_error(self.mcp_bin)}"
            )
        return _parse_json_for_sdk(
            _tool_text(tool_result, self.mcp_bin),
            self.mcp_bin,
            "conU MCP tool returned invalid JSON",
        )

    def _run(
        self,
        binary: str,
        *args: str,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        argv = (binary, *args)
        try:
            completed = subprocess.run(
                argv,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=self.env,
                check=False,
            )
        except OSError:
            raise ConuError(
                f"conU command failed before execution: {_safe_command_for_error(binary)}"
            ) from None
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        result = CommandResult(argv, stdout, stderr, completed.returncode)
        if completed.returncode != 0:
            raise ConuError(
                f"conU command failed ({completed.returncode}): {_safe_command_for_error(binary)}"
            )
        return result


def _safe_command_for_error(binary: str) -> str:
    return f"{_safe_binary_name(binary)} [arguments redacted]"


def _safe_binary_name(binary: str) -> str:
    value = str(binary).strip()
    if not value:
        return "conu"
    if "://" in value or any(marker in value for marker in ("@", "?", "#")):
        return "conu"
    base = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or "conu"
    sanitized = "".join(
        character if character.isascii() and (character.isalnum() or character in "._-") else "_"
        for character in base
    )
    return sanitized or "conu"


def _parse_mcp_response(stdout: str, binary: str) -> dict[str, Any]:
    line = next((value.strip() for value in stdout.splitlines() if value.strip()), None)
    if line is None:
        raise ConuError(f"conU MCP response was empty: {_safe_command_for_error(binary)}")
    return _parse_json_for_sdk(line, binary, "conU MCP response was invalid JSON")


def _parse_json_for_sdk(text: str, binary: str, message: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        raise ConuError(f"{message}: {_safe_command_for_error(binary)}") from None
    if not isinstance(value, dict):
        raise ConuError(f"{message}: {_safe_command_for_error(binary)}")
    return value


def _tool_text(tool_result: dict[str, Any], binary: str) -> str:
    content = tool_result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str):
                    return text
    raise ConuError(
        f"conU MCP tool response did not include text content: {_safe_command_for_error(binary)}"
    )


def _safe_mcp_error(error: Any) -> str:
    if isinstance(error, dict) and isinstance(error.get("code"), int):
        return f"code {error['code']}"
    return "unknown MCP error"


def _to_bytes(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return str(value).encode("utf-8")


def _hex_to_bytes(payload_hex: str, binary: str) -> bytes:
    if len(payload_hex) % 2 != 0 or any(
        character not in "0123456789abcdefABCDEF" for character in payload_hex
    ):
        raise ConuError(
            f"conU receive response included invalid payloadHex: "
            f"{_safe_command_for_error(binary)}"
        )
    return bytes.fromhex(payload_hex)


def _bool_arg(value: bool) -> str:
    return "true" if value else "false"


def _card_bool(values: Any, key: str, default: bool) -> bool:
    if not isinstance(values, dict):
        return default
    value = values.get(key, default)
    return value if isinstance(value, bool) else default


__all__ = ["CommandResult", "ConuClient", "ConuError"]
