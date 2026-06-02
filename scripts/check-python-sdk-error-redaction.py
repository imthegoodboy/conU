#!/usr/bin/env python3
"""Regression checks for Python SDK command failure redaction."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdk" / "python" / "conu_sdk" / "__init__.py"
SENSITIVE_ENDPOINT = "wss://user:secret@relay.example.com/conu?token=private#fragment"
SENSITIVE_STDOUT = "stdout with private fixture"
SENSITIVE_STDERR = f"stderr with {SENSITIVE_ENDPOINT}"


class Completed:
    stdout = SENSITIVE_STDOUT.encode("utf-8")
    stderr = SENSITIVE_STDERR.encode("utf-8")
    returncode = 2


def load_sdk():
    spec = importlib.util.spec_from_file_location("conu_sdk_regression", SDK)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Python SDK module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assert_redacted(rendered: str) -> None:
    for forbidden in (
        "secret",
        "token=private",
        "relay.example.com",
        "private fixture",
        SENSITIVE_ENDPOINT,
    ):
        if forbidden in rendered:
            raise AssertionError(f"Python SDK error leaked sensitive text: {forbidden}")


def run_failed_command_redaction_test(module) -> None:
    captured: dict[str, tuple[str, ...]] = {}

    def fake_run(argv, **_kwargs):
        captured["argv"] = tuple(argv)
        return Completed()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.trust_peer(
            "node.peer",
            "Peer",
            "aa",
            relay_endpoint=SENSITIVE_ENDPOINT,
        )
    except module.ConuError as exc:
        rendered = str(exc)
    else:
        raise AssertionError("expected Python SDK command failure")

    if SENSITIVE_ENDPOINT not in captured.get("argv", ()):
        raise AssertionError("test did not pass the sensitive endpoint through argv")
    assert_redacted(rendered)
    if "conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK error should retain only safe executable metadata")


def run_spawn_error_redaction_test(module) -> None:
    def fake_run(_argv, **_kwargs):
        raise OSError(f"cannot execute {SENSITIVE_ENDPOINT}")

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin=SENSITIVE_ENDPOINT)
    try:
        client.status()
    except module.ConuError as exc:
        rendered = str(exc)
    else:
        raise AssertionError("expected Python SDK spawn failure")

    assert_redacted(rendered)
    if "conu [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK spawn error should use a generic safe binary label")


def run_invalid_json_redaction_test(module) -> None:
    class JsonCompleted:
        stdout = f"not json with {SENSITIVE_ENDPOINT}".encode("utf-8")
        stderr = SENSITIVE_STDERR.encode("utf-8")
        returncode = 0

    def fake_run(argv, **_kwargs):
        return JsonCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.status()
    except module.ConuError as exc:
        rendered = str(exc)
    else:
        raise AssertionError("expected Python SDK JSON parse failure")

    assert_redacted(rendered)
    if "conU command returned invalid JSON: conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK JSON parse error should retain only safe command metadata")


def run_receive_message_helper_test(module) -> None:
    captured_requests: list[dict] = []

    class McpCompleted:
        returncode = 0
        stderr = b""

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout.encode("utf-8")

    def fake_run(argv, input=None, **_kwargs):
        if tuple(argv) != ("C:/tools/conu-mcp-test.exe",):
            raise AssertionError(f"unexpected argv for MCP helper: {argv!r}")
        request = json.loads(input.decode("utf-8"))
        captured_requests.append(request)
        include_payload = request["params"]["arguments"]["includePayload"] is True
        body = {
            "envelopeId": request["params"]["arguments"]["envelopeId"],
            "fromAgentId": "agent.alpha",
            "toAgentId": request["params"]["arguments"]["agentId"],
            "payloadBytes": 13,
            "payloadReturned": include_payload,
            "contentsDisplayed": False,
        }
        if include_payload:
            body["payloadHex"] = b"private bytes".hex()
            body["payloadEncoding"] = "hex"
        return McpCompleted(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(body)}],
                        "isError": False,
                    },
                }
            )
        )

    module.subprocess.run = fake_run
    client = module.ConuClient(mcp_bin="C:/tools/conu-mcp-test.exe")
    metadata = client.receive_message("agent.beta", "env.local.1")
    payload = client.receive_message_bytes("agent.beta", "env.local.1")

    if metadata.get("payloadReturned") is not False:
        raise AssertionError("Python SDK metadata receive should not return payload by default")
    if payload != b"private bytes":
        raise AssertionError("Python SDK receive_message_bytes should decode payloadHex")
    if captured_requests[0]["params"]["name"] != "conu_receive_message":
        raise AssertionError("Python SDK receive helper should call conu_receive_message")
    if captured_requests[0]["params"]["arguments"]["includePayload"] is not False:
        raise AssertionError("Python SDK receive_message should default includePayload to false")
    if captured_requests[1]["params"]["arguments"]["includePayload"] is not True:
        raise AssertionError("Python SDK receive_message_bytes should request payload explicitly")


def run_mcp_shape_redaction_tests(module) -> None:
    class McpCompleted:
        stderr = SENSITIVE_STDERR.encode("utf-8")
        returncode = 0

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout.encode("utf-8")

    cases = (
        (
            "missing text",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "resource", "text": f"text with {SENSITIVE_ENDPOINT}"}],
                    "isError": False,
                },
            },
            lambda client: client.receive_message("agent.beta", "env.local.1"),
            "conU MCP tool response did not include text content: conu-mcp-test.exe [arguments redacted]",
        ),
        (
            "missing payloadHex",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "payloadReturned": True,
                                    "note": f"private fixture with {SENSITIVE_ENDPOINT}",
                                }
                            ),
                        }
                    ],
                    "isError": False,
                },
            },
            lambda client: client.receive_message_bytes("agent.beta", "env.local.1"),
            "conU receive response did not include payloadHex: conu-mcp-test.exe [arguments redacted]",
        ),
        (
            "invalid payloadHex",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "payloadHex": SENSITIVE_ENDPOINT,
                                    "payloadReturned": True,
                                }
                            ),
                        }
                    ],
                    "isError": False,
                },
            },
            lambda client: client.receive_message_bytes("agent.beta", "env.local.1"),
            "conU receive response included invalid payloadHex: conu-mcp-test.exe [arguments redacted]",
        ),
        (
            "protocol error",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32602,
                    "message": f"protocol error with {SENSITIVE_ENDPOINT}",
                },
            },
            lambda client: client.receive_message("agent.beta", "env.local.1"),
            "conU MCP tool failed: code -32602: conu-mcp-test.exe [arguments redacted]",
        ),
    )

    for _label, response, action, expected in cases:
        def fake_run(_argv, **_kwargs):
            return McpCompleted(json.dumps(response))

        module.subprocess.run = fake_run
        client = module.ConuClient(mcp_bin="C:/tools/conu-mcp-test.exe")
        try:
            action(client)
        except module.ConuError as exc:
            rendered = str(exc)
        else:
            raise AssertionError("expected Python SDK MCP shape failure")

        assert_redacted(rendered)
        if expected not in rendered:
            raise AssertionError("Python SDK MCP error should retain only safe command metadata")


def main() -> int:
    module = load_sdk()
    run_failed_command_redaction_test(module)
    run_spawn_error_redaction_test(module)
    run_invalid_json_redaction_test(module)
    run_receive_message_helper_test(module)
    run_mcp_shape_redaction_tests(module)
    print("Python SDK error redaction regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
