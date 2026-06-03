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


def assert_safe_error_result(exc, expected_binary: str, expected_returncode: int) -> None:
    result = getattr(exc, "result", None)
    if result is None:
        raise AssertionError("Python SDK error should include redacted result metadata")
    rendered = repr(
        (
            result.args,
            result.stdout,
            result.stderr,
            result.returncode,
            result.contents_displayed,
            result.args_redacted,
            result.stdio_redacted,
        )
    )
    assert_redacted(rendered)
    if result.args != (expected_binary, "[arguments redacted]"):
        raise AssertionError(f"Python SDK error result kept unsafe args: {result.args!r}")
    if result.stdout != "" or result.stderr != "":
        raise AssertionError("Python SDK error result should redact stdout and stderr")
    if result.returncode != expected_returncode:
        raise AssertionError(
            f"Python SDK error result returncode mismatch: {result.returncode!r}"
        )
    if result.contents_displayed is not False:
        raise AssertionError("Python SDK error result should mark contents_displayed false")
    if result.args_redacted is not True:
        raise AssertionError("Python SDK error result should mark args_redacted true")
    if result.stdio_redacted is not True:
        raise AssertionError("Python SDK error result should mark stdio_redacted true")


def assert_success_result_defaults(result) -> None:
    if result.contents_displayed is not True:
        raise AssertionError("Python SDK successful result should keep contents_displayed true")
    if result.args_redacted is not False:
        raise AssertionError("Python SDK successful result should not mark args redacted")
    if result.stdio_redacted is not False:
        raise AssertionError("Python SDK successful result should not mark stdio redacted")


def run_success_result_metadata_test(module) -> None:
    class SuccessCompleted:
        stdout = b"safe stdout"
        stderr = b"safe stderr"
        returncode = 0

    def fake_run(argv, **_kwargs):
        return SuccessCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    result = client.init()

    if result.args != ("C:/tools/conu-test.exe", "init"):
        raise AssertionError("Python SDK successful result should keep actual argv")
    if result.stdout != "safe stdout" or result.stderr != "safe stderr":
        raise AssertionError("Python SDK successful result should keep command output")
    if result.returncode != 0:
        raise AssertionError("Python SDK successful result should keep returncode")
    assert_success_result_defaults(result)


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
        assert_safe_error_result(exc, "conu-test.exe", 2)
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
        assert_safe_error_result(exc, "conu", 1)
    else:
        raise AssertionError("expected Python SDK spawn failure")

    assert_redacted(rendered)
    if "conu [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK spawn error should use a generic safe binary label")


def run_constructor_binary_redaction_test(module) -> None:
    class SecretBinary:
        def __str__(self) -> str:
            raise RuntimeError(f"binary conversion exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        raise AssertionError("Python SDK should not execute subprocess for invalid binary")

    module.subprocess.run = fake_run
    try:
        module.ConuClient(conu_bin=SecretBinary())
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu", 1)
    else:
        raise AssertionError("expected Python SDK constructor binary failure")

    assert_redacted(rendered)
    if "conU command binary could not be encoded: conu [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK constructor binary error should retain safe metadata only")

    try:
        module.ConuClient(mcp_bin="")
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu", 1)
    else:
        raise AssertionError("expected Python SDK empty constructor binary failure")

    assert_redacted(rendered)
    if "conU command binary could not be encoded: conu [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK empty constructor binary error should retain safe metadata")


def run_constructor_option_redaction_test(module) -> None:
    class SecretPath:
        def __fspath__(self) -> str:
            raise RuntimeError(f"path conversion exposed {SENSITIVE_ENDPOINT}")

    class SecretEnv(dict):
        def items(self):
            raise RuntimeError(f"environment override exposed {SENSITIVE_ENDPOINT}")

    class SecretEnvValue:
        def __str__(self) -> str:
            raise RuntimeError(f"environment value exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        raise AssertionError("Python SDK should not execute subprocess for invalid constructor option")

    module.subprocess.run = fake_run

    cases = (
        (
            lambda: module.ConuClient(conu_bin="C:/tools/conu-test.exe", home=SecretPath()),
            "conU constructor home could not be encoded: conu-test.exe [arguments redacted]",
        ),
        (
            lambda: module.ConuClient(conu_bin="C:/tools/conu-test.exe", cwd=SecretPath()),
            "conU constructor cwd could not be encoded: conu-test.exe [arguments redacted]",
        ),
        (
            lambda: module.ConuClient(
                conu_bin="C:/tools/conu-test.exe",
                env=SecretEnv(CONU_SECRET_FIXTURE="safe"),
            ),
            "conU constructor environment could not be encoded: "
            "conu-test.exe [arguments redacted]",
        ),
        (
            lambda: module.ConuClient(
                conu_bin="C:/tools/conu-test.exe",
                env={"CONU_SECRET_FIXTURE": SecretEnvValue()},
            ),
            "conU constructor environment could not be encoded: "
            "conu-test.exe [arguments redacted]",
        ),
    )

    for action, expected in cases:
        try:
            action()
        except module.ConuError as exc:
            rendered = str(exc)
            assert_safe_error_result(exc, "conu-test.exe", 1)
        else:
            raise AssertionError("expected Python SDK constructor option failure")

        assert_redacted(rendered)
        if expected not in rendered:
            raise AssertionError("Python SDK constructor option error should retain safe metadata")


def run_subprocess_exception_redaction_test(module) -> None:
    def fake_run(_argv, **_kwargs):
        raise RuntimeError(f"custom runner exposed {SENSITIVE_ENDPOINT}")

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.status()
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK subprocess runner failure")

    assert_redacted(rendered)
    if "conU command failed before execution: conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK subprocess error should retain safe metadata only")


def run_malformed_completed_stdio_redaction_test(module) -> None:
    class MalformedCompleted:
        stderr = b"safe stderr"
        returncode = 0

        @property
        def stdout(self):
            raise RuntimeError(f"stdout getter exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        return MalformedCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.status()
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK malformed stdio failure")

    assert_redacted(rendered)
    if (
        "conU command returned malformed process result: "
        "conu-test.exe [arguments redacted]"
    ) not in rendered:
        raise AssertionError("Python SDK malformed stdio error should retain safe metadata only")


def run_malformed_completed_returncode_redaction_test(module) -> None:
    class MalformedCompleted:
        stdout = b"safe stdout"
        stderr = b"safe stderr"

        @property
        def returncode(self):
            raise RuntimeError(f"returncode getter exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        return MalformedCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.status()
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK malformed returncode failure")

    assert_redacted(rendered)
    if (
        "conU command returned malformed process result: "
        "conu-test.exe [arguments redacted]"
    ) not in rendered:
        raise AssertionError("Python SDK malformed returncode error should retain safe metadata only")


def run_malformed_completed_returncode_type_redaction_test(module) -> None:
    class MalformedCompleted:
        stdout = b"safe stdout"
        stderr = b"safe stderr"
        returncode = "0"

    def fake_run(_argv, **_kwargs):
        return MalformedCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.status()
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK malformed returncode type failure")

    assert_redacted(rendered)
    if (
        "conU command returned malformed process result: "
        "conu-test.exe [arguments redacted]"
    ) not in rendered:
        raise AssertionError("Python SDK malformed returncode type should retain safe metadata only")


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
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK JSON parse failure")

    assert_redacted(rendered)
    if "conU command returned invalid JSON: conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK JSON parse error should retain only safe command metadata")


def run_non_object_json_redaction_test(module) -> None:
    class JsonCompleted:
        stdout = json.dumps([f"array item with {SENSITIVE_ENDPOINT}"]).encode("utf-8")
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
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK non-object JSON failure")

    assert_redacted(rendered)
    if "conU command returned invalid JSON: conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK non-object JSON error should retain safe metadata only")


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
        (
            "MCP text non-object JSON",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps([f"array item with {SENSITIVE_ENDPOINT}"]),
                        }
                    ],
                    "isError": False,
                },
            },
            lambda client: client.receive_message("agent.beta", "env.local.1"),
            "conU MCP tool returned invalid JSON: conu-mcp-test.exe [arguments redacted]",
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
            assert_safe_error_result(exc, "conu-mcp-test.exe", 1)
        else:
            raise AssertionError("expected Python SDK MCP shape failure")

        assert_redacted(rendered)
        if expected not in rendered:
            raise AssertionError("Python SDK MCP error should retain only safe command metadata")


def run_command_surface_parity_test(module) -> None:
    captured: list[dict] = []

    class JsonCompleted:
        stderr = b""
        returncode = 0

        def __init__(self) -> None:
            self.stdout = json.dumps(
                {
                    "ok": True,
                    "contentsDisplayed": False,
                }
            ).encode("utf-8")

    def fake_run(argv, input=None, **_kwargs):
        captured.append({"argv": tuple(argv), "input": input})
        return JsonCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")

    calls = (
        (
            lambda: client.rotate_identity(),
            (
                "C:/tools/conu-test.exe",
                "security",
                "rotate",
                "identity",
                "--confirm-peer-refresh",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.retire_identity_archives(),
            (
                "C:/tools/conu-test.exe",
                "security",
                "retire",
                "identity",
                "--confirm-peer-refresh-complete",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.rotate_storage(),
            (
                "C:/tools/conu-test.exe",
                "security",
                "rotate",
                "storage",
                "--confirm",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.retire_storage(),
            (
                "C:/tools/conu-test.exe",
                "security",
                "retire",
                "storage",
                "--confirm",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.relay_credential_status(),
            (
                "C:/tools/conu-test.exe",
                "relay",
                "credential",
                "status",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.set_relay_credential("relay-token-fixture"),
            (
                "C:/tools/conu-test.exe",
                "relay",
                "credential",
                "set",
                "--stdin",
                "--json",
            ),
            b"relay-token-fixture",
        ),
        (
            lambda: client.clear_relay_credential(),
            (
                "C:/tools/conu-test.exe",
                "relay",
                "credential",
                "clear",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.telemetry_snapshot(),
            (
                "C:/tools/conu-test.exe",
                "telemetry",
                "snapshot",
                "--json",
            ),
            None,
        ),
        (
            lambda: client.rotate_logs(max_bytes=4096, keep=3),
            (
                "C:/tools/conu-test.exe",
                "logs",
                "rotate",
                "--json",
                "--max-bytes",
                "4096",
                "--keep",
                "3",
            ),
            None,
        ),
        (
            lambda: client.send_message("agent.alpha", "agent.beta", "payload fixture"),
            (
                "C:/tools/conu-test.exe",
                "messages",
                "send",
                "agent.alpha",
                "agent.beta",
                "--stdin",
                "--json",
            ),
            b"payload fixture",
        ),
        (
            lambda: client.write_stream("stream.local.1", bytearray(b"stream fixture")),
            (
                "C:/tools/conu-test.exe",
                "streams",
                "write",
                "stream.local.1",
                "--stdin",
                "--json",
            ),
            b"stream fixture",
        ),
    )

    for action, expected_argv, expected_input in calls:
        result = action()
        if result.get("contentsDisplayed") is not False:
            raise AssertionError("Python SDK command helper should preserve display guard results")
        recorded = captured[-1]
        if recorded["argv"] != expected_argv:
            raise AssertionError(f"unexpected argv: {recorded['argv']!r}")
        if recorded["input"] != expected_input:
            raise AssertionError(f"unexpected stdin bytes for {expected_argv!r}")
        if expected_input is not None:
            rendered_argv = " ".join(recorded["argv"])
            if expected_input.decode("utf-8") in rendered_argv:
                raise AssertionError("Python SDK placed stdin-only secret/payload in argv")


def run_stdin_secret_failure_redaction_test(module) -> None:
    captured: dict[str, bytes | None] = {}
    secret = b"relay-token-fixture-secret"

    class FailedCompleted:
        stdout = b"stdout relay-token-fixture-secret"
        stderr = b"stderr relay-token-fixture-secret"
        returncode = 9

    def fake_run(_argv, input=None, **_kwargs):
        captured["input"] = input
        return FailedCompleted()

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.set_relay_credential(secret)
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 9)
    else:
        raise AssertionError("expected Python SDK relay credential failure")

    if captured.get("input") != secret:
        raise AssertionError("Python SDK relay credential token should pass through stdin")
    if secret.decode("utf-8") in rendered:
        raise AssertionError("Python SDK error leaked relay credential stdin")
    if "conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK stdin failure should retain only safe command metadata")


def run_stdin_payload_encoding_redaction_test(module) -> None:
    class SecretPayload:
        def __str__(self) -> str:
            raise RuntimeError(f"payload conversion exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        raise AssertionError("Python SDK should not execute subprocess for invalid payload")

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.send_message("agent.alpha", "agent.beta", SecretPayload())
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK stdin payload encoding failure")

    assert_redacted(rendered)
    if "conU stdin payload could not be encoded: conu-test.exe [arguments redacted]" not in rendered:
        raise AssertionError("Python SDK payload encoding error should retain safe metadata only")


def run_command_argument_encoding_redaction_test(module) -> None:
    class SecretArgument:
        def __str__(self) -> str:
            raise RuntimeError(f"argument conversion exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        raise AssertionError("Python SDK should not execute subprocess for invalid argument")

    module.subprocess.run = fake_run
    client = module.ConuClient(conu_bin="C:/tools/conu-test.exe")
    try:
        client.trust_peer(
            "node.peer",
            "Peer",
            "aa",
            relay_endpoint=SecretArgument(),
        )
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK command argument encoding failure")

    assert_redacted(rendered)
    if (
        "conU command argument could not be encoded: "
        "conu-test.exe [arguments redacted]"
    ) not in rendered:
        raise AssertionError("Python SDK command argument error should retain safe metadata only")


def run_mcp_argument_encoding_redaction_test(module) -> None:
    class SecretArgument:
        def __str__(self) -> str:
            raise RuntimeError(f"MCP argument conversion exposed {SENSITIVE_ENDPOINT}")

    def fake_run(_argv, **_kwargs):
        raise AssertionError("Python SDK should not execute MCP subprocess for invalid argument")

    module.subprocess.run = fake_run
    client = module.ConuClient(mcp_bin="C:/tools/conu-mcp-test.exe")
    try:
        client.receive_message(SecretArgument(), "env.local.1")
    except module.ConuError as exc:
        rendered = str(exc)
        assert_safe_error_result(exc, "conu-mcp-test.exe", 1)
    else:
        raise AssertionError("expected Python SDK MCP argument encoding failure")

    assert_redacted(rendered)
    if (
        "conU command argument could not be encoded: "
        "conu-mcp-test.exe [arguments redacted]"
    ) not in rendered:
        raise AssertionError("Python SDK MCP argument error should retain safe metadata only")


def main() -> int:
    module = load_sdk()
    run_success_result_metadata_test(module)
    run_failed_command_redaction_test(module)
    run_spawn_error_redaction_test(module)
    run_constructor_binary_redaction_test(module)
    run_constructor_option_redaction_test(module)
    run_subprocess_exception_redaction_test(module)
    run_malformed_completed_stdio_redaction_test(module)
    run_malformed_completed_returncode_redaction_test(module)
    run_malformed_completed_returncode_type_redaction_test(module)
    run_invalid_json_redaction_test(module)
    run_non_object_json_redaction_test(module)
    run_receive_message_helper_test(module)
    run_mcp_shape_redaction_tests(module)
    run_command_surface_parity_test(module)
    run_stdin_secret_failure_redaction_test(module)
    run_stdin_payload_encoding_redaction_test(module)
    run_command_argument_encoding_redaction_test(module)
    run_mcp_argument_encoding_redaction_test(module)
    print("Python SDK error redaction regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
