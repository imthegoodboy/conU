#!/usr/bin/env python3
"""Regression checks for Python SDK command failure redaction."""

from __future__ import annotations

import importlib.util
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


def main() -> int:
    module = load_sdk()
    run_failed_command_redaction_test(module)
    run_spawn_error_redaction_test(module)
    run_invalid_json_redaction_test(module)
    print("Python SDK error redaction regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
