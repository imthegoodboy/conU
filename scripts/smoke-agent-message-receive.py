#!/usr/bin/env python3
"""Smoke test local two-agent delivery plus explicit SDK payload receive."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from conu_sdk import ConuClient  # noqa: E402


PAYLOAD = bytes(((index * 37 + 11) % 256 for index in range(64)))
FORBIDDEN_METADATA_KEYS = {"payload", "payloadHex", "payloadText"}


class SmokeFailure(RuntimeError):
    """Raised when the end-to-end agent smoke contract is violated."""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conu-bin", default="conu", help="path to conu binary")
    parser.add_argument("--conud-bin", default="conud", help="path to conud binary")
    parser.add_argument("--mcp-bin", default="conu-mcp", help="path to conu-mcp binary")
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=30_000,
        help="maximum wait time for local delivery",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="conu-agent-receive-smoke-") as home:
        run_smoke(args, home)

    print(
        json.dumps(
            {
                "status": "ok",
                "registeredAgents": 2,
                "payloadBytes": len(PAYLOAD),
                "receivedBytes": len(PAYLOAD),
                "contentsDisplayed": False,
            },
            sort_keys=True,
        )
    )
    return 0


def run_smoke(args: argparse.Namespace, home: str) -> None:
    client = ConuClient(
        conu_bin=args.conu_bin,
        conud_bin=args.conud_bin,
        mcp_bin=args.mcp_bin,
        home=home,
    )
    client.init()
    alpha = client.register_agent("agent.alpha", "Alpha")
    beta = client.register_agent("agent.beta", "Beta")
    client.process_queued()

    sent = client.send_message("agent.alpha", "agent.beta", PAYLOAD)
    waited = client.wait_for_message(
        "agent.beta",
        timeout_ms=args.timeout_ms,
        interval_ms=50,
        process_ipc=True,
    )
    message = require_mapping(waited.get("message"), "waited.message")
    envelope_id = require_string(message.get("envelopeId"), "waited.message.envelopeId")

    inbox = client.inbox("agent.beta")
    metadata = client.receive_message("agent.beta", envelope_id)
    received = client.receive_message_bytes("agent.beta", envelope_id)
    receipts = client.receipts()

    require_contents_hidden(alpha, "register alpha")
    require_contents_hidden(beta, "register beta")
    require_contents_hidden(sent, "send")
    require_contents_hidden(waited, "wait")
    require_contents_hidden(inbox, "inbox")
    require_contents_hidden(metadata, "metadata receive")
    require_contents_hidden(receipts, "receipts")

    require_no_payload_material(sent, "send")
    require_no_payload_material(waited, "wait")
    require_no_payload_material(inbox, "inbox")
    require_no_payload_material(metadata, "metadata receive")
    require_no_payload_material(receipts, "receipts")

    if sent.get("payloadBytes") != len(PAYLOAD):
        raise SmokeFailure("send payload byte count mismatch")
    if waited.get("status") != "delivered":
        raise SmokeFailure("wait did not deliver the message")
    if message.get("fromAgentId") != "agent.alpha" or message.get("toAgentId") != "agent.beta":
        raise SmokeFailure("waited message was not addressed to the expected agents")
    if message.get("payloadBytes") != len(PAYLOAD):
        raise SmokeFailure("waited message payload byte count mismatch")
    if not inbox_contains(inbox, envelope_id, len(PAYLOAD)):
        raise SmokeFailure("inbox did not list the delivered metadata")
    if metadata.get("payloadReturned") is not False:
        raise SmokeFailure("metadata receive unexpectedly returned payload bytes")
    if received != PAYLOAD:
        raise SmokeFailure("explicit receive did not return the submitted bytes")
    if not receipt_exists(receipts, envelope_id, len(PAYLOAD)):
        raise SmokeFailure("delivery receipt was not recorded")


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SmokeFailure(f"{label} was not an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SmokeFailure(f"{label} was not a non-empty string")
    return value


def require_contents_hidden(value: dict[str, Any], label: str) -> None:
    if value.get("contentsDisplayed") is not False:
        raise SmokeFailure(f"{label} did not report contentsDisplayed=false")


def require_no_payload_material(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_METADATA_KEYS:
                raise SmokeFailure(f"{label} exposed payload field {key}")
            require_no_payload_material(child, label)
    elif isinstance(value, list):
        for child in value:
            require_no_payload_material(child, label)


def inbox_contains(inbox: dict[str, Any], envelope_id: str, payload_bytes: int) -> bool:
    messages = inbox.get("messages")
    if not isinstance(messages, list):
        raise SmokeFailure("inbox.messages was not a list")
    return any(
        isinstance(message, dict)
        and message.get("envelopeId") == envelope_id
        and message.get("payloadBytes") == payload_bytes
        and message.get("fromAgentId") == "agent.alpha"
        and message.get("toAgentId") == "agent.beta"
        for message in messages
    )


def receipt_exists(receipts: dict[str, Any], envelope_id: str, payload_bytes: int) -> bool:
    receipt_items = receipts.get("receipts")
    if not isinstance(receipt_items, list):
        raise SmokeFailure("receipts.receipts was not a list")
    return any(
        isinstance(receipt, dict)
        and receipt.get("envelopeId") == envelope_id
        and receipt.get("payloadBytes") == payload_bytes
        and receipt.get("status") == "delivered_local"
        for receipt in receipt_items
    )


if __name__ == "__main__":
    raise SystemExit(main())
