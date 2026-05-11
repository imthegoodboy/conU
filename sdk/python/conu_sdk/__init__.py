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
        home: str | Path | None = None,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> None:
        self.conu_bin = str(conu_bin)
        self.conud_bin = str(conud_bin)
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

    def status(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "status", "--json")

    def agents(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "agents", "--json")

    def peers(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "peers", "--json")

    def sync_routes(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "routes", "sync", "--json")

    def routes(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "routes", "--json")

    def route_probes(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "routes", "probes", "--json")

    def inbox(self, agent_id: str) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "messages", "inbox", agent_id, "--json")

    def receipts(self) -> dict[str, Any]:
        return self._run_json(self.conu_bin, "messages", "receipts", "--json")

    def register_agent(
        self,
        agent_id: str,
        display_name: str,
        kind: str = "local-agent",
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "agents",
            "register",
            agent_id,
            display_name,
            "--kind",
            kind,
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
        payload: bytes,
    ) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "messages",
            "send",
            from_agent_id,
            to_agent_id,
            "--stdin",
            "--json",
            input_bytes=payload,
        )

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

    def write_stream(self, stream_id: str, payload: bytes) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "streams",
            "write",
            stream_id,
            "--stdin",
            "--json",
            input_bytes=payload,
        )

    def close_stream(self, stream_id: str) -> dict[str, Any]:
        return self._run_json(
            self.conu_bin,
            "streams",
            "close",
            stream_id,
            "--json",
        )

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
        return json.loads(result.stdout)

    def _run(
        self,
        binary: str,
        *args: str,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        argv = (binary, *args)
        completed = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=self.env,
            check=False,
        )
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        result = CommandResult(argv, stdout, stderr, completed.returncode)
        if completed.returncode != 0:
            raise ConuError(f"conU command failed ({completed.returncode}): {' '.join(argv)}")
        return result


__all__ = ["CommandResult", "ConuClient", "ConuError"]
