#!/usr/bin/env python3
"""Check smoke scripts keep local state paths out of readiness logs."""

from __future__ import annotations

import sys
from pathlib import Path

from command_output_redaction import redact_command_output


ROOT = Path(__file__).resolve().parents[1]
SMOKE_SCRIPTS = (
    ROOT / "scripts" / "smoke-local.ps1",
    ROOT / "scripts" / "smoke-identity-retirement.ps1",
    ROOT / "scripts" / "smoke-relay-daemon.ps1",
)
OUTPUT_COMMANDS = ("Write-Host", "throw")
FORBIDDEN_OUTPUT_FRAGMENTS = (
    "CONU_HOME=",
    "nodeA=",
    "nodeB=",
    "relay=",
    "$conuSmokeHome",
    "$smokeHome",
    "$smokeRoot",
    "$homeA",
    "$homeB",
    "$StateHome",
    "$resolvedSmoke",
)


def main() -> int:
    issues: list[str] = []
    for path in SMOKE_SCRIPTS:
        check_output_lines(path, issues)
        check_success_guard(path, issues)

    check_identity_cleanup(ROOT / "scripts" / "smoke-identity-retirement.ps1", issues)
    check_relay_output_suppression(ROOT / "scripts" / "smoke-relay-daemon.ps1", issues)
    check_command_output_redaction(issues)

    if issues:
        print("smoke output privacy check failed", file=sys.stderr)
        for issue in issues:
            print(f"issue: {issue}", file=sys.stderr)
        return 1

    print("smoke output privacy check passed")
    return 0


def check_output_lines(path: Path, issues: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith(OUTPUT_COMMANDS):
            continue
        for fragment in FORBIDDEN_OUTPUT_FRAGMENTS:
            if fragment in stripped:
                issues.append(
                    f"{path.relative_to(ROOT)}:line {index} prints local smoke state marker {fragment}"
                )


def check_success_guard(path: Path, issues: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if "statePathDisplayed=false" not in text:
        issues.append(f"{path.relative_to(ROOT)} is missing statePathDisplayed=false success guard")


def check_identity_cleanup(path: Path, issues: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    required_fragments = (
        "$previousConuHome = $env:CONU_HOME",
        "finally {",
        "Remove-Item Env:CONU_HOME -ErrorAction SilentlyContinue",
        "$env:CONU_HOME = $previousConuHome",
        "Remove-Item -LiteralPath $resolvedSmoke.Path -Recurse -Force",
    )
    for fragment in required_fragments:
        if fragment not in text:
            issues.append(
                f"{path.relative_to(ROOT)} is missing cleanup fragment {fragment!r}"
            )


def check_relay_output_suppression(path: Path, issues: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if "commandOutputDisplayed=false" not in text:
        issues.append(f"{path.relative_to(ROOT)} is missing commandOutputDisplayed=false guard")
    if "$($output -join" in text:
        issues.append(f"{path.relative_to(ROOT)} can echo captured command output on failure")


def check_command_output_redaction(issues: list[str]) -> None:
    sentinel = "do-not-print-this-secret-value"
    cases = (
        f"tool --token {sentinel}",
        f"tool --password='{sentinel} with spaces'",
        f"tool --security-token \"{sentinel} with spaces\"",
        f"tool -auth {sentinel}",
        f"tool --target conu --secret {sentinel} --mode dry-run",
    )
    for value in cases:
        redacted = redact_command_output(value)
        if sentinel in redacted:
            issues.append(f"command output redaction leaked secret flag value from {value!r}")
        if "[redacted]" not in redacted:
            issues.append(f"command output redaction did not mark secret flag value from {value!r}")

    safe_guards = (
        "contentsDisplayed=false tokenDisplayed=false keyMaterialDisplayed=false"
    )
    if redact_command_output(safe_guards) != safe_guards:
        issues.append("command output redaction changed safe display guard booleans")

    unsafe_guard_assignments = (
        f"tokenDisplayed={sentinel}",
        f"keyMaterialDisplayed={sentinel}",
    )
    for value in unsafe_guard_assignments:
        redacted = redact_command_output(value)
        if sentinel in redacted:
            issues.append(f"command output redaction leaked guarded secret value from {value!r}")
        if "[redacted]" not in redacted:
            issues.append(f"command output redaction did not mark guarded secret value from {value!r}")


if __name__ == "__main__":
    raise SystemExit(main())
