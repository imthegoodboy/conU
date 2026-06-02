#!/usr/bin/env python3
"""Regression checks for production-readiness Rust toolchain selection."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


HELPER = Path(__file__).with_name("production-readiness-toolchain.ps1")


def powershell_executable() -> str:
    for name in ("pwsh", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("PowerShell executable was not found")


def run_powershell(script: str) -> None:
    exe = powershell_executable()
    args = [exe, "-NoProfile"]
    if Path(exe).name.lower().startswith("powershell"):
        args.extend(["-ExecutionPolicy", "Bypass"])
    args.extend(["-Command", script])
    completed = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "production-readiness toolchain regression failed: "
            f"exit={completed.returncode}\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )


def main() -> int:
    helper = str(HELPER.resolve()).replace("'", "''")
    script = f"""
$ErrorActionPreference = "Stop"
. '{helper}'

$explicit = Resolve-ConuReadinessRustToolchain `
    -ExplicitToolchain "stable-custom" `
    -IsWindowsHost $true `
    -LinkExePath "" `
    -InstalledToolchains @("stable-x86_64-pc-windows-gnu") `
    -DefaultToolchain "stable-x86_64-pc-windows-msvc"
if ($explicit -ne "stable-custom") {{
    throw "explicit toolchain was not preserved: $explicit"
}}

$fallback = Resolve-ConuReadinessRustToolchain `
    -ExplicitToolchain "" `
    -IsWindowsHost $true `
    -LinkExePath "" `
    -InstalledToolchains @("stable-x86_64-pc-windows-gnu", "stable-x86_64-pc-windows-msvc") `
    -DefaultToolchain "stable-x86_64-pc-windows-msvc"
if ($fallback -ne "stable-x86_64-pc-windows-gnu") {{
    throw "GNU fallback was not selected: $fallback"
}}

$defaultGnu = Resolve-ConuReadinessRustToolchain `
    -ExplicitToolchain "" `
    -IsWindowsHost $true `
    -LinkExePath "" `
    -InstalledToolchains @("custom-x86_64-pc-windows-gnu") `
    -DefaultToolchain "custom-x86_64-pc-windows-gnu"
if ($defaultGnu -ne "") {{
    throw "default GNU toolchain should not be overridden: $defaultGnu"
}}

$nonWindows = Resolve-ConuReadinessRustToolchain `
    -ExplicitToolchain "" `
    -IsWindowsHost $false `
    -LinkExePath "" `
    -InstalledToolchains @() `
    -DefaultToolchain "stable-x86_64-unknown-linux-gnu"
if ($nonWindows -ne "") {{
    throw "non-Windows host should not select a Windows fallback: $nonWindows"
}}

$linkPresent = Resolve-ConuReadinessRustToolchain `
    -ExplicitToolchain "" `
    -IsWindowsHost $true `
    -LinkExePath "C:\\\\BuildTools\\\\VC\\\\Tools\\\\MSVC\\\\link.exe" `
    -InstalledToolchains @("stable-x86_64-pc-windows-gnu") `
    -DefaultToolchain "stable-x86_64-pc-windows-msvc"
if ($linkPresent -ne "") {{
    throw "available MSVC linker should not select fallback: $linkPresent"
}}

if (-not (Test-ConuGnuLinkerToolsAvailable -AvailableCommands @("dlltool.exe", "gcc.exe"))) {{
    throw "GNU linker tool availability was not detected"
}}

try {{
    Assert-ConuGnuLinkerToolsAvailable -AvailableCommands @("dlltool.exe")
    throw "missing GNU gcc.exe did not fail"
}} catch {{
    $message = $_.Exception.Message
    if (-not $message.Contains("dlltool.exe") -or -not $message.Contains("gcc.exe")) {{
        throw "GNU linker tool error was not actionable: $message"
    }}
}}

try {{
    Resolve-ConuReadinessRustToolchain `
        -ExplicitToolchain "" `
        -IsWindowsHost $true `
        -LinkExePath "" `
        -InstalledToolchains @("stable-x86_64-pc-windows-msvc") `
        -DefaultToolchain "stable-x86_64-pc-windows-msvc" | Out-Null
    throw "missing fallback did not fail"
}} catch {{
    $message = $_.Exception.Message
    if (-not $message.Contains("link.exe") -or -not $message.Contains("stable-x86_64-pc-windows-gnu")) {{
        throw "missing fallback error was not actionable: $message"
    }}
}}
"""
    run_powershell(script)
    print("Production readiness toolchain regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
