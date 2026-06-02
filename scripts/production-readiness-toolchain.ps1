function Test-ConuWindowsHost {
    return ($IsWindows -or $env:OS -eq "Windows_NT")
}

function Get-ConuInstalledRustToolchains {
    $output = & rustup toolchain list 2>$null
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    $toolchains = @()
    foreach ($line in $output) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }
        $toolchains += ($trimmed -split "\s+")[0]
    }
    return $toolchains
}

function Get-ConuDefaultRustToolchain {
    $output = & rustup default 2>$null
    if ($LASTEXITCODE -ne 0 -or $null -eq $output) {
        return ""
    }
    $firstLine = ($output | Select-Object -First 1)
    if ($null -eq $firstLine) {
        return ""
    }
    return (($firstLine.ToString().Trim()) -split "\s+")[0]
}

function Resolve-ConuReadinessRustToolchain {
    param(
        [string]$ExplicitToolchain = "",
        [bool]$IsWindowsHost = (Test-ConuWindowsHost),
        [string]$LinkExePath = "",
        [string[]]$InstalledToolchains = @(),
        [string]$DefaultToolchain = "",
        [string]$FallbackGnuToolchain = "stable-x86_64-pc-windows-gnu"
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitToolchain)) {
        return $ExplicitToolchain.Trim()
    }

    if (-not $IsWindowsHost) {
        return ""
    }

    if (-not [string]::IsNullOrWhiteSpace($LinkExePath)) {
        return ""
    }

    if ($DefaultToolchain -like "*windows-gnu*") {
        return ""
    }

    if ($InstalledToolchains -contains $FallbackGnuToolchain) {
        return $FallbackGnuToolchain
    }

    throw (
        "MSVC linker link.exe was not found and fallback Rust toolchain " +
        "$FallbackGnuToolchain is not installed. Install Visual C++ Build Tools " +
        "or run: rustup toolchain install $FallbackGnuToolchain"
    )
}

function Resolve-ConuReadinessRustToolchainForHost {
    param([string]$ExplicitToolchain = "")

    $link = Get-Command link.exe -ErrorAction SilentlyContinue
    $linkPath = if ($null -ne $link) { $link.Source } else { "" }
    return Resolve-ConuReadinessRustToolchain `
        -ExplicitToolchain $ExplicitToolchain `
        -IsWindowsHost (Test-ConuWindowsHost) `
        -LinkExePath $linkPath `
        -InstalledToolchains (Get-ConuInstalledRustToolchains) `
        -DefaultToolchain (Get-ConuDefaultRustToolchain)
}

function Test-ConuGnuLinkerToolsAvailable {
    param([object[]]$AvailableCommands = $null)

    if ($null -ne $AvailableCommands) {
        return (
            ($AvailableCommands -contains "dlltool.exe") -and
            ($AvailableCommands -contains "gcc.exe")
        )
    }

    return (
        (Get-Command dlltool.exe -ErrorAction SilentlyContinue) -and
        (Get-Command gcc.exe -ErrorAction SilentlyContinue)
    )
}

function Assert-ConuGnuLinkerToolsAvailable {
    param([object[]]$AvailableCommands = $null)

    if (-not (Test-ConuGnuLinkerToolsAvailable -AvailableCommands $AvailableCommands)) {
        throw (
            "GNU Rust toolchain selected but MinGW linker tools dlltool.exe and gcc.exe " +
            "were not found on PATH. Install MinGW-w64 binutils/GCC or use an MSVC " +
            "toolchain with Visual C++ Build Tools available."
        )
    }
}
