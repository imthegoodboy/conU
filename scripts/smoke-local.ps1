param(
    [string]$Conu = "target/debug/conu.exe",
    [string]$Conud = "target/debug/conud.exe",
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$conuSmokeHome = Join-Path $env:TEMP ("conu-smoke-" + [guid]::NewGuid().ToString("N"))

function Invoke-SmokeCommand {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    & $Command | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Smoke command failed: $Name exited with code $LASTEXITCODE"
    }
}

Push-Location $repo
try {
    if (-not $SkipBuild -and $Conu -eq "target/debug/conu.exe" -and $Conud -eq "target/debug/conud.exe") {
        Invoke-SmokeCommand "cargo build" {
            if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
                cargo "+$Toolchain" build --workspace
            } else {
                cargo build --workspace
            }
        }
    }

    $env:CONU_HOME = $conuSmokeHome
    $env:CONUD_EXE = (Resolve-Path $Conud).Path

    Invoke-SmokeCommand "conu init" { & $Conu init }
    Invoke-SmokeCommand "conu security audit" { & $Conu security audit --json }
    Invoke-SmokeCommand "register smoke agent a" { & $Conu agents register agent.smoke.a "Smoke Agent A" --kind smoke --json }
    Invoke-SmokeCommand "register smoke agent b" { & $Conu agents register agent.smoke.b "Smoke Agent B" --kind smoke --json }
    Invoke-SmokeCommand "conud process registration ipc" { & $Conud --process-ipc }
    Invoke-SmokeCommand "send smoke message" { "opaque smoke bytes" | & $Conu messages send agent.smoke.a agent.smoke.b --stdin --json }
    Invoke-SmokeCommand "conud process message ipc" { & $Conud --process-ipc }
    Invoke-SmokeCommand "read smoke inbox" { & $Conu messages inbox agent.smoke.b --json }
    Invoke-SmokeCommand "sync routes" { & $Conu routes sync --json }
    $doctorJson = & $Conu doctor --json
    if ($LASTEXITCODE -ne 0) {
        throw "Smoke command failed: conu doctor exited with code $LASTEXITCODE"
    }
    $doctor = ($doctorJson -join "`n") | ConvertFrom-Json
    if ($doctor.releaseGates.localInstallReady -ne $true) {
        throw "Smoke command failed: conu doctor did not report localInstallReady=true"
    }

    Write-Host "conU smoke passed; statePathDisplayed=false"
}
finally {
    Remove-Item Env:CONU_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:CONUD_EXE -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $conuSmokeHome) {
        Remove-Item -LiteralPath $conuSmokeHome -Recurse -Force
    }
    Pop-Location
}
