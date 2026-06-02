param(
    [string]$Conu = "target/debug/conu.exe",
    [string]$Conud = "target/debug/conud.exe",
    [string]$ConuRelay = "target/debug/conu-relay.exe",
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN,
    [int]$RelayPort = 0,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$smokeRoot = Join-Path $env:TEMP ("conu-relay-daemon-smoke-" + [guid]::NewGuid().ToString("N"))
$homeA = Join-Path $smokeRoot "node-a"
$homeB = Join-Path $smokeRoot "node-b"
$relayProcess = $null
$conudProcessA = $null
$conudProcessB = $null
$previousRelayToken = $env:CONU_RELAY_TOKEN

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

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return $listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }
}

function Invoke-Conu {
    param(
        [string]$StateHome,
        [string[]]$Arguments,
        [string]$InputText = $null
    )

    $oldHome = $env:CONU_HOME
    $oldConud = $env:CONUD_EXE
    try {
        $env:CONU_HOME = $StateHome
        $env:CONUD_EXE = $script:ConudPath
        if ($null -eq $InputText) {
            $output = & $script:ConuPath @Arguments
        } else {
            $output = $InputText | & $script:ConuPath @Arguments
        }
        if ($LASTEXITCODE -ne 0) {
            throw "conu smoke command failed with code $LASTEXITCODE; commandOutputDisplayed=false"
        }
        return ($output -join "`n")
    }
    finally {
        if ($null -eq $oldHome) {
            Remove-Item Env:CONU_HOME -ErrorAction SilentlyContinue
        } else {
            $env:CONU_HOME = $oldHome
        }
        if ($null -eq $oldConud) {
            Remove-Item Env:CONUD_EXE -ErrorAction SilentlyContinue
        } else {
            $env:CONUD_EXE = $oldConud
        }
    }
}

function Invoke-ConuJson {
    param(
        [string]$StateHome,
        [string[]]$Arguments,
        [string]$InputText = $null
    )

    $json = Invoke-Conu -StateHome $StateHome -Arguments $Arguments -InputText $InputText
    return $json | ConvertFrom-Json
}

function Write-ConuConfig {
    param(
        [string]$StateHome,
        [string]$Endpoint,
        [string]$Name
    )

    $config = @"
version = "1"
runtime_name = "$Name"
default_relay = "$Endpoint"
relay_auto_sync = true
"@
    Set-Content -LiteralPath (Join-Path $StateHome "config.toml") -Value $config -Encoding ASCII
}

function Stop-ConuRuntime {
    param(
        [string]$StateHome,
        [System.Diagnostics.Process]$Process = $null
    )

    try {
        Invoke-Conu -StateHome $StateHome -Arguments @("stop") | Out-Null
    }
    catch {
    }
    if ($null -ne $Process) {
        try {
            if (-not $Process.WaitForExit(5000)) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
    }
}

function Start-ConuRuntime {
    param([string]$StateHome)

    $oldHome = $env:CONU_HOME
    $oldConud = $env:CONUD_EXE
    try {
        $env:CONU_HOME = $StateHome
        $env:CONUD_EXE = $script:ConudPath
        $process = Start-Process -FilePath $script:ConudPath -ArgumentList @("--serve") -WindowStyle Hidden -PassThru
    }
    finally {
        if ($null -eq $oldHome) {
            Remove-Item Env:CONU_HOME -ErrorAction SilentlyContinue
        } else {
            $env:CONU_HOME = $oldHome
        }
        if ($null -eq $oldConud) {
            Remove-Item Env:CONUD_EXE -ErrorAction SilentlyContinue
        } else {
            $env:CONUD_EXE = $oldConud
        }
    }

    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 100
        $status = Invoke-ConuJson -StateHome $StateHome -Arguments @("status", "--json")
        if ($status.runtime.conud -eq "running") {
            return $process
        }
    }

    throw "conUD did not publish a running heartbeat for smoke state; statePathDisplayed=false"
}

function Wait-ForInbox {
    param(
        [string]$StateHome,
        [string]$AgentId,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $inbox = Invoke-ConuJson -StateHome $StateHome -Arguments @("messages", "inbox", $AgentId, "--json")
        if ($inbox.messages.Count -gt 0) {
            return $inbox
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for relay-delivered inbox entry for $AgentId"
}

Push-Location $repo
try {
    if (-not $SkipBuild -and $Conu -eq "target/debug/conu.exe" -and $Conud -eq "target/debug/conud.exe" -and $ConuRelay -eq "target/debug/conu-relay.exe") {
        Invoke-SmokeCommand "cargo build" {
            if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
                cargo "+$Toolchain" build --workspace
            } else {
                cargo build --workspace
            }
        }
    }

    $script:ConuPath = (Resolve-Path $Conu).Path
    $script:ConudPath = (Resolve-Path $Conud).Path
    $script:RelayPath = (Resolve-Path $ConuRelay).Path

    if ($RelayPort -eq 0) {
        $RelayPort = Get-FreeTcpPort
    }
    $relayEndpoint = "ws://127.0.0.1:$RelayPort"
    $env:CONU_RELAY_TOKEN = "local-dev-token"

    New-Item -ItemType Directory -Force -Path $homeA, $homeB | Out-Null
    $relayProcess = Start-Process -FilePath $script:RelayPath -ArgumentList @("--serve", "127.0.0.1:$RelayPort") -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 750
    if ($relayProcess.HasExited) {
        throw "conu-relay exited early with code $($relayProcess.ExitCode)"
    }
    Write-Host "relay started on loopback smoke endpoint; endpointDisplayed=false"

    Invoke-Conu -StateHome $homeA -Arguments @("init") | Out-Null
    Invoke-Conu -StateHome $homeB -Arguments @("init") | Out-Null
    Write-ConuConfig -StateHome $homeA -Endpoint $relayEndpoint -Name "node-a"
    Write-ConuConfig -StateHome $homeB -Endpoint $relayEndpoint -Name "node-b"
    Write-Host "nodes initialized"

    $cardA = Invoke-ConuJson -StateHome $homeA -Arguments @("identity", "export", "--json")
    $cardB = Invoke-ConuJson -StateHome $homeB -Arguments @("identity", "export", "--json")

    Invoke-Conu -StateHome $homeA -Arguments @("peers", "trust", $cardB.nodeId, $cardB.displayName, "--exchange-key", $cardB.exchangePublicKeyHex, "--relay", $relayEndpoint, "--signing-key", $cardB.signingPublicKeyHex, "--signature", $cardB.signatureHex, "--signature-key-id", $cardB.signatureKeyId) | Out-Null
    Invoke-Conu -StateHome $homeB -Arguments @("peers", "trust", $cardA.nodeId, $cardA.displayName, "--exchange-key", $cardA.exchangePublicKeyHex, "--relay", $relayEndpoint, "--signing-key", $cardA.signingPublicKeyHex, "--signature", $cardA.signatureHex, "--signature-key-id", $cardA.signatureKeyId) | Out-Null
    Invoke-Conu -StateHome $homeA -Arguments @("peers", "policy", $cardB.nodeId, "--messages", "true", "--streams", "true", "--rooms", "true") | Out-Null
    Invoke-Conu -StateHome $homeB -Arguments @("peers", "policy", $cardA.nodeId, "--messages", "true", "--streams", "true", "--rooms", "true") | Out-Null
    Write-Host "peer cards trusted and relay policy granted"

    $conudProcessA = Start-ConuRuntime -StateHome $homeA
    $conudProcessB = Start-ConuRuntime -StateHome $homeB
    Write-Host "conUD runtimes started"
    Invoke-Conu -StateHome $homeA -Arguments @("agents", "register", "agent.daemon.a", "Daemon Agent A", "--kind", "smoke", "--rooms", "true") | Out-Null
    Invoke-Conu -StateHome $homeB -Arguments @("agents", "register", "agent.daemon.b", "Daemon Agent B", "--kind", "smoke", "--rooms", "true") | Out-Null
    Write-Host "agents registered"

    $secret = "daemon relay smoke " + [guid]::NewGuid().ToString("N")
    $send = Invoke-ConuJson -StateHome $homeA -Arguments @("messages", "send", "agent.daemon.a", "agent.daemon.b", "--peer", $cardB.nodeId, "--stdin", "--json") -InputText $secret
    if ($send.status -ne "queued_remote") {
        throw "Expected queued_remote status, got $($send.status)"
    }
    Write-Host "remote message queued"

    $inbox = Wait-ForInbox -StateHome $homeB -AgentId "agent.daemon.b" -TimeoutSeconds 30
    Write-Host "remote message delivered"
    $delivered = @($inbox.messages)[0]
    if ($delivered.fromAgentId -ne "agent.daemon.a" -or $delivered.toAgentId -ne "agent.daemon.b") {
        throw "Relay inbox metadata did not match expected agents"
    }
    if ($inbox.contentsDisplayed -ne $false) {
        throw "Relay inbox did not preserve contentsDisplayed=false"
    }

    $watch = Invoke-Conu -StateHome $homeB -Arguments @("watch")
    if ($watch.Contains($secret)) {
        throw "Watch output leaked the smoke payload"
    }

    $leaks = Get-ChildItem -LiteralPath $smokeRoot -Recurse -File | Select-String -SimpleMatch $secret
    if ($null -ne $leaks) {
        throw "Smoke payload appeared in conU-owned state"
    }

    Write-Host "conU relay daemon smoke passed; statePathDisplayed=false; endpointDisplayed=false"
}
finally {
    Stop-ConuRuntime -StateHome $homeA -Process $conudProcessA
    Stop-ConuRuntime -StateHome $homeB -Process $conudProcessB
    if ($null -ne $relayProcess -and -not $relayProcess.HasExited) {
        Stop-Process -Id $relayProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -eq $previousRelayToken) {
        Remove-Item Env:CONU_RELAY_TOKEN -ErrorAction SilentlyContinue
    } else {
        $env:CONU_RELAY_TOKEN = $previousRelayToken
    }
    $resolvedSmoke = Resolve-Path $smokeRoot -ErrorAction SilentlyContinue
    if ($null -ne $resolvedSmoke -and $resolvedSmoke.Path.StartsWith([System.IO.Path]::GetTempPath(), [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedSmoke.Path -Recurse -Force
    }
    Pop-Location
}
