param(
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN,
    [switch]$SmokeOnly,
    [switch]$SkipRust,
    [switch]$SkipPackages,
    [switch]$SkipSmokes
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$tempRoot = $null

function Invoke-ReadinessStep {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host "==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Invoke-CargoStep {
    param(
        [string]$Name,
        [string[]]$CargoArgs
    )

    Invoke-ReadinessStep $Name {
        if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
            & cargo "+$Toolchain" @CargoArgs
        } else {
            & cargo @CargoArgs
        }
    }
}

function Invoke-PwshScript {
    param(
        [string]$Name,
        [string]$Path,
        [hashtable]$Parameters = @{}
    )

    Invoke-ReadinessStep $Name {
        & $Path @Parameters
    }
}

function Get-BinaryPath {
    param([string]$Name)

    $suffix = if ($IsWindows -or $env:OS -eq "Windows_NT") { ".exe" } else { "" }
    return Join-Path $repo "target/debug/$Name$suffix"
}

function Get-EffectiveSmokeToolchain {
    if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
        return $Toolchain
    }
    return "stable"
}

function ConvertTo-Hex {
    param([byte[]]$Bytes)

    $builder = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    foreach ($byte in $Bytes) {
        [void]$builder.AppendFormat("{0:x2}", $byte)
    }
    return $builder.ToString()
}

function Get-Sha256Hex {
    param([string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ConvertTo-Hex -Bytes $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    }
    finally {
        $sha.Dispose()
    }
}

function Write-AdminTokensFixture {
    param(
        [string]$Path,
        [string]$AdminToken
    )

    $hash = Get-Sha256Hex -Value $AdminToken
    $contents = @"
version = "1"

[[admin_token]]
account_id = "account.prod"
token_sha256_hex = "$hash"
token_length = $($AdminToken.Length)
status = "active"
scope_credentials = true
scope_tenants = true
scope_dashboard = true
scope_sessions = true
scope_mailbox_audit = true
scope_mailbox_purge = true
payload_displayed = false
token_displayed = false
token_hash_displayed = false
key_material_displayed = false
session_id_displayed = false
ciphertext_displayed = false
contents_displayed = false
"@
    Set-Content -LiteralPath $Path -Value $contents -Encoding ASCII
    return $hash
}

function Write-PolicyFixtures {
    param(
        [string]$RetentionPolicyPath,
        [string]$ThresholdsPath
    )

    $guards = @"
payload_displayed = false
token_displayed = false
token_hash_displayed = false
key_material_displayed = false
session_id_displayed = false
ciphertext_displayed = false
contents_displayed = false
"@
    Set-Content -LiteralPath $RetentionPolicyPath -Value "version = `"1`"`nttl_seconds = 3600`n$guards" -Encoding ASCII
    Set-Content -LiteralPath $ThresholdsPath -Value "version = `"1`"`nmax_rate_limited_sessions = 100`n$guards" -Encoding ASCII
}

function Invoke-HostedReadinessFixture {
    param([string]$ConuRelay)

    $fixtureRoot = Join-Path $tempRoot "hosted-readiness"
    $credentialsFile = Join-Path $fixtureRoot "credentials.toml"
    $tokenFile = Join-Path $fixtureRoot "node-prod.token"
    $adminTokensFile = Join-Path $fixtureRoot "admin-tokens.toml"
    $tenantsFile = Join-Path $fixtureRoot "tenants.toml"
    $sessionDir = Join-Path $fixtureRoot "sessions"
    $mailboxDir = Join-Path $fixtureRoot "mailbox"
    $accountingDir = Join-Path $fixtureRoot "accounting"
    $abuseDir = Join-Path $fixtureRoot "abuse"
    $retentionPolicyFile = Join-Path $fixtureRoot "mailbox-retention.toml"
    $thresholdsFile = Join-Path $fixtureRoot "abuse-thresholds.toml"
    $adminToken = "conu-readiness-admin-token-1234567890abcdef"

    New-Item -ItemType Directory -Force -Path $fixtureRoot, $sessionDir, $mailboxDir, $accountingDir, $abuseDir | Out-Null
    $adminHash = Write-AdminTokensFixture -Path $adminTokensFile -AdminToken $adminToken
    Write-PolicyFixtures -RetentionPolicyPath $retentionPolicyFile -ThresholdsPath $thresholdsFile

    Invoke-ReadinessStep "hosted readiness fixture credential" {
        & $ConuRelay --issue-credential node.prod --token-out $tokenFile --credentials-file $credentialsFile --json | Out-Null
    }
    Invoke-ReadinessStep "hosted readiness fixture tenant" {
        & $ConuRelay --tenant-upsert account.prod --tenants-file $tenantsFile --json | Out-Null
    }
    Invoke-ReadinessStep "hosted readiness fixture tenant node" {
        & $ConuRelay --tenant-node-upsert account.prod node.prod --tenants-file $tenantsFile --messages true --streams true --rooms true --files false --mailbox true --json | Out-Null
    }

    $nodeToken = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($nodeToken)) {
        throw "hosted readiness fixture credential token was empty"
    }
    $nodeHash = Get-Sha256Hex -Value $nodeToken
    $readinessOutput = & $ConuRelay `
        --hosted-readiness `
        --bind-addr 127.0.0.1:0 `
        --credentials-file $credentialsFile `
        --tenants-file $tenantsFile `
        --admin-tokens-file $adminTokensFile `
        --session-state-dir $sessionDir `
        --mailbox-dir $mailboxDir `
        --retention-policy-file $retentionPolicyFile `
        --accounting-dir $accountingDir `
        --abuse-dir $abuseDir `
        --thresholds-file $thresholdsFile `
        --json `
        --fail-on-warning
    if ($LASTEXITCODE -ne 0) {
        throw "hosted readiness fixture failed with exit code $LASTEXITCODE"
    }

    $joined = $readinessOutput -join "`n"
    foreach ($secret in @($adminToken, $adminHash, $nodeToken, $nodeHash)) {
        if ($joined.Contains($secret)) {
            throw "hosted readiness output exposed fixture token material"
        }
    }
    $report = $joined | ConvertFrom-Json
    if ($report.status -ne "ready") {
        throw "hosted readiness fixture expected ready status, got $($report.status)"
    }
    if ($report.warningCount -ne 0) {
        throw "hosted readiness fixture expected zero warnings, got $($report.warningCount)"
    }
    $displayGuardsClean = $report.checks.displayGuardsClean
    if ($null -eq $displayGuardsClean) {
        throw "hosted readiness fixture did not include checks.displayGuardsClean"
    }
    if ($displayGuardsClean -ne $true) {
        throw "hosted readiness fixture display guards were not clean"
    }
    foreach ($field in @(
        "payloadDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "sessionIdDisplayed",
        "ciphertextDisplayed",
        "contentsDisplayed"
    )) {
        if ($report.$field -ne $false) {
            throw "hosted readiness fixture expected $field=false"
        }
    }
}

Push-Location $repo
try {
    $tempBase = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $tempRoot = Join-Path $tempBase ("conu-production-readiness-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

    if (-not $SmokeOnly -and -not $SkipRust) {
        Invoke-CargoStep "cargo fmt" @("fmt", "--all", "--", "--check")
        Invoke-CargoStep "cargo check" @("check", "--workspace", "--all-targets")
        Invoke-CargoStep "cargo clippy" @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings")
        Invoke-CargoStep "cargo test" @("test", "--workspace")
    }

    if (-not $SkipRust) {
        Invoke-CargoStep "cargo build" @("build", "--workspace")
    }

    if (-not $SmokeOnly -and -not $SkipPackages) {
        Invoke-ReadinessStep "python compile" {
            & python -m py_compile sdk/python/conu_sdk/__init__.py examples/python/local_agent_pair.py scripts/verify-release-versions.py scripts/verify-release-artifacts.py
        }
        Invoke-ReadinessStep "release version consistency" {
            & python scripts/verify-release-versions.py
        }
        Invoke-ReadinessStep "TypeScript SDK check" {
            & npm run check --prefix sdk/typescript
        }
        Invoke-ReadinessStep "npm launcher check" {
            & npm run check --prefix packaging/npm/conu-cli
        }
    }

    $conu = Get-BinaryPath "conu"
    $conud = Get-BinaryPath "conud"
    $conuRelay = Get-BinaryPath "conu-relay"

    if (-not $SkipSmokes) {
        $smokeToolchain = Get-EffectiveSmokeToolchain
        Invoke-PwshScript "local smoke" (Join-Path $repo "scripts/smoke-local.ps1") @{
            Conu = $conu
            Conud = $conud
            Toolchain = $smokeToolchain
            SkipBuild = $true
        }
        Invoke-PwshScript "identity retirement smoke" (Join-Path $repo "scripts/smoke-identity-retirement.ps1") @{
            Toolchain = $smokeToolchain
        }
        Invoke-PwshScript "relay daemon smoke" (Join-Path $repo "scripts/smoke-relay-daemon.ps1") @{
            Conu = $conu
            Conud = $conud
            ConuRelay = $conuRelay
            Toolchain = $smokeToolchain
            SkipBuild = $true
        }
        Invoke-HostedReadinessFixture -ConuRelay $conuRelay
    }

    Invoke-ReadinessStep "git diff whitespace check" {
        & git diff --check
    }

    Write-Host "conU production readiness verification passed"
}
finally {
    if ($tempRoot -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    Pop-Location
}
