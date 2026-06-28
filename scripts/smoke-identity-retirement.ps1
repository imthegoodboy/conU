param(
    [string]$Conu = "target/debug/conu.exe",
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$smokeHome = Join-Path $env:TEMP ("conu-identity-retire-smoke-" + [guid]::NewGuid().ToString("N"))
$previousConuHome = $env:CONU_HOME
$script:ConuPath = $null

function Invoke-Conu {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ConuArgs)
    if ($SkipBuild) {
        & $script:ConuPath @ConuArgs
    } elseif (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
        & cargo "+$Toolchain" run -q -p conu-cli -- @ConuArgs
    } else {
        & cargo "+stable-x86_64-pc-windows-gnu" run -q -p conu-cli -- @ConuArgs
    }
}

Push-Location $repo
try {
    if ($SkipBuild) {
        $script:ConuPath = (Resolve-Path $Conu).Path
    }

    New-Item -ItemType Directory -Force $smokeHome | Out-Null
    $env:CONU_HOME = $smokeHome

    Invoke-Conu init | Out-Null
    $before = Invoke-Conu identity export --json | ConvertFrom-Json
    $rotateRaw = Invoke-Conu security rotate identity --confirm-peer-refresh --json
    $exportRaw = Invoke-Conu identity export --json
    $retireRaw = Invoke-Conu security retire identity --confirm-peer-refresh-complete --json

    if ($rotateRaw -match "secret_key_hex|dpapi_hex|private|plaintext") {
        throw "identity rotation output exposed sensitive marker; commandOutputDisplayed=false"
    }
    if ($retireRaw -match "secret_key_hex|dpapi_hex|private|plaintext") {
        throw "identity retirement output exposed sensitive marker; commandOutputDisplayed=false"
    }

    $after = $exportRaw | ConvertFrom-Json
    $retire = $retireRaw | ConvertFrom-Json
    if ($before.signatureKeyId -eq $after.signatureKeyId) {
        throw "signature key id did not change"
    }
    if ($before.exchangePublicKeyHex -eq $after.exchangePublicKeyHex) {
        throw "exchange public key did not change"
    }
    if ($retire.status -ne "retired") {
        throw "unexpected retirement status: $($retire.status)"
    }
    if ($retire.contentsDisplayed -ne $false) {
        throw "contentsDisplayed was not false"
    }
    if ($retire.peerCardRefreshConfirmed -ne $true) {
        throw "peerCardRefreshConfirmed was not true"
    }
    if ($retire.retiredIdentityKeys -lt 2) {
        throw "expected at least two retired identity keys, got $($retire.retiredIdentityKeys)"
    }

    $archiveDir = Join-Path $smokeHome "security\identity-keys"
    $archiveCount = 0
    if (Test-Path $archiveDir) {
        $archiveCount = @(Get-ChildItem -Path $archiveDir -Filter *.key).Count
    }
    if ($archiveCount -ne 0) {
        throw "expected no remaining identity key archives, found $archiveCount"
    }

    Write-Host "conU identity archive retirement smoke passed; statePathDisplayed=false"
}
finally {
    if ($null -eq $previousConuHome) {
        Remove-Item Env:CONU_HOME -ErrorAction SilentlyContinue
    } else {
        $env:CONU_HOME = $previousConuHome
    }

    $resolvedSmoke = Resolve-Path $smokeHome -ErrorAction SilentlyContinue
    if ($null -ne $resolvedSmoke -and $resolvedSmoke.Path.StartsWith([System.IO.Path]::GetTempPath(), [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedSmoke.Path -Recurse -Force
    }
    Pop-Location
}
