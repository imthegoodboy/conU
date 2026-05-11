param(
    [Parameter(Mandatory = $true)]
    [string]$SourceBin,
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\conU",
    [switch]$InstallService
)

$ErrorActionPreference = "Stop"

$source = Resolve-Path $SourceBin
$binDir = Join-Path $InstallDir "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

foreach ($binary in @("conu.exe", "conud.exe", "conu-relay.exe", "conu-mcp.exe")) {
    $from = Join-Path $source $binary
    if (-not (Test-Path -LiteralPath $from)) {
        throw "missing $from"
    }
    Copy-Item -LiteralPath $from -Destination $binDir -Force
}

Write-Host "installed conU binaries to $binDir"
Write-Host "add this directory to PATH if it is not already present"

if ($InstallService) {
    $conud = Join-Path $binDir "conud.exe"
    $serviceExists = (sc.exe query conud 2>$null | Select-String -SimpleMatch "SERVICE_NAME: conud") -ne $null
    if ($serviceExists) {
        Write-Host "service conud already exists"
    } else {
        sc.exe create conud binPath= "`"$conud`" --serve" start= auto DisplayName= "conU daemon"
        sc.exe description conud "conU local runtime daemon; payload contents are not logged"
        Write-Host "created Windows service conud"
    }
}
