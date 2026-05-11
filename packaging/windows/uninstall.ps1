param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\conU",
    [switch]$RemoveService
)

$ErrorActionPreference = "Stop"

if ($RemoveService) {
    $serviceExists = (sc.exe query conud 2>$null | Select-String -SimpleMatch "SERVICE_NAME: conud") -ne $null
    if ($serviceExists) {
        sc.exe stop conud | Out-Null
        sc.exe delete conud | Out-Null
        Write-Host "removed Windows service conud"
    }
}

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "removed $InstallDir"
}
