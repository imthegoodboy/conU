param(
    [string]$Target = "",
    [string]$Profile = "release",
    [string]$OutDir = "dist",
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")

function Invoke-CargoOrThrow {
    param(
        [string]$Name,
        [string[]]$CargoArgs
    )

    if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
        & cargo "+$Toolchain" @CargoArgs
    } else {
        & cargo @CargoArgs
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$metadataArgs = @("metadata", "--manifest-path", (Join-Path $repo "Cargo.toml"), "--format-version", "1", "--no-deps")
if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
    $metadataJson = & cargo "+$Toolchain" @metadataArgs
} else {
    $metadataJson = & cargo @metadataArgs
}
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed with exit code $LASTEXITCODE"
}
$metadata = $metadataJson | ConvertFrom-Json
$version = ($metadata.packages | Where-Object { $_.name -eq "conu-cli" } | Select-Object -First 1).version
if (-not $version) {
    throw "could not resolve conU version from cargo metadata"
}

$targetArgs = @()
$targetSuffix = "host"
if ($Target.Trim().Length -gt 0) {
    $targetArgs = @("--target", $Target)
    $targetSuffix = $Target
}

$profileArgs = if ($Profile -eq "release") { @("--release") } else { @() }

Push-Location $repo
try {
    Invoke-CargoOrThrow "cargo build" (@("build", "--workspace") + $profileArgs + $targetArgs)

    $buildDir = if ($Target.Trim().Length -gt 0) {
        Join-Path $repo "target\$Target\$Profile"
    } else {
        Join-Path $repo "target\$Profile"
    }

    $packageRoot = Join-Path $repo "$OutDir\conu-$version-$targetSuffix"
    $binDir = Join-Path $packageRoot "bin"
    $docDir = Join-Path $packageRoot "docs"
    if (Test-Path -LiteralPath $packageRoot) {
        Remove-Item -LiteralPath $packageRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $binDir, $docDir | Out-Null

    $suffix = if ($IsWindows -or $env:OS -eq "Windows_NT") { ".exe" } else { "" }
    foreach ($binary in @("conu", "conud", "conu-relay", "conu-mcp")) {
        $source = Join-Path $buildDir "$binary$suffix"
        if (-not (Test-Path $source)) {
            throw "missing built binary $source"
        }
        Copy-Item $source -Destination $binDir -Force
    }

    Copy-Item README.md -Destination $packageRoot -Force
    Copy-Item docs\user-install-and-agent-guide.md -Destination $docDir -Force
    Copy-Item docs\production-readiness.md -Destination $docDir -Force
    Copy-Item docs\release-checklist.md -Destination $docDir -Force
    Copy-Item docs\observability.md -Destination $docDir -Force
    Copy-Item -Recurse packaging -Destination $packageRoot -Force

    $manifest = @"
name = "conU"
version = "$version"
target = "$targetSuffix"
profile = "$Profile"
payload_contents_included = false
"@
    Set-Content -Path (Join-Path $packageRoot "manifest.toml") -Value $manifest -Encoding UTF8

    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        $archive = "$packageRoot.zip"
        if (Test-Path $archive) {
            Remove-Item $archive -Force
        }
        Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $archive
        Write-Host "created $archive"
    } else {
        Write-Host "created $packageRoot"
    }
}
finally {
    Pop-Location
}
