param(
    [string]$Target = "",
    [string]$Profile = "release",
    [string]$OutDir = "dist",
    [string]$PackageSuffix = "",
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN,
    [string]$WindowsSigningCertPfxBase64 = $env:CONU_WINDOWS_SIGN_CERT_PFX_BASE64,
    [string]$WindowsSigningCertPassword = $env:CONU_WINDOWS_SIGN_CERT_PASSWORD,
    [string]$WindowsTimestampUrl = $(if ($env:CONU_WINDOWS_TIMESTAMP_URL) { $env:CONU_WINDOWS_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }),
    [string]$SigningRequired = $env:CONU_SIGNING_REQUIRED
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

function Test-CurrentPlatformWindows {
    return ($IsWindows -or $env:OS -eq "Windows_NT")
}

function ConvertTo-TomlBool {
    param([bool]$Value)

    if ($Value) {
        return "true"
    }
    return "false"
}

function Sign-WindowsBinaries {
    param(
        [string]$BinDir
    )

    if (-not (Test-CurrentPlatformWindows)) {
        return $false
    }

    $hasCert = -not [string]::IsNullOrWhiteSpace($WindowsSigningCertPfxBase64)
    if (-not $hasCert) {
        if ($SigningRequired -eq "1") {
            throw "CONU_SIGNING_REQUIRED=1 but CONU_WINDOWS_SIGN_CERT_PFX_BASE64 is not configured"
        }
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($WindowsSigningCertPassword)) {
        throw "CONU_WINDOWS_SIGN_CERT_PASSWORD is required when CONU_WINDOWS_SIGN_CERT_PFX_BASE64 is set"
    }

    $pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) "conu-codesign-$([System.Guid]::NewGuid()).pfx"
    $cert = $null
    try {
        [System.IO.File]::WriteAllBytes($pfxPath, [System.Convert]::FromBase64String($WindowsSigningCertPfxBase64))
        $keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxPath,
            $WindowsSigningCertPassword,
            $keyFlags
        )

        foreach ($exe in Get-ChildItem -LiteralPath $BinDir -Filter "*.exe" -File) {
            $signature = Set-AuthenticodeSignature `
                -LiteralPath $exe.FullName `
                -Certificate $cert `
                -TimestampServer $WindowsTimestampUrl `
                -HashAlgorithm SHA256
            if ($signature.Status -ne "Valid") {
                throw "Authenticode signing failed for $($exe.Name): $($signature.Status)"
            }

            $verify = Get-AuthenticodeSignature -LiteralPath $exe.FullName
            if ($verify.Status -ne "Valid") {
                throw "Authenticode verification failed for $($exe.Name): $($verify.Status)"
            }
        }
        return $true
    }
    finally {
        if ($cert -ne $null) {
            $cert.Dispose()
        }
        if (Test-Path -LiteralPath $pfxPath) {
            Remove-Item -LiteralPath $pfxPath -Force
        }
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
if ($PackageSuffix.Trim().Length -gt 0) {
    $targetSuffix = $PackageSuffix
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
    Copy-Item docs\*.md -Destination $docDir -Force
    Copy-Item -Recurse packaging -Destination $packageRoot -Force

    $windowsSigned = Sign-WindowsBinaries -BinDir $binDir

    $manifest = @"
name = "conU"
version = "$version"
target = "$targetSuffix"
profile = "$Profile"
payload_contents_included = false
windows_authenticode_signed = $(ConvertTo-TomlBool $windowsSigned)
macos_codesigned = false
macos_notarized = false
linux_signature_policy = "sha256-checksum-and-github-artifact-attestation"
"@
    Set-Content -Path (Join-Path $packageRoot "manifest.toml") -Value $manifest -Encoding UTF8

    if (Test-CurrentPlatformWindows) {
        $archive = "$packageRoot.zip"
        if (Test-Path $archive) {
            Remove-Item $archive -Force
        }
        Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $archive
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
        Set-Content -Path "$archive.sha256" -Value "$hash  $(Split-Path -Leaf $archive)" -Encoding ASCII
        Write-Host "created $archive"
        Write-Host "created $archive.sha256"
    } else {
        Write-Host "created $packageRoot"
    }
}
finally {
    Pop-Location
}
