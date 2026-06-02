param(
    [string]$Toolchain = $env:CONU_RUST_TOOLCHAIN,
    [switch]$SmokeOnly,
    [switch]$SkipRust,
    [switch]$SkipPackages,
    [switch]$SkipSmokes,
    [switch]$CheckGitHubReleaseSecrets,
    [switch]$CheckGitHubBranchProtection,
    [switch]$CheckGitHubActionsPermissions,
    [switch]$CheckGitHubWorkflowPermissions,
    [switch]$CheckGitHubRepositorySecurity,
    [switch]$CheckPlatformSigningSecrets,
    [switch]$CheckGitHubPages,
    [switch]$CheckTaggedReleaseReadiness,
    [switch]$RequireTaggedReleaseCi,
    [switch]$RequireTaggedReleaseDefaultBranchHead,
    [switch]$CheckLinuxRepositoryEndpoint,
    [string]$LinuxRepositoryBaseUrl = $env:CONU_LINUX_REPOSITORY_BASE_URL,
    [string]$GitHubRepo = $env:GH_REPO,
    [string]$ReleaseSecretEnvFile = $env:CONU_RELEASE_SECRET_ENV_FILE,
    [string]$ReleaseTag = $env:CONU_RELEASE_TAG,
    [string]$TaggedReleaseCiHead = $env:CONU_RELEASE_CI_HEAD,
    [string]$TaggedReleaseTargetHead = $env:CONU_RELEASE_TARGET_HEAD,
    [string]$TaggedReleaseBranch = $env:CONU_RELEASE_BRANCH,
    [string]$GitHubBranchProtectionBranch = "main",
    [switch]$RequireGitHubBranchPrReviews,
    [switch]$RequireGitHubBranchAdminEnforcement,
    [switch]$RequireGitHubActionsShaPinning,
    [switch]$NpmRegistryCheck
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
            & python scripts/check-python-script-compile.py
        }
        Invoke-ReadinessStep "smoke output privacy regression" {
            & python scripts/check-smoke-output-privacy.py
        }
        Invoke-ReadinessStep "release version consistency" {
            & python scripts/verify-release-versions.py
        }
        Invoke-ReadinessStep "release artifact verifier regression" {
            & python scripts/check-release-artifact-verifier.py
        }
        Invoke-ReadinessStep "release artifact smoke preflight regression" {
            & python scripts/check-release-artifact-smoke-preflight.py
        }
        Invoke-ReadinessStep "package-manager manifest regression" {
            & python scripts/check-package-manager-manifests.py
        }
        Invoke-ReadinessStep "package-manager submission bundle regression" {
            & python scripts/check-package-manager-submissions.py
        }
        Invoke-ReadinessStep "linux signing secret preflight regression" {
            & python scripts/check-linux-signing-secrets-preflight-regression.py
        }
        Invoke-ReadinessStep "platform signing secret value preflight regression" {
            & python scripts/check-platform-signing-secrets-preflight-regression.py
        }
        Invoke-ReadinessStep "GitHub release secret readiness regression" {
            & python scripts/check-github-release-secret-readiness-regression.py
        }
        Invoke-ReadinessStep "release secret env preflight regression" {
            & python scripts/check-release-secret-env-preflight-regression.py
        }
        Invoke-ReadinessStep "GitHub release secret setup regression" {
            & python scripts/set-github-release-secrets-regression.py
        }
        Invoke-ReadinessStep "GitHub main branch protection regression" {
            & python scripts/check-github-main-protection-regression.py
        }
        Invoke-ReadinessStep "GitHub Actions permissions regression" {
            & python scripts/check-github-actions-permissions-regression.py
        }
        Invoke-ReadinessStep "GitHub workflow permissions regression" {
            & python scripts/check-github-workflow-permissions-regression.py
        }
        Invoke-ReadinessStep "GitHub repository security regression" {
            & python scripts/check-github-repository-security-regression.py
        }
        Invoke-ReadinessStep "GitHub Pages readiness regression" {
            & python scripts/check-github-pages-readiness-regression.py
        }
        Invoke-ReadinessStep "tagged release readiness regression" {
            & python scripts/check-tagged-release-readiness-regression.py
        }
        Invoke-ReadinessStep "GitHub Release asset publication regression" {
            & python scripts/check-github-release-assets-published-regression.py
        }
        Invoke-ReadinessStep "GitHub Release clobber preflight regression" {
            & python scripts/check-github-release-clobber-preflight-regression.py
        }
        Invoke-ReadinessStep "RPM package signing regression" {
            & python scripts/check-rpm-package-signing.py
        }
        Invoke-ReadinessStep "linux release signing regression" {
            & python scripts/check-linux-release-signing.py
        }
        Invoke-ReadinessStep "linux repository signing regression" {
            & python scripts/check-linux-repository-signing.py
        }
        Invoke-ReadinessStep "hosted Linux repository bundle regression" {
            & python scripts/check-hosted-linux-repositories.py
        }
        Invoke-ReadinessStep "hosted Linux repository site regression" {
            & python scripts/check-hosted-linux-repository-site.py
        }
        Invoke-ReadinessStep "hosted Linux repository Pages regression" {
            & python scripts/check-hosted-linux-repository-pages.py
        }
        Invoke-ReadinessStep "hosted Linux repository endpoint regression" {
            & python scripts/check-hosted-linux-repository-endpoint-regression.py
        }
        Invoke-ReadinessStep "hosted Linux repository S3 publication regression" {
            & python scripts/check-hosted-linux-repository-s3-publication.py
        }
        Invoke-ReadinessStep "release update policy regression" {
            & python scripts/check-release-update-policy.py
        }
        Invoke-ReadinessStep "release update download/apply gate regression" {
            & python scripts/check-release-update-download-gate.py
        }
        Invoke-ReadinessStep "linux GPG public-key export regression" {
            & python scripts/check-linux-gpg-public-key-export.py
        }
        Invoke-ReadinessStep "TypeScript SDK check" {
            & npm run check --prefix sdk/typescript
        }
        Invoke-ReadinessStep "npm launcher check" {
            & npm run check --prefix packaging/npm/conu-cli
        }
        Invoke-ReadinessStep "npm launcher local smoke preflight regression" {
            & python scripts/check-npm-launcher-local-smoke-preflight.py
        }
        Invoke-ReadinessStep "npm package content check" {
            & python scripts/verify-npm-package-contents.py
        }
        Invoke-ReadinessStep "npm package public metadata regression" {
            & python scripts/verify-npm-package-contents-regression.py
        }
        Invoke-ReadinessStep "npm publish preflight" {
            & python scripts/check-npm-publish-preflight.py
        }
        Invoke-ReadinessStep "npm publish preflight regression" {
            & python scripts/check-npm-publish-preflight-regression.py
        }
    }

    if ($CheckGitHubReleaseSecrets) {
        $secretReadinessArgs = @("scripts/check-github-release-secret-readiness.py")
        if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
            $secretReadinessArgs += @("--repo", $GitHubRepo)
        }
        Invoke-ReadinessStep "GitHub release secret readiness" {
            & python @secretReadinessArgs
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ReleaseSecretEnvFile)) {
        Invoke-ReadinessStep "release secret env-file validation" {
            & python scripts/set-github-release-secrets.py --env-file $ReleaseSecretEnvFile --check-env-file
        }
    }

    if ($CheckGitHubBranchProtection) {
        $branchProtectionArgs = @("scripts/check-github-main-protection.py")
        if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
            $branchProtectionArgs += @("--repo", $GitHubRepo)
        }
        if (-not [string]::IsNullOrWhiteSpace($GitHubBranchProtectionBranch)) {
            $branchProtectionArgs += @("--branch", $GitHubBranchProtectionBranch)
        }
        if ($RequireGitHubBranchPrReviews) {
            $branchProtectionArgs += @("--require-pr-reviews", "--require-stale-review-dismissal")
        }
        if ($RequireGitHubBranchAdminEnforcement) {
            $branchProtectionArgs += @("--require-admin-enforcement")
        }
        Invoke-ReadinessStep "GitHub main branch protection readiness" {
            & python @branchProtectionArgs
        }
    }

    if ($CheckGitHubActionsPermissions) {
        $actionsPermissionsArgs = @("scripts/check-github-actions-permissions.py")
        if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
            $actionsPermissionsArgs += @("--repo", $GitHubRepo)
        }
        if ($RequireGitHubActionsShaPinning) {
            $actionsPermissionsArgs += @("--require-sha-pinning")
        }
        Invoke-ReadinessStep "GitHub Actions permissions readiness" {
            & python @actionsPermissionsArgs
        }
    }

    if ($CheckGitHubWorkflowPermissions) {
        Invoke-ReadinessStep "GitHub workflow permissions readiness" {
            & python scripts/check-github-workflow-permissions.py
        }
    }

    if ($CheckGitHubRepositorySecurity) {
        $repositorySecurityArgs = @("scripts/check-github-repository-security.py")
        if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
            $repositorySecurityArgs += @("--repo", $GitHubRepo)
        }
        Invoke-ReadinessStep "GitHub repository security readiness" {
            & python @repositorySecurityArgs
        }
    }

    if ($CheckPlatformSigningSecrets) {
        Invoke-ReadinessStep "platform signing secret value preflight" {
            & python scripts/check-platform-signing-secrets-preflight.py --require-openssl
        }
    }

    if ($CheckGitHubPages) {
        $pagesReadinessArgs = @("scripts/check-github-pages-readiness.py")
        if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
            $pagesReadinessArgs += @("--repo", $GitHubRepo)
        }
        if (-not [string]::IsNullOrWhiteSpace($LinuxRepositoryBaseUrl)) {
            $pagesReadinessArgs += @("--linux-repository-base-url", $LinuxRepositoryBaseUrl)
        }
        Invoke-ReadinessStep "GitHub Pages readiness" {
            & python @pagesReadinessArgs
        }
    }

    if ($CheckTaggedReleaseReadiness) {
        $taggedReadinessArgs = @("scripts/check-tagged-release-readiness.py")
        if (-not [string]::IsNullOrWhiteSpace($GitHubRepo)) {
            $taggedReadinessArgs += @("--repo", $GitHubRepo)
        }
        if (-not [string]::IsNullOrWhiteSpace($ReleaseTag)) {
            $taggedReadinessArgs += @("--tag", $ReleaseTag)
        }
        if ($NpmRegistryCheck) {
            $taggedReadinessArgs += @("--npm-registry-check")
        }
        if ($RequireTaggedReleaseCi) {
            $taggedReadinessArgs += @("--require-ci")
            if (-not [string]::IsNullOrWhiteSpace($TaggedReleaseCiHead)) {
                $taggedReadinessArgs += @("--ci-head", $TaggedReleaseCiHead)
            }
        }
        if ($RequireTaggedReleaseDefaultBranchHead) {
            $taggedReadinessArgs += @("--require-default-branch-head")
            if (-not [string]::IsNullOrWhiteSpace($TaggedReleaseTargetHead)) {
                $taggedReadinessArgs += @("--release-target-head", $TaggedReleaseTargetHead)
            }
            if (-not [string]::IsNullOrWhiteSpace($TaggedReleaseBranch)) {
                $taggedReadinessArgs += @("--release-branch", $TaggedReleaseBranch)
            }
        }
        Invoke-ReadinessStep "tagged release readiness" {
            & python @taggedReadinessArgs
        }
    }

    if ($CheckLinuxRepositoryEndpoint) {
        $endpointReadinessArgs = @("scripts/check-hosted-linux-repository-endpoint.py")
        if (-not [string]::IsNullOrWhiteSpace($LinuxRepositoryBaseUrl)) {
            $endpointReadinessArgs += @("--base-url", $LinuxRepositoryBaseUrl)
        }
        Invoke-ReadinessStep "hosted Linux repository endpoint readiness" {
            & python @endpointReadinessArgs
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
