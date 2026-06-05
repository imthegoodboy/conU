#!/usr/bin/env python3
"""Regression checks for GitHub workflow permissions readiness."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-github-workflow-permissions.py")
SENSITIVE_SENTINEL = "do-not-print-this-token-or-payload"


def load_module():
    spec = importlib.util.spec_from_file_location("check_github_workflow_permissions", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load GitHub workflow permissions module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def ready_ci() -> str:
    return """
name: CI
on:
  push:
    branches: ["main"]
  pull_request:
permissions:
  contents: read
jobs:
  packages:
    name: Packages
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/setup-node@v6
        with:
          node-version: 24
      - name: Install package tools
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm createrepo-c gnupg openssl
      - name: Python script compile
        run: python scripts/check-python-script-compile.py
      - name: Production readiness toolchain regression
        run: python scripts/check-production-readiness-toolchain.py
      - name: Smoke output privacy regression
        run: python scripts/check-smoke-output-privacy.py
      - name: Release version consistency
        run: python scripts/verify-release-versions.py
      - name: Release artifact verifier regression
        run: python scripts/check-release-artifact-verifier.py
      - name: Release artifact smoke preflight regression
        run: python scripts/check-release-artifact-smoke-preflight.py
      - name: Package-manager manifest regression
        run: python scripts/check-package-manager-manifests.py
      - name: Package-manager submission bundle regression
        run: python scripts/check-package-manager-submissions.py
      - name: Linux signing secret preflight regression
        run: python scripts/check-linux-signing-secrets-preflight-regression.py
      - name: Platform signing secret value preflight regression
        run: python scripts/check-platform-signing-secrets-preflight-regression.py
      - name: GitHub release secret readiness regression
        run: python scripts/check-github-release-secret-readiness-regression.py
      - name: Release secret env preflight regression
        run: python scripts/check-release-secret-env-preflight-regression.py
      - name: Release secret rotation gate regression
        run: python scripts/check-release-secret-rotation-gate-regression.py
      - name: GitHub release secret setup regression
        run: python scripts/set-github-release-secrets-regression.py
      - name: GitHub main branch protection regression
        run: python scripts/check-github-main-protection-regression.py
      - name: GitHub Actions permissions regression
        run: python scripts/check-github-actions-permissions-regression.py
      - name: GitHub workflow permissions regression
        run: python scripts/check-github-workflow-permissions-regression.py
      - name: GitHub repository security regression
        run: python scripts/check-github-repository-security-regression.py
      - name: GitHub Pages readiness regression
        run: python scripts/check-github-pages-readiness-regression.py
      - name: GitHub Release asset publication regression
        run: python scripts/check-github-release-assets-published-regression.py
      - name: GitHub Release clobber preflight regression
        run: python scripts/check-github-release-clobber-preflight-regression.py
      - name: Unsigned preview release asset regression
        run: python scripts/check-unsigned-preview-release-assets-regression.py
      - name: Tagged release readiness regression
        run: python scripts/check-tagged-release-readiness-regression.py
      - name: RPM package signing regression
        run: python scripts/check-rpm-package-signing.py
      - name: Linux release signing regression
        run: python scripts/check-linux-release-signing.py
      - name: Linux repository signing regression
        run: python scripts/check-linux-repository-signing.py
      - name: Hosted Linux repository bundle regression
        run: python scripts/check-hosted-linux-repositories.py
      - name: Hosted Linux repository site regression
        run: python scripts/check-hosted-linux-repository-site.py
      - name: Hosted Linux repository Pages regression
        run: python scripts/check-hosted-linux-repository-pages.py
      - name: Hosted Linux repository endpoint regression
        run: python scripts/check-hosted-linux-repository-endpoint-regression.py
      - name: Hosted Linux repository S3 publication regression
        run: python scripts/check-hosted-linux-repository-s3-publication.py
      - name: Release update policy regression
        run: python scripts/check-release-update-policy.py
      - name: Release update download/apply gate regression
        run: python scripts/check-release-update-download-gate.py
      - name: Linux GPG public-key export regression
        run: python scripts/check-linux-gpg-public-key-export.py
      - name: TypeScript SDK check
        run: npm run check --prefix sdk/typescript
      - name: npm launcher check
        run: npm run check --prefix packaging/npm/conu-cli
      - name: npm launcher local smoke preflight regression
        run: python scripts/check-npm-launcher-local-smoke-preflight.py
      - name: Verify npm package contents
        run: python scripts/verify-npm-package-contents.py
      - name: npm package public metadata regression
        run: python scripts/verify-npm-package-contents-regression.py
      - name: npm publish preflight
        run: python scripts/check-npm-publish-preflight.py
      - name: npm publish preflight regression
        run: python scripts/check-npm-publish-preflight-regression.py
  rust:
    name: Rust (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-2025-vs2026, macos-15]
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Format
        run: cargo fmt --all -- --check
      - name: Check
        run: cargo check --workspace --all-targets
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Test
        run: cargo test --workspace
      - name: Python compile
        run: python scripts/check-python-script-compile.py
      - name: Doctor smoke
        run: cargo run -p conu-cli -- doctor --json
      - name: Production readiness smoke gate
        if: matrix.os == 'windows-2025-vs2026'
        shell: pwsh
        run: ./scripts/verify-production-readiness.ps1 -SmokeOnly
"""


def ready_release() -> str:
    return """
name: Release Artifacts
on:
  push:
    tags:
      - "v*"
  workflow_dispatch:
    inputs:
      publish_preview_release:
        description: "Publish unsigned preview prerelease artifacts for manual testing"
        required: false
        default: "false"
        type: choice
        options:
          - "false"
          - "true"
permissions:
  contents: read
jobs:
  release-preflight:
    permissions:
      actions: read
      contents: read
      pages: read
      security-events: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        if: startsWith(github.ref, 'refs/tags/v')
        with:
          persist-credentials: false
      - run: echo preflight
      - name: Validate tag target CI and release branch
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-tagged-release-readiness.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME" --ci-only --ci-head "$GITHUB_SHA" --require-default-branch-head
      - name: Validate GitHub main branch protection
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-main-protection.py --repo "$GITHUB_REPOSITORY" --require-admin-enforcement
      - name: Validate GitHub Actions permissions
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-actions-permissions.py --repo "$GITHUB_REPOSITORY"
      - name: Validate GitHub workflow permissions
        if: startsWith(github.ref, 'refs/tags/v')
        run: python scripts/check-github-workflow-permissions.py
      - name: Validate GitHub repository security
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-repository-security.py --repo "$GITHUB_REPOSITORY"
      - name: Check tagged release secrets
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          CONU_WINDOWS_SIGN_CERT_PFX_BASE64: ${{ secrets.CONU_WINDOWS_SIGN_CERT_PFX_BASE64 }}
          CONU_WINDOWS_SIGN_CERT_PASSWORD: ${{ secrets.CONU_WINDOWS_SIGN_CERT_PASSWORD }}
          CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64: ${{ secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 }}
          CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD: ${{ secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD }}
          CONU_MACOS_CODESIGN_IDENTITY: ${{ secrets.CONU_MACOS_CODESIGN_IDENTITY }}
          CONU_MACOS_NOTARY_APPLE_ID: ${{ secrets.CONU_MACOS_NOTARY_APPLE_ID }}
          CONU_MACOS_NOTARY_TEAM_ID: ${{ secrets.CONU_MACOS_NOTARY_TEAM_ID }}
          CONU_MACOS_NOTARY_PASSWORD: ${{ secrets.CONU_MACOS_NOTARY_PASSWORD }}
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: python scripts/check-release-secret-env-preflight.py
      - name: Validate NPM token rotation marker
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          CONU_NPM_TOKEN_ROTATED_AFTER: ${{ vars.CONU_NPM_TOKEN_ROTATED_AFTER }}
        run: python scripts/check-release-secret-rotation-gate.py --secret-name NPM_TOKEN --rotated-after-env CONU_NPM_TOKEN_ROTATED_AFTER --required-after 2026-06-05T00:00:00Z
      - name: Validate npm token authentication and registry availability
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: python scripts/check-npm-publish-preflight.py --registry-check --require-token-env NODE_AUTH_TOKEN --token-auth-check
      - name: Install signing preflight tools
        if: startsWith(github.ref, 'refs/tags/v')
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends gnupg openssl
      - name: Validate platform signing secret values
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          CONU_WINDOWS_SIGN_CERT_PFX_BASE64: ${{ secrets.CONU_WINDOWS_SIGN_CERT_PFX_BASE64 }}
          CONU_WINDOWS_SIGN_CERT_PASSWORD: ${{ secrets.CONU_WINDOWS_SIGN_CERT_PASSWORD }}
          CONU_WINDOWS_TIMESTAMP_URL: ${{ secrets.CONU_WINDOWS_TIMESTAMP_URL }}
          CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64: ${{ secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 }}
          CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD: ${{ secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD }}
          CONU_MACOS_CODESIGN_IDENTITY: ${{ secrets.CONU_MACOS_CODESIGN_IDENTITY }}
          CONU_MACOS_NOTARY_APPLE_ID: ${{ secrets.CONU_MACOS_NOTARY_APPLE_ID }}
          CONU_MACOS_NOTARY_TEAM_ID: ${{ secrets.CONU_MACOS_NOTARY_TEAM_ID }}
          CONU_MACOS_NOTARY_PASSWORD: ${{ secrets.CONU_MACOS_NOTARY_PASSWORD }}
        run: python scripts/check-platform-signing-secrets-preflight.py --require-openssl
      - name: Validate Linux signing secrets
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/check-linux-signing-secrets-preflight.py
      - name: Validate default GitHub Pages repository settings
        if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL == ''
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-pages-readiness.py --repo "$GITHUB_REPOSITORY"
      - name: Validate GitHub Release tag is unpublished
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-release-clobber-preflight.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"
      - name: Validate custom Linux repository publication config
        if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL != ''
        env:
          CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}
          CONU_LINUX_REPOSITORY_S3_BUCKET: ${{ vars.CONU_LINUX_REPOSITORY_S3_BUCKET }}
          CONU_LINUX_REPOSITORY_S3_PREFIX: ${{ vars.CONU_LINUX_REPOSITORY_S3_PREFIX }}
          CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL: ${{ vars.CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL }}
          CONU_LINUX_REPOSITORY_AWS_REGION: ${{ vars.CONU_LINUX_REPOSITORY_AWS_REGION }}
          CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID }}
          CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY }}
          CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN }}
        run: python scripts/check-custom-linux-repository-publication-preflight.py
  packages:
    needs: release-preflight
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/setup-node@v6
        with:
          node-version: 24
          registry-url: https://registry.npmjs.org
      - name: Install package tools
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm createrepo-c gnupg openssl
      - name: Python script compile
        run: python scripts/check-python-script-compile.py
      - name: Production readiness toolchain regression
        run: python scripts/check-production-readiness-toolchain.py
      - name: Smoke output privacy regression
        run: python scripts/check-smoke-output-privacy.py
      - name: Release version consistency
        run: python scripts/verify-release-versions.py
      - name: Release artifact verifier regression
        run: python scripts/check-release-artifact-verifier.py
      - name: Release artifact smoke preflight regression
        run: python scripts/check-release-artifact-smoke-preflight.py
      - name: Package-manager manifest regression
        run: python scripts/check-package-manager-manifests.py
      - name: Package-manager submission bundle regression
        run: python scripts/check-package-manager-submissions.py
      - name: Linux signing secret preflight regression
        run: python scripts/check-linux-signing-secrets-preflight-regression.py
      - name: Platform signing secret value preflight regression
        run: python scripts/check-platform-signing-secrets-preflight-regression.py
      - name: GitHub release secret readiness regression
        run: python scripts/check-github-release-secret-readiness-regression.py
      - name: Release secret env preflight regression
        run: python scripts/check-release-secret-env-preflight-regression.py
      - name: Release secret rotation gate regression
        run: python scripts/check-release-secret-rotation-gate-regression.py
      - name: GitHub release secret setup regression
        run: python scripts/set-github-release-secrets-regression.py
      - name: GitHub main branch protection regression
        run: python scripts/check-github-main-protection-regression.py
      - name: GitHub Actions permissions regression
        run: python scripts/check-github-actions-permissions-regression.py
      - name: GitHub workflow permissions regression
        run: python scripts/check-github-workflow-permissions-regression.py
      - name: GitHub repository security regression
        run: python scripts/check-github-repository-security-regression.py
      - name: GitHub Pages readiness regression
        run: python scripts/check-github-pages-readiness-regression.py
      - name: GitHub Release asset publication regression
        run: python scripts/check-github-release-assets-published-regression.py
      - name: GitHub Release clobber preflight regression
        run: python scripts/check-github-release-clobber-preflight-regression.py
      - name: Unsigned preview release asset regression
        run: python scripts/check-unsigned-preview-release-assets-regression.py
      - name: Tagged release readiness regression
        run: python scripts/check-tagged-release-readiness-regression.py
      - name: RPM package signing regression
        run: python scripts/check-rpm-package-signing.py
      - name: Linux release signing regression
        run: python scripts/check-linux-release-signing.py
      - name: Linux repository signing regression
        run: python scripts/check-linux-repository-signing.py
      - name: Hosted Linux repository bundle regression
        run: python scripts/check-hosted-linux-repositories.py
      - name: Hosted Linux repository site regression
        run: python scripts/check-hosted-linux-repository-site.py
      - name: Hosted Linux repository Pages regression
        run: python scripts/check-hosted-linux-repository-pages.py
      - name: Hosted Linux repository endpoint regression
        run: python scripts/check-hosted-linux-repository-endpoint-regression.py
      - name: Hosted Linux repository S3 publication regression
        run: python scripts/check-hosted-linux-repository-s3-publication.py
      - name: Release update policy regression
        run: python scripts/check-release-update-policy.py
      - name: Release update download/apply gate regression
        run: python scripts/check-release-update-download-gate.py
      - name: Linux GPG public-key export regression
        run: python scripts/check-linux-gpg-public-key-export.py
      - name: TypeScript SDK check
        run: npm run check --prefix sdk/typescript
      - name: npm launcher check
        run: npm run check --prefix packaging/npm/conu-cli
      - name: npm launcher local smoke preflight regression
        run: python scripts/check-npm-launcher-local-smoke-preflight.py
      - name: Verify npm package contents
        run: python scripts/verify-npm-package-contents.py
      - name: npm package public metadata regression
        run: python scripts/verify-npm-package-contents-regression.py
      - name: npm publish preflight
        run: python scripts/check-npm-publish-preflight.py
      - name: npm publish preflight regression
        run: python scripts/check-npm-publish-preflight-regression.py
  production-readiness:
    needs:
      - release-preflight
    runs-on: windows-2025-vs2026
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@stable
      - name: Production readiness smoke gate
        shell: pwsh
        run: ./scripts/verify-production-readiness.ps1 -SmokeOnly
  build:
    name: Build ${{ matrix.name }}
    needs: [packages, production-readiness]
    runs-on: ${{ matrix.os }}
    permissions:
      contents: read
      id-token: write
      attestations: write
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: windows-x64
            os: windows-2025-vs2026
            script: powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -PackageSuffix windows-x64
            artifact: |
              dist/*.zip
              dist/*.zip.sha256
          - name: linux-x64
            os: ubuntu-latest
            script: PACKAGE_SUFFIX=linux-x64 sh scripts/build-release.sh
            artifact: |
              dist/*.tar.gz
              dist/*.tar.gz.sha256
          - name: linux-arm64
            os: ubuntu-24.04-arm
            script: PACKAGE_SUFFIX=linux-arm64 sh scripts/build-release.sh
            artifact: |
              dist/*.tar.gz
              dist/*.tar.gz.sha256
          - name: macos-arm64
            os: macos-15
            script: PACKAGE_SUFFIX=macos-arm64 sh scripts/build-release.sh
            artifact: |
              dist/*.zip
              dist/*.zip.sha256
          - name: macos-x64
            os: macos-15-intel
            script: PACKAGE_SUFFIX=macos-x64 sh scripts/build-release.sh
            artifact: |
              dist/*.zip
              dist/*.zip.sha256
    env:
      CONU_SIGNING_REQUIRED: ${{ startsWith(github.ref, 'refs/tags/v') && '1' || '0' }}
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@stable
      - name: Configure macOS signing keychain
        if: runner.os == 'macOS'
        env:
          MACOS_P12_BASE64: ${{ secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 }}
          MACOS_P12_PASSWORD: ${{ secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD }}
          MACOS_CODESIGN_IDENTITY: ${{ secrets.CONU_MACOS_CODESIGN_IDENTITY }}
          MACOS_NOTARY_APPLE_ID: ${{ secrets.CONU_MACOS_NOTARY_APPLE_ID }}
          MACOS_NOTARY_TEAM_ID: ${{ secrets.CONU_MACOS_NOTARY_TEAM_ID }}
          MACOS_NOTARY_PASSWORD: ${{ secrets.CONU_MACOS_NOTARY_PASSWORD }}
        run: |
          set -eu
          append_github_env() {
            name="$1"
            value="$2"
            printf '%s=%s\\n' "$name" "$value" >> "$GITHUB_ENV"
          }
          if [ "${CONU_SIGNING_REQUIRED:-0}" = "1" ]; then
            echo "signing required"
          fi
          xcrun notarytool store-credentials conu-notary-profile
          append_github_env CONU_MACOS_CODESIGN_IDENTITY "$MACOS_CODESIGN_IDENTITY"
          append_github_env CONU_MACOS_KEYCHAIN "$keychain_path"
          append_github_env CONU_MACOS_NOTARY_KEYCHAIN_PROFILE "conu-notary-profile"
      - name: Build package
        env:
          CONU_WINDOWS_SIGN_CERT_PFX_BASE64: ${{ secrets.CONU_WINDOWS_SIGN_CERT_PFX_BASE64 }}
          CONU_WINDOWS_SIGN_CERT_PASSWORD: ${{ secrets.CONU_WINDOWS_SIGN_CERT_PASSWORD }}
          CONU_WINDOWS_TIMESTAMP_URL: ${{ secrets.CONU_WINDOWS_TIMESTAMP_URL }}
        run: ${{ matrix.script }}
      - name: Verify release artifact
        run: python scripts/verify-release-artifacts.py dist
      - name: Smoke release artifact install
        run: python scripts/smoke-release-artifacts.py dist
      - name: Smoke npm launcher local install
        run: python scripts/smoke-npm-launcher-local.py dist
      - name: Smoke npm launcher download install
        run: python scripts/smoke-npm-launcher-download.py dist
      - name: Attest release artifact provenance
        uses: actions/attest@v4.1.0
        with:
          subject-path: ${{ matrix.artifact }}
      - name: Upload artifact
        uses: actions/upload-artifact@v7.0.1
        with:
          name: conu-${{ matrix.name }}
          path: ${{ matrix.artifact }}
          if-no-files-found: error
  manual-preview-release:
    needs: build
    if: github.event_name == 'workflow_dispatch' && inputs.publish_preview_release == 'true'
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/download-artifact@v8.0.1
        with:
          path: dist
          pattern: conu-*
          digest-mismatch: error
          merge-multiple: true
      - name: Verify unsigned preview artifacts
        run: python scripts/verify-release-artifacts.py dist
      - name: Check unsigned preview asset set before publication
        run: python scripts/check-unsigned-preview-release-assets.py --dist-dir dist --json
      - name: Publish unsigned preview prerelease
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -eu
          PREVIEW_TAG="preview-${GITHUB_RUN_ID}"
          if gh release view "$PREVIEW_TAG" --repo "$GH_REPO" >/dev/null 2>&1; then
            echo "::error::Unsigned preview release $PREVIEW_TAG already exists; refusing to overwrite assets."
            exit 1
          fi
          gh release create "$PREVIEW_TAG" dist/* --target "$GITHUB_SHA" --prerelease --title "conU unsigned preview ${GITHUB_RUN_ID}" --notes-file release-notes.md
      - name: Verify published unsigned preview prerelease
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -eu
          PREVIEW_TAG="preview-${GITHUB_RUN_ID}"
          python scripts/check-unsigned-preview-release-assets.py --repo "$GH_REPO" --tag "$PREVIEW_TAG" --json
  github-release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/download-artifact@v8.0.1
        with:
          path: dist
          pattern: conu-*
          digest-mismatch: error
          merge-multiple: true
      - name: Install package tools
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm createrepo-c gnupg
      - name: Verify downloaded release assets
        run: python scripts/verify-release-artifacts.py dist
      - name: Generate package-manager manifests
        env:
          GH_REPO: ${{ github.repository }}
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          python scripts/generate-package-manager-manifests.py dist --output-dir dist --repo "$GH_REPO" --version "$VERSION" --tag "$TAG_NAME" --build-rpm-packages --build-apt-repository-metadata
      - name: Sign RPM packages
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-rpm-packages.py dist
      - name: Generate RPM repository metadata
        env:
          GH_REPO: ${{ github.repository }}
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          python scripts/generate-package-manager-manifests.py dist --output-dir dist --repo "$GH_REPO" --version "$VERSION" --tag "$TAG_NAME" --build-rpm-repository-metadata
      - name: Export Linux GPG public key
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/export-linux-gpg-public-key.py dist
      - name: Sign Linux repository metadata
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-linux-repository-metadata.py dist
      - name: Sign Linux release assets
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-linux-release-assets.py dist
      - name: Prepare package-manager submission bundle
        env:
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          python scripts/prepare-package-manager-submissions.py dist --output-dir dist --version "$VERSION" --require-rpm-assets --require-repository-metadata --require-linux-signatures
      - name: Sign package-manager submission bundle
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-linux-release-assets.py dist --only-package-manager-submissions
      - name: Generate hosted Linux repositories
        env:
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          python scripts/generate-hosted-linux-repositories.py dist --output-dir dist --version "$VERSION"
      - name: Sign hosted Linux repository bundle
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-linux-release-assets.py dist --only-hosted-repository-bundles
      - name: Generate hosted Linux repository site
        env:
          GH_REPO: ${{ github.repository }}
          GITHUB_REPOSITORY_OWNER: ${{ github.repository_owner }}
          TAG_NAME: ${{ github.ref_name }}
          CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          BASE_URL="${CONU_LINUX_REPOSITORY_BASE_URL:-}"
          if [ -z "$BASE_URL" ]; then
            REPO_NAME="${GH_REPO#*/}"
            BASE_URL="https://${GITHUB_REPOSITORY_OWNER}.github.io/${REPO_NAME}"
          fi
          python scripts/generate-hosted-linux-repository-site.py dist --output-dir dist --version "$VERSION" --base-url "$BASE_URL"
      - name: Sign hosted Linux repository site
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-linux-release-assets.py dist --only-hosted-repository-sites
      - name: Generate release update policy
        env:
          GH_REPO: ${{ github.repository }}
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          python scripts/generate-release-update-policy.py dist --output-dir dist --version "$VERSION" --tag "$TAG_NAME" --repo "$GH_REPO"
      - name: Sign release update policy
        env:
          CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}
          CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}
          CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: python scripts/sign-linux-release-assets.py dist --only-update-policies
      - name: Check release update policy with CLI
        env:
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          cargo run -p conu-cli -- update check --policy-file "dist/conu-${VERSION}-update-policy.json" --json
      - name: Prepare hosted Linux repository Pages artifact
        run: python scripts/prepare-hosted-linux-repository-pages.py dist --output-dir linux-repository-site
      - name: Upload hosted Linux repository Pages artifact
        uses: actions/upload-artifact@v7.0.1
        with:
          name: conu-hosted-linux-repository-pages
          path: linux-repository-site
          if-no-files-found: error
          retention-days: 14
      - name: Re-check GitHub Release tag is unpublished
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-release-clobber-preflight.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"
      - name: Verify local GitHub Release asset set
        env:
          TAG_NAME: ${{ github.ref_name }}
        run: python scripts/check-github-release-assets-published.py --tag "$TAG_NAME" --dist-dir dist
      - name: Publish release assets
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
          TAG_NAME: ${{ github.ref_name }}
        run: |
          set -eu
          if gh release view "$TAG_NAME" >/dev/null 2>&1; then
            echo "::error::GitHub Release $TAG_NAME already exists; refusing to overwrite release assets."
            exit 1
          fi
          gh release create "$TAG_NAME" dist/* --verify-tag --title "conU $TAG_NAME" --notes-file release-notes.md
      - name: Verify published release update policy and artifact with CLI
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
          TAG_NAME: ${{ github.ref_name }}
          CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}
        run: |
          set -eu
          VERSION="${TAG_NAME#v}"
          POLICY_URL="https://github.com/${GH_REPO}/releases/download/${TAG_NAME}/conu-${VERSION}-update-policy.json"
          KEY_DIR="$RUNNER_TEMP/conu-release-key"
          GNUPG_HOME="$RUNNER_TEMP/conu-release-gnupg"
          DOWNLOAD_DIR="$RUNNER_TEMP/conu-update-download"
          APPLY_INSTALL_DIR="$RUNNER_TEMP/conu-update-apply-bin"
          mkdir -p "$KEY_DIR" "$GNUPG_HOME"
          chmod 700 "$GNUPG_HOME"
          gh release download "$TAG_NAME" --repo "$GH_REPO" --pattern conu-linux-gpg-key.asc --dir "$KEY_DIR"
          gh release download "$TAG_NAME" --repo "$GH_REPO" --pattern conu-linux-gpg-key.asc.sha256 --dir "$KEY_DIR"
          (cd "$KEY_DIR" && sha256sum -c conu-linux-gpg-key.asc.sha256)
          export GNUPGHOME="$GNUPG_HOME"
          gpg --batch --yes --import "$KEY_DIR/conu-linux-gpg-key.asc"
          EXPECTED_FINGERPRINT="$(printf '%s' "$CONU_LINUX_GPG_KEY_FINGERPRINT" | tr -d '[:space:]:' | sed 's/^0[xX]//' | tr '[:lower:]' '[:upper:]')"
          ACTUAL_FINGERPRINT="$(gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
          if [ "$ACTUAL_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]; then
            echo "::error::Published Linux GPG public key fingerprint mismatch"
            exit 1
          fi
          cargo run -p conu-cli -- update check --policy-url "$POLICY_URL" --gpg-verify --json
          cargo run -p conu-cli -- update download --policy-url "$POLICY_URL" --output-dir "$DOWNLOAD_DIR" --target linux-x64 --gpg-verify --json
          cargo run -p conu-cli -- update apply --policy-url "$POLICY_URL" --artifact-file "$DOWNLOAD_DIR/conu-${VERSION}-linux-x64.tar.gz" --install-dir "$APPLY_INSTALL_DIR" --target linux-x64 --gpg-verify --dry-run --json
  linux-repository-pages:
    needs: github-release
    if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL == ''
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/download-artifact@v8.0.1
        with:
          name: conu-hosted-linux-repository-pages
          path: linux-repository-site
          digest-mismatch: error
      - uses: actions/configure-pages@v6
      - uses: actions/upload-pages-artifact@v5
        with:
          path: linux-repository-site
      - id: deployment
        uses: actions/deploy-pages@v5
  custom-linux-repository-publish:
    needs: github-release
    if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL != ''
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/download-artifact@v8.0.1
        with:
          name: conu-hosted-linux-repository-pages
          path: linux-repository-site
          digest-mismatch: error
      - name: Install AWS CLI
        run: |
          python -m pip install --user awscli
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Publish custom hosted Linux repository and verify endpoint
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY }}
          AWS_SESSION_TOKEN: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN }}
          CONU_LINUX_REPOSITORY_AWS_REGION: ${{ vars.CONU_LINUX_REPOSITORY_AWS_REGION }}
          CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}
          CONU_LINUX_REPOSITORY_S3_BUCKET: ${{ vars.CONU_LINUX_REPOSITORY_S3_BUCKET }}
          CONU_LINUX_REPOSITORY_S3_PREFIX: ${{ vars.CONU_LINUX_REPOSITORY_S3_PREFIX }}
          CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL: ${{ vars.CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL }}
        run: |
          set -eu
          VERSION="${GITHUB_REF_NAME#v}"
          python scripts/publish-hosted-linux-repository-s3.py linux-repository-site \
            --expected-version "$VERSION" \
            --confirm \
            --post-upload-check \
            --json
  linux-repository-publication:
    needs: [github-release, linux-repository-pages, custom-linux-repository-publish]
    if: always() && startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - name: Check Linux repository publication result
        env:
          CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}
          GITHUB_RELEASE_RESULT: ${{ needs.github-release.result }}
          PAGES_RESULT: ${{ needs.linux-repository-pages.result }}
          CUSTOM_RESULT: ${{ needs.custom-linux-repository-publish.result }}
        run: |
          set -eu
          if [ "$GITHUB_RELEASE_RESULT" != "success" ]; then
            echo "::error::GitHub Release publication did not complete successfully: $GITHUB_RELEASE_RESULT"
            exit 1
          fi
          if [ -z "${CONU_LINUX_REPOSITORY_BASE_URL:-}" ]; then
            if [ "$PAGES_RESULT" != "success" ]; then
              echo "::error::Default Linux repository Pages deployment did not complete successfully: $PAGES_RESULT"
              exit 1
            fi
          else
            if [ "$CUSTOM_RESULT" != "success" ]; then
              echo "::error::Custom Linux repository S3 publication did not complete successfully: $CUSTOM_RESULT"
              exit 1
            fi
          fi
  npm-publish:
    needs: [github-release, linux-repository-publication]
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/setup-node@v6
        with:
          node-version: 24
          registry-url: https://registry.npmjs.org
      - name: Verify npm package contents
        run: python scripts/verify-npm-package-contents.py
      - name: npm package public metadata regression
        run: python scripts/verify-npm-package-contents-regression.py
      - name: GitHub Release asset publication preflight
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-release-assets-published.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"
      - name: npm publish conflict preflight
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: python scripts/check-npm-publish-preflight.py --registry-check --require-token-env NODE_AUTH_TOKEN --token-auth-check
      - name: Publish @conu/cli
        working-directory: packaging/npm/conu-cli
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          if [ -z "${NODE_AUTH_TOKEN:-}" ]; then
            echo "::error::NPM_TOKEN is required for tagged @conu/cli publication."
            exit 1
          fi
          npm publish --access public --provenance
      - name: Publish @conu/sdk
        working-directory: sdk/typescript
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          if [ -z "${NODE_AUTH_TOKEN:-}" ]; then
            echo "::error::NPM_TOKEN is required for tagged @conu/sdk publication."
            exit 1
          fi
          npm publish --access public --provenance
"""


def build_fixture(ci_text: str | None = None, release_text: str | None = None) -> Path:
    root = Path(tempfile.mkdtemp(prefix="conu-workflow-permissions-"))
    write(root / "ci.yml", ci_text if ci_text is not None else ready_ci())
    write(root / "release.yml", release_text if release_text is not None else ready_release())
    return root


def audit(module, workflow_dir: Path):
    return module.audit_workflows(module.find_workflow_paths(workflow_dir))


def assert_safe_report(report) -> dict[str, object]:
    rendered = json.dumps(report.as_json(), sort_keys=True)
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("workflow permissions report leaked workflow contents")
    parsed = json.loads(rendered)
    for field in (
        "payloadDisplayed",
        "tokenDisplayed",
        "tokenHashDisplayed",
        "keyMaterialDisplayed",
        "contentsDisplayed",
    ):
        if parsed.get(field) is not False:
            raise AssertionError(f"expected {field}=false")
    return parsed


def with_fixture(module, ci_text: str | None, release_text: str | None):
    root = build_fixture(ci_text, release_text)
    try:
        return audit(module, root)
    finally:
        shutil.rmtree(root)


def replace_named_step_text(text: str, step_name: str, old: str, new: str) -> str:
    marker = f"      - name: {step_name}\n"
    start = text.index(marker)
    next_start = text.find("\n      - ", start + len(marker))
    if next_start == -1:
        next_start = len(text)
    step = text[start:next_start]
    if old not in step:
        raise AssertionError(f"{step_name} fixture block did not contain expected text")
    return text[:start] + step.replace(old, new, 1) + text[next_start:]


def replace_job_text(text: str, job_name: str, old: str, new: str) -> str:
    marker = f"  {job_name}:\n"
    start = text.index(marker)
    next_start = text.find("\n  ", start + len(marker))
    while next_start != -1:
        next_line_end = text.find("\n", next_start + 1)
        if next_line_end == -1:
            next_line_end = len(text)
        if text[next_start + 1 : next_line_end].startswith("  ") and not text[
            next_start + 1 : next_line_end
        ].startswith("    "):
            break
        next_start = text.find("\n  ", next_line_end)
    if next_start == -1:
        next_start = len(text)
    job = text[start:next_start]
    if old not in job:
        raise AssertionError(f"{job_name} fixture block did not contain expected text")
    return text[:start] + job.replace(old, new, 1) + text[next_start:]


def assert_release_gate_issue(
    module,
    release_text: str,
    expected_issue: str,
    ready_message: str,
) -> None:
    report = with_fixture(module, None, release_text)
    if report.ready:
        raise AssertionError(ready_message)
    if expected_issue not in json.dumps(assert_safe_report(report)):
        raise AssertionError(f"expected issue was not reported: {expected_issue}")


def assert_ci_issue(
    module,
    ci_text: str,
    expected_issue: str,
    ready_message: str,
) -> None:
    report = with_fixture(module, ci_text, None)
    if report.ready:
        raise AssertionError(ready_message)
    if expected_issue not in json.dumps(assert_safe_report(report)):
        raise AssertionError(f"expected issue was not reported: {expected_issue}")


def run_ready_tests(module) -> None:
    report = with_fixture(module, None, None)
    if not report.ready:
        raise AssertionError(f"expected workflow permissions readiness to pass: {report.issues!r}")
    parsed = assert_safe_report(report)
    if parsed["workflowCount"] != 2:
        raise AssertionError("expected two workflows")
    if "release.yml:github-release" not in parsed["jobsWithWritePermissions"]:
        raise AssertionError("expected release write job to be reported")

    yaml_module = module.yaml
    module.yaml = None
    try:
        fallback_report = with_fixture(module, None, None)
    finally:
        module.yaml = yaml_module
    if not fallback_report.ready:
        raise AssertionError(
            f"expected dependency-free workflow parser to pass: {fallback_report.issues!r}"
        )
    assert_safe_report(fallback_report)


def run_top_level_permission_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace("permissions:\n  contents: read\n", ""),
        None,
    )
    if report.ready:
        raise AssertionError("missing top-level permissions should fail")
    if "ci.yml must declare explicit top-level permissions" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing top-level permissions issue was not reported")

    report = with_fixture(
        module,
        ready_ci().replace("permissions:\n  contents: read\n", "permissions: write-all\n"),
        None,
    )
    if report.ready:
        raise AssertionError("top-level permission shorthand should fail")
    if "ci.yml must not use top-level permissions shorthand: write-all" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("top-level shorthand issue was not reported")


def run_forbidden_event_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace("  pull_request:\n", "  pull_request_target:\n"),
        None,
    )
    if report.ready:
        raise AssertionError("pull_request_target should fail")
    if "ci.yml uses forbidden event: pull_request_target" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("forbidden event issue was not reported")


def run_forbidden_workflow_command_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe unverified NPM marker setup\n"
            "        run: python scripts/set-github-release-secrets.py "
            "--set-npm-token-rotation-marker 2026-06-05T01:00:00Z "
            "--allow-unverified-npm-token-rotation-marker "
            "--confirm-npm-token-rotated --dry-run\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if report.ready:
        raise AssertionError("unverified NPM marker workflow override should fail")
    parsed = assert_safe_report(report)
    rendered = json.dumps(parsed)
    if (
        "must not use unverified NPM token rotation marker override: "
        "--allow-unverified-npm-token-rotation-marker"
    ) not in rendered:
        raise AssertionError("unverified NPM marker workflow override was not reported")
    if not parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("forbidden workflow command finding was not listed")

    split_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe split unverified NPM marker setup\n"
            "        run: |\n"
            "          python scripts/set-github-release-secrets.py "
            "--set-npm-token-rotation-marker 2026-06-05T01:00:00Z "
            "--allow-unverified-npm-token-\\\n"
            "            rotation-marker --confirm-npm-token-rotated --dry-run\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if split_report.ready:
        raise AssertionError("split unverified NPM marker workflow override should fail")
    split_parsed = assert_safe_report(split_report)
    split_rendered = json.dumps(split_parsed)
    if (
        "must not use unverified NPM token rotation marker override: "
        "--allow-unverified-npm-token-rotation-marker"
    ) not in split_rendered:
        raise AssertionError(
            "split unverified NPM marker workflow override was not reported"
        )
    if not split_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("split forbidden workflow command finding was not listed")

    marker_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe direct NPM marker variable write\n"
            "        run: gh variable set CONU_NPM_TOKEN_ROTATED_AFTER "
            "--body 2026-06-05T01:00:00Z\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if marker_write_report.ready:
        raise AssertionError("direct NPM marker workflow write should fail")
    marker_write_parsed = assert_safe_report(marker_write_report)
    marker_write_rendered = json.dumps(marker_write_parsed)
    if (
        "must not use direct NPM token rotation marker variable write: "
        "gh variable set CONU_NPM_TOKEN_ROTATED_AFTER"
    ) not in marker_write_rendered:
        raise AssertionError("direct NPM marker workflow write was not reported")
    if not marker_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct marker write finding was not listed")

    dynamic_variable_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe dynamic Actions variable write\n"
            "        run: gh variable set \"$CONU_RELEASE_VAR_NAME\" "
            "--body \"$CONU_RELEASE_VAR_VALUE\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if dynamic_variable_write_report.ready:
        raise AssertionError("dynamic Actions variable workflow write should fail")
    dynamic_variable_write_parsed = assert_safe_report(dynamic_variable_write_report)
    dynamic_variable_write_rendered = json.dumps(dynamic_variable_write_parsed)
    if (
        "must not use direct GitHub Actions variable workflow write: "
        "gh variable set <any-actions-variable>"
    ) not in dynamic_variable_write_rendered:
        raise AssertionError("dynamic Actions variable write was not reported")
    if not dynamic_variable_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("dynamic Actions variable write finding was not listed")

    dynamic_variable_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe dynamic Actions variable delete\n"
            "        run: gh variable delete \"$CONU_RELEASE_VAR_NAME\" --yes\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if dynamic_variable_delete_report.ready:
        raise AssertionError("dynamic Actions variable workflow delete should fail")
    dynamic_variable_delete_parsed = assert_safe_report(dynamic_variable_delete_report)
    dynamic_variable_delete_rendered = json.dumps(dynamic_variable_delete_parsed)
    if (
        "must not use direct GitHub Actions variable workflow delete: "
        "gh variable delete <any-actions-variable>"
    ) not in dynamic_variable_delete_rendered:
        raise AssertionError("dynamic Actions variable delete was not reported")
    if not dynamic_variable_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("dynamic Actions variable delete finding was not listed")

    api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe API NPM marker variable write\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "CONU_NPM_TOKEN_ROTATED_AFTER --method PATCH "
            "-f value=2026-06-05T01:00:00Z\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if api_write_report.ready:
        raise AssertionError("direct NPM marker API workflow write should fail")
    api_write_parsed = assert_safe_report(api_write_report)
    api_write_rendered = json.dumps(api_write_parsed)
    if (
        "must not use direct NPM token rotation marker variable API write: "
        "gh api actions/variables CONU_NPM_TOKEN_ROTATED_AFTER write"
    ) not in api_write_rendered:
        raise AssertionError("direct NPM marker API workflow write was not reported")
    if not api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct marker API write finding was not listed")

    api_equals_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe equals-form API NPM marker variable write\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "CONU_NPM_TOKEN_ROTATED_AFTER --method=PATCH "
            "-F value=2026-06-05T01:00:00Z\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if api_equals_write_report.ready:
        raise AssertionError("equals-form direct NPM marker API write should fail")
    api_equals_write_parsed = assert_safe_report(api_equals_write_report)
    api_equals_write_rendered = json.dumps(api_equals_write_parsed)
    if (
        "must not use direct NPM token rotation marker variable API write: "
        "gh api actions/variables CONU_NPM_TOKEN_ROTATED_AFTER write"
    ) not in api_equals_write_rendered:
        raise AssertionError("equals-form marker API write was not reported")
    if not api_equals_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("equals-form marker API write finding was not listed")

    api_field_equals_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe field equals-form API NPM marker write\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "CONU_NPM_TOKEN_ROTATED_AFTER "
            "--field=value=2026-06-05T01:00:00Z\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if api_field_equals_write_report.ready:
        raise AssertionError("field equals-form NPM marker API write should fail")
    api_field_equals_write_parsed = assert_safe_report(api_field_equals_write_report)
    api_field_equals_write_rendered = json.dumps(api_field_equals_write_parsed)
    if (
        "must not use direct NPM token rotation marker variable API write: "
        "gh api actions/variables CONU_NPM_TOKEN_ROTATED_AFTER write"
    ) not in api_field_equals_write_rendered:
        raise AssertionError("field equals-form marker API write was not reported")
    if not api_field_equals_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("field equals-form marker API write finding was not listed")

    variable_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe direct release variable write\n"
            "        run: gh variable set CONU_LINUX_REPOSITORY_BASE_URL "
            "--body https://example.invalid/conu\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if variable_write_report.ready:
        raise AssertionError("direct release variable workflow write should fail")
    variable_write_parsed = assert_safe_report(variable_write_report)
    variable_write_rendered = json.dumps(variable_write_parsed)
    if (
        "must not use direct release variable workflow write: "
        "gh variable set <release-variable>"
    ) not in variable_write_rendered:
        raise AssertionError("direct release variable workflow write was not reported")
    if not variable_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct release variable write finding was not listed")

    variable_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe direct release variable delete\n"
            "        run: gh variable delete CONU_LINUX_REPOSITORY_BASE_URL --yes\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if variable_delete_report.ready:
        raise AssertionError("direct release variable workflow delete should fail")
    variable_delete_parsed = assert_safe_report(variable_delete_report)
    variable_delete_rendered = json.dumps(variable_delete_parsed)
    if (
        "must not use direct release variable workflow delete: "
        "gh variable delete <release-variable>"
    ) not in variable_delete_rendered:
        raise AssertionError("direct release variable workflow delete was not reported")
    if not variable_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct release variable delete finding was not listed")

    variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe API release variable write\n"
            "        run: gh api --method PATCH repos/$GITHUB_REPOSITORY/"
            "actions/variables/CONU_LINUX_REPOSITORY_BASE_URL "
            "-f value=https://example.invalid/conu\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if variable_api_write_report.ready:
        raise AssertionError("direct release variable API workflow write should fail")
    variable_api_write_parsed = assert_safe_report(variable_api_write_report)
    variable_api_write_rendered = json.dumps(variable_api_write_parsed)
    if (
        "must not use direct release variable workflow API write: "
        "gh api actions/variables <release-variable> write"
    ) not in variable_api_write_rendered:
        raise AssertionError("direct release variable API workflow write was not reported")
    if not variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct release variable API write finding was not listed")

    environment_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe environment API release variable write\n"
            "        run: gh api --method PATCH repos/$GITHUB_REPOSITORY/"
            "environments/prod/variables/CONU_LINUX_REPOSITORY_BASE_URL "
            "-f value=https://example.invalid/conu\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if environment_variable_api_write_report.ready:
        raise AssertionError(
            "environment release variable API workflow write should fail"
        )
    environment_variable_api_write_parsed = assert_safe_report(
        environment_variable_api_write_report
    )
    environment_variable_api_write_rendered = json.dumps(
        environment_variable_api_write_parsed
    )
    if (
        "must not use direct release variable workflow API write: "
        "gh api actions/variables <release-variable> write"
    ) not in environment_variable_api_write_rendered:
        raise AssertionError(
            "environment release variable API workflow write was not reported"
        )
    if not environment_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "environment release variable API write finding was not listed"
        )

    dynamic_variable_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe dynamic API Actions variable delete\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "\"$CONU_RELEASE_VAR_NAME\" --method=DELETE\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if dynamic_variable_api_delete_report.ready:
        raise AssertionError("dynamic Actions variable API delete should fail")
    dynamic_variable_api_delete_parsed = assert_safe_report(
        dynamic_variable_api_delete_report
    )
    dynamic_variable_api_delete_rendered = json.dumps(
        dynamic_variable_api_delete_parsed
    )
    if (
        "must not use direct GitHub Actions variable workflow API write: "
        "gh api actions/variables write"
    ) not in dynamic_variable_api_delete_rendered:
        raise AssertionError("dynamic Actions variable API delete was not reported")
    if not dynamic_variable_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("dynamic Actions variable API delete finding was not listed")

    curl_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe curl Actions variable write\n"
            "        run: |\n"
            "          curl --fail-with-body -X PATCH \\\n"
            "            https://api.github.com/repos/$GITHUB_REPOSITORY/"
            "actions/variables/\"$CONU_RELEASE_VAR_NAME\" \\\n"
            "            -d '{\"name\":\"CONU_LINUX_REPOSITORY_BASE_URL\","
            "\"value\":\"https://example.invalid/conu\"}'\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if curl_variable_api_write_report.ready:
        raise AssertionError("curl Actions variable API write should fail")
    curl_variable_api_write_parsed = assert_safe_report(
        curl_variable_api_write_report
    )
    curl_variable_api_write_rendered = json.dumps(
        curl_variable_api_write_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions variable workflow write: "
        "HTTP actions/variables write"
    ) not in curl_variable_api_write_rendered:
        raise AssertionError("curl Actions variable API write was not reported")
    if not curl_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("curl Actions variable API write finding was not listed")

    curl_environment_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe curl environment Actions variable write\n"
            "        run: |\n"
            "          curl --fail-with-body -X PATCH \\\n"
            "            https://api.github.com/repos/$GITHUB_REPOSITORY/"
            "environments/prod/variables/\"$CONU_RELEASE_VAR_NAME\" \\\n"
            "            -d '{\"value\":\"https://example.invalid/conu\"}'\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if curl_environment_variable_api_write_report.ready:
        raise AssertionError("curl environment Actions variable API write should fail")
    curl_environment_variable_api_write_parsed = assert_safe_report(
        curl_environment_variable_api_write_report
    )
    curl_environment_variable_api_write_rendered = json.dumps(
        curl_environment_variable_api_write_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions variable workflow write: "
        "HTTP actions/variables write"
    ) not in curl_environment_variable_api_write_rendered:
        raise AssertionError(
            "curl environment Actions variable API write was not reported"
        )
    if not curl_environment_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "curl environment Actions variable API write finding was not listed"
        )

    wget_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe wget Actions variable write\n"
            "        run: |\n"
            "          wget --method=PATCH --body-data=value=redacted \\\n"
            "            https://api.github.com/repos/$GITHUB_REPOSITORY/"
            "actions/variables/\"$CONU_RELEASE_VAR_NAME\"\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if wget_variable_api_write_report.ready:
        raise AssertionError("wget Actions variable API write should fail")
    wget_variable_api_write_parsed = assert_safe_report(
        wget_variable_api_write_report
    )
    wget_variable_api_write_rendered = json.dumps(
        wget_variable_api_write_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions variable workflow write: "
        "HTTP actions/variables write"
    ) not in wget_variable_api_write_rendered:
        raise AssertionError("wget Actions variable API write was not reported")
    if not wget_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("wget Actions variable API write finding was not listed")

    httpie_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe HTTPie Actions variable write\n"
            "        run: http PATCH https://api.github.com/repos/"
            "$GITHUB_REPOSITORY/actions/variables/\"$CONU_RELEASE_VAR_NAME\" "
            "value=https://example.invalid/conu\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if httpie_variable_api_write_report.ready:
        raise AssertionError("HTTPie Actions variable API write should fail")
    httpie_variable_api_write_parsed = assert_safe_report(
        httpie_variable_api_write_report
    )
    httpie_variable_api_write_rendered = json.dumps(
        httpie_variable_api_write_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions variable workflow write: "
        "HTTP actions/variables write"
    ) not in httpie_variable_api_write_rendered:
        raise AssertionError("HTTPie Actions variable API write was not reported")
    if not httpie_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("HTTPie Actions variable API write finding was not listed")

    node_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe Node Actions variable write\n"
            "        run: |\n"
            "          node -e \"fetch('https://api.github.com/repos/"
            "owner/repo/actions/variables/CONU_NPM_TOKEN_ROTATED_AFTER', "
            "{method:'PATCH',body:'{}'})\"\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if node_variable_api_write_report.ready:
        raise AssertionError("Node Actions variable API write should fail")
    node_variable_api_write_parsed = assert_safe_report(
        node_variable_api_write_report
    )
    node_variable_api_write_rendered = json.dumps(
        node_variable_api_write_parsed
    )
    if (
        "must not use scripted GitHub Actions variable workflow write: "
        "script actions/variables write"
    ) not in node_variable_api_write_rendered:
        raise AssertionError("Node Actions variable API write was not reported")
    if not node_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("Node Actions variable API write finding was not listed")

    python_block_variable_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe Python block Actions variable write\n"
            "        run: |\n"
            "          python - <<'PY'\n"
            "          import requests\n"
            "          requests.patch('https://api.github.com/repos/"
            "owner/repo/actions/variables/CONU_NPM_TOKEN_ROTATED_AFTER', "
            "json={'value':'2026-06-05T00:00:00Z'})\n"
            "          PY\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if python_block_variable_api_write_report.ready:
        raise AssertionError("Python block Actions variable API write should fail")
    python_block_variable_api_write_parsed = assert_safe_report(
        python_block_variable_api_write_report
    )
    python_block_variable_api_write_rendered = json.dumps(
        python_block_variable_api_write_parsed
    )
    if (
        "literal run block"
        not in python_block_variable_api_write_rendered
        or "must not use scripted GitHub Actions variable workflow write: "
        "script actions/variables write"
        not in python_block_variable_api_write_rendered
    ):
        raise AssertionError("Python block Actions variable API write was not reported")
    if not python_block_variable_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "Python block Actions variable API write finding was not listed"
        )

    pwsh_variable_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe pwsh Actions variable delete\n"
            "        shell: pwsh\n"
            "        run: |\n"
            "          gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "\"$CONU_RELEASE_VAR_NAME\" `\n"
            "            --method=DELETE\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if pwsh_variable_api_delete_report.ready:
        raise AssertionError("pwsh Actions variable API delete should fail")
    pwsh_variable_api_delete_parsed = assert_safe_report(pwsh_variable_api_delete_report)
    pwsh_variable_api_delete_rendered = json.dumps(pwsh_variable_api_delete_parsed)
    if (
        "must not use direct GitHub Actions variable workflow API write: "
        "gh api actions/variables write"
    ) not in pwsh_variable_api_delete_rendered:
        raise AssertionError("pwsh Actions variable API delete was not reported")
    if not pwsh_variable_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("pwsh Actions variable API delete finding was not listed")

    folded_variable_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe folded Actions variable delete\n"
            "        run: >\n"
            "          gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "\"$CONU_RELEASE_VAR_NAME\"\n"
            "          --method=DELETE\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if folded_variable_api_delete_report.ready:
        raise AssertionError("folded Actions variable API delete should fail")
    folded_variable_api_delete_parsed = assert_safe_report(
        folded_variable_api_delete_report
    )
    folded_variable_api_delete_rendered = json.dumps(
        folded_variable_api_delete_parsed
    )
    if (
        "folded run block"
        not in folded_variable_api_delete_rendered
        or "must not use direct GitHub Actions variable workflow API write: "
        "gh api actions/variables write"
        not in folded_variable_api_delete_rendered
    ):
        raise AssertionError("folded Actions variable API delete was not reported")
    if not folded_variable_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("folded Actions variable API delete finding was not listed")

    variable_api_field_equals_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate custom Linux repository publication config\n",
            "      - name: Unsafe field equals-form API release variable write\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/variables/"
            "CONU_LINUX_REPOSITORY_BASE_URL "
            "--raw-field=value=https://example.invalid/conu\n"
            "      - name: Validate custom Linux repository publication config\n",
        ),
    )
    if variable_api_field_equals_write_report.ready:
        raise AssertionError("field equals-form release variable API write should fail")
    variable_api_field_equals_write_parsed = assert_safe_report(
        variable_api_field_equals_write_report
    )
    variable_api_field_equals_write_rendered = json.dumps(
        variable_api_field_equals_write_parsed
    )
    if (
        "must not use direct release variable workflow API write: "
        "gh api actions/variables <release-variable> write"
    ) not in variable_api_field_equals_write_rendered:
        raise AssertionError("field equals-form variable API write was not reported")
    if not variable_api_field_equals_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("field equals-form variable API write finding was not listed")

    secret_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe direct release secret write\n"
            "        run: gh secret set NPM_TOKEN --body \"$NODE_AUTH_TOKEN\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if secret_write_report.ready:
        raise AssertionError("direct release secret workflow write should fail")
    secret_write_parsed = assert_safe_report(secret_write_report)
    secret_write_rendered = json.dumps(secret_write_parsed)
    if (
        "must not use direct release secret workflow write: "
        "gh secret set <release-secret>"
    ) not in secret_write_rendered:
        raise AssertionError("direct release secret workflow write was not reported")
    if not secret_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct release secret write finding was not listed")

    secret_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe direct release secret delete\n"
            "        run: gh secret delete NPM_TOKEN --yes\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if secret_delete_report.ready:
        raise AssertionError("direct release secret workflow delete should fail")
    secret_delete_parsed = assert_safe_report(secret_delete_report)
    secret_delete_rendered = json.dumps(secret_delete_parsed)
    if (
        "must not use direct release secret workflow delete: "
        "gh secret delete <release-secret>"
    ) not in secret_delete_rendered:
        raise AssertionError("direct release secret workflow delete was not reported")
    if not secret_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct release secret delete finding was not listed")

    dynamic_secret_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe dynamic Actions secret write\n"
            "        run: gh secret set \"$CONU_RELEASE_SECRET_NAME\" "
            "--body \"$CONU_RELEASE_SECRET_VALUE\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if dynamic_secret_write_report.ready:
        raise AssertionError("dynamic Actions secret workflow write should fail")
    dynamic_secret_write_parsed = assert_safe_report(dynamic_secret_write_report)
    dynamic_secret_write_rendered = json.dumps(dynamic_secret_write_parsed)
    if (
        "must not use direct GitHub Actions secret workflow write: "
        "gh secret set <any-actions-secret>"
    ) not in dynamic_secret_write_rendered:
        raise AssertionError("dynamic Actions secret write was not reported")
    if not dynamic_secret_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("dynamic Actions secret write finding was not listed")

    dynamic_secret_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe dynamic Actions secret delete\n"
            "        run: gh secret delete \"$CONU_RELEASE_SECRET_NAME\" --yes\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if dynamic_secret_delete_report.ready:
        raise AssertionError("dynamic Actions secret workflow delete should fail")
    dynamic_secret_delete_parsed = assert_safe_report(dynamic_secret_delete_report)
    dynamic_secret_delete_rendered = json.dumps(dynamic_secret_delete_parsed)
    if (
        "must not use direct GitHub Actions secret workflow delete: "
        "gh secret delete <any-actions-secret>"
    ) not in dynamic_secret_delete_rendered:
        raise AssertionError("dynamic Actions secret delete was not reported")
    if not dynamic_secret_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("dynamic Actions secret delete finding was not listed")

    secret_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe API release secret write\n"
            "        run: gh api --method PUT repos/$GITHUB_REPOSITORY/"
            "actions/secrets/NPM_TOKEN -f encrypted_value=redacted "
            "-f key_id=redacted\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if secret_api_write_report.ready:
        raise AssertionError("direct release secret API workflow write should fail")
    secret_api_write_parsed = assert_safe_report(secret_api_write_report)
    secret_api_write_rendered = json.dumps(secret_api_write_parsed)
    if (
        "must not use direct release secret workflow API write: "
        "gh api actions/secrets <release-secret> write"
    ) not in secret_api_write_rendered:
        raise AssertionError("direct release secret API workflow write was not reported")
    if not secret_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("direct release secret API write finding was not listed")

    environment_secret_api_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe environment API release secret write\n"
            "        run: gh api --method PUT repos/$GITHUB_REPOSITORY/"
            "environments/prod/secrets/NPM_TOKEN -f encrypted_value=redacted "
            "-f key_id=redacted\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if environment_secret_api_write_report.ready:
        raise AssertionError("environment release secret API workflow write should fail")
    environment_secret_api_write_parsed = assert_safe_report(
        environment_secret_api_write_report
    )
    environment_secret_api_write_rendered = json.dumps(
        environment_secret_api_write_parsed
    )
    if (
        "must not use direct release secret workflow API write: "
        "gh api actions/secrets <release-secret> write"
    ) not in environment_secret_api_write_rendered:
        raise AssertionError(
            "environment release secret API workflow write was not reported"
        )
    if not environment_secret_api_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "environment release secret API write finding was not listed"
        )

    dynamic_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe dynamic API Actions secret delete\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/secrets/"
            "\"$CONU_RELEASE_SECRET_NAME\" -X DELETE\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if dynamic_secret_api_delete_report.ready:
        raise AssertionError("dynamic Actions secret API delete should fail")
    dynamic_secret_api_delete_parsed = assert_safe_report(
        dynamic_secret_api_delete_report
    )
    dynamic_secret_api_delete_rendered = json.dumps(dynamic_secret_api_delete_parsed)
    if (
        "must not use direct GitHub Actions secret workflow API write: "
        "gh api actions/secrets write"
    ) not in dynamic_secret_api_delete_rendered:
        raise AssertionError("dynamic Actions secret API delete was not reported")
    if not dynamic_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("dynamic Actions secret API delete finding was not listed")

    curl_compact_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe compact curl Actions secret delete\n"
            "        run: curl -XDELETE https://api.github.com/repos/"
            "$GITHUB_REPOSITORY/actions/secrets/\"$CONU_RELEASE_SECRET_NAME\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if curl_compact_secret_api_delete_report.ready:
        raise AssertionError("compact curl Actions secret API delete should fail")
    curl_compact_secret_api_delete_parsed = assert_safe_report(
        curl_compact_secret_api_delete_report
    )
    curl_compact_secret_api_delete_rendered = json.dumps(
        curl_compact_secret_api_delete_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions secret workflow write: "
        "HTTP actions/secrets write"
    ) not in curl_compact_secret_api_delete_rendered:
        raise AssertionError("compact curl Actions secret API delete was not reported")
    if not curl_compact_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "compact curl Actions secret API delete finding was not listed"
        )

    pwsh_http_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe PowerShell HTTP Actions secret delete\n"
            "        shell: pwsh\n"
            "        run: |\n"
            "          Invoke-RestMethod -Method DELETE `\n"
            "            \"https://api.github.com/repos/$env:GITHUB_REPOSITORY/"
            "actions/secrets/$env:CONU_RELEASE_SECRET_NAME\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if pwsh_http_secret_api_delete_report.ready:
        raise AssertionError("PowerShell HTTP Actions secret API delete should fail")
    pwsh_http_secret_api_delete_parsed = assert_safe_report(
        pwsh_http_secret_api_delete_report
    )
    pwsh_http_secret_api_delete_rendered = json.dumps(
        pwsh_http_secret_api_delete_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions secret workflow write: "
        "HTTP actions/secrets write"
    ) not in pwsh_http_secret_api_delete_rendered:
        raise AssertionError("PowerShell HTTP Actions secret API delete was not reported")
    if not pwsh_http_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "PowerShell HTTP Actions secret API delete finding was not listed"
        )

    wget_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe wget Actions secret delete\n"
            "        run: |\n"
            "          wget --method=DELETE \\\n"
            "            https://api.github.com/repos/$GITHUB_REPOSITORY/"
            "actions/secrets/\"$CONU_RELEASE_SECRET_NAME\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if wget_secret_api_delete_report.ready:
        raise AssertionError("wget Actions secret API delete should fail")
    wget_secret_api_delete_parsed = assert_safe_report(
        wget_secret_api_delete_report
    )
    wget_secret_api_delete_rendered = json.dumps(
        wget_secret_api_delete_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions secret workflow write: "
        "HTTP actions/secrets write"
    ) not in wget_secret_api_delete_rendered:
        raise AssertionError("wget Actions secret API delete was not reported")
    if not wget_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("wget Actions secret API delete finding was not listed")

    httpie_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe HTTPie Actions secret delete\n"
            "        run: http DELETE https://api.github.com/repos/"
            "$GITHUB_REPOSITORY/actions/secrets/\"$CONU_RELEASE_SECRET_NAME\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if httpie_secret_api_delete_report.ready:
        raise AssertionError("HTTPie Actions secret API delete should fail")
    httpie_secret_api_delete_parsed = assert_safe_report(
        httpie_secret_api_delete_report
    )
    httpie_secret_api_delete_rendered = json.dumps(
        httpie_secret_api_delete_parsed
    )
    if (
        "must not use direct HTTP GitHub Actions secret workflow write: "
        "HTTP actions/secrets write"
    ) not in httpie_secret_api_delete_rendered:
        raise AssertionError("HTTPie Actions secret API delete was not reported")
    if not httpie_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("HTTPie Actions secret API delete finding was not listed")

    python_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe Python Actions secret delete\n"
            "        run: |\n"
            "          python -c \"import urllib.request; "
            "urllib.request.Request('https://api.github.com/repos/"
            "owner/repo/actions/secrets/NPM_TOKEN', method='DELETE')\"\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if python_secret_api_delete_report.ready:
        raise AssertionError("Python Actions secret API delete should fail")
    python_secret_api_delete_parsed = assert_safe_report(
        python_secret_api_delete_report
    )
    python_secret_api_delete_rendered = json.dumps(
        python_secret_api_delete_parsed
    )
    if (
        "must not use scripted GitHub Actions secret workflow write: "
        "script actions/secrets write"
    ) not in python_secret_api_delete_rendered:
        raise AssertionError("Python Actions secret API delete was not reported")
    if not python_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("Python Actions secret API delete finding was not listed")

    node_block_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe Node block Actions secret delete\n"
            "        run: |\n"
            "          node <<'JS'\n"
            "          fetch('https://api.github.com/repos/"
            "owner/repo/actions/secrets/NPM_TOKEN', { method: 'DELETE' })\n"
            "          JS\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if node_block_secret_api_delete_report.ready:
        raise AssertionError("Node block Actions secret API delete should fail")
    node_block_secret_api_delete_parsed = assert_safe_report(
        node_block_secret_api_delete_report
    )
    node_block_secret_api_delete_rendered = json.dumps(
        node_block_secret_api_delete_parsed
    )
    if (
        "literal run block"
        not in node_block_secret_api_delete_rendered
        or "must not use scripted GitHub Actions secret workflow write: "
        "script actions/secrets write"
        not in node_block_secret_api_delete_rendered
    ):
        raise AssertionError("Node block Actions secret API delete was not reported")
    if not node_block_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError(
            "Node block Actions secret API delete finding was not listed"
        )

    node_block_environment_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe Node block environment Actions secret delete\n"
            "        run: |\n"
            "          node <<'JS'\n"
            "          fetch('https://api.github.com/repos/"
            "owner/repo/environments/prod/secrets/NPM_TOKEN', "
            "{ method: 'DELETE' })\n"
            "          JS\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if node_block_environment_secret_api_delete_report.ready:
        raise AssertionError(
            "Node block environment Actions secret API delete should fail"
        )
    node_block_environment_secret_api_delete_parsed = assert_safe_report(
        node_block_environment_secret_api_delete_report
    )
    node_block_environment_secret_api_delete_rendered = json.dumps(
        node_block_environment_secret_api_delete_parsed
    )
    if (
        "literal run block"
        not in node_block_environment_secret_api_delete_rendered
        or "must not use scripted GitHub Actions secret workflow write: "
        "script actions/secrets write"
        not in node_block_environment_secret_api_delete_rendered
    ):
        raise AssertionError(
            "Node block environment Actions secret API delete was not reported"
        )
    if not node_block_environment_secret_api_delete_parsed[
        "forbiddenWorkflowCommands"
    ]:
        raise AssertionError(
            "Node block environment Actions secret API delete finding was not listed"
        )

    cmd_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe cmd Actions secret delete\n"
            "        shell: cmd\n"
            "        run: |\n"
            "          gh api repos/%GITHUB_REPOSITORY%/actions/secrets/"
            "%CONU_RELEASE_SECRET_NAME% ^\n"
            "            -X DELETE\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if cmd_secret_api_delete_report.ready:
        raise AssertionError("cmd Actions secret API delete should fail")
    cmd_secret_api_delete_parsed = assert_safe_report(cmd_secret_api_delete_report)
    cmd_secret_api_delete_rendered = json.dumps(cmd_secret_api_delete_parsed)
    if (
        "must not use direct GitHub Actions secret workflow API write: "
        "gh api actions/secrets write"
    ) not in cmd_secret_api_delete_rendered:
        raise AssertionError("cmd Actions secret API delete was not reported")
    if not cmd_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("cmd Actions secret API delete finding was not listed")

    folded_secret_api_delete_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe folded Actions secret delete\n"
            "        run: >-\n"
            "          gh api repos/$GITHUB_REPOSITORY/actions/secrets/"
            "\"$CONU_RELEASE_SECRET_NAME\"\n"
            "          -X DELETE\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if folded_secret_api_delete_report.ready:
        raise AssertionError("folded Actions secret API delete should fail")
    folded_secret_api_delete_parsed = assert_safe_report(folded_secret_api_delete_report)
    folded_secret_api_delete_rendered = json.dumps(folded_secret_api_delete_parsed)
    if (
        "folded run block"
        not in folded_secret_api_delete_rendered
        or "must not use direct GitHub Actions secret workflow API write: "
        "gh api actions/secrets write"
        not in folded_secret_api_delete_rendered
    ):
        raise AssertionError("folded Actions secret API delete was not reported")
    if not folded_secret_api_delete_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("folded Actions secret API delete finding was not listed")

    secret_api_field_equals_write_report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate NPM token rotation marker\n",
            "      - name: Unsafe field equals-form API release secret write\n"
            "        run: gh api repos/$GITHUB_REPOSITORY/actions/secrets/NPM_TOKEN "
            "--field=encrypted_value=redacted --field=key_id=redacted\n"
            "      - name: Validate NPM token rotation marker\n",
        ),
    )
    if secret_api_field_equals_write_report.ready:
        raise AssertionError("field equals-form release secret API write should fail")
    secret_api_field_equals_write_parsed = assert_safe_report(
        secret_api_field_equals_write_report
    )
    secret_api_field_equals_write_rendered = json.dumps(
        secret_api_field_equals_write_parsed
    )
    if (
        "must not use direct release secret workflow API write: "
        "gh api actions/secrets <release-secret> write"
    ) not in secret_api_field_equals_write_rendered:
        raise AssertionError("field equals-form secret API write was not reported")
    if not secret_api_field_equals_write_parsed["forbiddenWorkflowCommands"]:
        raise AssertionError("field equals-form secret API write finding was not listed")


def run_checkout_credential_persistence_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace(
            "    steps:\n",
            "    steps:\n"
            "      - uses: actions/checkout@v6\n",
            1,
        ),
        None,
    )
    if report.ready:
        raise AssertionError("checkout without persisted credential guard should fail")
    rendered = json.dumps(assert_safe_report(report))
    if (
        "ci.yml:checkout step at line" not in rendered
        or "must set persist-credentials=false" not in rendered
    ):
        raise AssertionError("checkout persisted credential issue was not reported")


def run_unexpected_job_write_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace(
            "    runs-on: ubuntu-latest\n",
            "    permissions:\n      contents: write\n    runs-on: ubuntu-latest\n",
        ),
        None,
    )
    if report.ready:
        raise AssertionError("unexpected CI write permission should fail")
    rendered = json.dumps(assert_safe_report(report))
    if "ci.yml:packages must not request write permission for contents" not in rendered:
        raise AssertionError("unexpected write issue was not reported")


def run_required_ci_package_checks_job_tests(module) -> None:
    report = with_fixture(
        module,
        ready_ci().replace(
            "          node-version: 24\n",
            "          node-version: 22\n",
            1,
        ),
        None,
    )
    if report.ready:
        raise AssertionError("weakened CI package Node LTS setup should fail")
    if "ci.yml:packages is missing Node version" not in json.dumps(
        assert_safe_report(report)
    ):
        raise AssertionError("weakened CI package Node version was not reported")

    report = with_fixture(
        module,
        ready_ci().replace(
            "        run: python scripts/check-github-workflow-permissions-regression.py\n",
            "        run: echo skipped-workflow-permissions-regression\n",
        ),
        None,
    )
    if report.ready:
        raise AssertionError("missing CI workflow permissions regression should fail")
    if (
        "ci.yml:packages run GitHub workflow permissions regression is "
        "missing workflow permissions regression command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError(
            "missing CI workflow permissions regression was not reported"
        )


def run_required_ci_rust_job_tests(module) -> None:
    assert_ci_issue(
        module,
        replace_job_text(
            ready_ci(),
            "rust",
            "        os: [ubuntu-latest, windows-2025-vs2026, macos-15]\n",
            "        os: [ubuntu-latest, windows-latest, macos-15]\n",
        ),
        "ci.yml:rust is missing Windows runner matrix",
        "weakened CI Rust Windows matrix should fail",
    )

    assert_ci_issue(
        module,
        replace_job_text(
            ready_ci(),
            "rust",
            "          components: rustfmt, clippy\n",
            "          components: rustfmt\n",
        ),
        "ci.yml:rust is missing rustfmt/clippy components",
        "weakened CI Rust toolchain components should fail",
    )

    assert_ci_issue(
        module,
        replace_job_text(
            ready_ci(),
            "rust",
            "        run: cargo clippy --workspace --all-targets -- -D warnings\n",
            "        run: cargo clippy --workspace --all-targets\n",
        ),
        "ci.yml:rust run Rust clippy is missing cargo clippy command",
        "weakened CI Rust clippy command should fail",
    )

    assert_ci_issue(
        module,
        replace_job_text(
            ready_ci(),
            "rust",
            "        run: cargo run -p conu-cli -- doctor --json\n",
            "        run: cargo run -p conu-cli -- --help\n",
        ),
        "ci.yml:rust run doctor smoke is missing doctor smoke command",
        "weakened CI Rust doctor smoke should fail",
    )

    assert_ci_issue(
        module,
        replace_job_text(
            ready_ci(),
            "rust",
            "        if: matrix.os == 'windows-2025-vs2026'\n",
            "        if: matrix.os == 'windows-latest'\n",
        ),
        (
            "ci.yml:rust run Windows production readiness smoke gate "
            "is missing Windows matrix gate"
        ),
        "weakened CI Rust production readiness smoke gate should fail",
    )


def run_expected_job_permission_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace("      id-token: write\n      attestations: write\n", "      id-token: write\n"),
    )
    if report.ready:
        raise AssertionError("missing expected release job permission should fail")
    if "release.yml:build must set attestations=write; found unset" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing expected permission issue was not reported")

    report = with_fixture(
        module,
        None,
        replace_job_text(
            ready_release(),
            "github-release",
            "      contents: write\n",
            "      contents: write\n      actions: read\n",
        ),
    )
    if report.ready:
        raise AssertionError("extra release job permission should fail")
    if "release.yml:github-release has extra permission actions=read" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("extra expected permission issue was not reported")


def run_required_release_preflight_tests(module) -> None:
    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "release-preflight",
            "    runs-on: ubuntu-latest\n",
            "",
        ),
        "release.yml:release-preflight is missing Ubuntu runner",
        "missing release-preflight Ubuntu runner should fail",
    )

    release_preflight_checkout = (
        "      - uses: actions/checkout@v6\n"
        "        if: startsWith(github.ref, 'refs/tags/v')\n"
        "        with:\n"
        "          persist-credentials: false\n"
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "release-preflight",
            release_preflight_checkout,
            "",
        ),
        "release.yml:release-preflight is missing tag-gated checkout action",
        "missing release-preflight checkout should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "release-preflight",
            release_preflight_checkout,
            "      - uses: actions/checkout@v6\n"
            "        with:\n"
            "          persist-credentials: false\n",
        ),
        "release.yml:release-preflight is missing tag-gated checkout action",
        "untagged release-preflight checkout should fail",
    )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate GitHub workflow permissions\n"
            "        if: startsWith(github.ref, 'refs/tags/v')\n"
            "        run: python scripts/check-github-workflow-permissions.py\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing release workflow permissions preflight should fail")
    if (
        "release.yml:release-preflight must validate GitHub workflow permissions"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing release workflow permissions preflight issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '        run: python scripts/check-github-main-protection.py --repo "$GITHUB_REPOSITORY" --require-admin-enforcement\n',
            "        run: echo skipped-main-protection\n",
        ),
    )
    if report.ready:
        raise AssertionError("weakened main branch protection preflight should fail")
    if (
        "release.yml:release-preflight validate GitHub main branch protection "
        "is missing main branch protection command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("weakened main branch protection preflight issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            ' --require-admin-enforcement\n',
            "\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("main branch protection preflight without admin enforcement should fail")
    if (
        "release.yml:release-preflight validate GitHub main branch protection "
        "is missing main branch protection command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError(
            "missing admin enforcement in main branch protection preflight was not reported"
        )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Validate GitHub repository security\n"
            "        if: startsWith(github.ref, 'refs/tags/v')\n",
            "      - name: Validate GitHub repository security\n",
        ),
    )
    if report.ready:
        raise AssertionError("untagged repository security preflight should fail")
    if (
        "release.yml:release-preflight validate GitHub repository security "
        "is missing tag gate"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("untagged repository security preflight issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '        run: python scripts/check-tagged-release-readiness.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME" --ci-only --ci-head "$GITHUB_SHA" --require-default-branch-head\n',
            '        run: python scripts/check-tagged-release-readiness.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"\n',
        ),
    )
    if report.ready:
        raise AssertionError("weakened tag/default-branch release preflight should fail")
    if (
        "release.yml:release-preflight validate tag target CI and release branch "
        "is missing tagged release readiness command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("weakened tag/default-branch preflight issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-npm-publish-preflight.py --registry-check --require-token-env NODE_AUTH_TOKEN --token-auth-check\n",
            "        run: python scripts/check-npm-publish-preflight.py\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing early npm auth/registry preflight should fail")
    if (
        "release.yml:release-preflight validate npm token authentication "
        "and registry availability is missing npm auth/registry command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing early npm auth/registry preflight issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-release-secret-env-preflight.py\n",
            "        run: echo skipped-release-secret-env-preflight\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing tagged release secret preflight should fail")
    if (
        "release.yml:release-preflight check tagged release secrets "
        "is missing release secret env command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing tagged release secret preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-release-secret-rotation-gate.py --secret-name NPM_TOKEN --rotated-after-env CONU_NPM_TOKEN_ROTATED_AFTER --required-after 2026-06-05T00:00:00Z\n",
            "        run: echo skipped-npm-token-rotation-marker\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing NPM token rotation marker preflight should fail")
    if (
        "release.yml:release-preflight validate NPM token rotation marker "
        "is missing rotation marker command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing NPM token rotation marker preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends gnupg openssl\n",
            "        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends gnupg\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing signing preflight OpenSSL install should fail")
    if (
        "release.yml:release-preflight install signing preflight tools is missing "
        "signing preflight tool install command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing signing preflight tool install was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-platform-signing-secrets-preflight.py --require-openssl\n",
            "        run: python scripts/check-platform-signing-secrets-preflight.py\n",
        ),
    )
    if report.ready:
        raise AssertionError("weakened platform signing value preflight should fail")
    if (
        "release.yml:release-preflight validate platform signing secret values "
        "is missing platform signing secret value command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("weakened platform signing value preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-linux-signing-secrets-preflight.py\n",
            "        run: echo skipped-linux-signing-secret-preflight\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing Linux signing secret preflight should fail")
    if (
        "release.yml:release-preflight validate Linux signing secrets "
        "is missing Linux signing secret command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing Linux signing secret preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL == ''\n",
            "        if: startsWith(github.ref, 'refs/tags/v')\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("default Pages preflight without mode gate should fail")
    if (
        "release.yml:release-preflight validate default GitHub Pages "
        "repository settings is missing default repository mode gate"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing default Pages preflight mode gate was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '        run: python scripts/check-github-release-clobber-preflight.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"\n',
            "        run: echo skipped-release-clobber-preflight\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing release clobber preflight should fail")
    if (
        "release.yml:release-preflight validate GitHub Release tag is unpublished "
        "is missing release clobber preflight command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing release clobber preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-custom-linux-repository-publication-preflight.py\n",
            "        run: echo skipped-custom-repository-preflight\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing custom repository publication preflight should fail")
    if (
        "release.yml:release-preflight validate custom Linux repository "
        "publication config is missing custom repository preflight command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing custom repository preflight was not reported")


def run_required_release_job_needs_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "    needs: [packages, production-readiness]\n",
            "    needs: packages\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing production-readiness build gate should fail")
    if "release.yml:build must depend on production-readiness" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing build production-readiness dependency was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "    needs: [github-release, linux-repository-publication]\n",
            "    needs: github-release\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing npm publish repository-publication gate should fail")
    if "release.yml:npm-publish must depend on linux-repository-publication" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing npm publish repository-publication dependency was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "  packages:\n    needs: release-preflight\n",
            "  packages:\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing package preflight dependency should fail")
    if "release.yml:packages must depend on release-preflight" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing package preflight dependency was not reported")


def run_required_package_checks_job_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "          node-version: 24\n",
            "          node-version: 22\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing package checks Node LTS setup should fail")
    if "release.yml:packages is missing Node version" not in json.dumps(
        assert_safe_report(report)
    ):
        raise AssertionError("missing package checks Node version was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm createrepo-c gnupg openssl\n",
            "        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm createrepo-c gnupg\n",
        ),
    )
    if report.ready:
        raise AssertionError("weakened package tool install should fail")
    if (
        "release.yml:packages install package tools is missing "
        "package tool install command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("weakened package tool install was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-production-readiness-toolchain.py\n",
            "        run: echo skipped-production-readiness-toolchain\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing production readiness toolchain regression should fail")
    if (
        "release.yml:packages run production readiness toolchain regression is "
        "missing production readiness toolchain command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError(
            "missing production readiness toolchain regression was not reported"
        )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/check-github-workflow-permissions-regression.py\n",
            "        run: echo skipped-workflow-permissions-regression\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing workflow permissions regression should fail")
    if (
        "release.yml:packages run GitHub workflow permissions regression is "
        "missing workflow permissions regression command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing workflow permissions regression was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/verify-npm-package-contents.py\n",
            "        run: echo skipped-npm-package-content-check\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing npm package content check should fail")
    if (
        "release.yml:packages verify npm package contents is missing "
        "npm package content command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing npm package content check was not reported")


def run_required_production_readiness_job_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "    runs-on: windows-2025-vs2026\n"
            "    steps:\n"
            "      - uses: actions/checkout@v6\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "      - uses: dtolnay/rust-toolchain@stable\n"
            "      - name: Production readiness smoke gate\n"
            "        shell: pwsh\n"
            "        run: ./scripts/verify-production-readiness.ps1 -SmokeOnly\n",
            "    runs-on: windows-2025-vs2026\n"
            "    steps:\n"
            "      - run: echo smoke\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing production readiness smoke gate should fail")
    if (
        "release.yml:production-readiness must run production readiness smoke gate"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing production readiness smoke gate was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        shell: pwsh\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("production readiness smoke gate without pwsh should fail")
    if (
        "release.yml:production-readiness production readiness smoke gate "
        "is missing PowerShell shell"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing production readiness PowerShell shell was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "    runs-on: windows-2025-vs2026\n",
            "    runs-on: ubuntu-latest\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("production readiness smoke gate off Windows should fail")
    if (
        "release.yml:production-readiness is missing Windows runner"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing production readiness Windows runner was not reported")


def run_required_build_job_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "    runs-on: ${{ matrix.os }}\n",
            "    runs-on: ubuntu-latest\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("build job without matrix runner should fail")
    if "release.yml:build is missing matrix runner" not in json.dumps(
        assert_safe_report(report)
    ):
        raise AssertionError("missing build matrix runner was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "          - name: linux-arm64\n",
            "          - name: linux-aarch64\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("build job without Linux arm64 target should fail")
    if "release.yml:build is missing Linux arm64 target" not in json.dumps(
        assert_safe_report(report)
    ):
        raise AssertionError("missing Linux arm64 build target was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: python scripts/verify-release-artifacts.py dist\n",
            "        run: echo skipped-artifact-verifier\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("build job without artifact verifier should fail")
    if (
        "release.yml:build verify release artifact is missing "
        "release artifact verifier command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing build artifact verifier was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        uses: actions/attest@v4.1.0\n",
            "        uses: actions/upload-artifact@v7.0.1\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("build job without artifact attestation should fail")
    if (
        "release.yml:build attest release artifact provenance is missing "
        "artifact attestation action"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing build artifact attestation was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "          subject-path: ${{ matrix.artifact }}\n",
            "          subject-path: dist/*\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("build job without matrix attestation subject should fail")
    if (
        "release.yml:build attest release artifact provenance is missing "
        "attestation subject path"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing matrix attestation subject was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        run: ${{ matrix.script }}\n",
            "        run: echo skipped-matrix-build\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("build job without matrix build command should fail")
    if (
        "release.yml:build build release package is missing matrix build command"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing matrix build command was not reported")


def run_required_github_release_gate_tests(module) -> None:
    assert_release_gate_issue(
        module,
        ready_release().replace(
            "\n    if: startsWith(github.ref, 'refs/tags/v')\n",
            "\n",
            1,
        ),
        "release.yml:github-release is missing tag gate",
        "missing GitHub Release tag gate should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "github-release",
            "      - uses: actions/download-artifact@v8.0.1\n",
            "      - uses: actions/upload-artifact@v7.0.1\n",
        ),
        "release.yml:github-release is missing artifact download action",
        "missing GitHub Release artifact download should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "github-release",
            "          pattern: conu-*\n",
            "",
        ),
        "release.yml:github-release is missing release artifact download pattern",
        "missing GitHub Release artifact download pattern should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "github-release",
            "          digest-mismatch: error\n",
            "",
        ),
        "release.yml:github-release is missing release artifact digest mismatch policy",
        "missing GitHub Release artifact digest mismatch policy should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Verify downloaded release assets",
            "        run: python scripts/verify-release-artifacts.py dist",
            "        run: echo skipped-release-asset-verifier",
        ),
        "release.yml:github-release verify downloaded release assets "
        "is missing release artifact verifier command",
        "downloaded release asset verifier removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Generate package-manager manifests",
            "--build-rpm-packages",
            "--skip-rpm-packages",
        ),
        "release.yml:github-release generate package-manager manifests "
        "is missing RPM package build flag",
        "RPM package generation removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Sign RPM packages",
            "        run: python scripts/sign-rpm-packages.py dist",
            "        run: echo skipped-rpm-signing",
        ),
        "release.yml:github-release sign RPM packages is missing RPM signing command",
        "RPM package signing removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Prepare package-manager submission bundle",
            "--require-linux-signatures",
            "--allow-unsigned-linux-assets",
        ),
        "release.yml:github-release prepare package-manager submission bundle "
        "is missing Linux signature requirement",
        "package-manager submission without Linux signatures should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Sign package-manager submission bundle",
            "        run: python scripts/sign-linux-release-assets.py dist "
            "--only-package-manager-submissions",
            "        run: python scripts/sign-linux-release-assets.py dist",
        ),
        "release.yml:github-release sign package-manager submission bundle "
        "is missing package-manager submission signing command",
        "package-manager submission signing mode removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Generate hosted Linux repositories",
            '          python scripts/generate-hosted-linux-repositories.py dist --output-dir dist --version "$VERSION"',
            "          echo skipped-hosted-repository-generation",
        ),
        "release.yml:github-release generate hosted Linux repositories "
        "is missing hosted repository generation command",
        "hosted repository generation removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Generate hosted Linux repository site",
            '            BASE_URL="https://${GITHUB_REPOSITORY_OWNER}.github.io/${REPO_NAME}"',
            '            BASE_URL="${CONU_LINUX_REPOSITORY_BASE_URL}"',
        ),
        "release.yml:github-release generate hosted Linux repository site "
        "is missing default Pages base URL",
        "default hosted repository site URL fallback removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Generate release update policy",
            "python scripts/generate-release-update-policy.py dist",
            "python scripts/generate-release-update-metadata.py dist",
        ),
        "release.yml:github-release generate release update policy "
        "is missing release update policy generation command",
        "release update policy generation removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Sign release update policy",
            "        run: python scripts/sign-linux-release-assets.py dist --only-update-policies",
            "        run: python scripts/sign-linux-release-assets.py dist",
        ),
        "release.yml:github-release sign release update policy "
        "is missing release update policy signing command",
        "release update policy signing mode removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Prepare hosted Linux repository Pages artifact",
            "        run: python scripts/prepare-hosted-linux-repository-pages.py dist --output-dir linux-repository-site",
            "        run: echo skipped-pages-artifact-prep",
        ),
        "release.yml:github-release prepare hosted Linux repository Pages artifact "
        "is missing Pages artifact preparation command",
        "hosted Linux repository Pages artifact preparation removal should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Upload hosted Linux repository Pages artifact",
            "          retention-days: 14",
            "          retention-days: 1",
        ),
        "release.yml:github-release upload hosted Linux repository Pages artifact "
        "is missing retention period",
        "hosted Linux repository Pages artifact retention weakening should fail",
    )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Re-check GitHub Release tag is unpublished\n"
            "        env:\n"
            "          GH_TOKEN: ${{ github.token }}\n"
            '        run: python scripts/check-github-release-clobber-preflight.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"\n',
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing late GitHub Release clobber preflight should fail")
    if (
        "release.yml:github-release must re-check GitHub Release tag is unpublished"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing late GitHub Release clobber preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Verify local GitHub Release asset set\n"
            "        env:\n"
            "          TAG_NAME: ${{ github.ref_name }}\n"
            '        run: python scripts/check-github-release-assets-published.py --tag "$TAG_NAME" --dist-dir dist\n',
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing local GitHub Release asset-set preflight should fail")
    if (
        "release.yml:github-release must verify local GitHub Release asset set"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing local GitHub Release asset-set preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '        run: python scripts/check-github-release-assets-published.py --tag "$TAG_NAME" --dist-dir dist\n',
            "        run: echo skipped-local-asset-check\n",
        ),
    )
    if report.ready:
        raise AssertionError("weakened local GitHub Release asset-set preflight should fail")
    if (
        "release.yml:github-release verify local GitHub Release asset set "
        "is missing local release asset preflight command"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("weakened local GitHub Release asset-set preflight was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '          gh release create "$TAG_NAME" dist/* --verify-tag --title "conU $TAG_NAME" --notes-file release-notes.md\n',
            '          gh release create "$TAG_NAME" dist/* --title "conU $TAG_NAME" --notes-file release-notes.md\n',
        ),
    )
    if report.ready:
        raise AssertionError("GitHub Release creation without --verify-tag should fail")
    if (
        "release.yml:github-release publish release assets without clobber "
        "is missing release create command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing GitHub Release --verify-tag issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '          gh release create "$TAG_NAME" dist/* --verify-tag --title "conU $TAG_NAME" --notes-file release-notes.md\n',
            '          gh release create "$TAG_NAME" dist/* --verify-tag --title "conU $TAG_NAME" --notes-file release-notes.md --clobber\n',
        ),
    )
    if report.ready:
        raise AssertionError("GitHub Release clobber publication should fail")
    if (
        "release.yml:github-release publish release assets must not use "
        "gh release upload/create clobber"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("GitHub Release clobber issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '          cargo run -p conu-cli -- update apply --policy-url "$POLICY_URL" --artifact-file "$DOWNLOAD_DIR/conu-${VERSION}-linux-x64.tar.gz" --install-dir "$APPLY_INSTALL_DIR" --target linux-x64 --gpg-verify --dry-run --json\n',
            '          cargo run -p conu-cli -- update apply --policy-url "$POLICY_URL" --artifact-file "$DOWNLOAD_DIR/conu-${VERSION}-linux-x64.tar.gz" --install-dir "$APPLY_INSTALL_DIR" --target linux-x64 --gpg-verify --json\n',
        ),
    )
    if report.ready:
        raise AssertionError("published update apply without dry-run should fail")
    if (
        "release.yml:github-release verify published release update policy "
        "and artifact with CLI is missing update apply dry-run command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing published update apply dry-run issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '          if [ "$ACTUAL_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]; then\n',
            '          if [ "$ACTUAL_FINGERPRINT" = "$EXPECTED_FINGERPRINT" ]; then\n',
        ),
    )
    if report.ready:
        raise AssertionError("missing published GPG fingerprint mismatch gate should fail")
    if (
        "release.yml:github-release verify published release update policy "
        "and artifact with CLI is missing fingerprint comparison"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing published GPG fingerprint comparison was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '            echo "::error::Published Linux GPG public key fingerprint mismatch"\n',
            (
                '            echo "::error::Published Linux GPG public key fingerprint '
                'mismatch: expected $EXPECTED_FINGERPRINT, found $ACTUAL_FINGERPRINT"\n'
            ),
        ),
    )
    if report.ready:
        raise AssertionError("value-bearing published GPG fingerprint mismatch output should fail")
    if (
        "release.yml:github-release verify published release update policy "
        "and artifact with CLI is missing redacted fingerprint mismatch error"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("value-bearing published GPG fingerprint output was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '          (cd "$KEY_DIR" && sha256sum -c conu-linux-gpg-key.asc.sha256)\n',
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing published GPG public-key checksum verification should fail")
    if (
        "release.yml:github-release verify published release update policy "
        "and artifact with CLI is missing public key checksum verification"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError(
            "missing published GPG public-key checksum verification was not reported"
        )


def run_required_unsigned_preview_release_gate_tests(module) -> None:
    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "manual-preview-release",
            "    if: github.event_name == 'workflow_dispatch' && inputs.publish_preview_release == 'true'\n",
            "",
        ),
        "release.yml:manual-preview-release is missing manual preview dispatch gate",
        "missing unsigned preview dispatch gate should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "manual-preview-release",
            "          pattern: conu-*\n",
            "",
        ),
        "release.yml:manual-preview-release is missing release artifact download pattern",
        "missing unsigned preview artifact pattern should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Check unsigned preview asset set before publication",
            "python scripts/check-unsigned-preview-release-assets.py --dist-dir dist --json",
            "echo skipped-preview-asset-check",
        ),
        "release.yml:manual-preview-release check unsigned preview asset set "
        "before publication is missing preview asset checker command",
        "missing unsigned preview local asset check should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Publish unsigned preview prerelease",
            'gh release view "$PREVIEW_TAG"',
            'echo "skip existing preview guard"',
        ),
        "release.yml:manual-preview-release publish unsigned preview prerelease "
        "without clobber is missing existing preview guard",
        "missing unsigned preview clobber guard should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Publish unsigned preview prerelease",
            "--prerelease",
            "",
        ),
        "release.yml:manual-preview-release publish unsigned preview prerelease "
        "without clobber is missing preview release create command",
        "missing unsigned preview prerelease flag should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Publish unsigned preview prerelease",
            "--notes-file release-notes.md",
            "--notes-file release-notes.md --clobber",
        ),
        "release.yml:manual-preview-release publish unsigned preview "
        "prerelease must not use gh release upload/create clobber",
        "unsigned preview clobber use should fail",
    )

    assert_release_gate_issue(
        module,
        replace_named_step_text(
            ready_release(),
            "Verify published unsigned preview prerelease",
            'python scripts/check-unsigned-preview-release-assets.py --repo "$GH_REPO" --tag "$PREVIEW_TAG" --json',
            "echo skipped-published-preview-check",
        ),
        "release.yml:manual-preview-release verify published unsigned preview "
        "prerelease is missing published preview asset checker command",
        "missing unsigned preview published asset check should fail",
    )


def run_required_linux_repository_publication_job_tests(module) -> None:
    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "linux-repository-pages",
            "    runs-on: ubuntu-latest\n",
            "",
        ),
        "release.yml:linux-repository-pages is missing Ubuntu runner",
        "missing Linux repository Pages Ubuntu runner should fail",
    )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "\n    if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL == ''\n",
            "\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing default Pages repository gate should fail")
    if (
        "release.yml:linux-repository-pages is missing default repository "
        "tag/base URL gate"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing default Pages repository gate was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - id: deployment\n"
            "        uses: actions/deploy-pages@v5\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing Pages deploy action should fail")
    if (
        "release.yml:linux-repository-pages is missing deploy Pages action"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing Pages deploy action was not reported")

    report = with_fixture(
        module,
        None,
        replace_job_text(
            ready_release(),
            "linux-repository-pages",
            "          digest-mismatch: error\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing Pages artifact digest mismatch policy should fail")
    if (
        "release.yml:linux-repository-pages is missing hosted repository "
        "artifact digest mismatch policy"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError(
            "missing Pages artifact digest mismatch policy was not reported"
        )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "custom-linux-repository-publish",
            "    runs-on: ubuntu-latest\n",
            "",
        ),
        "release.yml:custom-linux-repository-publish is missing Ubuntu runner",
        "missing custom Linux repository publication Ubuntu runner should fail",
    )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "\n    if: startsWith(github.ref, 'refs/tags/v') && vars.CONU_LINUX_REPOSITORY_BASE_URL != ''\n",
            "\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing custom repository gate should fail")
    if (
        "release.yml:custom-linux-repository-publish is missing custom "
        "repository tag/base URL gate"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing custom repository gate was not reported")

    report = with_fixture(
        module,
        None,
        replace_job_text(
            ready_release(),
            "custom-linux-repository-publish",
            "          digest-mismatch: error\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing custom artifact digest mismatch policy should fail")
    if (
        "release.yml:custom-linux-repository-publish is missing hosted "
        "repository artifact digest mismatch policy"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError(
            "missing custom artifact digest mismatch policy was not reported"
        )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Publish custom hosted Linux repository and verify endpoint\n",
            "      - name: Publish custom hosted Linux repository\n",
        ),
    )
    if report.ready:
        raise AssertionError("renamed custom publish/verify step should fail")
    if (
        "release.yml:custom-linux-repository-publish must publish custom "
        "hosted Linux repository and verify endpoint"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing custom publish/verify step was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            " --post-upload-check ",
            " ",
        ),
    )
    if report.ready:
        raise AssertionError("missing custom repository post-upload check should fail")
    if (
        "release.yml:custom-linux-repository-publish publish custom hosted "
        "Linux repository and verify endpoint is missing post-upload live endpoint check"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing custom repository post-upload check was not reported")


def run_required_npm_publication_gate_tests(module) -> None:
    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "npm-publish",
            "    runs-on: ubuntu-latest\n",
            "",
        ),
        "release.yml:npm-publish is missing Ubuntu runner",
        "missing npm-publish Ubuntu runner should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "npm-publish",
            "      contents: read\n      id-token: write\n",
            "      contents: read\n",
        ),
        "release.yml:npm-publish is missing provenance id-token permission",
        "missing npm-publish provenance id-token permission should fail",
    )

    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "npm-publish",
            "      - uses: actions/checkout@v6\n"
            "        with:\n"
            "          persist-credentials: false\n",
            "",
        ),
        "release.yml:npm-publish is missing checkout action",
        "missing npm-publish checkout should fail",
    )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "  npm-publish:\n"
            "    needs: [github-release, linux-repository-publication]\n"
            "    if: startsWith(github.ref, 'refs/tags/v')\n",
            "  npm-publish:\n"
            "    needs: [github-release, linux-repository-publication]\n",
        ),
    )
    if report.ready:
        raise AssertionError("missing npm-publish tag gate should fail")
    if "release.yml:npm-publish is missing tag gate" not in json.dumps(
        assert_safe_report(report)
    ):
        raise AssertionError("missing npm-publish tag gate issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '        run: python scripts/check-github-release-assets-published.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"\n',
            "        run: echo skipped-release-asset-check\n",
        ),
    )
    if report.ready:
        raise AssertionError("weakened npm release asset preflight should fail")
    if (
        "release.yml:npm-publish verify GitHub Release asset publication "
        "before npm is missing GitHub Release asset preflight command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("weakened npm release asset preflight issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "          npm publish --access public --provenance\n",
            "          npm publish --access public\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("missing @conu/cli npm provenance should fail")
    if (
        "release.yml:npm-publish publish @conu/cli with provenance "
        "is missing provenance publish command"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing @conu/cli provenance issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "        working-directory: sdk/typescript\n",
            "        working-directory: sdk\n",
        ),
    )
    if report.ready:
        raise AssertionError("wrong @conu/sdk package directory should fail")
    if (
        "release.yml:npm-publish publish @conu/sdk with provenance "
        "is missing SDK package directory"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("wrong @conu/sdk package directory issue was not reported")


def run_required_release_publication_gate_tests(module) -> None:
    assert_release_gate_issue(
        module,
        replace_job_text(
            ready_release(),
            "linux-repository-publication",
            "    runs-on: ubuntu-latest\n",
            "",
        ),
        "release.yml:linux-repository-publication is missing Ubuntu runner",
        "missing Linux repository publication Ubuntu runner should fail",
    )

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "    if: always() && startsWith(github.ref, 'refs/tags/v')\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing Linux repository publication always/tag gate should fail")
    if (
        "release.yml:linux-repository-publication must be tag-gated "
        "and always evaluate upstream results"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("missing Linux repository always/tag gate issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "          PAGES_RESULT: ${{ needs.linux-repository-pages.result }}\n",
            "",
        ),
    )
    if report.ready:
        raise AssertionError("missing Pages result env should fail")
    if (
        "release.yml:linux-repository-publication gate is missing Pages result"
        not in json.dumps(assert_safe_report(report))
    ):
        raise AssertionError("missing Pages result issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '            if [ "$CUSTOM_RESULT" != "success" ]; then\n',
            '            if [ "$CUSTOM_RESULT" != "failure" ]; then\n',
        ),
    )
    if report.ready:
        raise AssertionError("weakened custom repository result check should fail")
    if (
        "release.yml:linux-repository-publication gate is missing "
        "custom repository success check"
    ) not in json.dumps(assert_safe_report(report)):
        raise AssertionError("weakened custom repository result check issue was not reported")


def run_unsafe_environment_file_write_tests(module) -> None:
    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Verify release artifact\n",
            "      - name: Unsafe env write\n"
            "        run: |\n"
            "          {\n"
            "            echo \"CONU_MACOS_CODESIGN_IDENTITY=$MACOS_CODESIGN_IDENTITY\"\n"
            "          } >> \"$GITHUB_ENV\"\n"
            "      - name: Verify release artifact\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("unsafe GITHUB_ENV secret-derived echo should fail")
    parsed = assert_safe_report(report)
    rendered = json.dumps(parsed)
    if "echoes secret-derived MACOS_CODESIGN_IDENTITY directly to GITHUB_ENV" not in rendered:
        raise AssertionError("unsafe GITHUB_ENV write issue was not reported")
    if not parsed["unsafeEnvironmentFileWrites"]:
        raise AssertionError("unsafe GITHUB_ENV write finding was not listed")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Verify release artifact\n",
            "      - name: Unsafe printf env write\n"
            "        run: |\n"
            "          printf 'CONU_MACOS_CODESIGN_IDENTITY=%s\\n' "
            "\"$MACOS_CODESIGN_IDENTITY\" >> \"$GITHUB_ENV\"\n"
            "      - name: Verify release artifact\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("unsafe GITHUB_ENV secret-derived printf should fail")
    rendered = json.dumps(assert_safe_report(report))
    if (
        "writes secret-derived MACOS_CODESIGN_IDENTITY directly to GITHUB_ENV"
        not in rendered
    ):
        raise AssertionError("unsafe GITHUB_ENV printf write issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            "      - name: Verify release artifact\n",
            "      - name: Unsafe heredoc env write\n"
            "        run: |\n"
            "          cat <<EOF >> \"$GITHUB_ENV\"\n"
            "          NODE_AUTH_TOKEN=$NODE_AUTH_TOKEN\n"
            "          EOF\n"
            "      - name: Verify release artifact\n",
            1,
        ),
    )
    if report.ready:
        raise AssertionError("unsafe GITHUB_ENV secret-derived heredoc should fail")
    rendered = json.dumps(assert_safe_report(report))
    if "writes secret-derived NODE_AUTH_TOKEN directly to GITHUB_ENV" not in rendered:
        raise AssertionError("unsafe GITHUB_ENV heredoc write issue was not reported")

    report = with_fixture(
        module,
        None,
        ready_release().replace(
            '          append_github_env CONU_MACOS_NOTARY_KEYCHAIN_PROFILE "conu-notary-profile"\n',
            '          append_github_env CONU_MACOS_NOTARY_KEYCHAIN_PROFILE "conu-notary-profile"\n'
            '          append_github_env NODE_AUTH_TOKEN "$NODE_AUTH_TOKEN"\n',
            1,
        ),
    )
    if report.ready:
        raise AssertionError("extra secret-like append_github_env call should fail")
    rendered = json.dumps(assert_safe_report(report))
    if (
        "uses unapproved append_github_env helper call for secret-like NODE_AUTH_TOKEN"
        not in rendered
    ):
        raise AssertionError("extra append_github_env helper call issue was not reported")


def main() -> int:
    module = load_module()
    run_ready_tests(module)
    run_top_level_permission_tests(module)
    run_forbidden_event_tests(module)
    run_forbidden_workflow_command_tests(module)
    run_checkout_credential_persistence_tests(module)
    run_unexpected_job_write_tests(module)
    run_required_ci_package_checks_job_tests(module)
    run_required_ci_rust_job_tests(module)
    run_expected_job_permission_tests(module)
    run_required_release_preflight_tests(module)
    run_required_release_job_needs_tests(module)
    run_required_package_checks_job_tests(module)
    run_required_production_readiness_job_tests(module)
    run_required_build_job_tests(module)
    run_required_unsigned_preview_release_gate_tests(module)
    run_required_github_release_gate_tests(module)
    run_required_linux_repository_publication_job_tests(module)
    run_required_npm_publication_gate_tests(module)
    run_required_release_publication_gate_tests(module)
    run_unsafe_environment_file_write_tests(module)
    print("GitHub workflow permissions regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
