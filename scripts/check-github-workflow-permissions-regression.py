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
    return f"""
name: CI
on:
  push:
    branches: ["main"]
  pull_request:
permissions:
  contents: read
jobs:
  packages:
    runs-on: ubuntu-latest
    steps:
      - run: echo {SENSITIVE_SENTINEL}
"""


def ready_release() -> str:
    return """
name: Release Artifacts
on:
  push:
    tags:
      - "v*"
  workflow_dispatch:
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
        run: python scripts/check-github-main-protection.py --repo "$GITHUB_REPOSITORY"
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
      - uses: actions/setup-node@v6
        with:
          node-version: 24
          registry-url: https://registry.npmjs.org
      - name: Install package tools
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm createrepo-c gnupg openssl
      - name: Python script compile
        run: python scripts/check-python-script-compile.py
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
  github-release:
    needs: build
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - name: Re-check GitHub Release tag is unpublished
        env:
          GH_TOKEN: ${{ github.token }}
        run: python scripts/check-github-release-clobber-preflight.py --repo "$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"
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
      - uses: actions/download-artifact@v8.0.1
        with:
          name: conu-hosted-linux-repository-pages
          path: linux-repository-site
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
        ready_release().replace("      contents: write\n    runs-on", "      contents: write\n      actions: read\n    runs-on"),
    )
    if report.ready:
        raise AssertionError("extra release job permission should fail")
    if "release.yml:github-release has extra permission actions=read" not in json.dumps(assert_safe_report(report)):
        raise AssertionError("extra expected permission issue was not reported")


def run_required_release_preflight_tests(module) -> None:
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
            '        run: python scripts/check-github-main-protection.py --repo "$GITHUB_REPOSITORY"\n',
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


def run_required_linux_repository_publication_job_tests(module) -> None:
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


def main() -> int:
    module = load_module()
    run_ready_tests(module)
    run_top_level_permission_tests(module)
    run_forbidden_event_tests(module)
    run_unexpected_job_write_tests(module)
    run_expected_job_permission_tests(module)
    run_required_release_preflight_tests(module)
    run_required_release_job_needs_tests(module)
    run_required_package_checks_job_tests(module)
    run_required_production_readiness_job_tests(module)
    run_required_build_job_tests(module)
    run_required_github_release_gate_tests(module)
    run_required_linux_repository_publication_job_tests(module)
    run_required_npm_publication_gate_tests(module)
    run_required_release_publication_gate_tests(module)
    run_unsafe_environment_file_write_tests(module)
    print("GitHub workflow permissions regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
