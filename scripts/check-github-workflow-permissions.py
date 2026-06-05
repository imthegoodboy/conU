#!/usr/bin/env python3
"""Audit GitHub workflow permissions for production release hygiene."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by dependency-free runners.
    yaml = None  # type: ignore[assignment]


DEFAULT_WORKFLOW_DIR = Path(".github/workflows")
FORBIDDEN_EVENTS = ("pull_request_target", "workflow_run")
NPM_TOKEN_ROTATION_MARKER_VAR = "CONU_NPM_TOKEN_ROTATED_AFTER"
RELEASE_SECRET_WRITE_GUARD_NAMES: tuple[str, ...] = (
    "CONU_WINDOWS_SIGN_CERT_PFX_BASE64",
    "CONU_WINDOWS_SIGN_CERT_PASSWORD",
    "CONU_WINDOWS_TIMESTAMP_URL",
    "CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64",
    "CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD",
    "CONU_MACOS_CODESIGN_IDENTITY",
    "CONU_MACOS_NOTARY_APPLE_ID",
    "CONU_MACOS_NOTARY_TEAM_ID",
    "CONU_MACOS_NOTARY_PASSWORD",
    "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
    "CONU_LINUX_GPG_PASSPHRASE",
    "CONU_LINUX_GPG_KEY_ID",
    "CONU_LINUX_GPG_KEY_FINGERPRINT",
    "CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID",
    "CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY",
    "CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN",
    "NPM_TOKEN",
)
RELEASE_SECRET_WRITE_GUARD_PATTERN = "|".join(
    re.escape(name) for name in RELEASE_SECRET_WRITE_GUARD_NAMES
)
RELEASE_VARIABLE_WRITE_GUARD_NAMES: tuple[str, ...] = (
    "CONU_LINUX_REPOSITORY_BASE_URL",
    "CONU_LINUX_REPOSITORY_S3_BUCKET",
    "CONU_LINUX_REPOSITORY_S3_PREFIX",
    "CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL",
    "CONU_LINUX_REPOSITORY_AWS_REGION",
)
RELEASE_VARIABLE_WRITE_GUARD_PATTERN = "|".join(
    re.escape(name) for name in RELEASE_VARIABLE_WRITE_GUARD_NAMES
)
ACTIONS_VARIABLE_ENDPOINT_PATTERN = (
    r"(?:\bactions/variables\b|\benvironments/[^\s/;&|\"']+/variables\b)"
)
ACTIONS_SECRET_ENDPOINT_PATTERN = (
    r"(?:\bactions/secrets\b|\benvironments/[^\s/;&|\"']+/secrets\b)"
)
API_VARIABLE_FIELD_WRITE_PATTERN = (
    r"\s(?:(?:-f|-F)(?:\s+|=)?|(?:--field|--raw-field)(?:\s+|=))"
    r"(?:name|value)="
)
API_SECRET_FIELD_WRITE_PATTERN = (
    r"\s(?:(?:-f|-F)(?:\s+|=)?|(?:--field|--raw-field)(?:\s+|=))"
    r"(?:encrypted_value|key_id|secret_name)="
)
API_MUTATION_METHOD_PATTERN = (
    r"\s(?:--method|-X)(?:\s+|=)(?:POST|PUT|PATCH|DELETE)\b"
)
HTTP_MUTATION_METHOD_PATTERN = (
    r"\s(?:(?:-X)(?:\s+|=)?|(?:--request|--method|-Method)(?:\s+|=))"
    r"(?:POST|PUT|PATCH|DELETE)\b"
)
HTTPIE_MUTATION_METHOD_PATTERN = (
    r"\b(?:http(?:\.exe)?|https(?:\.exe)?)\s+"
    r"(?:POST|PUT|PATCH|DELETE)\b"
)
HTTP_BODY_WRITE_PATTERN = (
    r"\s(?:-d|--data|--data-raw|--data-binary|--data-urlencode|"
    r"--json|--form|--body-data|--body-file|--post-data|--post-file|"
    r"-Body)(?:\s+|=)"
)
HTTP_MUTATION_SIGNAL_PATTERN = (
    rf"(?:{HTTP_MUTATION_METHOD_PATTERN}|{HTTP_BODY_WRITE_PATTERN})"
)
HTTP_CLIENT_PATTERN = (
    r"\b(?:curl(?:\.exe)?|wget(?:\.exe)?|Invoke-RestMethod|"
    r"Invoke-WebRequest|irm|iwr)\b"
)
SCRIPT_CLIENT_PATTERN = (
    r"\b(?:python(?:3)?|py(?:\.exe)?|node(?:\.exe)?|deno(?:\.exe)?|"
    r"bun(?:\.exe)?)\b"
)
SCRIPT_COMMAND_SPAN_PATTERN = r"[^\n]*"
SCRIPT_BLOCK_SPAN_PATTERN = r"[\s\S]*"
SCRIPT_MUTATION_SIGNAL_PATTERN = (
    r"(?:"
    r"\brequests\.(?:post|put|patch|delete)\s*\("
    r"|(?:\bfetch\s*\(|\burllib\.request\.Request\s*\(|\bRequest\s*\()"
    rf"{SCRIPT_COMMAND_SPAN_PATTERN}\bmethod\s*[:=]\s*['\"]?"
    r"(?:POST|PUT|PATCH|DELETE)\b"
    r"|\bmethod\s*[:=]\s*['\"]?(?:POST|PUT|PATCH|DELETE)\b"
    r")"
)
SCRIPT_BLOCK_MUTATION_SIGNAL_PATTERN = (
    r"(?:"
    r"\brequests\.(?:post|put|patch|delete)\s*\("
    r"|(?:\bfetch\s*\(|\burllib\.request\.Request\s*\(|\bRequest\s*\()"
    rf"{SCRIPT_BLOCK_SPAN_PATTERN}\bmethod\s*[:=]\s*['\"]?"
    r"(?:POST|PUT|PATCH|DELETE)\b"
    r"|\bmethod\s*[:=]\s*['\"]?(?:POST|PUT|PATCH|DELETE)\b"
    r")"
)
FORBIDDEN_WORKFLOW_COMMAND_FRAGMENTS: tuple[tuple[str, str], ...] = (
    (
        "--allow-unverified-npm-token-rotation-marker",
        "unverified NPM token rotation marker override",
    ),
)
FORBIDDEN_WORKFLOW_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "gh variable set <any-actions-variable>",
        re.compile(r"\bgh\s+variable\s+set\b"),
        "direct GitHub Actions variable workflow write",
    ),
    (
        "gh variable delete <any-actions-variable>",
        re.compile(r"\bgh\s+variable\s+delete\b"),
        "direct GitHub Actions variable workflow delete",
    ),
    (
        "gh api actions/variables write",
        re.compile(
            rf"\bgh\s+api\b"
            rf"(?=[^\n;&|]*{ACTIONS_VARIABLE_ENDPOINT_PATTERN})"
            rf"(?=[^\n;&|]*(?:{API_MUTATION_METHOD_PATTERN}|"
            rf"{API_VARIABLE_FIELD_WRITE_PATTERN}))",
            re.IGNORECASE,
        ),
        "direct GitHub Actions variable workflow API write",
    ),
    (
        "HTTP actions/variables write",
        re.compile(
            rf"(?:{HTTP_CLIENT_PATTERN}"
            rf"(?=[^\n;&|]*{HTTP_MUTATION_SIGNAL_PATTERN})|"
            rf"{HTTPIE_MUTATION_METHOD_PATTERN})"
            rf"(?=[^\n;&|]*{ACTIONS_VARIABLE_ENDPOINT_PATTERN})",
            re.IGNORECASE,
        ),
        "direct HTTP GitHub Actions variable workflow write",
    ),
    (
        "script actions/variables write",
        re.compile(
            rf"{SCRIPT_CLIENT_PATTERN}"
            rf"(?={SCRIPT_COMMAND_SPAN_PATTERN}{ACTIONS_VARIABLE_ENDPOINT_PATTERN})"
            rf"(?={SCRIPT_COMMAND_SPAN_PATTERN}{SCRIPT_MUTATION_SIGNAL_PATTERN})",
            re.IGNORECASE,
        ),
        "scripted GitHub Actions variable workflow write",
    ),
    (
        "gh secret set <any-actions-secret>",
        re.compile(r"\bgh\s+secret\s+set\b"),
        "direct GitHub Actions secret workflow write",
    ),
    (
        "gh secret delete <any-actions-secret>",
        re.compile(r"\bgh\s+secret\s+delete\b"),
        "direct GitHub Actions secret workflow delete",
    ),
    (
        "gh api actions/secrets write",
        re.compile(
            rf"\bgh\s+api\b"
            rf"(?=[^\n;&|]*{ACTIONS_SECRET_ENDPOINT_PATTERN})"
            rf"(?=[^\n;&|]*(?:{API_MUTATION_METHOD_PATTERN}|"
            rf"{API_SECRET_FIELD_WRITE_PATTERN}))",
            re.IGNORECASE,
        ),
        "direct GitHub Actions secret workflow API write",
    ),
    (
        "HTTP actions/secrets write",
        re.compile(
            rf"(?:{HTTP_CLIENT_PATTERN}"
            rf"(?=[^\n;&|]*{HTTP_MUTATION_SIGNAL_PATTERN})|"
            rf"{HTTPIE_MUTATION_METHOD_PATTERN})"
            rf"(?=[^\n;&|]*{ACTIONS_SECRET_ENDPOINT_PATTERN})",
            re.IGNORECASE,
        ),
        "direct HTTP GitHub Actions secret workflow write",
    ),
    (
        "script actions/secrets write",
        re.compile(
            rf"{SCRIPT_CLIENT_PATTERN}"
            rf"(?={SCRIPT_COMMAND_SPAN_PATTERN}{ACTIONS_SECRET_ENDPOINT_PATTERN})"
            rf"(?={SCRIPT_COMMAND_SPAN_PATTERN}{SCRIPT_MUTATION_SIGNAL_PATTERN})",
            re.IGNORECASE,
        ),
        "scripted GitHub Actions secret workflow write",
    ),
    (
        f"gh variable set {NPM_TOKEN_ROTATION_MARKER_VAR}",
        re.compile(
            rf"\bgh\s+variable\s+set\b[^\n;&|]*\b{NPM_TOKEN_ROTATION_MARKER_VAR}\b"
        ),
        "direct NPM token rotation marker variable write",
    ),
    (
        f"gh api actions/variables {NPM_TOKEN_ROTATION_MARKER_VAR} write",
        re.compile(
            rf"\bgh\s+api\b"
            rf"(?=[^\n;&|]*{ACTIONS_VARIABLE_ENDPOINT_PATTERN})"
            rf"(?=[^\n;&|]*\b{NPM_TOKEN_ROTATION_MARKER_VAR}\b)"
            rf"(?=[^\n;&|]*(?:\b(?:--method|-X)(?:\s+|=)"
            rf"(?:POST|PUT|PATCH)\b|"
            rf"{API_VARIABLE_FIELD_WRITE_PATTERN}))",
            re.IGNORECASE,
        ),
        "direct NPM token rotation marker variable API write",
    ),
    (
        "gh variable set <release-variable>",
        re.compile(
            rf"\bgh\s+variable\s+set\b[^\n;&|]*\b"
            rf"(?:{RELEASE_VARIABLE_WRITE_GUARD_PATTERN})\b"
        ),
        "direct release variable workflow write",
    ),
    (
        "gh variable delete <release-variable>",
        re.compile(
            rf"\bgh\s+variable\s+delete\b[^\n;&|]*\b"
            rf"(?:{RELEASE_VARIABLE_WRITE_GUARD_PATTERN})\b"
        ),
        "direct release variable workflow delete",
    ),
    (
        "gh api actions/variables <release-variable> write",
        re.compile(
            rf"\bgh\s+api\b"
            rf"(?=[^\n;&|]*{ACTIONS_VARIABLE_ENDPOINT_PATTERN})"
            rf"(?=[^\n;&|]*\b(?:{RELEASE_VARIABLE_WRITE_GUARD_PATTERN})\b)"
            rf"(?=[^\n;&|]*(?:\b(?:--method|-X)(?:\s+|=)"
            rf"(?:POST|PUT|PATCH)\b|"
            rf"{API_VARIABLE_FIELD_WRITE_PATTERN}))",
            re.IGNORECASE,
        ),
        "direct release variable workflow API write",
    ),
    (
        "gh secret set <release-secret>",
        re.compile(
            rf"\bgh\s+secret\s+set\b[^\n;&|]*\b"
            rf"(?:{RELEASE_SECRET_WRITE_GUARD_PATTERN})\b"
        ),
        "direct release secret workflow write",
    ),
    (
        "gh secret delete <release-secret>",
        re.compile(
            rf"\bgh\s+secret\s+delete\b[^\n;&|]*\b"
            rf"(?:{RELEASE_SECRET_WRITE_GUARD_PATTERN})\b"
        ),
        "direct release secret workflow delete",
    ),
    (
        "gh api actions/secrets <release-secret> write",
        re.compile(
            rf"\bgh\s+api\b"
            rf"(?=[^\n;&|]*{ACTIONS_SECRET_ENDPOINT_PATTERN})"
            rf"(?=[^\n;&|]*\b(?:{RELEASE_SECRET_WRITE_GUARD_PATTERN})\b)"
            rf"(?=[^\n;&|]*(?:\b(?:--method|-X)(?:\s+|=)"
            rf"(?:POST|PUT|PATCH)\b|"
            rf"{API_SECRET_FIELD_WRITE_PATTERN}))",
            re.IGNORECASE,
        ),
        "direct release secret workflow API write",
    ),
)
FORBIDDEN_WORKFLOW_BLOCK_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "script actions/variables write",
        re.compile(
            rf"{SCRIPT_CLIENT_PATTERN}"
            rf"(?={SCRIPT_BLOCK_SPAN_PATTERN}{ACTIONS_VARIABLE_ENDPOINT_PATTERN})"
            rf"(?={SCRIPT_BLOCK_SPAN_PATTERN}{SCRIPT_BLOCK_MUTATION_SIGNAL_PATTERN})",
            re.IGNORECASE,
        ),
        "scripted GitHub Actions variable workflow write",
    ),
    (
        "script actions/secrets write",
        re.compile(
            rf"{SCRIPT_CLIENT_PATTERN}"
            rf"(?={SCRIPT_BLOCK_SPAN_PATTERN}{ACTIONS_SECRET_ENDPOINT_PATTERN})"
            rf"(?={SCRIPT_BLOCK_SPAN_PATTERN}{SCRIPT_BLOCK_MUTATION_SIGNAL_PATTERN})",
            re.IGNORECASE,
        ),
        "scripted GitHub Actions secret workflow write",
    ),
)
WORKFLOW_COMMAND_DIAGNOSTIC_GUARD = (
    "workflowCommandDisplayed=false contentsDisplayed=false "
    "tokenDisplayed=false secretValuesDisplayed=false"
)
PERMISSION_DIAGNOSTIC_GUARD = (
    "unexpectedPermissionKeyDisplayed=false rawPermissionValueDisplayed=false "
    "contentsDisplayed=false tokenDisplayed=false secretValuesDisplayed=false"
)
ALLOWED_PERMISSION_KEYS = (
    "actions",
    "attestations",
    "contents",
    "id-token",
    "pages",
    "security-events",
)
ALLOWED_PERMISSION_VALUES = {"read", "write", "none"}
TOP_LEVEL_PERMISSIONS = {
    "contents": "read",
}
SECRET_LIKE_ENV_TOKENS = (
    "PASSWORD",
    "TOKEN",
    "SECRET",
    "KEY",
    "IDENTITY",
    "P12",
    "PFX",
    "GPG",
)
UNSAFE_GITHUB_ENV_ECHO_RE = re.compile(
    r"\becho\s+[\"']?([A-Z0-9_]+)=\$([A-Z0-9_]+)"
)
SHELL_VARIABLE_RE = re.compile(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)(?:\})?")
GITHUB_ENV_ASSIGNMENT_NAME_RE = re.compile(r"\b([A-Z][A-Z0-9_]*)\s*=")
GITHUB_ENV_HELPER_CALL_RE = re.compile(
    r"^append_github_env\s+([A-Z][A-Z0-9_]*)\b(.*)$"
)
SAFE_GITHUB_ENV_HELPER_CALLS = (
    'append_github_env CONU_MACOS_CODESIGN_IDENTITY "$MACOS_CODESIGN_IDENTITY"',
    'append_github_env CONU_MACOS_KEYCHAIN "$keychain_path"',
    'append_github_env CONU_MACOS_NOTARY_KEYCHAIN_PROFILE "conu-notary-profile"',
)
RELEASE_PREFLIGHT_NPM_AUTH_COMMAND = (
    "python scripts/check-npm-publish-preflight.py "
    "--registry-check --require-token-env NODE_AUTH_TOKEN --token-auth-check"
)
RELEASE_PREFLIGHT_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    (
        "tag-gated checkout action",
        "      - uses: actions/checkout@v6\n"
        "        if: startsWith(github.ref, 'refs/tags/v')",
    ),
)
RELEASE_PREFLIGHT_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Validate tag target CI and release branch",
        "validate tag target CI and release branch",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "tagged release readiness command",
                "python scripts/check-tagged-release-readiness.py --repo "
                '"$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME" --ci-only '
                '--ci-head "$GITHUB_SHA" --require-default-branch-head',
            ),
        ),
    ),
    (
        "Validate GitHub main branch protection",
        "validate GitHub main branch protection",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "main branch protection command",
                'python scripts/check-github-main-protection.py --repo "$GITHUB_REPOSITORY" '
                "--require-admin-enforcement",
            ),
        ),
    ),
    (
        "Validate GitHub Actions permissions",
        "validate GitHub Actions permissions",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "Actions permissions command",
                'python scripts/check-github-actions-permissions.py --repo "$GITHUB_REPOSITORY"',
            ),
        ),
    ),
    (
        "Validate GitHub workflow permissions",
        "validate GitHub workflow permissions",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "workflow permissions command",
                "python scripts/check-github-workflow-permissions.py",
            ),
        ),
    ),
    (
        "Validate GitHub repository security",
        "validate GitHub repository security",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "repository security command",
                'python scripts/check-github-repository-security.py --repo "$GITHUB_REPOSITORY"',
            ),
        ),
    ),
    (
        "Check tagged release secrets",
        "check tagged release secrets",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "Windows signing cert env",
                "CONU_WINDOWS_SIGN_CERT_PFX_BASE64: ${{ "
                "secrets.CONU_WINDOWS_SIGN_CERT_PFX_BASE64 }}",
            ),
            (
                "Windows signing password env",
                "CONU_WINDOWS_SIGN_CERT_PASSWORD: ${{ "
                "secrets.CONU_WINDOWS_SIGN_CERT_PASSWORD }}",
            ),
            (
                "macOS P12 secret env",
                "CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64: ${{ "
                "secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 }}",
            ),
            (
                "macOS P12 password env",
                "CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD: ${{ "
                "secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD }}",
            ),
            (
                "macOS codesign identity env",
                "CONU_MACOS_CODESIGN_IDENTITY: ${{ secrets.CONU_MACOS_CODESIGN_IDENTITY }}",
            ),
            (
                "macOS notary Apple ID env",
                "CONU_MACOS_NOTARY_APPLE_ID: ${{ secrets.CONU_MACOS_NOTARY_APPLE_ID }}",
            ),
            (
                "macOS notary team env",
                "CONU_MACOS_NOTARY_TEAM_ID: ${{ secrets.CONU_MACOS_NOTARY_TEAM_ID }}",
            ),
            (
                "macOS notary password env",
                "CONU_MACOS_NOTARY_PASSWORD: ${{ secrets.CONU_MACOS_NOTARY_PASSWORD }}",
            ),
            (
                "Linux GPG private key env",
                "CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ "
                "secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}",
            ),
            (
                "Linux GPG passphrase env",
                "CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}",
            ),
            (
                "Linux GPG key id env",
                "CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}",
            ),
            (
                "Linux GPG fingerprint env",
                "CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ "
                "secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}",
            ),
            ("NPM token env", "NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"),
            (
                "release secret env command",
                "python scripts/check-release-secret-env-preflight.py",
            ),
        ),
    ),
    (
        "Validate NPM token rotation marker",
        "validate NPM token rotation marker",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "rotation marker env",
                "CONU_NPM_TOKEN_ROTATED_AFTER: ${{ vars.CONU_NPM_TOKEN_ROTATED_AFTER }}",
            ),
            (
                "rotation marker command",
                "python scripts/check-release-secret-rotation-gate.py --secret-name "
                "NPM_TOKEN --rotated-after-env CONU_NPM_TOKEN_ROTATED_AFTER "
                "--required-after 2026-06-05T00:00:00Z",
            ),
        ),
    ),
    (
        "Validate npm token authentication and registry availability",
        "validate npm token authentication and registry availability",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("NPM token env", "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}"),
            ("npm auth/registry command", RELEASE_PREFLIGHT_NPM_AUTH_COMMAND),
        ),
    ),
    (
        "Install signing preflight tools",
        "install signing preflight tools",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "signing preflight tool install command",
                "sudo apt-get update && sudo apt-get install -y "
                "--no-install-recommends gnupg openssl",
            ),
        ),
    ),
    (
        "Validate platform signing secret values",
        "validate platform signing secret values",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "Windows signing cert env",
                "CONU_WINDOWS_SIGN_CERT_PFX_BASE64: ${{ "
                "secrets.CONU_WINDOWS_SIGN_CERT_PFX_BASE64 }}",
            ),
            (
                "Windows signing password env",
                "CONU_WINDOWS_SIGN_CERT_PASSWORD: ${{ "
                "secrets.CONU_WINDOWS_SIGN_CERT_PASSWORD }}",
            ),
            (
                "Windows timestamp URL env",
                "CONU_WINDOWS_TIMESTAMP_URL: ${{ secrets.CONU_WINDOWS_TIMESTAMP_URL }}",
            ),
            (
                "macOS P12 secret env",
                "CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64: ${{ "
                "secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 }}",
            ),
            (
                "macOS P12 password env",
                "CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD: ${{ "
                "secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD }}",
            ),
            (
                "macOS codesign identity env",
                "CONU_MACOS_CODESIGN_IDENTITY: ${{ secrets.CONU_MACOS_CODESIGN_IDENTITY }}",
            ),
            (
                "macOS notary Apple ID env",
                "CONU_MACOS_NOTARY_APPLE_ID: ${{ secrets.CONU_MACOS_NOTARY_APPLE_ID }}",
            ),
            (
                "macOS notary team env",
                "CONU_MACOS_NOTARY_TEAM_ID: ${{ secrets.CONU_MACOS_NOTARY_TEAM_ID }}",
            ),
            (
                "macOS notary password env",
                "CONU_MACOS_NOTARY_PASSWORD: ${{ secrets.CONU_MACOS_NOTARY_PASSWORD }}",
            ),
            (
                "platform signing secret value command",
                "python scripts/check-platform-signing-secrets-preflight.py "
                "--require-openssl",
            ),
        ),
    ),
    (
        "Validate Linux signing secrets",
        "validate Linux signing secrets",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            (
                "Linux GPG private key env",
                "CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ "
                "secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}",
            ),
            (
                "Linux GPG passphrase env",
                "CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}",
            ),
            (
                "Linux GPG key id env",
                "CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}",
            ),
            (
                "Linux GPG fingerprint env",
                "CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ "
                "secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}",
            ),
            (
                "Linux signing secret command",
                "python scripts/check-linux-signing-secrets-preflight.py",
            ),
        ),
    ),
    (
        "Validate default GitHub Pages repository settings",
        "validate default GitHub Pages repository settings",
        (
            (
                "default repository mode gate",
                "if: startsWith(github.ref, 'refs/tags/v') && "
                "vars.CONU_LINUX_REPOSITORY_BASE_URL == ''",
            ),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "GitHub Pages readiness command",
                'python scripts/check-github-pages-readiness.py --repo "$GITHUB_REPOSITORY"',
            ),
        ),
    ),
    (
        "Validate GitHub Release tag is unpublished",
        "validate GitHub Release tag is unpublished",
        (
            ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "release clobber preflight command",
                'python scripts/check-github-release-clobber-preflight.py --repo '
                '"$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"',
            ),
        ),
    ),
    (
        "Validate custom Linux repository publication config",
        "validate custom Linux repository publication config",
        (
            (
                "custom repository mode gate",
                "if: startsWith(github.ref, 'refs/tags/v') && "
                "vars.CONU_LINUX_REPOSITORY_BASE_URL != ''",
            ),
            (
                "custom repository base URL env",
                "CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}",
            ),
            (
                "custom repository bucket env",
                "CONU_LINUX_REPOSITORY_S3_BUCKET: ${{ "
                "vars.CONU_LINUX_REPOSITORY_S3_BUCKET }}",
            ),
            (
                "custom repository prefix env",
                "CONU_LINUX_REPOSITORY_S3_PREFIX: ${{ "
                "vars.CONU_LINUX_REPOSITORY_S3_PREFIX }}",
            ),
            (
                "custom repository endpoint env",
                "CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL: ${{ "
                "vars.CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL }}",
            ),
            (
                "custom repository region env",
                "CONU_LINUX_REPOSITORY_AWS_REGION: ${{ "
                "vars.CONU_LINUX_REPOSITORY_AWS_REGION }}",
            ),
            (
                "custom repository access key env",
                "CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID: ${{ "
                "secrets.CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID }}",
            ),
            (
                "custom repository secret key env",
                "CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY: ${{ "
                "secrets.CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY }}",
            ),
            (
                "custom repository session token env",
                "CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN: ${{ "
                "secrets.CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN }}",
            ),
            (
                "custom repository preflight command",
                "python scripts/check-custom-linux-repository-publication-preflight.py",
            ),
        ),
    ),
)
RELEASE_PUBLICATION_GATE_STEP = "Check Linux repository publication result"
RELEASE_PUBLICATION_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
)
RELEASE_PUBLICATION_GATE_SNIPPETS: tuple[tuple[str, str], ...] = (
    (
        "base URL mode selector",
        "CONU_LINUX_REPOSITORY_BASE_URL: ${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}",
    ),
    (
        "GitHub Release result",
        "GITHUB_RELEASE_RESULT: ${{ needs.github-release.result }}",
    ),
    ("Pages result", "PAGES_RESULT: ${{ needs.linux-repository-pages.result }}"),
    (
        "custom repository result",
        "CUSTOM_RESULT: ${{ needs.custom-linux-repository-publish.result }}",
    ),
    (
        "GitHub Release success check",
        'if [ "$GITHUB_RELEASE_RESULT" != "success" ]; then',
    ),
    (
        "default repository mode check",
        'if [ -z "${CONU_LINUX_REPOSITORY_BASE_URL:-}" ]; then',
    ),
    ("Pages success check", 'if [ "$PAGES_RESULT" != "success" ]; then'),
    ("custom repository success check", 'if [ "$CUSTOM_RESULT" != "success" ]; then'),
)
CI_PACKAGES_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    ("checkout action", "uses: actions/checkout@v6"),
    ("Node setup", "uses: actions/setup-node@v6"),
    ("Node version", "node-version: 24"),
)
PACKAGES_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    *CI_PACKAGES_JOB_SNIPPETS,
    ("npm registry URL", "registry-url: https://registry.npmjs.org"),
)
PACKAGES_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Install package tools",
        "install package tools",
        (
            (
                "package tool install command",
                "sudo apt-get update && sudo apt-get install -y "
                "--no-install-recommends rpm createrepo-c gnupg openssl",
            ),
        ),
    ),
    (
        "Python script compile",
        "compile Python scripts",
        (("Python compile command", "python scripts/check-python-script-compile.py"),),
    ),
    (
        "Production readiness toolchain regression",
        "run production readiness toolchain regression",
        (
            (
                "production readiness toolchain command",
                "python scripts/check-production-readiness-toolchain.py",
            ),
        ),
    ),
    (
        "Smoke output privacy regression",
        "run smoke output privacy regression",
        (("smoke privacy command", "python scripts/check-smoke-output-privacy.py"),),
    ),
    (
        "Release version consistency",
        "verify release version consistency",
        (("release version command", "python scripts/verify-release-versions.py"),),
    ),
    (
        "Release artifact verifier regression",
        "run release artifact verifier regression",
        (("artifact verifier command", "python scripts/check-release-artifact-verifier.py"),),
    ),
    (
        "Release artifact smoke preflight regression",
        "run release artifact smoke preflight regression",
        (
            (
                "artifact smoke preflight command",
                "python scripts/check-release-artifact-smoke-preflight.py",
            ),
        ),
    ),
    (
        "Package-manager manifest regression",
        "run package-manager manifest regression",
        (
            (
                "package-manager manifest command",
                "python scripts/check-package-manager-manifests.py",
            ),
        ),
    ),
    (
        "Package-manager submission bundle regression",
        "run package-manager submission bundle regression",
        (
            (
                "package-manager submission command",
                "python scripts/check-package-manager-submissions.py",
            ),
        ),
    ),
    (
        "Linux signing secret preflight regression",
        "run Linux signing secret preflight regression",
        (
            (
                "Linux signing secret command",
                "python scripts/check-linux-signing-secrets-preflight-regression.py",
            ),
        ),
    ),
    (
        "Platform signing secret value preflight regression",
        "run platform signing secret value preflight regression",
        (
            (
                "platform signing secret command",
                "python scripts/check-platform-signing-secrets-preflight-regression.py",
            ),
        ),
    ),
    (
        "GitHub release secret readiness regression",
        "run GitHub release secret readiness regression",
        (
            (
                "release secret readiness command",
                "python scripts/check-github-release-secret-readiness-regression.py",
            ),
        ),
    ),
    (
        "Release secret env preflight regression",
        "run release secret env preflight regression",
        (
            (
                "release secret env command",
                "python scripts/check-release-secret-env-preflight-regression.py",
            ),
        ),
    ),
    (
        "Release secret rotation gate regression",
        "run release secret rotation gate regression",
        (
            (
                "release secret rotation gate command",
                "python scripts/check-release-secret-rotation-gate-regression.py",
            ),
        ),
    ),
    (
        "GitHub release secret setup regression",
        "run GitHub release secret setup regression",
        (
            (
                "release secret setup command",
                "python scripts/set-github-release-secrets-regression.py",
            ),
        ),
    ),
    (
        "GitHub main branch protection regression",
        "run GitHub main branch protection regression",
        (
            (
                "main branch protection regression command",
                "python scripts/check-github-main-protection-regression.py",
            ),
        ),
    ),
    (
        "GitHub Actions permissions regression",
        "run GitHub Actions permissions regression",
        (
            (
                "Actions permissions regression command",
                "python scripts/check-github-actions-permissions-regression.py",
            ),
        ),
    ),
    (
        "GitHub workflow permissions regression",
        "run GitHub workflow permissions regression",
        (
            (
                "workflow permissions regression command",
                "python scripts/check-github-workflow-permissions-regression.py",
            ),
        ),
    ),
    (
        "GitHub repository security regression",
        "run GitHub repository security regression",
        (
            (
                "repository security regression command",
                "python scripts/check-github-repository-security-regression.py",
            ),
        ),
    ),
    (
        "GitHub Pages readiness regression",
        "run GitHub Pages readiness regression",
        (
            (
                "GitHub Pages readiness command",
                "python scripts/check-github-pages-readiness-regression.py",
            ),
        ),
    ),
    (
        "GitHub Release asset publication regression",
        "run GitHub Release asset publication regression",
        (
            (
                "Release asset publication command",
                "python scripts/check-github-release-assets-published-regression.py",
            ),
        ),
    ),
    (
        "GitHub Release clobber preflight regression",
        "run GitHub Release clobber preflight regression",
        (
            (
                "Release clobber preflight command",
                "python scripts/check-github-release-clobber-preflight-regression.py",
            ),
        ),
    ),
    (
        "Unsigned preview release asset regression",
        "run unsigned preview release asset regression",
        (
            (
                "unsigned preview release asset command",
                "python scripts/check-unsigned-preview-release-assets-regression.py",
            ),
        ),
    ),
    (
        "Tagged release readiness regression",
        "run tagged release readiness regression",
        (
            (
                "tagged release readiness command",
                "python scripts/check-tagged-release-readiness-regression.py",
            ),
        ),
    ),
    (
        "RPM package signing regression",
        "run RPM package signing regression",
        (("RPM package signing command", "python scripts/check-rpm-package-signing.py"),),
    ),
    (
        "Linux release signing regression",
        "run Linux release signing regression",
        (("Linux release signing command", "python scripts/check-linux-release-signing.py"),),
    ),
    (
        "Linux repository signing regression",
        "run Linux repository signing regression",
        (
            (
                "Linux repository signing command",
                "python scripts/check-linux-repository-signing.py",
            ),
        ),
    ),
    (
        "Hosted Linux repository bundle regression",
        "run hosted Linux repository bundle regression",
        (
            (
                "hosted repository bundle command",
                "python scripts/check-hosted-linux-repositories.py",
            ),
        ),
    ),
    (
        "Hosted Linux repository site regression",
        "run hosted Linux repository site regression",
        (
            (
                "hosted repository site command",
                "python scripts/check-hosted-linux-repository-site.py",
            ),
        ),
    ),
    (
        "Hosted Linux repository Pages regression",
        "run hosted Linux repository Pages regression",
        (
            (
                "hosted repository Pages command",
                "python scripts/check-hosted-linux-repository-pages.py",
            ),
        ),
    ),
    (
        "Hosted Linux repository endpoint regression",
        "run hosted Linux repository endpoint regression",
        (
            (
                "hosted repository endpoint command",
                "python scripts/check-hosted-linux-repository-endpoint-regression.py",
            ),
        ),
    ),
    (
        "Hosted Linux repository S3 publication regression",
        "run hosted Linux repository S3 publication regression",
        (
            (
                "hosted repository S3 publication command",
                "python scripts/check-hosted-linux-repository-s3-publication.py",
            ),
        ),
    ),
    (
        "Release update policy regression",
        "run release update policy regression",
        (("release update policy command", "python scripts/check-release-update-policy.py"),),
    ),
    (
        "Release update download/apply gate regression",
        "run release update download/apply gate regression",
        (
            (
                "release update download/apply command",
                "python scripts/check-release-update-download-gate.py",
            ),
        ),
    ),
    (
        "Linux GPG public-key export regression",
        "run Linux GPG public-key export regression",
        (
            (
                "Linux GPG public-key export command",
                "python scripts/check-linux-gpg-public-key-export.py",
            ),
        ),
    ),
    (
        "TypeScript SDK check",
        "check TypeScript SDK",
        (("TypeScript SDK command", "npm run check --prefix sdk/typescript"),),
    ),
    (
        "npm launcher check",
        "check npm launcher",
        (("npm launcher command", "npm run check --prefix packaging/npm/conu-cli"),),
    ),
    (
        "npm launcher local smoke preflight regression",
        "run npm launcher local smoke preflight regression",
        (
            (
                "npm launcher local smoke command",
                "python scripts/check-npm-launcher-local-smoke-preflight.py",
            ),
        ),
    ),
    (
        "Verify npm package contents",
        "verify npm package contents",
        (("npm package content command", "python scripts/verify-npm-package-contents.py"),),
    ),
    (
        "npm package public metadata regression",
        "run npm package public metadata regression",
        (
            (
                "npm package metadata command",
                "python scripts/verify-npm-package-contents-regression.py",
            ),
        ),
    ),
    (
        "npm publish preflight",
        "run npm publish preflight",
        (("npm publish preflight command", "python scripts/check-npm-publish-preflight.py"),),
    ),
    (
        "npm publish preflight regression",
        "run npm publish preflight regression",
        (
            (
                "npm publish preflight regression command",
                "python scripts/check-npm-publish-preflight-regression.py",
            ),
        ),
    ),
)
CI_RUST_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("matrix job name", "name: Rust (${{ matrix.os }})"),
    ("matrix runner", "runs-on: ${{ matrix.os }}"),
    ("matrix fail-fast", "fail-fast: false"),
    ("checkout action", "uses: actions/checkout@v6"),
    ("Rust toolchain action", "uses: dtolnay/rust-toolchain@stable"),
    ("rustfmt/clippy components", "components: rustfmt, clippy"),
)
CI_RUST_REQUIRED_OS: tuple[tuple[str, str], ...] = (
    ("Ubuntu runner matrix", "ubuntu-latest"),
    ("Windows runner matrix", "windows-2025-vs2026"),
    ("macOS runner matrix", "macos-15"),
)
CI_RUST_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Format",
        "run Rust format check",
        (("cargo fmt command", "cargo fmt --all -- --check"),),
    ),
    (
        "Check",
        "run Rust check",
        (("cargo check command", "cargo check --workspace --all-targets"),),
    ),
    (
        "Clippy",
        "run Rust clippy",
        (
            (
                "cargo clippy command",
                "cargo clippy --workspace --all-targets -- -D warnings",
            ),
        ),
    ),
    (
        "Test",
        "run Rust tests",
        (("cargo test command", "cargo test --workspace"),),
    ),
    (
        "Python compile",
        "compile Python scripts",
        (("Python compile command", "python scripts/check-python-script-compile.py"),),
    ),
    (
        "Doctor smoke",
        "run doctor smoke",
        (("doctor smoke command", "cargo run -p conu-cli -- doctor --json"),),
    ),
    (
        "Production readiness smoke gate",
        "run Windows production readiness smoke gate",
        (
            ("Windows matrix gate", "if: matrix.os == 'windows-2025-vs2026'"),
            ("PowerShell shell", "shell: pwsh"),
            (
                "production readiness smoke command",
                "run: ./scripts/verify-production-readiness.ps1 -SmokeOnly",
            ),
        ),
    ),
)
BUILD_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("matrix job name", "name: Build ${{ matrix.name }}"),
    ("matrix runner", "runs-on: ${{ matrix.os }}"),
    ("matrix fail-fast", "fail-fast: false"),
    ("Windows x64 target", "name: windows-x64"),
    ("Windows runner", "os: windows-2025-vs2026"),
    (
        "Windows build command",
        "powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 "
        "-PackageSuffix windows-x64",
    ),
    ("Linux x64 target", "name: linux-x64"),
    ("Linux x64 runner", "os: ubuntu-latest"),
    ("Linux x64 build command", "PACKAGE_SUFFIX=linux-x64 sh scripts/build-release.sh"),
    ("Linux arm64 target", "name: linux-arm64"),
    ("Linux arm64 runner", "os: ubuntu-24.04-arm"),
    ("Linux arm64 build command", "PACKAGE_SUFFIX=linux-arm64 sh scripts/build-release.sh"),
    ("macOS arm64 target", "name: macos-arm64"),
    ("macOS arm64 runner", "os: macos-15"),
    ("macOS arm64 build command", "PACKAGE_SUFFIX=macos-arm64 sh scripts/build-release.sh"),
    ("macOS x64 target", "name: macos-x64"),
    ("macOS x64 runner", "os: macos-15-intel"),
    ("macOS x64 build command", "PACKAGE_SUFFIX=macos-x64 sh scripts/build-release.sh"),
    ("zip artifact glob", "dist/*.zip"),
    ("zip checksum glob", "dist/*.zip.sha256"),
    ("tarball artifact glob", "dist/*.tar.gz"),
    ("tarball checksum glob", "dist/*.tar.gz.sha256"),
    (
        "signing required env",
        "CONU_SIGNING_REQUIRED: ${{ startsWith(github.ref, 'refs/tags/v') && "
        "'1' || '0' }}",
    ),
    ("checkout action", "uses: actions/checkout@v6"),
    ("Rust toolchain action", "uses: dtolnay/rust-toolchain@stable"),
)
BUILD_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Configure macOS signing keychain",
        "configure macOS signing keychain",
        (
            ("macOS runner gate", "if: runner.os == 'macOS'"),
            (
                "macOS P12 secret env",
                "MACOS_P12_BASE64: ${{ "
                "secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64 }}",
            ),
            (
                "macOS P12 password secret env",
                "MACOS_P12_PASSWORD: ${{ "
                "secrets.CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD }}",
            ),
            (
                "macOS codesign identity secret env",
                "MACOS_CODESIGN_IDENTITY: ${{ secrets.CONU_MACOS_CODESIGN_IDENTITY }}",
            ),
            (
                "macOS notary Apple ID secret env",
                "MACOS_NOTARY_APPLE_ID: ${{ secrets.CONU_MACOS_NOTARY_APPLE_ID }}",
            ),
            (
                "macOS notary team secret env",
                "MACOS_NOTARY_TEAM_ID: ${{ secrets.CONU_MACOS_NOTARY_TEAM_ID }}",
            ),
            (
                "macOS notary password secret env",
                "MACOS_NOTARY_PASSWORD: ${{ secrets.CONU_MACOS_NOTARY_PASSWORD }}",
            ),
            (
                "tagged signing required gate",
                'if [ "${CONU_SIGNING_REQUIRED:-0}" = "1" ]; then',
            ),
            (
                "notary credential storage",
                "xcrun notarytool store-credentials conu-notary-profile",
            ),
            ("safe GitHub env writer", "append_github_env() {"),
            (
                "codesign identity export",
                'append_github_env CONU_MACOS_CODESIGN_IDENTITY "$MACOS_CODESIGN_IDENTITY"',
            ),
            (
                "keychain export",
                'append_github_env CONU_MACOS_KEYCHAIN "$keychain_path"',
            ),
            (
                "notary profile export",
                'append_github_env CONU_MACOS_NOTARY_KEYCHAIN_PROFILE "conu-notary-profile"',
            ),
        ),
    ),
    (
        "Build package",
        "build release package",
        (
            (
                "Windows signing cert env",
                "CONU_WINDOWS_SIGN_CERT_PFX_BASE64: ${{ "
                "secrets.CONU_WINDOWS_SIGN_CERT_PFX_BASE64 }}",
            ),
            (
                "Windows signing password env",
                "CONU_WINDOWS_SIGN_CERT_PASSWORD: ${{ "
                "secrets.CONU_WINDOWS_SIGN_CERT_PASSWORD }}",
            ),
            (
                "Windows timestamp URL env",
                "CONU_WINDOWS_TIMESTAMP_URL: ${{ secrets.CONU_WINDOWS_TIMESTAMP_URL }}",
            ),
            ("matrix build command", "run: ${{ matrix.script }}"),
        ),
    ),
    (
        "Verify release artifact",
        "verify release artifact",
        (
            (
                "release artifact verifier command",
                "python scripts/verify-release-artifacts.py dist",
            ),
        ),
    ),
    (
        "Smoke release artifact install",
        "smoke release artifact install",
        (("release artifact smoke command", "python scripts/smoke-release-artifacts.py dist"),),
    ),
    (
        "Smoke npm launcher local install",
        "smoke npm launcher local install",
        (
            (
                "npm launcher local smoke command",
                "python scripts/smoke-npm-launcher-local.py dist",
            ),
        ),
    ),
    (
        "Smoke npm launcher download install",
        "smoke npm launcher download install",
        (
            (
                "npm launcher download smoke command",
                "python scripts/smoke-npm-launcher-download.py dist",
            ),
        ),
    ),
    (
        "Upload artifact",
        "upload release artifact",
        (
            ("artifact upload action", "uses: actions/upload-artifact@v7.0.1"),
            ("matrix artifact name", "name: conu-${{ matrix.name }}"),
            ("matrix artifact path", "path: ${{ matrix.artifact }}"),
            ("missing artifact failure", "if-no-files-found: error"),
        ),
    ),
    (
        "Attest release artifact provenance",
        "attest release artifact provenance",
        (
            ("artifact attestation action", "uses: actions/attest@v4.1.0"),
            ("attestation subject path", "subject-path: ${{ matrix.artifact }}"),
        ),
    ),
)
NPM_PUBLISH_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    ("contents read permission", "contents: read"),
    ("provenance id-token permission", "id-token: write"),
    ("checkout action", "uses: actions/checkout@v6"),
    ("Node setup", "uses: actions/setup-node@v6"),
    ("Node version", "node-version: 24"),
    ("npm registry URL", "registry-url: https://registry.npmjs.org"),
)
NPM_PUBLISH_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Verify npm package contents",
        "verify npm package contents",
        (("package content verifier", "python scripts/verify-npm-package-contents.py"),),
    ),
    (
        "npm package public metadata regression",
        "run npm package public metadata regression",
        (
            (
                "package metadata regression command",
                "python scripts/verify-npm-package-contents-regression.py",
            ),
        ),
    ),
    (
        "GitHub Release asset publication preflight",
        "verify GitHub Release asset publication before npm",
        (
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "GitHub Release asset preflight command",
                'python scripts/check-github-release-assets-published.py --repo '
                '"$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"',
            ),
        ),
    ),
    (
        "npm publish conflict preflight",
        "check npm publication conflicts and token authentication",
        (
            ("NPM token env", "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}"),
            ("npm auth/registry command", RELEASE_PREFLIGHT_NPM_AUTH_COMMAND),
        ),
    ),
    (
        "Publish @conu/cli",
        "publish @conu/cli with provenance",
        (
            ("CLI package directory", "working-directory: packaging/npm/conu-cli"),
            ("NPM token env", "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}"),
            ("NPM token guard", 'if [ -z "${NODE_AUTH_TOKEN:-}" ]; then'),
            ("provenance publish command", "npm publish --access public --provenance"),
        ),
    ),
    (
        "Publish @conu/sdk",
        "publish @conu/sdk with provenance",
        (
            ("SDK package directory", "working-directory: sdk/typescript"),
            ("NPM token env", "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}"),
            ("NPM token guard", 'if [ -z "${NODE_AUTH_TOKEN:-}" ]; then'),
            ("provenance publish command", "npm publish --access public --provenance"),
        ),
    ),
)
GITHUB_RELEASE_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("tag gate", "if: startsWith(github.ref, 'refs/tags/v')"),
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    ("checkout action", "uses: actions/checkout@v6"),
    ("Rust toolchain action", "uses: dtolnay/rust-toolchain@stable"),
    ("artifact download action", "uses: actions/download-artifact@v8.0.1"),
    ("merged artifact download path", "path: dist"),
    ("release artifact download pattern", "pattern: conu-*"),
    ("release artifact digest mismatch policy", "digest-mismatch: error"),
    ("merged artifact download flag", "merge-multiple: true"),
)
UNSIGNED_PREVIEW_RELEASE_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    (
        "manual preview dispatch gate",
        "if: github.event_name == 'workflow_dispatch' && "
        "inputs.publish_preview_release == 'true'",
    ),
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    ("contents write permission", "contents: write"),
    ("checkout action", "uses: actions/checkout@v6"),
    ("artifact download action", "uses: actions/download-artifact@v8.0.1"),
    ("merged artifact download path", "path: dist"),
    ("release artifact download pattern", "pattern: conu-*"),
    ("release artifact digest mismatch policy", "digest-mismatch: error"),
    ("merged artifact download flag", "merge-multiple: true"),
)
UNSIGNED_PREVIEW_RELEASE_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Verify unsigned preview artifacts",
        "verify unsigned preview artifacts",
        (("release artifact verifier command", "python scripts/verify-release-artifacts.py dist"),),
    ),
    (
        "Check unsigned preview asset set before publication",
        "check unsigned preview asset set before publication",
        (
            (
                "preview asset checker command",
                "python scripts/check-unsigned-preview-release-assets.py --dist-dir dist --json",
            ),
        ),
    ),
    (
        "Publish unsigned preview prerelease",
        "publish unsigned preview prerelease without clobber",
        (
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            ("release repository env", "GH_REPO: ${{ github.repository }}"),
            ("preview tag derivation", 'PREVIEW_TAG="preview-${GITHUB_RUN_ID}"'),
            ("existing preview guard", 'gh release view "$PREVIEW_TAG"'),
            (
                "preview release create command",
                'gh release create "$PREVIEW_TAG" dist/* --target "$GITHUB_SHA" '
                '--prerelease --title "conU unsigned preview ${GITHUB_RUN_ID}" '
                "--notes-file release-notes.md",
            ),
        ),
    ),
    (
        "Verify published unsigned preview prerelease",
        "verify published unsigned preview prerelease",
        (
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            ("release repository env", "GH_REPO: ${{ github.repository }}"),
            ("preview tag derivation", 'PREVIEW_TAG="preview-${GITHUB_RUN_ID}"'),
            (
                "published preview asset checker command",
                'python scripts/check-unsigned-preview-release-assets.py --repo "$GH_REPO" '
                '--tag "$PREVIEW_TAG" --json',
            ),
        ),
    ),
)
GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS: tuple[tuple[str, str], ...] = (
    (
        "Linux GPG private key env",
        "CONU_LINUX_GPG_PRIVATE_KEY_BASE64: ${{ "
        "secrets.CONU_LINUX_GPG_PRIVATE_KEY_BASE64 }}",
    ),
    (
        "Linux GPG passphrase env",
        "CONU_LINUX_GPG_PASSPHRASE: ${{ secrets.CONU_LINUX_GPG_PASSPHRASE }}",
    ),
    (
        "Linux GPG key id env",
        "CONU_LINUX_GPG_KEY_ID: ${{ secrets.CONU_LINUX_GPG_KEY_ID }}",
    ),
    (
        "Linux GPG fingerprint env",
        "CONU_LINUX_GPG_KEY_FINGERPRINT: ${{ "
        "secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}",
    ),
)
GITHUB_RELEASE_REQUIRED_STEPS: tuple[
    tuple[str, str, tuple[tuple[str, str], ...]],
    ...,
] = (
    (
        "Install package tools",
        "install package tools",
        (
            (
                "package tool install command",
                "sudo apt-get update && sudo apt-get install -y "
                "--no-install-recommends rpm createrepo-c gnupg",
            ),
        ),
    ),
    (
        "Verify downloaded release assets",
        "verify downloaded release assets",
        (("release artifact verifier command", "python scripts/verify-release-artifacts.py dist"),),
    ),
    (
        "Generate package-manager manifests",
        "generate package-manager manifests",
        (
            ("GitHub repository env", "GH_REPO: ${{ github.repository }}"),
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            (
                "manifest generation command",
                "python scripts/generate-package-manager-manifests.py dist",
            ),
            ("manifest output dir", "--output-dir dist"),
            ("manifest repo flag", '--repo "$GH_REPO"'),
            ("manifest version flag", '--version "$VERSION"'),
            ("manifest tag flag", '--tag "$TAG_NAME"'),
            ("RPM package build flag", "--build-rpm-packages"),
            ("APT repository metadata flag", "--build-apt-repository-metadata"),
        ),
    ),
    (
        "Sign RPM packages",
        "sign RPM packages",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            ("RPM signing command", "python scripts/sign-rpm-packages.py dist"),
        ),
    ),
    (
        "Generate RPM repository metadata",
        "generate RPM repository metadata",
        (
            ("GitHub repository env", "GH_REPO: ${{ github.repository }}"),
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            (
                "manifest generation command",
                "python scripts/generate-package-manager-manifests.py dist",
            ),
            ("RPM repository metadata flag", "--build-rpm-repository-metadata"),
        ),
    ),
    (
        "Export Linux GPG public key",
        "export Linux GPG public key",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            ("Linux public-key export command", "python scripts/export-linux-gpg-public-key.py dist"),
        ),
    ),
    (
        "Sign Linux repository metadata",
        "sign Linux repository metadata",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            (
                "Linux repository metadata signing command",
                "python scripts/sign-linux-repository-metadata.py dist",
            ),
        ),
    ),
    (
        "Sign Linux release assets",
        "sign Linux release assets",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            ("Linux release asset signing command", "python scripts/sign-linux-release-assets.py dist"),
        ),
    ),
    (
        "Prepare package-manager submission bundle",
        "prepare package-manager submission bundle",
        (
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            (
                "package-manager submission command",
                "python scripts/prepare-package-manager-submissions.py dist",
            ),
            ("submission output dir", "--output-dir dist"),
            ("submission version flag", '--version "$VERSION"'),
            ("RPM asset requirement", "--require-rpm-assets"),
            ("repository metadata requirement", "--require-repository-metadata"),
            ("Linux signature requirement", "--require-linux-signatures"),
        ),
    ),
    (
        "Sign package-manager submission bundle",
        "sign package-manager submission bundle",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            (
                "package-manager submission signing command",
                "python scripts/sign-linux-release-assets.py dist "
                "--only-package-manager-submissions",
            ),
        ),
    ),
    (
        "Generate hosted Linux repositories",
        "generate hosted Linux repositories",
        (
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            (
                "hosted repository generation command",
                "python scripts/generate-hosted-linux-repositories.py dist "
                '--output-dir dist --version "$VERSION"',
            ),
        ),
    ),
    (
        "Sign hosted Linux repository bundle",
        "sign hosted Linux repository bundle",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            (
                "hosted repository bundle signing command",
                "python scripts/sign-linux-release-assets.py dist "
                "--only-hosted-repository-bundles",
            ),
        ),
    ),
    (
        "Generate hosted Linux repository site",
        "generate hosted Linux repository site",
        (
            ("GitHub repository env", "GH_REPO: ${{ github.repository }}"),
            (
                "GitHub repository owner env",
                "GITHUB_REPOSITORY_OWNER: ${{ github.repository_owner }}",
            ),
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            (
                "custom base URL env",
                "CONU_LINUX_REPOSITORY_BASE_URL: "
                "${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}",
            ),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            ("base URL derivation", 'BASE_URL="${CONU_LINUX_REPOSITORY_BASE_URL:-}"'),
            ("default Pages base URL", 'BASE_URL="https://${GITHUB_REPOSITORY_OWNER}.github.io/${REPO_NAME}"'),
            (
                "hosted repository site generation command",
                "python scripts/generate-hosted-linux-repository-site.py dist",
            ),
            ("site output dir", "--output-dir dist"),
            ("site version flag", '--version "$VERSION"'),
            ("site base URL flag", '--base-url "$BASE_URL"'),
        ),
    ),
    (
        "Sign hosted Linux repository site",
        "sign hosted Linux repository site",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            (
                "hosted repository site signing command",
                "python scripts/sign-linux-release-assets.py dist "
                "--only-hosted-repository-sites",
            ),
        ),
    ),
    (
        "Generate release update policy",
        "generate release update policy",
        (
            ("GitHub repository env", "GH_REPO: ${{ github.repository }}"),
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            (
                "release update policy generation command",
                "python scripts/generate-release-update-policy.py dist",
            ),
            ("update policy output dir", "--output-dir dist"),
            ("update policy version flag", '--version "$VERSION"'),
            ("update policy tag flag", '--tag "$TAG_NAME"'),
            ("update policy repo flag", '--repo "$GH_REPO"'),
        ),
    ),
    (
        "Sign release update policy",
        "sign release update policy",
        (
            *GITHUB_RELEASE_LINUX_GPG_ENV_SNIPPETS,
            (
                "release update policy signing command",
                "python scripts/sign-linux-release-assets.py dist --only-update-policies",
            ),
        ),
    ),
    (
        "Check release update policy with CLI",
        "check release update policy with CLI",
        (
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("tag version derivation", 'VERSION="${TAG_NAME#v}"'),
            (
                "local update policy check command",
                'cargo run -p conu-cli -- update check --policy-file '
                '"dist/conu-${VERSION}-update-policy.json" --json',
            ),
        ),
    ),
    (
        "Prepare hosted Linux repository Pages artifact",
        "prepare hosted Linux repository Pages artifact",
        (
            (
                "Pages artifact preparation command",
                "python scripts/prepare-hosted-linux-repository-pages.py dist "
                "--output-dir linux-repository-site",
            ),
        ),
    ),
    (
        "Upload hosted Linux repository Pages artifact",
        "upload hosted Linux repository Pages artifact",
        (
            ("artifact upload action", "uses: actions/upload-artifact@v7.0.1"),
            ("hosted repository artifact name", "name: conu-hosted-linux-repository-pages"),
            ("hosted repository artifact path", "path: linux-repository-site"),
            ("missing artifact failure", "if-no-files-found: error"),
            ("retention period", "retention-days: 14"),
        ),
    ),
    (
        "Re-check GitHub Release tag is unpublished",
        "re-check GitHub Release tag is unpublished",
        (
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "clobber preflight command",
                'python scripts/check-github-release-clobber-preflight.py --repo '
                '"$GITHUB_REPOSITORY" --tag "$GITHUB_REF_NAME"',
            ),
        ),
    ),
    (
        "Verify local GitHub Release asset set",
        "verify local GitHub Release asset set",
        (
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            (
                "local release asset preflight command",
                'python scripts/check-github-release-assets-published.py --tag "$TAG_NAME" '
                "--dist-dir dist",
            ),
        ),
    ),
    (
        "Publish release assets",
        "publish release assets without clobber",
        (
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            ("release repository env", "GH_REPO: ${{ github.repository }}"),
            ("tag name env", "TAG_NAME: ${{ github.ref_name }}"),
            ("existing release guard", 'gh release view "$TAG_NAME"'),
            (
                "release create command",
                'gh release create "$TAG_NAME" dist/* --verify-tag --title '
                '"conU $TAG_NAME" --notes-file release-notes.md',
            ),
        ),
    ),
    (
        "Verify published release update policy and artifact with CLI",
        "verify published release update policy and artifact with CLI",
        (
            ("GitHub token env", "GH_TOKEN: ${{ github.token }}"),
            (
                "Linux fingerprint env",
                "CONU_LINUX_GPG_KEY_FINGERPRINT: "
                "${{ secrets.CONU_LINUX_GPG_KEY_FINGERPRINT }}",
            ),
            (
                "public key download",
                'gh release download "$TAG_NAME" --repo "$GH_REPO" --pattern '
                'conu-linux-gpg-key.asc --dir "$KEY_DIR"',
            ),
            (
                "public key checksum download",
                'gh release download "$TAG_NAME" --repo "$GH_REPO" --pattern '
                'conu-linux-gpg-key.asc.sha256 --dir "$KEY_DIR"',
            ),
            (
                "public key checksum verification",
                '(cd "$KEY_DIR" && sha256sum -c conu-linux-gpg-key.asc.sha256)',
            ),
            (
                "fingerprint comparison",
                'if [ "$ACTUAL_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]; then',
            ),
            (
                "redacted fingerprint mismatch error",
                'echo "::error::Published Linux GPG public key fingerprint mismatch"',
            ),
            (
                "update check command",
                'cargo run -p conu-cli -- update check --policy-url "$POLICY_URL" '
                "--gpg-verify --json",
            ),
            (
                "update download command",
                'cargo run -p conu-cli -- update download --policy-url "$POLICY_URL" '
                '--output-dir "$DOWNLOAD_DIR" --target linux-x64 --gpg-verify --json',
            ),
            (
                "update apply dry-run command",
                'cargo run -p conu-cli -- update apply --policy-url "$POLICY_URL" '
                '--artifact-file "$DOWNLOAD_DIR/conu-${VERSION}-linux-x64.tar.gz" '
                '--install-dir "$APPLY_INSTALL_DIR" --target linux-x64 --gpg-verify '
                "--dry-run --json",
            ),
        ),
    ),
)
LINUX_REPOSITORY_PAGES_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    (
        "default repository tag/base URL gate",
        "if: startsWith(github.ref, 'refs/tags/v') && "
        "vars.CONU_LINUX_REPOSITORY_BASE_URL == ''",
    ),
    ("Pages environment", "name: github-pages"),
    ("Pages deployment output", "url: ${{ steps.deployment.outputs.page_url }}"),
    ("hosted repository artifact download", "uses: actions/download-artifact@v8.0.1"),
    ("hosted repository artifact name", "name: conu-hosted-linux-repository-pages"),
    ("hosted repository artifact path", "path: linux-repository-site"),
    ("hosted repository artifact digest mismatch policy", "digest-mismatch: error"),
    ("configure Pages action", "uses: actions/configure-pages@v6"),
    ("upload Pages artifact action", "uses: actions/upload-pages-artifact@v5"),
    ("deploy Pages action", "uses: actions/deploy-pages@v5"),
)
CUSTOM_LINUX_REPOSITORY_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("Ubuntu runner", "runs-on: ubuntu-latest"),
    (
        "custom repository tag/base URL gate",
        "if: startsWith(github.ref, 'refs/tags/v') && "
        "vars.CONU_LINUX_REPOSITORY_BASE_URL != ''",
    ),
    ("checkout action", "uses: actions/checkout@v6"),
    ("hosted repository artifact download", "uses: actions/download-artifact@v8.0.1"),
    ("hosted repository artifact name", "name: conu-hosted-linux-repository-pages"),
    ("hosted repository artifact path", "path: linux-repository-site"),
    ("hosted repository artifact digest mismatch policy", "digest-mismatch: error"),
    ("AWS CLI install", "python -m pip install --user awscli"),
)
CUSTOM_LINUX_REPOSITORY_PUBLISH_STEP = (
    "Publish custom hosted Linux repository and verify endpoint"
)
CUSTOM_LINUX_REPOSITORY_PUBLISH_SNIPPETS: tuple[tuple[str, str], ...] = (
    (
        "AWS access key env",
        "AWS_ACCESS_KEY_ID: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_ACCESS_KEY_ID }}",
    ),
    (
        "AWS secret key env",
        "AWS_SECRET_ACCESS_KEY: "
        "${{ secrets.CONU_LINUX_REPOSITORY_AWS_SECRET_ACCESS_KEY }}",
    ),
    (
        "AWS session token env",
        "AWS_SESSION_TOKEN: ${{ secrets.CONU_LINUX_REPOSITORY_AWS_SESSION_TOKEN }}",
    ),
    (
        "AWS region env",
        "CONU_LINUX_REPOSITORY_AWS_REGION: "
        "${{ vars.CONU_LINUX_REPOSITORY_AWS_REGION }}",
    ),
    (
        "custom base URL env",
        "CONU_LINUX_REPOSITORY_BASE_URL: "
        "${{ vars.CONU_LINUX_REPOSITORY_BASE_URL }}",
    ),
    (
        "S3 bucket env",
        "CONU_LINUX_REPOSITORY_S3_BUCKET: "
        "${{ vars.CONU_LINUX_REPOSITORY_S3_BUCKET }}",
    ),
    (
        "S3 prefix env",
        "CONU_LINUX_REPOSITORY_S3_PREFIX: "
        "${{ vars.CONU_LINUX_REPOSITORY_S3_PREFIX }}",
    ),
    (
        "S3 endpoint env",
        "CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL: "
        "${{ vars.CONU_LINUX_REPOSITORY_S3_ENDPOINT_URL }}",
    ),
    ("tag version derivation", 'VERSION="${GITHUB_REF_NAME#v}"'),
    (
        "S3 publication command",
        "python scripts/publish-hosted-linux-repository-s3.py linux-repository-site",
    ),
    ("expected version flag", '--expected-version "$VERSION"'),
    ("confirm flag", "--confirm"),
    ("post-upload live endpoint check", "--post-upload-check"),
    ("JSON report flag", "--json"),
)
PRODUCTION_READINESS_JOB_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("Windows runner", "runs-on: windows-2025-vs2026"),
    ("checkout action", "uses: actions/checkout@v6"),
    ("Rust toolchain action", "uses: dtolnay/rust-toolchain@stable"),
)
PRODUCTION_READINESS_STEP = "Production readiness smoke gate"
PRODUCTION_READINESS_STEP_SNIPPETS: tuple[tuple[str, str], ...] = (
    ("PowerShell shell", "shell: pwsh"),
    (
        "production readiness smoke command",
        "run: ./scripts/verify-production-readiness.ps1 -SmokeOnly",
    ),
)
EXPECTED_JOB_PERMISSIONS: dict[tuple[str, str], dict[str, str]] = {
    ("release.yml", "release-preflight"): {
        "actions": "read",
        "contents": "read",
        "pages": "read",
        "security-events": "read",
    },
    ("release.yml", "build"): {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    },
    ("release.yml", "manual-preview-release"): {
        "contents": "write",
    },
    ("release.yml", "github-release"): {
        "contents": "write",
    },
    ("release.yml", "linux-repository-pages"): {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    },
    ("release.yml", "custom-linux-repository-publish"): {
        "contents": "read",
    },
    ("release.yml", "npm-publish"): {
        "contents": "read",
        "id-token": "write",
    },
}
EXPECTED_RELEASE_JOB_NEEDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("release.yml", "packages"): ("release-preflight",),
    ("release.yml", "production-readiness"): ("release-preflight",),
    ("release.yml", "build"): ("packages", "production-readiness"),
    ("release.yml", "manual-preview-release"): ("build",),
    ("release.yml", "github-release"): ("build",),
    ("release.yml", "linux-repository-pages"): ("github-release",),
    ("release.yml", "custom-linux-repository-publish"): ("github-release",),
    (
        "release.yml",
        "linux-repository-publication",
    ): ("github-release", "linux-repository-pages", "custom-linux-repository-publish"),
    ("release.yml", "npm-publish"): ("github-release", "linux-repository-publication"),
}


@dataclass(frozen=True)
class WorkflowPermissionsReadiness:
    ready: bool
    workflow_count: int
    checked_workflows: tuple[str, ...]
    workflows_with_explicit_top_level_permissions: tuple[str, ...]
    jobs_with_write_permissions: tuple[str, ...]
    unsafe_environment_file_writes: tuple[str, ...]
    forbidden_events: tuple[str, ...]
    forbidden_workflow_commands: tuple[str, ...]
    issues: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "conu.githubWorkflowPermissions.v1",
            "ready": self.ready,
            "workflowCount": self.workflow_count,
            "checkedWorkflows": list(self.checked_workflows),
            "workflowsWithExplicitTopLevelPermissions": list(
                self.workflows_with_explicit_top_level_permissions
            ),
            "jobsWithWritePermissions": list(self.jobs_with_write_permissions),
            "unsafeEnvironmentFileWrites": list(self.unsafe_environment_file_writes),
            "forbiddenEvents": list(self.forbidden_events),
            "forbiddenWorkflowCommands": list(self.forbidden_workflow_commands),
            "issues": list(self.issues),
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
            "contentsDisplayed": False,
            "workflowCommandDisplayed": False,
            "secretValuesDisplayed": False,
            "unexpectedPermissionKeyDisplayed": False,
            "rawPermissionValueDisplayed": False,
        }


def yaml_items(text: str) -> list[tuple[int, str, str]]:
    items: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        if content.startswith("- "):
            items.append((indent, "-", content[2:].strip()))
            continue
        if ":" not in content:
            continue
        key, value = content.split(":", 1)
        items.append((indent, key.strip().strip("\"'"), value.strip()))
    return items


def scalar_value(value: str) -> str:
    return value.strip().strip("\"'")


def parse_inline_sequence(value: str) -> list[str] | None:
    text = scalar_value(value)
    if not text.startswith("[") or not text.endswith("]"):
        return None
    inner = text[1:-1].strip()
    if not inner:
        return []
    return [scalar_value(item.strip()) for item in inner.split(",")]


def parse_mapping_at(items: list[tuple[int, str, str]], start: int, base_indent: int, value: str) -> dict[str, str] | str:
    if value:
        return scalar_value(value)
    mapping: dict[str, str] = {}
    for indent, key, child_value in items[start + 1 :]:
        if indent <= base_indent:
            break
        if key == "-" or indent != base_indent + 2:
            continue
        mapping[key] = scalar_value(child_value)
    return mapping


def parse_sequence_at(
    items: list[tuple[int, str, str]],
    start: int,
    base_indent: int,
    value: str,
) -> list[str] | str:
    inline_sequence = parse_inline_sequence(value)
    if inline_sequence is not None:
        return inline_sequence
    if value:
        return scalar_value(value)
    sequence: list[str] = []
    for indent, key, child_value in items[start + 1 :]:
        if indent <= base_indent:
            break
        if indent == base_indent + 2 and key == "-":
            sequence.append(scalar_value(child_value))
    return sequence


def parse_events_at(items: list[tuple[int, str, str]], start: int, base_indent: int, value: str) -> str | dict[str, Any]:
    if value:
        return scalar_value(value)
    events: dict[str, Any] = {}
    for indent, key, child_value in items[start + 1 :]:
        if indent <= base_indent:
            break
        if indent != base_indent + 2:
            continue
        if key == "-":
            events[scalar_value(child_value)] = {}
        else:
            events[key] = {}
    return events


def parse_jobs_at(items: list[tuple[int, str, str]], start: int, base_indent: int) -> dict[str, Any]:
    jobs: dict[str, Any] = {}
    job_indexes: list[tuple[int, str]] = []
    for index, (indent, key, _value) in enumerate(items[start + 1 :], start + 1):
        if indent <= base_indent:
            break
        if indent == base_indent + 2 and key != "-":
            job_indexes.append((index, key))
            jobs[key] = {}
    for job_index, job_name in job_indexes:
        for index, (indent, key, value) in enumerate(items[job_index + 1 :], job_index + 1):
            if indent <= base_indent + 2:
                break
            if indent == base_indent + 4 and key == "permissions":
                jobs[job_name]["permissions"] = parse_mapping_at(items, index, indent, value)
            elif indent == base_indent + 4 and key == "needs":
                jobs[job_name]["needs"] = parse_sequence_at(items, index, indent, value)
    return jobs


def load_workflow_minimal(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc
    items = yaml_items(text)
    payload: dict[str, Any] = {}
    for index, (indent, key, value) in enumerate(items):
        if indent != 0:
            continue
        if key == "on":
            payload["on"] = parse_events_at(items, index, indent, value)
        elif key == "permissions":
            payload["permissions"] = parse_mapping_at(items, index, indent, value)
        elif key == "jobs":
            payload["jobs"] = parse_jobs_at(items, index, indent)
    return payload


def load_workflow(path: Path) -> dict[str, Any]:
    if yaml is None:
        return load_workflow_minimal(path)
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc
    except yaml.YAMLError as exc:  # type: ignore[union-attr]
        raise ValueError(f"workflow {path.name} is invalid YAML: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"workflow {path.name} must contain a YAML mapping")
    return payload


def audit_environment_file_writes(path: Path) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    findings: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        helper_match = GITHUB_ENV_HELPER_CALL_RE.search(stripped)
        if helper_match is not None:
            if stripped in SAFE_GITHUB_ENV_HELPER_CALLS:
                continue
            output_name, helper_args = helper_match.groups()
            source_names = tuple(
                name
                for name in SHELL_VARIABLE_RE.findall(helper_args)
                if is_secret_like_env_name(name)
            )
            if is_secret_like_env_name(output_name) or source_names:
                finding_name = source_names[0] if source_names else output_name
                findings.append(
                    f"{path.name}:line {index + 1} uses unapproved "
                    f"append_github_env helper call for secret-like {finding_name}"
                )
            continue
        if not has_nearby_github_env_redirect(lines, index):
            continue

        match = UNSAFE_GITHUB_ENV_ECHO_RE.search(stripped)
        if match is not None:
            output_name, source_name = match.groups()
            if not is_secret_like_env_name(output_name) and not is_secret_like_env_name(
                source_name
            ):
                continue
            findings.append(
                f"{path.name}:line {index + 1} echoes secret-derived {source_name} directly to GITHUB_ENV"
            )
            continue

        source_names = tuple(
            name
            for name in SHELL_VARIABLE_RE.findall(stripped)
            if name != "GITHUB_ENV" and is_secret_like_env_name(name)
        )
        if source_names:
            for source_name in source_names:
                findings.append(
                    f"{path.name}:line {index + 1} writes secret-derived {source_name} directly to GITHUB_ENV"
                )
            continue

        output_names = tuple(
            name
            for name in GITHUB_ENV_ASSIGNMENT_NAME_RE.findall(stripped)
            if is_secret_like_env_name(name)
        )
        for output_name in output_names:
            findings.append(
                f"{path.name}:line {index + 1} writes secret-like {output_name} directly to GITHUB_ENV"
            )
    return tuple(findings)


def extract_job_block(text: str, job_name: str) -> str:
    lines = text.splitlines()
    start_index = None
    for index, line in enumerate(lines):
        if line == f"  {job_name}:":
            start_index = index
            break
    if start_index is None:
        return ""

    block = [lines[start_index]]
    for line in lines[start_index + 1 :]:
        if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            break
        block.append(line)
    return "\n".join(block)


def extract_named_step_block(job_block: str, step_name: str) -> str:
    lines = job_block.splitlines()
    start_index = None
    for index, line in enumerate(lines):
        if line.strip() == f"- name: {step_name}":
            start_index = index
            break
    if start_index is None:
        return ""

    block = [lines[start_index]]
    for line in lines[start_index + 1 :]:
        if line.startswith("      - "):
            break
        block.append(line)
    return "\n".join(block)


def find_named_step_line(job_block: str, step_name: str) -> int | None:
    for index, line in enumerate(job_block.splitlines(), start=1):
        if line.strip() == f"- name: {step_name}":
            return index
    return None


def extract_uses_step_blocks(text: str, action: str) -> tuple[tuple[int, str], ...]:
    lines = text.splitlines()
    blocks: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if line.strip() != f"- uses: {action}":
            continue
        base_indent = len(line) - len(line.lstrip(" "))
        block = [line]
        for next_line in lines[index + 1 :]:
            stripped = next_line.lstrip(" ")
            next_indent = len(next_line) - len(stripped)
            if next_indent == base_indent and stripped.startswith("- "):
                break
            block.append(next_line)
        blocks.append((index + 1, "\n".join(block)))
    return tuple(blocks)


FOLDED_RUN_DECLARATION_RE = re.compile(
    r"^(\s*)run:\s*>(?:[+-]?\d?|\d?[+-]?)?\s*(?:#.*)?$"
)
LITERAL_RUN_DECLARATION_RE = re.compile(
    r"^(\s*)run:\s*\|(?:[+-]?\d?|\d?[+-]?)?\s*(?:#.*)?$"
)
SHELL_CONTINUATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\\\r?\n\s*"),
    re.compile(r"`\r?\n\s*"),
    re.compile(r"\^\r?\n\s*"),
)


def normalize_shell_continuations(text: str) -> str:
    normalized = text
    for pattern in SHELL_CONTINUATION_PATTERNS:
        normalized = pattern.sub("", normalized)
    return normalized


def extract_folded_run_blocks(text: str) -> tuple[tuple[int, str], ...]:
    lines = text.splitlines()
    blocks: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = FOLDED_RUN_DECLARATION_RE.match(lines[index])
        if match is None:
            index += 1
            continue

        line_number = index + 1
        base_indent = len(match.group(1))
        folded_lines: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                folded_lines.append("")
                index += 1
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= base_indent:
                break
            folded_lines.append(line.strip())
            index += 1
        if folded_lines:
            blocks.append((line_number, " ".join(folded_lines)))
    return tuple(blocks)


def extract_literal_run_blocks(text: str) -> tuple[tuple[int, str], ...]:
    lines = text.splitlines()
    blocks: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = LITERAL_RUN_DECLARATION_RE.match(lines[index])
        if match is None:
            index += 1
            continue

        line_number = index + 1
        base_indent = len(match.group(1))
        literal_lines: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                literal_lines.append("")
                index += 1
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= base_indent:
                break
            literal_lines.append(line.strip())
            index += 1
        if literal_lines:
            blocks.append((line_number, "\n".join(literal_lines)))
    return tuple(blocks)


def audit_checkout_credential_persistence(path: Path) -> tuple[str, ...]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    issues: list[str] = []
    for line_number, block in extract_uses_step_blocks(text, "actions/checkout@v6"):
        if "persist-credentials: false" not in block:
            issues.append(
                f"{path.name}:checkout step at line {line_number} must set "
                "persist-credentials=false"
            )
    return tuple(issues)


def format_forbidden_workflow_command_issue(
    path: Path, location: str, description: str, command_signature: str
) -> str:
    return (
        f"{path.name}{location} must not use {description}: {command_signature}; "
        f"{WORKFLOW_COMMAND_DIAGNOSTIC_GUARD}"
    )


def audit_forbidden_workflow_commands(path: Path) -> tuple[str, ...]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    issues: list[str] = []
    seen_fragments: set[str] = set()
    seen_patterns: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for fragment, description in FORBIDDEN_WORKFLOW_COMMAND_FRAGMENTS:
            if fragment in line:
                issue = format_forbidden_workflow_command_issue(
                    path, f":line {line_number}", description, fragment
                )
                seen_fragments.add(fragment)
                issues.append(issue)
        for command, pattern, description in FORBIDDEN_WORKFLOW_COMMAND_PATTERNS:
            if pattern.search(line):
                issue = format_forbidden_workflow_command_issue(
                    path, f":line {line_number}", description, command
                )
                seen_patterns.add(command)
                issues.append(issue)
    continuation_normalized = normalize_shell_continuations(text)
    for fragment, description in FORBIDDEN_WORKFLOW_COMMAND_FRAGMENTS:
        if fragment in seen_fragments or fragment not in continuation_normalized:
            continue
        issues.append(
            format_forbidden_workflow_command_issue(path, "", description, fragment)
        )
    for command, pattern, description in FORBIDDEN_WORKFLOW_COMMAND_PATTERNS:
        if command in seen_patterns or not pattern.search(continuation_normalized):
            continue
        issues.append(
            format_forbidden_workflow_command_issue(path, "", description, command)
        )
    for line_number, block in extract_folded_run_blocks(text):
        for fragment, description in FORBIDDEN_WORKFLOW_COMMAND_FRAGMENTS:
            if fragment in seen_fragments or fragment not in block:
                continue
            seen_fragments.add(fragment)
            issues.append(
                format_forbidden_workflow_command_issue(
                    path,
                    f":folded run block at line {line_number}",
                    description,
                    fragment,
                )
            )
        for command, pattern, description in FORBIDDEN_WORKFLOW_COMMAND_PATTERNS:
            if command in seen_patterns or not pattern.search(block):
                continue
            seen_patterns.add(command)
            issues.append(
                format_forbidden_workflow_command_issue(
                    path,
                    f":folded run block at line {line_number}",
                    description,
                    command,
                )
            )
        for command, pattern, description in FORBIDDEN_WORKFLOW_BLOCK_PATTERNS:
            if command in seen_patterns or not pattern.search(block):
                continue
            seen_patterns.add(command)
            issues.append(
                format_forbidden_workflow_command_issue(
                    path,
                    f":folded run block at line {line_number}",
                    description,
                    command,
                )
            )
    for line_number, block in extract_literal_run_blocks(text):
        for command, pattern, description in FORBIDDEN_WORKFLOW_BLOCK_PATTERNS:
            if command in seen_patterns or not pattern.search(block):
                continue
            seen_patterns.add(command)
            issues.append(
                format_forbidden_workflow_command_issue(
                    path,
                    f":literal run block at line {line_number}",
                    description,
                    command,
                )
            )
    return tuple(issues)


def audit_required_release_preflight_steps(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "release-preflight")
    issues: list[str] = []
    if not block:
        return ("release.yml must define release-preflight job",)

    for label, snippet in RELEASE_PREFLIGHT_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:release-preflight is missing {label}")

    for step_name, description, required_snippets in RELEASE_PREFLIGHT_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"release.yml:release-preflight must {description}")
            continue
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(
                    f"release.yml:release-preflight {description} is missing {label}"
                )
    return tuple(issues)


def audit_required_release_publication_gate(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "linux-repository-publication")
    issues: list[str] = []
    if not block:
        return ("release.yml must define linux-repository-publication job",)
    if "if: always() && startsWith(github.ref, 'refs/tags/v')" not in block:
        issues.append(
            "release.yml:linux-repository-publication must be tag-gated "
            "and always evaluate upstream results"
        )
    for label, snippet in RELEASE_PUBLICATION_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:linux-repository-publication is missing {label}")

    step = extract_named_step_block(block, RELEASE_PUBLICATION_GATE_STEP)
    if not step:
        issues.append(
            "release.yml:linux-repository-publication must check "
            "Linux repository publication results"
        )
        return tuple(issues)
    for label, snippet in RELEASE_PUBLICATION_GATE_SNIPPETS:
        if snippet not in step:
            issues.append(f"release.yml:linux-repository-publication gate is missing {label}")
    return tuple(issues)


def audit_required_npm_publication_gate(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "npm-publish")
    issues: list[str] = []
    if not block:
        return ("release.yml must define npm-publish job",)
    for label, snippet in NPM_PUBLISH_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:npm-publish is missing {label}")

    for step_name, description, required_snippets in NPM_PUBLISH_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"release.yml:npm-publish must {description}")
            continue
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(f"release.yml:npm-publish {description} is missing {label}")
    return tuple(issues)


def audit_required_package_checks_job(path: Path) -> tuple[str, ...]:
    if path.name == "release.yml":
        required_job_snippets = PACKAGES_JOB_SNIPPETS
    elif path.name == "ci.yml":
        required_job_snippets = CI_PACKAGES_JOB_SNIPPETS
    else:
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "packages")
    issues: list[str] = []
    if not block:
        return (f"{path.name} must define packages job",)
    for label, snippet in required_job_snippets:
        if snippet not in block:
            issues.append(f"{path.name}:packages is missing {label}")

    for step_name, description, required_snippets in PACKAGES_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"{path.name}:packages must {description}")
            continue
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(f"{path.name}:packages {description} is missing {label}")
    return tuple(issues)


def extract_ci_rust_matrix_os(job_block: str) -> tuple[str, ...]:
    lines = job_block.splitlines()
    for index, line in enumerate(lines):
        if not line.strip().startswith("os:"):
            continue
        base_indent = len(line) - len(line.lstrip(" "))
        _, value = line.split(":", 1)
        inline_sequence = parse_inline_sequence(value)
        if inline_sequence is not None:
            return tuple(inline_sequence)
        entries: list[str] = []
        for next_line in lines[index + 1 :]:
            if not next_line.strip():
                continue
            stripped = next_line.lstrip(" ")
            next_indent = len(next_line) - len(stripped)
            if next_indent <= base_indent:
                break
            if stripped.startswith("- "):
                entries.append(scalar_value(stripped[2:]))
        return tuple(entries)
    return ()


def audit_required_ci_rust_job(path: Path) -> tuple[str, ...]:
    if path.name != "ci.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "rust")
    issues: list[str] = []
    if not block:
        return ("ci.yml must define rust job",)
    for label, snippet in CI_RUST_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"ci.yml:rust is missing {label}")
    matrix_os = set(extract_ci_rust_matrix_os(block))
    expected_os = {runner for _label, runner in CI_RUST_REQUIRED_OS}
    if not matrix_os:
        issues.append("ci.yml:rust must define OS runner matrix")
    for label, runner in CI_RUST_REQUIRED_OS:
        if runner not in matrix_os:
            issues.append(f"ci.yml:rust is missing {label}")
    for runner in sorted(matrix_os - expected_os):
        issues.append(f"ci.yml:rust uses unexpected OS runner matrix entry: {runner}")

    for step_name, description, required_snippets in CI_RUST_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"ci.yml:rust must {description}")
            continue
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(f"ci.yml:rust {description} is missing {label}")
    return tuple(issues)


def audit_required_build_job(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "build")
    issues: list[str] = []
    if not block:
        return ("release.yml must define build job",)

    for label, snippet in BUILD_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:build is missing {label}")

    for step_name, description, required_snippets in BUILD_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"release.yml:build must {description}")
            continue
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(f"release.yml:build {description} is missing {label}")
    upload_line = find_named_step_line(block, "Upload artifact")
    attest_line = find_named_step_line(block, "Attest release artifact provenance")
    if upload_line is not None and attest_line is not None and upload_line > attest_line:
        issues.append(
            "release.yml:build must upload artifacts before attestation to avoid "
            "Windows artifact file lock races"
        )
    return tuple(issues)


def audit_required_github_release_gate(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "github-release")
    issues: list[str] = []
    if not block:
        return ("release.yml must define github-release job",)

    for label, snippet in GITHUB_RELEASE_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:github-release is missing {label}")

    for step_name, description, required_snippets in GITHUB_RELEASE_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"release.yml:github-release must {description}")
            continue
        if step_name == "Publish release assets" and "--clobber" in step:
            issues.append(
                "release.yml:github-release publish release assets must not use "
                "gh release upload/create clobber"
            )
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(
                    f"release.yml:github-release {description} is missing {label}"
                )
    return tuple(issues)


def audit_required_unsigned_preview_release_gate(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "manual-preview-release")
    issues: list[str] = []
    if not block:
        return ("release.yml must define manual-preview-release job",)

    for label, snippet in UNSIGNED_PREVIEW_RELEASE_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:manual-preview-release is missing {label}")

    for step_name, description, required_snippets in UNSIGNED_PREVIEW_RELEASE_REQUIRED_STEPS:
        step = extract_named_step_block(block, step_name)
        if not step:
            issues.append(f"release.yml:manual-preview-release must {description}")
            continue
        if step_name == "Publish unsigned preview prerelease" and "--clobber" in step:
            issues.append(
                "release.yml:manual-preview-release publish unsigned preview "
                "prerelease must not use gh release upload/create clobber"
            )
        for label, snippet in required_snippets:
            if snippet not in step:
                issues.append(
                    "release.yml:manual-preview-release "
                    f"{description} is missing {label}"
                )
    return tuple(issues)


def audit_required_linux_repository_publication_jobs(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    issues: list[str] = []
    pages_block = extract_job_block(text, "linux-repository-pages")
    if not pages_block:
        issues.append("release.yml must define linux-repository-pages job")
    else:
        for label, snippet in LINUX_REPOSITORY_PAGES_JOB_SNIPPETS:
            if snippet not in pages_block:
                issues.append(
                    f"release.yml:linux-repository-pages is missing {label}"
                )

    custom_block = extract_job_block(text, "custom-linux-repository-publish")
    if not custom_block:
        issues.append("release.yml must define custom-linux-repository-publish job")
        return tuple(issues)

    for label, snippet in CUSTOM_LINUX_REPOSITORY_JOB_SNIPPETS:
        if snippet not in custom_block:
            issues.append(
                f"release.yml:custom-linux-repository-publish is missing {label}"
            )

    publish_step = extract_named_step_block(
        custom_block,
        CUSTOM_LINUX_REPOSITORY_PUBLISH_STEP,
    )
    if not publish_step:
        issues.append(
            "release.yml:custom-linux-repository-publish must publish custom "
            "hosted Linux repository and verify endpoint"
        )
        return tuple(issues)

    for label, snippet in CUSTOM_LINUX_REPOSITORY_PUBLISH_SNIPPETS:
        if snippet not in publish_step:
            issues.append(
                "release.yml:custom-linux-repository-publish publish custom "
                f"hosted Linux repository and verify endpoint is missing {label}"
            )
    return tuple(issues)


def audit_required_production_readiness_job(path: Path) -> tuple[str, ...]:
    if path.name != "release.yml":
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"failed to read workflow {path.name}: {exc}") from exc

    block = extract_job_block(text, "production-readiness")
    issues: list[str] = []
    if not block:
        return ("release.yml must define production-readiness job",)

    for label, snippet in PRODUCTION_READINESS_JOB_SNIPPETS:
        if snippet not in block:
            issues.append(f"release.yml:production-readiness is missing {label}")

    step = extract_named_step_block(block, PRODUCTION_READINESS_STEP)
    if not step:
        issues.append("release.yml:production-readiness must run production readiness smoke gate")
        return tuple(issues)

    for label, snippet in PRODUCTION_READINESS_STEP_SNIPPETS:
        if snippet not in step:
            issues.append(
                "release.yml:production-readiness production readiness smoke gate "
                f"is missing {label}"
            )
    return tuple(issues)


def is_secret_like_env_name(name: str) -> bool:
    return any(token in name for token in SECRET_LIKE_ENV_TOKENS)


def has_nearby_github_env_redirect(lines: list[str], index: int) -> bool:
    start = max(0, index - 3)
    end = min(len(lines), index + 4)
    return any("GITHUB_ENV" in lines[position] for position in range(start, end))


def workflow_trigger(payload: dict[str, Any]) -> Any:
    if "on" in payload:
        return payload["on"]
    # PyYAML's YAML 1.1 resolver treats unquoted "on" as a boolean key.
    return payload.get(True)


def event_names(trigger: Any) -> tuple[str, ...]:
    if isinstance(trigger, str):
        return (trigger,)
    if isinstance(trigger, list):
        return tuple(sorted(item for item in trigger if isinstance(item, str)))
    if isinstance(trigger, dict):
        return tuple(sorted(str(key) for key in trigger.keys()))
    return ()


def normalize_permissions(value: Any, *, scope: str) -> dict[str, str] | str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        raise ValueError(f"{scope} permissions must be a mapping or permission shorthand")
    normalized: dict[str, str] = {}
    for key, permission_value in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{scope} permission keys must be strings")
        if not isinstance(permission_value, str):
            raise ValueError(f"{scope} permission values must be strings")
        normalized[key] = permission_value
    return normalized


def normalize_needs(value: Any, *, scope: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list):
        raise ValueError(f"{scope} needs must be a string or list of strings")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{scope} needs entries must be strings")
        normalized.append(item)
    return tuple(normalized)


def format_job(workflow_name: str, job_name: str) -> str:
    return f"{workflow_name}:{job_name}"


def mapping_contains_write(permissions: dict[str, str]) -> bool:
    return any(value == "write" for value in permissions.values())


def format_permission_diagnostic_suffix() -> str:
    return f"; {PERMISSION_DIAGNOSTIC_GUARD}"


def describe_permission_key(key: str) -> str:
    if key in ALLOWED_PERMISSION_KEYS:
        return key
    return "unrecognized key"


def describe_actual_permission_value(value: str | None) -> str:
    if value is None:
        return "unset"
    if value in ALLOWED_PERMISSION_VALUES:
        return "nonmatching value"
    return "invalid value"


def audit_mapping(
    *,
    permissions: dict[str, str],
    expected: dict[str, str],
    scope: str,
    allow_write: bool,
) -> list[str]:
    issues: list[str] = []
    for key, value in permissions.items():
        if key not in ALLOWED_PERMISSION_KEYS:
            issues.append(
                f"{scope} uses unexpected permission key"
                f"{format_permission_diagnostic_suffix()}"
            )
        if value not in ALLOWED_PERMISSION_VALUES:
            issues.append(
                f"{scope} uses unexpected permission value for "
                f"{describe_permission_key(key)}{format_permission_diagnostic_suffix()}"
            )
        if value == "write" and not allow_write:
            issues.append(
                f"{scope} must not request write permission for "
                f"{describe_permission_key(key)}{format_permission_diagnostic_suffix()}"
            )
    for key, expected_value in expected.items():
        actual_value = permissions.get(key)
        if actual_value != expected_value:
            issues.append(
                f"{scope} must set {key}={expected_value}; found "
                f"{describe_actual_permission_value(actual_value)}"
                f"{format_permission_diagnostic_suffix()}"
            )
    for key, value in permissions.items():
        if key not in expected:
            issues.append(
                f"{scope} has extra permission {describe_permission_key(key)}"
                f"{format_permission_diagnostic_suffix()}"
            )
    return issues


def audit_release_job_needs(workflow_name: str, jobs: dict[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    for (expected_workflow, job_name), expected_needs in EXPECTED_RELEASE_JOB_NEEDS.items():
        if expected_workflow != workflow_name:
            continue
        scope = format_job(workflow_name, job_name)
        job_payload = jobs.get(job_name)
        if job_payload is None:
            issues.append(f"{workflow_name} must define {job_name} job")
            continue
        if not isinstance(job_payload, dict):
            continue
        actual_needs = normalize_needs(job_payload.get("needs"), scope=scope)
        actual_needs_set = set(actual_needs)
        for expected_need in expected_needs:
            if expected_need not in actual_needs_set:
                issues.append(f"{scope} must depend on {expected_need}")
    return tuple(issues)


def audit_workflows(workflow_paths: tuple[Path, ...]) -> WorkflowPermissionsReadiness:
    issues: list[str] = []
    checked: list[str] = []
    explicit_top_level: list[str] = []
    write_jobs: list[str] = []
    unsafe_env_writes: list[str] = []
    forbidden_events_seen: set[str] = set()
    forbidden_workflow_commands: list[str] = []

    if not workflow_paths:
        issues.append("no workflow files found")

    for path in workflow_paths:
        workflow_name = path.name
        checked.append(workflow_name)
        payload = load_workflow(path)
        for finding in audit_environment_file_writes(path):
            unsafe_env_writes.append(finding)
            issues.append(finding)
        for finding in audit_forbidden_workflow_commands(path):
            forbidden_workflow_commands.append(finding)
            issues.append(finding)
        issues.extend(audit_checkout_credential_persistence(path))
        issues.extend(audit_required_release_preflight_steps(path))
        issues.extend(audit_required_package_checks_job(path))
        issues.extend(audit_required_ci_rust_job(path))
        issues.extend(audit_required_production_readiness_job(path))
        issues.extend(audit_required_build_job(path))
        issues.extend(audit_required_unsigned_preview_release_gate(path))
        issues.extend(audit_required_github_release_gate(path))
        issues.extend(audit_required_linux_repository_publication_jobs(path))
        issues.extend(audit_required_release_publication_gate(path))
        issues.extend(audit_required_npm_publication_gate(path))

        events = event_names(workflow_trigger(payload))
        for event in events:
            if event in FORBIDDEN_EVENTS:
                forbidden_events_seen.add(f"{workflow_name}:{event}")
                issues.append(f"{workflow_name} uses forbidden event: {event}")

        top_permissions = normalize_permissions(
            payload.get("permissions"),
            scope=f"{workflow_name} top-level",
        )
        if top_permissions is None:
            issues.append(f"{workflow_name} must declare explicit top-level permissions")
        elif isinstance(top_permissions, str):
            issues.append(f"{workflow_name} must not use top-level permissions shorthand: {top_permissions}")
        else:
            explicit_top_level.append(workflow_name)
            issues.extend(
                audit_mapping(
                    permissions=top_permissions,
                    expected=TOP_LEVEL_PERMISSIONS,
                    scope=f"{workflow_name} top-level",
                    allow_write=False,
                )
            )

        jobs = payload.get("jobs")
        if not isinstance(jobs, dict):
            issues.append(f"{workflow_name} must define jobs as a mapping")
            continue

        issues.extend(audit_release_job_needs(workflow_name, jobs))

        for job_name, job_payload in jobs.items():
            if not isinstance(job_name, str):
                issues.append(f"{workflow_name} contains a non-string job id")
                continue
            if not isinstance(job_payload, dict):
                issues.append(f"{format_job(workflow_name, job_name)} must be a mapping")
                continue
            scope = format_job(workflow_name, job_name)
            expected_permissions = EXPECTED_JOB_PERMISSIONS.get((workflow_name, job_name))
            job_permissions = normalize_permissions(
                job_payload.get("permissions"),
                scope=scope,
            )
            if job_permissions is None:
                continue
            if isinstance(job_permissions, str):
                issues.append(f"{scope} must not use permissions shorthand: {job_permissions}")
                continue
            has_write = mapping_contains_write(job_permissions)
            if has_write:
                write_jobs.append(scope)
            if expected_permissions is None:
                issues.extend(
                    audit_mapping(
                        permissions=job_permissions,
                        expected=TOP_LEVEL_PERMISSIONS,
                        scope=scope,
                        allow_write=False,
                    )
                )
            else:
                issues.extend(
                    audit_mapping(
                        permissions=job_permissions,
                        expected=expected_permissions,
                        scope=scope,
                        allow_write=True,
                    )
                )

    return WorkflowPermissionsReadiness(
        ready=not issues,
        workflow_count=len(workflow_paths),
        checked_workflows=tuple(sorted(checked)),
        workflows_with_explicit_top_level_permissions=tuple(sorted(explicit_top_level)),
        jobs_with_write_permissions=tuple(sorted(write_jobs)),
        unsafe_environment_file_writes=tuple(sorted(unsafe_env_writes)),
        forbidden_events=tuple(sorted(forbidden_events_seen)),
        forbidden_workflow_commands=tuple(sorted(forbidden_workflow_commands)),
        issues=tuple(issues),
    )


def find_workflow_paths(workflow_dir: Path) -> tuple[Path, ...]:
    if not workflow_dir.exists():
        return ()
    paths = [
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    ]
    return tuple(sorted(paths, key=lambda item: item.name))


def print_text_report(report: WorkflowPermissionsReadiness) -> None:
    if report.ready:
        print("GitHub workflow permissions readiness passed")
        return
    print("GitHub workflow permissions readiness failed", file=sys.stderr)
    for issue in report.issues:
        print(f"issue: {issue}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflow-dir",
        type=Path,
        default=DEFAULT_WORKFLOW_DIR,
        help="directory containing GitHub workflow YAML files",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = audit_workflows(find_workflow_paths(args.workflow_dir))
    except (OSError, ValueError) as exc:
        print(f"GitHub workflow permissions readiness failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print_text_report(report)
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
