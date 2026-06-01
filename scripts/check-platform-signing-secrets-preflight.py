#!/usr/bin/env python3
"""Fail-closed preflight for conU Windows/macOS signing secret values."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


MAX_PKCS12_BYTES = 2 * 1024 * 1024

WINDOWS_PFX_ENV = "CONU_WINDOWS_SIGN_CERT_PFX_BASE64"
WINDOWS_PASSWORD_ENV = "CONU_WINDOWS_SIGN_CERT_PASSWORD"
WINDOWS_TIMESTAMP_URL_ENV = "CONU_WINDOWS_TIMESTAMP_URL"

MACOS_P12_ENV = "CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64"
MACOS_PASSWORD_ENV = "CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD"
MACOS_CODESIGN_IDENTITY_ENV = "CONU_MACOS_CODESIGN_IDENTITY"
MACOS_NOTARY_APPLE_ID_ENV = "CONU_MACOS_NOTARY_APPLE_ID"
MACOS_NOTARY_TEAM_ID_ENV = "CONU_MACOS_NOTARY_TEAM_ID"
MACOS_NOTARY_PASSWORD_ENV = "CONU_MACOS_NOTARY_PASSWORD"


@dataclass(frozen=True)
class Pkcs12Secret:
    key: str
    label: str
    data_env: str
    password_env: str


PKCS12_SECRETS: tuple[Pkcs12Secret, ...] = (
    Pkcs12Secret(
        key="windows",
        label="Windows Authenticode certificate",
        data_env=WINDOWS_PFX_ENV,
        password_env=WINDOWS_PASSWORD_ENV,
    ),
    Pkcs12Secret(
        key="macos",
        label="macOS Developer ID certificate",
        data_env=MACOS_P12_ENV,
        password_env=MACOS_PASSWORD_ENV,
    ),
)

TEXT_SECRET_ENVS: tuple[tuple[str, str], ...] = (
    ("macosCodesignIdentity", MACOS_CODESIGN_IDENTITY_ENV),
    ("macosNotaryAppleId", MACOS_NOTARY_APPLE_ID_ENV),
    ("macosNotaryTeamId", MACOS_NOTARY_TEAM_ID_ENV),
    ("macosNotaryPassword", MACOS_NOTARY_PASSWORD_ENV),
)


class PreflightIssue(Exception):
    """A sanitized preflight failure that must not include secret values."""


def main() -> int:
    args = parse_args()
    report = audit_environment(
        os.environ,
        require_openssl=args.require_openssl,
        skip_pkcs12_parse=args.skip_pkcs12_parse,
        openssl_path=args.openssl,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ready"]:
        print("Platform signing secret value preflight passed.")
    else:
        print("Platform signing secret value preflight failed.")
        if report["missing"]:
            print("Missing required environment variable(s):")
            for name in report["missing"]:
                print(f"  - {name}")
        if report["issues"]:
            print("Issue(s):")
            for issue in report["issues"]:
                print(f"  - {issue}")

    return 0 if report["ready"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-openssl",
        action="store_true",
        help="fail when OpenSSL is unavailable and require PKCS#12 cert/key parsing",
    )
    parser.add_argument(
        "--skip-pkcs12-parse",
        action="store_true",
        help="only validate required env values and strict base64 structure",
    )
    parser.add_argument(
        "--openssl",
        help="path to the OpenSSL executable; defaults to PATH lookup",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a machine-readable report without secret values",
    )
    return parser.parse_args()


def audit_environment(
    env: os._Environ[str] | dict[str, str],
    *,
    require_openssl: bool = False,
    skip_pkcs12_parse: bool = False,
    openssl_path: str | None = None,
) -> dict[str, object]:
    missing: list[str] = []
    issues: list[str] = []
    checks: dict[str, bool] = {}
    decoded_blobs: dict[str, bytes] = {}

    openssl = None if skip_pkcs12_parse else resolve_openssl(openssl_path)
    checks["opensslAvailable"] = bool(openssl)
    checks["opensslRequired"] = require_openssl
    checks["pkcs12ParseSkipped"] = skip_pkcs12_parse

    if require_openssl and skip_pkcs12_parse:
        issues.append("--require-openssl and --skip-pkcs12-parse cannot be used together")

    if require_openssl and not skip_pkcs12_parse and openssl is None:
        issues.append("OpenSSL is required to validate Windows/macOS PKCS#12 signing secrets")

    for secret in PKCS12_SECRETS:
        data_value = env.get(secret.data_env, "")
        password_value = env.get(secret.password_env, "")
        checks[f"{secret.key}Pkcs12Configured"] = bool(data_value)
        checks[f"{secret.key}PasswordConfigured"] = bool(password_value)

        if not data_value:
            missing.append(secret.data_env)
        else:
            try:
                decoded = decode_base64_secret(secret.data_env, data_value)
            except PreflightIssue as exc:
                issues.append(str(exc))
            else:
                decoded_blobs[secret.key] = decoded
                checks[f"{secret.key}Pkcs12StrictBase64"] = True
                checks[f"{secret.key}Pkcs12NonEmpty"] = True
                checks[f"{secret.key}Pkcs12SizeAllowed"] = True

        if not password_value:
            missing.append(secret.password_env)

    for key, name in TEXT_SECRET_ENVS:
        value = env.get(name, "")
        checks[f"{key}Configured"] = bool(value)
        if not value:
            missing.append(name)

    validate_text_secret_shapes(env, checks, issues)
    validate_timestamp_url(env.get(WINDOWS_TIMESTAMP_URL_ENV, ""), checks, issues)

    parsed: dict[str, bool | None] = {}
    if skip_pkcs12_parse or openssl is None:
        for secret in PKCS12_SECRETS:
            parsed[secret.key] = None
    else:
        with tempfile.TemporaryDirectory(prefix="conu-platform-signing-preflight-") as temp_text:
            temp = Path(temp_text)
            for secret in PKCS12_SECRETS:
                decoded = decoded_blobs.get(secret.key)
                password = env.get(secret.password_env, "")
                if decoded is None or not password:
                    parsed[secret.key] = False
                    checks[f"{secret.key}Pkcs12Parsed"] = False
                    continue
                try:
                    validate_pkcs12_with_openssl(
                        openssl,
                        secret,
                        decoded,
                        password,
                        temp,
                    )
                except PreflightIssue as exc:
                    parsed[secret.key] = False
                    checks[f"{secret.key}Pkcs12Parsed"] = False
                    issues.append(str(exc))
                else:
                    parsed[secret.key] = True
                    checks[f"{secret.key}Pkcs12Parsed"] = True

    ready = not missing and not issues
    return {
        "ready": ready,
        "checks": checks,
        "missing": tuple(sorted(set(missing))),
        "issues": tuple(issues),
        "pkcs12Parsed": parsed,
        "secretValuesDisplayed": False,
        "keyMaterialDisplayed": False,
        "tokenDisplayed": False,
    }


def resolve_openssl(path: str | None) -> str | None:
    if path:
        return path
    return shutil.which("openssl")


def decode_base64_secret(name: str, value: str) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise PreflightIssue(f"{name} must contain strict base64 data") from exc
    if not decoded:
        raise PreflightIssue(f"{name} decoded to an empty PKCS#12 blob")
    if len(decoded) > MAX_PKCS12_BYTES:
        raise PreflightIssue(f"{name} decoded PKCS#12 blob is too large")
    return decoded


def validate_text_secret_shapes(
    env: os._Environ[str] | dict[str, str],
    checks: dict[str, bool],
    issues: list[str],
) -> None:
    apple_id = env.get(MACOS_NOTARY_APPLE_ID_ENV, "")
    if apple_id:
        valid = "@" in apple_id and not any(character.isspace() for character in apple_id)
        checks["macosNotaryAppleIdShapeValid"] = valid
        if not valid:
            issues.append(f"{MACOS_NOTARY_APPLE_ID_ENV} must look like a single Apple ID email")

    team_id = env.get(MACOS_NOTARY_TEAM_ID_ENV, "")
    if team_id:
        valid = len(team_id) == 10 and team_id.isalnum() and team_id.upper() == team_id
        checks["macosNotaryTeamIdShapeValid"] = valid
        if not valid:
            issues.append(f"{MACOS_NOTARY_TEAM_ID_ENV} must be a 10-character uppercase Apple Team ID")


def validate_timestamp_url(
    value: str,
    checks: dict[str, bool],
    issues: list[str],
) -> None:
    if not value:
        checks["windowsTimestampUrlValid"] = True
        return

    parsed = urlparse(value)
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        host = None
        port = None
    valid = (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and bool(host)
        and not (port is None and parsed.netloc.rsplit("@", 1)[-1].endswith(":"))
        and not parsed.username
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and not any(character.isspace() for character in value)
    )
    checks["windowsTimestampUrlValid"] = valid
    if not valid:
        issues.append(
            f"{WINDOWS_TIMESTAMP_URL_ENV} must be an absolute http(s) URL with a valid host and authority, without credentials, query, or fragment"
        )


def validate_pkcs12_with_openssl(
    openssl: str,
    secret: Pkcs12Secret,
    blob: bytes,
    password: str,
    temp: Path,
) -> None:
    pkcs12_path = temp / f"{secret.key}.p12"
    certs_path = temp / f"{secret.key}-certs.pem"
    key_path = temp / f"{secret.key}-key.pem"
    pkcs12_path.write_bytes(blob)

    if not run_pkcs12_extract(
        openssl,
        pkcs12_path,
        certs_path,
        password,
        ["-nokeys"],
    ):
        raise PreflightIssue(f"{secret.label} could not be parsed with the configured password")
    certs = certs_path.read_text(encoding="utf-8", errors="ignore") if certs_path.exists() else ""
    if "BEGIN CERTIFICATE" not in certs:
        raise PreflightIssue(f"{secret.label} does not contain a certificate")

    if not run_pkcs12_extract(
        openssl,
        pkcs12_path,
        key_path,
        password,
        ["-nocerts"],
        export_password=secrets.token_urlsafe(24),
    ):
        raise PreflightIssue(f"{secret.label} private key could not be parsed with the configured password")
    key_data = key_path.read_text(encoding="utf-8", errors="ignore") if key_path.exists() else ""
    if "PRIVATE KEY" not in key_data:
        raise PreflightIssue(f"{secret.label} does not contain a private key")


def run_pkcs12_extract(
    openssl: str,
    pkcs12_path: Path,
    output_path: Path,
    password: str,
    extract_args: list[str],
    *,
    export_password: str | None = None,
) -> bool:
    for legacy in (False, True):
        env = os.environ.copy()
        env["CONU_PLATFORM_PREFLIGHT_PKCS12_PASSWORD"] = password
        command = [
            openssl,
            "pkcs12",
            "-in",
            str(pkcs12_path),
            *extract_args,
            "-passin",
            "env:CONU_PLATFORM_PREFLIGHT_PKCS12_PASSWORD",
            "-out",
            str(output_path),
        ]
        if export_password is not None:
            env["CONU_PLATFORM_PREFLIGHT_EXPORT_PASSWORD"] = export_password
            command += ["-passout", "env:CONU_PLATFORM_PREFLIGHT_EXPORT_PASSWORD"]
        if legacy:
            command.insert(2, "-legacy")

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        if result.returncode == 0:
            return True
    return False

if __name__ == "__main__":
    sys.exit(main())
