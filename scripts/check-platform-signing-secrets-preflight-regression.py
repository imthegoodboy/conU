#!/usr/bin/env python3
"""Regression checks for platform signing-secret value preflight."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "check-platform-signing-secrets-preflight.py"
SENTINEL = "conu-platform-signing-secret-sentinel"
P12_PASSWORD = "conu-platform-signing-preflight-password"


def main() -> int:
    module = import_preflight()

    env = minimal_env(base64.b64encode(b"not-a-real-pkcs12").decode("ascii"))
    passed = run_preflight(env, "--skip-pkcs12-parse", "--json")
    assert_success(passed)
    report = json.loads(passed.stdout)
    if not report["ready"]:
        raise AssertionError(f"decode-only preflight should pass:\n{passed.stdout}")
    if report["secretValuesDisplayed"] or report["keyMaterialDisplayed"] or report["tokenDisplayed"]:
        raise AssertionError("preflight reported unsafe display guards")

    missing_env = os.environ.copy()
    for name in all_platform_env_names(module):
        missing_env.pop(name, None)
    failed = run_preflight(missing_env, "--skip-pkcs12-parse", "--json")
    assert_failed(failed, "missing")

    invalid_env = minimal_env(base64.b64encode(b"not-a-real-pkcs12").decode("ascii"))
    invalid_env[module.WINDOWS_PFX_ENV] = f"not strict base64 {SENTINEL}"
    invalid_env[module.WINDOWS_TIMESTAMP_URL_ENV] = f"https://user:{SENTINEL}@timestamp.example.invalid/?token={SENTINEL}"
    failed = run_preflight(invalid_env, "--skip-pkcs12-parse")
    assert_failed(failed, "strict base64")
    assert_not_leaked(failed.stdout, SENTINEL)

    malformed_timestamp_env = minimal_env(base64.b64encode(b"not-a-real-pkcs12").decode("ascii"))
    malformed_timestamp_env[
        module.WINDOWS_TIMESTAMP_URL_ENV
    ] = f"https://timestamp-{SENTINEL}.example.invalid:"
    failed = run_preflight(malformed_timestamp_env, "--skip-pkcs12-parse")
    assert_failed(failed, "valid host and authority")
    assert_not_leaked(failed.stdout, SENTINEL)

    invalid_apple_env = minimal_env(base64.b64encode(b"not-a-real-pkcs12").decode("ascii"))
    invalid_apple_env[module.MACOS_NOTARY_APPLE_ID_ENV] = f"{SENTINEL} invalid"
    invalid_apple_env[module.MACOS_NOTARY_TEAM_ID_ENV] = "not-a-team-id"
    failed = run_preflight(invalid_apple_env, "--skip-pkcs12-parse")
    assert_failed(failed, "Apple ID")
    assert_not_leaked(failed.stdout, SENTINEL)

    openssl = shutil.which("openssl")
    if openssl is None:
        print("Platform signing-secret OpenSSL parse regression skipped: openssl is unavailable")
        print("Platform signing-secret preflight regression checks passed")
        return 0

    with tempfile.TemporaryDirectory(prefix="conu-platform-signing-preflight-check-") as temp_text:
        temp = Path(temp_text)
        pkcs12 = create_pkcs12_fixture(openssl, temp)
        pkcs12_base64 = base64.b64encode(pkcs12.read_bytes()).decode("ascii")
        parsed_env = minimal_env(pkcs12_base64)

        passed = run_preflight(parsed_env, "--require-openssl", "--json")
        assert_success(passed)
        report = json.loads(passed.stdout)
        if report["pkcs12Parsed"] != {"windows": True, "macos": True}:
            raise AssertionError(f"expected both PKCS#12 values to parse:\n{passed.stdout}")

        wrong_password_env = parsed_env.copy()
        wrong_password_env[module.MACOS_PASSWORD_ENV] = SENTINEL
        failed = run_preflight(wrong_password_env, "--require-openssl")
        assert_failed(failed, "could not be parsed")
        assert_not_leaked(failed.stdout, SENTINEL)

        cert_only = create_cert_only_pkcs12_fixture(openssl, temp)
        cert_only_env = minimal_env(base64.b64encode(cert_only.read_bytes()).decode("ascii"))
        failed = run_preflight(cert_only_env, "--require-openssl")
        assert_failed(failed, "private key")

    print("Platform signing-secret preflight regression checks passed")
    return 0


def import_preflight() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_platform_signing_secrets_preflight", PREFLIGHT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load platform signing preflight module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def minimal_env(pkcs12_base64: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "CONU_WINDOWS_SIGN_CERT_PFX_BASE64": pkcs12_base64,
            "CONU_WINDOWS_SIGN_CERT_PASSWORD": P12_PASSWORD,
            "CONU_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64": pkcs12_base64,
            "CONU_MACOS_DEVELOPER_ID_APPLICATION_PASSWORD": P12_PASSWORD,
            "CONU_MACOS_CODESIGN_IDENTITY": "Developer ID Application: conU Regression (ABCDE12345)",
            "CONU_MACOS_NOTARY_APPLE_ID": "maintainer@example.invalid",
            "CONU_MACOS_NOTARY_TEAM_ID": "ABCDE12345",
            "CONU_MACOS_NOTARY_PASSWORD": "app-specific-password",
        }
    )
    return env


def all_platform_env_names(module: ModuleType) -> tuple[str, ...]:
    return (
        module.WINDOWS_PFX_ENV,
        module.WINDOWS_PASSWORD_ENV,
        module.WINDOWS_TIMESTAMP_URL_ENV,
        module.MACOS_P12_ENV,
        module.MACOS_PASSWORD_ENV,
        module.MACOS_CODESIGN_IDENTITY_ENV,
        module.MACOS_NOTARY_APPLE_ID_ENV,
        module.MACOS_NOTARY_TEAM_ID_ENV,
        module.MACOS_NOTARY_PASSWORD_ENV,
    )


def create_pkcs12_fixture(openssl: str, temp: Path) -> Path:
    key = temp / "regression.key"
    cert = temp / "regression.crt"
    pkcs12 = temp / "regression.p12"
    run_openssl(
        openssl,
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=conU Platform Signing Preflight Regression",
        ],
    )
    export_pkcs12(openssl, pkcs12, cert, key)
    return pkcs12


def create_cert_only_pkcs12_fixture(openssl: str, temp: Path) -> Path:
    key = temp / "cert-only.key"
    cert = temp / "cert-only.crt"
    pkcs12 = temp / "cert-only.p12"
    run_openssl(
        openssl,
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=conU Platform Signing Preflight Cert Only Regression",
        ],
    )
    export_pkcs12(openssl, pkcs12, cert, None)
    return pkcs12


def export_pkcs12(openssl: str, pkcs12: Path, cert: Path, key: Path | None) -> None:
    env = os.environ.copy()
    env["CONU_REGRESSION_P12_PASSWORD"] = P12_PASSWORD
    command = [
        openssl,
        "pkcs12",
        "-export",
        "-out",
        str(pkcs12),
        "-in",
        str(cert),
        "-passout",
        "env:CONU_REGRESSION_P12_PASSWORD",
    ]
    if key is None:
        command.append("-nokeys")
    else:
        command += ["-inkey", str(key)]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise AssertionError(f"openssl pkcs12 export failed:\n{result.stdout}")


def run_openssl(openssl: str, args: list[str]) -> None:
    result = subprocess.run(
        [openssl, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(f"openssl {' '.join(args)} failed:\n{result.stdout}")


def run_preflight(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREFLIGHT), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )


def assert_success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        raise AssertionError(f"preflight unexpectedly failed:\n{result.stdout}")


def assert_failed(result: subprocess.CompletedProcess[str], expected: str) -> None:
    if result.returncode == 0:
        raise AssertionError("preflight unexpectedly succeeded")
    if expected not in result.stdout:
        raise AssertionError(f"expected {expected!r} in output:\n{result.stdout}")


def assert_not_leaked(output: str, secret: str) -> None:
    if secret in output:
        raise AssertionError(f"sensitive sentinel leaked in output:\n{output}")


if __name__ == "__main__":
    sys.exit(main())
