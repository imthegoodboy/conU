#!/usr/bin/env python3
"""Regression checks for Linux signing-secret preflight."""

from __future__ import annotations

import base64
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
PREFLIGHT = ROOT / "scripts" / "check-linux-signing-secrets-preflight.py"
PASSPHRASE = "conu-linux-signing-preflight-regression-passphrase"
USER_ID = "conU Linux Signing Preflight Regression <noreply@github.com>"
WRONG_FINGERPRINT = "F" * 40
SENSITIVE_FAILURE_VALUES = (
    "npm_fakeLinuxSigningToken1234567890",
    "ghp_fakeLinuxSigningToken1234567890",
    "fake-bearer-token-1234567890",
    "fake-basic-token-1234567890",
    "fake-node-auth-token-1234567890",
    "fake-url-password-1234567890",
    "fake-query-token-1234567890",
    "fake-private-key-1234567890",
    "fake-amz-signature-1234567890",
    "fake-amz-credential-1234567890",
    "fake-amz-security-token-1234567890",
    "fake-azure-sas-signature-1234567890",
)


def main() -> int:
    run_common_output_redaction_tests()
    run_preflight_output_redaction_tests()

    gpg = shutil.which("gpg")
    if gpg is None:
        print(
            "Linux signing-secret redaction checks passed; "
            "GPG integration regression skipped: gpg is unavailable"
        )
        return 0

    with tempfile.TemporaryDirectory(prefix="conu-linux-signing-preflight-check-") as temp_text:
        temp = Path(temp_text)
        key_home = temp / "key-home"
        key_home.mkdir(mode=0o700)

        key_id = create_test_key(gpg, key_home)
        private_key = export_secret_key(gpg, key_home, key_id)

        env = os.environ.copy()
        env["CONU_LINUX_GPG_PRIVATE_KEY_BASE64"] = base64.b64encode(private_key).decode("ascii")
        env["CONU_LINUX_GPG_PASSPHRASE"] = PASSPHRASE
        env["CONU_LINUX_GPG_KEY_ID"] = key_id
        env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = key_id
        passed = subprocess.run(
            [sys.executable, str(PREFLIGHT)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        if "Linux signing secret preflight passed." not in passed.stdout:
            raise AssertionError("preflight did not report success")

        missing_env = os.environ.copy()
        for name in (
            "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
            "CONU_LINUX_GPG_PASSPHRASE",
            "CONU_LINUX_GPG_KEY_ID",
            "CONU_LINUX_GPG_KEY_FINGERPRINT",
        ):
            missing_env.pop(name, None)
        assert_failed(missing_env, "missing required environment variable")

        invalid_base64_env = env.copy()
        invalid_base64_env["CONU_LINUX_GPG_PRIVATE_KEY_BASE64"] = "not strict base64"
        assert_failed(invalid_base64_env, "strict base64 data")

        invalid_fingerprint_env = env.copy()
        invalid_fingerprint_env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = "not-a-fingerprint"
        assert_failed(invalid_fingerprint_env, "full 40-hex-character")

        mismatch_env = env.copy()
        mismatch_env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = WRONG_FINGERPRINT
        assert_failed(
            mismatch_env,
            "fingerprint mismatch",
            forbidden=(WRONG_FINGERPRINT, key_id),
        )

        wrong_passphrase_env = env.copy()
        wrong_passphrase_env["CONU_LINUX_GPG_PASSPHRASE"] = "wrong-passphrase"
        assert_failed(wrong_passphrase_env, "gpg failed")

    print("Linux signing-secret preflight regression checks passed")
    return 0


def run_common_output_redaction_tests() -> None:
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        import linux_gpg_common
    finally:
        try:
            sys.path.remove(str(SCRIPT_DIR))
        except ValueError:
            pass

    original_run_gpg_text = linux_gpg_common.run_gpg_text
    original_subprocess_run = linux_gpg_common.subprocess.run
    actual = "A" * 40
    other = "B" * 40
    expected = WRONG_FINGERPRINT
    try:
        assert_common_command_output_redacts(linux_gpg_common)

        linux_gpg_common.run_gpg_text = (
            lambda *_args, **_kwargs: f"sec:::::::::\nfpr:::::::::{actual}:\n"
        )
        assert_common_failed(
            linux_gpg_common,
            expected,
            "fingerprint mismatch",
            forbidden=(expected, actual),
        )

        linux_gpg_common.run_gpg_text = (
            lambda *_args, **_kwargs: (
                f"sec:::::::::\nfpr:::::::::{actual}:\n"
                f"sec:::::::::\nfpr:::::::::{other}:\n"
            )
        )
        assert_common_failed(
            linux_gpg_common,
            actual,
            "found 2 primary secret key(s)",
            forbidden=(actual, other),
        )
    finally:
        linux_gpg_common.run_gpg_text = original_run_gpg_text
        linux_gpg_common.subprocess.run = original_subprocess_run


def run_preflight_output_redaction_tests() -> None:
    preflight = load_preflight()
    original_subprocess_run = preflight.subprocess.run
    raw = sensitive_command_output()
    try:

        def failed_run(*args, **_kwargs):
            command = args[0] if args else "gpg"
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=command,
                output=raw.encode("utf-8"),
            )

        preflight.subprocess.run = failed_run
        try:
            preflight.run_gpg("gpg", {}, ["--fixture"])
        except SystemExit as exc:
            rendered = str(exc)
        else:
            raise AssertionError("Linux signing-secret preflight unexpectedly passed")
    finally:
        preflight.subprocess.run = original_subprocess_run

    if "gpg failed with output:" not in rendered:
        raise AssertionError("preflight failure output omitted the command failure label")
    for value in SENSITIVE_FAILURE_VALUES:
        if value in rendered:
            raise AssertionError("preflight GPG failure output leaked a sensitive value")


def load_preflight():
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec = importlib.util.spec_from_file_location(
            "check_linux_signing_secrets_preflight",
            PREFLIGHT,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load Linux signing-secret preflight")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(str(SCRIPT_DIR))
        except ValueError:
            pass


def assert_common_command_output_redacts(linux_gpg_common) -> None:
    raw = sensitive_command_output()
    redacted = linux_gpg_common.redact_command_output(raw)
    if "[redacted]" not in redacted:
        raise AssertionError("Linux GPG command output redaction did not mark redacted output")
    for value in SENSITIVE_FAILURE_VALUES:
        if value in redacted:
            raise AssertionError("Linux GPG command output redaction leaked a sensitive value")

    def failed_run(*args, **_kwargs):
        command = args[0] if args else "gpg"
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=command,
            output=raw.encode("utf-8"),
        )

    linux_gpg_common.subprocess.run = failed_run
    try:
        linux_gpg_common.run_gpg_text("gpg", {}, ["--fixture"])
    except SystemExit as exc:
        rendered = str(exc)
    else:
        raise AssertionError("Linux GPG command output redaction unexpectedly passed")
    if "gpg failed with output:" not in rendered:
        raise AssertionError("Linux GPG failure output omitted the command failure label")
    for value in SENSITIVE_FAILURE_VALUES:
        if value in rendered:
            raise AssertionError("Linux GPG failure output leaked a sensitive value")


def sensitive_command_output() -> str:
    return "\n".join(
        [
            f"npm ERR! auth token {SENSITIVE_FAILURE_VALUES[0]}",
            f"gh token {SENSITIVE_FAILURE_VALUES[1]}",
            f"Authorization: Bearer {SENSITIVE_FAILURE_VALUES[2]}",
            f"Authorization: Basic {SENSITIVE_FAILURE_VALUES[3]}",
            f"NODE_AUTH_TOKEN={SENSITIVE_FAILURE_VALUES[4]}",
            f"https://user:{SENSITIVE_FAILURE_VALUES[5]}@example.invalid/conu",
            f"https://example.invalid/conu?token={SENSITIVE_FAILURE_VALUES[6]}",
            f"PRIVATE_KEY={SENSITIVE_FAILURE_VALUES[7]}",
            "https://s3.example.invalid/conu?"
            f"X-Amz-Signature={SENSITIVE_FAILURE_VALUES[8]}&"
            f"X-Amz-Credential={SENSITIVE_FAILURE_VALUES[9]}&"
            f"X-Amz-Security-Token={SENSITIVE_FAILURE_VALUES[10]}",
            f"https://blob.example.invalid/conu?sig={SENSITIVE_FAILURE_VALUES[11]}",
        ]
    )


def assert_common_failed(
    linux_gpg_common,
    expected_fingerprint: str,
    expected_error: str,
    *,
    forbidden: tuple[str, ...],
) -> None:
    try:
        linux_gpg_common.verify_imported_secret_key_fingerprint(
            "gpg",
            {},
            "test-key",
            expected_fingerprint,
        )
    except SystemExit as exc:
        rendered = str(exc)
    else:
        raise AssertionError("Linux GPG common fingerprint check unexpectedly passed")
    if expected_error not in rendered:
        raise AssertionError(f"expected {expected_error!r} in failure output:\n{rendered}")
    for value in forbidden:
        if value and value in rendered:
            raise AssertionError("Linux GPG common failure output leaked a fingerprint value")


def assert_failed(
    env: dict[str, str],
    expected: str,
    *,
    forbidden: tuple[str, ...] = (),
) -> None:
    failed = subprocess.run(
        [sys.executable, str(PREFLIGHT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    if failed.returncode == 0:
        raise AssertionError("preflight unexpectedly succeeded")
    if expected not in failed.stdout:
        raise AssertionError(f"expected {expected!r} in failure output:\n{failed.stdout}")
    for value in forbidden:
        if value and value in failed.stdout:
            raise AssertionError("failure output leaked a fingerprint value")


def create_test_key(gpg: str, home: Path) -> str:
    run_gpg(
        gpg,
        home,
        [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            PASSPHRASE,
            "--quick-gen-key",
            USER_ID,
            "rsa2048",
            "sign",
            "1d",
        ],
    )
    listing = run_gpg(gpg, home, ["--with-colons", "--list-secret-keys", USER_ID])
    for line in listing.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "fpr" and len(parts) > 9 and parts[9]:
            return parts[9]
    raise AssertionError("could not find generated test signing key fingerprint")


def export_secret_key(gpg: str, home: Path, key_id: str) -> bytes:
    return run_gpg_bytes(
        gpg,
        home,
        [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            PASSPHRASE,
            "--armor",
            "--export-secret-keys",
            key_id,
        ],
    )


def run_gpg(gpg: str, home: Path, args: list[str]) -> str:
    return run_gpg_bytes(gpg, home, args).decode("utf-8", errors="replace")


def run_gpg_bytes(
    gpg: str,
    home: Path,
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    result = subprocess.run(
        [gpg, "--batch", "--yes", "--no-tty", *args],
        input=input_bytes,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
