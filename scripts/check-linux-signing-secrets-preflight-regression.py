#!/usr/bin/env python3
"""Regression checks for Linux signing-secret preflight."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "check-linux-signing-secrets-preflight.py"
PASSPHRASE = "conu-linux-signing-preflight-regression-passphrase"
USER_ID = "conU Linux Signing Preflight Regression <noreply@github.com>"
WRONG_FINGERPRINT = "F" * 40


def main() -> int:
    gpg = shutil.which("gpg")
    if gpg is None:
        print("Linux signing-secret preflight regression skipped: gpg is unavailable")
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
        assert_failed(mismatch_env, "fingerprint mismatch")

        wrong_passphrase_env = env.copy()
        wrong_passphrase_env["CONU_LINUX_GPG_PASSPHRASE"] = "wrong-passphrase"
        assert_failed(wrong_passphrase_env, "gpg failed")

    print("Linux signing-secret preflight regression checks passed")
    return 0


def assert_failed(env: dict[str, str], expected: str) -> None:
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
