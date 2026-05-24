#!/usr/bin/env python3
"""Regression checks for the Linux release GPG public-key export asset."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts" / "export-linux-gpg-public-key.py"
PASSPHRASE = "conu-linux-public-key-regression-passphrase"
USER_ID = "conU Linux Public Key Regression <noreply@github.com>"
PUBLIC_KEY_ASSET = "conu-linux-gpg-key.asc"


def main() -> int:
    gpg = shutil.which("gpg")
    if gpg is None:
        print("Linux GPG public-key export regression skipped: gpg is unavailable")
        return 0

    with tempfile.TemporaryDirectory(prefix="conu-linux-public-key-check-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        key_home = temp / "key-home"
        verify_home = temp / "verify-home"
        dist.mkdir()
        key_home.mkdir(mode=0o700)
        verify_home.mkdir(mode=0o700)

        key_id = create_test_key(gpg, key_home)
        private_key = export_secret_key(gpg, key_home, key_id)

        env = os.environ.copy()
        env["CONU_LINUX_GPG_PRIVATE_KEY_BASE64"] = base64.b64encode(private_key).decode("ascii")
        env["CONU_LINUX_GPG_PASSPHRASE"] = PASSPHRASE
        env["CONU_LINUX_GPG_KEY_ID"] = key_id
        subprocess.run(
            [sys.executable, str(EXPORTER), str(dist)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        public_key = dist / PUBLIC_KEY_ASSET
        if not public_key.exists():
            raise AssertionError(f"{PUBLIC_KEY_ASSET} was not generated")
        public_key_text = public_key.read_text(encoding="ascii")
        if "BEGIN PGP PUBLIC KEY BLOCK" not in public_key_text:
            raise AssertionError("exported key was not an armored public key")
        if "PRIVATE KEY BLOCK" in public_key_text:
            raise AssertionError("exported key included private key material")
        assert_sha256_sidecar(public_key)

        run_gpg_bytes(gpg, verify_home, ["--import"], input_bytes=public_key.read_bytes())
        fixture = temp / "fixture.txt"
        signature = temp / "fixture.txt.asc"
        fixture.write_text("conU release signature verification fixture\n", encoding="ascii")
        run_gpg_bytes(
            gpg,
            key_home,
            [
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                PASSPHRASE,
                "--local-user",
                key_id,
                "--armor",
                "--detach-sign",
                "--output",
                str(signature),
                str(fixture),
            ],
        )
        run_gpg_bytes(gpg, verify_home, ["--verify", str(signature), str(fixture)])

        missing_env = os.environ.copy()
        for name in (
            "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
            "CONU_LINUX_GPG_PASSPHRASE",
            "CONU_LINUX_GPG_KEY_ID",
        ):
            missing_env.pop(name, None)
        failed = subprocess.run(
            [sys.executable, str(EXPORTER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=missing_env,
        )
        if failed.returncode == 0 or "missing required environment variable" not in failed.stdout:
            raise AssertionError("public-key exporter did not fail closed with missing secrets")

    print("Linux GPG public-key export regression checks passed")
    return 0


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{sha256_file(path)}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash the public key")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes())
    return digest.hexdigest()


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
        stderr=subprocess.PIPE,
        env=env,
    )
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
