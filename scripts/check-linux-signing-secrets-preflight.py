#!/usr/bin/env python3
"""Fail-closed preflight for conU Linux GPG signing secrets."""

from __future__ import annotations

import argparse
import base64
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    verify_imported_secret_key_fingerprint,
)


MAX_SIGNING_KEY_BYTES = 1024 * 1024
PROBE_CONTENT = b"conU Linux signing secret preflight\n"


def main() -> int:
    args = parse_args()
    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to preflight Linux signing secrets")

    signing_key = read_secret_key(args.key_env)
    passphrase = read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")
    expected_fingerprint = read_expected_fingerprint(os.environ, args.fingerprint_env)

    with tempfile.TemporaryDirectory(prefix="conu-linux-signing-preflight-") as temp_text:
        temp = Path(temp_text)
        gnupg_home = temp / "gnupg"
        gnupg_home.mkdir(mode=0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)

        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        verify_imported_secret_key_fingerprint(gpg, env, key_id, expected_fingerprint)

        probe = temp / "probe.txt"
        signature = temp / "probe.txt.asc"
        probe.write_bytes(PROBE_CONTENT)
        run_gpg(
            gpg,
            env,
            [
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--local-user",
                key_id,
                "--armor",
                "--detach-sign",
                "--output",
                str(signature),
                str(probe),
            ],
            input_bytes=(passphrase + "\n").encode("utf-8"),
        )
        run_gpg(gpg, env, ["--verify", str(signature), str(probe)])

    print("Linux signing secret preflight passed.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-env",
        default="CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
        help="environment variable containing the base64-encoded armored or binary private key",
    )
    parser.add_argument(
        "--passphrase-env",
        default="CONU_LINUX_GPG_PASSPHRASE",
        help="environment variable containing the private-key passphrase",
    )
    parser.add_argument(
        "--key-id-env",
        default="CONU_LINUX_GPG_KEY_ID",
        help="environment variable containing the signing key id or fingerprint",
    )
    add_fingerprint_env_argument(parser)
    return parser.parse_args()


def read_required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def read_secret_key(name: str) -> bytes:
    raw = read_required_env(name)
    try:
        decoded = base64.b64decode(raw.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise SystemExit(f"{name} must contain strict base64 data") from exc
    if not decoded:
        raise SystemExit(f"{name} decoded to an empty key")
    if len(decoded) > MAX_SIGNING_KEY_BYTES:
        raise SystemExit(f"{name} decoded key is too large")
    return decoded


def run_gpg(
    gpg: str,
    env: dict[str, str],
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> str:
    try:
        result = subprocess.run(
            [gpg, "--batch", "--yes", "--no-tty", *args],
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        raise SystemExit(f"gpg failed with output:\n{output}") from exc
    return result.stdout.decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
