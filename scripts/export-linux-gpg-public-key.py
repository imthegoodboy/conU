#!/usr/bin/env python3
"""Export the public Linux release-signing GPG key as a release asset."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_OUTPUT_NAME = "conu-linux-gpg-key.asc"
MAX_SIGNING_KEY_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024


def main() -> int:
    args = parse_args()
    dist = args.dist.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")
    output_name = validate_output_name(args.output_name)

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to export the Linux release public key")

    signing_key = read_secret_key(args.key_env)
    read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")

    with tempfile.TemporaryDirectory(prefix="conu-linux-public-key-") as gnupg_home_text:
        gnupg_home = Path(gnupg_home_text)
        gnupg_home.chmod(0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)
        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        public_key = run_gpg(gpg, env, ["--armor", "--export", key_id])

    if b"BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
        raise SystemExit("exported Linux GPG key was not an armored public key")
    if b"PRIVATE KEY BLOCK" in public_key:
        raise SystemExit("refusing to write private key material as a public-key asset")

    output = dist / output_name
    output.write_bytes(public_key)
    write_sha256_sidecar(output)
    print(f"exported Linux release public key: {output.name}, {output.name}.sha256")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory receiving release assets")
    parser.add_argument(
        "--output-name",
        default=DEFAULT_OUTPUT_NAME,
        help=f"public-key asset filename, defaults to {DEFAULT_OUTPUT_NAME}",
    )
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
    return parser.parse_args()


def validate_output_name(name: str) -> str:
    if name != Path(name).name or name in {"", ".", ".."}:
        raise SystemExit(f"invalid Linux public-key output filename: {name}")
    if not name.endswith(".asc"):
        raise SystemExit("Linux public-key output filename must end with .asc")
    return name


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


def write_sha256_sidecar(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_gpg(
    gpg: str,
    env: dict[str, str],
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    command = [gpg, "--batch", "--yes", "--no-tty", *args]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        output = ""
        if exc.stdout:
            output += exc.stdout.decode("utf-8", errors="replace")
        if exc.stderr:
            output += exc.stderr.decode("utf-8", errors="replace")
        raise SystemExit(f"gpg failed with output:\n{output}") from exc
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
