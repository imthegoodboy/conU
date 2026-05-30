#!/usr/bin/env python3
"""Export the public Linux release-signing GPG key as a release asset."""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    verify_imported_secret_key_fingerprint,
)


DEFAULT_OUTPUT_NAME = "conu-linux-gpg-key.asc"
MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
HASH_CHUNK_BYTES = 1024 * 1024
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def main() -> int:
    args = parse_args()
    dist = args.dist.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")
    output_name = validate_output_name(args.output_name)
    output = dist / output_name
    prepare_public_key_output(output)

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to export the Linux release public key")

    signing_key = read_secret_key(args.key_env)
    read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")
    expected_fingerprint = read_expected_fingerprint(os.environ, args.fingerprint_env)

    with tempfile.TemporaryDirectory(prefix="conu-linux-public-key-") as gnupg_home_text:
        gnupg_home = Path(gnupg_home_text)
        gnupg_home.chmod(0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)
        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        verify_imported_secret_key_fingerprint(gpg, env, key_id, expected_fingerprint)
        public_key = run_gpg(gpg, env, ["--armor", "--export", key_id])

    validate_public_key_bytes(public_key)
    write_public_key_asset(output, public_key)
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
    add_fingerprint_env_argument(parser)
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


def validate_public_key_bytes(public_key: bytes) -> None:
    if not public_key:
        raise SystemExit("exported Linux GPG key was empty")
    if len(public_key) > MAX_PUBLIC_KEY_BYTES:
        raise SystemExit(f"exported Linux GPG key exceeds {MAX_PUBLIC_KEY_BYTES} bytes")
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
        raise SystemExit("exported Linux GPG key was not an armored public key")
    if b"PRIVATE KEY BLOCK" in public_key:
        raise SystemExit("refusing to write private key material as a public-key asset")


def prepare_public_key_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        validate_regular_file(
            path,
            f"Linux public-key output {path.name}",
            max_bytes=MAX_PUBLIC_KEY_BYTES,
            allow_empty=True,
        )


def write_public_key_asset(path: Path, public_key: bytes) -> None:
    validate_public_key_bytes(public_key)
    prepare_public_key_output(path)
    temp_path = temporary_sibling_path(path)
    try:
        write_output_bytes(
            temp_path,
            public_key,
            f"temporary Linux public-key output {path.name}",
            max_bytes=MAX_PUBLIC_KEY_BYTES,
        )
        validate_regular_file(
            temp_path,
            f"temporary Linux public-key output {path.name}",
            max_bytes=MAX_PUBLIC_KEY_BYTES,
            allow_empty=False,
        )
        os.replace(temp_path, path)
        validate_regular_file(
            path,
            f"Linux public-key output {path.name}",
            max_bytes=MAX_PUBLIC_KEY_BYTES,
            allow_empty=False,
        )
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def write_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    if sidecar.exists() or sidecar.is_symlink():
        validate_regular_file(
            sidecar,
            f"SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=True,
        )
    text = f"{sha256_file(path, f'Linux public-key output {path.name}')}  {path.name}\n"
    temp_path = temporary_sibling_path(sidecar)
    try:
        write_output_bytes(
            temp_path,
            text.encode("ascii"),
            f"temporary SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
        )
        validate_regular_file(
            temp_path,
            f"temporary SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=False,
        )
        os.replace(temp_path, sidecar)
        validate_regular_file(
            sidecar,
            f"SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=False,
        )
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def validate_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> int:
    handle, size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )
    handle.close()
    return size


def open_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> tuple[BinaryIO, int]:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    if not path.exists():
        raise SystemExit(f"missing {label}: {path.name}")
    flags = os.O_RDONLY | OPEN_BINARY | OPEN_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"{label} must not be a symlink: {path.name}") from exc
        if not path.exists():
            raise SystemExit(f"missing {label}: {path.name}") from exc
        if not path.is_file():
            raise SystemExit(f"{label} must be a regular file: {path.name}") from exc
        raise SystemExit(f"{label} could not be opened: {path.name}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} must be a regular file: {path.name}")
        size = metadata.st_size
        if not allow_empty and size == 0:
            raise SystemExit(f"{label} must not be empty: {path.name}")
        if size > max_bytes:
            raise SystemExit(f"{label} is too large: {path.name} exceeds {max_bytes} bytes")
        return os.fdopen(fd, "rb"), size
    except BaseException:
        os.close(fd)
        raise


def validate_open_regular_file(
    handle: BinaryIO,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    size = metadata.st_size
    if not allow_empty and size == 0:
        raise SystemExit(f"{label} must not be empty")
    if size > max_bytes:
        raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
    return size


def write_output_bytes(path: Path, data: bytes, label: str, *, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large: {path.name} exceeds {max_bytes} bytes")
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC | OPEN_BINARY | OPEN_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"{label} must not be a symlink: {path.name}") from exc
        if path.exists() and not path.is_file():
            raise SystemExit(f"{label} must be a regular file: {path.name}") from exc
        raise SystemExit(f"{label} could not be opened: {path.name}") from exc
    try:
        with os.fdopen(fd, "w+b") as handle:
            fd = -1
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise SystemExit(f"{label} must be a regular file: {path.name}")
            handle.write(data)
            handle.flush()
            validate_open_regular_file(
                handle,
                label,
                max_bytes=max_bytes,
                allow_empty=False,
            )
        path.chmod(0o644)
    except BaseException:
        if fd != -1:
            os.close(fd)
        raise


def temporary_sibling_path(path: Path) -> Path:
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        delete=False,
    ) as handle:
        return Path(handle.name)


def sha256_file(
    path: Path,
    label: str = "Linux public-key output",
    *,
    max_bytes: int | None = None,
    allow_empty: bool = False,
) -> str:
    effective_max_bytes = MAX_PUBLIC_KEY_BYTES if max_bytes is None else max_bytes
    handle, _size = open_regular_file(
        path,
        label,
        max_bytes=effective_max_bytes,
        allow_empty=allow_empty,
    )
    with handle:
        return sha256_open_file(
            handle,
            label,
            max_bytes=effective_max_bytes,
            allow_empty=allow_empty,
        )


def sha256_open_file(
    handle: BinaryIO,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    total = 0
    while True:
        chunk = handle.read(HASH_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
        digest.update(chunk)
    validate_open_regular_file(
        handle,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )
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
