#!/usr/bin/env python3
"""Sign generated conU RPM package assets with the Linux release GPG key."""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    redact_command_output,
    verify_imported_secret_key_fingerprint,
)


MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_RPM_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_RPM_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
RPM_PACKAGE_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-1\.(x86_64|aarch64)\.rpm$")
SIGNATURE_OUTPUT_RE = re.compile(r"(signature|pgp|rsa|dsa|openpgp)", re.IGNORECASE)
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass
class RpmPackageBudget:
    total_bytes: int = 0

    def add(self, size: int) -> None:
        self.total_bytes += size
        if self.total_bytes > MAX_TOTAL_RPM_PACKAGE_BYTES:
            raise SystemExit(
                f"RPM package assets exceed {MAX_TOTAL_RPM_PACKAGE_BYTES} bytes"
            )


def main() -> int:
    args = parse_args()
    dist = validate_input_directory(args.dist, "release dist directory")

    packages = rpm_package_assets(dist)
    if not packages:
        raise SystemExit(f"no generated conU RPM package assets found in {dist}")
    for package in packages:
        verify_sha256_sidecar(package, "generated RPM package")

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to sign RPM packages")
    signer = shutil.which("rpmsign") or shutil.which("rpm")
    if signer is None:
        raise SystemExit("rpmsign or rpm is required to sign RPM packages")
    verifier = shutil.which("rpmkeys") or shutil.which("rpm")
    if verifier is None:
        raise SystemExit("rpmkeys or rpm is required to verify signed RPM packages")

    signing_key = read_secret_key(args.key_env)
    passphrase = read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")
    expected_fingerprint = read_expected_fingerprint(os.environ, args.fingerprint_env)

    with tempfile.TemporaryDirectory(prefix="conu-rpm-package-signing-") as temp_text:
        temp = Path(temp_text)
        gnupg_home = temp / "gnupg"
        rpmdb = temp / "rpmdb"
        home = temp / "home"
        for directory in (gnupg_home, rpmdb, home):
            directory.mkdir(mode=0o700)

        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)
        env["HOME"] = str(home)

        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        verify_imported_secret_key_fingerprint(gpg, env, key_id, expected_fingerprint)
        public_key = run_gpg(gpg, env, ["--armor", "--export", key_id])
        if b"BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
            raise SystemExit("imported Linux GPG key did not export an armored public key")
        public_key_path = temp / "linux-public-key.asc"
        public_key_path.write_bytes(public_key)
        import_rpm_public_key(verifier, env, rpmdb, public_key_path)
        warm_gpg_agent(gpg, env, key_id, passphrase, temp)

        for package in packages:
            validate_rpm_package(package)
            sign_rpm_package(signer, env, gpg, gnupg_home, key_id, package)
            validate_rpm_package(package)
            verify_rpm_signature(verifier, env, rpmdb, package)
            write_sha256_sidecar(package)

    print("signed RPM package assets: " + ", ".join(package.name for package in packages))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release assets")
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


def rpm_package_assets(dist: Path) -> tuple[Path, ...]:
    packages: list[Path] = []
    budget = RpmPackageBudget()
    for path in sorted(dist.iterdir(), key=lambda candidate: candidate.name):
        if RPM_PACKAGE_RE.fullmatch(path.name):
            validate_rpm_package(path, budget)
            packages.append(path)
    return tuple(packages)


def verify_sha256_sidecar(path: Path, label: str) -> str:
    sidecar = path.with_name(f"{path.name}.sha256")
    try:
        checksum_text = read_text_file(
            sidecar,
            f"SHA-256 sidecar for {label}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=False,
            encoding="ascii",
            size_label=f"SHA-256 sidecar for {label}",
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}")
    named_path = match.group(2)
    if named_path != path.name:
        raise SystemExit(
            f"SHA-256 sidecar for {label} names wrong file; "
            "checksumTargetDisplayed=false contentsDisplayed=false"
        )
    expected = match.group(1).lower()
    actual = sha256_file(
        path,
        f"{label} {path.name}",
        max_bytes=MAX_RPM_PACKAGE_BYTES,
        allow_empty=False,
        size_label=label,
    )
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}")
    return expected


def write_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    if sidecar.exists() or sidecar.is_symlink():
        validate_regular_file(
            sidecar,
            f"SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=True,
            size_label="SHA-256 sidecar output",
        )
    digest = sha256_file(
        path,
        f"RPM package asset {path.name}",
        max_bytes=MAX_RPM_PACKAGE_BYTES,
        size_label="RPM package asset",
    )
    text = f"{digest}  {path.name}\n"
    temp_path = temporary_sibling_path(sidecar)
    try:
        temp_path.write_text(text, encoding="ascii", newline="\n")
        temp_path.chmod(0o644)
        validate_regular_file(
            temp_path,
            f"temporary SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=False,
            size_label="temporary SHA-256 sidecar output",
        )
        os.replace(temp_path, sidecar)
        validate_regular_file(
            sidecar,
            f"SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=False,
            size_label="SHA-256 sidecar output",
        )
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def validate_input_directory(path: Path, label: str) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")
    return path.resolve()


def validate_rpm_package(
    path: Path,
    budget: RpmPackageBudget | None = None,
) -> int:
    size = validate_regular_file(
        path,
        f"RPM package asset {path.name}",
        max_bytes=MAX_RPM_PACKAGE_BYTES,
        allow_empty=False,
        size_label="RPM package asset",
    )
    if budget is not None:
        budget.add(size)
    return size


def validate_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    size_label: str | None = None,
) -> int:
    handle, size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
        size_label=size_label,
    )
    handle.close()
    return size


def open_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    size_label: str | None = None,
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
            display_label = size_label or label
            raise SystemExit(f"{display_label} is too large: exceeds {max_bytes} bytes")
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
    size_label: str | None = None,
) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    size = metadata.st_size
    if not allow_empty and size == 0:
        raise SystemExit(f"{label} must not be empty")
    if size > max_bytes:
        display_label = size_label or label
        raise SystemExit(f"{display_label} is too large: exceeds {max_bytes} bytes")
    return size


def read_text_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    encoding: str,
    size_label: str | None = None,
) -> str:
    handle, _size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
        size_label=size_label,
    )
    with handle:
        data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            display_label = size_label or label
            raise SystemExit(f"{display_label} is too large: exceeds {max_bytes} bytes")
        validate_open_regular_file(
            handle,
            label,
            max_bytes=max_bytes,
            allow_empty=allow_empty,
            size_label=size_label,
        )
    return data.decode(encoding)


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
    label: str = "RPM package asset",
    *,
    max_bytes: int = MAX_RPM_PACKAGE_BYTES,
    allow_empty: bool = False,
    size_label: str | None = None,
) -> str:
    handle, _size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
        size_label=size_label,
    )
    with handle:
        return sha256_open_file(
            handle,
            label,
            max_bytes=max_bytes,
            allow_empty=allow_empty,
            size_label=size_label,
        )


def sha256_open_file(
    handle: BinaryIO,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    size_label: str | None = None,
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
            display_label = size_label or label
            raise SystemExit(f"{display_label} is too large: exceeds {max_bytes} bytes")
        digest.update(chunk)
    validate_open_regular_file(
        handle,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
        size_label=size_label,
    )
    return digest.hexdigest()


def warm_gpg_agent(gpg: str, env: dict[str, str], key_id: str, passphrase: str, temp: Path) -> None:
    payload = temp / "warmup.txt"
    signature = temp / "warmup.txt.asc"
    payload.write_text("conU RPM signing warmup\n", encoding="ascii", newline="\n")
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
            str(payload),
        ],
        input_bytes=(passphrase + "\n").encode("utf-8"),
    )


def sign_rpm_package(
    signer: str,
    env: dict[str, str],
    gpg: str,
    gnupg_home: Path,
    key_id: str,
    package: Path,
) -> None:
    args = [
        "--define",
        f"_gpg_name {key_id}",
        "--define",
        f"_openpgp_sign_id {key_id}",
        "--define",
        f"_gpg_path {gnupg_home}",
        "--define",
        f"__gpg {gpg}",
        "--define",
        "_gpg_digest_algo sha256",
        "--addsign",
        str(package),
    ]
    run_tool(signer, args, env=env, label=f"RPM signing failed for {package.name}")


def import_rpm_public_key(
    verifier: str,
    env: dict[str, str],
    rpmdb: Path,
    public_key: Path,
) -> None:
    run_tool(
        verifier,
        ["--define", f"_dbpath {rpmdb}", "--import", str(public_key)],
        env=env,
        label="RPM public-key import failed",
    )


def verify_rpm_signature(
    verifier: str,
    env: dict[str, str],
    rpmdb: Path,
    package: Path,
) -> str:
    output = run_tool(
        verifier,
        ["--define", f"_dbpath {rpmdb}", "--checksig", "--verbose", str(package)],
        env=env,
        label=f"RPM signature verification failed for {package.name}",
    )
    lowered = output.lower()
    if "nokey" in lowered or "not ok" in lowered or "missing" in lowered:
        raise SystemExit(
            f"RPM signature verification was not trusted for {package.name}:\n"
            f"{redact_command_output(output)}"
        )
    if SIGNATURE_OUTPUT_RE.search(output) is None:
        raise SystemExit(
            "RPM signature verification did not report a package signature for "
            f"{package.name}:\n{redact_command_output(output)}"
        )
    return output


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
        raise SystemExit(f"gpg failed with output:\n{redact_command_output(output)}") from exc
    return result.stdout


def run_tool(
    tool: str,
    args: list[str],
    *,
    env: dict[str, str],
    label: str,
) -> str:
    try:
        result = subprocess.run(
            [tool, *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"{label}:\n{redact_command_output(exc.stdout or '')}") from exc
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
