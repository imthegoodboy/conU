#!/usr/bin/env python3
"""Add native GPG signatures to generated conU APT/RPM repository metadata."""

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
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    redact_command_output,
    verify_imported_secret_key_fingerprint,
)


CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([^ \t\r\n]+)\n$")
MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_REPOSITORY_METADATA_BUNDLE_BYTES = 512_000_000
MAX_TOTAL_REPOSITORY_METADATA_BUNDLE_BYTES = 1_000_000_000
MAX_ZIP_MEMBER_BYTES = 512_000_000
MAX_ZIP_MEMBERS = 10_000
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
MAX_GENERATED_SIGNATURE_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
APT_METADATA_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-apt-repository-metadata\.zip$")
RPM_METADATA_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-rpm-repository-metadata\.zip$")
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass
class RepositoryMetadataBudget:
    total_bytes: int = 0

    def add(self, size: int) -> None:
        self.total_bytes += size
        if self.total_bytes > MAX_TOTAL_REPOSITORY_METADATA_BUNDLE_BYTES:
            raise SystemExit(
                "repository metadata bundles exceed "
                f"{MAX_TOTAL_REPOSITORY_METADATA_BUNDLE_BYTES} bytes"
            )


def main() -> int:
    args = parse_args()
    dist = validate_input_directory(args.dist, "release dist directory")

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to sign Linux repository metadata")

    signing_key = read_secret_key(args.key_env)
    passphrase = read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")
    expected_fingerprint = read_expected_fingerprint(os.environ, args.fingerprint_env)

    apt_bundles, rpm_bundles = repository_metadata_assets(dist)
    if not apt_bundles and not rpm_bundles:
        raise SystemExit(f"no generated APT/RPM repository metadata bundles found in {dist}")
    for bundle in apt_bundles:
        verify_sha256_sidecar(bundle, "APT repository metadata bundle")
    for bundle in rpm_bundles:
        verify_sha256_sidecar(bundle, "RPM repository metadata bundle")

    signed: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="conu-repository-signing-") as gnupg_home_text:
        gnupg_home = Path(gnupg_home_text)
        gnupg_home.chmod(0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)
        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        verify_imported_secret_key_fingerprint(gpg, env, key_id, expected_fingerprint)

        for bundle in apt_bundles:
            sign_apt_bundle(gpg, env, key_id, passphrase, bundle)
            write_sha256_sidecar(bundle)
            signed.append(bundle)

        for bundle in rpm_bundles:
            sign_rpm_bundle(gpg, env, key_id, passphrase, bundle)
            write_sha256_sidecar(bundle)
            signed.append(bundle)

    print("signed Linux repository metadata: " + ", ".join(str(path) for path in signed))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing generated release assets")
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


def repository_metadata_assets(dist: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    apt_bundles: list[Path] = []
    rpm_bundles: list[Path] = []
    budget = RepositoryMetadataBudget()
    for path in sorted(dist.iterdir(), key=lambda candidate: candidate.name):
        if APT_METADATA_RE.fullmatch(path.name):
            validate_repository_metadata_bundle(path, budget)
            apt_bundles.append(path)
        elif RPM_METADATA_RE.fullmatch(path.name):
            validate_repository_metadata_bundle(path, budget)
            rpm_bundles.append(path)
    return tuple(apt_bundles), tuple(rpm_bundles)


def sign_apt_bundle(
    gpg: str,
    env: dict[str, str],
    key_id: str,
    passphrase: str,
    bundle: Path,
) -> None:
    members = read_zip_members(bundle)
    release = members.get("Release")
    if release is None:
        raise SystemExit(f"{bundle.name} is missing APT Release metadata")

    with tempfile.TemporaryDirectory(prefix="conu-apt-signing-") as temp_text:
        temp = Path(temp_text)
        release_path = temp / "Release"
        inrelease_path = temp / "InRelease"
        release_gpg_path = temp / "Release.gpg"
        release_path.write_bytes(release)

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
                "--digest-algo",
                "SHA256",
                "--clearsign",
                "--output",
                str(inrelease_path),
                str(release_path),
            ],
            input_bytes=(passphrase + "\n").encode("utf-8"),
        )
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
                "--digest-algo",
                "SHA256",
                "--armor",
                "--detach-sign",
                "--output",
                str(release_gpg_path),
                str(release_path),
            ],
            input_bytes=(passphrase + "\n").encode("utf-8"),
        )
        run_gpg(gpg, env, ["--verify", str(inrelease_path)])
        run_gpg(gpg, env, ["--verify", str(release_gpg_path), str(release_path)])

        members["InRelease"] = read_generated_signature(
            inrelease_path,
            f"generated InRelease signature for {bundle.name}",
        )
        members["Release.gpg"] = read_generated_signature(
            release_gpg_path,
            f"generated Release.gpg signature for {bundle.name}",
        )

    write_zip_members(bundle, members)


def sign_rpm_bundle(
    gpg: str,
    env: dict[str, str],
    key_id: str,
    passphrase: str,
    bundle: Path,
) -> None:
    members = read_zip_members(bundle)
    repomd = members.get("repodata/repomd.xml")
    if repomd is None:
        raise SystemExit(f"{bundle.name} is missing repodata/repomd.xml")

    with tempfile.TemporaryDirectory(prefix="conu-rpm-signing-") as temp_text:
        temp = Path(temp_text)
        repomd_path = temp / "repomd.xml"
        signature_path = temp / "repomd.xml.asc"
        repomd_path.write_bytes(repomd)
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
                "--digest-algo",
                "SHA256",
                "--armor",
                "--detach-sign",
                "--output",
                str(signature_path),
                str(repomd_path),
            ],
            input_bytes=(passphrase + "\n").encode("utf-8"),
        )
        run_gpg(gpg, env, ["--verify", str(signature_path), str(repomd_path)])
        members["repodata/repomd.xml.asc"] = read_generated_signature(
            signature_path,
            f"generated repomd.xml.asc signature for {bundle.name}",
        )

    write_zip_members(bundle, members)


def read_zip_members(bundle: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_uncompressed = 0
    bundle_file, _size = open_regular_file(
        bundle,
        f"repository metadata bundle {bundle.name}",
        max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
        allow_empty=False,
    )
    try:
        with bundle_file:
            with zipfile.ZipFile(bundle_file) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ZIP_MEMBERS:
                    raise SystemExit(f"{bundle.name} contains more than {MAX_ZIP_MEMBERS} members")
                for member in infos:
                    name = normalize_zip_path(member.filename)
                    if not validate_zip_member_for_read(bundle.name, member, name):
                        continue
                    if name in members:
                        raise SystemExit(f"{bundle.name} contains duplicate zip member: {name}")
                    total_uncompressed += member.file_size
                    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                        raise SystemExit(
                            f"{bundle.name} uncompressed ZIP contents exceed "
                            f"{MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES} bytes"
                        )
                    members[name] = archive.read(member)
            validate_open_regular_file(
                bundle_file,
                f"repository metadata bundle {bundle.name}",
                max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
                allow_empty=False,
            )
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"{bundle.name} is not a readable zip archive") from exc
    return members


def validate_zip_member_for_read(bundle_name: str, member: zipfile.ZipInfo, name: str) -> bool:
    if member.flag_bits & 0x1:
        raise SystemExit(f"{bundle_name} contains encrypted zip member: {name}")
    file_type = (member.external_attr >> 16) & 0o170000
    is_directory = member.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise SystemExit(f"{bundle_name} contains unsupported link member: {name}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise SystemExit(f"{bundle_name} contains unsupported zip member: {name}")
    if is_directory:
        if member.file_size != 0:
            raise SystemExit(f"{bundle_name} contains directory member with data: {name}")
        return False
    if member.file_size > MAX_ZIP_MEMBER_BYTES:
        raise SystemExit(f"{bundle_name} zip member is too large: {name}")
    return True


def normalize_zip_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe repository metadata zip path: {raw_name}")
    if not parts:
        raise SystemExit(f"unsafe empty repository metadata zip path: {raw_name}")
    return "/".join(parts)


def write_zip_members(bundle: Path, members: dict[str, bytes]) -> None:
    validate_regular_file(
        bundle,
        f"repository metadata bundle output {bundle.name}",
        max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
        allow_empty=False,
    )
    order = [name for name in members if not signature_member(name)]
    for signature in ("InRelease", "Release.gpg", "repodata/repomd.xml.asc"):
        if signature in members:
            order.append(signature)

    temp_path = temporary_sibling_path(bundle)
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in order:
                write_deterministic_zip_bytes(archive, name, members[name])
        temp_path.chmod(0o644)
        validate_regular_file(
            temp_path,
            f"rewritten repository metadata bundle {bundle.name}",
            max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
            allow_empty=False,
        )
        os.replace(temp_path, bundle)
        validate_regular_file(
            bundle,
            f"repository metadata bundle output {bundle.name}",
            max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
            allow_empty=False,
        )
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def signature_member(name: str) -> bool:
    return name in {"InRelease", "Release.gpg", "repodata/repomd.xml.asc"}


def write_deterministic_zip_bytes(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def validate_input_directory(path: Path, label: str) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")
    return path.resolve()


def verify_sha256_sidecar(path: Path, label: str) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    try:
        checksum_text = read_text_file(
            sidecar,
            f"SHA-256 sidecar for {label} {path.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=False,
            encoding="ascii",
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}: {path.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}: {path.name}")
    if match.group(2) != path.name:
        raise SystemExit(
            f"SHA-256 sidecar for {label} {path.name} names wrong file: {match.group(2)}"
        )
    if match.group(1).lower() != sha256_file(
        path,
        f"{label} {path.name}",
        max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
    ):
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")


def write_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    if sidecar.exists() or sidecar.is_symlink():
        validate_regular_file(
            sidecar,
            f"SHA-256 sidecar output {sidecar.name}",
            max_bytes=MAX_CHECKSUM_BYTES,
            allow_empty=True,
        )
    digest = sha256_file(
        path,
        f"repository metadata bundle {path.name}",
        max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
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


def validate_repository_metadata_bundle(
    path: Path,
    budget: RepositoryMetadataBudget | None = None,
) -> int:
    size = validate_regular_file(
        path,
        f"repository metadata bundle {path.name}",
        max_bytes=MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
        allow_empty=False,
    )
    if budget is not None:
        budget.add(size)
    return size


def read_generated_signature(path: Path, label: str) -> bytes:
    return read_binary_file(
        path,
        label,
        max_bytes=MAX_GENERATED_SIGNATURE_BYTES,
        allow_empty=False,
    )


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


def read_binary_file(path: Path, label: str, *, max_bytes: int, allow_empty: bool) -> bytes:
    handle, _size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )
    with handle:
        data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise SystemExit(f"{label} is too large: {path.name} exceeds {max_bytes} bytes")
        validate_open_regular_file(
            handle,
            label,
            max_bytes=max_bytes,
            allow_empty=allow_empty,
        )
    return data


def read_text_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    encoding: str,
) -> str:
    return read_binary_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    ).decode(encoding)


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
    label: str = "repository metadata bundle",
    *,
    max_bytes: int = MAX_REPOSITORY_METADATA_BUNDLE_BYTES,
    allow_empty: bool = False,
) -> str:
    handle, _size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        allow_empty=allow_empty,
    )
    with handle:
        return sha256_open_file(
            handle,
            label,
            max_bytes=max_bytes,
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
) -> str:
    command = [gpg, "--batch", "--yes", "--no-tty", *args]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        raise SystemExit(f"gpg failed with output:\n{redact_command_output(output)}") from exc
    return result.stdout.decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
