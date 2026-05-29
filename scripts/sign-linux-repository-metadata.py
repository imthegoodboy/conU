#!/usr/bin/env python3
"""Add native GPG signatures to generated conU APT/RPM repository metadata."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from linux_gpg_common import (
    add_fingerprint_env_argument,
    read_expected_fingerprint,
    verify_imported_secret_key_fingerprint,
)


CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([^ \t\r\n]+)\n$")
MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_ZIP_MEMBER_BYTES = 512_000_000
MAX_ZIP_MEMBERS = 10_000
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
HASH_CHUNK_BYTES = 1024 * 1024
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
APT_METADATA_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-apt-repository-metadata\.zip$")
RPM_METADATA_RE = re.compile(r"^conu-[0-9A-Za-z.+_~-]+-rpm-repository-metadata\.zip$")


def main() -> int:
    args = parse_args()
    dist = args.dist.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")

    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg is required to sign Linux repository metadata")

    signing_key = read_secret_key(args.key_env)
    passphrase = read_required_env(args.passphrase_env)
    key_id = read_required_env(args.key_id_env).strip()
    if not key_id:
        raise SystemExit(f"{args.key_id_env} must not be empty")
    expected_fingerprint = read_expected_fingerprint(os.environ, args.fingerprint_env)

    apt_bundles = repository_metadata_assets(dist, APT_METADATA_RE)
    rpm_bundles = repository_metadata_assets(dist, RPM_METADATA_RE)
    if not apt_bundles and not rpm_bundles:
        raise SystemExit(f"no generated APT/RPM repository metadata bundles found in {dist}")

    signed: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="conu-repository-signing-") as gnupg_home_text:
        gnupg_home = Path(gnupg_home_text)
        gnupg_home.chmod(0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg_home)
        run_gpg(gpg, env, ["--import"], input_bytes=signing_key)
        verify_imported_secret_key_fingerprint(gpg, env, key_id, expected_fingerprint)

        for bundle in apt_bundles:
            verify_sha256_sidecar(bundle, "APT repository metadata bundle")
            sign_apt_bundle(gpg, env, key_id, passphrase, bundle)
            write_sha256_sidecar(bundle)
            signed.append(bundle)

        for bundle in rpm_bundles:
            verify_sha256_sidecar(bundle, "RPM repository metadata bundle")
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


def repository_metadata_assets(dist: Path, pattern: re.Pattern[str]) -> tuple[Path, ...]:
    return tuple(
        path
        for path in sorted(dist.iterdir(), key=lambda candidate: candidate.name)
        if path.is_file() and pattern.fullmatch(path.name)
    )


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

        members["InRelease"] = inrelease_path.read_bytes()
        members["Release.gpg"] = release_gpg_path.read_bytes()

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
        members["repodata/repomd.xml.asc"] = signature_path.read_bytes()

    write_zip_members(bundle, members)


def read_zip_members(bundle: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(bundle) as archive:
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
    order = [name for name in members if not signature_member(name)]
    for signature in ("InRelease", "Release.gpg", "repodata/repomd.xml.asc"):
        if signature in members:
            order.append(signature)

    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in order:
            write_deterministic_zip_bytes(archive, name, members[name])


def signature_member(name: str) -> bool:
    return name in {"InRelease", "Release.gpg", "repodata/repomd.xml.asc"}


def write_deterministic_zip_bytes(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def verify_sha256_sidecar(path: Path, label: str) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    if not sidecar.exists() or not sidecar.is_file():
        raise SystemExit(f"missing SHA-256 sidecar for {label}: {path.name}")
    if sidecar.stat().st_size > MAX_CHECKSUM_BYTES:
        raise SystemExit(f"SHA-256 sidecar is too large for {label}: {path.name}")
    try:
        checksum_text = sidecar.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}: {path.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}: {path.name}")
    if match.group(2) != path.name:
        raise SystemExit(
            f"SHA-256 sidecar for {label} {path.name} names wrong file: {match.group(2)}"
        )
    if match.group(1).lower() != sha256_file(path):
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")


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
        raise SystemExit(f"gpg failed with output:\n{output}") from exc
    return result.stdout.decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
