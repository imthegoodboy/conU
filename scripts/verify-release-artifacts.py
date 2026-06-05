#!/usr/bin/env python3
"""Validate conU release archives without inspecting local conU state."""

from __future__ import annotations

import argparse
import errno
import hashlib
import os
import re
import stat
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO


HASH_CHUNK_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 1_000_000_000
MAX_CHECKSUM_BYTES = 4096
MAX_MANIFEST_BYTES = 1_000_000
MAX_MEMBER_BYTES = 512_000_000
MAX_MEMBER_COUNT = 10_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
FORBIDDEN_PARTS = {
    ".conu",
    ".git",
    "logs",
    "messages",
    "node_modules",
    "routes",
    "runtime",
    "security",
    "sessions",
    "streams",
    "target",
    "vendor",
}
FORBIDDEN_NAMES = {
    ".env",
    ".env.local",
    ".npmrc",
    "node.toml",
    "runtime.toml",
    "trust.toml",
}
FORBIDDEN_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".token")
REQUIRED_BINARIES = {"conu", "conud", "conu-relay", "conu-mcp"}
REQUIRED_PACKAGING_FILES = {
    "packaging/README.md",
    "packaging/docker/README.md",
    "packaging/docker/relay.Dockerfile",
    "packaging/linux/conud.service",
    "packaging/macos/com.conu.conud.plist",
    "packaging/npm/conu-cli/package.json",
    "packaging/npm/conu-cli/scripts/install.js",
    "packaging/windows/install.ps1",
    "packaging/windows/uninstall.ps1",
}


@dataclass
class ArchiveMembers:
    paths: set[str]
    manifest: bytes | None


def archive_member_path_error(archive_name: str, reason: str) -> SystemExit:
    return SystemExit(
        f"{archive_name} {reason}; pathDisplayed=false contentsDisplayed=false"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    args = parser.parse_args()

    dist = args.dist.expanduser()
    validate_input_directory(dist, "release dist directory")
    dist = dist.resolve()

    archives = sorted(dist.glob("*.zip")) + sorted(dist.glob("*.tar.gz"))
    if not archives:
        raise SystemExit(f"no release archives found in {dist}")

    for archive in archives:
        verify_checksum(archive)
        members = archive_members(archive)
        verify_members(archive, members)

    print(f"verified {len(archives)} conU release archive(s)")
    return 0


def verify_checksum(archive: Path) -> None:
    archive_file, _archive_size = open_regular_file(
        archive,
        "release archive",
        max_bytes=MAX_ARCHIVE_BYTES,
        too_large_message=f"{archive.name} is larger than {MAX_ARCHIVE_BYTES} bytes",
    )

    checksum_path = archive.with_name(f"{archive.name}.sha256")
    checksum_file, _checksum_size = open_regular_file(
        checksum_path,
        f"checksum file for {archive.name}",
        max_bytes=MAX_CHECKSUM_BYTES,
        missing_message=f"missing checksum file for {archive.name}",
        too_large_message=f"checksum file is too large for {archive.name}",
    )

    with archive_file:
        with checksum_file:
            try:
                checksum_text = read_text_file(
                    checksum_file,
                    f"checksum file for {archive.name}",
                    max_bytes=MAX_CHECKSUM_BYTES,
                    encoding="ascii",
                )
            except UnicodeDecodeError as exc:
                raise SystemExit(f"checksum file is not ASCII for {archive.name}") from exc

        match = CHECKSUM_RE.fullmatch(checksum_text)
        if match is None:
            raise SystemExit(f"checksum file has invalid format for {archive.name}")

        checksum_archive_name = match.group(2)
        if checksum_archive_name != archive.name:
            raise SystemExit(
                f"checksum file for {archive.name} names wrong archive: {checksum_archive_name}"
            )

        expected = match.group(1).lower()
        actual = sha256_open_file(
            archive_file,
            "release archive",
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        if expected != actual:
            raise SystemExit(f"checksum mismatch for {archive.name}")


def sha256_file(path: Path) -> str:
    handle, _size = open_regular_file(path, "release archive", max_bytes=MAX_ARCHIVE_BYTES)
    with handle:
        return sha256_open_file(handle, "release archive", max_bytes=MAX_ARCHIVE_BYTES)


def sha256_open_file(handle: BinaryIO, label: str, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    total = 0
    while True:
        chunk = handle.read(HASH_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise SystemExit(f"{label} is too large")
        digest.update(chunk)
    validate_open_regular_file(handle, label, max_bytes=max_bytes)
    return digest.hexdigest()


def archive_members(archive: Path) -> ArchiveMembers:
    archive_file, _size = open_regular_file(
        archive,
        "release archive",
        max_bytes=MAX_ARCHIVE_BYTES,
        too_large_message=f"{archive.name} is larger than {MAX_ARCHIVE_BYTES} bytes",
    )
    expected_root = expected_archive_root(archive.name)

    if archive.suffix == ".zip":
        try:
            with archive_file:
                with zipfile.ZipFile(archive_file) as package:
                    paths: set[str] = set()
                    manifest: bytes | None = None
                    total_uncompressed = 0
                    entry_count = 0
                    root_style: str | None = None
                    for member in package.infolist():
                        if member.is_dir():
                            if member.file_size != 0:
                                raise archive_member_path_error(
                                    archive.name, "contains directory member with data"
                                )
                            _, total_uncompressed, entry_count, root_style = record_entry(
                                archive.name,
                                paths,
                                member.filename,
                                expected_root,
                                root_style,
                                0,
                                total_uncompressed,
                                entry_count,
                                allow_empty=True,
                            )
                            continue
                        if member.flag_bits & 0x1:
                            raise archive_member_path_error(
                                archive.name, "contains encrypted zip member"
                            )
                        file_type = (member.external_attr >> 16) & 0o170000
                        if file_type == stat.S_IFLNK:
                            raise archive_member_path_error(
                                archive.name, "contains unsupported link member"
                            )
                        if file_type not in {0, stat.S_IFREG}:
                            raise archive_member_path_error(
                                archive.name, "contains unsupported zip member"
                            )
                        normalized, total_uncompressed, entry_count, root_style = record_entry(
                            archive.name,
                            paths,
                            member.filename,
                            expected_root,
                            root_style,
                            member.file_size,
                            total_uncompressed,
                            entry_count,
                        )
                        if normalized == "manifest.toml":
                            manifest = read_zip_member(
                                archive.name,
                                package,
                                member,
                                MAX_MANIFEST_BYTES,
                            )
                        else:
                            drain_zip_member(archive.name, package, member)
                    validate_open_regular_file(
                        archive_file,
                        "release archive",
                        max_bytes=MAX_ARCHIVE_BYTES,
                    )
                    return ArchiveMembers(paths=paths, manifest=manifest)
        except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            raise archive_member_path_error(
                archive.name, "is not a readable zip archive"
            ) from exc
    if archive.name.endswith(".tar.gz"):
        try:
            with archive_file:
                with tarfile.open(fileobj=archive_file, mode="r|gz") as package:
                    paths: set[str] = set()
                    manifest: bytes | None = None
                    total_uncompressed = 0
                    entry_count = 0
                    root_style: str | None = None
                    for member in package:
                        if member.isdir():
                            _, total_uncompressed, entry_count, root_style = record_entry(
                                archive.name,
                                paths,
                                member.name,
                                expected_root,
                                root_style,
                                0,
                                total_uncompressed,
                                entry_count,
                                allow_empty=True,
                            )
                            continue
                        if not member.isfile():
                            raise archive_member_path_error(
                                archive.name, "contains unsupported non-file member"
                            )
                        normalized, total_uncompressed, entry_count, root_style = record_entry(
                            archive.name,
                            paths,
                            member.name,
                            expected_root,
                            root_style,
                            member.size,
                            total_uncompressed,
                            entry_count,
                        )
                        if normalized == "manifest.toml":
                            manifest = read_tar_member(
                                archive.name,
                                package,
                                member,
                                MAX_MANIFEST_BYTES,
                            )
                    validate_open_regular_file(
                        archive_file,
                        "release archive",
                        max_bytes=MAX_ARCHIVE_BYTES,
                    )
                    return ArchiveMembers(paths=paths, manifest=manifest)
        except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
            raise archive_member_path_error(
                archive.name, "is not a readable tar.gz archive"
            ) from exc
    raise SystemExit(f"unsupported release archive {archive.name}")


def validate_input_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")


def validate_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    missing_message: str | None = None,
    too_large_message: str | None = None,
) -> int:
    handle, size = open_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        missing_message=missing_message,
        too_large_message=too_large_message,
    )
    handle.close()
    return size


def open_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    missing_message: str | None = None,
    too_large_message: str | None = None,
) -> tuple[BinaryIO, int]:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    if not path.exists():
        raise SystemExit(missing_message or f"missing {label}: {path.name}")
    flags = os.O_RDONLY | OPEN_BINARY | OPEN_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"{label} must not be a symlink: {path.name}") from exc
        if not path.exists():
            raise SystemExit(missing_message or f"missing {label}: {path.name}") from exc
        if not path.is_file():
            raise SystemExit(f"{label} must be a regular file: {path.name}") from exc
        raise SystemExit(f"{label} could not be opened: {path.name}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} must be a regular file: {path.name}")
        if metadata.st_size > max_bytes:
            raise SystemExit(too_large_message or f"{label} is too large: {path.name}")
        return os.fdopen(fd, "rb"), metadata.st_size
    except BaseException:
        os.close(fd)
        raise


def validate_open_regular_file(handle: BinaryIO, label: str, *, max_bytes: int) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{label} is too large")
    return metadata.st_size


def read_text_file(handle: BinaryIO, label: str, *, max_bytes: int, encoding: str) -> str:
    handle.seek(0)
    data = handle.read(max_bytes + 1)
    validate_open_regular_file(handle, label, max_bytes=max_bytes)
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large")
    return data.decode(encoding)


def record_entry(
    archive_name: str,
    paths: set[str],
    raw_name: str,
    expected_root: str,
    root_style: str | None,
    size: int,
    total_uncompressed: int,
    entry_count: int,
    *,
    allow_empty: bool = False,
) -> tuple[str, int, int, str | None]:
    if size < 0:
        raise archive_member_path_error(archive_name, "contains member with invalid size")
    if size > MAX_MEMBER_BYTES:
        raise archive_member_path_error(archive_name, "member is too large")

    entry_count += 1
    if entry_count > MAX_MEMBER_COUNT:
        raise SystemExit(f"{archive_name} contains more than {MAX_MEMBER_COUNT} entries")

    normalized, member_root_style = normalize_member(raw_name, archive_name, expected_root)
    root_style = update_archive_root_style(
        archive_name, raw_name, root_style, member_root_style
    )
    if not normalized:
        if allow_empty:
            return normalized, total_uncompressed, entry_count, root_style
        raise archive_member_path_error(archive_name, "contains empty archive path")
    if normalized in paths:
        raise archive_member_path_error(archive_name, "contains duplicate archive path")

    paths.add(normalized)

    total_uncompressed += size
    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise SystemExit(
            f"{archive_name} uncompressed contents exceed {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
        )
    return normalized, total_uncompressed, entry_count, root_style


def read_zip_member(
    archive_name: str,
    package: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    limit: int,
) -> bytes:
    if member.file_size > limit:
        raise archive_member_path_error(archive_name, f"member is larger than {limit} bytes")
    try:
        with package.open(member, "r") as handle:
            return read_limited(archive_name, "manifest.toml", handle, limit)
    except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise archive_member_path_error(archive_name, "could not read zip member") from exc


def drain_zip_member(
    archive_name: str,
    package: zipfile.ZipFile,
    member: zipfile.ZipInfo,
) -> None:
    try:
        with package.open(member, "r") as handle:
            while handle.read(HASH_CHUNK_BYTES):
                pass
    except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise archive_member_path_error(archive_name, "could not read zip member") from exc


def read_tar_member(
    archive_name: str,
    package: tarfile.TarFile,
    member: tarfile.TarInfo,
    limit: int,
) -> bytes:
    try:
        file_object = package.extractfile(member)
        if file_object is None:
            raise archive_member_path_error(archive_name, "could not read tar member")
        return read_limited(archive_name, "manifest.toml", file_object, limit)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise archive_member_path_error(archive_name, "could not read tar member") from exc


def read_limited(archive_name: str, member_name: str, handle, limit: int) -> bytes:
    content = handle.read(limit + 1)
    if len(content) > limit:
        raise archive_member_path_error(archive_name, f"member is larger than {limit} bytes")
    return content


def expected_archive_root(archive_name: str) -> str:
    if archive_name.endswith(".tar.gz"):
        return archive_name[: -len(".tar.gz")]
    if archive_name.endswith(".zip"):
        return archive_name[: -len(".zip")]
    raise SystemExit(f"unsupported release archive {archive_name}")


def normalize_member(name: str, archive_name: str, expected_root: str) -> tuple[str, str | None]:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    has_windows_drive = re.match(r"^[A-Za-z]:", normalized) is not None
    if path.is_absolute() or has_windows_drive or normalized.startswith("//") or ".." in parts:
        raise archive_member_path_error(archive_name, "contains unsafe archive path")
    root_style = None
    if parts:
        if parts[0] == expected_root:
            root_style = "rooted"
            parts = parts[1:]
        elif parts[0].startswith("conu-"):
            raise archive_member_path_error(archive_name, "contains unexpected archive root")
        else:
            root_style = "rootless"
    return "/".join(parts), root_style


def update_archive_root_style(
    archive_name: str,
    raw_name: str,
    current: str | None,
    member_style: str | None,
) -> str | None:
    if member_style is None:
        return current
    if current is not None and current != member_style:
        raise archive_member_path_error(
            archive_name, "mixes rooted and rootless archive paths"
        )
    return member_style


def verify_members(archive: Path, members: ArchiveMembers) -> None:
    paths = members.paths
    required_bins = required_binary_paths(paths)
    missing_bins = sorted(required_bins - paths)
    if missing_bins:
        raise SystemExit(f"{archive.name} missing binaries: {', '.join(missing_bins)}")

    missing_packaging = sorted(REQUIRED_PACKAGING_FILES - paths)
    if missing_packaging:
        raise SystemExit(
            f"{archive.name} missing packaging templates: {', '.join(missing_packaging)}"
        )

    if members.manifest is None:
        raise SystemExit(f"{archive.name} missing manifest.toml")
    manifest = parse_manifest_key_values(archive, members.manifest)
    if manifest.get("payload_contents_included") != "false":
        raise SystemExit(
            f"{archive.name} manifest does not declare payload_contents_included = false"
        )

    for path in sorted(paths):
        if is_forbidden_release_path(path):
            raise archive_member_path_error(
                archive.name, "contains forbidden release archive path"
            )


def required_binary_paths(paths: set[str]) -> set[str]:
    windows_bins = {f"bin/{binary}.exe" for binary in REQUIRED_BINARIES}
    if windows_bins <= paths:
        return windows_bins
    return {f"bin/{binary}" for binary in REQUIRED_BINARIES}


def parse_manifest_key_values(archive: Path, manifest_bytes: bytes) -> dict[str, str]:
    try:
        manifest_text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{archive.name} manifest.toml is invalid UTF-8") from exc

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(manifest_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise SystemExit(
                f"{archive.name} manifest.toml line {line_number} must include a key"
            )
        if key in values:
            raise SystemExit(
                f"{archive.name} manifest.toml line {line_number} contains duplicate key {key}"
            )
        values[key] = parse_manifest_value(raw_value)
    return values


def parse_manifest_value(raw_value: str) -> str:
    value = raw_value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def is_forbidden_release_path(path: str) -> bool:
    member_path = PurePosixPath(path)
    lower_parts = {part.lower() for part in member_path.parts}
    if lower_parts & FORBIDDEN_PARTS:
        return True

    name = member_path.name.lower()
    if name in FORBIDDEN_NAMES or name.startswith(".env."):
        return True
    return name.endswith(FORBIDDEN_SUFFIXES)


if __name__ == "__main__":
    sys.exit(main())
