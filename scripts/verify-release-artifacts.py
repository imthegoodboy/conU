#!/usr/bin/env python3
"""Validate conU release archives without inspecting local conU state."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


HASH_CHUNK_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 1_000_000_000
MAX_CHECKSUM_BYTES = 4096
MAX_MANIFEST_BYTES = 1_000_000
MAX_MEMBER_BYTES = 512_000_000
MAX_MEMBER_COUNT = 10_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
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
    "node.toml",
    "runtime.toml",
    "trust.toml",
}
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
    validate_regular_file(
        archive,
        "release archive",
        max_bytes=MAX_ARCHIVE_BYTES,
        too_large_message=f"{archive.name} is larger than {MAX_ARCHIVE_BYTES} bytes",
    )

    checksum_path = archive.with_name(f"{archive.name}.sha256")
    validate_regular_file(
        checksum_path,
        f"checksum file for {archive.name}",
        max_bytes=MAX_CHECKSUM_BYTES,
        missing_message=f"missing checksum file for {archive.name}",
        too_large_message=f"checksum file is too large for {archive.name}",
    )

    try:
        checksum_text = checksum_path.read_text(encoding="ascii")
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
    actual = sha256_file(archive)
    if expected != actual:
        raise SystemExit(f"checksum mismatch for {archive.name}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def archive_members(archive: Path) -> ArchiveMembers:
    validate_regular_file(
        archive,
        "release archive",
        max_bytes=MAX_ARCHIVE_BYTES,
        too_large_message=f"{archive.name} is larger than {MAX_ARCHIVE_BYTES} bytes",
    )
    expected_root = expected_archive_root(archive.name)

    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            paths: set[str] = set()
            manifest: bytes | None = None
            total_uncompressed = 0
            entry_count = 0
            root_style: str | None = None
            for member in package.infolist():
                if member.is_dir():
                    if member.file_size != 0:
                        raise SystemExit(
                            f"{archive.name} contains directory member with data: {member.filename}"
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
                    raise SystemExit(
                        f"{archive.name} contains encrypted zip member: {member.filename}"
                    )
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise SystemExit(
                        f"{archive.name} contains unsupported link member: {member.filename}"
                    )
                if file_type not in {0, stat.S_IFREG}:
                    raise SystemExit(
                        f"{archive.name} contains unsupported zip member: {member.filename}"
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
                    manifest = read_zip_member(archive.name, package, member, MAX_MANIFEST_BYTES)
                else:
                    drain_zip_member(archive.name, package, member)
            return ArchiveMembers(paths=paths, manifest=manifest)
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r|gz") as package:
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
                    raise SystemExit(
                        f"{archive.name} contains unsupported non-file member: {member.name}"
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
                    file_object = package.extractfile(member)
                    if file_object is None:
                        raise SystemExit(f"{archive.name} could not read manifest.toml")
                    manifest = read_limited(
                        archive.name,
                        "manifest.toml",
                        file_object,
                        MAX_MANIFEST_BYTES,
                    )
            return ArchiveMembers(paths=paths, manifest=manifest)
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
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    if not path.exists():
        raise SystemExit(missing_message or f"missing {label}: {path.name}")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise SystemExit(f"{label} could not be inspected: {path.name}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file: {path.name}")
    if metadata.st_size > max_bytes:
        raise SystemExit(too_large_message or f"{label} is too large: {path.name}")
    return metadata.st_size


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
        raise SystemExit(f"{archive_name} contains member with invalid size: {raw_name}")
    if size > MAX_MEMBER_BYTES:
        raise SystemExit(f"{archive_name} member is too large: {raw_name}")

    entry_count += 1
    if entry_count > MAX_MEMBER_COUNT:
        raise SystemExit(f"{archive_name} contains more than {MAX_MEMBER_COUNT} entries")

    normalized, member_root_style = normalize_member(raw_name, expected_root)
    root_style = update_archive_root_style(
        archive_name, raw_name, root_style, member_root_style
    )
    if not normalized:
        if allow_empty:
            return normalized, total_uncompressed, entry_count, root_style
        raise SystemExit(f"{archive_name} contains empty archive path: {raw_name}")
    if normalized in paths:
        raise SystemExit(f"{archive_name} contains duplicate archive path: {normalized}")

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
        raise SystemExit(f"{archive_name} manifest.toml is larger than {limit} bytes")
    try:
        with package.open(member, "r") as handle:
            return read_limited(archive_name, "manifest.toml", handle, limit)
    except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise SystemExit(
            f"{archive_name} could not read zip member: {member.filename}"
        ) from exc


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
        raise SystemExit(
            f"{archive_name} could not read zip member: {member.filename}"
        ) from exc


def read_limited(archive_name: str, member_name: str, handle, limit: int) -> bytes:
    content = handle.read(limit + 1)
    if len(content) > limit:
        raise SystemExit(f"{archive_name} {member_name} is larger than {limit} bytes")
    return content


def expected_archive_root(archive_name: str) -> str:
    if archive_name.endswith(".tar.gz"):
        return archive_name[: -len(".tar.gz")]
    if archive_name.endswith(".zip"):
        return archive_name[: -len(".zip")]
    raise SystemExit(f"unsupported release archive {archive_name}")


def normalize_member(name: str, expected_root: str) -> tuple[str, str | None]:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe archive path: {name}")
    root_style = None
    if parts:
        if parts[0] == expected_root:
            root_style = "rooted"
            parts = parts[1:]
        elif parts[0].startswith("conu-"):
            raise SystemExit(
                f"unexpected archive root: {parts[0]} (expected {expected_root})"
            )
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
        raise SystemExit(
            f"{archive_name} mixes rooted and rootless archive paths: {raw_name}"
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
    manifest_text = members.manifest.decode("utf-8", errors="replace")
    if "payload_contents_included = false" not in manifest_text:
        raise SystemExit(
            f"{archive.name} manifest does not declare payload_contents_included = false"
        )

    for path in sorted(paths):
        member_path = PurePosixPath(path)
        parts = set(member_path.parts)
        if parts & FORBIDDEN_PARTS or member_path.name in FORBIDDEN_NAMES:
            raise SystemExit(f"{archive.name} contains forbidden state path: {path}")


def required_binary_paths(paths: set[str]) -> set[str]:
    windows_bins = {f"bin/{binary}.exe" for binary in REQUIRED_BINARIES}
    if windows_bins <= paths:
        return windows_bins
    return {f"bin/{binary}" for binary in REQUIRED_BINARIES}


if __name__ == "__main__":
    sys.exit(main())
