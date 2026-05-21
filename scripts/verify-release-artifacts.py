#!/usr/bin/env python3
"""Validate conU release archives without inspecting local conU state."""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    args = parser.parse_args()

    archives = sorted(args.dist.glob("*.zip")) + sorted(args.dist.glob("*.tar.gz"))
    if not archives:
        raise SystemExit(f"no release archives found in {args.dist}")

    for archive in archives:
        verify_checksum(archive)
        members = archive_members(archive)
        verify_members(archive, members)

    print(f"verified {len(archives)} conU release archive(s)")
    return 0


def verify_checksum(archive: Path) -> None:
    checksum_path = archive.with_name(f"{archive.name}.sha256")
    if not checksum_path.exists():
        raise SystemExit(f"missing checksum file for {archive.name}")
    expected = checksum_path.read_text(encoding="ascii").split()[0].lower()
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if expected != actual:
        raise SystemExit(f"checksum mismatch for {archive.name}")


def archive_members(archive: Path) -> dict[str, bytes | None]:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            members: dict[str, bytes | None] = {}
            for member in package.infolist():
                if member.filename.endswith("/"):
                    continue
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise SystemExit(
                        f"{archive.name} contains unsupported link member: {member.filename}"
                    )
                members[normalize_member(member.filename)] = package.read(member)
            return members
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as package:
            members: dict[str, bytes | None] = {}
            for member in package.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    raise SystemExit(
                        f"{archive.name} contains unsupported non-file member: {member.name}"
                    )
                file_object = package.extractfile(member)
                members[normalize_member(member.name)] = (
                    file_object.read() if file_object is not None else None
                )
            return members
    raise SystemExit(f"unsupported release archive {archive.name}")


def normalize_member(name: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe archive path: {name}")
    if parts and parts[0].startswith("conu-"):
        parts = parts[1:]
    return "/".join(parts)


def verify_members(archive: Path, members: dict[str, bytes | None]) -> None:
    paths = set(members)
    required_bins = {
        f"bin/{binary}{'.exe' if archive.suffix == '.zip' else ''}"
        for binary in REQUIRED_BINARIES
    }
    missing_bins = sorted(required_bins - paths)
    if missing_bins:
        raise SystemExit(f"{archive.name} missing binaries: {', '.join(missing_bins)}")

    manifest = members.get("manifest.toml")
    if manifest is None:
        raise SystemExit(f"{archive.name} missing manifest.toml")
    manifest_text = manifest.decode("utf-8", errors="replace")
    if "payload_contents_included = false" not in manifest_text:
        raise SystemExit(
            f"{archive.name} manifest does not declare payload_contents_included = false"
        )

    for path in sorted(paths):
        member_path = PurePosixPath(path)
        parts = set(member_path.parts)
        if parts & FORBIDDEN_PARTS or member_path.name in FORBIDDEN_NAMES:
            raise SystemExit(f"{archive.name} contains forbidden state path: {path}")


if __name__ == "__main__":
    sys.exit(main())
