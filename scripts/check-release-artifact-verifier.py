#!/usr/bin/env python3
"""Regression checks for release artifact verification fail-closed behavior."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify-release-artifacts.py"
REQUIRED_FILES = {
    "manifest.toml": b'payload_contents_included = false\n',
    "bin/conu": b"placeholder",
    "bin/conud": b"placeholder",
    "bin/conu-relay": b"placeholder",
    "bin/conu-mcp": b"placeholder",
    "packaging/README.md": b"placeholder",
    "packaging/docker/README.md": b"placeholder",
    "packaging/docker/relay.Dockerfile": b"placeholder",
    "packaging/linux/conud.service": b"placeholder",
    "packaging/macos/com.conu.conud.plist": b"placeholder",
    "packaging/npm/conu-cli/package.json": b"{}",
    "packaging/npm/conu-cli/scripts/install.js": b"placeholder",
    "packaging/windows/install.ps1": b"placeholder",
    "packaging/windows/uninstall.ps1": b"placeholder",
}


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_release_artifacts", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load release artifact verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_checksum(path: Path, archive_name: str | None = None, hash_text: str | None = None) -> None:
    digest = hash_text or hashlib.sha256(path.read_bytes()).hexdigest()
    name = archive_name or path.name
    path.with_name(f"{path.name}.sha256").write_text(f"{digest}  {name}\n", encoding="ascii")


def archive_prefix(path: Path) -> str:
    if path.name.endswith(".tar.gz"):
        return path.name[: -len(".tar.gz")]
    return path.stem


def write_zip(
    path: Path,
    extra: dict[str, bytes] | None = None,
    *,
    prefix: str | None = None,
) -> None:
    prefix = prefix or archive_prefix(path)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in REQUIRED_FILES.items():
            package.writestr(f"{prefix}/{name}", content)
        for name, content in (extra or {}).items():
            package.writestr(name, content)
    write_checksum(path)


def mark_zip_member_encrypted(path: Path, member_name: str) -> None:
    data = bytearray(path.read_bytes())
    target = member_name.encode("utf-8")
    offset = 0
    while offset + 4 <= len(data):
        signature = int.from_bytes(data[offset : offset + 4], "little")
        if signature == 0x04034B50:
            name_length = int.from_bytes(data[offset + 26 : offset + 28], "little")
            extra_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
            name_start = offset + 30
            name_end = name_start + name_length
            compressed_size = int.from_bytes(data[offset + 18 : offset + 22], "little")
            if data[name_start:name_end] == target:
                flags = int.from_bytes(data[offset + 6 : offset + 8], "little") | 0x1
                data[offset + 6 : offset + 8] = flags.to_bytes(2, "little")
            offset = name_end + extra_length + compressed_size
            continue
        if signature == 0x02014B50:
            name_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
            extra_length = int.from_bytes(data[offset + 30 : offset + 32], "little")
            comment_length = int.from_bytes(data[offset + 32 : offset + 34], "little")
            name_start = offset + 46
            name_end = name_start + name_length
            if data[name_start:name_end] == target:
                flags = int.from_bytes(data[offset + 8 : offset + 10], "little") | 0x1
                data[offset + 8 : offset + 10] = flags.to_bytes(2, "little")
            offset = name_end + extra_length + comment_length
            continue
        offset += 1
    path.write_bytes(data)
    write_checksum(path)


def corrupt_zip_member_data(path: Path, member_name: str) -> None:
    data = bytearray(path.read_bytes())
    target = member_name.encode("utf-8")
    offset = 0
    while offset + 4 <= len(data):
        signature = int.from_bytes(data[offset : offset + 4], "little")
        if signature != 0x04034B50:
            offset += 1
            continue
        name_length = int.from_bytes(data[offset + 26 : offset + 28], "little")
        extra_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
        name_start = offset + 30
        name_end = name_start + name_length
        data_start = name_end + extra_length
        compressed_size = int.from_bytes(data[offset + 18 : offset + 22], "little")
        data_end = data_start + compressed_size
        if data[name_start:name_end] == target:
            if compressed_size == 0:
                raise AssertionError(f"{member_name} had no compressed data to corrupt")
            data[data_end - 1] ^= 0xFF
            path.write_bytes(data)
            write_checksum(path)
            return
        offset = data_end
    raise AssertionError(f"zip member not found for corruption: {member_name}")


def write_tar(path: Path, *, prefix: str | None = None) -> None:
    prefix = prefix or archive_prefix(path)
    with tarfile.open(path, "w:gz") as package:
        for name, content in REQUIRED_FILES.items():
            data = io.BytesIO(content)
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(content)
            package.addfile(info, data)
    write_checksum(path)


def verify_archive(verifier, archive: Path) -> None:
    verifier.verify_checksum(archive)
    members = verifier.archive_members(archive)
    verifier.verify_members(archive, members)


def expect_failure(description: str, action, expected: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected not in message:
            raise AssertionError(
                f"{description} failed with {message!r}, expected {expected!r}"
            ) from exc
        return
    raise AssertionError(f"{description} unexpectedly passed")


def main() -> int:
    verifier = load_verifier()
    with tempfile.TemporaryDirectory(prefix="conu-release-verifier-") as temp:
        root = Path(temp)

        valid_zip = root / "conu-0.1.0-test.zip"
        write_zip(valid_zip)
        verify_archive(verifier, valid_zip)

        original_max_archive_bytes = verifier.MAX_ARCHIVE_BYTES
        verifier.MAX_ARCHIVE_BYTES = 1
        try:
            expect_failure(
                "oversized archive before checksum hashing",
                lambda: verifier.verify_checksum(valid_zip),
                "is larger than",
            )
        finally:
            verifier.MAX_ARCHIVE_BYTES = original_max_archive_bytes

        valid_tar = root / "conu-0.1.0-test.tar.gz"
        write_tar(valid_tar)
        verify_archive(verifier, valid_tar)

        wrong_name = root / "conu-0.1.0-wrong-name.zip"
        write_zip(wrong_name)
        write_checksum(wrong_name, archive_name="other.zip")
        expect_failure(
            "wrong checksum archive name",
            lambda: verifier.verify_checksum(wrong_name),
            "names wrong archive",
        )

        loose_checksum = root / "conu-0.1.0-loose-checksum.zip"
        write_zip(loose_checksum)
        digest = hashlib.sha256(loose_checksum.read_bytes()).hexdigest()
        loose_checksum.with_name(f"{loose_checksum.name}.sha256").write_text(
            f"{digest}\n",
            encoding="ascii",
        )
        expect_failure(
            "loose checksum format",
            lambda: verifier.verify_checksum(loose_checksum),
            "invalid format",
        )

        duplicate = root / "conu-0.1.0-duplicate.zip"
        write_zip(duplicate, {f"{archive_prefix(duplicate)}/./manifest.toml": b"duplicate"})
        expect_failure(
            "duplicate normalized path",
            lambda: verifier.archive_members(duplicate),
            "duplicate archive path",
        )

        encrypted = root / "conu-0.1.0-encrypted.zip"
        write_zip(encrypted)
        mark_zip_member_encrypted(encrypted, f"{archive_prefix(encrypted)}/bin/conu")
        expect_failure(
            "encrypted zip member",
            lambda: verifier.archive_members(encrypted),
            "encrypted zip member",
        )

        corrupt_member = root / "conu-0.1.0-corrupt-member.zip"
        write_zip(corrupt_member)
        corrupt_zip_member_data(corrupt_member, f"{archive_prefix(corrupt_member)}/bin/conu")
        expect_failure(
            "corrupt zip member",
            lambda: verifier.archive_members(corrupt_member),
            "could not read zip member",
        )

        forbidden = root / "conu-0.1.0-forbidden.zip"
        write_zip(forbidden, {f"{archive_prefix(forbidden)}/.conu/node.toml": b"state"})
        expect_failure(
            "forbidden state path",
            lambda: verify_archive(verifier, forbidden),
            "forbidden state path",
        )

        forbidden_dir = root / "conu-0.1.0-forbidden-dir.zip"
        write_zip(forbidden_dir, {f"{archive_prefix(forbidden_dir)}/security/": b""})
        expect_failure(
            "forbidden state directory",
            lambda: verify_archive(verifier, forbidden_dir),
            "forbidden state path",
        )

        wrong_root = root / "conu-0.1.0-wrong-root.zip"
        write_zip(wrong_root, prefix="conu-9.9.9-test")
        expect_failure(
            "unexpected archive root",
            lambda: verifier.archive_members(wrong_root),
            "unexpected archive root",
        )

        mixed_root = root / "conu-0.1.0-mixed-root.zip"
        write_zip(mixed_root, {"bin/conu": b"rootless duplicate"})
        expect_failure(
            "mixed rooted and rootless archive paths",
            lambda: verifier.archive_members(mixed_root),
            "mixes rooted and rootless",
        )

        data_dir = root / "conu-0.1.0-data-dir.zip"
        write_zip(data_dir, {f"{archive_prefix(data_dir)}/docs/": b"payload"})
        expect_failure(
            "data-bearing directory",
            lambda: verifier.archive_members(data_dir),
            "directory member with data",
        )

    print("release artifact verifier regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
