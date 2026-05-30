#!/usr/bin/env python3
"""Generate package-manager manifests from verified conU release assets."""

from __future__ import annotations

import argparse
import errno
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_CHECKSUM_BYTES = 4096
HASH_CHUNK_BYTES = 1024 * 1024
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_BINARY = getattr(os, "O_BINARY", 0)
EXPECTED_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
DEBIAN_ARCHES = {
    "linux-x64": "amd64",
    "linux-arm64": "arm64",
}
RPM_ARCHES = {
    "linux-x64": "x86_64",
    "linux-arm64": "aarch64",
}
STATIC_OUTPUT_FILENAMES = (
    "conu.rb",
    "conu.json",
    "imthegoodboy.conU.yaml",
    "conu.spec",
)
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
SOURCE_EPOCH = 1577836800
MAX_RELEASE_ARCHIVE_BYTES = 1_000_000_000
MAX_RELEASE_MEMBER_BYTES = 512_000_000
MAX_RELEASE_MEMBER_COUNT = 10_000
MAX_RELEASE_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
MAX_PACKAGE_BINARY_BYTES = MAX_RELEASE_MEMBER_BYTES
MAX_GENERATED_OUTPUT_BYTES = MAX_RELEASE_TOTAL_UNCOMPRESSED_BYTES


@dataclass
class ArchiveScanState:
    paths: set[str]
    entry_count: int = 0
    total_uncompressed: int = 0


@dataclass(frozen=True)
class ReleaseAsset:
    target: str
    filename: str
    sha256: str
    url: str


@dataclass(frozen=True)
class DebianPackage:
    filename: str
    architecture: str
    package_version: str
    content: bytes
    sha256: str
    metadata_text: str


@dataclass(frozen=True)
class AptRepositoryMetadata:
    filename: str
    content: bytes
    sha256: str
    metadata_text: str


@dataclass(frozen=True)
class RpmRepositoryMetadata:
    filename: str
    content: bytes
    sha256: str
    metadata_text: str


def main() -> int:
    args = parse_args()
    dist = args.dist.expanduser()
    validate_input_directory(dist, "release dist directory")
    dist = dist.resolve()
    version = args.version or read_repo_version()
    validate_version(version)
    repo = validate_repo(args.repo)
    tag = validate_tag(args.tag or f"v{version}")
    output_dir = args.output_dir.expanduser()
    prepare_output_directory(output_dir, "package-manager output directory")
    output_dir = output_dir.resolve()

    assets = load_release_assets(dist, version, repo, tag)
    windows_extract_dir = detect_windows_extract_dir(dist / assets["windows-x64"].filename, version)
    linux_binaries = {
        target: extract_linux_binaries(dist / assets[target].filename, version, target)
        for target in DEBIAN_ARCHES
    }

    homebrew = render_homebrew_formula(version, repo, assets)
    scoop = render_scoop_manifest(version, repo, assets["windows-x64"], windows_extract_dir)
    winget = render_winget_manifest(version, repo, assets["windows-x64"], windows_extract_dir)
    chocolatey_nuspec = render_chocolatey_nuspec(version, repo)
    chocolatey_install = render_chocolatey_install(
        version,
        assets["windows-x64"],
        windows_extract_dir,
    )
    chocolatey_uninstall = render_chocolatey_uninstall(
        assets["windows-x64"],
    )
    debian_packages = [
        build_debian_package(version, repo, target, linux_binaries[target])
        for target in DEBIAN_ARCHES
    ]
    apt_repository_metadata = (
        build_apt_repository_metadata(version, repo, debian_packages)
        if args.build_apt_repository_metadata
        else None
    )
    rpm_spec = render_rpm_spec(version, repo, assets)
    safe_texts = [
        homebrew,
        scoop,
        winget,
        chocolatey_nuspec,
        chocolatey_install,
        chocolatey_uninstall,
        rpm_spec,
        *[package.metadata_text for package in debian_packages],
    ]
    if apt_repository_metadata is not None:
        safe_texts.append(apt_repository_metadata.metadata_text)
    assert_output_safe(
        "\n".join(safe_texts),
        dist,
    )

    write_text_output(output_dir / "conu.rb", "Homebrew formula", homebrew)
    write_text_output(output_dir / "conu.json", "Scoop manifest", scoop)
    write_text_output(output_dir / "imthegoodboy.conU.yaml", "WinGet manifest", winget)
    write_chocolatey_package(
        output_dir / chocolatey_filename(version),
        chocolatey_nuspec,
        chocolatey_install,
        chocolatey_uninstall,
    )
    for package in debian_packages:
        package_path = output_dir / package.filename
        write_bytes_output(package_path, "generated Debian package", package.content)
        write_sha256_sidecar(package_path, package.sha256)
    if apt_repository_metadata is not None:
        metadata_path = output_dir / apt_repository_metadata.filename
        write_bytes_output(
            metadata_path,
            "generated APT repository metadata",
            apt_repository_metadata.content,
        )
        write_sha256_sidecar(metadata_path, apt_repository_metadata.sha256)
    rpm_spec_path = output_dir / "conu.spec"
    write_text_output(rpm_spec_path, "RPM spec", rpm_spec)
    rpm_package_paths: tuple[Path, ...] = ()
    if args.build_rpm_packages:
        rpm_package_paths = build_rpm_packages(version, dist, rpm_spec_path, output_dir)
    elif args.build_rpm_repository_metadata:
        rpm_package_paths = existing_rpm_package_paths(version, output_dir)
    if args.build_rpm_repository_metadata:
        rpm_repository_metadata = build_rpm_repository_metadata(version, rpm_package_paths)
        assert_output_safe(rpm_repository_metadata.metadata_text, dist)
        metadata_path = output_dir / rpm_repository_metadata.filename
        write_bytes_output(
            metadata_path,
            "generated RPM repository metadata",
            rpm_repository_metadata.content,
        )
        write_sha256_sidecar(metadata_path, rpm_repository_metadata.sha256)
    print(
        "generated package-manager manifests: "
        + ", ".join(
            str(output_dir / name)
            for name in output_filenames(
                version,
                include_rpm_packages=args.build_rpm_packages,
                include_apt_repository_metadata=args.build_apt_repository_metadata,
                include_rpm_repository_metadata=args.build_rpm_repository_metadata,
            )
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory for generated package-manager files",
    )
    parser.add_argument("--version", help="release version; defaults to npm package version")
    parser.add_argument("--tag", help="release tag; defaults to v<version>")
    parser.add_argument("--repo", default="imthegoodboy/conU", help="GitHub repository owner/name")
    parser.add_argument(
        "--build-rpm-packages",
        action="store_true",
        help="build unsigned x86_64 and aarch64 .rpm packages with rpmbuild",
    )
    parser.add_argument(
        "--build-apt-repository-metadata",
        action="store_true",
        help="build unsigned deterministic APT repository metadata for generated .deb packages",
    )
    parser.add_argument(
        "--build-rpm-repository-metadata",
        action="store_true",
        help="build RPM/YUM repository metadata for generated .rpm packages",
    )
    return parser.parse_args()


def read_repo_version() -> str:
    package_json = Path(__file__).resolve().parents[1] / "packaging/npm/conu-cli/package.json"
    with package_json.open("r", encoding="utf-8") as handle:
        package = json.load(handle)
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{package_json} does not contain a non-empty version")
    return version


def validate_version(version: str) -> str:
    if not SEMVER_RE.fullmatch(version):
        raise SystemExit(f"invalid release version for package-manager manifests: {version}")
    return version


def validate_repo(repo: str) -> str:
    if not REPO_RE.fullmatch(repo):
        raise SystemExit(f"invalid GitHub repository owner/name: {repo}")
    return repo


def validate_tag(tag: str) -> str:
    if not TAG_RE.fullmatch(tag):
        raise SystemExit(f"invalid release tag for package-manager manifests: {tag}")
    return tag


def expected_filenames(version: str) -> dict[str, str]:
    return {
        "macos-arm64": f"conu-{version}-macos-arm64.zip",
        "macos-x64": f"conu-{version}-macos-x64.zip",
        "linux-arm64": f"conu-{version}-linux-arm64.tar.gz",
        "linux-x64": f"conu-{version}-linux-x64.tar.gz",
        "windows-x64": f"conu-{version}-windows-x64.zip",
    }


def chocolatey_filename(version: str) -> str:
    return f"conu.{version}.nupkg"


def debian_version(version: str) -> str:
    return version.replace("-", "~")


def debian_filename(version: str, target: str) -> str:
    return f"conu_{debian_version(version)}_{DEBIAN_ARCHES[target]}.deb"


def rpm_version(version: str) -> str:
    return version.replace("-", "~").replace("+", "_")


def rpm_filename(version: str, target: str) -> str:
    return f"conu-{rpm_version(version)}-1.{RPM_ARCHES[target]}.rpm"


def rpm_output_filenames(version: str) -> tuple[str, ...]:
    outputs = []
    for target in RPM_ARCHES:
        filename = rpm_filename(version, target)
        outputs.extend([filename, f"{filename}.sha256"])
    return tuple(outputs)


def apt_repository_metadata_filename(version: str) -> str:
    return f"conu-{debian_version(version)}-apt-repository-metadata.zip"


def apt_repository_metadata_output_filenames(version: str) -> tuple[str, ...]:
    filename = apt_repository_metadata_filename(version)
    return (filename, f"{filename}.sha256")


def rpm_repository_metadata_filename(version: str) -> str:
    return f"conu-{rpm_version(version)}-rpm-repository-metadata.zip"


def rpm_repository_metadata_output_filenames(version: str) -> tuple[str, ...]:
    filename = rpm_repository_metadata_filename(version)
    return (filename, f"{filename}.sha256")


def output_filenames(
    version: str,
    *,
    include_rpm_packages: bool = False,
    include_apt_repository_metadata: bool = False,
    include_rpm_repository_metadata: bool = False,
) -> tuple[str, ...]:
    debian_outputs = []
    for target in DEBIAN_ARCHES:
        filename = debian_filename(version, target)
        debian_outputs.extend([filename, f"{filename}.sha256"])
    rpm_outputs = rpm_output_filenames(version) if include_rpm_packages else ()
    apt_outputs = (
        apt_repository_metadata_output_filenames(version)
        if include_apt_repository_metadata
        else ()
    )
    rpm_repository_outputs = (
        rpm_repository_metadata_output_filenames(version)
        if include_rpm_repository_metadata
        else ()
    )
    return (
        *STATIC_OUTPUT_FILENAMES,
        chocolatey_filename(version),
        *debian_outputs,
        *apt_outputs,
        *rpm_outputs,
        *rpm_repository_outputs,
    )


def load_release_assets(
    dist: Path,
    version: str,
    repo: str,
    tag: str,
) -> dict[str, ReleaseAsset]:
    validate_input_directory(dist, "release dist directory")

    assets: dict[str, ReleaseAsset] = {}
    for target, filename in expected_filenames(version).items():
        archive = dist / filename
        validate_regular_file(
            archive,
            f"release asset for {target}",
            max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
        )
        sha256 = read_verified_checksum(archive)
        url = f"https://github.com/{repo}/releases/download/{tag}/{filename}"
        assets[target] = ReleaseAsset(
            target=target,
            filename=filename,
            sha256=sha256,
            url=url,
        )
    return assets


def validate_release_asset_size(archive: Path) -> None:
    validate_regular_file(
        archive,
        "release asset",
        max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
    )


def read_verified_checksum(archive: Path) -> str:
    validate_regular_file(
        archive,
        "package-manager release asset",
        max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
    )
    checksum_path = archive.with_name(f"{archive.name}.sha256")
    validate_regular_file(
        checksum_path,
        "checksum file for package-manager asset",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    try:
        checksum_text = read_ascii_file(
            checksum_path,
            "checksum file for package-manager asset",
            max_bytes=MAX_CHECKSUM_BYTES,
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"checksum file is not ASCII for package-manager asset: {archive.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"checksum file has invalid format for package-manager asset: {archive.name}")
    named_archive = match.group(2)
    if named_archive != archive.name:
        raise SystemExit(
            f"checksum file for package-manager asset {archive.name} names wrong archive: {named_archive}"
        )
    expected = match.group(1).lower()
    actual = sha256_file(
        archive,
        "package-manager release asset",
        max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
    )
    if expected != actual:
        raise SystemExit(f"checksum mismatch for package-manager asset: {archive.name}")
    return expected


def validate_input_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")


def prepare_output_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if path.exists() and not path.is_dir():
        raise SystemExit(f"{label} must be a directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def validate_regular_file(path: Path, label: str, *, max_bytes: int) -> int:
    handle, size = open_regular_file(path, label, max_bytes=max_bytes)
    handle.close()
    return size


def open_regular_file(path: Path, label: str, *, max_bytes: int) -> tuple[BinaryIO, int]:
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
        if metadata.st_size > max_bytes:
            raise SystemExit(f"{label} is too large: {path.name}")
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


def validate_output_file(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{label} output must not be a symlink: {path.name}")
    if path.exists():
        try:
            metadata = path.stat()
        except OSError as exc:
            raise SystemExit(f"{label} output could not be inspected: {path.name}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} output must be a regular file: {path.name}")


def open_output_file(path: Path, label: str) -> BinaryIO:
    validate_output_file(path, label)
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC | OPEN_BINARY | OPEN_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"{label} output must not be a symlink: {path.name}") from exc
        if path.exists() and not path.is_file():
            raise SystemExit(f"{label} output must be a regular file: {path.name}") from exc
        raise SystemExit(f"{label} output could not be opened: {path.name}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} output must be a regular file: {path.name}")
        return os.fdopen(fd, "w+b")
    except BaseException:
        os.close(fd)
        raise


def write_text_output(path: Path, label: str, text: str) -> None:
    with open_output_file(path, label) as handle:
        handle.write(text.encode("ascii"))
        handle.flush()
        validate_open_regular_file(handle, label, max_bytes=MAX_GENERATED_OUTPUT_BYTES)
    validate_regular_file(path, label, max_bytes=MAX_GENERATED_OUTPUT_BYTES)


def write_bytes_output(path: Path, label: str, data: bytes) -> None:
    with open_output_file(path, label) as handle:
        handle.write(data)
        handle.flush()
        validate_open_regular_file(handle, label, max_bytes=MAX_GENERATED_OUTPUT_BYTES)
    validate_regular_file(path, label, max_bytes=MAX_GENERATED_OUTPUT_BYTES)


def read_ascii_file(path: Path, label: str, *, max_bytes: int) -> str:
    data = read_regular_file(path, label, max_bytes=max_bytes)
    return data.decode("ascii")


def read_regular_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    handle, _size = open_regular_file(path, label, max_bytes=max_bytes)
    with handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large: {path.name}")
    return data


def copy_regular_file_output(source: Path, output: Path, label: str, *, max_bytes: int) -> None:
    source_file, _size = open_regular_file(source, label, max_bytes=max_bytes)
    with source_file:
        with open_output_file(output, label) as output_file:
            shutil.copyfileobj(source_file, output_file, HASH_CHUNK_BYTES)
            output_file.flush()
            validate_open_regular_file(output_file, label, max_bytes=max_bytes)
    validate_regular_file(output, label, max_bytes=max_bytes)


def sha256_file(
    path: Path,
    label: str = "package-manager file",
    *,
    max_bytes: int = MAX_GENERATED_OUTPUT_BYTES,
) -> str:
    handle, _size = open_regular_file(path, label, max_bytes=max_bytes)
    with handle:
        return sha256_open_file(handle, label, max_bytes=max_bytes)


def sha256_open_file(handle: BinaryIO, label: str, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    if handle.writable():
        handle.flush()
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
    handle.seek(0, os.SEEK_END)
    return digest.hexdigest()


def detect_windows_extract_dir(archive: Path, version: str) -> str | None:
    archive_file, _size = open_regular_file(
        archive,
        "Windows package-manager release asset",
        max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
    )
    root = f"conu-{version}-windows-x64"
    rootless_bins = {f"bin/{binary}.exe" for binary in EXPECTED_BINARIES}
    state = ArchiveScanState(paths=set())
    root_style: str | None = None
    file_paths: set[str] = set()

    try:
        with archive_file:
            with zipfile.ZipFile(archive_file) as package:
                infos = package.infolist()
                if len(infos) > MAX_RELEASE_MEMBER_COUNT:
                    raise SystemExit(
                        f"{archive.name} contains more than {MAX_RELEASE_MEMBER_COUNT} entries"
                    )
                for member in infos:
                    normalized, root_style, is_file = validate_zip_release_member_for_scan(
                        archive.name,
                        member,
                        root,
                        state,
                        root_style,
                    )
                    if is_file:
                        file_paths.add(normalized)
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"windows release asset is not a readable zip: {archive.name}") from exc

    if rootless_bins <= file_paths:
        if root_style == "rooted":
            return root
        return None
    raise SystemExit(
        f"{archive.name} does not contain expected rootless or {root}/bin Windows binaries"
    )


def validate_zip_release_member_for_scan(
    archive_name: str,
    member: zipfile.ZipInfo,
    expected_root: str,
    state: ArchiveScanState,
    root_style: str | None,
) -> tuple[str, str | None, bool]:
    raw_name = member.filename
    if member.flag_bits & 0x1:
        raise SystemExit(f"{archive_name} contains encrypted zip member: {raw_name}")
    file_type = (member.external_attr >> 16) & 0o170000
    is_directory = member.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise SystemExit(f"{archive_name} contains unsupported link member: {raw_name}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise SystemExit(f"{archive_name} contains unsupported zip member: {raw_name}")
    if is_directory:
        if member.file_size != 0:
            raise SystemExit(f"{archive_name} contains directory member with data: {raw_name}")
        normalized, root_style = record_release_archive_member(
            archive_name,
            raw_name,
            expected_root,
            0,
            state,
            root_style,
            allow_empty=True,
        )
        return normalized, root_style, False
    normalized, root_style = record_release_archive_member(
        archive_name,
        raw_name,
        expected_root,
        member.file_size,
        state,
        root_style,
    )
    return normalized, root_style, True


def record_release_archive_member(
    archive_name: str,
    raw_name: str,
    expected_root: str,
    size: int,
    state: ArchiveScanState,
    root_style: str | None,
    *,
    allow_empty: bool = False,
) -> tuple[str, str | None]:
    if size < 0:
        raise SystemExit(f"{archive_name} contains member with invalid size: {raw_name}")
    if size > MAX_RELEASE_MEMBER_BYTES:
        raise SystemExit(f"{archive_name} member is too large: {raw_name}")

    state.entry_count += 1
    if state.entry_count > MAX_RELEASE_MEMBER_COUNT:
        raise SystemExit(f"{archive_name} contains more than {MAX_RELEASE_MEMBER_COUNT} entries")

    normalized, member_style = normalize_release_member_path(raw_name, expected_root)
    root_style = update_release_root_style(archive_name, raw_name, root_style, member_style)
    if not normalized:
        if allow_empty:
            return normalized, root_style
        raise SystemExit(f"{archive_name} contains empty archive path: {raw_name}")

    if normalized in state.paths:
        raise SystemExit(f"{archive_name} contains duplicate archive path: {normalized}")
    state.paths.add(normalized)

    state.total_uncompressed += size
    if state.total_uncompressed > MAX_RELEASE_TOTAL_UNCOMPRESSED_BYTES:
        raise SystemExit(
            f"{archive_name} uncompressed contents exceed "
            f"{MAX_RELEASE_TOTAL_UNCOMPRESSED_BYTES} bytes"
        )
    return normalized, root_style


def normalize_release_member_path(raw_name: str, expected_root: str) -> tuple[str, str | None]:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe archive path in package-manager asset: {raw_name}")
    root_style = None
    if parts:
        if parts[0] == expected_root:
            root_style = "rooted"
            parts = parts[1:]
        elif parts[0].startswith("conu-"):
            raise SystemExit(
                f"unexpected archive root in package-manager asset: {parts[0]} "
                f"(expected {expected_root})"
            )
        else:
            root_style = "rootless"
    return "/".join(parts), root_style


def update_release_root_style(
    archive_name: str,
    raw_name: str,
    current: str | None,
    member_style: str | None,
) -> str | None:
    if member_style is None:
        return current
    if current is not None and current != member_style:
        raise SystemExit(f"{archive_name} mixes rooted and rootless archive paths: {raw_name}")
    return member_style


def extract_linux_binaries(archive: Path, version: str, target: str) -> dict[str, bytes]:
    archive_file, _size = open_regular_file(
        archive,
        "Linux package-manager release asset",
        max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
    )
    root = f"conu-{version}-{target}"
    rootless_bins = {f"bin/{binary}" for binary in EXPECTED_BINARIES}
    state = ArchiveScanState(paths=set())
    file_paths: set[str] = set()
    root_style: str | None = None
    extracted: dict[str, bytes] = {}

    try:
        with archive_file:
            with tarfile.open(fileobj=archive_file, mode="r|gz") as package:
                for member in package:
                    if member.isdir():
                        if member.size != 0:
                            raise SystemExit(
                                f"{archive.name} contains directory member with data: {member.name}"
                            )
                        _, root_style = record_release_archive_member(
                            archive.name,
                            member.name,
                            root,
                            0,
                            state,
                            root_style,
                            allow_empty=True,
                        )
                        continue
                    if not member.isfile():
                        raise SystemExit(
                            f"{archive.name} contains unsupported non-file member: {member.name}"
                        )
                    normalized, root_style = record_release_archive_member(
                        archive.name,
                        member.name,
                        root,
                        member.size,
                        state,
                        root_style,
                    )
                    if not normalized:
                        continue
                    file_paths.add(normalized)
                    if normalized not in rootless_bins:
                        continue
                    handle = package.extractfile(member)
                    if handle is None:
                        raise SystemExit(f"{archive.name} could not read binary: {member.name}")
                    extracted[normalized] = read_limited_release_member(
                        archive.name,
                        member.name,
                        handle,
                        MAX_PACKAGE_BINARY_BYTES,
                    )
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise SystemExit(f"linux release asset is not a readable tar.gz: {archive.name}") from exc

    if not rootless_bins <= file_paths:
        raise SystemExit(
            f"{archive.name} does not contain expected rootless or {root}/bin Linux binaries"
        )

    binaries: dict[str, bytes] = {}
    for binary in EXPECTED_BINARIES:
        path = f"bin/{binary}"
        if path not in extracted:
            raise SystemExit(f"{archive.name} could not extract expected binary: {path}")
        binaries[binary] = extracted[path]
    return binaries


def read_limited_release_member(
    archive_name: str,
    member_name: str,
    handle,
    limit: int,
) -> bytes:
    content = handle.read(limit + 1)
    if len(content) > limit:
        raise SystemExit(f"{archive_name} member is too large: {member_name}")
    return content


def render_homebrew_formula(version: str, repo: str, assets: dict[str, ReleaseAsset]) -> str:
    return f"""# Generated by scripts/generate-package-manager-manifests.py.
class Conu < Formula
  desc "Agent-native encrypted communication layer"
  homepage "https://github.com/{repo}"
  license :cannot_represent
  version "{version}"

  on_macos do
    if Hardware::CPU.arm?
      url "{assets["macos-arm64"].url}"
      sha256 "{assets["macos-arm64"].sha256}"
    else
      url "{assets["macos-x64"].url}"
      sha256 "{assets["macos-x64"].sha256}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "{assets["linux-arm64"].url}"
      sha256 "{assets["linux-arm64"].sha256}"
    else
      url "{assets["linux-x64"].url}"
      sha256 "{assets["linux-x64"].sha256}"
    end
  end

  def package_root
    suffix = if OS.mac?
      Hardware::CPU.arm? ? "macos-arm64" : "macos-x64"
    else
      Hardware::CPU.arm? ? "linux-arm64" : "linux-x64"
    end
    rooted = buildpath/"conu-#{{version}}-#{{suffix}}"
    return rooted if (rooted/"bin/conu").exist?
    return buildpath if (buildpath/"bin/conu").exist?
    odie "conU release archive is missing bin/conu"
  end

  def install
    root = package_root
    bin.install root/"bin/conu"
    bin.install root/"bin/conud"
    bin.install root/"bin/conu-relay"
    bin.install root/"bin/conu-mcp"
    pkgshare.install root/"docs" if (root/"docs").exist?
    pkgshare.install root/"packaging" if (root/"packaging").exist?
  end

  service do
    run [opt_bin/"conud", "--serve"]
    keep_alive true
    log_path var/"log/conu/conud.log"
    error_log_path var/"log/conu/conud.err.log"
  end

  test do
    system "#{{bin}}/conu", "--version"
    system "#{{bin}}/conud", "--check"
    system "#{{bin}}/conu-relay", "--check"
    assert_equal "", pipe_output("#{{bin}}/conu-mcp", "", 0)
  end
end
"""


def render_scoop_manifest(
    version: str,
    repo: str,
    windows_asset: ReleaseAsset,
    extract_dir: str | None,
) -> str:
    manifest: dict[str, Any] = {
        "version": version,
        "description": "conU native Rust CLI, daemon, relay, and MCP adapter.",
        "homepage": f"https://github.com/{repo}",
        "license": "UNLICENSED",
        "architecture": {
            "64bit": {
                "url": windows_asset.url,
                "hash": windows_asset.sha256,
            }
        },
        "bin": [
            ["bin\\conu.exe", "conu"],
            ["bin\\conud.exe", "conud"],
            ["bin\\conu-relay.exe", "conu-relay"],
            ["bin\\conu-mcp.exe", "conu-mcp"],
        ],
        "checkver": {
            "github": f"https://github.com/{repo}",
        },
    }
    if extract_dir is not None:
        manifest["extract_dir"] = extract_dir
    return json.dumps(manifest, indent=2, sort_keys=False) + "\n"


def windows_binary_path(binary: str, extract_dir: str | None, separator: str) -> str:
    pieces = ["bin", f"{binary}.exe"]
    if extract_dir is not None:
        pieces.insert(0, extract_dir)
    return separator.join(pieces)


def render_winget_manifest(
    version: str,
    repo: str,
    windows_asset: ReleaseAsset,
    extract_dir: str | None,
    package_identifier: str = "imthegoodboy.conU",
) -> str:
    nested_files = []
    for binary in EXPECTED_BINARIES:
        nested_files.append(
            f"""- RelativeFilePath: {windows_binary_path(binary, extract_dir, "/")}
  PortableCommandAlias: {binary}"""
        )
    nested_block = "\n".join(nested_files)
    return f"""# Generated by scripts/generate-package-manager-manifests.py.
# yaml-language-server: $schema=https://aka.ms/winget-manifest.singleton.1.12.0.schema.json
PackageIdentifier: {package_identifier}
PackageVersion: {version}
PackageLocale: en-US
Publisher: imthegoodboy
PublisherUrl: https://github.com/imthegoodboy
PackageName: conU
PackageUrl: https://github.com/{repo}
License: UNLICENSED
ShortDescription: Agent-native encrypted communication layer.
Description: conU native Rust CLI, daemon, relay, and MCP adapter.
Moniker: conu
Tags:
- agents
- cli
- networking
Commands:
- conu
- conud
- conu-relay
- conu-mcp
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
{nested_block}
Installers:
- Architecture: x64
  InstallerUrl: {windows_asset.url}
  InstallerSha256: {windows_asset.sha256}
ManifestType: singleton
ManifestVersion: 1.12.0
"""


def render_chocolatey_nuspec(
    version: str,
    repo: str,
    package_id: str = "conu",
) -> str:
    repo_url = f"https://github.com/{repo}"
    return f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>{xml_escape(package_id)}</id>
    <version>{xml_escape(version)}</version>
    <title>conU</title>
    <authors>imthegoodboy</authors>
    <owners>imthegoodboy</owners>
    <projectUrl>{xml_escape(repo_url)}</projectUrl>
    <licenseUrl>{xml_escape(repo_url)}</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <summary>Agent-native encrypted communication layer.</summary>
    <description>conU native Rust CLI, daemon, relay, and MCP adapter.</description>
    <tags>conu agents cli networking relay</tags>
  </metadata>
  <files>
    <file src="tools\\**" target="tools" />
  </files>
</package>
"""


def render_chocolatey_install(
    version: str,
    windows_asset: ReleaseAsset,
    extract_dir: str | None,
    package_id: str = "conu",
) -> str:
    rootless_bin = "bin"
    rooted_bin = (
        f"{extract_dir}\\bin"
        if extract_dir is not None
        else f"conu-{version}-windows-x64\\bin"
    )
    return f"""# Generated by scripts/generate-package-manager-manifests.py.
$ErrorActionPreference = 'Stop'

$packageName = '{powershell_single_quote(package_id)}'
$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

$packageArgs = @{{
  PackageName = $packageName
  Url64bit = '{powershell_single_quote(windows_asset.url)}'
  Checksum64 = '{windows_asset.sha256}'
  ChecksumType64 = 'sha256'
  UnzipLocation = $toolsDir
}}

Install-ChocolateyZipPackage @packageArgs

$rootlessBin = Join-Path $toolsDir '{powershell_single_quote(rootless_bin)}'
$rootedBin = Join-Path $toolsDir '{powershell_single_quote(rooted_bin)}'
if (Test-Path (Join-Path $rootlessBin 'conu.exe')) {{
  $binDir = $rootlessBin
}} elseif (Test-Path (Join-Path $rootedBin 'conu.exe')) {{
  $binDir = $rootedBin
}} else {{
  throw 'conU release archive is missing bin\\conu.exe'
}}

foreach ($binary in @('conu', 'conud', 'conu-relay', 'conu-mcp')) {{
  $binaryPath = Join-Path $binDir "$binary.exe"
  if (-not (Test-Path $binaryPath -PathType Leaf)) {{
    throw "conU release archive is missing $binary.exe"
  }}
  Install-BinFile -Name $binary -Path $binaryPath
}}
"""


def render_chocolatey_uninstall(
    windows_asset: ReleaseAsset,
    package_id: str = "conu",
) -> str:
    return f"""# Generated by scripts/generate-package-manager-manifests.py.
$ErrorActionPreference = 'Stop'

$packageName = '{powershell_single_quote(package_id)}'

foreach ($binary in @('conu', 'conud', 'conu-relay', 'conu-mcp')) {{
  Uninstall-BinFile -Name $binary
}}

Uninstall-ChocolateyZipPackage $packageName '{powershell_single_quote(windows_asset.filename)}'
"""


def write_chocolatey_package(
    path: Path,
    nuspec: str,
    install_script: str,
    uninstall_script: str,
) -> None:
    with open_output_file(path, "Chocolatey package") as package_file:
        with zipfile.ZipFile(package_file, "w", compression=zipfile.ZIP_STORED) as package:
            write_deterministic_zip_text(package, "conu.nuspec", nuspec)
            write_deterministic_zip_text(package, "tools/chocolateyInstall.ps1", install_script)
            write_deterministic_zip_text(
                package,
                "tools/chocolateyUninstall.ps1",
                uninstall_script,
            )
        validate_open_regular_file(
            package_file,
            "Chocolatey package",
            max_bytes=MAX_GENERATED_OUTPUT_BYTES,
        )
    validate_regular_file(path, "Chocolatey package", max_bytes=MAX_GENERATED_OUTPUT_BYTES)


def build_debian_package(
    version: str,
    repo: str,
    target: str,
    binaries: dict[str, bytes],
) -> DebianPackage:
    architecture = DEBIAN_ARCHES[target]
    package_version = debian_version(version)
    filename = debian_filename(version, target)
    doc_readme = render_debian_readme(version, repo)
    service_example = render_debian_service_example()
    data_files = {
        **{f"usr/bin/{binary}": binaries[binary] for binary in EXPECTED_BINARIES},
        "usr/share/doc/conu/README.Debian": doc_readme.encode("ascii"),
        "usr/share/doc/conu/conud.service.example": service_example.encode("ascii"),
    }
    md5sums = render_debian_md5sums(data_files)
    control = render_debian_control(package_version, architecture, repo)
    control_archive = build_tar_gz(
        [
            ("./control", control.encode("ascii"), 0o644),
            ("./md5sums", md5sums.encode("ascii"), 0o644),
        ],
        dirs=[],
    )
    data_archive = build_tar_gz(
        [(f"./{path}", data, 0o755 if path.startswith("usr/bin/") else 0o644) for path, data in data_files.items()],
        dirs=[
            "./usr",
            "./usr/bin",
            "./usr/share",
            "./usr/share/doc",
            "./usr/share/doc/conu",
        ],
    )
    content = build_ar_archive(
        [
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", control_archive),
            ("data.tar.gz", data_archive),
        ]
    )
    return DebianPackage(
        filename=filename,
        architecture=architecture,
        package_version=package_version,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        metadata_text="\n".join([control, md5sums, doc_readme, service_example]),
    )


def build_apt_repository_metadata(
    version: str,
    repo: str,
    packages: list[DebianPackage],
) -> AptRepositoryMetadata:
    packages_text = "".join(render_apt_package_entry(package, repo) for package in packages)
    packages_bytes = packages_text.encode("ascii")
    packages_gz = deterministic_gzip(packages_bytes)
    release_text = render_apt_release(
        version,
        {
            "Packages": packages_bytes,
            "Packages.gz": packages_gz,
        },
    )
    readme_text = render_apt_repository_readme(version, packages)

    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
        write_deterministic_zip_text(archive, "README.txt", readme_text)
        write_deterministic_zip_bytes(archive, "Packages", packages_bytes)
        write_deterministic_zip_bytes(archive, "Packages.gz", packages_gz)
        write_deterministic_zip_text(archive, "Release", release_text)
    content = raw.getvalue()
    return AptRepositoryMetadata(
        filename=apt_repository_metadata_filename(version),
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        metadata_text="\n".join([readme_text, packages_text, release_text]),
    )


def render_apt_package_entry(package: DebianPackage, repo: str) -> str:
    return f"""Package: conu
Version: {package.package_version}
Architecture: {package.architecture}
Maintainer: imthegoodboy <noreply@github.com>
Filename: {package.filename}
Size: {len(package.content)}
MD5sum: {md5_hex(package.content)}
SHA1: {sha1_hex(package.content)}
SHA256: {package.sha256}
Section: net
Priority: optional
Homepage: https://github.com/{repo}
Description: Agent-native encrypted communication layer
 conU native Rust CLI, daemon, relay, and MCP adapter.

"""


def render_apt_release(version: str, files: dict[str, bytes]) -> str:
    lines = [
        "Origin: conU",
        "Label: conU",
        "Suite: stable",
        "Codename: stable",
        f"Version: {debian_version(version)}",
        "Architectures: amd64 arm64",
        "Description: conU generated APT repository metadata",
        "Date: Wed, 01 Jan 2020 00:00:00 UTC",
    ]
    for title, digest_fn in (
        ("MD5Sum", md5_hex),
        ("SHA1", sha1_hex),
        ("SHA256", lambda data: hashlib.sha256(data).hexdigest()),
    ):
        lines.append(f"{title}:")
        for name, content in files.items():
            lines.append(f" {digest_fn(content)} {len(content)} {name}")
    return "\n".join(lines) + "\n"


def render_apt_repository_readme(version: str, packages: list[DebianPackage]) -> str:
    package_list = "\n".join(f"- {package.filename}" for package in packages)
    return f"""conU {debian_version(version)} APT repository metadata

This archive is generated before release signing and contains deterministic
Packages, Packages.gz, and Release files for the generated conU Debian package
assets:

{package_list}

Tagged release publication adds native APT signatures to this ZIP: InRelease
and Release.gpg over the Release file, then refreshes this ZIP's .sha256
sidecar. Before serving this as an APT repository, verify those signatures with
the conU maintainer GPG public key. Repository hosting and operator-owned
publishing credentials are still required.
"""


def render_debian_control(version: str, architecture: str, repo: str) -> str:
    return f"""Package: conu
Version: {version}
Section: net
Priority: optional
Architecture: {architecture}
Maintainer: imthegoodboy <noreply@github.com>
Homepage: https://github.com/{repo}
Description: Agent-native encrypted communication layer
 conU native Rust CLI, daemon, relay, and MCP adapter.
"""


def render_debian_readme(version: str, repo: str) -> str:
    return f"""conU {version}

conU is an agent-native encrypted communication layer.
Project: https://github.com/{repo}

This generated Debian package installs the conu, conud, conu-relay, and
conu-mcp binaries under /usr/bin. Initialize local state with `conu init`,
then run `conu doctor` before starting the daemon.
"""


def render_debian_service_example() -> str:
    return """[Unit]
Description=conU local runtime daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/conud --serve
Restart=on-failure
RestartSec=5
Environment=CONU_HOME=/var/lib/conu
User=conu
Group=conu
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/conu

[Install]
WantedBy=multi-user.target
"""


def render_debian_md5sums(files: dict[str, bytes]) -> str:
    lines = []
    for path in sorted(files):
        digest = md5_hex(files[path])
        lines.append(f"{digest}  {path}")
    return "\n".join(lines) + "\n"


def md5_hex(data: bytes) -> str:
    try:
        digest = hashlib.md5(data, usedforsecurity=False)
    except TypeError:
        digest = hashlib.md5(data)
    return digest.hexdigest()


def sha1_hex(data: bytes) -> str:
    try:
        digest = hashlib.sha1(data, usedforsecurity=False)
    except TypeError:
        digest = hashlib.sha1(data)
    return digest.hexdigest()


def deterministic_gzip(data: bytes) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=SOURCE_EPOCH) as gzip_file:
        gzip_file.write(data)
    return raw.getvalue()


def build_tar_gz(
    files: list[tuple[str, bytes, int]],
    *,
    dirs: list[str],
) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=SOURCE_EPOCH) as gzip_file:
        with tarfile.open(fileobj=gzip_file, mode="w") as package:
            for name in dirs:
                info = deterministic_tar_info(name.rstrip("/") + "/", 0o755)
                info.type = tarfile.DIRTYPE
                info.size = 0
                package.addfile(info)
            for name, data, mode in files:
                info = deterministic_tar_info(name, mode)
                info.size = len(data)
                package.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def deterministic_tar_info(name: str, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mode = mode
    info.mtime = SOURCE_EPOCH
    return info


def build_ar_archive(members: list[tuple[str, bytes]]) -> bytes:
    output = bytearray(b"!<arch>\n")
    for name, data in members:
        if len(name) > 16:
            raise SystemExit(f"debian ar member name is too long: {name}")
        header = (
            f"{name:<16}"
            f"{0:<12}"
            f"{0:<6}"
            f"{0:<6}"
            f"{'100644':<8}"
            f"{len(data):<10}"
            "`\n"
        )
        output.extend(header.encode("ascii"))
        output.extend(data)
        if len(data) % 2:
            output.extend(b"\n")
    return bytes(output)


def write_sha256_sidecar(path: Path, digest: str) -> None:
    validate_regular_file(path, "package-manager output", max_bytes=MAX_GENERATED_OUTPUT_BYTES)
    sidecar = path.with_name(f"{path.name}.sha256")
    with open_output_file(sidecar, "package-manager output SHA-256 sidecar") as handle:
        handle.write(f"{digest}  {path.name}\n".encode("ascii"))
        handle.flush()
        validate_open_regular_file(
            handle,
            "package-manager output SHA-256 sidecar",
            max_bytes=MAX_CHECKSUM_BYTES,
        )
    validate_regular_file(
        sidecar,
        "package-manager output SHA-256 sidecar",
        max_bytes=MAX_CHECKSUM_BYTES,
    )


def existing_rpm_package_paths(version: str, output_dir: Path) -> tuple[Path, ...]:
    paths = tuple(output_dir / rpm_filename(version, target) for target in RPM_ARCHES)
    for path in paths:
        verify_sha256_sidecar(path, "generated RPM package")
    return paths


def verify_sha256_sidecar(path: Path, label: str) -> str:
    validate_regular_file(path, label, max_bytes=MAX_GENERATED_OUTPUT_BYTES)
    sidecar = path.with_name(f"{path.name}.sha256")
    validate_regular_file(
        sidecar,
        f"SHA-256 sidecar for {label}",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    try:
        checksum_text = read_ascii_file(
            sidecar,
            f"SHA-256 sidecar for {label}",
            max_bytes=MAX_CHECKSUM_BYTES,
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}: {path.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}: {path.name}")
    named_path = match.group(2)
    if named_path != path.name:
        raise SystemExit(
            f"SHA-256 sidecar for {label} {path.name} names wrong file: {named_path}"
        )
    expected = match.group(1).lower()
    actual = sha256_file(path, label, max_bytes=MAX_GENERATED_OUTPUT_BYTES)
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")
    return expected


def build_rpm_packages(
    version: str,
    dist: Path,
    spec_path: Path,
    output_dir: Path,
) -> tuple[Path, ...]:
    rpmbuild = shutil.which("rpmbuild")
    if rpmbuild is None:
        raise SystemExit("rpmbuild is required when --build-rpm-packages is set")

    outputs = []
    for target, rpm_arch in RPM_ARCHES.items():
        with tempfile.TemporaryDirectory(
            prefix=f"conu-rpmbuild-{rpm_arch}-",
        ) as topdir_text:
            topdir = Path(topdir_text)
            for name in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
                (topdir / name).mkdir()
            command = rpm_build_command(rpmbuild, spec_path, dist, topdir, rpm_arch)
            env = os.environ.copy()
            env.setdefault("SOURCE_DATE_EPOCH", str(SOURCE_EPOCH))
            try:
                subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                )
            except subprocess.CalledProcessError as exc:
                raise SystemExit(
                    f"rpmbuild failed for {target} with output:\n{exc.stdout}"
                ) from exc

            packages = sorted((topdir / "RPMS").rglob("conu-*.rpm"))
            if len(packages) != 1:
                raise SystemExit(
                    f"rpmbuild for {target} produced packages {[str(path) for path in packages]!r}"
                )
            expected_name = rpm_filename(version, target)
            if packages[0].name != expected_name:
                raise SystemExit(
                    f"rpmbuild for {target} produced unexpected package name "
                    f"{packages[0].name!r}; expected {expected_name!r}"
                )
            output_path = output_dir / expected_name
            copy_regular_file_output(
                packages[0],
                output_path,
                "generated RPM package",
                max_bytes=MAX_GENERATED_OUTPUT_BYTES,
            )
            write_sha256_sidecar(output_path, sha256_file(output_path))
            outputs.append(output_path)
    return tuple(outputs)


def build_rpm_repository_metadata(
    version: str,
    package_paths: tuple[Path, ...],
) -> RpmRepositoryMetadata:
    createrepo = shutil.which("createrepo_c") or shutil.which("createrepo")
    if createrepo is None:
        raise SystemExit(
            "createrepo_c is required when --build-rpm-repository-metadata is set"
        )
    if len(package_paths) != len(RPM_ARCHES):
        raise SystemExit("RPM repository metadata requires one package per supported RPM arch")

    for package_path in package_paths:
        verify_sha256_sidecar(package_path, "generated RPM package")

    with tempfile.TemporaryDirectory(prefix="conu-rpm-repository-") as repo_text:
        repo_dir = Path(repo_text)
        for package_path in package_paths:
            repo_package = repo_dir / package_path.name
            copy_regular_file_output(
                package_path,
                repo_package,
                "generated RPM package",
                max_bytes=MAX_GENERATED_OUTPUT_BYTES,
            )
            os.utime(repo_package, (SOURCE_EPOCH, SOURCE_EPOCH))

        command = [
            createrepo,
            "--checksum",
            "sha256",
            "--repomd-checksum",
            "sha256",
            "--no-database",
            "--simple-md-filenames",
            "--revision",
            str(SOURCE_EPOCH),
            "--set-timestamp-to-revision",
            "--general-compress-type",
            "gz",
            str(repo_dir),
        ]
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"createrepo_c failed with output:\n{exc.stdout}") from exc

        repodata_dir = repo_dir / "repodata"
        if not repodata_dir.is_dir():
            raise SystemExit("createrepo_c did not create repodata")
        repodata_files = sorted(path for path in repodata_dir.rglob("*") if path.is_file())
        if not repodata_files:
            raise SystemExit("createrepo_c did not create repository metadata files")

        readme_text = render_rpm_repository_readme(version, package_paths)
        raw = io.BytesIO()
        metadata_texts = [readme_text]
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
            write_deterministic_zip_text(archive, "README.txt", readme_text)
            for path in repodata_files:
                relative = path.relative_to(repo_dir).as_posix()
                data = read_regular_file(
                    path,
                    "RPM repository metadata file",
                    max_bytes=MAX_GENERATED_OUTPUT_BYTES,
                )
                metadata_texts.append(decode_rpm_repository_metadata(relative, data))
                write_deterministic_zip_bytes(archive, relative, data)
        content = raw.getvalue()
        return RpmRepositoryMetadata(
            filename=rpm_repository_metadata_filename(version),
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            metadata_text="\n".join(metadata_texts),
        )


def decode_rpm_repository_metadata(name: str, data: bytes) -> str:
    text_bytes = data
    if name.endswith(".gz"):
        text_bytes = gzip.decompress(data)
    if name.endswith(".xml") or name.endswith(".xml.gz"):
        return text_bytes.decode("utf-8")
    return ""


def render_rpm_repository_readme(version: str, package_paths: tuple[Path, ...]) -> str:
    package_list = "\n".join(f"- {path.name}" for path in package_paths)
    return f"""conU {rpm_version(version)} RPM repository metadata

This archive is generated before release signing and contains repodata
generated by createrepo_c for the generated conU RPM package assets:

{package_list}

Tagged release publication signs the generated .rpm package payloads first,
generates this metadata from the signed packages, adds repodata/repomd.xml.asc
over repodata/repomd.xml, then refreshes this ZIP's .sha256 sidecar. Before
serving this as a YUM/DNF repository, verify that signature with the conU
maintainer GPG public key and place the signed .rpm files beside the unpacked
metadata. Repository hosting and operator-owned publishing credentials are
still required.
"""


def rpm_build_command(
    rpmbuild: str,
    spec_path: Path,
    dist: Path,
    topdir: Path,
    rpm_arch: str,
) -> list[str]:
    return [
        rpmbuild,
        "--define",
        f"_topdir {topdir}",
        "--define",
        f"_sourcedir {dist}",
        "--define",
        f"_builddir {topdir / 'BUILD'}",
        "--define",
        f"_buildrootdir {topdir / 'BUILDROOT'}",
        "--define",
        f"_rpmdir {topdir / 'RPMS'}",
        "--define",
        f"_srcrpmdir {topdir / 'SRPMS'}",
        "--define",
        "dist %{nil}",
        "--define",
        "__os_install_post %{nil}",
        "--target",
        rpm_arch,
        "-bb",
        str(spec_path),
    ]


def render_rpm_spec(version: str, repo: str, assets: dict[str, ReleaseAsset]) -> str:
    return f"""# Generated by scripts/generate-package-manager-manifests.py.
Name: conu
Version: {rpm_version(version)}
Release: 1%{{?dist}}
Summary: Agent-native encrypted communication layer
License: LicenseRef-UNLICENSED
URL: https://github.com/{repo}

%global conu_semver {version}

%ifarch x86_64
%global conu_target linux-x64
%global conu_source_sha256 {assets["linux-x64"].sha256}
Source0: {assets["linux-x64"].url}
%endif

%ifarch aarch64
%global conu_target linux-arm64
%global conu_source_sha256 {assets["linux-arm64"].sha256}
Source0: {assets["linux-arm64"].url}
%endif

%ifnarch x86_64 aarch64
%{{error:conU release assets currently support x86_64 and aarch64 Linux RPM builds}}
%endif

%description
conU is a native Rust CLI, daemon, relay, and MCP adapter for agent-native
encrypted communication.

%prep
echo "%{{conu_source_sha256}}  %{{SOURCE0}}" | sha256sum -c -
%setup -q -c -n conu-build
if [ -d "conu-%{{conu_semver}}-%{{conu_target}}/bin" ]; then
  cp -a "conu-%{{conu_semver}}-%{{conu_target}}/." .
fi
test -x bin/conu
test -x bin/conud
test -x bin/conu-relay
test -x bin/conu-mcp

%build
# Binaries are built by the conU release workflow.

%install
install -Dm0755 bin/conu "%{{buildroot}}%{{_bindir}}/conu"
install -Dm0755 bin/conud "%{{buildroot}}%{{_bindir}}/conud"
install -Dm0755 bin/conu-relay "%{{buildroot}}%{{_bindir}}/conu-relay"
install -Dm0755 bin/conu-mcp "%{{buildroot}}%{{_bindir}}/conu-mcp"

%files
%{{_bindir}}/conu
%{{_bindir}}/conud
%{{_bindir}}/conu-relay
%{{_bindir}}/conu-mcp
%doc README.md docs packaging

%changelog
* Thu Jan 01 2020 imthegoodboy <noreply@github.com> - {rpm_version(version)}-1
- Generated from verified conU release assets.
"""


def write_deterministic_zip_text(package: zipfile.ZipFile, name: str, text: str) -> None:
    write_deterministic_zip_bytes(package, name, text.encode("ascii"))


def write_deterministic_zip_bytes(package: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    package.writestr(info, data)


def xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def powershell_single_quote(value: str) -> str:
    return value.replace("'", "''")


def assert_output_safe(text: str, dist: Path) -> None:
    forbidden_literals = [
        "NPM_TOKEN",
        "CONU_RELAY_TOKEN",
        "CONU_WINDOWS_SIGN_CERT",
        "CONU_MACOS_DEVELOPER_ID",
        "PRIVATE KEY BLOCK",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "payload_ciphertext",
        "payload_hex",
        "payloadHex",
        "token_sha256_hex",
    ]
    for literal in forbidden_literals:
        if literal in text:
            raise SystemExit(f"generated package-manager manifests contain forbidden literal: {literal}")
    resolved_dist = str(dist.resolve()).replace("\\", "/")
    if resolved_dist and resolved_dist in text.replace("\\", "/"):
        raise SystemExit("generated package-manager manifests contain local dist path")


if __name__ == "__main__":
    sys.exit(main())
