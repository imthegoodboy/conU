#!/usr/bin/env python3
"""Smoke test conU release archives on the current platform."""

from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


REQUIRED_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
MAX_ARCHIVE_BYTES = 1_000_000_000
MAX_MEMBER_BYTES = 512_000_000
MAX_MEMBER_COUNT = 10_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_BINARY = getattr(os, "O_BINARY", 0)


class ExtractState:
    def __init__(self) -> None:
        self.paths: set[str] = set()
        self.entry_count = 0
        self.total_uncompressed = 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    args = parser.parse_args()

    dist = validate_input_directory(args.dist, "release dist directory")
    archives = sorted(dist.glob("*.zip")) + sorted(dist.glob("*.tar.gz"))
    if not archives:
        raise SystemExit(f"no release archives found in {dist}")

    smoked = 0
    skipped = 0
    with tempfile.TemporaryDirectory(prefix="conu-release-smoke-") as temp_dir:
        temp_root = Path(temp_dir)
        for archive in archives:
            target = read_manifest_target(archive)
            if not target_is_current_platform(target):
                skipped += 1
                print(f"skipping {archive.name}: target {target!r} is not this runner")
                continue

            smoke_dir = temp_root / archive_stem(archive)
            extract_archive(archive, smoke_dir)
            smoke_extracted_package(archive, smoke_dir, temp_root)
            smoked += 1

    if smoked == 0:
        raise SystemExit("no current-platform release archives were smoke tested")

    print(f"smoked {smoked} conU release archive(s); skipped {skipped}")
    return 0


def read_manifest_target(archive: Path) -> str:
    manifest_bytes = read_archive_member(archive, "manifest.toml")
    if manifest_bytes is None:
        raise SystemExit(f"{archive.name} missing manifest.toml")

    for raw_line in manifest_bytes.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("target") and "=" in line:
            value = line.split("=", 1)[1].strip()
            if value.startswith('"') and value.endswith('"'):
                return value[1:-1]
            return value

    raise SystemExit(f"{archive.name} manifest.toml missing target")


def read_archive_member(archive: Path, normalized_name: str) -> bytes | None:
    expected_root = expected_archive_root(archive)
    state = ExtractState()
    if archive.suffix == ".zip":
        archive_file, _size = open_regular_file(
            archive,
            "release archive",
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        with archive_file:
            with zipfile.ZipFile(archive_file) as package:
                found: bytes | None = None
                root_style: str | None = None
                for member in package.infolist():
                    normalized, root_style, is_file = validate_zip_member_for_read(
                        archive.name,
                        member,
                        expected_root,
                        state,
                        root_style,
                    )
                    if not is_file:
                        continue
                    if normalized == normalized_name:
                        if found is not None:
                            raise SystemExit(
                                f"{archive.name} contains duplicate archive path: {normalized_name}"
                            )
                        found = package.read(member)
                return found

    if archive.name.endswith(".tar.gz"):
        archive_file, _size = open_regular_file(
            archive,
            "release archive",
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        with archive_file:
            with tarfile.open(fileobj=archive_file, mode="r|gz") as package:
                found: bytes | None = None
                root_style: str | None = None
                for member in package:
                    normalized, root_style, is_file = validate_tar_member_for_read(
                        archive.name,
                        member,
                        expected_root,
                        state,
                        root_style,
                    )
                    if not is_file:
                        continue
                    if normalized == normalized_name:
                        if found is not None:
                            raise SystemExit(
                                f"{archive.name} contains duplicate archive path: {normalized_name}"
                            )
                        file_object = package.extractfile(member)
                        found = file_object.read() if file_object is not None else None
                return found

    raise SystemExit(f"unsupported release archive {archive.name}")


def validate_zip_member_for_read(
    archive_name: str,
    member: zipfile.ZipInfo,
    expected_root: str,
    state: ExtractState,
    root_style: str | None,
) -> tuple[str, str | None, bool]:
    if member.flag_bits & 0x1:
        raise SystemExit(f"{archive_name} contains encrypted zip member: {member.filename}")
    file_type = (member.external_attr >> 16) & 0o170000
    is_directory = member.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise SystemExit(f"{archive_name} contains unsupported link member: {member.filename}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise SystemExit(f"{archive_name} contains unsupported zip member: {member.filename}")
    if is_directory and member.file_size != 0:
        raise SystemExit(
            f"{archive_name} contains directory member with data: {member.filename}"
        )
    normalized, root_style = validate_archive_read_entry(
        archive_name,
        member.filename,
        0 if is_directory else member.file_size,
        state,
        expected_root,
        root_style,
        allow_empty=is_directory,
    )
    return normalized, root_style, not is_directory


def validate_tar_member_for_read(
    archive_name: str,
    member: tarfile.TarInfo,
    expected_root: str,
    state: ExtractState,
    root_style: str | None,
) -> tuple[str, str | None, bool]:
    if member.isdir():
        if member.size != 0:
            raise SystemExit(f"{archive_name} contains directory member with data: {member.name}")
        normalized, root_style = validate_archive_read_entry(
            archive_name,
            member.name,
            0,
            state,
            expected_root,
            root_style,
            allow_empty=True,
        )
        return normalized, root_style, False
    if not member.isfile():
        raise SystemExit(f"{archive_name} contains unsupported non-file member: {member.name}")
    normalized, root_style = validate_archive_read_entry(
        archive_name,
        member.name,
        member.size,
        state,
        expected_root,
        root_style,
    )
    return normalized, root_style, True


def validate_archive_read_entry(
    archive_name: str,
    member_name: str,
    size: int,
    state: ExtractState,
    expected_root: str,
    root_style: str | None,
    *,
    allow_empty: bool = False,
) -> tuple[str, str | None]:
    if size < 0:
        raise SystemExit(f"{archive_name} contains member with invalid size: {member_name}")
    if size > MAX_MEMBER_BYTES:
        raise SystemExit(f"{archive_name} member is too large: {member_name}")

    state.entry_count += 1
    if state.entry_count > MAX_MEMBER_COUNT:
        raise SystemExit(f"{archive_name} contains more than {MAX_MEMBER_COUNT} entries")

    normalized, member_style = normalize_member(member_name, expected_root)
    root_style = update_archive_root_style(archive_name, member_name, root_style, member_style)
    if not normalized:
        if allow_empty:
            return normalized, root_style
        raise SystemExit(f"{archive_name} contains empty archive path: {member_name}")

    state.total_uncompressed += size
    if state.total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise SystemExit(
            f"{archive_name} uncompressed contents exceed {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
        )
    if normalized in state.paths:
        raise SystemExit(f"{archive_name} contains duplicate archive path: {normalized}")
    state.paths.add(normalized)
    return normalized, root_style


def expected_archive_root(archive: Path) -> str:
    return archive_stem(archive)


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


def target_is_current_platform(target: str) -> bool:
    target = target.lower()
    if target == "host":
        return True

    system = platform.system().lower()
    machine = platform.machine().lower()
    current_os = {
        "windows": ("windows",),
        "linux": ("linux",),
        "darwin": ("macos", "darwin", "apple"),
    }.get(system)
    current_arch = {
        "amd64": ("x64", "x86_64", "amd64"),
        "x86_64": ("x64", "x86_64", "amd64"),
        "arm64": ("arm64", "aarch64"),
        "aarch64": ("arm64", "aarch64"),
    }.get(machine)

    if current_os is None or current_arch is None:
        return False

    return any(value in target for value in current_os) and any(
        value in target for value in current_arch
    )


def archive_stem(archive: Path) -> str:
    if archive.name.endswith(".tar.gz"):
        return archive.name[:-7]
    return archive.stem


def extract_archive(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    state = ExtractState()
    if archive.suffix == ".zip":
        archive_file, _size = open_regular_file(
            archive,
            "release archive",
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        with archive_file:
            with zipfile.ZipFile(archive_file) as package:
                for member in package.infolist():
                    if member.filename.endswith("/"):
                        if member.file_size != 0:
                            raise SystemExit(
                                f"{archive.name} contains directory member with data: "
                                f"{member.filename}"
                            )
                        validate_extract_entry(
                            archive.name,
                            member.filename,
                            0,
                            state,
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
                    output_path = checked_extract_path(
                        archive.name,
                        destination,
                        member.filename,
                        member.file_size,
                        state,
                    )
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_bytes(package.read(member))
                    unix_mode = (member.external_attr >> 16) & 0o777
                    if unix_mode:
                        output_path.chmod(unix_mode)
        return

    if archive.name.endswith(".tar.gz"):
        archive_file, _size = open_regular_file(
            archive,
            "release archive",
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        with archive_file:
            with tarfile.open(fileobj=archive_file, mode="r|gz") as package:
                for member in package:
                    if member.isdir():
                        if member.size != 0:
                            raise SystemExit(
                                f"{archive.name} contains directory member with data: {member.name}"
                            )
                        validate_extract_entry(
                            archive.name,
                            member.name,
                            0,
                            state,
                            allow_empty=True,
                        )
                        continue
                    if not member.isfile():
                        raise SystemExit(
                            f"{archive.name} contains unsupported non-file member: {member.name}"
                        )
                    output_path = checked_extract_path(
                        archive.name,
                        destination,
                        member.name,
                        member.size,
                        state,
                    )
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    file_object = package.extractfile(member)
                    if file_object is None:
                        raise SystemExit(f"{archive.name} could not read member {member.name}")
                    output_path.write_bytes(file_object.read())
                    output_path.chmod(member.mode & 0o777)
        return

    raise SystemExit(f"unsupported release archive {archive.name}")


def validate_input_directory(path: Path, label: str) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")
    return path.resolve()


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


def checked_extract_path(
    archive_name: str,
    destination: Path,
    member_name: str,
    size: int,
    state: ExtractState,
) -> Path:
    normalized = validate_extract_entry(archive_name, member_name, size, state)
    output_path = (destination / Path(*PurePosixPath(normalized).parts)).resolve()
    destination_resolved = destination.resolve()
    try:
        output_path.relative_to(destination_resolved)
    except ValueError as exc:
        raise SystemExit(f"unsafe archive path: {member_name}") from exc
    return output_path


def validate_extract_entry(
    archive_name: str,
    member_name: str,
    size: int,
    state: ExtractState,
    *,
    allow_empty: bool = False,
) -> str:
    if size < 0:
        raise SystemExit(f"{archive_name} contains member with invalid size: {member_name}")
    if size > MAX_MEMBER_BYTES:
        raise SystemExit(f"{archive_name} member is too large: {member_name}")

    state.entry_count += 1
    if state.entry_count > MAX_MEMBER_COUNT:
        raise SystemExit(f"{archive_name} contains more than {MAX_MEMBER_COUNT} entries")

    normalized = normalize_extract_path(member_name)
    if not normalized:
        if allow_empty:
            return normalized
        raise SystemExit(f"{archive_name} contains empty archive path: {member_name}")

    state.total_uncompressed += size
    if state.total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise SystemExit(
            f"{archive_name} uncompressed contents exceed {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
        )
    if normalized in state.paths:
        raise SystemExit(f"{archive_name} contains duplicate archive path: {normalized}")
    state.paths.add(normalized)
    return normalized


def normalize_extract_path(member_name: str) -> str:
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe archive path: {member_name}")
    return "/".join(parts)


def smoke_extracted_package(archive: Path, smoke_dir: Path, temp_root: Path) -> None:
    package_root = find_package_root(archive, smoke_dir)
    bin_dir = package_root / "bin"
    binaries = verify_archive_binaries(archive, bin_dir)

    if binary_suffix() == "":
        for path in binaries.values():
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    home = temp_root / f"{archive_stem(archive)}-home"
    env = os.environ.copy()
    env["CONU_HOME"] = str(home)
    env["CONUD_EXE"] = str(binaries["conud"])
    env["CONU_RELAY_EXE"] = str(binaries["conu-relay"])
    env["CONU_MCP_EXE"] = str(binaries["conu-mcp"])

    run_command(archive, [str(binaries["conu"]), "init"], env)

    audit = run_json_command(
        archive,
        [str(binaries["conu"]), "security", "audit", "--json"],
        env,
    )
    if audit.get("contentsDisplayed") is not False:
        raise SystemExit(f"{archive.name} security audit displayed contents")

    doctor = run_json_command(archive, [str(binaries["conu"]), "doctor", "--json"], env)
    if doctor.get("status") != "ready_for_local_use":
        status = doctor.get("status")
        raise SystemExit(
            f"{archive.name} doctor status was {status!r}, expected ready_for_local_use"
        )
    if doctor.get("releaseGates", {}).get("localInstallReady") is not True:
        raise SystemExit(f"{archive.name} doctor did not report localInstallReady=true")
    if doctor.get("privacy", {}).get("contentsDisplayed") is not False:
        raise SystemExit(f"{archive.name} doctor displayed contents")

    required_binaries = {
        "conu": doctor.get("binaries", {}).get("conu"),
        "conud": doctor.get("binaries", {}).get("conud"),
        "conu-relay": doctor.get("binaries", {}).get("conuRelay"),
        "conu-mcp": doctor.get("binaries", {}).get("conuMcp"),
    }
    unresolved = [name for name, value in required_binaries.items() if not value]
    if unresolved:
        raise SystemExit(f"{archive.name} doctor did not resolve: {', '.join(unresolved)}")

    if home.exists():
        shutil.rmtree(home)
    print(f"smoked {archive.name}: packaged conu doctor is ready_for_local_use")


def find_package_root(archive: Path, smoke_dir: Path) -> Path:
    expected_root = expected_archive_root(archive)
    rootless_manifest = smoke_dir / "manifest.toml"
    rooted_dir = smoke_dir / expected_root
    rooted_manifest = rooted_dir / "manifest.toml"
    has_rootless = rootless_manifest.is_file()
    has_rooted = rooted_manifest.is_file()

    if has_rootless and has_rooted:
        raise SystemExit(f"{archive.name} mixes rooted and rootless archive paths")
    if has_rooted:
        return rooted_dir
    if has_rootless:
        return smoke_dir

    unexpected_roots = sorted(
        path.name
        for path in smoke_dir.iterdir()
        if path.is_dir() and path.name.startswith("conu-")
    )
    if unexpected_roots:
        raise SystemExit(
            f"{archive.name} contains unexpected archive root: "
            f"{unexpected_roots[0]} (expected {expected_root})"
        )
    raise SystemExit(
        f"{archive.name} missing manifest.toml at expected release root {expected_root}"
    )


def verify_archive_binaries(archive: Path, bin_dir: Path) -> dict[str, Path]:
    exe_suffix = binary_suffix()
    if not bin_dir.is_dir():
        raise SystemExit(f"{archive.name} missing binary directory: {bin_dir}")

    binaries = {
        name: bin_dir / f"{name}{exe_suffix}"
        for name in REQUIRED_BINARIES
    }
    missing = [name for name, path in binaries.items() if not path.exists()]
    if missing:
        raise SystemExit(f"{archive.name} missing executable(s): {', '.join(missing)}")

    not_regular = [
        name
        for name, path in binaries.items()
        if not is_regular_file(path)
    ]
    if not_regular:
        raise SystemExit(
            f"{archive.name} executable path is not a regular file: {', '.join(not_regular)}"
        )

    return binaries


def is_regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def binary_suffix() -> str:
    return ".exe" if platform.system().lower() == "windows" else ""


def run_json_command(archive: Path, command: list[str], env: dict[str, str]) -> dict[str, object]:
    output = run_command(archive, command, env)
    try:
        return json.loads(output.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{archive.name} command did not return JSON: {' '.join(command)}\n"
            f"{safe_snippet(output.stdout)}"
        ) from exc


def run_command(
    archive: Path,
    command: list[str],
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    output = subprocess.run(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if output.returncode != 0:
        raise SystemExit(
            f"{archive.name} command failed with exit code {output.returncode}: {' '.join(command)}\n"
            f"stdout:\n{safe_snippet(output.stdout)}\n"
            f"stderr:\n{safe_snippet(output.stderr)}"
        )
    return output


def safe_snippet(value: str) -> str:
    value = value.strip()
    if len(value) > 2000:
        return value[:2000] + "\n... truncated ..."
    return value


if __name__ == "__main__":
    sys.exit(main())
