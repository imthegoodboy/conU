#!/usr/bin/env python3
"""Smoke test conU release archives on the current platform."""

from __future__ import annotations

import argparse
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


REQUIRED_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    args = parser.parse_args()

    archives = sorted(args.dist.glob("*.zip")) + sorted(args.dist.glob("*.tar.gz"))
    if not archives:
        raise SystemExit(f"no release archives found in {args.dist}")

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
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                if member.filename.endswith("/"):
                    continue
                if normalize_member(member.filename) == normalized_name:
                    return package.read(member)
        return None

    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as package:
            for member in package.getmembers():
                if not member.isfile():
                    continue
                if normalize_member(member.name) == normalized_name:
                    file_object = package.extractfile(member)
                    return file_object.read() if file_object is not None else None
        return None

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
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                if member.filename.endswith("/"):
                    continue
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise SystemExit(
                        f"{archive.name} contains unsupported link member: {member.filename}"
                    )
                output_path = safe_extract_path(destination, member.filename)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(package.read(member))
                unix_mode = (member.external_attr >> 16) & 0o777
                if unix_mode:
                    output_path.chmod(unix_mode)
        return

    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as package:
            for member in package.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    raise SystemExit(
                        f"{archive.name} contains unsupported non-file member: {member.name}"
                    )
                output_path = safe_extract_path(destination, member.name)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                file_object = package.extractfile(member)
                if file_object is None:
                    raise SystemExit(f"{archive.name} could not read member {member.name}")
                output_path.write_bytes(file_object.read())
                output_path.chmod(member.mode & 0o777)
        return

    raise SystemExit(f"unsupported release archive {archive.name}")


def safe_extract_path(destination: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe archive path: {member_name}")

    output_path = (destination / Path(*parts)).resolve()
    destination_resolved = destination.resolve()
    try:
        output_path.relative_to(destination_resolved)
    except ValueError as exc:
        raise SystemExit(f"unsafe archive path: {member_name}") from exc
    return output_path


def smoke_extracted_package(archive: Path, smoke_dir: Path, temp_root: Path) -> None:
    package_root = find_package_root(smoke_dir)
    bin_dir = package_root / "bin"
    exe_suffix = ".exe" if platform.system().lower() == "windows" else ""
    binaries = {
        name: bin_dir / f"{name}{exe_suffix}"
        for name in REQUIRED_BINARIES
    }
    missing = [name for name, path in binaries.items() if not path.exists()]
    if missing:
        raise SystemExit(f"{archive.name} missing executable(s): {', '.join(missing)}")

    if exe_suffix == "":
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


def find_package_root(smoke_dir: Path) -> Path:
    candidates = [
        path
        for path in smoke_dir.iterdir()
        if path.is_dir() and path.name.startswith("conu-")
    ]
    if len(candidates) == 1:
        return candidates[0]
    return smoke_dir


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
