#!/usr/bin/env python3
"""Regression checks for package-manager manifest generation."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from command_output_redaction import redact_command_output


ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate-package-manager-manifests.py"
VERSION = "0.1.0"
TARGETS = {
    "macos-arm64": f"conu-{VERSION}-macos-arm64.zip",
    "macos-x64": f"conu-{VERSION}-macos-x64.zip",
    "linux-arm64": f"conu-{VERSION}-linux-arm64.tar.gz",
    "linux-x64": f"conu-{VERSION}-linux-x64.tar.gz",
    "windows-x64": f"conu-{VERSION}-windows-x64.zip",
}
WINDOWS_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
LINUX_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
HOMEBREW_FILENAME = "conu.rb"
SCOOP_FILENAME = "conu.json"
WINGET_FILENAME = "imthegoodboy.conU.yaml"
CHOCOLATEY_FILENAME = f"conu.{VERSION}.nupkg"
RPM_SPEC_FILENAME = "conu.spec"
DEBIAN_AMD64_FILENAME = f"conu_{VERSION}_amd64.deb"
DEBIAN_ARM64_FILENAME = f"conu_{VERSION}_arm64.deb"
APT_REPOSITORY_METADATA_FILENAME = f"conu-{VERSION}-apt-repository-metadata.zip"
RPM_REPOSITORY_METADATA_FILENAME = f"conu-{VERSION}-rpm-repository-metadata.zip"
RPM_ARCHES = {
    "linux-x64": "x86_64",
    "linux-arm64": "aarch64",
}
RPM_X64_FILENAME = f"conu-{VERSION}-1.x86_64.rpm"
RPM_ARM64_FILENAME = f"conu-{VERSION}-1.aarch64.rpm"
SENSITIVE_FAILURE_VALUES = (
    "npm_fakePackageToolToken1234567890",
    "ghp_fakePackageToolToken1234567890",
    "fake-bearer-token-1234567890",
    "fake-basic-token-1234567890",
    "fake-node-auth-token-1234567890",
    "fake-url-password-1234567890",
    "fake-query-token-1234567890",
    "fake-private-key-1234567890",
    "fake-amz-signature-1234567890",
    "fake-amz-credential-1234567890",
    "fake-amz-security-token-1234567890",
    "fake-azure-sas-signature-1234567890",
)


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_package_manager_manifests",
        GENERATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package-manager manifest generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_checksum(path: Path, archive_name: str | None = None) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(f"{path.name}.sha256").write_text(
        f"{digest}  {archive_name or path.name}\n",
        encoding="ascii",
    )
    return digest


def sha1_hexdigest(data: bytes) -> str:
    try:
        digest = hashlib.sha1(data, usedforsecurity=False)
    except TypeError:
        digest = hashlib.sha1(data)
    return digest.hexdigest()


def write_windows_zip(path: Path, *, rooted: bool) -> str:
    root = f"conu-{VERSION}-windows-x64/" if rooted else ""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for binary in WINDOWS_BINARIES:
            package.writestr(f"{root}bin/{binary}.exe", f"{binary}\n")
    return write_checksum(path)


def write_linux_tar_gz(path: Path, target: str, *, rooted: bool) -> str:
    root = f"conu-{VERSION}-{target}/" if rooted else ""
    with tarfile.open(path, "w:gz") as package:
        for binary in LINUX_BINARIES:
            data = f"{binary}-{target}\n".encode("ascii")
            info = tarfile.TarInfo(f"{root}bin/{binary}")
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 1577836800
            package.addfile(info, io.BytesIO(data))
        for name, data in {
            "README.md": b"# conU\n\nRPM package fixture.\n",
            "docs/distribution-and-hosting.md": b"# Distribution\n\nRPM docs fixture.\n",
            "packaging/README.md": b"# Packaging\n\nRPM packaging fixture.\n",
        }.items():
            info = tarfile.TarInfo(f"{root}{name}")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 1577836800
            package.addfile(info, io.BytesIO(data))
    return write_checksum(path)


def write_dist(
    root: Path,
    *,
    rooted_windows: bool = False,
    rooted_linux: bool = False,
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for target, filename in TARGETS.items():
        archive = root / filename
        if target == "windows-x64":
            hashes[target] = write_windows_zip(archive, rooted=rooted_windows)
        elif target.startswith("linux-"):
            hashes[target] = write_linux_tar_gz(archive, target, rooted=rooted_linux)
        else:
            archive.write_bytes(f"{target}\n".encode("ascii"))
            hashes[target] = write_checksum(archive)
    return hashes


def generate(
    generator,
    dist: Path,
    output: Path,
    *,
    build_rpm_packages: bool = False,
    build_apt_repository_metadata: bool = False,
    build_rpm_repository_metadata: bool = False,
) -> None:
    assets = generator.load_release_assets(
        dist,
        VERSION,
        "imthegoodboy/conU",
        f"v{VERSION}",
    )
    windows_extract_dir = generator.detect_windows_extract_dir(
        dist / assets["windows-x64"].filename,
        VERSION,
    )
    linux_binaries = {
        target: generator.extract_linux_binaries(
            dist / assets[target].filename,
            VERSION,
            target,
        )
        for target in ("linux-x64", "linux-arm64")
    }
    output.mkdir(parents=True, exist_ok=True)
    homebrew = generator.render_homebrew_formula(VERSION, "imthegoodboy/conU", assets)
    scoop = generator.render_scoop_manifest(
        VERSION,
        "imthegoodboy/conU",
        assets["windows-x64"],
        windows_extract_dir,
    )
    winget = generator.render_winget_manifest(
        VERSION,
        "imthegoodboy/conU",
        assets["windows-x64"],
        windows_extract_dir,
    )
    chocolatey_nuspec = generator.render_chocolatey_nuspec(VERSION, "imthegoodboy/conU")
    chocolatey_install = generator.render_chocolatey_install(
        VERSION,
        assets["windows-x64"],
        windows_extract_dir,
    )
    chocolatey_uninstall = generator.render_chocolatey_uninstall(
        assets["windows-x64"],
    )
    debian_packages = [
        generator.build_debian_package(
            VERSION,
            "imthegoodboy/conU",
            target,
            linux_binaries[target],
        )
        for target in ("linux-x64", "linux-arm64")
    ]
    apt_repository_metadata = (
        generator.build_apt_repository_metadata(VERSION, "imthegoodboy/conU", debian_packages)
        if build_apt_repository_metadata
        else None
    )
    rpm_spec = generator.render_rpm_spec(VERSION, "imthegoodboy/conU", assets)
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
    generator.assert_output_safe(
        "\n".join(safe_texts),
        dist,
    )
    (output / HOMEBREW_FILENAME).write_text(homebrew, encoding="ascii", newline="\n")
    (output / SCOOP_FILENAME).write_text(scoop, encoding="ascii", newline="\n")
    (output / WINGET_FILENAME).write_text(winget, encoding="ascii", newline="\n")
    generator.write_chocolatey_package(
        output / CHOCOLATEY_FILENAME,
        chocolatey_nuspec,
        chocolatey_install,
        chocolatey_uninstall,
    )
    for package in debian_packages:
        package_path = output / package.filename
        package_path.write_bytes(package.content)
        generator.write_sha256_sidecar(package_path, package.sha256)
    if apt_repository_metadata is not None:
        metadata_path = output / apt_repository_metadata.filename
        metadata_path.write_bytes(apt_repository_metadata.content)
        generator.write_sha256_sidecar(metadata_path, apt_repository_metadata.sha256)
    rpm_spec_path = output / RPM_SPEC_FILENAME
    rpm_spec_path.write_text(rpm_spec, encoding="ascii", newline="\n")
    rpm_package_paths = ()
    if build_rpm_packages:
        rpm_package_paths = generator.build_rpm_packages(VERSION, dist, rpm_spec_path, output)
    elif build_rpm_repository_metadata:
        rpm_package_paths = generator.existing_rpm_package_paths(VERSION, output)
    if build_rpm_repository_metadata:
        rpm_repository_metadata = generator.build_rpm_repository_metadata(
            VERSION,
            rpm_package_paths,
        )
        generator.assert_output_safe(rpm_repository_metadata.metadata_text, dist)
        metadata_path = output / rpm_repository_metadata.filename
        metadata_path.write_bytes(rpm_repository_metadata.content)
        generator.write_sha256_sidecar(metadata_path, rpm_repository_metadata.sha256)


def expect_failure(description: str, action, expected: str) -> str:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected not in message:
            raise AssertionError(
                f"{description} failed with {message!r}, expected {expected!r}"
            ) from exc
        return message
    raise AssertionError(f"{description} unexpectedly passed")


def expect_member_redacted_failure(
    description: str,
    action,
    expected: str,
    *forbidden_values: str,
) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
    else:
        raise AssertionError(f"{description} unexpectedly passed")
    if expected not in message:
        raise AssertionError(f"{description} failed with {message!r}, expected {expected!r}")
    for marker in ("pathDisplayed=false", "contentsDisplayed=false"):
        if marker not in message:
            raise AssertionError(f"{description} did not include {marker}: {message!r}")
    for value in forbidden_values:
        if value in message:
            raise AssertionError(f"{description} leaked archive member value {value!r}")


def expect_redacted_failure(description: str, action, expected: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
    else:
        raise AssertionError(f"{description} unexpectedly passed")
    if expected not in message:
        raise AssertionError(f"{description} failed with {message!r}, expected {expected!r}")
    if "[redacted]" not in message:
        raise AssertionError(f"{description} did not mark redacted output")
    for value in SENSITIVE_FAILURE_VALUES:
        if value in message:
            raise AssertionError(f"{description} leaked a sensitive value")


def run_generator_cli(dist: Path, output: Path, *extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(GENERATOR_PATH),
            str(dist),
            "--output-dir",
            str(output),
            "--version",
            VERSION,
            "--repo",
            "imthegoodboy/conU",
            "--tag",
            f"v{VERSION}",
            *extra_args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def expect_cli_failure(
    description: str,
    dist: Path,
    output: Path,
    expected: str,
    *extra_args: str,
) -> None:
    failed = run_generator_cli(dist, output, *extra_args)
    if failed.returncode == 0 or expected not in failed.stdout:
        raise AssertionError(
            f"{description} failed with {failed.stdout!r}, expected {expected!r}"
        )


def try_symlink(target: Path, link: Path, *, target_is_directory: bool = False) -> bool:
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


def expect_failure_with_limit(
    generator,
    limit_name: str,
    value: int,
    description: str,
    action,
    expected: str,
) -> None:
    original = getattr(generator, limit_name)
    setattr(generator, limit_name, value)
    try:
        expect_failure(description, action, expected)
    finally:
        setattr(generator, limit_name, original)


def expect_member_redacted_failure_with_limit(
    generator,
    limit_name: str,
    value: int,
    description: str,
    action,
    expected: str,
    *forbidden_values: str,
) -> None:
    original = getattr(generator, limit_name)
    setattr(generator, limit_name, value)
    try:
        expect_member_redacted_failure(description, action, expected, *forbidden_values)
    finally:
        setattr(generator, limit_name, original)


def assert_no_forbidden_output(path: Path, temp: Path) -> None:
    text = path.read_text(encoding="ascii")
    assert_no_forbidden_text(text, path.name, temp)


def assert_no_forbidden_text(text: str, label: str, temp: Path) -> None:
    forbidden = [
        str(temp).replace("\\", "/"),
        "NPM_TOKEN",
        "CONU_RELAY_TOKEN",
        "token_sha256_hex",
        "payloadHex",
        "PRIVATE KEY BLOCK",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN PRIVATE KEY",
    ]
    normalized = text.replace("\\", "/")
    for literal in forbidden:
        if literal and literal in normalized:
            raise AssertionError(f"{label} contained forbidden literal {literal!r}")


def assert_not_displayed(message: str, label: str, *forbidden_values: str) -> None:
    for value in forbidden_values:
        if value and value in message:
            raise AssertionError(f"{label}: displayed forbidden value {value!r}: {message!r}")


def assert_external_tool_output_redacts(generator) -> None:
    original_which = generator.shutil.which
    original_run = generator.subprocess.run
    raw = sensitive_command_output()
    try:

        def fake_which(name: str):
            if name == "rpmbuild":
                return "rpmbuild"
            if name == "createrepo_c":
                return "createrepo_c"
            if name == "createrepo":
                return None
            return original_which(name)

        def failed_run(command, *_args, **_kwargs):
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=command,
                output=raw,
            )

        generator.shutil.which = fake_which
        generator.subprocess.run = failed_run
        with tempfile.TemporaryDirectory(prefix="conu-package-tool-output-check-") as temp_text:
            temp = Path(temp_text)
            dist = temp / "dist"
            output = temp / "output"
            dist.mkdir()
            output.mkdir()
            spec_path = temp / RPM_SPEC_FILENAME
            spec_path.write_text("Name: conu\n", encoding="ascii", newline="\n")

            expect_redacted_failure(
                "rpmbuild failure output",
                lambda: generator.build_rpm_packages(VERSION, dist, spec_path, output),
                "rpmbuild failed",
            )

            package_paths = []
            for target in RPM_ARCHES:
                package = output / generator.rpm_filename(VERSION, target)
                package.write_bytes(b"rpm package fixture\n")
                write_checksum(package)
                package_paths.append(package)
            expect_redacted_failure(
                "createrepo failure output",
                lambda: generator.build_rpm_repository_metadata(VERSION, tuple(package_paths)),
                "createrepo_c failed",
            )
    finally:
        generator.shutil.which = original_which
        generator.subprocess.run = original_run


def sensitive_command_output() -> str:
    return "\n".join(
        [
            f"npm ERR! auth token {SENSITIVE_FAILURE_VALUES[0]}",
            f"gh token {SENSITIVE_FAILURE_VALUES[1]}",
            f"Authorization: Bearer {SENSITIVE_FAILURE_VALUES[2]}",
            f"Authorization: Basic {SENSITIVE_FAILURE_VALUES[3]}",
            f"NODE_AUTH_TOKEN={SENSITIVE_FAILURE_VALUES[4]}",
            f"https://user:{SENSITIVE_FAILURE_VALUES[5]}@example.invalid/conu",
            f"https://example.invalid/conu?token={SENSITIVE_FAILURE_VALUES[6]}",
            f"PRIVATE_KEY={SENSITIVE_FAILURE_VALUES[7]}",
            "https://s3.example.invalid/conu?"
            f"X-Amz-Signature={SENSITIVE_FAILURE_VALUES[8]}&"
            f"X-Amz-Credential={SENSITIVE_FAILURE_VALUES[9]}&"
            f"X-Amz-Security-Token={SENSITIVE_FAILURE_VALUES[10]}",
            f"https://blob.example.invalid/conu?sig={SENSITIVE_FAILURE_VALUES[11]}",
        ]
    )


def read_chocolatey_package(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as package:
        names = sorted(package.namelist())
        expected = [
            "conu.nuspec",
            "tools/chocolateyInstall.ps1",
            "tools/chocolateyUninstall.ps1",
        ]
        if names != expected:
            raise AssertionError(f"chocolatey package had entries {names!r}")
        return {
            name: package.read(name).decode("ascii")
            for name in names
        }


def read_ar_members(path: Path) -> dict[str, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise AssertionError(f"{path.name} was not an ar archive")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(data):
        header = data[offset : offset + 60]
        if len(header) != 60 or not header.endswith(b"`\n"):
            raise AssertionError(f"{path.name} had invalid ar header at {offset}")
        name = header[:16].decode("ascii").strip()
        size = int(header[48:58].decode("ascii").strip())
        offset += 60
        body = data[offset : offset + size]
        if len(body) != size:
            raise AssertionError(f"{path.name} truncated ar member {name}")
        members[name] = body
        offset += size + (size % 2)
    return members


def read_tar_gz_members(data: bytes) -> dict[str, tuple[bytes, int]]:
    members: dict[str, tuple[bytes, int]] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as package:
        for member in package.getmembers():
            if member.isdir():
                continue
            handle = package.extractfile(member)
            if handle is None:
                raise AssertionError(f"could not read tar member {member.name}")
            members[member.name] = (handle.read(), member.mode)
    return members


def read_debian_package(path: Path) -> tuple[str, dict[str, tuple[bytes, int]], str]:
    members = read_ar_members(path)
    expected = ["debian-binary", "control.tar.gz", "data.tar.gz"]
    if list(members) != expected:
        raise AssertionError(f"{path.name} had ar members {list(members)!r}")
    if members["debian-binary"] != b"2.0\n":
        raise AssertionError(f"{path.name} had invalid debian-binary marker")
    control_members = read_tar_gz_members(members["control.tar.gz"])
    data_members = read_tar_gz_members(members["data.tar.gz"])
    control = control_members["./control"][0].decode("ascii")
    md5sums = control_members["./md5sums"][0].decode("ascii")
    return control, data_members, md5sums


def assert_debian_package(
    path: Path,
    *,
    architecture: str,
    target: str,
) -> None:
    control, data_members, md5sums = read_debian_package(path)
    if f"Architecture: {architecture}" not in control or "Package: conu" not in control:
        raise AssertionError(f"{path.name} control metadata was missing")
    if "Description: Agent-native encrypted communication layer" not in control:
        raise AssertionError(f"{path.name} control description was missing")
    for binary in LINUX_BINARIES:
        member_name = f"./usr/bin/{binary}"
        if member_name not in data_members:
            raise AssertionError(f"{path.name} missing {member_name}")
        content, mode = data_members[member_name]
        if content != f"{binary}-{target}\n".encode("ascii"):
            raise AssertionError(f"{path.name} embedded wrong content for {binary}")
        if mode != 0o755:
            raise AssertionError(f"{path.name} did not preserve executable mode for {binary}")
        digest = hashlib.md5(content, usedforsecurity=False).hexdigest()
        if f"{digest}  usr/bin/{binary}" not in md5sums:
            raise AssertionError(f"{path.name} md5sums was missing {binary}")
    if "./usr/share/doc/conu/README.Debian" not in data_members:
        raise AssertionError(f"{path.name} missing README.Debian")
    if "./usr/share/doc/conu/conud.service.example" not in data_members:
        raise AssertionError(f"{path.name} missing service example")
    assert_dpkg_deb_accepts(path, architecture)


def assert_dpkg_deb_accepts(path: Path, architecture: str) -> None:
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb is None:
        return
    info = subprocess.run(
        [dpkg_deb, "--info", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    if "Package: conu" not in info or f"Architecture: {architecture}" not in info:
        raise AssertionError(f"{path.name} was not accepted with expected dpkg-deb metadata")
    contents = subprocess.run(
        [dpkg_deb, "--contents", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    for binary in LINUX_BINARIES:
        if f"./usr/bin/{binary}" not in contents:
            raise AssertionError(f"{path.name} dpkg-deb contents missed {binary}")


def assert_rpmbuild_accepts(generator, spec_path: Path, dist: Path) -> None:
    rpmbuild = shutil.which("rpmbuild")
    if rpmbuild is None:
        return
    rpm = shutil.which("rpm")
    for target, rpm_arch in RPM_ARCHES.items():
        with tempfile.TemporaryDirectory(prefix=f"conu-rpmbuild-{rpm_arch}-") as topdir_text:
            topdir = Path(topdir_text)
            for name in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
                (topdir / name).mkdir()
            command = generator.rpm_build_command(
                rpmbuild,
                spec_path,
                dist,
                topdir,
                rpm_arch,
            )
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
                raise AssertionError(
                    f"rpmbuild failed for {target} with output:\n"
                    f"{redact_command_output(exc.stdout or '')}"
                ) from exc
            packages = sorted((topdir / "RPMS").rglob("conu-*.rpm"))
            if len(packages) != 1:
                raise AssertionError(
                    f"rpmbuild for {target} produced packages {[str(path) for path in packages]!r}"
                )
            expected_name = generator.rpm_filename(VERSION, target)
            if packages[0].name != expected_name:
                raise AssertionError(
                    f"rpmbuild for {target} produced {packages[0].name!r}; "
                    f"expected {expected_name!r}"
                )
            if rpm is not None:
                assert_rpm_package_metadata(rpm, packages[0], rpm_arch)


def assert_rpm_package_metadata(rpm: str, package: Path, rpm_arch: str) -> None:
    info = subprocess.run(
        [rpm, "-qip", str(package)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    if "Name        : conu" not in info or f"Architecture: {rpm_arch}" not in info:
        raise AssertionError(f"{package.name} had unexpected RPM metadata:\n{info}")
    contents = subprocess.run(
        [rpm, "-qlp", str(package)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    for binary in LINUX_BINARIES:
        if f"/usr/bin/{binary}" not in contents:
            raise AssertionError(f"{package.name} rpm contents missed {binary}")


def assert_generated_rpm_assets(generator, output: Path) -> None:
    rpm = shutil.which("rpm")
    for target, rpm_arch in RPM_ARCHES.items():
        package = output / generator.rpm_filename(VERSION, target)
        if not package.exists():
            raise AssertionError(f"{package.name} was not generated")
        assert_sha256_sidecar(package)
        if rpm is not None:
            assert_rpm_package_metadata(rpm, package, rpm_arch)


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    if sidecar.read_text(encoding="ascii") != f"{expected}  {path.name}\n":
        raise AssertionError(f"{sidecar.name} did not name and hash the generated package")


def read_apt_repository_metadata(path: Path) -> dict[str, bytes]:
    expected = ["README.txt", "Packages", "Packages.gz", "Release"]
    with zipfile.ZipFile(path) as package:
        if package.namelist() != expected:
            raise AssertionError(f"{path.name} had APT metadata members {package.namelist()!r}")
        for name in expected:
            info = package.getinfo(name)
            if info.date_time != (2020, 1, 1, 0, 0, 0):
                raise AssertionError(f"{path.name}:{name} was not timestamp-normalized")
            mode = (info.external_attr >> 16) & 0o777
            if mode != 0o644:
                raise AssertionError(f"{path.name}:{name} had mode {oct(mode)}")
        return {name: package.read(name) for name in expected}


def assert_apt_repository_metadata(path: Path, temp: Path) -> None:
    contents = read_apt_repository_metadata(path)
    packages_bytes = contents["Packages"]
    packages_text = packages_bytes.decode("ascii")
    packages_gz = contents["Packages.gz"]
    release_text = contents["Release"].decode("ascii")
    readme_text = contents["README.txt"].decode("ascii")

    if gzip.decompress(packages_gz) != packages_bytes:
        raise AssertionError(f"{path.name} Packages.gz did not decompress to Packages")
    if packages_text.count("Package: conu\n") != 2:
        raise AssertionError(f"{path.name} Packages did not contain two conU package entries")
    for deb_name, architecture in (
        (DEBIAN_AMD64_FILENAME, "amd64"),
        (DEBIAN_ARM64_FILENAME, "arm64"),
    ):
        deb_bytes = path.with_name(deb_name).read_bytes()
        expected_fields = [
            f"Version: {VERSION}",
            f"Architecture: {architecture}",
            f"Filename: {deb_name}",
            f"Size: {len(deb_bytes)}",
            f"MD5sum: {hashlib.md5(deb_bytes, usedforsecurity=False).hexdigest()}",
            f"SHA1: {sha1_hexdigest(deb_bytes)}",
            f"SHA256: {hashlib.sha256(deb_bytes).hexdigest()}",
            "Homepage: https://github.com/imthegoodboy/conU",
            "Description: Agent-native encrypted communication layer",
        ]
        for field in expected_fields:
            if field not in packages_text:
                raise AssertionError(f"{path.name} Packages missed {field!r}")
    if "Architectures: amd64 arm64" not in release_text:
        raise AssertionError(f"{path.name} Release missed architectures")
    for name, content in (("Packages", packages_bytes), ("Packages.gz", packages_gz)):
        release_fields = [
            f" {hashlib.md5(content, usedforsecurity=False).hexdigest()} {len(content)} {name}",
            f" {sha1_hexdigest(content)} {len(content)} {name}",
            f" {hashlib.sha256(content).hexdigest()} {len(content)} {name}",
        ]
        for field in release_fields:
            if field not in release_text:
                raise AssertionError(f"{path.name} Release missed {field!r}")
    if (
        "Tagged release publication adds native APT signatures" not in readme_text
        or "InRelease" not in readme_text
        or "Release.gpg" not in readme_text
        or DEBIAN_AMD64_FILENAME not in readme_text
    ):
        raise AssertionError(f"{path.name} README missed signed publication guidance")
    for label, text in (
        ("README.txt", readme_text),
        ("Packages", packages_text),
        ("Release", release_text),
    ):
        assert_no_forbidden_text(text, f"{path.name}:{label}", temp)
    assert_sha256_sidecar(path)


def read_rpm_repository_metadata(path: Path) -> dict[str, bytes]:
    required = [
        "README.txt",
        "repodata/filelists.xml.gz",
        "repodata/other.xml.gz",
        "repodata/primary.xml.gz",
        "repodata/repomd.xml",
    ]
    with zipfile.ZipFile(path) as package:
        names = package.namelist()
        if names != required:
            raise AssertionError(f"{path.name} had RPM repository members {names!r}")
        for name in names:
            if name.endswith(".rpm"):
                raise AssertionError(f"{path.name} unexpectedly embedded RPM payload {name}")
            info = package.getinfo(name)
            if info.date_time != (2020, 1, 1, 0, 0, 0):
                raise AssertionError(f"{path.name}:{name} was not timestamp-normalized")
            mode = (info.external_attr >> 16) & 0o777
            if mode != 0o644:
                raise AssertionError(f"{path.name}:{name} had mode {oct(mode)}")
        return {name: package.read(name) for name in names}


def assert_rpm_repository_metadata(path: Path, temp: Path, generator, output: Path) -> None:
    contents = read_rpm_repository_metadata(path)
    readme_text = contents["README.txt"].decode("ascii")
    repomd_text = contents["repodata/repomd.xml"].decode("utf-8")
    primary_text = gzip.decompress(contents["repodata/primary.xml.gz"]).decode("utf-8")
    filelists_text = gzip.decompress(contents["repodata/filelists.xml.gz"]).decode("utf-8")
    other_text = gzip.decompress(contents["repodata/other.xml.gz"]).decode("utf-8")

    if (
        "Tagged release publication signs the generated .rpm package payloads first" not in readme_text
        or "generates this metadata from the signed packages" not in readme_text
        or RPM_X64_FILENAME not in readme_text
    ):
        raise AssertionError(f"{path.name} README missed signed publication guidance")
    normalized_readme = " ".join(readme_text.split())
    if "signed .rpm files beside the unpacked metadata" not in normalized_readme:
        raise AssertionError(f"{path.name} README missed repository placement guidance")

    repomd_root = ET.fromstring(repomd_text)
    repo_ns = {"repo": "http://linux.duke.edu/metadata/repo"}
    expected_metadata = {
        "primary": "repodata/primary.xml.gz",
        "filelists": "repodata/filelists.xml.gz",
        "other": "repodata/other.xml.gz",
    }
    seen_metadata: dict[str, str] = {}
    for data in repomd_root.findall("repo:data", repo_ns):
        metadata_type = data.attrib.get("type")
        location = data.find("repo:location", repo_ns)
        checksum = data.find("repo:checksum", repo_ns)
        timestamp = data.find("repo:timestamp", repo_ns)
        if metadata_type not in expected_metadata:
            continue
        if location is None or checksum is None or timestamp is None:
            raise AssertionError(f"{path.name} repomd.xml missed fields for {metadata_type}")
        href = location.attrib.get("href", "")
        if href != expected_metadata[metadata_type]:
            raise AssertionError(f"{path.name} repomd.xml had unexpected {metadata_type} href {href!r}")
        if checksum.attrib.get("type") != "sha256":
            raise AssertionError(f"{path.name} repomd.xml did not use sha256 for {metadata_type}")
        if checksum.text != hashlib.sha256(contents[href]).hexdigest():
            raise AssertionError(f"{path.name} repomd.xml had wrong checksum for {href}")
        if timestamp.text != "1577836800":
            raise AssertionError(f"{path.name} repomd.xml had nondeterministic timestamp for {href}")
        seen_metadata[metadata_type] = href
    if seen_metadata != expected_metadata:
        raise AssertionError(f"{path.name} repomd.xml metadata set was {seen_metadata!r}")

    primary_root = ET.fromstring(primary_text)
    common_ns = {"common": "http://linux.duke.edu/metadata/common"}
    packages_by_href: dict[str, ET.Element] = {}
    for package in primary_root.findall("common:package", common_ns):
        location = package.find("common:location", common_ns)
        if location is not None:
            packages_by_href[location.attrib.get("href", "")] = package
    if set(packages_by_href) != {RPM_X64_FILENAME, RPM_ARM64_FILENAME}:
        raise AssertionError(f"{path.name} primary metadata had packages {set(packages_by_href)!r}")

    for filename, rpm_arch in (
        (RPM_X64_FILENAME, "x86_64"),
        (RPM_ARM64_FILENAME, "aarch64"),
    ):
        rpm_bytes = (output / filename).read_bytes()
        package = packages_by_href[filename]
        name = package.findtext("common:name", namespaces=common_ns)
        arch = package.findtext("common:arch", namespaces=common_ns)
        checksum = package.find("common:checksum", common_ns)
        version = package.find("common:version", common_ns)
        size = package.find("common:size", common_ns)
        if name != "conu" or arch != rpm_arch:
            raise AssertionError(f"{path.name} primary metadata missed {filename} name/arch")
        if checksum is None or checksum.attrib.get("type") != "sha256":
            raise AssertionError(f"{path.name} primary metadata missed sha256 for {filename}")
        if checksum.text != hashlib.sha256(rpm_bytes).hexdigest():
            raise AssertionError(f"{path.name} primary metadata had wrong package checksum")
        if version is None or version.attrib.get("ver") != VERSION or version.attrib.get("rel") != "1":
            raise AssertionError(f"{path.name} primary metadata had wrong version for {filename}")
        if size is None or size.attrib.get("package") != str(len(rpm_bytes)):
            raise AssertionError(f"{path.name} primary metadata had wrong size for {filename}")

    for binary in LINUX_BINARIES:
        if f"/usr/bin/{binary}" not in filelists_text:
            raise AssertionError(f"{path.name} filelists metadata missed {binary}")
    if primary_text.count("<package type=\"rpm\">") != 2 or other_text.count("pkgid=") != 2:
        raise AssertionError(f"{path.name} RPM metadata did not describe two packages")
    for label, text in (
        ("README.txt", readme_text),
        ("repomd.xml", repomd_text),
        ("primary.xml.gz", primary_text),
        ("filelists.xml.gz", filelists_text),
        ("other.xml.gz", other_text),
    ):
        assert_no_forbidden_text(text, f"{path.name}:{label}", temp)
    assert_sha256_sidecar(path)


def assert_zip_no_forbidden_output(path: Path, temp: Path) -> None:
    for name, text in read_chocolatey_package(path).items():
        assert_no_forbidden_text(text, f"{path.name}:{name}", temp)


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


def main() -> int:
    generator = load_generator()
    assert_external_tool_output_redacts(generator)
    if generator.validate_version("1.2.3-rc.1+build.5") != "1.2.3-rc.1+build.5":
        raise AssertionError("package-manager generator rejected semver prerelease plus build metadata")
    if generator.validate_tag("v1.2.3-rc.1+build.5") != "v1.2.3-rc.1+build.5":
        raise AssertionError("package-manager generator rejected semver release tag")
    for repo in ("owner/repo", "owner-name/repo.name", "owner/repo_name"):
        if generator.validate_repo(repo) != repo:
            raise AssertionError(f"valid package-manager repository changed during validation: {repo}")
    for repo, expected in (
        ("owner_name/repo", "owner contains unsupported characters"),
        ("owner/..", "repository name is invalid"),
        ("owner/repo/extra", "owner/name form"),
        ("owner/repo?secret=value", "name contains unsupported characters"),
    ):
        expect_failure(
            f"invalid package-manager repository {repo}",
            lambda repo=repo: generator.validate_repo(repo),
            expected,
        )
    with tempfile.TemporaryDirectory(prefix="conu-package-manifest-") as temp_text:
        temp = Path(temp_text)

        rootless_dist = temp / "rootless-dist"
        rootless_out = temp / "rootless-out"
        rootless_dist.mkdir()
        hashes = write_dist(rootless_dist, rooted_windows=False)
        generate(generator, rootless_dist, rootless_out)

        oversized_input = temp / "secret-package-manager-input-name-should-not-print.zip"
        oversized_input.write_bytes(b"oversized\n")
        message = expect_failure(
            "oversized package-manager input",
            lambda: generator.open_regular_file(
                oversized_input,
                "package-manager input asset",
                max_bytes=1,
            ),
            "package-manager input asset is too large",
        )
        assert_not_displayed(
            message,
            "oversized package-manager input",
            oversized_input.name,
        )

        original_open_regular_file = generator.open_regular_file
        try:
            generator.open_regular_file = lambda _path, _label, *, max_bytes: (
                io.BytesIO(b"xx"),
                2,
            )
            message = expect_failure(
                "oversized package-manager read",
                lambda: generator.read_regular_file(
                    Path("secret-package-manager-read-name-should-not-print.zip"),
                    "package-manager read asset",
                    max_bytes=1,
                ),
                "package-manager read asset is too large",
            )
            assert_not_displayed(
                message,
                "oversized package-manager read",
                "secret-package-manager-read-name-should-not-print.zip",
            )
        finally:
            generator.open_regular_file = original_open_regular_file

        for literal in ("PRIVATE KEY BLOCK", "BEGIN OPENSSH PRIVATE KEY"):
            expect_failure(
                f"forbidden package-manager manifest literal {literal}",
                lambda literal=literal: generator.assert_output_safe(
                    f"public manifest text\n{literal}\n",
                    rootless_dist,
                ),
                f"forbidden literal: {literal}",
            )

        expect_failure_with_limit(
            generator,
            "MAX_RELEASE_ARCHIVE_BYTES",
            1,
            "oversized release asset",
            lambda: generator.load_release_assets(
                rootless_dist,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "release asset for macos-arm64 is too large",
        )

        symlink_dist = temp / "symlink-dist"
        if try_symlink(rootless_dist, symlink_dist, target_is_directory=True):
            expect_cli_failure(
                "symlinked release dist directory",
                symlink_dist,
                temp / "symlink-dist-out",
                "release dist directory must not be a symlink",
            )

        expect_cli_failure(
            "invalid package-manager repository CLI",
            rootless_dist,
            temp / "invalid-repo-out",
            "owner contains unsupported characters",
            "--repo",
            "owner_name/repo",
        )

        symlink_asset = temp / "symlink-asset"
        shutil.copytree(rootless_dist, symlink_asset)
        asset_target = temp / "symlink-asset-target.zip"
        shutil.copy2(symlink_asset / TARGETS["windows-x64"], asset_target)
        (symlink_asset / TARGETS["windows-x64"]).unlink()
        if try_symlink(asset_target, symlink_asset / TARGETS["windows-x64"]):
            expect_cli_failure(
                "symlinked release asset",
                symlink_asset,
                temp / "symlink-asset-out",
                "release asset for windows-x64 must not be a symlink",
            )

        symlink_checksum = temp / "symlink-checksum"
        shutil.copytree(rootless_dist, symlink_checksum)
        checksum_target = temp / "symlink-checksum-target.sha256"
        shutil.copy2(symlink_checksum / f"{TARGETS['macos-arm64']}.sha256", checksum_target)
        (symlink_checksum / f"{TARGETS['macos-arm64']}.sha256").unlink()
        if try_symlink(checksum_target, symlink_checksum / f"{TARGETS['macos-arm64']}.sha256"):
            expect_cli_failure(
                "symlinked release checksum",
                symlink_checksum,
                temp / "symlink-checksum-out",
                "checksum file for package-manager asset must not be a symlink",
            )

        symlink_output_target = temp / "symlink-output-target"
        symlink_output_target.mkdir()
        symlink_output = temp / "symlink-output"
        if try_symlink(symlink_output_target, symlink_output, target_is_directory=True):
            expect_cli_failure(
                "symlinked output directory",
                rootless_dist,
                symlink_output,
                "package-manager output directory must not be a symlink",
            )

        symlink_output_file = temp / "symlink-output-file"
        symlink_output_file.mkdir()
        output_file_target = temp / "symlink-output-file-target.rb"
        output_file_target.write_text("# target\n", encoding="ascii", newline="\n")
        if try_symlink(output_file_target, symlink_output_file / HOMEBREW_FILENAME):
            expect_cli_failure(
                "symlinked Homebrew output",
                rootless_dist,
                symlink_output_file,
                "Homebrew formula output must not be a symlink",
            )

        symlink_chocolatey = temp / "symlink-chocolatey"
        symlink_chocolatey.mkdir()
        chocolatey_target = temp / "symlink-chocolatey-target.nupkg"
        chocolatey_target.write_bytes(b"target\n")
        if try_symlink(chocolatey_target, symlink_chocolatey / CHOCOLATEY_FILENAME):
            expect_cli_failure(
                "symlinked Chocolatey output",
                rootless_dist,
                symlink_chocolatey,
                "Chocolatey package output must not be a symlink",
            )

        symlink_sidecar = temp / "symlink-sidecar"
        symlink_sidecar.mkdir()
        sidecar_target = temp / "symlink-sidecar-target.sha256"
        sidecar_target.write_text(f"{'0' * 64}  target\n", encoding="ascii", newline="\n")
        if try_symlink(sidecar_target, symlink_sidecar / f"{DEBIAN_AMD64_FILENAME}.sha256"):
            expect_cli_failure(
                "symlinked generated sidecar",
                rootless_dist,
                symlink_sidecar,
                "package-manager output SHA-256 sidecar output must not be a symlink",
            )

        symlink_existing_rpm = temp / "symlink-existing-rpm"
        symlink_existing_rpm.mkdir()
        rpm_target = temp / "symlink-existing-rpm-target.rpm"
        rpm_target.write_bytes(b"rpm target\n")
        if try_symlink(rpm_target, symlink_existing_rpm / RPM_X64_FILENAME):
            expect_failure(
                "symlinked existing RPM package",
                lambda: generator.existing_rpm_package_paths(VERSION, symlink_existing_rpm),
                "generated RPM package must not be a symlink",
            )

        symlink_existing_rpm_sidecar = temp / "symlink-existing-rpm-sidecar"
        symlink_existing_rpm_sidecar.mkdir()
        rpm_package = symlink_existing_rpm_sidecar / RPM_X64_FILENAME
        rpm_package.write_bytes(b"rpm package\n")
        write_checksum(rpm_package)
        rpm_sidecar_target = temp / "symlink-existing-rpm-sidecar-target.sha256"
        shutil.copy2(rpm_package.with_name(f"{rpm_package.name}.sha256"), rpm_sidecar_target)
        rpm_package.with_name(f"{rpm_package.name}.sha256").unlink()
        if try_symlink(rpm_sidecar_target, rpm_package.with_name(f"{rpm_package.name}.sha256")):
            expect_failure(
                "symlinked existing RPM sidecar",
                lambda: generator.existing_rpm_package_paths(VERSION, symlink_existing_rpm_sidecar),
                "SHA-256 sidecar for generated RPM package must not be a symlink",
            )

        non_ascii_existing_rpm_sidecar = temp / "non-ascii-existing-rpm-sidecar"
        non_ascii_existing_rpm_sidecar.mkdir()
        rpm_package = non_ascii_existing_rpm_sidecar / RPM_X64_FILENAME
        rpm_package.write_bytes(b"rpm package\n")
        rpm_package.with_name(f"{rpm_package.name}.sha256").write_bytes(b"\xff\n")
        message = expect_failure(
            "non-ASCII existing RPM sidecar",
            lambda: generator.existing_rpm_package_paths(VERSION, non_ascii_existing_rpm_sidecar),
            "SHA-256 sidecar is not ASCII",
        )
        assert_not_displayed(message, "non-ASCII existing RPM sidecar", rpm_package.name)

        invalid_existing_rpm_sidecar = temp / "invalid-existing-rpm-sidecar"
        invalid_existing_rpm_sidecar.mkdir()
        rpm_package = invalid_existing_rpm_sidecar / RPM_X64_FILENAME
        rpm_package.write_bytes(b"rpm package\n")
        rpm_package.with_name(f"{rpm_package.name}.sha256").write_text(
            "not a strict checksum\n",
            encoding="ascii",
            newline="\n",
        )
        message = expect_failure(
            "invalid existing RPM sidecar",
            lambda: generator.existing_rpm_package_paths(VERSION, invalid_existing_rpm_sidecar),
            "invalid format",
        )
        assert_not_displayed(message, "invalid existing RPM sidecar", rpm_package.name)

        wrong_existing_rpm_sidecar = temp / "wrong-existing-rpm-sidecar"
        wrong_existing_rpm_sidecar.mkdir()
        rpm_package = wrong_existing_rpm_sidecar / RPM_X64_FILENAME
        rpm_package.write_bytes(b"rpm package\n")
        malicious_rpm_target = "secret-package-manager-rpm-sidecar-target.rpm"
        write_checksum(rpm_package, archive_name=malicious_rpm_target)
        message = expect_failure(
            "wrong existing RPM sidecar target",
            lambda: generator.existing_rpm_package_paths(VERSION, wrong_existing_rpm_sidecar),
            "names wrong file",
        )
        assert_not_displayed(
            message,
            "wrong existing RPM sidecar target",
            rpm_package.name,
            malicious_rpm_target,
        )

        mismatched_existing_rpm_sidecar = temp / "mismatched-existing-rpm-sidecar"
        mismatched_existing_rpm_sidecar.mkdir()
        rpm_package = mismatched_existing_rpm_sidecar / RPM_X64_FILENAME
        rpm_package.write_bytes(b"rpm package\n")
        rpm_package.with_name(f"{rpm_package.name}.sha256").write_text(
            f"{'0' * 64}  {rpm_package.name}\n",
            encoding="ascii",
            newline="\n",
        )
        message = expect_failure(
            "mismatched existing RPM sidecar",
            lambda: generator.existing_rpm_package_paths(VERSION, mismatched_existing_rpm_sidecar),
            "SHA-256 mismatch",
        )
        assert_not_displayed(message, "mismatched existing RPM sidecar", rpm_package.name)

        expect_member_redacted_failure_with_limit(
            generator,
            "MAX_RELEASE_MEMBER_COUNT",
            1,
            "windows archive member count bound",
            lambda: generator.detect_windows_extract_dir(
                rootless_dist / TARGETS["windows-x64"],
                VERSION,
            ),
            "contains more than 1 entries",
        )

        homebrew = (rootless_out / HOMEBREW_FILENAME).read_text(encoding="ascii")
        if "class Conu < Formula" not in homebrew:
            raise AssertionError("homebrew formula class was missing")
        if "license :cannot_represent" not in homebrew:
            raise AssertionError("homebrew formula did not use a Homebrew-compatible license")
        if 'pipe_output("#{bin}/conu-mcp", "", 0)' not in homebrew or "conu-mcp\", \"--help\"" in homebrew:
            raise AssertionError("homebrew formula did not close stdin for the conu-mcp smoke test")
        if TARGETS["macos-arm64"] not in homebrew or hashes["macos-arm64"] not in homebrew:
            raise AssertionError("homebrew formula did not include macOS arm64 asset and hash")
        if TARGETS["linux-x64"] not in homebrew or hashes["linux-x64"] not in homebrew:
            raise AssertionError("homebrew formula did not include Linux x64 asset and hash")
        assert_no_forbidden_output(rootless_out / HOMEBREW_FILENAME, temp)

        scoop = json.loads((rootless_out / SCOOP_FILENAME).read_text(encoding="ascii"))
        if scoop["architecture"]["64bit"]["hash"] != hashes["windows-x64"]:
            raise AssertionError("scoop manifest did not use the Windows release hash")
        if "extract_dir" in scoop:
            raise AssertionError("rootless Windows archive should not set extract_dir")
        if ["bin\\conu.exe", "conu"] not in scoop["bin"]:
            raise AssertionError("scoop manifest did not expose conu")
        assert_no_forbidden_output(rootless_out / SCOOP_FILENAME, temp)

        winget = (rootless_out / WINGET_FILENAME).read_text(encoding="ascii")
        if "PackageIdentifier: imthegoodboy.conU" not in winget:
            raise AssertionError("winget manifest package identifier was missing")
        if "InstallerType: zip" not in winget or "NestedInstallerType: portable" not in winget:
            raise AssertionError("winget manifest did not describe a portable zip installer")
        if f"InstallerSha256: {hashes['windows-x64']}" not in winget:
            raise AssertionError("winget manifest did not use the Windows release hash")
        if TARGETS["windows-x64"] not in winget:
            raise AssertionError("winget manifest did not include the Windows release URL")
        if "RelativeFilePath: bin/conu.exe" not in winget:
            raise AssertionError("rootless winget manifest did not map conu.exe")
        if "PortableCommandAlias: conu-mcp" not in winget:
            raise AssertionError("winget manifest did not expose conu-mcp")
        assert_no_forbidden_output(rootless_out / WINGET_FILENAME, temp)

        chocolatey = read_chocolatey_package(rootless_out / CHOCOLATEY_FILENAME)
        nuspec = chocolatey["conu.nuspec"]
        install_script = chocolatey["tools/chocolateyInstall.ps1"]
        uninstall_script = chocolatey["tools/chocolateyUninstall.ps1"]
        if "<id>conu</id>" not in nuspec or "<version>0.1.0</version>" not in nuspec:
            raise AssertionError("chocolatey nuspec package metadata was missing")
        if TARGETS["windows-x64"] not in install_script or hashes["windows-x64"] not in install_script:
            raise AssertionError("chocolatey install script did not include the Windows asset and hash")
        if "Install-ChocolateyZipPackage @packageArgs" not in install_script:
            raise AssertionError("chocolatey install script did not use the Chocolatey ZIP helper")
        if "ChecksumType64 = 'sha256'" not in install_script:
            raise AssertionError("chocolatey install script did not require SHA-256 checksums")
        if "Install-BinFile -Name $binary -Path $binaryPath" not in install_script:
            raise AssertionError("chocolatey install script did not expose command shims")
        if "conu-0.1.0-windows-x64\\bin" not in install_script:
            raise AssertionError("chocolatey install script did not keep rooted archive fallback")
        if "Uninstall-BinFile -Name $binary" not in uninstall_script:
            raise AssertionError("chocolatey uninstall script did not remove command shims")
        if f"Uninstall-ChocolateyZipPackage $packageName '{TARGETS['windows-x64']}'" not in uninstall_script:
            raise AssertionError("chocolatey uninstall script did not clean extracted zip files")
        assert_zip_no_forbidden_output(rootless_out / CHOCOLATEY_FILENAME, temp)
        if (rootless_out / "conu-chocolatey.zip").exists():
            raise AssertionError("chocolatey output should not use a .zip release-archive name")
        if generator.chocolatey_filename(VERSION) != CHOCOLATEY_FILENAME:
            raise AssertionError("chocolatey package filename did not include package id and version")

        deb_amd64 = rootless_out / DEBIAN_AMD64_FILENAME
        deb_arm64 = rootless_out / DEBIAN_ARM64_FILENAME
        assert_debian_package(deb_amd64, architecture="amd64", target="linux-x64")
        assert_debian_package(deb_arm64, architecture="arm64", target="linux-arm64")
        assert_sha256_sidecar(deb_amd64)
        assert_sha256_sidecar(deb_arm64)
        apt_out = temp / "apt-out"
        generate(generator, rootless_dist, apt_out, build_apt_repository_metadata=True)
        assert_apt_repository_metadata(apt_out / APT_REPOSITORY_METADATA_FILENAME, temp)
        rpm_spec = (rootless_out / RPM_SPEC_FILENAME).read_text(encoding="ascii")
        if "Name: conu" not in rpm_spec or "Version: 0.1.0" not in rpm_spec:
            raise AssertionError("rpm spec package metadata was missing")
        if TARGETS["linux-x64"] not in rpm_spec or hashes["linux-x64"] not in rpm_spec:
            raise AssertionError("rpm spec did not include Linux x64 source and checksum")
        if TARGETS["linux-arm64"] not in rpm_spec or hashes["linux-arm64"] not in rpm_spec:
            raise AssertionError("rpm spec did not include Linux arm64 source and checksum")
        if "%ifarch x86_64" not in rpm_spec or "%ifarch aarch64" not in rpm_spec:
            raise AssertionError("rpm spec did not guard supported Linux architectures")
        if "%{_bindir}/conu-mcp" not in rpm_spec:
            raise AssertionError("rpm spec did not install conu-mcp")
        assert_no_forbidden_output(rootless_out / RPM_SPEC_FILENAME, temp)
        assert_rpmbuild_accepts(generator, rootless_out / RPM_SPEC_FILENAME, rootless_dist)
        if DEBIAN_AMD64_FILENAME not in generator.output_filenames(VERSION):
            raise AssertionError("output filenames did not include Debian amd64 package")
        if f"{DEBIAN_AMD64_FILENAME}.sha256" not in generator.output_filenames(VERSION):
            raise AssertionError("output filenames did not include Debian amd64 checksum")
        if RPM_X64_FILENAME in generator.output_filenames(VERSION):
            raise AssertionError("default output filenames should not include RPM packages")
        if APT_REPOSITORY_METADATA_FILENAME in generator.output_filenames(VERSION):
            raise AssertionError("default output filenames should not include APT repository metadata")
        if RPM_REPOSITORY_METADATA_FILENAME in generator.output_filenames(VERSION):
            raise AssertionError("default output filenames should not include RPM repository metadata")
        if APT_REPOSITORY_METADATA_FILENAME not in generator.output_filenames(
            VERSION,
            include_apt_repository_metadata=True,
        ):
            raise AssertionError("APT repository output filenames did not include metadata bundle")
        if f"{APT_REPOSITORY_METADATA_FILENAME}.sha256" not in generator.output_filenames(
            VERSION,
            include_apt_repository_metadata=True,
        ):
            raise AssertionError("APT repository output filenames did not include metadata checksum")
        if RPM_REPOSITORY_METADATA_FILENAME not in generator.output_filenames(
            VERSION,
            include_rpm_repository_metadata=True,
        ):
            raise AssertionError("RPM repository output filenames did not include metadata bundle")
        if f"{RPM_REPOSITORY_METADATA_FILENAME}.sha256" not in generator.output_filenames(
            VERSION,
            include_rpm_repository_metadata=True,
        ):
            raise AssertionError("RPM repository output filenames did not include metadata checksum")
        if RPM_X64_FILENAME not in generator.output_filenames(VERSION, include_rpm_packages=True):
            raise AssertionError("RPM package output filenames did not include x86_64 package")
        if f"{RPM_ARM64_FILENAME}.sha256" not in generator.output_filenames(
            VERSION,
            include_rpm_packages=True,
        ):
            raise AssertionError("RPM package output filenames did not include aarch64 checksum")
        if generator.debian_version("1.2.3-rc.1+build.5") != "1.2.3~rc.1+build.5":
            raise AssertionError("Debian version conversion did not preserve prerelease ordering")
        if generator.rpm_version("1.2.3-rc.1+build.5") != "1.2.3~rc.1_build.5":
            raise AssertionError("RPM version conversion did not normalize semver build metadata")
        if (
            generator.rpm_filename("1.2.3-rc.1+build.5", "linux-x64")
            != "conu-1.2.3~rc.1_build.5-1.x86_64.rpm"
        ):
            raise AssertionError("RPM package filename did not normalize semver metadata")

        if shutil.which("rpmbuild") is not None:
            rpm_out = temp / "rpm-out"
            generate(
                generator,
                rootless_dist,
                rpm_out,
                build_rpm_packages=True,
                build_rpm_repository_metadata=shutil.which("createrepo_c") is not None
                or shutil.which("createrepo") is not None,
            )
            assert_generated_rpm_assets(generator, rpm_out)
            if shutil.which("createrepo_c") is not None or shutil.which("createrepo") is not None:
                rpm_repository_metadata = rpm_out / RPM_REPOSITORY_METADATA_FILENAME
                assert_rpm_repository_metadata(
                    rpm_repository_metadata,
                    temp,
                    generator,
                    rpm_out,
                )
                repeated_metadata = generator.build_rpm_repository_metadata(
                    VERSION,
                    tuple(rpm_out / generator.rpm_filename(VERSION, target) for target in RPM_ARCHES),
                )
                if repeated_metadata.content != rpm_repository_metadata.read_bytes():
                    raise AssertionError("RPM repository metadata generation was not deterministic")

        repeat_out = temp / "repeat-out"
        generate(generator, rootless_dist, repeat_out)
        if (rootless_out / CHOCOLATEY_FILENAME).read_bytes() != (repeat_out / CHOCOLATEY_FILENAME).read_bytes():
            raise AssertionError("chocolatey package generation was not deterministic")
        if (rootless_out / DEBIAN_AMD64_FILENAME).read_bytes() != (repeat_out / DEBIAN_AMD64_FILENAME).read_bytes():
            raise AssertionError("Debian amd64 package generation was not deterministic")
        if (rootless_out / DEBIAN_ARM64_FILENAME).read_bytes() != (repeat_out / DEBIAN_ARM64_FILENAME).read_bytes():
            raise AssertionError("Debian arm64 package generation was not deterministic")
        apt_repeat_out = temp / "apt-repeat-out"
        generate(generator, rootless_dist, apt_repeat_out, build_apt_repository_metadata=True)
        if (
            (apt_out / APT_REPOSITORY_METADATA_FILENAME).read_bytes()
            != (apt_repeat_out / APT_REPOSITORY_METADATA_FILENAME).read_bytes()
        ):
            raise AssertionError("APT repository metadata generation was not deterministic")

        rooted_dist = temp / "rooted-dist"
        rooted_out = temp / "rooted-out"
        rooted_dist.mkdir()
        write_dist(rooted_dist, rooted_windows=True, rooted_linux=True)
        generate(generator, rooted_dist, rooted_out)
        rooted_scoop = json.loads((rooted_out / SCOOP_FILENAME).read_text(encoding="ascii"))
        if rooted_scoop.get("extract_dir") != f"conu-{VERSION}-windows-x64":
            raise AssertionError("rooted Windows archive should set extract_dir")
        rooted_winget = (rooted_out / WINGET_FILENAME).read_text(encoding="ascii")
        if f"RelativeFilePath: conu-{VERSION}-windows-x64/bin/conu.exe" not in rooted_winget:
            raise AssertionError("rooted winget manifest did not map rooted conu.exe")
        rooted_chocolatey = read_chocolatey_package(rooted_out / CHOCOLATEY_FILENAME)
        if f"conu-{VERSION}-windows-x64\\bin" not in rooted_chocolatey["tools/chocolateyInstall.ps1"]:
            raise AssertionError("rooted chocolatey script did not use rooted bin path")
        assert_debian_package(
            rooted_out / DEBIAN_AMD64_FILENAME,
            architecture="amd64",
            target="linux-x64",
        )
        assert_rpmbuild_accepts(generator, rooted_out / RPM_SPEC_FILENAME, rooted_dist)

        missing_checksum = temp / "missing-checksum"
        missing_checksum.mkdir()
        write_dist(missing_checksum)
        (missing_checksum / f"{TARGETS['linux-x64']}.sha256").unlink()
        expect_failure(
            "missing checksum",
            lambda: generator.load_release_assets(
                missing_checksum,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "missing checksum file",
        )

        non_ascii_checksum = temp / "non-ascii-checksum"
        non_ascii_checksum.mkdir()
        write_dist(non_ascii_checksum)
        non_ascii_archive = non_ascii_checksum / TARGETS["windows-x64"]
        non_ascii_archive.with_name(f"{non_ascii_archive.name}.sha256").write_bytes(b"\xff\n")
        message = expect_failure(
            "non-ASCII checksum",
            lambda: generator.load_release_assets(
                non_ascii_checksum,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "checksum file is not ASCII",
        )
        assert_not_displayed(message, "non-ASCII checksum", non_ascii_archive.name)

        invalid_checksum = temp / "invalid-checksum"
        invalid_checksum.mkdir()
        write_dist(invalid_checksum)
        invalid_archive = invalid_checksum / TARGETS["windows-x64"]
        invalid_archive.with_name(f"{invalid_archive.name}.sha256").write_text(
            "not a strict checksum\n",
            encoding="ascii",
        )
        message = expect_failure(
            "invalid checksum",
            lambda: generator.load_release_assets(
                invalid_checksum,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "invalid format",
        )
        assert_not_displayed(message, "invalid checksum", invalid_archive.name)

        wrong_name = temp / "wrong-name"
        wrong_name.mkdir()
        write_dist(wrong_name)
        windows_archive = wrong_name / TARGETS["windows-x64"]
        malicious_archive_name = "secret-package-manager-checksum-target.zip"
        write_checksum(windows_archive, archive_name=malicious_archive_name)
        message = expect_failure(
            "checksum names wrong archive",
            lambda: generator.load_release_assets(
                wrong_name,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "names wrong archive",
        )
        assert_not_displayed(
            message,
            "checksum names wrong archive",
            windows_archive.name,
            malicious_archive_name,
        )

        wrong_digest = temp / "wrong-digest"
        wrong_digest.mkdir()
        write_dist(wrong_digest)
        linux_archive = wrong_digest / TARGETS["linux-x64"]
        linux_archive.with_name(f"{linux_archive.name}.sha256").write_text(
            f"{'0' * 64}  {linux_archive.name}\n",
            encoding="ascii",
        )
        message = expect_failure(
            "checksum mismatch",
            lambda: generator.load_release_assets(
                wrong_digest,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "checksum mismatch",
        )
        assert_not_displayed(message, "checksum mismatch", linux_archive.name)

        unreadable_windows = temp / "unreadable-windows"
        unreadable_windows.mkdir()
        write_dist(unreadable_windows)
        unreadable_windows_archive = unreadable_windows / TARGETS["windows-x64"]
        unreadable_windows_archive.write_bytes(b"not a zip archive\n")
        expect_member_redacted_failure(
            "unreadable windows zip",
            lambda: generator.detect_windows_extract_dir(unreadable_windows_archive, VERSION),
            "not a readable zip",
            "not a zip archive",
        )

        corrupt_linux = temp / "corrupt-linux"
        corrupt_linux.mkdir()
        write_dist(corrupt_linux)
        corrupt_archive = corrupt_linux / TARGETS["linux-x64"]
        corrupt_archive.write_bytes(b"\x1f\x8bbad")
        write_checksum(corrupt_archive)
        corrupt_assets = generator.load_release_assets(
            corrupt_linux,
            VERSION,
            "imthegoodboy/conU",
            f"v{VERSION}",
        )
        expect_member_redacted_failure(
            "corrupt linux tarball",
            lambda: generator.extract_linux_binaries(
                corrupt_linux / corrupt_assets["linux-x64"].filename,
                VERSION,
                "linux-x64",
            ),
            "not a readable tar.gz",
            "bad",
        )

        secret_tar_member = "secret-package-manager-binary-should-not-print"

        class BrokenTar:
            def extractfile(self, _member):
                raise tarfile.ReadError(secret_tar_member)

        expect_member_redacted_failure(
            "linux tar binary read error",
            lambda: generator.read_tar_release_member(
                TARGETS["linux-x64"],
                BrokenTar(),
                tarfile.TarInfo(secret_tar_member),
                generator.MAX_PACKAGE_BINARY_BYTES,
            ),
            "could not read binary",
            secret_tar_member,
        )

        encrypted_windows = temp / "encrypted-windows"
        encrypted_windows.mkdir()
        write_dist(encrypted_windows)
        encrypted_archive = encrypted_windows / TARGETS["windows-x64"]
        mark_zip_member_encrypted(encrypted_archive, "bin/conu.exe")
        expect_member_redacted_failure(
            "encrypted windows zip member",
            lambda: generator.detect_windows_extract_dir(encrypted_archive, VERSION),
            "contains encrypted zip member",
            "bin/conu.exe",
        )

        unsupported_windows = temp / "unsupported-windows"
        unsupported_windows.mkdir()
        write_dist(unsupported_windows)
        unsupported_archive = unsupported_windows / TARGETS["windows-x64"]
        with zipfile.ZipFile(unsupported_archive, "a", compression=zipfile.ZIP_STORED) as package:
            info = zipfile.ZipInfo("device")
            info.external_attr = stat.S_IFCHR << 16
            package.writestr(info, b"device\n")
        expect_member_redacted_failure(
            "unsupported windows zip member",
            lambda: generator.detect_windows_extract_dir(unsupported_archive, VERSION),
            "contains unsupported zip member",
            "device",
        )

        duplicate_windows = temp / "duplicate-windows"
        duplicate_windows.mkdir()
        write_dist(duplicate_windows)
        duplicate_archive = duplicate_windows / TARGETS["windows-x64"]
        with zipfile.ZipFile(duplicate_archive, "a", compression=zipfile.ZIP_STORED) as package:
            package.writestr("bin/./conu.exe", b"duplicate\n")
        expect_member_redacted_failure(
            "duplicate windows zip member",
            lambda: generator.detect_windows_extract_dir(duplicate_archive, VERSION),
            "contains duplicate archive path",
            "bin/./conu.exe",
            "bin/conu.exe",
        )

        drive_windows = temp / "drive-windows"
        drive_windows.mkdir()
        write_dist(drive_windows)
        drive_archive = drive_windows / TARGETS["windows-x64"]
        drive_member = "C:\\secret-package-manager-path"
        with zipfile.ZipFile(drive_archive, "a", compression=zipfile.ZIP_STORED) as package:
            package.writestr(drive_member, b"drive\n")
        expect_member_redacted_failure(
            "Windows drive zip member",
            lambda: generator.detect_windows_extract_dir(drive_archive, VERSION),
            "unsafe archive path",
            drive_member,
            "C:/secret-package-manager-path",
            "secret-package-manager-path",
        )

        mixed_windows = temp / "mixed-windows"
        mixed_windows.mkdir()
        write_dist(mixed_windows)
        mixed_archive = mixed_windows / TARGETS["windows-x64"]
        with zipfile.ZipFile(mixed_archive, "a", compression=zipfile.ZIP_STORED) as package:
            package.writestr(f"conu-{VERSION}-windows-x64/README.md", "# conU\n")
        expect_member_redacted_failure(
            "mixed rooted windows archive",
            lambda: generator.detect_windows_extract_dir(mixed_archive, VERSION),
            "mixes rooted and rootless archive paths",
            f"conu-{VERSION}-windows-x64/README.md",
        )

        expect_member_redacted_failure_with_limit(
            generator,
            "MAX_RELEASE_MEMBER_BYTES",
            1,
            "linux archive member size bound",
            lambda: generator.extract_linux_binaries(
                rootless_dist / TARGETS["linux-x64"],
                VERSION,
                "linux-x64",
            ),
            "member is too large",
            "bin/conu",
        )

        expect_member_redacted_failure_with_limit(
            generator,
            "MAX_RELEASE_TOTAL_UNCOMPRESSED_BYTES",
            1,
            "linux archive total uncompressed bound",
            lambda: generator.extract_linux_binaries(
                rootless_dist / TARGETS["linux-x64"],
                VERSION,
                "linux-x64",
            ),
            "uncompressed contents exceed 1 bytes",
        )

        unsupported_linux = temp / "unsupported-linux"
        unsupported_linux.mkdir()
        unsupported_linux_archive = unsupported_linux / TARGETS["linux-x64"]
        with tarfile.open(unsupported_linux_archive, "w:gz") as package:
            for binary in LINUX_BINARIES:
                data = f"{binary}-linux-x64\n".encode("ascii")
                info = tarfile.TarInfo(f"bin/{binary}")
                info.size = len(data)
                info.mode = 0o755
                info.mtime = 1577836800
                package.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("bin/linked-conu")
            link.type = tarfile.SYMTYPE
            link.linkname = "bin/conu"
            link.mtime = 1577836800
            package.addfile(link)
        expect_member_redacted_failure(
            "unsupported linux tar member",
            lambda: generator.extract_linux_binaries(
                unsupported_linux_archive,
                VERSION,
                "linux-x64",
            ),
            "contains unsupported non-file member",
            "bin/linked-conu",
        )

        mixed_linux = temp / "mixed-linux"
        mixed_linux.mkdir()
        mixed_linux_archive = mixed_linux / TARGETS["linux-x64"]
        with tarfile.open(mixed_linux_archive, "w:gz") as package:
            for binary in LINUX_BINARIES:
                data = f"{binary}-linux-x64\n".encode("ascii")
                info = tarfile.TarInfo(f"bin/{binary}")
                info.size = len(data)
                info.mode = 0o755
                info.mtime = 1577836800
                package.addfile(info, io.BytesIO(data))
            rooted_data = b"# conU\n"
            rooted_info = tarfile.TarInfo(f"conu-{VERSION}-linux-x64/README.md")
            rooted_info.size = len(rooted_data)
            rooted_info.mode = 0o644
            rooted_info.mtime = 1577836800
            package.addfile(rooted_info, io.BytesIO(rooted_data))
        expect_member_redacted_failure(
            "mixed rooted linux archive",
            lambda: generator.extract_linux_binaries(
                mixed_linux_archive,
                VERSION,
                "linux-x64",
            ),
            "mixes rooted and rootless archive paths",
            f"conu-{VERSION}-linux-x64/README.md",
        )

    print("package-manager manifest generation regressions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
