#!/usr/bin/env python3
"""Regression checks for package-manager manifest generation."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


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
RPM_ARCHES = {
    "linux-x64": "x86_64",
    "linux-arm64": "aarch64",
}
RPM_X64_FILENAME = f"conu-{VERSION}-1.x86_64.rpm"
RPM_ARM64_FILENAME = f"conu-{VERSION}-1.aarch64.rpm"


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
    if build_rpm_packages:
        generator.build_rpm_packages(VERSION, dist, rpm_spec_path, output)


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
        "BEGIN PRIVATE KEY",
    ]
    normalized = text.replace("\\", "/")
    for literal in forbidden:
        if literal and literal in normalized:
            raise AssertionError(f"{label} contained forbidden literal {literal!r}")


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
                    f"rpmbuild failed for {target} with output:\n{exc.stdout}"
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
    if "This bundle is unsigned" not in readme_text or DEBIAN_AMD64_FILENAME not in readme_text:
        raise AssertionError(f"{path.name} README missed unsigned publication guidance")
    for label, text in (
        ("README.txt", readme_text),
        ("Packages", packages_text),
        ("Release", release_text),
    ):
        assert_no_forbidden_text(text, f"{path.name}:{label}", temp)
    assert_sha256_sidecar(path)


def assert_zip_no_forbidden_output(path: Path, temp: Path) -> None:
    for name, text in read_chocolatey_package(path).items():
        assert_no_forbidden_text(text, f"{path.name}:{name}", temp)


def main() -> int:
    generator = load_generator()
    if generator.validate_version("1.2.3-rc.1+build.5") != "1.2.3-rc.1+build.5":
        raise AssertionError("package-manager generator rejected semver prerelease plus build metadata")
    if generator.validate_tag("v1.2.3-rc.1+build.5") != "v1.2.3-rc.1+build.5":
        raise AssertionError("package-manager generator rejected semver release tag")
    with tempfile.TemporaryDirectory(prefix="conu-package-manifest-") as temp_text:
        temp = Path(temp_text)

        rootless_dist = temp / "rootless-dist"
        rootless_out = temp / "rootless-out"
        rootless_dist.mkdir()
        hashes = write_dist(rootless_dist, rooted_windows=False)
        generate(generator, rootless_dist, rootless_out)

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
            generate(generator, rootless_dist, rpm_out, build_rpm_packages=True)
            assert_generated_rpm_assets(generator, rpm_out)

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

        wrong_name = temp / "wrong-name"
        wrong_name.mkdir()
        write_dist(wrong_name)
        windows_archive = wrong_name / TARGETS["windows-x64"]
        write_checksum(windows_archive, archive_name="other.zip")
        expect_failure(
            "checksum names wrong archive",
            lambda: generator.load_release_assets(
                wrong_name,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "names wrong archive",
        )

        wrong_digest = temp / "wrong-digest"
        wrong_digest.mkdir()
        write_dist(wrong_digest)
        linux_archive = wrong_digest / TARGETS["linux-x64"]
        linux_archive.with_name(f"{linux_archive.name}.sha256").write_text(
            f"{'0' * 64}  {linux_archive.name}\n",
            encoding="ascii",
        )
        expect_failure(
            "checksum mismatch",
            lambda: generator.load_release_assets(
                wrong_digest,
                VERSION,
                "imthegoodboy/conU",
                f"v{VERSION}",
            ),
            "checksum mismatch",
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
        expect_failure(
            "corrupt linux tarball",
            lambda: generator.extract_linux_binaries(
                corrupt_linux / corrupt_assets["linux-x64"].filename,
                VERSION,
                "linux-x64",
            ),
            "linux release asset is not a readable tar.gz",
        )

    print("package-manager manifest generation regressions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
