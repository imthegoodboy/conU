#!/usr/bin/env python3
"""Regression checks for package-manager manifest generation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
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
HOMEBREW_FILENAME = "conu.rb"
SCOOP_FILENAME = "conu.json"
WINGET_FILENAME = "imthegoodboy.conU.yaml"
CHOCOLATEY_FILENAME = f"conu.{VERSION}.nupkg"


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


def write_windows_zip(path: Path, *, rooted: bool) -> str:
    root = f"conu-{VERSION}-windows-x64/" if rooted else ""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for binary in WINDOWS_BINARIES:
            package.writestr(f"{root}bin/{binary}.exe", f"{binary}\n")
    return write_checksum(path)


def write_dist(root: Path, *, rooted_windows: bool = False) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for target, filename in TARGETS.items():
        archive = root / filename
        if target == "windows-x64":
            hashes[target] = write_windows_zip(archive, rooted=rooted_windows)
        else:
            archive.write_bytes(f"{target}\n".encode("ascii"))
            hashes[target] = write_checksum(archive)
    return hashes


def generate(generator, dist: Path, output: Path) -> None:
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
    generator.assert_output_safe(
        "\n".join(
            [
                homebrew,
                scoop,
                winget,
                chocolatey_nuspec,
                chocolatey_install,
                chocolatey_uninstall,
            ]
        ),
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

        repeat_out = temp / "repeat-out"
        generate(generator, rootless_dist, repeat_out)
        if (rootless_out / CHOCOLATEY_FILENAME).read_bytes() != (repeat_out / CHOCOLATEY_FILENAME).read_bytes():
            raise AssertionError("chocolatey package generation was not deterministic")

        rooted_dist = temp / "rooted-dist"
        rooted_out = temp / "rooted-out"
        rooted_dist.mkdir()
        write_dist(rooted_dist, rooted_windows=True)
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

    print("package-manager manifest generation regressions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
