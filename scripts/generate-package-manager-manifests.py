#!/usr/bin/env python3
"""Generate package-manager manifests from verified conU release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_CHECKSUM_BYTES = 4096
HASH_CHUNK_BYTES = 1024 * 1024
EXPECTED_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
STATIC_OUTPUT_FILENAMES = (
    "conu.rb",
    "conu.json",
    "imthegoodboy.conU.yaml",
)
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class ReleaseAsset:
    target: str
    filename: str
    sha256: str
    url: str


def main() -> int:
    args = parse_args()
    dist = args.dist.resolve()
    version = args.version or read_repo_version()
    validate_version(version)
    repo = validate_repo(args.repo)
    tag = validate_tag(args.tag or f"v{version}")
    output_dir = args.output_dir.resolve()

    assets = load_release_assets(dist, version, repo, tag)
    windows_extract_dir = detect_windows_extract_dir(dist / assets["windows-x64"].filename, version)

    output_dir.mkdir(parents=True, exist_ok=True)
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
    assert_output_safe(
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

    (output_dir / "conu.rb").write_text(homebrew, encoding="ascii", newline="\n")
    (output_dir / "conu.json").write_text(scoop, encoding="ascii", newline="\n")
    (output_dir / "imthegoodboy.conU.yaml").write_text(winget, encoding="ascii", newline="\n")
    write_chocolatey_package(
        output_dir / chocolatey_filename(version),
        chocolatey_nuspec,
        chocolatey_install,
        chocolatey_uninstall,
    )
    print(
        "generated package-manager manifests: "
        + ", ".join(str(output_dir / name) for name in output_filenames(version))
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


def output_filenames(version: str) -> tuple[str, ...]:
    return (*STATIC_OUTPUT_FILENAMES, chocolatey_filename(version))


def load_release_assets(
    dist: Path,
    version: str,
    repo: str,
    tag: str,
) -> dict[str, ReleaseAsset]:
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")

    assets: dict[str, ReleaseAsset] = {}
    for target, filename in expected_filenames(version).items():
        archive = dist / filename
        if not archive.exists() or not archive.is_file():
            raise SystemExit(f"missing required release asset for {target}: {filename}")
        sha256 = read_verified_checksum(archive)
        url = f"https://github.com/{repo}/releases/download/{tag}/{filename}"
        assets[target] = ReleaseAsset(
            target=target,
            filename=filename,
            sha256=sha256,
            url=url,
        )
    return assets


def read_verified_checksum(archive: Path) -> str:
    checksum_path = archive.with_name(f"{archive.name}.sha256")
    if not checksum_path.exists() or not checksum_path.is_file():
        raise SystemExit(f"missing checksum file for package-manager asset: {archive.name}")
    if checksum_path.stat().st_size > MAX_CHECKSUM_BYTES:
        raise SystemExit(f"checksum file is too large for package-manager asset: {archive.name}")
    try:
        checksum_text = checksum_path.read_text(encoding="ascii")
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
    actual = sha256_file(archive)
    if expected != actual:
        raise SystemExit(f"checksum mismatch for package-manager asset: {archive.name}")
    return expected


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def detect_windows_extract_dir(archive: Path, version: str) -> str | None:
    root = f"conu-{version}-windows-x64"
    root_prefix = f"{root}/"
    rootless_bins = {f"bin/{binary}.exe" for binary in EXPECTED_BINARIES}
    rooted_bins = {f"{root_prefix}bin/{binary}.exe" for binary in EXPECTED_BINARIES}

    try:
        with zipfile.ZipFile(archive) as package:
            paths = {
                normalize_zip_path(member.filename)
                for member in package.infolist()
                if not member.is_dir()
            }
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"windows release asset is not a readable zip: {archive.name}") from exc

    if rootless_bins <= paths:
        return None
    if rooted_bins <= paths:
        return root
    raise SystemExit(
        f"{archive.name} does not contain expected rootless or {root}/bin Windows binaries"
    )


def normalize_zip_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe zip path in package-manager asset: {raw_name}")
    return "/".join(parts)


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
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as package:
        write_deterministic_zip_text(package, "conu.nuspec", nuspec)
        write_deterministic_zip_text(package, "tools/chocolateyInstall.ps1", install_script)
        write_deterministic_zip_text(
            package,
            "tools/chocolateyUninstall.ps1",
            uninstall_script,
        )


def write_deterministic_zip_text(package: zipfile.ZipFile, name: str, text: str) -> None:
    info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    package.writestr(info, text.encode("ascii"))


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
