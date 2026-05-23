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
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_CHECKSUM_BYTES = 4096
HASH_CHUNK_BYTES = 1024 * 1024
EXPECTED_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
OUTPUT_FILENAMES = ("conu.rb", "conu.json")


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
    tag = args.tag or f"v{version}"
    output_dir = args.output_dir.resolve()

    assets = load_release_assets(dist, version, repo, tag)
    windows_extract_dir = detect_windows_extract_dir(dist / assets["windows-x64"].filename, version)

    output_dir.mkdir(parents=True, exist_ok=True)
    homebrew = render_homebrew_formula(version, repo, assets)
    scoop = render_scoop_manifest(version, repo, assets["windows-x64"], windows_extract_dir)
    assert_output_safe(homebrew + "\n" + scoop, dist)

    (output_dir / "conu.rb").write_text(homebrew, encoding="ascii", newline="\n")
    (output_dir / "conu.json").write_text(scoop, encoding="ascii", newline="\n")
    print(
        "generated package-manager manifests: "
        + ", ".join(str(output_dir / name) for name in OUTPUT_FILENAMES)
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release archives")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory for generated conu.rb and conu.json",
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


def expected_filenames(version: str) -> dict[str, str]:
    return {
        "macos-arm64": f"conu-{version}-macos-arm64.zip",
        "macos-x64": f"conu-{version}-macos-x64.zip",
        "linux-arm64": f"conu-{version}-linux-arm64.tar.gz",
        "linux-x64": f"conu-{version}-linux-x64.tar.gz",
        "windows-x64": f"conu-{version}-windows-x64.zip",
    }


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


def assert_output_safe(text: str, dist: Path) -> None:
    forbidden_literals = [
        "NPM_TOKEN",
        "CONU_RELAY_TOKEN",
        "CONU_WINDOWS_SIGN_CERT",
        "CONU_MACOS_DEVELOPER_ID",
        "BEGIN PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "payload_ciphertext",
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
