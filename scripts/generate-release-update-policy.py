#!/usr/bin/env python3
"""Generate payload-safe conU release update policy metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlunparse


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_TEXT_ASSET_BYTES = 1024 * 1024
MAX_SOURCE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 10 * 1024 * 1024 * 1024
UPDATE_POLICY_SCHEMA = "conu.releaseUpdatePolicy.v1"
NPM_REGISTRY = "https://registry.npmjs.org"
PLATFORM_ARCHIVES = {
    "windows-x64": "zip",
    "macos-x64": "zip",
    "macos-arm64": "zip",
    "linux-x64": "tar.gz",
    "linux-arm64": "tar.gz",
}
DEBIAN_ARCHES = {
    "linux-x64": "amd64",
    "linux-arm64": "arm64",
}
RPM_ARCHES = {
    "linux-x64": "x86_64",
    "linux-arm64": "aarch64",
}
STATIC_PACKAGE_MANAGER_ASSETS = (
    ("homebrew-formula", "conu.rb"),
    ("scoop-manifest", "conu.json"),
    ("winget-manifest", "imthegoodboy.conU.yaml"),
    ("rpm-spec", "conu.spec"),
)
FORBIDDEN_TEXT = (
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PRIVATE KEY",
    "NPM_TOKEN",
    "CONU_RELAY_TOKEN",
    "token_sha256_hex",
    "payloadHex",
    "ciphertext_body",
    "do-not-print-this-secret-value",
)


@dataclass(frozen=True)
class ReleaseAsset:
    kind: str
    filename: str
    sha256: str
    url: str
    target: str | None = None
    package_manager: str | None = None
    sha256_url: str | None = None
    signature_url: str | None = None

    def as_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind,
            "filename": self.filename,
            "sha256": self.sha256,
            "url": self.url,
        }
        if self.target is not None:
            data["target"] = self.target
        if self.package_manager is not None:
            data["packageManager"] = self.package_manager
        if self.sha256_url is not None:
            data["sha256Url"] = self.sha256_url
        if self.signature_url is not None:
            data["signatureUrl"] = self.signature_url
        return data


@dataclass
class SourceBudget:
    total_bytes: int = 0

    def add(self, size: int) -> None:
        self.total_bytes += size
        if self.total_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise SystemExit(
                "release update policy source inputs exceed "
                f"{MAX_TOTAL_SOURCE_BYTES} bytes"
            )


def main() -> int:
    args = parse_args()
    version = validate_version(args.version or read_package_version("packaging/npm/conu-cli/package.json"))
    verify_package_versions(version)
    tag = validate_tag(args.tag or f"v{version}", version)
    repo = validate_repo(args.repo)
    channel = validate_channel(args.channel or infer_channel(version))
    release_base_url = validate_release_base_url(args.release_base_url, repo, tag)
    dist = args.dist.resolve()
    output_dir = args.output_dir.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")
    output_dir.mkdir(parents=True, exist_ok=True)

    policy = build_update_policy(
        dist=dist,
        version=version,
        tag=tag,
        repo=repo,
        channel=channel,
        release_base_url=release_base_url,
    )
    text = json.dumps(policy, indent=2, sort_keys=True) + "\n"
    assert_output_safe(text)
    output = output_dir / update_policy_filename(version)
    output.write_text(text, encoding="ascii", newline="\n")
    write_sha256_sidecar(output)
    print(f"generated release update policy: {output.name}, {output.name}.sha256")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing release assets")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory receiving the update policy JSON",
    )
    parser.add_argument("--version", help="release version; defaults to @conu/cli version")
    parser.add_argument("--tag", help="release tag; defaults to v<version>")
    parser.add_argument("--repo", default="imthegoodboy/conU", help="GitHub repository owner/name")
    parser.add_argument(
        "--release-base-url",
        default=os.environ.get("CONU_RELEASE_BASE_URL", ""),
        help="HTTPS base URL where GitHub Release assets are downloaded",
    )
    parser.add_argument(
        "--channel",
        choices=("stable", "prerelease"),
        help="release update channel; defaults to prerelease for semver prereleases",
    )
    return parser.parse_args()


def read_package_version(relative_path: str) -> str:
    path = Path(__file__).resolve().parents[1] / relative_path
    with path.open("r", encoding="utf-8") as handle:
        package = json.load(handle)
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{path} does not contain a non-empty version")
    return version


def verify_package_versions(version: str) -> None:
    packages = {
        "packaging/npm/conu-cli/package.json": "@conu/cli",
        "sdk/typescript/package.json": "@conu/sdk",
    }
    for relative, label in packages.items():
        actual = read_package_version(relative)
        if actual != version:
            raise SystemExit(f"{label} version is {actual}, expected {version}")


def validate_version(version: str) -> str:
    if not SEMVER_RE.fullmatch(version):
        raise SystemExit(f"invalid release version for update policy: {version}")
    return version


def validate_tag(tag: str, version: str) -> str:
    raw = tag.strip()
    if not TAG_RE.fullmatch(raw):
        raise SystemExit(f"invalid release tag for update policy: {tag}")
    if raw != f"v{version}":
        raise SystemExit(f"release tag {raw} does not match version {version}")
    return raw


def validate_repo(repo: str) -> str:
    if not REPO_RE.fullmatch(repo):
        raise SystemExit(f"invalid GitHub repository owner/name: {repo}")
    return repo


def infer_channel(version: str) -> str:
    return "prerelease" if "-" in version else "stable"


def validate_channel(channel: str) -> str:
    if channel not in {"stable", "prerelease"}:
        raise SystemExit(f"invalid update channel: {channel}")
    return channel


def validate_release_base_url(raw: str, repo: str, tag: str) -> str:
    candidate = raw.strip()
    if not candidate:
        owner_repo = repo.split("/", 1)
        candidate = (
            f"https://github.com/{quote(owner_repo[0], safe='')}/"
            f"{quote(owner_repo[1], safe='')}/releases/download/{quote(tag, safe='')}"
        )
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("release update policy base URL must be an absolute https URL")
    if parsed.username or parsed.password:
        raise SystemExit("release update policy base URL must not include credentials")
    if parsed.params or parsed.query or parsed.fragment:
        raise SystemExit("release update policy base URL must not include params, query, or fragment")
    normalized_path = "/" + "/".join(part for part in parsed.path.split("/") if part)
    if normalized_path == "/":
        normalized_path = ""
    return urlunparse(("https", parsed.netloc, normalized_path, "", "", ""))


def build_update_policy(
    *,
    dist: Path,
    version: str,
    tag: str,
    repo: str,
    channel: str,
    release_base_url: str,
) -> dict[str, Any]:
    source_budget = SourceBudget()
    platform_archives = collect_platform_archives(dist, version, release_base_url, source_budget)
    package_manager_assets = collect_package_manager_assets(
        dist, version, release_base_url, source_budget
    )
    linux_package_assets = collect_linux_package_assets(
        dist, version, release_base_url, source_budget
    )
    repository_assets = collect_repository_assets(dist, version, release_base_url, source_budget)
    policy_name = update_policy_filename(version)

    return {
        "schema": UPDATE_POLICY_SCHEMA,
        "product": "conU",
        "sourceRepository": f"https://github.com/{repo}",
        "releaseBaseUrl": release_base_url,
        "releaseTag": tag,
        "version": version,
        "channel": channel,
        "policyAsset": {
            "filename": policy_name,
            "url": asset_url(release_base_url, policy_name),
            "sha256Url": asset_url(release_base_url, f"{policy_name}.sha256"),
            "signatureUrl": asset_url(release_base_url, f"{policy_name}.asc"),
            "cacheControl": "no-cache",
        },
        "apply": {
            "autoApply": False,
            "manualVerificationRequired": True,
            "downgradeAllowed": False,
            "operatorConsentRequired": True,
        },
        "verification": {
            "strictSha256SidecarsRequired": True,
            "linuxDetachedSignaturesRequired": True,
            "policyDetachedSignatureRequired": True,
            "githubArtifactAttestationsExpectedForPlatformArchives": True,
        },
        "platformArchives": [asset.as_json() for asset in platform_archives],
        "packageManagerAssets": [asset.as_json() for asset in package_manager_assets],
        "linuxPackageAssets": [asset.as_json() for asset in linux_package_assets],
        "repositoryAssets": [asset.as_json() for asset in repository_assets],
        "npm": {
            "registry": NPM_REGISTRY,
            "packages": [
                {"name": "@conu/cli", "version": version},
                {"name": "@conu/sdk", "version": version},
            ],
        },
        "payloadDisplayed": False,
        "tokenDisplayed": False,
        "keyMaterialDisplayed": False,
        "ciphertextDisplayed": False,
        "contentsDisplayed": False,
    }


def collect_platform_archives(
    dist: Path,
    version: str,
    release_base_url: str,
    source_budget: SourceBudget,
) -> tuple[ReleaseAsset, ...]:
    assets: list[ReleaseAsset] = []
    for target, extension in PLATFORM_ARCHIVES.items():
        filename = f"conu-{version}-{target}.{extension}"
        signature = target.startswith("linux-")
        assets.append(
            release_asset(
                dist,
                filename,
                kind="platform-archive",
                release_base_url=release_base_url,
                target=target,
                require_sidecar=True,
                require_signature=signature,
                source_budget=source_budget,
            )
        )
    return tuple(assets)


def collect_package_manager_assets(
    dist: Path,
    version: str,
    release_base_url: str,
    source_budget: SourceBudget,
) -> tuple[ReleaseAsset, ...]:
    assets = [
        release_asset(
            dist,
            filename,
            kind="package-manager",
            release_base_url=release_base_url,
            package_manager=package_manager,
            require_sidecar=False,
            require_signature=False,
            source_budget=source_budget,
        )
        for package_manager, filename in STATIC_PACKAGE_MANAGER_ASSETS
    ]
    assets.append(
        release_asset(
            dist,
            f"conu.{version}.nupkg",
            kind="package-manager",
            release_base_url=release_base_url,
            package_manager="chocolatey",
            require_sidecar=False,
            require_signature=False,
            source_budget=source_budget,
        )
    )
    return tuple(assets)


def collect_linux_package_assets(
    dist: Path,
    version: str,
    release_base_url: str,
    source_budget: SourceBudget,
) -> tuple[ReleaseAsset, ...]:
    assets: list[ReleaseAsset] = []
    deb_version = debian_version(version)
    for target, arch in DEBIAN_ARCHES.items():
        assets.append(
            release_asset(
                dist,
                f"conu_{deb_version}_{arch}.deb",
                kind="debian-package",
                release_base_url=release_base_url,
                target=target,
                require_sidecar=True,
                require_signature=True,
                source_budget=source_budget,
            )
        )
    rpm_ver = rpm_version(version)
    for target, arch in RPM_ARCHES.items():
        assets.append(
            release_asset(
                dist,
                f"conu-{rpm_ver}-1.{arch}.rpm",
                kind="rpm-package",
                release_base_url=release_base_url,
                target=target,
                require_sidecar=True,
                require_signature=True,
                source_budget=source_budget,
            )
        )
    return tuple(assets)


def collect_repository_assets(
    dist: Path,
    version: str,
    release_base_url: str,
    source_budget: SourceBudget,
) -> tuple[ReleaseAsset, ...]:
    deb_version = debian_version(version)
    rpm_ver = rpm_version(version)
    names = (
        ("apt-repository-metadata", f"conu-{deb_version}-apt-repository-metadata.zip", True, True),
        ("rpm-repository-metadata", f"conu-{rpm_ver}-rpm-repository-metadata.zip", True, True),
        ("linux-gpg-public-key", "conu-linux-gpg-key.asc", True, False),
        ("hosted-linux-repository-bundle", f"conu-{version}-hosted-linux-repositories.zip", True, True),
        ("hosted-linux-repository-site", f"conu-{version}-hosted-linux-repository-site.zip", True, True),
    )
    return tuple(
        release_asset(
            dist,
            filename,
            kind=kind,
            release_base_url=release_base_url,
            require_sidecar=require_sidecar,
            require_signature=require_signature,
            source_budget=source_budget,
        )
        for kind, filename, require_sidecar, require_signature in names
    )


def release_asset(
    dist: Path,
    filename: str,
    *,
    kind: str,
    release_base_url: str,
    target: str | None = None,
    package_manager: str | None = None,
    require_sidecar: bool,
    require_signature: bool,
    source_budget: SourceBudget,
) -> ReleaseAsset:
    path = dist / filename
    validate_source_file(
        path,
        f"release update policy asset {filename}",
        MAX_TEXT_ASSET_BYTES if is_text_asset(filename) else MAX_SOURCE_ASSET_BYTES,
        source_budget,
    )
    if is_text_asset(filename):
        assert_file_text_safe(path)
    sha256 = (
        verify_sha256_sidecar(path, kind, source_budget)
        if require_sidecar
        else sha256_file(path)
    )
    signature_url = None
    if require_signature:
        require_detached_signature(path, source_budget)
        signature_url = asset_url(release_base_url, f"{filename}.asc")
    return ReleaseAsset(
        kind=kind,
        target=target,
        package_manager=package_manager,
        filename=filename,
        sha256=sha256,
        url=asset_url(release_base_url, filename),
        sha256_url=asset_url(release_base_url, f"{filename}.sha256") if require_sidecar else None,
        signature_url=signature_url,
    )


def verify_sha256_sidecar(path: Path, label: str, source_budget: SourceBudget) -> str:
    sidecar = path.with_name(f"{path.name}.sha256")
    validate_source_file(
        sidecar,
        f"SHA-256 sidecar for {label} {path.name}",
        MAX_CHECKSUM_BYTES,
        source_budget,
    )
    try:
        checksum_text = sidecar.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}: {path.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}: {path.name}")
    if match.group(2) != path.name:
        raise SystemExit(
            f"SHA-256 sidecar for {label} {path.name} names wrong file: {match.group(2)}"
        )
    expected = match.group(1).lower()
    actual = sha256_file(path)
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")
    return expected


def require_detached_signature(path: Path, source_budget: SourceBudget) -> None:
    signature = path.with_name(f"{path.name}.asc")
    validate_source_file(
        signature,
        f"detached signature for release update policy asset {path.name}",
        MAX_SIGNATURE_BYTES,
        source_budget,
    )
    try:
        signature_text = signature.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")


def asset_url(release_base_url: str, filename: str) -> str:
    return f"{release_base_url.rstrip('/')}/{quote(filename, safe='')}"


def update_policy_filename(version: str) -> str:
    return f"conu-{version}-update-policy.json"


def debian_version(version: str) -> str:
    return version.replace("-", "~")


def rpm_version(version: str) -> str:
    return version.replace("-", "~").replace("+", "_")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def validate_source_file(
    path: Path,
    label: str,
    max_bytes: int,
    source_budget: SourceBudget | None = None,
) -> int:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise SystemExit(f"missing {label}: {path.name}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file: {path.name}")
    size = metadata.st_size
    if size > max_bytes:
        raise SystemExit(f"{label} is too large: {path.name} exceeds {max_bytes} bytes")
    if source_budget is not None:
        source_budget.add(size)
    return size


def write_sha256_sidecar(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def assert_output_safe(text: str) -> None:
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SystemExit("release update policy must be ASCII JSON") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"release update policy contains forbidden text: {forbidden}")
    if "\\" in text:
        raise SystemExit("release update policy must not contain local path separators")


def is_text_asset(filename: str) -> bool:
    return filename.endswith((".rb", ".json", ".yaml", ".yml", ".spec", ".asc"))


def assert_file_text_safe(path: Path) -> None:
    validate_source_file(path, f"text release update policy asset {path.name}", MAX_TEXT_ASSET_BYTES)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{path.name} is not UTF-8 text") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{path.name} contains forbidden text: {forbidden}")


if __name__ == "__main__":
    sys.exit(main())
