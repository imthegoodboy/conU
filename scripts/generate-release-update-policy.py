#!/usr/bin/env python3
"""Generate payload-safe conU release update policy metadata."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import quote, unquote, urlparse, urlunparse

from github_release_secrets import normalize_repo
from json_safety import load_json_object
from public_host_validation import validate_public_host


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_TEXT_ASSET_BYTES = 1024 * 1024
MAX_SOURCE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 10 * 1024 * 1024 * 1024
UPDATE_POLICY_SCHEMA = "conu.releaseUpdatePolicy.v1"
NPM_REGISTRY = "https://registry.npmjs.org"
OPEN_BINARY = getattr(os, "O_BINARY", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
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
TEXT_FAILURE_GUARDS = (
    "contentsDisplayed=false tokenDisplayed=false keyMaterialDisplayed=false"
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
    dist = validate_input_directory(args.dist, "release dist directory")
    output_dir = args.output_dir.expanduser()
    prepare_output_directory(output_dir)
    output_dir = output_dir.resolve()

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
    write_text_output(output, "release update policy", text, max_bytes=MAX_TEXT_ASSET_BYTES)
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
    parser.add_argument("--version", help="release version; defaults to conu package version")
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
    package = load_json_object(path, encoding="utf-8")
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{path} does not contain a non-empty version")
    return version


def verify_package_versions(version: str) -> None:
    packages = {
        "packaging/npm/conu-cli/package.json": "conu",
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
    try:
        return normalize_repo(repo)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


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
    netloc = normalize_url_netloc(parsed, "release update policy base URL")
    validate_public_host(
        parsed.hostname or "",
        "release update policy base URL",
        error_factory=SystemExit,
    )
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise SystemExit("release update policy base URL path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise SystemExit("release update policy base URL path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise SystemExit("release update policy base URL path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise SystemExit(
            "release update policy base URL path must not contain whitespace or control characters"
        )
    normalized_path = "/" + "/".join(parts) if parts else ""
    return urlunparse(("https", netloc, normalized_path, "", "", ""))


def normalize_url_netloc(parsed, label: str) -> str:
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"{label} authority is invalid") from exc
    if not host:
        raise SystemExit(f"{label} authority must include a host")
    if port is None and parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
        raise SystemExit(f"{label} authority is invalid")
    raw_authority = parsed.netloc.rsplit("@", 1)[-1]
    if has_url_authority_control(raw_authority) or has_url_authority_control(host):
        raise SystemExit(f"{label} authority is invalid")
    host = host.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is None:
        return host
    return f"{host}:{port}"


def has_url_authority_control(value: str) -> bool:
    return any(ord(char) <= 32 or ord(char) == 127 or char in {"\\", "%"} for char in value)


def has_url_path_control(value: str) -> bool:
    return any(ord(char) <= 32 or ord(char) == 127 for char in value)


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
                {"name": "conu", "version": version},
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
    label = f"release update policy {kind} asset"
    max_bytes = MAX_TEXT_ASSET_BYTES if is_text_asset(filename) else MAX_SOURCE_ASSET_BYTES
    asset_file, _size = open_source_file(
        path,
        label,
        max_bytes=max_bytes,
        source_budget=source_budget,
    )
    with asset_file:
        if is_text_asset(filename):
            assert_open_file_text_safe(asset_file, filename, label, max_bytes=max_bytes)
        actual_sha256 = sha256_open_file(asset_file, label, max_bytes=max_bytes)
    sha256 = (
        verify_sha256_sidecar(path, kind, source_budget, actual_sha256)
        if require_sidecar
        else actual_sha256
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


def verify_sha256_sidecar(
    path: Path,
    label: str,
    source_budget: SourceBudget,
    actual: str,
) -> str:
    sidecar = path.with_name(f"{path.name}.sha256")
    try:
        checksum_text = read_text_file(
            sidecar,
            f"SHA-256 sidecar for release update policy {label}",
            max_bytes=MAX_CHECKSUM_BYTES,
            source_budget=source_budget,
            encoding="ascii",
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}")
    if match.group(2) != path.name:
        raise SystemExit(
            f"SHA-256 sidecar for {label} names wrong file; "
            "checksumTargetDisplayed=false contentsDisplayed=false"
        )
    expected = match.group(1).lower()
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}")
    return expected


def require_detached_signature(path: Path, source_budget: SourceBudget) -> None:
    signature = path.with_name(f"{path.name}.asc")
    try:
        signature_text = read_text_file(
            signature,
            "detached signature for release update policy asset",
            max_bytes=MAX_SIGNATURE_BYTES,
            source_budget=source_budget,
            encoding="ascii",
        )
    except UnicodeDecodeError as exc:
        raise SystemExit("detached signature is not ASCII-armored") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit("detached signature is not ASCII-armored")
    if "PRIVATE KEY BLOCK" in signature_text:
        raise SystemExit("detached signature contains private key material")


def asset_url(release_base_url: str, filename: str) -> str:
    return f"{release_base_url.rstrip('/')}/{quote(filename, safe='')}"


def update_policy_filename(version: str) -> str:
    return f"conu-{version}-update-policy.json"


def debian_version(version: str) -> str:
    return version.replace("-", "~")


def rpm_version(version: str) -> str:
    return version.replace("-", "~").replace("+", "_")


def sha256_file(
    path: Path,
    label: str = "release update policy file",
    *,
    max_bytes: int = MAX_SOURCE_ASSET_BYTES,
) -> str:
    handle, _size = open_regular_file(path, label, max_bytes=max_bytes)
    with handle:
        return sha256_open_file(handle, label, max_bytes=max_bytes)


def sha256_open_file(handle: BinaryIO, label: str, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    total = 0
    while True:
        chunk = handle.read(HASH_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
        digest.update(chunk)
    validate_open_regular_file(handle, label, max_bytes=max_bytes)
    return digest.hexdigest()


def validate_source_file(
    path: Path,
    label: str,
    max_bytes: int,
    source_budget: SourceBudget | None = None,
) -> int:
    handle, size = open_source_file(
        path,
        label,
        max_bytes=max_bytes,
        source_budget=source_budget,
    )
    handle.close()
    return size


def open_source_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    source_budget: SourceBudget | None = None,
) -> tuple[BinaryIO, int]:
    handle, size = open_regular_file(path, label, max_bytes=max_bytes)
    if source_budget is not None:
        source_budget.add(size)
    return handle, size


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
        size = metadata.st_size
        if size > max_bytes:
            raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
        return os.fdopen(fd, "rb"), size
    except BaseException:
        os.close(fd)
        raise


def read_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    source_budget: SourceBudget | None = None,
) -> bytes:
    handle, _size = open_source_file(
        path,
        label,
        max_bytes=max_bytes,
        source_budget=source_budget,
    )
    with handle:
        data = handle.read(max_bytes + 1)
        validate_open_regular_file(handle, label, max_bytes=max_bytes)
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
    return data


def read_text_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    source_budget: SourceBudget | None = None,
    encoding: str,
) -> str:
    return read_regular_file(
        path,
        label,
        max_bytes=max_bytes,
        source_budget=source_budget,
    ).decode(encoding)


def prepare_output_directory(path: Path) -> None:
    if path.is_symlink():
        raise SystemExit(f"release update policy output directory must not be a symlink: {path}")
    if path.exists() and not path.is_dir():
        raise SystemExit(f"release update policy output path must be a directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def validate_input_directory(path: Path, label: str) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")
    return path.resolve()


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


def write_text_output(path: Path, label: str, text: str, *, max_bytes: int) -> None:
    data = text.encode("ascii")
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
    with open_output_file(path, label) as handle:
        handle.write(data)
        handle.flush()
        validate_open_regular_file(handle, label, max_bytes=max_bytes)
    validate_source_file(path, label, max_bytes=max_bytes)


def validate_open_regular_file(handle: BinaryIO, label: str, *, max_bytes: int) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    size = metadata.st_size
    if size > max_bytes:
        raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
    return size


def write_sha256_sidecar(path: Path) -> None:
    digest = sha256_file(
        path,
        "release update policy output",
        max_bytes=MAX_TEXT_ASSET_BYTES,
    )
    write_text_output(
        path.with_name(f"{path.name}.sha256"),
        "release update policy SHA-256 sidecar",
        f"{digest}  {path.name}\n",
        max_bytes=MAX_CHECKSUM_BYTES,
    )


def assert_output_safe(text: str) -> None:
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SystemExit("release update policy must be ASCII JSON") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(
                f"release update policy contains forbidden text; {TEXT_FAILURE_GUARDS}"
            )
    if "\\" in text:
        raise SystemExit("release update policy must not contain local path separators")


def is_text_asset(filename: str) -> bool:
    return filename.endswith((".rb", ".json", ".yaml", ".yml", ".spec", ".asc"))


def assert_open_file_text_safe(
    handle: BinaryIO,
    _filename: str,
    label: str,
    *,
    max_bytes: int,
) -> None:
    handle.seek(0)
    data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large: exceeds {max_bytes} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{label} is not UTF-8 text") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{label} contains forbidden text; {TEXT_FAILURE_GUARDS}")
    validate_open_regular_file(handle, label, max_bytes=max_bytes)
    handle.seek(0)


if __name__ == "__main__":
    sys.exit(main())
