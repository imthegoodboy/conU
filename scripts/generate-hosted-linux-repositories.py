#!/usr/bin/env python3
"""Generate a static hosted APT/YUM repository bundle from signed release assets."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 1024 * 1024
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
DEBIAN_ARCHES = {
    "linux-x64": "amd64",
    "linux-arm64": "arm64",
}
RPM_ARCHES = {
    "linux-x64": "x86_64",
    "linux-arm64": "aarch64",
}
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"


@dataclass(frozen=True)
class HostedLinuxAssets:
    version: str
    apt_metadata: Path
    rpm_metadata: Path
    debian_packages: tuple[Path, ...]
    rpm_packages: tuple[Path, ...]
    public_key: Path


def main() -> int:
    args = parse_args()
    version = validate_version(args.version or read_repo_version())
    dist = args.dist.resolve()
    output_dir = args.output_dir.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")
    output_dir.mkdir(parents=True, exist_ok=True)

    assets = collect_assets(dist, version)
    members = build_hosted_repository_members(assets)
    output = output_dir / hosted_repository_bundle_filename(version)
    write_zip_members(output, members)
    write_sha256_sidecar(output)
    print(f"generated hosted Linux repositories: {output.name}, {output.name}.sha256")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing signed release assets")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory receiving the hosted repository bundle",
    )
    parser.add_argument("--version", help="release version; defaults to npm package version")
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
        raise SystemExit(f"invalid release version for hosted Linux repositories: {version}")
    return version


def debian_version(version: str) -> str:
    return version.replace("-", "~")


def rpm_version(version: str) -> str:
    return version.replace("-", "~").replace("+", "_")


def hosted_repository_bundle_filename(version: str) -> str:
    return f"conu-{version}-hosted-linux-repositories.zip"


def debian_filename(version: str, target: str) -> str:
    return f"conu_{debian_version(version)}_{DEBIAN_ARCHES[target]}.deb"


def rpm_filename(version: str, target: str) -> str:
    return f"conu-{rpm_version(version)}-1.{RPM_ARCHES[target]}.rpm"


def apt_repository_metadata_filename(version: str) -> str:
    return f"conu-{debian_version(version)}-apt-repository-metadata.zip"


def rpm_repository_metadata_filename(version: str) -> str:
    return f"conu-{rpm_version(version)}-rpm-repository-metadata.zip"


def collect_assets(dist: Path, version: str) -> HostedLinuxAssets:
    apt_metadata = required_asset(
        dist / apt_repository_metadata_filename(version),
        "signed APT repository metadata bundle",
    )
    rpm_metadata = required_asset(
        dist / rpm_repository_metadata_filename(version),
        "signed RPM repository metadata bundle",
    )
    debian_packages = tuple(
        required_asset(dist / debian_filename(version, target), "signed Debian package")
        for target in DEBIAN_ARCHES
    )
    rpm_packages = tuple(
        required_asset(dist / rpm_filename(version, target), "signed RPM package")
        for target in RPM_ARCHES
    )
    public_key = required_asset(dist / PUBLIC_KEY_NAME, "Linux GPG public key")

    for path in (*debian_packages, *rpm_packages):
        require_detached_signature(path)
    verify_public_key(public_key)

    return HostedLinuxAssets(
        version=version,
        apt_metadata=apt_metadata,
        rpm_metadata=rpm_metadata,
        debian_packages=debian_packages,
        rpm_packages=rpm_packages,
        public_key=public_key,
    )


def required_asset(path: Path, label: str) -> Path:
    if not path.exists() or not path.is_file():
        raise SystemExit(f"missing {label}: {path.name}")
    verify_sha256_sidecar(path, label)
    return path


def require_detached_signature(path: Path) -> Path:
    signature = path.with_name(f"{path.name}.asc")
    if not signature.exists() or not signature.is_file():
        raise SystemExit(f"missing detached signature for hosted repository asset: {path.name}.asc")
    if signature.stat().st_size > MAX_SIGNATURE_BYTES:
        raise SystemExit(f"detached signature is too large: {signature.name}")
    try:
        signature_text = signature.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")
    return signature


def verify_public_key(path: Path) -> None:
    if path.stat().st_size > MAX_PUBLIC_KEY_BYTES:
        raise SystemExit(f"Linux public key asset is too large: {path.name}")
    try:
        text = path.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"Linux public key asset is not ASCII-armored: {path.name}") from exc
    if "BEGIN PGP PUBLIC KEY BLOCK" not in text:
        raise SystemExit(f"Linux public key asset is not an armored public key: {path.name}")
    if "PRIVATE KEY BLOCK" in text:
        raise SystemExit(f"refusing to bundle private key material from {path.name}")


def build_hosted_repository_members(assets: HostedLinuxAssets) -> dict[str, bytes]:
    apt_metadata = read_zip_members(assets.apt_metadata)
    rpm_metadata = read_zip_members(assets.rpm_metadata)
    debian_names = tuple(path.name for path in assets.debian_packages)
    rpm_names = tuple(path.name for path in assets.rpm_packages)
    validate_apt_metadata(assets.apt_metadata, apt_metadata, debian_names)
    validate_rpm_metadata(assets.rpm_metadata, rpm_metadata, rpm_names)

    members: dict[str, bytes] = {
        "README.txt": render_root_readme(assets.version).encode("ascii"),
        PUBLIC_KEY_NAME: assets.public_key.read_bytes(),
        f"{PUBLIC_KEY_NAME}.sha256": assets.public_key.with_name(
            f"{PUBLIC_KEY_NAME}.sha256"
        ).read_bytes(),
        "apt/README.txt": render_apt_readme(assets.version, debian_names).encode("ascii"),
        f"apt/{PUBLIC_KEY_NAME}": assets.public_key.read_bytes(),
        f"apt/{PUBLIC_KEY_NAME}.sha256": assets.public_key.with_name(
            f"{PUBLIC_KEY_NAME}.sha256"
        ).read_bytes(),
    }
    for name in ("Packages", "Packages.gz", "Release", "InRelease", "Release.gpg"):
        members[f"apt/{name}"] = apt_metadata[name]
    for package in assets.debian_packages:
        add_asset_triplet(members, "apt", package)

    members["rpm/README.txt"] = render_rpm_readme(assets.version, rpm_names).encode("ascii")
    members[f"rpm/{PUBLIC_KEY_NAME}"] = assets.public_key.read_bytes()
    members[f"rpm/{PUBLIC_KEY_NAME}.sha256"] = assets.public_key.with_name(
        f"{PUBLIC_KEY_NAME}.sha256"
    ).read_bytes()
    for package in assets.rpm_packages:
        add_asset_triplet(members, "rpm", package)
    for name in sorted(rpm_metadata):
        if name == "README.txt":
            continue
        members[f"rpm/{name}"] = rpm_metadata[name]

    return members


def add_asset_triplet(members: dict[str, bytes], prefix: str, asset: Path) -> None:
    members[f"{prefix}/{asset.name}"] = asset.read_bytes()
    members[f"{prefix}/{asset.name}.sha256"] = asset.with_name(f"{asset.name}.sha256").read_bytes()
    members[f"{prefix}/{asset.name}.asc"] = asset.with_name(f"{asset.name}.asc").read_bytes()


def validate_apt_metadata(
    bundle: Path,
    members: dict[str, bytes],
    debian_names: tuple[str, ...],
) -> None:
    required = {"README.txt", "Packages", "Packages.gz", "Release", "InRelease", "Release.gpg"}
    missing = sorted(required - set(members))
    if missing:
        raise SystemExit(f"{bundle.name} is missing signed APT member(s): {', '.join(missing)}")
    packages = members["Packages"]
    try:
        packages_text = packages.decode("ascii")
        release_text = members["Release"].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{bundle.name} contains non-ASCII APT metadata") from exc
    if gzip.decompress(members["Packages.gz"]) != packages:
        raise SystemExit(f"{bundle.name} Packages.gz does not match Packages")
    for name in debian_names:
        if f"Filename: {name}\n" not in packages_text:
            raise SystemExit(f"{bundle.name} Packages metadata does not reference {name}")
    for name, content in (("Packages", packages), ("Packages.gz", members["Packages.gz"])):
        for digest in (
            md5_hex(content),
            sha1_hex(content),
            hashlib.sha256(content).hexdigest(),
        ):
            if f" {digest} {len(content)} {name}" not in release_text:
                raise SystemExit(f"{bundle.name} Release metadata does not hash {name}")
    if b"BEGIN PGP SIGNED MESSAGE" not in members["InRelease"]:
        raise SystemExit(f"{bundle.name} is missing an armored InRelease signature")
    if b"BEGIN PGP SIGNATURE" not in members["Release.gpg"]:
        raise SystemExit(f"{bundle.name} is missing an armored Release.gpg signature")


def validate_rpm_metadata(
    bundle: Path,
    members: dict[str, bytes],
    rpm_names: tuple[str, ...],
) -> None:
    for name in ("README.txt", "repodata/repomd.xml", "repodata/repomd.xml.asc"):
        if name not in members:
            raise SystemExit(f"{bundle.name} is missing signed RPM member: {name}")
    if b"BEGIN PGP SIGNATURE" not in members["repodata/repomd.xml.asc"]:
        raise SystemExit(f"{bundle.name} is missing an armored repomd.xml.asc signature")
    primary_member = find_primary_metadata_member(bundle, members)
    try:
        primary_text = gzip.decompress(members[primary_member]).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit(f"{bundle.name} contains unreadable RPM primary metadata") from exc

    try:
        root = ET.fromstring(primary_text)
    except ET.ParseError as exc:
        raise SystemExit(f"{bundle.name} contains invalid RPM primary metadata") from exc
    common_ns = {"common": "http://linux.duke.edu/metadata/common"}
    hrefs = {
        location.attrib.get("href", "")
        for package in root.findall("common:package", common_ns)
        for location in [package.find("common:location", common_ns)]
        if location is not None
    }
    if hrefs != set(rpm_names):
        raise SystemExit(
            f"{bundle.name} RPM metadata references {sorted(hrefs)!r}; "
            f"expected {sorted(rpm_names)!r}"
        )


def find_primary_metadata_member(bundle: Path, members: dict[str, bytes]) -> str:
    try:
        root = ET.fromstring(members["repodata/repomd.xml"].decode("utf-8"))
    except (UnicodeDecodeError, ET.ParseError) as exc:
        raise SystemExit(f"{bundle.name} contains invalid repomd.xml") from exc
    repo_ns = {"repo": "http://linux.duke.edu/metadata/repo"}
    for data in root.findall("repo:data", repo_ns):
        if data.attrib.get("type") != "primary":
            continue
        location = data.find("repo:location", repo_ns)
        if location is None:
            continue
        href = location.attrib.get("href", "")
        if href in members:
            return href
    raise SystemExit(f"{bundle.name} repomd.xml does not reference primary metadata")


def read_zip_members(bundle: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(bundle) as archive:
            for member in archive.infolist():
                name = normalize_zip_path(member.filename)
                if member.is_dir():
                    continue
                if name in members:
                    raise SystemExit(f"{bundle.name} contains duplicate zip member: {name}")
                if name != "README.txt" and not (
                    name in {"Packages", "Packages.gz", "Release", "InRelease", "Release.gpg"}
                    or name.startswith("repodata/")
                ):
                    raise SystemExit(f"{bundle.name} contains unexpected zip member: {name}")
                members[name] = archive.read(member)
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"{bundle.name} is not a readable zip archive") from exc
    return members


def normalize_zip_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe repository metadata zip path: {raw_name}")
    if not parts:
        raise SystemExit(f"unsafe empty repository metadata zip path: {raw_name}")
    return "/".join(parts)


def render_root_readme(version: str) -> str:
    return f"""conU {version} hosted Linux repositories

This archive is a static hosting bundle for the signed conU Linux package
repositories generated from the release assets.

Serve the apt/ directory as a flat APT repository and the rpm/ directory as a
YUM/DNF repository. Import or install conu-linux-gpg-key.asc only after
comparing it with the published maintainer fingerprint. The package payloads
and repository metadata are signed; strict SHA-256 sidecars are included for
the public key, package files, and this bundle.

This bundle contains public package files, public checksums, public signatures,
and repository metadata only. It does not contain signing secrets, npm tokens,
relay tokens, conU state, logs, inboxes, private payloads, or private keys.
"""


def render_apt_readme(version: str, package_names: tuple[str, ...]) -> str:
    package_list = "\n".join(f"- {name}" for name in package_names)
    return f"""conU {debian_version(version)} flat APT repository

Files:
{package_list}

Suggested source format after serving this directory:

deb [signed-by=/usr/share/keyrings/conu-linux-gpg-key.asc] https://example.invalid/conu/apt ./

This flat repository keeps package filenames at repository root so the signed
Packages and Release metadata can be served without rewriting or resigning.
"""


def render_rpm_readme(version: str, package_names: tuple[str, ...]) -> str:
    package_list = "\n".join(f"- {name}" for name in package_names)
    return f"""conU {rpm_version(version)} YUM/DNF repository

Files:
{package_list}

Serve this directory as the repository baseurl. The repodata/repomd.xml file is
signed by repodata/repomd.xml.asc, and the RPM package payloads also carry
native RPM signatures from the release signing key.
"""


def write_zip_members(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            archive.writestr(info, members[name])


def verify_sha256_sidecar(path: Path, label: str) -> str:
    sidecar = path.with_name(f"{path.name}.sha256")
    if not sidecar.exists() or not sidecar.is_file():
        raise SystemExit(f"missing SHA-256 sidecar for {label}: {path.name}")
    if sidecar.stat().st_size > MAX_CHECKSUM_BYTES:
        raise SystemExit(f"SHA-256 sidecar is too large for {label}: {path.name}")
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


def write_sha256_sidecar(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


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


if __name__ == "__main__":
    sys.exit(main())
