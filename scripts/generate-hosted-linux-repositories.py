#!/usr/bin/env python3
"""Generate a static hosted APT/YUM repository bundle from signed release assets."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import stat
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
MAX_RELEASE_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_HOSTED_BUNDLE_BYTES = 6 * 1024 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 512_000_000
MAX_ZIP_MEMBERS = 10_000
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
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
    dist = args.dist.expanduser()
    output_dir = args.output_dir.expanduser()
    validate_input_directory(dist, "release dist directory")
    prepare_output_directory(output_dir, "hosted repository output directory")
    dist = dist.resolve()
    output_dir = output_dir.resolve()

    assets = collect_assets(dist, version)
    members = build_hosted_repository_members(assets)
    output = output_dir / hosted_repository_bundle_filename(version)
    validate_output_file(output, "hosted Linux repository bundle")
    validate_output_file(
        output.with_name(f"{output.name}.sha256"),
        "hosted Linux repository bundle SHA-256 sidecar",
    )
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


def required_asset(path: Path, label: str, *, max_bytes: int = MAX_RELEASE_ASSET_BYTES) -> Path:
    validate_regular_file(path, label, max_bytes=max_bytes)
    verify_sha256_sidecar(path, label)
    return path


def require_detached_signature(path: Path) -> Path:
    signature = path.with_name(f"{path.name}.asc")
    validate_regular_file(
        signature,
        "detached signature for hosted repository asset",
        max_bytes=MAX_SIGNATURE_BYTES,
    )
    try:
        signature_text = signature.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")
    return signature


def verify_public_key(path: Path) -> None:
    validate_regular_file(path, "Linux public key asset", max_bytes=MAX_PUBLIC_KEY_BYTES)
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
        PUBLIC_KEY_NAME: read_regular_file(
            assets.public_key,
            "Linux GPG public key",
            max_bytes=MAX_PUBLIC_KEY_BYTES,
        ),
        f"{PUBLIC_KEY_NAME}.sha256": read_regular_file(
            assets.public_key.with_name(f"{PUBLIC_KEY_NAME}.sha256"),
            "SHA-256 sidecar for Linux GPG public key",
            max_bytes=MAX_CHECKSUM_BYTES,
        ),
        "apt/README.txt": render_apt_readme(assets.version, debian_names).encode("ascii"),
        f"apt/{PUBLIC_KEY_NAME}": read_regular_file(
            assets.public_key,
            "Linux GPG public key",
            max_bytes=MAX_PUBLIC_KEY_BYTES,
        ),
        f"apt/{PUBLIC_KEY_NAME}.sha256": read_regular_file(
            assets.public_key.with_name(f"{PUBLIC_KEY_NAME}.sha256"),
            "SHA-256 sidecar for Linux GPG public key",
            max_bytes=MAX_CHECKSUM_BYTES,
        ),
    }
    for name in ("Packages", "Packages.gz", "Release", "InRelease", "Release.gpg"):
        members[f"apt/{name}"] = apt_metadata[name]
    for package in assets.debian_packages:
        add_asset_triplet(members, "apt", package)

    members["rpm/README.txt"] = render_rpm_readme(assets.version, rpm_names).encode("ascii")
    members[f"rpm/{PUBLIC_KEY_NAME}"] = read_regular_file(
        assets.public_key,
        "Linux GPG public key",
        max_bytes=MAX_PUBLIC_KEY_BYTES,
    )
    members[f"rpm/{PUBLIC_KEY_NAME}.sha256"] = read_regular_file(
        assets.public_key.with_name(f"{PUBLIC_KEY_NAME}.sha256"),
        "SHA-256 sidecar for Linux GPG public key",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    for package in assets.rpm_packages:
        add_asset_triplet(members, "rpm", package)
    for name in sorted(rpm_metadata):
        if name == "README.txt":
            continue
        members[f"rpm/{name}"] = rpm_metadata[name]

    return members


def add_asset_triplet(members: dict[str, bytes], prefix: str, asset: Path) -> None:
    members[f"{prefix}/{asset.name}"] = read_regular_file(
        asset,
        f"{prefix} hosted repository asset",
        max_bytes=MAX_RELEASE_ASSET_BYTES,
    )
    members[f"{prefix}/{asset.name}.sha256"] = read_regular_file(
        asset.with_name(f"{asset.name}.sha256"),
        f"SHA-256 sidecar for {prefix} hosted repository asset",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    members[f"{prefix}/{asset.name}.asc"] = read_regular_file(
        asset.with_name(f"{asset.name}.asc"),
        f"detached signature for {prefix} hosted repository asset",
        max_bytes=MAX_SIGNATURE_BYTES,
    )


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
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(bundle) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                raise SystemExit(f"{bundle.name} contains more than {MAX_ZIP_MEMBERS} members")
            for member in infos:
                name = normalize_zip_path(member.filename)
                if not validate_zip_member_for_read(bundle.name, member, name):
                    continue
                if name in members:
                    raise SystemExit(f"{bundle.name} contains duplicate zip member: {name}")
                if name != "README.txt" and not (
                    name in {"Packages", "Packages.gz", "Release", "InRelease", "Release.gpg"}
                    or name.startswith("repodata/")
                ):
                    raise SystemExit(f"{bundle.name} contains unexpected zip member: {name}")
                total_uncompressed += member.file_size
                if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                    raise SystemExit(
                        f"{bundle.name} uncompressed ZIP contents exceed "
                        f"{MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES} bytes"
                    )
                members[name] = archive.read(member)
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"{bundle.name} is not a readable zip archive") from exc
    return members


def validate_zip_member_for_read(bundle_name: str, member: zipfile.ZipInfo, name: str) -> bool:
    if member.flag_bits & 0x1:
        raise SystemExit(f"{bundle_name} contains encrypted zip member: {name}")
    file_type = (member.external_attr >> 16) & 0o170000
    is_directory = member.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise SystemExit(f"{bundle_name} contains unsupported link member: {name}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise SystemExit(f"{bundle_name} contains unsupported zip member: {name}")
    if is_directory:
        if member.file_size != 0:
            raise SystemExit(f"{bundle_name} contains directory member with data: {name}")
        return False
    if member.file_size > MAX_ZIP_MEMBER_BYTES:
        raise SystemExit(f"{bundle_name} zip member is too large: {name}")
    return True


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
    validate_output_file(path, "hosted Linux repository bundle")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            archive.writestr(info, members[name])


def verify_sha256_sidecar(path: Path, label: str) -> str:
    validate_regular_file(path, label, max_bytes=MAX_RELEASE_ASSET_BYTES)
    sidecar = path.with_name(f"{path.name}.sha256")
    validate_regular_file(
        sidecar,
        f"SHA-256 sidecar for {label}",
        max_bytes=MAX_CHECKSUM_BYTES,
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


def write_sha256_sidecar(path: Path) -> None:
    validate_regular_file(path, "hosted Linux repository bundle", max_bytes=MAX_HOSTED_BUNDLE_BYTES)
    sidecar = path.with_name(f"{path.name}.sha256")
    validate_output_file(sidecar, "hosted Linux repository bundle SHA-256 sidecar")
    sidecar.write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )
    validate_regular_file(
        sidecar,
        "hosted Linux repository bundle SHA-256 sidecar",
        max_bytes=MAX_CHECKSUM_BYTES,
    )


def validate_input_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist: {path}")


def prepare_output_directory(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path}")
    if path.exists() and not path.is_dir():
        raise SystemExit(f"{label} must be a directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def validate_regular_file(path: Path, label: str, *, max_bytes: int) -> int:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {path.name}")
    if not path.exists():
        raise SystemExit(f"missing {label}: {path.name}")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise SystemExit(f"{label} could not be inspected: {path.name}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file: {path.name}")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{label} is too large: {path.name}")
    return metadata.st_size


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


def read_regular_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    validate_regular_file(path, label, max_bytes=max_bytes)
    return path.read_bytes()


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
