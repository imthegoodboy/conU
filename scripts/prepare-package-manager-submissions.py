#!/usr/bin/env python3
"""Prepare a verified package-manager submission bundle for a conU release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SUBMISSION_BUNDLE_BYTES = MAX_TOTAL_SOURCE_BYTES + MAX_TEXT_BYTES + (1024 * 1024)
MAX_CHECKSUM_BYTES = 4096
ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
DEBIAN_ARCHES = ("amd64", "arm64")
RPM_ARCHES = ("x86_64", "aarch64")
FORBIDDEN_TEXT = (
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "CONU_RELAY_TOKEN",
    "CONU_WINDOWS_SIGN_CERT",
    "CONU_MACOS_DEVELOPER_ID",
    "CONU_LINUX_GPG_PRIVATE_KEY",
    "BEGIN PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "payload_ciphertext",
    "payload_hex",
    "payloadHex",
    "token_sha256_hex",
)


@dataclass(frozen=True)
class BundleEntry:
    source_name: str
    archive_name: str
    kind: str
    required: bool = True


@dataclass(frozen=True)
class PreparedEntry:
    entry: BundleEntry
    source: Path
    size: int


@dataclass(frozen=True)
class SubmissionBundleReport:
    version: str
    output: Path
    checksum: Path
    entry_count: int
    entries: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "output": str(self.output),
            "checksum": str(self.checksum),
            "entryCount": self.entry_count,
            "entries": list(self.entries),
            "contentsDisplayed": False,
            "payloadDisplayed": False,
            "tokenDisplayed": False,
            "tokenHashDisplayed": False,
            "keyMaterialDisplayed": False,
        }


def main() -> int:
    args = parse_args()
    dist = args.dist.expanduser()
    output_dir = args.output_dir.expanduser()
    version = validate_version(args.version or read_repo_version())
    report = prepare_submission_bundle(
        dist,
        output_dir,
        version,
        require_rpm_assets=args.require_rpm_assets,
        require_repository_metadata=args.require_repository_metadata,
        require_linux_signatures=args.require_linux_signatures,
    )
    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print(
            "prepared package-manager submission bundle: "
            f"{report.output} ({report.entry_count} entries)"
        )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing generated release files")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory for the generated submission bundle",
    )
    parser.add_argument("--version", help="release version; defaults to npm package version")
    parser.add_argument(
        "--require-rpm-assets",
        action="store_true",
        help="fail unless signed-release RPM package outputs are present",
    )
    parser.add_argument(
        "--require-repository-metadata",
        action="store_true",
        help="fail unless APT and RPM repository metadata bundles are present",
    )
    parser.add_argument(
        "--require-linux-signatures",
        action="store_true",
        help="fail unless Linux package/metadata signatures and public key assets are present",
    )
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
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
        raise SystemExit(f"invalid release version for package-manager submissions: {version}")
    return version


def debian_version(version: str) -> str:
    return version.replace("-", "~")


def rpm_version(version: str) -> str:
    return version.replace("-", "~").replace("+", "_")


def submission_bundle_filename(version: str) -> str:
    return f"conu-{version}-package-manager-submissions.zip"


def required_and_optional_entries(
    version: str,
    *,
    require_rpm_assets: bool,
    require_repository_metadata: bool,
    require_linux_signatures: bool,
) -> tuple[BundleEntry, ...]:
    deb_version = debian_version(version)
    rpm_ver = rpm_version(version)
    entries: list[BundleEntry] = [
        BundleEntry("conu.rb", "homebrew-tap/Formula/conu.rb", "homebrew"),
        BundleEntry("conu.json", "scoop-bucket/bucket/conu.json", "scoop"),
        BundleEntry(
            "imthegoodboy.conU.yaml",
            f"winget-pkgs/manifests/i/imthegoodboy/conU/{version}/imthegoodboy.conU.yaml",
            "winget",
        ),
        BundleEntry(f"conu.{version}.nupkg", f"chocolatey/conu.{version}.nupkg", "chocolatey"),
        BundleEntry("conu.spec", "rpm/conu.spec", "rpm-spec"),
    ]
    for arch in DEBIAN_ARCHES:
        package = f"conu_{deb_version}_{arch}.deb"
        entries.extend(
            [
                BundleEntry(package, f"debian/{package}", "binary"),
                BundleEntry(f"{package}.sha256", f"debian/{package}.sha256", "checksum"),
                BundleEntry(
                    f"{package}.asc",
                    f"debian/{package}.asc",
                    "signature",
                    required=require_linux_signatures,
                ),
            ]
        )

    apt_metadata = f"conu-{deb_version}-apt-repository-metadata.zip"
    rpm_metadata = f"conu-{rpm_ver}-rpm-repository-metadata.zip"
    for metadata, archive_prefix in (
        (apt_metadata, "apt"),
        (rpm_metadata, "rpm"),
    ):
        entries.extend(
            [
                BundleEntry(
                    metadata,
                    f"{archive_prefix}/{metadata}",
                    "binary",
                    required=require_repository_metadata,
                ),
                BundleEntry(
                    f"{metadata}.sha256",
                    f"{archive_prefix}/{metadata}.sha256",
                    "checksum",
                    required=require_repository_metadata,
                ),
                BundleEntry(
                    f"{metadata}.asc",
                    f"{archive_prefix}/{metadata}.asc",
                    "signature",
                    required=require_repository_metadata and require_linux_signatures,
                ),
            ]
        )

    for arch in RPM_ARCHES:
        package = f"conu-{rpm_ver}-1.{arch}.rpm"
        entries.extend(
            [
                BundleEntry(package, f"rpm/{package}", "binary", required=require_rpm_assets),
                BundleEntry(
                    f"{package}.sha256",
                    f"rpm/{package}.sha256",
                    "checksum",
                    required=require_rpm_assets,
                ),
                BundleEntry(
                    f"{package}.asc",
                    f"rpm/{package}.asc",
                    "signature",
                    required=require_rpm_assets and require_linux_signatures,
                ),
            ]
        )

    entries.extend(
        [
            BundleEntry(
                "conu-linux-gpg-key.asc",
                "linux-signing/conu-linux-gpg-key.asc",
                "public-key",
                required=require_linux_signatures,
            ),
            BundleEntry(
                "conu-linux-gpg-key.asc.sha256",
                "linux-signing/conu-linux-gpg-key.asc.sha256",
                "checksum",
                required=require_linux_signatures,
            ),
        ]
    )
    return tuple(entries)


def prepare_submission_bundle(
    dist: Path,
    output_dir: Path,
    version: str,
    *,
    require_rpm_assets: bool = False,
    require_repository_metadata: bool = False,
    require_linux_signatures: bool = False,
) -> SubmissionBundleReport:
    validate_input_directory(dist, "package-manager submission source directory")
    dist = dist.resolve()
    prepare_output_directory(output_dir, "package-manager submission output directory")
    output_dir = output_dir.resolve()

    entries = required_and_optional_entries(
        version,
        require_rpm_assets=require_rpm_assets,
        require_repository_metadata=require_repository_metadata,
        require_linux_signatures=require_linux_signatures,
    )
    selected: list[PreparedEntry] = []
    total_source_bytes = 0
    for entry in entries:
        source = dist / entry.source_name
        if not source.exists() and not source.is_symlink():
            if entry.required:
                raise SystemExit(f"missing package-manager submission source: {entry.source_name}")
            continue
        size = validate_entry_source(source, entry, dist)
        total_source_bytes += size
        if total_source_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise SystemExit(
                "package-manager submission sources exceed "
                f"{MAX_TOTAL_SOURCE_BYTES} bytes"
            )
        selected.append(PreparedEntry(entry=entry, source=source, size=size))

    validate_no_duplicate_archive_names(prepared.entry.archive_name for prepared in selected)
    readme = render_readme(version, [prepared.entry.archive_name for prepared in selected])
    assert_safe_text(readme, "README.txt", dist)

    bundle = output_dir / submission_bundle_filename(version)
    validate_output_file(bundle, "package-manager submission bundle")
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED) as archive:
        write_zip_text(archive, "README.txt", readme)
        for prepared in selected:
            write_zip_file(archive, prepared.entry.archive_name, prepared.source, prepared.size)
    validate_regular_file(
        bundle,
        "package-manager submission bundle",
        max_bytes=MAX_SUBMISSION_BUNDLE_BYTES,
    )

    checksum = sha256_file(bundle)
    checksum_path = bundle.with_name(f"{bundle.name}.sha256")
    validate_output_file(checksum_path, "package-manager submission bundle SHA-256 sidecar")
    checksum_path.write_text(f"{checksum}  {bundle.name}\n", encoding="ascii", newline="\n")
    validate_regular_file(
        checksum_path,
        "package-manager submission bundle SHA-256 sidecar",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    entries_written = ("README.txt", *(prepared.entry.archive_name for prepared in selected))
    return SubmissionBundleReport(
        version=version,
        output=bundle,
        checksum=checksum_path,
        entry_count=len(entries_written),
        entries=tuple(entries_written),
    )


def validate_entry_source(source: Path, entry: BundleEntry, dist: Path) -> int:
    size = validate_regular_file(
        source,
        "package-manager submission source",
        display_name=entry.source_name,
        max_bytes=MAX_BINARY_BYTES,
        missing_message=f"missing package-manager submission source: {entry.source_name}",
        non_regular_message=f"package-manager submission source is not a file: {entry.source_name}",
    )
    if size <= 0:
        raise SystemExit(f"package-manager submission source is empty: {entry.source_name}")
    if entry.kind == "checksum":
        validate_checksum_source(source, dist)
    elif entry.kind == "signature":
        validate_signature_source(source, entry.source_name, dist)
    elif entry.kind == "public-key":
        validate_public_key_source(source, entry.source_name)
    elif entry.kind == "chocolatey":
        validate_chocolatey_package(source, dist)
    elif entry.kind in {"homebrew", "scoop", "winget", "rpm-spec"}:
        text = read_ascii_text(source, entry.source_name)
        validate_structured_manifest(text, entry, source)
        assert_safe_text(text, entry.source_name, dist)
    return size


def read_ascii_text(path: Path, label: str) -> str:
    if path.stat().st_size > MAX_TEXT_BYTES:
        raise SystemExit(f"{label} is too large to inspect as text")
    try:
        return path.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{label} is not ASCII") from exc


def validate_structured_manifest(text: str, entry: BundleEntry, source: Path) -> None:
    if entry.kind == "homebrew":
        for required in ('class Conu < Formula', 'homepage "https://github.com/', 'sha256 "'):
            if required not in text:
                raise SystemExit(f"{entry.source_name} is missing expected Homebrew field: {required}")
    elif entry.kind == "scoop":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{entry.source_name} is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise SystemExit(f"{entry.source_name} must contain a JSON object")
        if payload.get("version") is None or "architecture" not in payload or "bin" not in payload:
            raise SystemExit(f"{entry.source_name} is missing Scoop version, architecture, or bin data")
    elif entry.kind == "winget":
        for required in ("PackageIdentifier: imthegoodboy.conU", "InstallerSha256:", "InstallerUrl: https://"):
            if required not in text:
                raise SystemExit(f"{entry.source_name} is missing expected winget field: {required}")
    elif entry.kind == "rpm-spec":
        for required in ("Name: conu", "Source0: https://", "%install", "%files"):
            if required not in text:
                raise SystemExit(f"{entry.source_name} is missing expected RPM spec field: {required}")
    if str(source.resolve()).replace("\\", "/") in text.replace("\\", "/"):
        raise SystemExit(f"{entry.source_name} contains a local source path")


def validate_chocolatey_package(path: Path, dist: Path) -> None:
    try:
        with zipfile.ZipFile(path) as package:
            infos = package.infolist()
            names = [info.filename for info in infos]
            expected = [
                "conu.nuspec",
                "tools/chocolateyInstall.ps1",
                "tools/chocolateyUninstall.ps1",
            ]
            for info in infos:
                validate_chocolatey_member(path.name, info)
            if names != expected:
                raise SystemExit(f"{path.name} has unexpected Chocolatey package entries: {names!r}")
            for info in infos:
                name = info.filename
                normalized = normalize_archive_path(name)
                if normalized != name:
                    raise SystemExit(f"{path.name} has unsafe Chocolatey package path: {name}")
                text = read_chocolatey_text_member(package, info, path.name)
                assert_safe_text(text, f"{path.name}:{name}", dist)
    except (RuntimeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"{path.name} is not a readable Chocolatey nupkg") from exc
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{path.name} contains non-ASCII Chocolatey metadata") from exc


def validate_chocolatey_member(package_name: str, info: zipfile.ZipInfo) -> None:
    name = info.filename
    if info.flag_bits & 0x1:
        raise SystemExit(f"{package_name} contains encrypted Chocolatey package member: {name}")
    file_type = (info.external_attr >> 16) & 0o170000
    is_directory = info.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise SystemExit(f"{package_name} contains unsupported Chocolatey link member: {name}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise SystemExit(f"{package_name} contains unsupported Chocolatey package member: {name}")
    if is_directory:
        if info.file_size != 0:
            raise SystemExit(f"{package_name} contains Chocolatey directory member with data: {name}")
        raise SystemExit(f"{package_name} has unexpected Chocolatey package directory: {name}")
    if info.file_size > MAX_TEXT_BYTES:
        raise SystemExit(f"{package_name}:{name} is too large")


def read_chocolatey_text_member(
    package: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    package_name: str,
) -> str:
    try:
        with package.open(info, "r") as handle:
            data = handle.read(MAX_TEXT_BYTES + 1)
    except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise SystemExit(f"{package_name} could not read Chocolatey package member: {info.filename}") from exc
    if len(data) > MAX_TEXT_BYTES:
        raise SystemExit(f"{package_name}:{info.filename} is too large")
    return data.decode("ascii")


def validate_checksum_source(path: Path, dist: Path) -> None:
    text = read_ascii_text(path, path.name)
    match = CHECKSUM_RE.fullmatch(text)
    if match is None:
        raise SystemExit(f"{path.name} is not a strict SHA-256 sidecar")
    target_name = match.group(2)
    expected_target = path.name[: -len(".sha256")]
    if target_name != expected_target:
        raise SystemExit(f"{path.name} names wrong target: {target_name}")
    target = dist / target_name
    validate_regular_file(
        target,
        f"{path.name} target",
        display_name=target_name,
        max_bytes=MAX_BINARY_BYTES,
        missing_message=f"{path.name} target is missing: {target_name}",
        non_regular_message=f"{path.name} target is not a regular file: {target_name}",
    )
    expected = match.group(1).lower()
    actual = sha256_file(target)
    if expected != actual:
        raise SystemExit(f"{path.name} SHA-256 mismatch for {target_name}")


def validate_signature_source(source: Path, label: str, dist: Path) -> None:
    target_name = source.name[: -len(".asc")]
    target = dist / target_name
    validate_regular_file(
        target,
        f"{label} signed target",
        display_name=target_name,
        max_bytes=MAX_BINARY_BYTES,
        missing_message=f"{label} signed target is missing: {target_name}",
        non_regular_message=f"{label} signed target is not a regular file: {target_name}",
    )
    text = read_ascii_text(source, label)
    if "BEGIN PGP SIGNATURE" not in text or "END PGP SIGNATURE" not in text:
        raise SystemExit(f"{label} is not an armored detached PGP signature")
    assert_safe_text(text, label, Path())


def validate_public_key_source(source: Path, label: str) -> None:
    text = read_ascii_text(source, label)
    if "BEGIN PGP PUBLIC KEY BLOCK" not in text or "END PGP PUBLIC KEY BLOCK" not in text:
        raise SystemExit(f"{label} is not an armored PGP public key")
    assert_safe_text(text, label, Path())


def assert_safe_text(text: str, label: str, dist: Path) -> None:
    normalized = text.replace("\\", "/")
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{label} contains forbidden literal: {forbidden}")
    if dist != Path():
        resolved_dist = str(dist.resolve()).replace("\\", "/")
        if resolved_dist and resolved_dist in normalized:
            raise SystemExit(f"{label} contains local package-manager output path")


def validate_no_duplicate_archive_names(names: Any) -> None:
    seen: set[str] = set()
    for name in names:
        normalized = normalize_archive_path(name)
        if normalized in seen:
            raise SystemExit(f"duplicate package-manager submission archive path: {normalized}")
        seen.add(normalized)


def normalize_archive_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts or not parts:
        raise SystemExit(f"unsafe package-manager submission archive path: {raw_name}")
    return "/".join(parts)


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


def validate_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    display_name: str | None = None,
    missing_message: str | None = None,
    non_regular_message: str | None = None,
) -> int:
    display = display_name or path.name
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink: {display}")
    if not path.exists():
        raise SystemExit(missing_message or f"missing {label}: {display}")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise SystemExit(f"{label} could not be inspected: {display}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(non_regular_message or f"{label} must be a regular file: {display}")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{label} is too large: {display}")
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


def render_readme(version: str, entries: list[str]) -> str:
    entry_list = "\n".join(f"- {entry}" for entry in entries)
    return f"""conU {version} package-manager submission bundle

This deterministic bundle is generated from verified release package-manager
outputs. Copy the files into the matching package-manager repository layout only
after reviewing the public release assets, checksums, and signatures.

Included files:

{entry_list}

Display guards:
payload_displayed = false
token_displayed = false
token_hash_displayed = false
key_material_displayed = false
contents_displayed = false
"""


def write_zip_text(archive: zipfile.ZipFile, name: str, text: str) -> None:
    write_zip_bytes(archive, name, text.encode("ascii"))


def write_zip_bytes(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    normalized = normalize_archive_path(name)
    info = zipfile.ZipInfo(normalized, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def write_zip_file(archive: zipfile.ZipFile, name: str, source: Path, size: int) -> None:
    normalized = normalize_archive_path(name)
    info = zipfile.ZipInfo(normalized, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    info.file_size = size
    with archive.open(info, "w") as output, source.open("rb") as input_file:
        shutil.copyfileobj(input_file, output, HASH_CHUNK_BYTES)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
