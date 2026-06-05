#!/usr/bin/env python3
"""Prepare a verified hosted Linux repository site for GitHub Pages."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import unquote, urlparse, urlunparse

from json_safety import loads_json


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SITE_RE = re.compile(
    r"^conu-(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)-"
    r"hosted-linux-repository-site\.zip$"
)
HASH_CHUNK_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_SITE_ZIP_BYTES = 2 * 1024 * 1024 * 1024
MAX_SITE_MEMBER_BYTES = 512_000_000
MAX_SITE_MEMBERS = 10000
MAX_SITE_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MEMBER_FAILURE_GUARDS = "pathDisplayed=false contentsDisplayed=false"
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
CACHE_CONTROL_RULES = (
    {
        "kind": "mutable-site-metadata",
        "cacheControl": "no-cache",
        "paths": (
            "/.nojekyll",
            "/README.txt",
            "/index.html",
            "/repository.json",
            "/cache-policy.json",
            "/_headers",
            "/install/*",
            f"/{PUBLIC_KEY_NAME}",
            f"/{PUBLIC_KEY_NAME}.sha256",
            "/apt/README.txt",
            f"/apt/{PUBLIC_KEY_NAME}",
            f"/apt/{PUBLIC_KEY_NAME}.sha256",
            "/rpm/README.txt",
            f"/rpm/{PUBLIC_KEY_NAME}",
            f"/rpm/{PUBLIC_KEY_NAME}.sha256",
        ),
    },
    {
        "kind": "repository-metadata",
        "cacheControl": "public, max-age=300, must-revalidate",
        "paths": (
            "/apt/Packages",
            "/apt/Packages.gz",
            "/apt/Release",
            "/apt/InRelease",
            "/apt/Release.gpg",
            "/rpm/repodata/*",
        ),
    },
    {
        "kind": "immutable-release-assets",
        "cacheControl": "public, max-age=31536000, immutable",
        "paths": (
            "/apt/*.deb",
            "/apt/*.deb.sha256",
            "/apt/*.deb.asc",
            "/rpm/*.rpm",
            "/rpm/*.rpm.sha256",
            "/rpm/*.rpm.asc",
            "/downloads/conu-*-hosted-linux-repositories.zip",
            "/downloads/conu-*-hosted-linux-repositories.zip.sha256",
            "/downloads/conu-*-hosted-linux-repositories.zip.asc",
        ),
    },
)
FORBIDDEN_SEGMENTS = {
    ".conu",
    ".git",
    ".github",
    "logs",
    "messages",
    "node_modules",
    "routes",
    "runtime",
    "security",
}
FORBIDDEN_TEXT = (
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PRIVATE KEY",
    "NPM_TOKEN",
    "CONU_RELAY_TOKEN",
    "token_sha256_hex",
    "payloadHex",
    "payload_hex",
    "ciphertext_body",
)
TEXT_SUFFIXES = (".txt", ".json", ".html", ".list", ".repo", ".asc", ".sha256")
TEXT_MEMBER_NAMES = {"_headers"}
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_BINARY = getattr(os, "O_BINARY", 0)


def main() -> int:
    args = parse_args()
    site_zip = find_site_zip(args.site, args.version)
    version = version_from_site_name(site_zip.name)
    verify_sha256_sidecar(site_zip, "hosted Linux repository site")
    require_detached_signature(site_zip)
    output_dir = args.output_dir.expanduser()
    prepare_output_dir(output_dir)
    output_dir = output_dir.resolve()
    members = read_site_members(site_zip)
    validate_site_members(site_zip.name, version, members)
    extract_members(output_dir, members)
    print(f"prepared hosted Linux repository Pages artifact: {output_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "site",
        type=Path,
        help="hosted Linux repository site ZIP, or a directory containing one",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist/hosted-linux-repository-site"),
        help="empty directory receiving the extracted static site",
    )
    parser.add_argument(
        "--version",
        help="release version to select when the input is a directory",
    )
    return parser.parse_args()


def find_site_zip(site: Path, version: str | None) -> Path:
    path = site.expanduser()
    if path.is_symlink():
        raise SystemExit(f"hosted Linux repository site input must not be a symlink: {site}")
    if path.is_file():
        if version is not None and f"conu-{version}-hosted-linux-repository-site.zip" != path.name:
            raise SystemExit(f"site ZIP {path.name} does not match requested version {version}")
        version_from_site_name(path.name)
        validate_regular_file(
            path,
            "hosted Linux repository site ZIP",
            max_bytes=MAX_SITE_ZIP_BYTES,
        )
        return path
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"hosted Linux repository site input does not exist: {site}")
    if version is not None:
        candidate = path / f"conu-{version}-hosted-linux-repository-site.zip"
        validate_regular_file(
            candidate,
            "hosted Linux repository site ZIP",
            max_bytes=MAX_SITE_ZIP_BYTES,
        )
        return candidate
    candidates = sorted(
        item
        for item in path.glob("conu-*-hosted-linux-repository-site.zip")
        if item.is_file() or item.is_symlink()
    )
    if len(candidates) != 1:
        raise SystemExit(
            f"expected exactly one hosted Linux repository site ZIP in {path}, found {len(candidates)}"
        )
    version_from_site_name(candidates[0].name)
    validate_regular_file(
        candidates[0],
        "hosted Linux repository site ZIP",
        max_bytes=MAX_SITE_ZIP_BYTES,
    )
    return candidates[0]


def version_from_site_name(name: str) -> str:
    match = SITE_RE.fullmatch(name)
    if match is None:
        raise SystemExit(f"invalid hosted Linux repository site ZIP name: {name}")
    return match.group("version")


def verify_sha256_sidecar(path: Path, label: str) -> str:
    validate_regular_file(path, label, max_bytes=MAX_SITE_ZIP_BYTES)
    sidecar = path.with_name(f"{path.name}.sha256")
    validate_regular_file(
        sidecar,
        f"SHA-256 sidecar for {label}",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    try:
        checksum_text = read_ascii_file(
            sidecar,
            f"SHA-256 sidecar for {label}",
            max_bytes=MAX_CHECKSUM_BYTES,
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"SHA-256 sidecar is not ASCII for {label}: {path.name}") from exc
    match = CHECKSUM_RE.fullmatch(checksum_text)
    if match is None:
        raise SystemExit(f"SHA-256 sidecar has invalid format for {label}: {path.name}")
    if match.group(2) != path.name:
        raise SystemExit(f"SHA-256 sidecar for {label} names wrong file: {match.group(2)}")
    expected = match.group(1).lower()
    actual = sha256_file(path, label, max_bytes=MAX_SITE_ZIP_BYTES)
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")
    return expected


def require_detached_signature(path: Path) -> None:
    signature = path.with_name(f"{path.name}.asc")
    validate_regular_file(
        signature,
        "detached signature for hosted Linux repository site",
        max_bytes=MAX_SIGNATURE_BYTES,
    )
    try:
        signature_text = read_ascii_file(
            signature,
            "detached signature for hosted Linux repository site",
            max_bytes=MAX_SIGNATURE_BYTES,
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")
    if "PRIVATE KEY BLOCK" in signature_text:
        raise SystemExit(f"detached signature contains private key material: {signature.name}")


def prepare_output_dir(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise SystemExit(f"Pages output directory must not be a symlink: {output_dir}")
    if output_dir.exists() and not output_dir.is_dir():
        raise SystemExit(f"Pages output path must be a directory: {output_dir}")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"Pages output directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)


def validate_regular_file(path: Path, label: str, *, max_bytes: int) -> int:
    handle, size = open_regular_file(path, label, max_bytes=max_bytes)
    handle.close()
    return size


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
        if metadata.st_size > max_bytes:
            raise SystemExit(f"{label} is too large for Pages deployment: {path.name}")
        return os.fdopen(fd, "rb"), metadata.st_size
    except BaseException:
        os.close(fd)
        raise


def validate_open_regular_file(handle: BinaryIO, label: str, *, max_bytes: int) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{label} is too large for Pages deployment")
    return metadata.st_size


def read_site_members(site_zip: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_uncompressed = 0
    try:
        site_file, _size = open_regular_file(
            site_zip,
            "hosted Linux repository site ZIP",
            max_bytes=MAX_SITE_ZIP_BYTES,
        )
        with site_file:
            with zipfile.ZipFile(site_file) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_SITE_MEMBERS:
                    raise SystemExit(f"{site_zip.name} has too many members for Pages deployment")
                for info in infos:
                    name = normalize_zip_path(site_zip.name, info.filename)
                    if not validate_zip_member_for_read(site_zip.name, info, name):
                        continue
                    if name in members:
                        raise zip_member_failure(site_zip.name, "contains duplicate zip member")
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_SITE_TOTAL_UNCOMPRESSED_BYTES:
                        raise SystemExit(
                            f"{site_zip.name} uncompressed contents exceed "
                            f"{MAX_SITE_TOTAL_UNCOMPRESSED_BYTES} bytes"
                        )
                    members[name] = read_zip_member(site_zip.name, archive, info)
                validate_open_regular_file(
                    site_file,
                    "hosted Linux repository site ZIP",
                    max_bytes=MAX_SITE_ZIP_BYTES,
                )
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"{site_zip.name} is not a readable zip archive") from exc
    return members


def zip_member_failure(archive_name: str, reason: str) -> SystemExit:
    return SystemExit(f"{archive_name} {reason}; {MEMBER_FAILURE_GUARDS}")


def has_windows_drive_prefix(path: str) -> bool:
    return len(path) >= 2 and path[1] == ":" and path[0].isalpha()


def normalize_zip_path(archive_name: str, raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if (
        path.is_absolute()
        or normalized.startswith("//")
        or has_windows_drive_prefix(normalized)
        or ".." in parts
    ):
        raise zip_member_failure(archive_name, "contains unsafe hosted repository site path")
    if not parts:
        raise zip_member_failure(archive_name, "contains empty hosted repository site path")
    lowered = {part.lower() for part in parts}
    forbidden = sorted(lowered & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise zip_member_failure(archive_name, "contains forbidden local-state path")
    return "/".join(parts)


def validate_zip_member_for_read(site_name: str, info: zipfile.ZipInfo, name: str) -> bool:
    if info.flag_bits & 0x1:
        raise zip_member_failure(site_name, "contains encrypted zip member")
    file_type = (info.external_attr >> 16) & 0o170000
    is_directory = info.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise zip_member_failure(site_name, "contains unsupported link member")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise zip_member_failure(site_name, "contains unsupported member type")
    if is_directory:
        if info.file_size != 0:
            raise zip_member_failure(site_name, "contains directory member with data")
        return False
    if info.file_size > MAX_SITE_MEMBER_BYTES:
        raise zip_member_failure(site_name, "member is too large for Pages deployment")
    return True


def read_zip_member(site_name: str, archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    try:
        return archive.read(info)
    except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise zip_member_failure(site_name, "could not read zip member") from exc


def validate_site_members(site_name: str, version: str, members: dict[str, bytes]) -> None:
    hosted_bundle = f"conu-{version}-hosted-linux-repositories.zip"
    required = {
        ".nojekyll",
        "README.txt",
        "_headers",
        "cache-policy.json",
        "index.html",
        "repository.json",
        PUBLIC_KEY_NAME,
        f"{PUBLIC_KEY_NAME}.sha256",
        "apt/Packages",
        "apt/Packages.gz",
        "apt/Release",
        "apt/InRelease",
        "apt/Release.gpg",
        f"apt/{PUBLIC_KEY_NAME}",
        "rpm/repodata/repomd.xml",
        "rpm/repodata/repomd.xml.asc",
        f"rpm/{PUBLIC_KEY_NAME}",
        "install/README.txt",
        "install/conu.list",
        "install/conu.repo",
        f"downloads/{hosted_bundle}",
        f"downloads/{hosted_bundle}.sha256",
        f"downloads/{hosted_bundle}.asc",
    }
    missing = sorted(required - set(members))
    if missing:
        raise SystemExit(f"{site_name} is missing Pages member(s): {', '.join(missing)}")
    for name, data in members.items():
        validate_allowed_path(site_name, version, name)
        if is_text_member(name):
            assert_no_forbidden_text(data, f"{site_name}:{name}")
    base_url = validate_repository_json(version, members["repository.json"])
    validate_cache_policy_json(version, base_url, members["cache-policy.json"])
    validate_headers_file(members["_headers"])
    validate_key_and_signature_material(site_name, members)
    validate_downloaded_bundle(version, members)


def validate_allowed_path(site_name: str, version: str, name: str) -> None:
    hosted_bundle = f"conu-{version}-hosted-linux-repositories.zip"
    if name in {
        ".nojekyll",
        "README.txt",
        "_headers",
        "cache-policy.json",
        "index.html",
        "repository.json",
        PUBLIC_KEY_NAME,
        f"{PUBLIC_KEY_NAME}.sha256",
    }:
        return
    if name in {
        "install/README.txt",
        "install/conu.list",
        "install/conu.repo",
        f"downloads/{hosted_bundle}",
        f"downloads/{hosted_bundle}.sha256",
        f"downloads/{hosted_bundle}.asc",
    }:
        return
    if name.startswith(("apt/", "rpm/")):
        return
    raise SystemExit(f"{site_name} contains unexpected Pages member: {name}")


def validate_repository_json(version: str, data: bytes) -> str:
    try:
        repository = loads_json(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("repository.json is not ASCII JSON") from exc
    if repository.get("schema") != "conu.hostedLinuxRepository.site.v1":
        raise SystemExit("repository.json has unexpected schema")
    if repository.get("version") != version:
        raise SystemExit("repository.json version does not match site artifact name")
    base_url = repository.get("baseUrl")
    if not isinstance(base_url, str):
        raise SystemExit("repository.json baseUrl is missing")
    base_url = validate_repository_base_url(base_url)
    expected = {
        "payloadDisplayed": False,
        "tokenDisplayed": False,
        "keyMaterialDisplayed": False,
    }
    for key, value in expected.items():
        if repository.get(key) is not value:
            raise SystemExit(f"repository.json expected {key}=false")
    apt = repository.get("apt")
    rpm = repository.get("rpm")
    downloads = repository.get("downloads")
    if not isinstance(apt, dict) or not isinstance(rpm, dict) or not isinstance(downloads, dict):
        raise SystemExit("repository.json apt/rpm/download metadata is missing")
    hosted_bundle = f"conu-{version}-hosted-linux-repositories.zip"
    expected_paths = {
        "repository.json apt.repositoryUrl": (apt.get("repositoryUrl"), "/apt"),
        "repository.json apt.keyUrl": (apt.get("keyUrl"), f"/apt/{PUBLIC_KEY_NAME}"),
        "repository.json rpm.repositoryUrl": (rpm.get("repositoryUrl"), "/rpm"),
        "repository.json rpm.repoFileUrl": (rpm.get("repoFileUrl"), "/install/conu.repo"),
        "repository.json rpm.keyUrl": (rpm.get("keyUrl"), f"/rpm/{PUBLIC_KEY_NAME}"),
        "repository.json downloads.hostedBundleUrl": (
            downloads.get("hostedBundleUrl"),
            f"/downloads/{hosted_bundle}",
        ),
        "repository.json downloads.hostedBundleChecksumUrl": (
            downloads.get("hostedBundleChecksumUrl"),
            f"/downloads/{hosted_bundle}.sha256",
        ),
        "repository.json downloads.hostedBundleSignatureUrl": (
            downloads.get("hostedBundleSignatureUrl"),
            f"/downloads/{hosted_bundle}.asc",
        ),
    }
    for label, (actual, expected_path) in expected_paths.items():
        if url_to_base_path(base_url, actual, label) != expected_path:
            raise SystemExit(f"{label} does not match baseUrl")
    expected_source = f"deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY_NAME}] {base_url}/apt ./"
    if apt.get("sourceList") != expected_source:
        raise SystemExit("repository.json APT source list does not match baseUrl")
    cache_policy = repository.get("cachePolicy")
    if not isinstance(cache_policy, dict):
        raise SystemExit("repository.json cachePolicy metadata is missing")
    if url_to_base_path(
        base_url,
        cache_policy.get("policyUrl"),
        "repository.json cachePolicy.policyUrl",
    ) != "/cache-policy.json":
        raise SystemExit("repository.json cache policy URL does not match baseUrl")
    if url_to_base_path(
        base_url,
        cache_policy.get("headersFileUrl"),
        "repository.json cachePolicy.headersFileUrl",
    ) != "/_headers":
        raise SystemExit("repository.json cache headers URL does not match baseUrl")
    if cache_policy.get("hostMustApply") is not True:
        raise SystemExit("repository.json expected cachePolicy.hostMustApply=true")
    return base_url


def validate_repository_base_url(raw: str) -> str:
    parsed = urlparse(raw.strip())
    if parsed.username or parsed.password:
        raise SystemExit("repository.json baseUrl must not include credentials")
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("repository.json baseUrl must be an absolute https URL")
    if parsed.params or parsed.query or parsed.fragment:
        raise SystemExit("repository.json baseUrl must not include params, query, or fragment")
    netloc = normalize_url_netloc(parsed, "repository.json baseUrl")
    path_parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in path_parts):
        raise SystemExit("repository.json baseUrl path must not contain dot segments")
    decoded_parts = [unquote(part) for part in path_parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise SystemExit("repository.json baseUrl path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise SystemExit("repository.json baseUrl path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise SystemExit(
            "repository.json baseUrl path must not contain whitespace or control characters"
        )
    normalized_path = "/" + "/".join(path_parts) if path_parts else ""
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


def url_to_base_path(base_url: str, value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"{label} must be a URL string")
    parsed_base = urlparse(base_url)
    parsed_value = urlparse(value)
    if parsed_value.username or parsed_value.password:
        raise SystemExit(f"{label} must not include credentials")
    if parsed_value.params or parsed_value.query or parsed_value.fragment:
        raise SystemExit(f"{label} must not include params, query, or fragment")
    if (parsed_value.scheme, parsed_value.netloc.lower()) != (
        parsed_base.scheme,
        parsed_base.netloc.lower(),
    ):
        raise SystemExit(f"{label} points outside repository origin")
    base_path = parsed_base.path.rstrip("/")
    value_path = parsed_value.path.rstrip("/")
    path_parts = [part for part in parsed_value.path.split("/") if part]
    if any(part in {".", ".."} for part in path_parts):
        raise SystemExit(f"{label} path must not contain dot segments")
    decoded_parts = [unquote(part) for part in path_parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise SystemExit(f"{label} path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise SystemExit(f"{label} path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise SystemExit(f"{label} path must not contain whitespace or control characters")
    forbidden = sorted({part.lower() for part in decoded_parts} & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise SystemExit(
            f"{label} path contains forbidden local-state segment: {', '.join(forbidden)}"
        )
    if base_path:
        if value_path != base_path and not value_path.startswith(f"{base_path}/"):
            raise SystemExit(f"{label} points outside repository path")
        relative = value_path[len(base_path) :]
    else:
        relative = value_path
    if not relative.startswith("/"):
        relative = f"/{relative}"
    return validate_repository_path(relative or "/", f"{label} path")


def validate_repository_path(path: str, label: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise SystemExit(f"{label} must be an absolute path")
    if "\\" in path:
        raise SystemExit(f"{label} must not contain backslashes")
    if "?" in path or "#" in path:
        raise SystemExit(f"{label} must not contain query or fragment")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise SystemExit(f"{label} must not contain empty or dot segments")
    if any(has_url_path_control(part) for part in parts[1:]):
        raise SystemExit(f"{label} must not contain whitespace or control characters")
    forbidden = sorted({part.lower() for part in parts[1:]} & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise SystemExit(f"{label} contains forbidden local-state segment: {', '.join(forbidden)}")
    return path


def has_url_authority_control(value: str) -> bool:
    return any(ord(char) <= 32 or ord(char) == 127 or char in {"\\", "%"} for char in value)


def has_url_path_control(value: str) -> bool:
    return any(ord(char) <= 32 or ord(char) == 127 for char in value)


def validate_cache_policy_json(version: str, base_url: str, data: bytes) -> None:
    try:
        policy = loads_json(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("cache-policy.json is not ASCII JSON") from exc
    if policy.get("schema") != CACHE_POLICY_SCHEMA:
        raise SystemExit("cache-policy.json has unexpected schema")
    if policy.get("version") != version:
        raise SystemExit("cache-policy.json version does not match site artifact name")
    if policy.get("baseUrl") != base_url:
        raise SystemExit("cache-policy.json baseUrl does not match repository.json")
    if policy.get("headersFile") != "_headers":
        raise SystemExit("cache-policy.json headersFile must be _headers")
    if policy.get("hostMustApply") is not True:
        raise SystemExit("cache-policy.json expected hostMustApply=true")
    for key, value in {
        "payloadDisplayed": False,
        "tokenDisplayed": False,
        "keyMaterialDisplayed": False,
    }.items():
        if policy.get(key) is not value:
            raise SystemExit(f"cache-policy.json expected {key}=false")
    actual_rules = []
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict):
            raise SystemExit("cache-policy.json contains non-object cache rule")
        paths = rule.get("paths")
        if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
            raise SystemExit("cache-policy.json contains invalid cache rule paths")
        actual_rules.append(
            {
                "kind": rule.get("kind"),
                "paths": tuple(paths),
                "cacheControl": rule.get("cacheControl"),
            }
        )
    expected_rules = [
        {
            "kind": rule["kind"],
            "paths": rule["paths"],
            "cacheControl": rule["cacheControl"],
        }
        for rule in CACHE_CONTROL_RULES
    ]
    if actual_rules != expected_rules:
        raise SystemExit("cache-policy.json cache rules do not match the generated repository policy")


def validate_headers_file(data: bytes) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("_headers is not ASCII") from exc
    entries = parse_headers_file(text)
    expected = {
        path: {"Cache-Control": rule["cacheControl"]}
        for rule in CACHE_CONTROL_RULES
        for path in rule["paths"]
    }
    if entries != expected:
        raise SystemExit("_headers cache rules do not match cache-policy.json")


def parse_headers_file(text: str) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    current_path: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            if current_path is None:
                raise SystemExit("_headers contains a header before any path")
            stripped = line.strip()
            if ":" not in stripped:
                raise SystemExit("_headers contains a malformed header line")
            name, value = stripped.split(":", 1)
            entries[current_path][name.strip()] = value.strip()
            continue
        current_path = line.strip()
        if not current_path.startswith("/"):
            raise SystemExit("_headers contains a non-absolute path")
        if current_path in entries:
            raise SystemExit(f"_headers contains duplicate path: {current_path}")
        entries[current_path] = {}
    return entries


def validate_key_and_signature_material(site_name: str, members: dict[str, bytes]) -> None:
    for name in (PUBLIC_KEY_NAME, f"apt/{PUBLIC_KEY_NAME}", f"rpm/{PUBLIC_KEY_NAME}"):
        if b"BEGIN PGP PUBLIC KEY BLOCK" not in members[name]:
            raise SystemExit(f"{site_name}:{name} is not armored public key material")
    for name in ("apt/Release.gpg", "rpm/repodata/repomd.xml.asc"):
        if b"BEGIN PGP SIGNATURE" not in members[name]:
            raise SystemExit(f"{site_name}:{name} is not armored signature material")
    if b"BEGIN PGP SIGNED MESSAGE" not in members["apt/InRelease"]:
        raise SystemExit(f"{site_name}:apt/InRelease is not armored signed metadata")


def validate_downloaded_bundle(version: str, members: dict[str, bytes]) -> None:
    hosted_bundle = f"conu-{version}-hosted-linux-repositories.zip"
    bundle_path = f"downloads/{hosted_bundle}"
    checksum_path = f"{bundle_path}.sha256"
    signature_path = f"{bundle_path}.asc"
    checksum = members[checksum_path].decode("ascii")
    match = CHECKSUM_RE.fullmatch(checksum)
    if match is None:
        raise SystemExit(f"{checksum_path} has invalid SHA-256 sidecar format")
    if match.group(2) != hosted_bundle:
        raise SystemExit(f"{checksum_path} names wrong file: {match.group(2)}")
    actual = hashlib.sha256(members[bundle_path]).hexdigest()
    if match.group(1).lower() != actual:
        raise SystemExit(f"{checksum_path} does not match embedded hosted repository bundle")
    if b"BEGIN PGP SIGNATURE" not in members[signature_path]:
        raise SystemExit(f"{signature_path} is not armored signature material")


def extract_members(output_dir: Path, members: dict[str, bytes]) -> None:
    for name in sorted(members):
        path = (output_dir / name).resolve()
        if not path.is_relative_to(output_dir):
            raise SystemExit(f"hosted repository site extraction escaped output directory: {name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.resolve().is_relative_to(output_dir):
            raise SystemExit(f"hosted repository site extraction escaped output directory: {name}")
        write_bytes_output(
            path,
            "hosted repository Pages file",
            members[name],
            max_bytes=MAX_SITE_MEMBER_BYTES,
        )


def assert_no_forbidden_text(data: bytes, label: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{label} is not UTF-8 text") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{label} contains forbidden Pages deployment text: {forbidden}")


def is_text_member(name: str) -> bool:
    return name in TEXT_MEMBER_NAMES or name.endswith(TEXT_SUFFIXES)


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
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | OPEN_BINARY | OPEN_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SystemExit(f"{label} output must not be a symlink: {path.name}") from exc
        if exc.errno == errno.EEXIST:
            raise SystemExit(f"{label} output already exists: {path.name}") from exc
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


def write_bytes_output(path: Path, label: str, data: bytes, *, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large for Pages deployment: {path.name}")
    with open_output_file(path, label) as handle:
        handle.write(data)
        handle.flush()
        validate_open_regular_file(handle, label, max_bytes=max_bytes)
    validate_regular_file(path, label, max_bytes=max_bytes)


def read_ascii_file(path: Path, label: str, *, max_bytes: int) -> str:
    data = read_regular_file(path, label, max_bytes=max_bytes)
    return data.decode("ascii")


def read_regular_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    handle, _size = open_regular_file(path, label, max_bytes=max_bytes)
    with handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SystemExit(f"{label} is too large for Pages deployment: {path.name}")
    return data


def sha256_file(
    path: Path,
    label: str = "hosted repository Pages file",
    *,
    max_bytes: int = MAX_SITE_ZIP_BYTES,
) -> str:
    handle, _size = open_regular_file(path, label, max_bytes=max_bytes)
    with handle:
        return sha256_open_file(handle, label, max_bytes=max_bytes)


def sha256_open_file(handle: BinaryIO, label: str, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    if handle.writable():
        handle.flush()
    handle.seek(0)
    total = 0
    while True:
        chunk = handle.read(HASH_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise SystemExit(f"{label} is too large for Pages deployment")
        digest.update(chunk)
    handle.seek(0, os.SEEK_END)
    return digest.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
