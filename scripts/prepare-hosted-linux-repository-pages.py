#!/usr/bin/env python3
"""Prepare a verified hosted Linux repository site for GitHub Pages."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SITE_RE = re.compile(
    r"^conu-(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)-"
    r"hosted-linux-repository-site\.zip$"
)
HASH_CHUNK_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_SITE_ZIP_BYTES = 2 * 1024 * 1024 * 1024
MAX_SITE_MEMBERS = 10000
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


def main() -> int:
    args = parse_args()
    site_zip = find_site_zip(args.site, args.version)
    version = version_from_site_name(site_zip.name)
    verify_sha256_sidecar(site_zip, "hosted Linux repository site")
    require_detached_signature(site_zip)
    output_dir = args.output_dir.resolve()
    prepare_output_dir(output_dir)
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
    path = site.resolve()
    if path.is_file():
        if version is not None and f"conu-{version}-hosted-linux-repository-site.zip" != path.name:
            raise SystemExit(f"site ZIP {path.name} does not match requested version {version}")
        version_from_site_name(path.name)
        return path
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"hosted Linux repository site input does not exist: {site}")
    if version is not None:
        candidate = path / f"conu-{version}-hosted-linux-repository-site.zip"
        if not candidate.exists() or not candidate.is_file():
            raise SystemExit(f"missing hosted Linux repository site ZIP: {candidate.name}")
        return candidate
    candidates = sorted(item for item in path.glob("conu-*-hosted-linux-repository-site.zip") if item.is_file())
    if len(candidates) != 1:
        raise SystemExit(
            f"expected exactly one hosted Linux repository site ZIP in {path}, found {len(candidates)}"
        )
    version_from_site_name(candidates[0].name)
    return candidates[0]


def version_from_site_name(name: str) -> str:
    match = SITE_RE.fullmatch(name)
    if match is None:
        raise SystemExit(f"invalid hosted Linux repository site ZIP name: {name}")
    return match.group("version")


def verify_sha256_sidecar(path: Path, label: str) -> str:
    if path.stat().st_size > MAX_SITE_ZIP_BYTES:
        raise SystemExit(f"{label} is too large for Pages deployment: {path.name}")
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
        raise SystemExit(f"SHA-256 sidecar for {label} names wrong file: {match.group(2)}")
    expected = match.group(1).lower()
    actual = sha256_file(path)
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")
    return expected


def require_detached_signature(path: Path) -> None:
    signature = path.with_name(f"{path.name}.asc")
    if not signature.exists() or not signature.is_file():
        raise SystemExit(f"missing detached signature for hosted Linux repository site: {signature.name}")
    if signature.stat().st_size > MAX_SIGNATURE_BYTES:
        raise SystemExit(f"detached signature is too large: {signature.name}")
    try:
        signature_text = signature.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")


def prepare_output_dir(output_dir: Path) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"Pages output directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)


def read_site_members(site_zip: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(site_zip) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_SITE_MEMBERS:
                raise SystemExit(f"{site_zip.name} has too many members for Pages deployment")
            for info in infos:
                name = normalize_zip_path(info.filename)
                if info.is_dir():
                    continue
                reject_unsupported_member_type(info, name)
                if name in members:
                    raise SystemExit(f"{site_zip.name} contains duplicate zip member: {name}")
                members[name] = archive.read(info)
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"{site_zip.name} is not a readable zip archive") from exc
    return members


def normalize_zip_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe hosted repository site path: {raw_name}")
    if not parts:
        raise SystemExit(f"unsafe empty hosted repository site path: {raw_name}")
    lowered = {part.lower() for part in parts}
    forbidden = sorted(lowered & FORBIDDEN_SEGMENTS)
    if forbidden:
        raise SystemExit(f"hosted repository site contains forbidden local-state path: {'/'.join(parts)}")
    return "/".join(parts)


def reject_unsupported_member_type(info: zipfile.ZipInfo, name: str) -> None:
    mode = (info.external_attr >> 16) & 0o177777
    file_type = mode & 0o170000
    if file_type not in (0, 0o100000):
        raise SystemExit(f"hosted repository site contains unsupported member type: {name}")


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
        repository = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("repository.json is not ASCII JSON") from exc
    if repository.get("schema") != "conu.hostedLinuxRepository.site.v1":
        raise SystemExit("repository.json has unexpected schema")
    if repository.get("version") != version:
        raise SystemExit("repository.json version does not match site artifact name")
    base_url = repository.get("baseUrl")
    if not isinstance(base_url, str):
        raise SystemExit("repository.json baseUrl is missing")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.params or parsed.query or parsed.fragment:
        raise SystemExit("repository.json baseUrl must be an absolute https URL without params, query, or fragment")
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
    if not isinstance(apt, dict) or not isinstance(rpm, dict):
        raise SystemExit("repository.json apt/rpm metadata is missing")
    if apt.get("repositoryUrl") != f"{base_url}/apt":
        raise SystemExit("repository.json APT repository URL does not match baseUrl")
    if rpm.get("repositoryUrl") != f"{base_url}/rpm":
        raise SystemExit("repository.json RPM repository URL does not match baseUrl")
    cache_policy = repository.get("cachePolicy")
    if not isinstance(cache_policy, dict):
        raise SystemExit("repository.json cachePolicy metadata is missing")
    if cache_policy.get("policyUrl") != f"{base_url}/cache-policy.json":
        raise SystemExit("repository.json cache policy URL does not match baseUrl")
    if cache_policy.get("headersFileUrl") != f"{base_url}/_headers":
        raise SystemExit("repository.json cache headers URL does not match baseUrl")
    if cache_policy.get("hostMustApply") is not True:
        raise SystemExit("repository.json expected cachePolicy.hostMustApply=true")
    return base_url


def validate_cache_policy_json(version: str, base_url: str, data: bytes) -> None:
    try:
        policy = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
        path.write_bytes(members[name])


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
