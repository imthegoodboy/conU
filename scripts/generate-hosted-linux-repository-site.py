#!/usr/bin/env python3
"""Generate a static site artifact for publishing conU Linux repositories."""

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
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_PACKAGE_JSON_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
MAX_HOSTED_BUNDLE_BYTES = 4 * 1024 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 512_000_000
MAX_ZIP_MEMBERS = 10_000
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 2_000_000_000
MEMBER_FAILURE_GUARDS = "pathDisplayed=false contentsDisplayed=false"
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
CACHE_CONTROL_RULES = (
    {
        "kind": "mutable-site-metadata",
        "cacheControl": "no-cache",
        "reason": "Install snippets, endpoint metadata, and trust-anchor files must revalidate before use.",
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
        "reason": "APT and RPM indexes can change on each release and should stay fresh for package managers.",
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
        "reason": "Versioned package payloads, sidecars, signatures, and hosted bundles are immutable release assets.",
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
FORBIDDEN_TEXT = (
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PRIVATE KEY",
    "NPM_TOKEN",
    "CONU_RELAY_TOKEN",
    "token_sha256_hex",
    "payloadHex",
    "ciphertext_body",
)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_BINARY = getattr(os, "O_BINARY", 0)


def main() -> int:
    args = parse_args()
    version = validate_version(args.version or read_repo_version())
    base_url = validate_base_url(args.base_url or os.environ.get("CONU_LINUX_REPOSITORY_BASE_URL", ""))
    dist = args.dist.expanduser()
    output_dir = args.output_dir.expanduser()
    validate_input_directory(dist, "release dist directory")
    prepare_output_directory(output_dir, "hosted repository site output directory")
    dist = dist.resolve()
    output_dir = output_dir.resolve()

    bundle = required_asset(
        dist / hosted_repository_bundle_filename(version),
        "hosted Linux repository bundle",
    )
    signature = require_detached_signature(bundle)
    bundle_members = read_hosted_bundle(bundle)
    validate_hosted_bundle_members(bundle.name, bundle_members)

    site_members = build_site_members(
        version=version,
        base_url=base_url,
        bundle=bundle,
        signature=signature,
        bundle_members=bundle_members,
    )
    output = output_dir / hosted_repository_site_filename(version)
    validate_output_file(output, "hosted Linux repository site artifact")
    validate_output_file(
        output.with_name(f"{output.name}.sha256"),
        "hosted Linux repository site artifact SHA-256 sidecar",
    )
    write_zip_members(output, site_members)
    write_sha256_sidecar(output)
    print(f"generated hosted Linux repository site: {output.name}, {output.name}.sha256")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing signed release assets")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="directory receiving the hosted repository site artifact",
    )
    parser.add_argument("--version", help="release version; defaults to npm package version")
    parser.add_argument(
        "--base-url",
        help=(
            "HTTPS base URL where the extracted site will be served; "
            "defaults to CONU_LINUX_REPOSITORY_BASE_URL"
        ),
    )
    return parser.parse_args()


def read_repo_version() -> str:
    package_json = Path(__file__).resolve().parents[1] / "packaging/npm/conu-cli/package.json"
    package_data = read_regular_file(
        package_json,
        "npm package metadata",
        max_bytes=MAX_PACKAGE_JSON_BYTES,
    )
    return parse_package_version(package_json, package_data, "hosted Linux repository site")


def parse_package_version(package_json: Path, package_data: bytes, context: str) -> str:
    try:
        package = loads_json(package_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{package_json} is not valid UTF-8 JSON") from exc
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{package_json} does not contain a non-empty version for {context}")
    return version


def validate_version(version: str) -> str:
    if not SEMVER_RE.fullmatch(version):
        raise SystemExit(f"invalid release version for hosted Linux repository site: {version}")
    return version


def validate_base_url(raw: str) -> str:
    if not raw:
        raise SystemExit(
            "missing hosted Linux repository base URL; pass --base-url or set "
            "CONU_LINUX_REPOSITORY_BASE_URL"
        )
    parsed = urlparse(raw)
    if parsed.username or parsed.password:
        raise SystemExit("hosted Linux repository base URL must not include credentials")
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("hosted Linux repository base URL must be an absolute https URL")
    if parsed.params or parsed.query or parsed.fragment:
        raise SystemExit("hosted Linux repository base URL must not include params, query, or fragment")
    netloc = normalize_url_netloc(parsed, "hosted Linux repository base URL")
    parts = [part for part in parsed.path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise SystemExit("hosted Linux repository base URL path must not contain dot segments")
    decoded_parts = [unquote(part) for part in parts]
    if any(part in {".", ".."} for part in decoded_parts):
        raise SystemExit("hosted Linux repository base URL path must not contain dot segments")
    if any("/" in part or "\\" in part for part in decoded_parts):
        raise SystemExit("hosted Linux repository base URL path must not contain encoded separators")
    if any(has_url_path_control(part) for part in decoded_parts):
        raise SystemExit(
            "hosted Linux repository base URL path must not contain whitespace or control characters"
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


def hosted_repository_bundle_filename(version: str) -> str:
    return f"conu-{version}-hosted-linux-repositories.zip"


def hosted_repository_site_filename(version: str) -> str:
    return f"conu-{version}-hosted-linux-repository-site.zip"


def required_asset(path: Path, label: str, *, max_bytes: int = MAX_HOSTED_BUNDLE_BYTES) -> Path:
    validate_regular_file(path, label, max_bytes=max_bytes)
    verify_sha256_sidecar(path, label)
    return path


def require_detached_signature(path: Path) -> Path:
    signature = path.with_name(f"{path.name}.asc")
    validate_regular_file(
        signature,
        "detached signature for hosted Linux repository site input",
        max_bytes=MAX_SIGNATURE_BYTES,
    )
    try:
        signature_text = read_ascii_file(
            signature,
            "detached signature for hosted Linux repository site input",
            max_bytes=MAX_SIGNATURE_BYTES,
        )
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")
    if "PRIVATE KEY BLOCK" in signature_text:
        raise SystemExit(f"detached signature contains private key material: {signature.name}")
    return signature


def read_hosted_bundle(bundle: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_uncompressed = 0
    try:
        bundle_file, _size = open_regular_file(
            bundle,
            "hosted Linux repository bundle",
            max_bytes=MAX_HOSTED_BUNDLE_BYTES,
        )
        with bundle_file:
            with zipfile.ZipFile(bundle_file) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ZIP_MEMBERS:
                    raise SystemExit(f"{bundle.name} contains more than {MAX_ZIP_MEMBERS} members")
                for member in infos:
                    name = normalize_zip_path(bundle.name, member.filename)
                    if not validate_zip_member_for_read(bundle.name, member, name):
                        continue
                    if name in members:
                        raise zip_member_failure(bundle.name, "contains duplicate zip member")
                    total_uncompressed += member.file_size
                    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                        raise SystemExit(
                            f"{bundle.name} uncompressed ZIP contents exceed "
                            f"{MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES} bytes"
                        )
                    members[name] = read_zip_member(bundle.name, archive, member)
                validate_open_regular_file(
                    bundle_file,
                    "hosted Linux repository bundle",
                    max_bytes=MAX_HOSTED_BUNDLE_BYTES,
                )
    except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise zip_member_failure(bundle.name, "is not a readable zip archive") from exc
    return members


def validate_zip_member_for_read(bundle_name: str, member: zipfile.ZipInfo, name: str) -> bool:
    if member.flag_bits & 0x1:
        raise zip_member_failure(bundle_name, "contains encrypted zip member")
    file_type = (member.external_attr >> 16) & 0o170000
    is_directory = member.is_dir() or file_type == stat.S_IFDIR
    if file_type == stat.S_IFLNK:
        raise zip_member_failure(bundle_name, "contains unsupported link member")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise zip_member_failure(bundle_name, "contains unsupported zip member")
    if is_directory:
        if member.file_size != 0:
            raise zip_member_failure(bundle_name, "contains directory member with data")
        return False
    if member.file_size > MAX_ZIP_MEMBER_BYTES:
        raise zip_member_failure(bundle_name, "zip member is too large")
    return True


def read_zip_member(bundle_name: str, archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> bytes:
    try:
        return archive.read(member)
    except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise zip_member_failure(bundle_name, "could not read zip member") from exc


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
        raise zip_member_failure(archive_name, "contains unsafe hosted repository zip path")
    if not parts:
        raise zip_member_failure(archive_name, "contains empty hosted repository zip path")
    return "/".join(parts)


def validate_hosted_bundle_members(bundle_name: str, members: dict[str, bytes]) -> None:
    required = {
        "README.txt",
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
    }
    missing = sorted(required - set(members))
    if missing:
        raise SystemExit(f"{bundle_name} is missing hosted repository member(s): {', '.join(missing)}")
    for name in members:
        if not (
            name == "README.txt"
            or name == PUBLIC_KEY_NAME
            or name == f"{PUBLIC_KEY_NAME}.sha256"
            or name.startswith("apt/")
            or name.startswith("rpm/")
        ):
            raise SystemExit(f"{bundle_name} contains unexpected hosted repository member: {name}")
        if name.endswith(".mailbox") or name.endswith(".session") or ".conu" in name:
            raise SystemExit(f"{bundle_name} contains forbidden conU state path: {name}")
    for name, data in members.items():
        if name.endswith((".txt", ".json", ".html", ".list", ".repo", ".asc", ".sha256")):
            assert_no_forbidden_text(data, f"{bundle_name}:{name}")
    public_key = members[PUBLIC_KEY_NAME]
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
        raise SystemExit(f"{bundle_name} root public key is not armored public key material")
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in members[f"apt/{PUBLIC_KEY_NAME}"]:
        raise SystemExit(f"{bundle_name} APT public key is not armored public key material")
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in members[f"rpm/{PUBLIC_KEY_NAME}"]:
        raise SystemExit(f"{bundle_name} RPM public key is not armored public key material")
    if b"BEGIN PGP SIGNED MESSAGE" not in members["apt/InRelease"]:
        raise SystemExit(f"{bundle_name} APT InRelease is not armored signed metadata")
    if b"BEGIN PGP SIGNATURE" not in members["apt/Release.gpg"]:
        raise SystemExit(f"{bundle_name} APT Release.gpg is not armored signature material")
    if b"BEGIN PGP SIGNATURE" not in members["rpm/repodata/repomd.xml.asc"]:
        raise SystemExit(f"{bundle_name} RPM repomd.xml.asc is not armored signature material")


def build_site_members(
    *,
    version: str,
    base_url: str,
    bundle: Path,
    signature: Path,
    bundle_members: dict[str, bytes],
) -> dict[str, bytes]:
    members = {name: data for name, data in bundle_members.items()}
    members[".nojekyll"] = b""
    members["README.txt"] = render_site_readme(version, base_url).encode("ascii")
    members["_headers"] = render_headers_file().encode("ascii")
    members["cache-policy.json"] = render_cache_policy_json(version, base_url).encode("ascii")
    members["index.html"] = render_index_html(version, base_url).encode("ascii")
    members["repository.json"] = render_repository_json(version, base_url).encode("ascii")
    members["install/README.txt"] = render_install_readme(version, base_url).encode("ascii")
    members["install/conu.list"] = render_apt_source(base_url).encode("ascii")
    members["install/conu.repo"] = render_yum_repo(base_url).encode("ascii")
    members[f"downloads/{bundle.name}"] = read_regular_file(
        bundle,
        "hosted Linux repository bundle",
        max_bytes=MAX_HOSTED_BUNDLE_BYTES,
    )
    members[f"downloads/{bundle.name}.sha256"] = read_regular_file(
        bundle.with_name(f"{bundle.name}.sha256"),
        "SHA-256 sidecar for hosted Linux repository bundle",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    members[f"downloads/{bundle.name}.asc"] = read_regular_file(
        signature,
        "detached signature for hosted Linux repository bundle",
        max_bytes=MAX_SIGNATURE_BYTES,
    )
    for name, data in members.items():
        if is_text_member(name):
            assert_no_forbidden_text(data, name)
    return members


def render_site_readme(version: str, base_url: str) -> str:
    return f"""conU {version} hosted Linux repository site

This archive is ready to extract onto an operator-controlled static HTTPS
endpoint at:

{base_url}

It contains public APT and YUM/DNF repository files, public GPG key material,
public signatures, public checksums, install snippets, and public cache policy
metadata only. It does not contain signing secrets, npm tokens, relay tokens,
conU state, logs, inboxes, private payloads, private keys, or package-manager
repository credentials.
"""


def render_index_html(version: str, base_url: str) -> str:
    apt_source = html_escape(f"deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY_NAME}] {base_url}/apt ./")
    rpm_source = html_escape(f"{base_url}/rpm")
    apt_commands = html_escape(
        "\n".join(
            [
                "sudo install -d -m 0755 /usr/share/keyrings",
                f"curl -fsSL {base_url}/apt/{PUBLIC_KEY_NAME} | sudo tee /usr/share/keyrings/{PUBLIC_KEY_NAME} >/dev/null",
                f"curl -fsSL {base_url}/install/conu.list | sudo tee /etc/apt/sources.list.d/conu.list >/dev/null",
                "sudo apt update",
                "sudo apt install conu",
            ]
        )
    )
    rpm_commands = html_escape(
        "\n".join(
            [
                f"sudo dnf config-manager --add-repo {base_url}/install/conu.repo",
                "sudo dnf install conu",
            ]
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>conU Linux repository {html_escape(version)}</title>
</head>
<body>
  <h1>conU Linux repository {html_escape(version)}</h1>
  <p>This endpoint serves signed conU APT and YUM/DNF repository files.</p>
  <h2>APT</h2>
  <pre>{apt_source}</pre>
  <pre>{apt_commands}</pre>
  <h2>YUM/DNF</h2>
  <pre>{rpm_source}</pre>
  <pre>{rpm_commands}</pre>
  <p>Verify {PUBLIC_KEY_NAME} against the published maintainer fingerprint before trusting packages.</p>
  <p>Machine-readable metadata is available in repository.json.</p>
  <p>Static hosting cache policy metadata is available in cache-policy.json and _headers.</p>
</body>
</html>
"""


def render_repository_json(version: str, base_url: str) -> str:
    data = {
        "schema": "conu.hostedLinuxRepository.site.v1",
        "version": version,
        "baseUrl": base_url,
        "apt": {
            "sourceList": f"deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY_NAME}] {base_url}/apt ./",
            "repositoryUrl": f"{base_url}/apt",
            "keyUrl": f"{base_url}/apt/{PUBLIC_KEY_NAME}",
        },
        "rpm": {
            "repositoryUrl": f"{base_url}/rpm",
            "repoFileUrl": f"{base_url}/install/conu.repo",
            "keyUrl": f"{base_url}/rpm/{PUBLIC_KEY_NAME}",
        },
        "downloads": {
            "hostedBundleUrl": f"{base_url}/downloads/conu-{version}-hosted-linux-repositories.zip",
            "hostedBundleChecksumUrl": f"{base_url}/downloads/conu-{version}-hosted-linux-repositories.zip.sha256",
            "hostedBundleSignatureUrl": f"{base_url}/downloads/conu-{version}-hosted-linux-repositories.zip.asc",
        },
        "cachePolicy": {
            "policyUrl": f"{base_url}/cache-policy.json",
            "headersFileUrl": f"{base_url}/_headers",
            "hostMustApply": True,
        },
        "payloadDisplayed": False,
        "tokenDisplayed": False,
        "keyMaterialDisplayed": False,
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def render_install_readme(version: str, base_url: str) -> str:
    return f"""conU {version} Linux repository install snippets

APT source:

deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY_NAME}] {base_url}/apt ./

APT install:

sudo install -d -m 0755 /usr/share/keyrings
curl -fsSL {base_url}/apt/{PUBLIC_KEY_NAME} | sudo tee /usr/share/keyrings/{PUBLIC_KEY_NAME} >/dev/null
curl -fsSL {base_url}/install/conu.list | sudo tee /etc/apt/sources.list.d/conu.list >/dev/null
sudo apt update
sudo apt install conu

YUM/DNF repo file:

{base_url}/install/conu.repo

YUM/DNF install:

sudo dnf config-manager --add-repo {base_url}/install/conu.repo
sudo dnf install conu

Before use, compare {PUBLIC_KEY_NAME} with the published maintainer
fingerprint. Keep this endpoint on HTTPS and serve files without rewriting the
apt/ or rpm/ paths after extraction. Apply cache-policy.json or _headers at the
static host so mutable repository metadata revalidates and versioned package
payloads can be cached immutably.
"""


def render_apt_source(base_url: str) -> str:
    return f"deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY_NAME}] {base_url}/apt ./\n"


def render_yum_repo(base_url: str) -> str:
    return f"""[conu]
name=conU
baseurl={base_url}/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey={base_url}/rpm/{PUBLIC_KEY_NAME}
metadata_expire=1h
"""


def render_cache_policy_json(version: str, base_url: str) -> str:
    data = {
        "schema": CACHE_POLICY_SCHEMA,
        "version": version,
        "baseUrl": base_url,
        "headersFile": "_headers",
        "hostMustApply": True,
        "rules": [
            {
                "kind": rule["kind"],
                "paths": list(rule["paths"]),
                "cacheControl": rule["cacheControl"],
                "reason": rule["reason"],
            }
            for rule in CACHE_CONTROL_RULES
        ],
        "payloadDisplayed": False,
        "tokenDisplayed": False,
        "keyMaterialDisplayed": False,
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def render_headers_file() -> str:
    lines = [
        "# conU hosted Linux repository cache policy",
        "# Apply these Cache-Control rules on static hosts that support _headers.",
        "# For other hosts, translate the same rules from cache-policy.json.",
    ]
    for rule in CACHE_CONTROL_RULES:
        lines.append("")
        lines.append(f"# {rule['kind']}: {rule['reason']}")
        for path in rule["paths"]:
            lines.append(path)
            lines.append(f"  Cache-Control: {rule['cacheControl']}")
    return "\n".join(lines) + "\n"


def verify_sha256_sidecar(path: Path, label: str) -> str:
    validate_regular_file(path, label, max_bytes=MAX_HOSTED_BUNDLE_BYTES)
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
        raise SystemExit(
            f"SHA-256 sidecar for {label} {path.name} names wrong file: {match.group(2)}"
        )
    expected = match.group(1).lower()
    actual = sha256_file(path, label, max_bytes=MAX_HOSTED_BUNDLE_BYTES)
    if expected != actual:
        raise SystemExit(f"SHA-256 mismatch for {label}: {path.name}")
    return expected


def write_sha256_sidecar(path: Path) -> None:
    validate_regular_file(path, "hosted Linux repository site artifact", max_bytes=MAX_HOSTED_BUNDLE_BYTES)
    sidecar = path.with_name(f"{path.name}.sha256")
    write_text_output(
        sidecar,
        "hosted Linux repository site artifact SHA-256 sidecar",
        f"{sha256_file(path)}  {path.name}\n",
        max_bytes=MAX_CHECKSUM_BYTES,
    )
    validate_regular_file(
        sidecar,
        "hosted Linux repository site artifact SHA-256 sidecar",
        max_bytes=MAX_CHECKSUM_BYTES,
    )


def write_zip_members(path: Path, members: dict[str, bytes]) -> None:
    with open_output_file(path, "hosted Linux repository site artifact") as site_file:
        with zipfile.ZipFile(site_file, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in sorted(members):
                info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o644 << 16
                archive.writestr(info, members[name])
        validate_open_regular_file(
            site_file,
            "hosted Linux repository site artifact",
            max_bytes=MAX_HOSTED_BUNDLE_BYTES,
        )
    validate_regular_file(path, "hosted Linux repository site artifact", max_bytes=MAX_HOSTED_BUNDLE_BYTES)


def assert_no_forbidden_text(data: bytes, label: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{label} is not UTF-8 text") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{label} contains forbidden release-site text: {forbidden}")


def is_text_member(name: str) -> bool:
    return name == "_headers" or name.endswith((".txt", ".json", ".html", ".list", ".repo", ".asc", ".sha256"))


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
            raise SystemExit(f"{label} is too large: {path.name}")
        return os.fdopen(fd, "rb"), metadata.st_size
    except BaseException:
        os.close(fd)
        raise


def validate_open_regular_file(handle: BinaryIO, label: str, *, max_bytes: int) -> int:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    if metadata.st_size > max_bytes:
        raise SystemExit(f"{label} is too large")
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
        raise SystemExit(f"{label} is too large: {path.name}")
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
        raise SystemExit(f"{label} is too large: {path.name}")
    return data


def sha256_file(
    path: Path,
    label: str = "hosted Linux repository site file",
    *,
    max_bytes: int = MAX_HOSTED_BUNDLE_BYTES,
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
            raise SystemExit(f"{label} is too large")
        digest.update(chunk)
    handle.seek(0, os.SEEK_END)
    return digest.hexdigest()


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


if __name__ == "__main__":
    sys.exit(main())
