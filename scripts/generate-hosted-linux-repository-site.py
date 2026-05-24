#!/usr/bin/env python3
"""Generate a static site artifact for publishing conU Linux repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, urlunparse


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+([^ \t\r\n]+)(?:\r?\n)?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
HASH_CHUNK_BYTES = 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_SIGNATURE_BYTES = 1024 * 1024
ZIP_SOURCE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
PUBLIC_KEY_NAME = "conu-linux-gpg-key.asc"
FORBIDDEN_TEXT = (
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PRIVATE KEY",
    "NPM_TOKEN",
    "CONU_RELAY_TOKEN",
    "token_sha256_hex",
    "payloadHex",
    "ciphertext_body",
)


def main() -> int:
    args = parse_args()
    version = validate_version(args.version or read_repo_version())
    base_url = validate_base_url(args.base_url or os.environ.get("CONU_LINUX_REPOSITORY_BASE_URL", ""))
    dist = args.dist.resolve()
    output_dir = args.output_dir.resolve()
    if not dist.exists() or not dist.is_dir():
        raise SystemExit(f"release dist directory does not exist: {dist}")
    output_dir.mkdir(parents=True, exist_ok=True)

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
    with package_json.open("r", encoding="utf-8") as handle:
        package = json.load(handle)
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit(f"{package_json} does not contain a non-empty version")
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
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("hosted Linux repository base URL must be an absolute https URL")
    if parsed.params or parsed.query or parsed.fragment:
        raise SystemExit("hosted Linux repository base URL must not include params, query, or fragment")
    normalized_path = "/" + "/".join(part for part in parsed.path.split("/") if part)
    if normalized_path == "/":
        normalized_path = ""
    return urlunparse(("https", parsed.netloc, normalized_path, "", "", ""))


def hosted_repository_bundle_filename(version: str) -> str:
    return f"conu-{version}-hosted-linux-repositories.zip"


def hosted_repository_site_filename(version: str) -> str:
    return f"conu-{version}-hosted-linux-repository-site.zip"


def required_asset(path: Path, label: str) -> Path:
    if not path.exists() or not path.is_file():
        raise SystemExit(f"missing {label}: {path.name}")
    verify_sha256_sidecar(path, label)
    return path


def require_detached_signature(path: Path) -> Path:
    signature = path.with_name(f"{path.name}.asc")
    if not signature.exists() or not signature.is_file():
        raise SystemExit(f"missing detached signature for hosted Linux repository site input: {signature.name}")
    if signature.stat().st_size > MAX_SIGNATURE_BYTES:
        raise SystemExit(f"detached signature is too large: {signature.name}")
    try:
        signature_text = signature.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}") from exc
    if "BEGIN PGP SIGNATURE" not in signature_text:
        raise SystemExit(f"detached signature is not ASCII-armored: {signature.name}")
    return signature


def read_hosted_bundle(bundle: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(bundle) as archive:
            for member in archive.infolist():
                name = normalize_zip_path(member.filename)
                if member.is_dir():
                    continue
                if name in members:
                    raise SystemExit(f"{bundle.name} contains duplicate zip member: {name}")
                members[name] = archive.read(member)
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"{bundle.name} is not a readable zip archive") from exc
    return members


def normalize_zip_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", ".", "/"}]
    if path.is_absolute() or ".." in parts:
        raise SystemExit(f"unsafe hosted repository zip path: {raw_name}")
    if not parts:
        raise SystemExit(f"unsafe empty hosted repository zip path: {raw_name}")
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
    members["index.html"] = render_index_html(version, base_url).encode("ascii")
    members["repository.json"] = render_repository_json(version, base_url).encode("ascii")
    members["install/README.txt"] = render_install_readme(version, base_url).encode("ascii")
    members["install/conu.list"] = render_apt_source(base_url).encode("ascii")
    members["install/conu.repo"] = render_yum_repo(base_url).encode("ascii")
    members[f"downloads/{bundle.name}"] = bundle.read_bytes()
    members[f"downloads/{bundle.name}.sha256"] = bundle.with_name(f"{bundle.name}.sha256").read_bytes()
    members[f"downloads/{bundle.name}.asc"] = signature.read_bytes()
    for name, data in members.items():
        if name.endswith((".txt", ".json", ".html", ".list", ".repo", ".asc", ".sha256")):
            assert_no_forbidden_text(data, name)
    return members


def render_site_readme(version: str, base_url: str) -> str:
    return f"""conU {version} hosted Linux repository site

This archive is ready to extract onto an operator-controlled static HTTPS
endpoint at:

{base_url}

It contains public APT and YUM/DNF repository files, public GPG key material,
public signatures, public checksums, and install snippets only. It does not
contain signing secrets, npm tokens, relay tokens, conU state, logs, inboxes,
private payloads, private keys, or package-manager repository credentials.
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
apt/ or rpm/ paths after extraction.
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


def write_zip_members(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, ZIP_SOURCE_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            archive.writestr(info, members[name])


def assert_no_forbidden_text(data: bytes, label: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{label} is not UTF-8 text") from exc
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise SystemExit(f"{label} contains forbidden release-site text: {forbidden}")


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


if __name__ == "__main__":
    sys.exit(main())
