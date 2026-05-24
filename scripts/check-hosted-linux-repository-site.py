#!/usr/bin/env python3
"""Regression checks for hosted Linux repository site artifact generation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE_GENERATOR = ROOT / "scripts" / "generate-hosted-linux-repository-site.py"
BUNDLE_CHECKER = ROOT / "scripts" / "check-hosted-linux-repositories.py"
VERSION = "0.1.0"
BASE_URL = "https://packages.example.com/conu"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
SITE_BUNDLE = f"conu-{VERSION}-hosted-linux-repository-site.zip"
PUBLIC_KEY = "conu-linux-gpg-key.asc"
ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
CACHE_CONTROL_RULES = (
    {
        "kind": "mutable-site-metadata",
        "cacheControl": "no-cache",
        "paths": (
            "/README.txt",
            "/index.html",
            "/repository.json",
            "/cache-policy.json",
            "/_headers",
            "/install/*",
            f"/{PUBLIC_KEY}",
            f"/{PUBLIC_KEY}.sha256",
            f"/apt/{PUBLIC_KEY}",
            f"/apt/{PUBLIC_KEY}.sha256",
            f"/rpm/{PUBLIC_KEY}",
            f"/rpm/{PUBLIC_KEY}.sha256",
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


def main() -> int:
    bundle_checker = load_bundle_checker()
    with tempfile.TemporaryDirectory(prefix="conu-hosted-linux-site-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        output = temp / "output"
        repeat = temp / "repeat"
        dist.mkdir()
        output.mkdir()
        repeat.mkdir()

        bundle_checker.write_signed_dist(dist)
        bundle_checker.run_generator(dist, dist)
        hosted_bundle = dist / HOSTED_BUNDLE
        write_signature(hosted_bundle)
        run_generator(dist, output, BASE_URL)
        site = output / SITE_BUNDLE
        assert_sha256_sidecar(site)
        assert_site_bundle(site, hosted_bundle)

        run_generator(dist, repeat, BASE_URL)
        if site.read_bytes() != (repeat / SITE_BUNDLE).read_bytes():
            raise AssertionError("hosted Linux repository site artifact was not deterministic")

        missing_signature = temp / "missing-signature"
        shutil.copytree(dist, missing_signature)
        (missing_signature / f"{HOSTED_BUNDLE}.asc").unlink()
        expect_failure(
            "missing hosted bundle signature",
            missing_signature,
            BASE_URL,
            "missing detached signature",
        )

        unsafe_bundle = temp / "unsafe-bundle"
        shutil.copytree(dist, unsafe_bundle)
        with zipfile.ZipFile(unsafe_bundle / HOSTED_BUNDLE, "w", compression=zipfile.ZIP_STORED) as archive:
            write_zip_bytes(archive, "../apt/Packages", b"Package: conu\n")
        write_checksum(unsafe_bundle / HOSTED_BUNDLE)
        write_signature(unsafe_bundle / HOSTED_BUNDLE)
        expect_failure(
            "unsafe hosted bundle member",
            unsafe_bundle,
            BASE_URL,
            "unsafe hosted repository zip path",
        )

        expect_failure(
            "insecure base URL",
            dist,
            "http://packages.example.com/conu",
            "absolute https URL",
        )

        bad_url = temp / "bad-url"
        shutil.copytree(dist, bad_url)
        expect_failure(
            "base URL with query",
            bad_url,
            "https://packages.example.com/conu?token=secret",
            "must not include params, query, or fragment",
        )

    print("Hosted Linux repository site regression checks passed")
    return 0


def load_bundle_checker():
    spec = importlib.util.spec_from_file_location(
        "check_hosted_linux_repositories",
        BUNDLE_CHECKER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository bundle checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_generator(dist: Path, output: Path, base_url: str) -> str:
    return subprocess.run(
        [
            sys.executable,
            str(SITE_GENERATOR),
            str(dist),
            "--output-dir",
            str(output),
            "--version",
            VERSION,
            "--base-url",
            base_url,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def expect_failure(description: str, dist: Path, base_url: str, expected: str) -> None:
    failed = subprocess.run(
        [
            sys.executable,
            str(SITE_GENERATOR),
            str(dist),
            "--output-dir",
            str(dist / "out"),
            "--version",
            VERSION,
            "--base-url",
            base_url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if failed.returncode == 0 or expected not in failed.stdout:
        raise AssertionError(
            f"{description} failed with {failed.stdout!r}, expected {expected!r}"
        )


def assert_site_bundle(site: Path, hosted_bundle: Path) -> None:
    hosted_members = read_zip_members(hosted_bundle)
    expected = sorted(
        {
            ".nojekyll",
            "README.txt",
            "_headers",
            "cache-policy.json",
            "index.html",
            "repository.json",
            "install/README.txt",
            "install/conu.list",
            "install/conu.repo",
            f"downloads/{HOSTED_BUNDLE}",
            f"downloads/{HOSTED_BUNDLE}.sha256",
            f"downloads/{HOSTED_BUNDLE}.asc",
            *hosted_members,
        }
    )
    with zipfile.ZipFile(site) as archive:
        names = archive.namelist()
        if names != expected:
            raise AssertionError(f"{site.name} had members {names!r}")
        for name in names:
            info = archive.getinfo(name)
            if info.date_time != ZIP_TIMESTAMP:
                raise AssertionError(f"{site.name}:{name} was not timestamp-normalized")
            mode = (info.external_attr >> 16) & 0o777
            if mode != 0o644:
                raise AssertionError(f"{site.name}:{name} had mode {oct(mode)}")
        contents = {name: archive.read(name) for name in names}

    repository = json.loads(contents["repository.json"].decode("ascii"))
    if repository["schema"] != "conu.hostedLinuxRepository.site.v1":
        raise AssertionError("repository.json schema was wrong")
    if repository["baseUrl"] != BASE_URL:
        raise AssertionError("repository.json base URL was wrong")
    if repository["apt"]["sourceList"] != (
        f"deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY}] {BASE_URL}/apt ./"
    ):
        raise AssertionError("repository.json APT source was wrong")
    if repository["rpm"]["repositoryUrl"] != f"{BASE_URL}/rpm":
        raise AssertionError("repository.json RPM URL was wrong")
    if repository["downloads"]["hostedBundleUrl"] != f"{BASE_URL}/downloads/{HOSTED_BUNDLE}":
        raise AssertionError("repository.json hosted bundle URL was wrong")
    if repository["cachePolicy"] != {
        "policyUrl": f"{BASE_URL}/cache-policy.json",
        "headersFileUrl": f"{BASE_URL}/_headers",
        "hostMustApply": True,
    }:
        raise AssertionError("repository.json cache policy metadata was wrong")
    for guard in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if repository[guard] is not False:
            raise AssertionError(f"repository.json expected {guard}=false")

    assert_cache_policy_json(contents["cache-policy.json"])
    assert_headers_file(contents["_headers"])

    apt_source = contents["install/conu.list"].decode("ascii")
    if BASE_URL not in apt_source or "/apt" not in apt_source:
        raise AssertionError("APT source snippet missed base URL")
    install_readme = contents["install/README.txt"].decode("ascii")
    if "sudo apt install conu" not in install_readme:
        raise AssertionError("install README missed APT install command")
    if "sudo dnf install conu" not in install_readme:
        raise AssertionError("install README missed YUM/DNF install command")
    index = contents["index.html"].decode("ascii")
    if "repository.json" not in index or "sudo apt install conu" not in index:
        raise AssertionError("index page missed repository metadata or install commands")
    if "cache-policy.json" not in index or "_headers" not in index:
        raise AssertionError("index page missed cache policy metadata")
    yum_repo = contents["install/conu.repo"].decode("ascii")
    if f"baseurl={BASE_URL}/rpm" not in yum_repo or "repo_gpgcheck=1" not in yum_repo:
        raise AssertionError("YUM repo snippet missed signed repository settings")
    if contents[f"downloads/{HOSTED_BUNDLE}"] != hosted_bundle.read_bytes():
        raise AssertionError("site download bundle did not match hosted bundle")
    if contents[f"downloads/{HOSTED_BUNDLE}.sha256"] != hosted_bundle.with_name(
        f"{HOSTED_BUNDLE}.sha256"
    ).read_bytes():
        raise AssertionError("site bundle checksum did not match hosted bundle checksum")
    if contents[f"downloads/{HOSTED_BUNDLE}.asc"] != hosted_bundle.with_name(
        f"{HOSTED_BUNDLE}.asc"
    ).read_bytes():
        raise AssertionError("site bundle signature did not match hosted bundle signature")
    for name in hosted_members:
        if name == "README.txt":
            continue
        if contents[name] != hosted_members[name]:
            raise AssertionError(f"site member {name} did not match hosted bundle member")
    for name, data in contents.items():
        if is_text_member(name):
            text = data.decode("utf-8")
            for forbidden in (
                "BEGIN PGP PRIVATE KEY BLOCK",
                "NPM_TOKEN",
                "CONU_RELAY_TOKEN",
                "token_sha256_hex",
                "payloadHex",
            ):
                if forbidden in text:
                    raise AssertionError(f"{name} contained forbidden text {forbidden!r}")


def assert_cache_policy_json(data: bytes) -> None:
    policy = json.loads(data.decode("ascii"))
    if policy["schema"] != CACHE_POLICY_SCHEMA:
        raise AssertionError("cache-policy.json schema was wrong")
    if policy["version"] != VERSION:
        raise AssertionError("cache-policy.json version was wrong")
    if policy["baseUrl"] != BASE_URL:
        raise AssertionError("cache-policy.json base URL was wrong")
    if policy["headersFile"] != "_headers":
        raise AssertionError("cache-policy.json headersFile was wrong")
    if policy["hostMustApply"] is not True:
        raise AssertionError("cache-policy.json expected hostMustApply=true")
    for guard in ("payloadDisplayed", "tokenDisplayed", "keyMaterialDisplayed"):
        if policy[guard] is not False:
            raise AssertionError(f"cache-policy.json expected {guard}=false")
    actual_rules = [
        {
            "kind": rule["kind"],
            "paths": tuple(rule["paths"]),
            "cacheControl": rule["cacheControl"],
        }
        for rule in policy["rules"]
    ]
    expected_rules = [
        {
            "kind": rule["kind"],
            "paths": rule["paths"],
            "cacheControl": rule["cacheControl"],
        }
        for rule in CACHE_CONTROL_RULES
    ]
    if actual_rules != expected_rules:
        raise AssertionError("cache-policy.json cache rules were wrong")


def assert_headers_file(data: bytes) -> None:
    entries = parse_headers_file(data.decode("ascii"))
    expected = {
        path: {"Cache-Control": rule["cacheControl"]}
        for rule in CACHE_CONTROL_RULES
        for path in rule["paths"]
    }
    if entries != expected:
        raise AssertionError(f"_headers had cache entries {entries!r}, expected {expected!r}")


def parse_headers_file(text: str) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    current_path: str | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            if current_path is None:
                raise AssertionError("_headers contained a header before any path")
            stripped = line.strip()
            if ":" not in stripped:
                raise AssertionError(f"_headers contained malformed header line {line!r}")
            name, value = stripped.split(":", 1)
            entries[current_path][name.strip()] = value.strip()
            continue
        current_path = line.strip()
        if not current_path.startswith("/"):
            raise AssertionError(f"_headers path was not absolute: {current_path!r}")
        if current_path in entries:
            raise AssertionError(f"_headers duplicated path: {current_path}")
        entries[current_path] = {}
    return entries


def is_text_member(name: str) -> bool:
    return name == "_headers" or name.endswith((".txt", ".json", ".html", ".list", ".repo", ".asc", ".sha256"))


def read_zip_members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def write_signature(path: Path) -> None:
    path.with_name(f"{path.name}.asc").write_text(
        "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
        encoding="ascii",
        newline="\n",
    )


def write_checksum(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash {path.name}")


def write_zip_bytes(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


if __name__ == "__main__":
    sys.exit(main())
