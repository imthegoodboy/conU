#!/usr/bin/env python3
"""Regression checks for hosted Linux repository Pages preparation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE_CHECKER = ROOT / "scripts" / "check-hosted-linux-repository-site.py"
PAGES_PREPARER = ROOT / "scripts" / "prepare-hosted-linux-repository-pages.py"
VERSION = "0.1.0"
BASE_URL = "https://imthegoodboy.github.io/conU"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
SITE_BUNDLE = f"conu-{VERSION}-hosted-linux-repository-site.zip"
PUBLIC_KEY = "conu-linux-gpg-key.asc"
ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"


def main() -> int:
    site_checker = load_site_checker()
    bundle_checker = site_checker.load_bundle_checker()
    with tempfile.TemporaryDirectory(prefix="conu-hosted-linux-pages-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        pages = temp / "pages"
        dist.mkdir()
        pages.mkdir()

        bundle_checker.write_signed_dist(dist)
        bundle_checker.run_generator(dist, dist)
        hosted_bundle = dist / HOSTED_BUNDLE
        site_checker.write_signature(hosted_bundle)
        site_checker.run_generator(dist, dist, BASE_URL)
        site = dist / SITE_BUNDLE
        site_checker.write_signature(site)

        run_preparer(dist, pages)
        assert_pages_output(pages, site)

        preparer = load_pages_preparer()
        expect_zip_bound_failure(
            preparer,
            site,
            "MAX_SITE_MEMBER_BYTES",
            1,
            "member is too large",
            "Pages site member size bound",
        )
        expect_zip_bound_failure(
            preparer,
            site,
            "MAX_SITE_MEMBERS",
            1,
            "too many members",
            "Pages site member count bound",
        )
        expect_zip_bound_failure(
            preparer,
            site,
            "MAX_SITE_TOTAL_UNCOMPRESSED_BYTES",
            1,
            "uncompressed contents exceed",
            "Pages site total size bound",
        )

        encrypted_site = temp / "encrypted-site.zip"
        shutil.copy2(site, encrypted_site)
        mark_zip_member_encrypted(encrypted_site, "index.html")
        expect_action_failure(
            lambda: preparer.read_site_members(encrypted_site),
            "encrypted zip member",
            "encrypted Pages site member",
        )

        unsupported_site = temp / "unsupported-site.zip"
        with zipfile.ZipFile(unsupported_site, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("index.html", ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFCHR | 0o644) << 16
            archive.writestr(info, b"device\n")
        expect_action_failure(
            lambda: preparer.read_site_members(unsupported_site),
            "unsupported member type",
            "unsupported Pages site member",
        )

        missing_checksum = temp / "missing-checksum"
        shutil.copytree(dist, missing_checksum)
        (missing_checksum / f"{SITE_BUNDLE}.sha256").unlink()
        expect_failure(
            "missing site checksum",
            missing_checksum / SITE_BUNDLE,
            temp / "missing-checksum-pages",
            "missing SHA-256 sidecar",
        )

        missing_signature = temp / "missing-signature"
        shutil.copytree(dist, missing_signature)
        (missing_signature / f"{SITE_BUNDLE}.asc").unlink()
        expect_failure(
            "missing site signature",
            missing_signature / SITE_BUNDLE,
            temp / "missing-signature-pages",
            "missing detached signature",
        )

        private_key_signature = temp / "private-key-signature"
        shutil.copytree(dist, private_key_signature)
        (private_key_signature / f"{SITE_BUNDLE}.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\n"
            "fixture\n"
            "-----END PGP SIGNATURE-----\n"
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            "fixture\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n",
            encoding="ascii",
            newline="\n",
        )
        expect_failure(
            "private key site signature",
            private_key_signature / SITE_BUNDLE,
            temp / "private-key-signature-pages",
            "private key material",
        )

        symlink_site = temp / "symlink-site"
        shutil.copytree(dist, symlink_site)
        site_target = temp / "site-target.zip"
        shutil.copy2(site, site_target)
        (symlink_site / SITE_BUNDLE).unlink()
        if try_symlink(site_target, symlink_site / SITE_BUNDLE):
            expect_failure(
                "symlinked site ZIP",
                symlink_site,
                temp / "symlink-site-pages",
                "site ZIP must not be a symlink",
            )

        symlink_checksum = temp / "symlink-checksum"
        shutil.copytree(dist, symlink_checksum)
        checksum_target = temp / "site-target.zip.sha256"
        shutil.copy2(dist / f"{SITE_BUNDLE}.sha256", checksum_target)
        (symlink_checksum / f"{SITE_BUNDLE}.sha256").unlink()
        if try_symlink(checksum_target, symlink_checksum / f"{SITE_BUNDLE}.sha256"):
            expect_failure(
                "symlinked site checksum",
                symlink_checksum / SITE_BUNDLE,
                temp / "symlink-checksum-pages",
                "SHA-256 sidecar for hosted Linux repository site must not be a symlink",
            )

        symlink_signature = temp / "symlink-signature"
        shutil.copytree(dist, symlink_signature)
        signature_target = temp / "site-target.zip.asc"
        shutil.copy2(dist / f"{SITE_BUNDLE}.asc", signature_target)
        (symlink_signature / f"{SITE_BUNDLE}.asc").unlink()
        if try_symlink(signature_target, symlink_signature / f"{SITE_BUNDLE}.asc"):
            expect_failure(
                "symlinked site signature",
                symlink_signature / SITE_BUNDLE,
                temp / "symlink-signature-pages",
                "detached signature for hosted Linux repository site must not be a symlink",
            )

        unsafe = temp / "unsafe"
        shutil.copytree(dist, unsafe)
        rewrite_site_zip(unsafe / SITE_BUNDLE, {"../index.html": b"escape\n"})
        sign_site(unsafe / SITE_BUNDLE)
        expect_failure(
            "unsafe site member path",
            unsafe / SITE_BUNDLE,
            temp / "unsafe-pages",
            "unsafe hosted repository site path",
        )

        forbidden = temp / "forbidden"
        shutil.copytree(dist, forbidden)
        rewrite_site_zip(forbidden / SITE_BUNDLE, {"install/README.txt": b"NPM_TOKEN\n"})
        sign_site(forbidden / SITE_BUNDLE)
        expect_failure(
            "forbidden site text",
            forbidden / SITE_BUNDLE,
            temp / "forbidden-pages",
            "forbidden Pages deployment text",
        )

        unexpected_download = temp / "unexpected-download"
        shutil.copytree(dist, unexpected_download)
        rewrite_site_zip(unexpected_download / SITE_BUNDLE, {"downloads/extra.bin": b"not expected\n"})
        sign_site(unexpected_download / SITE_BUNDLE)
        expect_failure(
            "unexpected download member",
            unexpected_download / SITE_BUNDLE,
            temp / "unexpected-download-pages",
            "unexpected Pages member",
        )

        missing_cache_policy = temp / "missing-cache-policy"
        shutil.copytree(dist, missing_cache_policy)
        rewrite_site_zip(
            missing_cache_policy / SITE_BUNDLE,
            {},
            removals=("cache-policy.json",),
        )
        sign_site(missing_cache_policy / SITE_BUNDLE)
        expect_failure(
            "missing cache policy",
            missing_cache_policy / SITE_BUNDLE,
            temp / "missing-cache-policy-pages",
            "missing Pages member",
        )

        bad_cache_policy = temp / "bad-cache-policy"
        shutil.copytree(dist, bad_cache_policy)
        cache_policy = read_site_json_member(bad_cache_policy / SITE_BUNDLE, "cache-policy.json")
        cache_policy["tokenDisplayed"] = True
        rewrite_site_zip(
            bad_cache_policy / SITE_BUNDLE,
            {
                "cache-policy.json": json.dumps(cache_policy, indent=2, sort_keys=True).encode("ascii")
                + b"\n"
            },
        )
        sign_site(bad_cache_policy / SITE_BUNDLE)
        expect_failure(
            "cache policy display guard",
            bad_cache_policy / SITE_BUNDLE,
            temp / "bad-cache-policy-pages",
            "cache-policy.json expected tokenDisplayed=false",
        )

        bad_headers = temp / "bad-headers"
        shutil.copytree(dist, bad_headers)
        rewrite_site_zip(
            bad_headers / SITE_BUNDLE,
            {"_headers": b"/repository.json\n  Cache-Control: public, max-age=31536000, immutable\n"},
        )
        sign_site(bad_headers / SITE_BUNDLE)
        expect_failure(
            "bad cache headers",
            bad_headers / SITE_BUNDLE,
            temp / "bad-headers-pages",
            "_headers cache rules do not match cache-policy.json",
        )

        insecure = temp / "insecure"
        shutil.copytree(dist, insecure)
        repository = read_site_json(insecure / SITE_BUNDLE)
        repository["baseUrl"] = "http://imthegoodboy.github.io/conU"
        rewrite_site_zip(
            insecure / SITE_BUNDLE,
            {"repository.json": json.dumps(repository, indent=2, sort_keys=True).encode("ascii") + b"\n"},
        )
        sign_site(insecure / SITE_BUNDLE)
        expect_failure(
            "insecure repository URL",
            insecure / SITE_BUNDLE,
            temp / "insecure-pages",
            "absolute https URL",
        )

        encoded_base = temp / "encoded-base"
        shutil.copytree(dist, encoded_base)
        repository = read_site_json(encoded_base / SITE_BUNDLE)
        cache_policy = read_site_json_member(encoded_base / SITE_BUNDLE, "cache-policy.json")
        encoded_url = f"{BASE_URL}/%2e%2e%2fother"
        rewrite_repository_base_url(repository, encoded_url)
        cache_policy["baseUrl"] = encoded_url
        rewrite_site_zip(
            encoded_base / SITE_BUNDLE,
            {
                "repository.json": json.dumps(repository, indent=2, sort_keys=True).encode("ascii")
                + b"\n",
                "cache-policy.json": json.dumps(cache_policy, indent=2, sort_keys=True).encode("ascii")
                + b"\n",
            },
        )
        sign_site(encoded_base / SITE_BUNDLE)
        expect_failure(
            "encoded repository base URL",
            encoded_base / SITE_BUNDLE,
            temp / "encoded-base-pages",
            "baseUrl path must not contain encoded separators",
        )

        off_origin_key = temp / "off-origin-key"
        shutil.copytree(dist, off_origin_key)
        repository = read_site_json(off_origin_key / SITE_BUNDLE)
        repository["apt"]["keyUrl"] = "https://evil.example/conu-linux-gpg-key.asc"
        rewrite_site_zip(
            off_origin_key / SITE_BUNDLE,
            {"repository.json": json.dumps(repository, indent=2, sort_keys=True).encode("ascii") + b"\n"},
        )
        sign_site(off_origin_key / SITE_BUNDLE)
        expect_failure(
            "off-origin APT key URL",
            off_origin_key / SITE_BUNDLE,
            temp / "off-origin-key-pages",
            "repository.json apt.keyUrl points outside repository origin",
        )

        query_download = temp / "query-download"
        shutil.copytree(dist, query_download)
        repository = read_site_json(query_download / SITE_BUNDLE)
        repository["downloads"]["hostedBundleUrl"] += "?token=value"
        rewrite_site_zip(
            query_download / SITE_BUNDLE,
            {"repository.json": json.dumps(repository, indent=2, sort_keys=True).encode("ascii") + b"\n"},
        )
        sign_site(query_download / SITE_BUNDLE)
        expect_failure(
            "query download URL",
            query_download / SITE_BUNDLE,
            temp / "query-download-pages",
            "repository.json downloads.hostedBundleUrl must not include params, query, or fragment",
        )

        escaped_download = temp / "escaped-download"
        shutil.copytree(dist, escaped_download)
        repository = read_site_json(escaped_download / SITE_BUNDLE)
        repository["downloads"]["hostedBundleUrl"] = repository["downloads"][
            "hostedBundleUrl"
        ].replace("/downloads/", "/downloads/%2e%2e/")
        rewrite_site_zip(
            escaped_download / SITE_BUNDLE,
            {"repository.json": json.dumps(repository, indent=2, sort_keys=True).encode("ascii") + b"\n"},
        )
        sign_site(escaped_download / SITE_BUNDLE)
        expect_failure(
            "escaped download URL",
            escaped_download / SITE_BUNDLE,
            temp / "escaped-download-pages",
            "repository.json downloads.hostedBundleUrl path must not contain dot segments",
        )

        non_empty_output = temp / "non-empty"
        non_empty_output.mkdir()
        (non_empty_output / "existing.txt").write_text("existing\n", encoding="ascii")
        expect_failure(
            "non-empty output",
            dist / SITE_BUNDLE,
            non_empty_output,
            "must be empty",
        )

        output_target = temp / "output-target"
        output_target.mkdir()
        output_link = temp / "output-link"
        if try_symlink(output_target, output_link, target_is_directory=True):
            expect_failure(
                "symlinked output",
                dist / SITE_BUNDLE,
                output_link,
                "Pages output directory must not be a symlink",
            )

    print("Hosted Linux repository Pages regression checks passed")
    return 0


def load_site_checker():
    spec = importlib.util.spec_from_file_location(
        "check_hosted_linux_repository_site",
        SITE_CHECKER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository site checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_pages_preparer():
    spec = importlib.util.spec_from_file_location(
        "prepare_hosted_linux_repository_pages",
        PAGES_PREPARER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository Pages preparer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_preparer(site: Path, output_dir: Path) -> str:
    return subprocess.run(
        [
            sys.executable,
            str(PAGES_PREPARER),
            str(site),
            "--output-dir",
            str(output_dir),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def expect_failure(description: str, site: Path, output_dir: Path, expected: str) -> None:
    failed = subprocess.run(
        [
            sys.executable,
            str(PAGES_PREPARER),
            str(site),
            "--output-dir",
            str(output_dir),
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


def expect_zip_bound_failure(
    preparer,
    site: Path,
    constant_name: str,
    value: int,
    expected: str,
    label: str,
) -> None:
    original = getattr(preparer, constant_name)
    setattr(preparer, constant_name, value)
    try:
        expect_action_failure(
            lambda: preparer.read_site_members(site),
            expected,
            label,
        )
    finally:
        setattr(preparer, constant_name, original)


def expect_action_failure(action, expected: str, label: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected in message:
            return
        raise AssertionError(f"{label}: expected {expected!r}, got {message!r}") from exc
    raise AssertionError(f"{label}: expected failure containing {expected!r}")


def try_symlink(target: Path, link: Path, *, target_is_directory: bool = False) -> bool:
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


def assert_pages_output(pages: Path, site: Path) -> None:
    with zipfile.ZipFile(site) as archive:
        site_members = {name: archive.read(name) for name in archive.namelist()}
    extracted = {
        str(path.relative_to(pages)).replace("\\", "/"): path.read_bytes()
        for path in sorted(pages.rglob("*"))
        if path.is_file()
    }
    if extracted != site_members:
        raise AssertionError("Pages output did not match the hosted site ZIP members")
    required = [
        ".nojekyll",
        "_headers",
        "cache-policy.json",
        "index.html",
        "repository.json",
        "install/conu.list",
        "install/conu.repo",
        f"apt/{PUBLIC_KEY}",
        "apt/InRelease",
        f"rpm/{PUBLIC_KEY}",
        "rpm/repodata/repomd.xml.asc",
        f"downloads/{HOSTED_BUNDLE}",
        f"downloads/{HOSTED_BUNDLE}.sha256",
        f"downloads/{HOSTED_BUNDLE}.asc",
    ]
    for name in required:
        if name not in extracted:
            raise AssertionError(f"Pages output missed {name}")
    repository = json.loads(extracted["repository.json"].decode("ascii"))
    if repository["baseUrl"] != BASE_URL:
        raise AssertionError("Pages repository.json baseUrl was wrong")
    if repository["cachePolicy"] != {
        "policyUrl": f"{BASE_URL}/cache-policy.json",
        "headersFileUrl": f"{BASE_URL}/_headers",
        "hostMustApply": True,
    }:
        raise AssertionError("Pages repository.json cache policy metadata was wrong")
    if repository["payloadDisplayed"] is not False:
        raise AssertionError("Pages repository.json leaked payload display state")
    cache_policy = json.loads(extracted["cache-policy.json"].decode("ascii"))
    if cache_policy["schema"] != CACHE_POLICY_SCHEMA:
        raise AssertionError("Pages cache-policy.json schema was wrong")
    if cache_policy["baseUrl"] != BASE_URL or cache_policy["hostMustApply"] is not True:
        raise AssertionError("Pages cache-policy.json endpoint metadata was wrong")
    if cache_policy["payloadDisplayed"] is not False or cache_policy["tokenDisplayed"] is not False:
        raise AssertionError("Pages cache-policy.json leaked display state")
    headers = extracted["_headers"].decode("ascii")
    for expected in (
        "Cache-Control: no-cache",
        "Cache-Control: public, max-age=300, must-revalidate",
        "Cache-Control: public, max-age=31536000, immutable",
    ):
        if expected not in headers:
            raise AssertionError(f"Pages _headers missed {expected}")
    checksum = extracted[f"downloads/{HOSTED_BUNDLE}.sha256"].decode("ascii")
    expected_checksum = f"{hashlib.sha256(extracted[f'downloads/{HOSTED_BUNDLE}']).hexdigest()}  {HOSTED_BUNDLE}\n"
    if checksum != expected_checksum:
        raise AssertionError("Pages hosted bundle checksum did not match embedded download")


def rewrite_site_zip(
    path: Path,
    replacements: dict[str, bytes],
    *,
    removals: tuple[str, ...] = (),
) -> None:
    original_members: dict[str, bytes] = {}
    if path.exists():
        with zipfile.ZipFile(path) as archive:
            original_members = {name: archive.read(name) for name in archive.namelist()}
    for name in removals:
        original_members.pop(name, None)
    original_members.update(replacements)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(original_members):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            archive.writestr(info, original_members[name])
    write_checksum(path)


def read_site_json(path: Path) -> dict:
    return read_site_json_member(path, "repository.json")


def read_site_json_member(path: Path, name: str) -> dict:
    with zipfile.ZipFile(path) as archive:
        return json.loads(archive.read(name).decode("ascii"))


def rewrite_repository_base_url(repository: dict, base_url: str) -> None:
    repository["baseUrl"] = base_url
    repository["apt"]["sourceList"] = (
        f"deb [signed-by=/usr/share/keyrings/{PUBLIC_KEY}] {base_url}/apt ./"
    )
    repository["apt"]["repositoryUrl"] = f"{base_url}/apt"
    repository["apt"]["keyUrl"] = f"{base_url}/apt/{PUBLIC_KEY}"
    repository["rpm"]["repositoryUrl"] = f"{base_url}/rpm"
    repository["rpm"]["repoFileUrl"] = f"{base_url}/install/conu.repo"
    repository["rpm"]["keyUrl"] = f"{base_url}/rpm/{PUBLIC_KEY}"
    repository["downloads"]["hostedBundleUrl"] = f"{base_url}/downloads/{HOSTED_BUNDLE}"
    repository["downloads"]["hostedBundleChecksumUrl"] = (
        f"{base_url}/downloads/{HOSTED_BUNDLE}.sha256"
    )
    repository["downloads"]["hostedBundleSignatureUrl"] = (
        f"{base_url}/downloads/{HOSTED_BUNDLE}.asc"
    )
    repository["cachePolicy"]["policyUrl"] = f"{base_url}/cache-policy.json"
    repository["cachePolicy"]["headersFileUrl"] = f"{base_url}/_headers"


def sign_site(path: Path) -> None:
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


def mark_zip_member_encrypted(path: Path, member_name: str) -> None:
    data = bytearray(path.read_bytes())
    target = member_name.encode("utf-8")
    offset = 0
    while offset + 4 <= len(data):
        signature = int.from_bytes(data[offset : offset + 4], "little")
        if signature == 0x04034B50:
            name_length = int.from_bytes(data[offset + 26 : offset + 28], "little")
            extra_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
            name_start = offset + 30
            name_end = name_start + name_length
            compressed_size = int.from_bytes(data[offset + 18 : offset + 22], "little")
            if data[name_start:name_end] == target:
                flags = int.from_bytes(data[offset + 6 : offset + 8], "little") | 0x1
                data[offset + 6 : offset + 8] = flags.to_bytes(2, "little")
            offset = name_end + extra_length + compressed_size
            continue
        if signature == 0x02014B50:
            name_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
            extra_length = int.from_bytes(data[offset + 30 : offset + 32], "little")
            comment_length = int.from_bytes(data[offset + 32 : offset + 34], "little")
            name_start = offset + 46
            name_end = name_start + name_length
            if data[name_start:name_end] == target:
                flags = int.from_bytes(data[offset + 8 : offset + 10], "little") | 0x1
                data[offset + 8 : offset + 10] = flags.to_bytes(2, "little")
            offset = name_end + extra_length + comment_length
            continue
        offset += 1
    path.write_bytes(data)


if __name__ == "__main__":
    sys.exit(main())
