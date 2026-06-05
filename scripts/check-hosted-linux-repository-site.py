#!/usr/bin/env python3
"""Regression checks for hosted Linux repository site artifact generation."""

from __future__ import annotations

import hashlib
import importlib.util
import io
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
SITE_GENERATOR = ROOT / "scripts" / "generate-hosted-linux-repository-site.py"
BUNDLE_CHECKER = ROOT / "scripts" / "check-hosted-linux-repositories.py"
VERSION = "0.1.0"
BASE_URL = "https://packages.example.com/conu"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
SITE_BUNDLE = f"conu-{VERSION}-hosted-linux-repository-site.zip"
PUBLIC_KEY = "conu-linux-gpg-key.asc"
ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
CACHE_POLICY_SCHEMA = "conu.hostedLinuxRepository.cachePolicy.v1"
SENSITIVE_SENTINEL = "do-not-print-this-shadow-value"
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
            f"/{PUBLIC_KEY}",
            f"/{PUBLIC_KEY}.sha256",
            "/apt/README.txt",
            f"/apt/{PUBLIC_KEY}",
            f"/apt/{PUBLIC_KEY}.sha256",
            "/rpm/README.txt",
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

        site_generator = load_site_generator()
        expect_zip_bound_failure(
            site_generator,
            hosted_bundle,
            "MAX_ZIP_MEMBER_BYTES",
            1,
            "zip member is too large",
            "hosted bundle member size bound",
        )
        expect_zip_bound_failure(
            site_generator,
            hosted_bundle,
            "MAX_ZIP_MEMBERS",
            1,
            "contains more than",
            "hosted bundle member count bound",
        )
        expect_zip_bound_failure(
            site_generator,
            hosted_bundle,
            "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
            1,
            "uncompressed ZIP contents exceed",
            "hosted bundle total size bound",
        )

        oversized_input = temp / "secret-hosted-site-input-name-should-not-print.txt"
        oversized_input.write_bytes(b"oversized\n")
        message = expect_action_failure(
            lambda: site_generator.open_regular_file(
                oversized_input,
                "hosted repository site input",
                max_bytes=1,
            ),
            "hosted repository site input is too large",
            "oversized hosted repository site input",
        )
        assert_not_displayed(
            message,
            "oversized hosted repository site input",
            oversized_input.name,
        )

        original_open_regular_file = site_generator.open_regular_file
        try:
            site_generator.open_regular_file = lambda _path, _label, *, max_bytes: (
                io.BytesIO(b"xx"),
                2,
            )
            message = expect_action_failure(
                lambda: site_generator.read_regular_file(
                    Path("secret-hosted-site-read-name-should-not-print.txt"),
                    "hosted repository site read",
                    max_bytes=1,
                ),
                "hosted repository site read is too large",
                "oversized hosted repository site read",
            )
            assert_not_displayed(
                message,
                "oversized hosted repository site read",
                "secret-hosted-site-read-name-should-not-print.txt",
            )
        finally:
            site_generator.open_regular_file = original_open_regular_file

        oversized_output = temp / "secret-hosted-site-output-name-should-not-print.txt"
        message = expect_action_failure(
            lambda: site_generator.write_text_output(
                oversized_output,
                "hosted repository site output",
                "oversized",
                max_bytes=1,
            ),
            "hosted repository site output is too large",
            "oversized hosted repository site output",
        )
        assert_not_displayed(
            message,
            "oversized hosted repository site output",
            oversized_output.name,
        )

        unreadable_bundle = temp / "unreadable-hosted-bundle.zip"
        unreadable_bundle_payload = "secret-unreadable-hosted-bundle-should-not-print"
        unreadable_bundle.write_text(unreadable_bundle_payload, encoding="ascii")
        message = expect_action_failure(
            lambda: site_generator.read_hosted_bundle(unreadable_bundle),
            "not a readable zip archive",
            "unreadable hosted bundle",
        )
        assert_member_failure_redacted(
            message,
            "unreadable hosted bundle",
            unreadable_bundle_payload,
        )

        encrypted_bundle = temp / "encrypted-hosted-bundle.zip"
        shutil.copy2(hosted_bundle, encrypted_bundle)
        mark_zip_member_encrypted(encrypted_bundle, "apt/Packages")
        message = expect_action_failure(
            lambda: site_generator.read_hosted_bundle(encrypted_bundle),
            "encrypted zip member",
            "encrypted hosted bundle member",
        )
        assert_member_failure_redacted(
            message,
            "encrypted hosted bundle member",
            "apt/Packages",
        )

        corrupt_bundle = temp / "corrupt-hosted-bundle.zip"
        shutil.copy2(hosted_bundle, corrupt_bundle)
        corrupt_zip_member_data(corrupt_bundle, "apt/Packages")
        message = expect_action_failure(
            lambda: site_generator.read_hosted_bundle(corrupt_bundle),
            "could not read zip member",
            "corrupt hosted bundle member",
        )
        assert_member_failure_redacted(
            message,
            "corrupt hosted bundle member",
            "apt/Packages",
        )

        unsupported_bundle = temp / "unsupported-hosted-bundle.zip"
        with zipfile.ZipFile(unsupported_bundle, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("README.txt", ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFCHR | 0o644) << 16
            archive.writestr(info, b"device\n")
        message = expect_action_failure(
            lambda: site_generator.read_hosted_bundle(unsupported_bundle),
            "unsupported zip member",
            "unsupported hosted bundle member",
        )
        assert_member_failure_redacted(
            message,
            "unsupported hosted bundle member",
            "README.txt",
        )

        run_generator(dist, repeat, BASE_URL)
        if site.read_bytes() != (repeat / SITE_BUNDLE).read_bytes():
            raise AssertionError("hosted Linux repository site artifact was not deterministic")

        message = expect_action_failure(
            lambda: site_generator.parse_package_version(
                Path("package.json"),
                (
                    '{"version":"0.1.0",'
                    f'"version":"{SENSITIVE_SENTINEL}"}}\n'
                ).encode("utf-8"),
                "hosted Linux repository site regression",
            ),
            "not valid UTF-8 JSON",
            "duplicate package metadata JSON",
        )
        assert_no_sentinel(message, "duplicate package metadata JSON output")

        non_ascii_checksum = temp / "non-ascii-checksum"
        shutil.copytree(dist, non_ascii_checksum)
        (non_ascii_checksum / f"{HOSTED_BUNDLE}.sha256").write_bytes(b"\xff\n")
        output = expect_failure(
            "non-ASCII hosted bundle checksum",
            non_ascii_checksum,
            BASE_URL,
            "SHA-256 sidecar is not ASCII",
        )
        assert_not_displayed(output, "non-ASCII hosted bundle checksum", HOSTED_BUNDLE)

        invalid_checksum = temp / "invalid-checksum"
        shutil.copytree(dist, invalid_checksum)
        (invalid_checksum / f"{HOSTED_BUNDLE}.sha256").write_text(
            "not a strict checksum\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "invalid hosted bundle checksum",
            invalid_checksum,
            BASE_URL,
            "invalid format",
        )
        assert_not_displayed(output, "invalid hosted bundle checksum", HOSTED_BUNDLE)

        wrong_checksum_target = temp / "wrong-checksum-target"
        shutil.copytree(dist, wrong_checksum_target)
        malicious_target = "secret-hosted-site-sidecar-target.zip"
        (wrong_checksum_target / f"{HOSTED_BUNDLE}.sha256").write_text(
            f"{hashlib.sha256(hosted_bundle.read_bytes()).hexdigest()}  {malicious_target}\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "wrong hosted bundle checksum target",
            wrong_checksum_target,
            BASE_URL,
            "names wrong file",
        )
        assert_not_displayed(
            output,
            "wrong hosted bundle checksum target",
            HOSTED_BUNDLE,
            malicious_target,
        )

        mismatched_checksum = temp / "mismatched-checksum"
        shutil.copytree(dist, mismatched_checksum)
        (mismatched_checksum / f"{HOSTED_BUNDLE}.sha256").write_text(
            f"{'0' * 64}  {HOSTED_BUNDLE}\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "mismatched hosted bundle checksum",
            mismatched_checksum,
            BASE_URL,
            "SHA-256 mismatch",
        )
        assert_not_displayed(output, "mismatched hosted bundle checksum", HOSTED_BUNDLE)

        missing_signature = temp / "missing-signature"
        shutil.copytree(dist, missing_signature)
        (missing_signature / f"{HOSTED_BUNDLE}.asc").unlink()
        expect_failure(
            "missing hosted bundle signature",
            missing_signature,
            BASE_URL,
            "missing detached signature",
        )

        non_ascii_signature = temp / "non-ascii-signature"
        shutil.copytree(dist, non_ascii_signature)
        (non_ascii_signature / f"{HOSTED_BUNDLE}.asc").write_bytes(b"\xff\n")
        output = expect_failure(
            "non-ASCII hosted bundle signature",
            non_ascii_signature,
            BASE_URL,
            "detached signature is not ASCII-armored",
        )
        assert_not_displayed(
            output,
            "non-ASCII hosted bundle signature",
            f"{HOSTED_BUNDLE}.asc",
        )

        non_armored_signature = temp / "non-armored-signature"
        shutil.copytree(dist, non_armored_signature)
        (non_armored_signature / f"{HOSTED_BUNDLE}.asc").write_text(
            "not a signature\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "non-armored hosted bundle signature",
            non_armored_signature,
            BASE_URL,
            "detached signature is not ASCII-armored",
        )
        assert_not_displayed(
            output,
            "non-armored hosted bundle signature",
            f"{HOSTED_BUNDLE}.asc",
        )

        private_key_signature = temp / "private-key-signature"
        shutil.copytree(dist, private_key_signature)
        (private_key_signature / f"{HOSTED_BUNDLE}.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\n"
            "fixture\n"
            "-----END PGP SIGNATURE-----\n"
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            "fixture\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "private key hosted bundle signature",
            private_key_signature,
            BASE_URL,
            "private key material",
        )
        assert_not_displayed(
            output,
            "private key hosted bundle signature",
            f"{HOSTED_BUNDLE}.asc",
        )

        symlink_dist = temp / "symlink-dist"
        if try_symlink(dist, symlink_dist, target_is_directory=True):
            expect_failure_at_output(
                "symlinked dist directory",
                symlink_dist,
                temp / "symlink-dist-output",
                BASE_URL,
                "release dist directory must not be a symlink",
            )

        symlink_bundle = temp / "symlink-bundle"
        shutil.copytree(dist, symlink_bundle)
        bundle_target = temp / "hosted-bundle-target.zip"
        shutil.copy2(symlink_bundle / HOSTED_BUNDLE, bundle_target)
        (symlink_bundle / HOSTED_BUNDLE).unlink()
        if try_symlink(bundle_target, symlink_bundle / HOSTED_BUNDLE):
            expect_failure(
                "symlinked hosted bundle",
                symlink_bundle,
                BASE_URL,
                "hosted Linux repository bundle must not be a symlink",
            )

        symlink_checksum = temp / "symlink-checksum"
        shutil.copytree(dist, symlink_checksum)
        checksum_target = temp / "hosted-bundle-target.zip.sha256"
        shutil.copy2(symlink_checksum / f"{HOSTED_BUNDLE}.sha256", checksum_target)
        (symlink_checksum / f"{HOSTED_BUNDLE}.sha256").unlink()
        if try_symlink(checksum_target, symlink_checksum / f"{HOSTED_BUNDLE}.sha256"):
            expect_failure(
                "symlinked hosted bundle checksum",
                symlink_checksum,
                BASE_URL,
                "SHA-256 sidecar for hosted Linux repository bundle must not be a symlink",
            )

        symlink_signature = temp / "symlink-signature"
        shutil.copytree(dist, symlink_signature)
        signature_target = temp / "hosted-bundle-target.zip.asc"
        shutil.copy2(symlink_signature / f"{HOSTED_BUNDLE}.asc", signature_target)
        (symlink_signature / f"{HOSTED_BUNDLE}.asc").unlink()
        if try_symlink(signature_target, symlink_signature / f"{HOSTED_BUNDLE}.asc"):
            expect_failure(
                "symlinked hosted bundle signature",
                symlink_signature,
                BASE_URL,
                "detached signature for hosted Linux repository site input must not be a symlink",
            )

        symlink_output_target = temp / "output-target"
        symlink_output_target.mkdir()
        symlink_output = temp / "symlink-output"
        if try_symlink(symlink_output_target, symlink_output, target_is_directory=True):
            expect_failure_at_output(
                "symlinked output directory",
                dist,
                symlink_output,
                BASE_URL,
                "hosted repository site output directory must not be a symlink",
            )

        symlink_output_file = temp / "symlink-output-file"
        symlink_output_file.mkdir()
        output_file_target = temp / "site-target.zip"
        output_file_target.write_bytes(b"existing\n")
        if try_symlink(output_file_target, symlink_output_file / SITE_BUNDLE):
            expect_failure_at_output(
                "symlinked output site bundle",
                dist,
                symlink_output_file,
                BASE_URL,
                "hosted Linux repository site artifact output must not be a symlink",
            )

        symlink_output_sidecar = temp / "symlink-output-sidecar"
        symlink_output_sidecar.mkdir()
        output_sidecar_target = temp / "site-target.zip.sha256"
        output_sidecar_target.write_text("", encoding="ascii")
        if try_symlink(output_sidecar_target, symlink_output_sidecar / f"{SITE_BUNDLE}.sha256"):
            expect_failure_at_output(
                "symlinked output site checksum",
                dist,
                symlink_output_sidecar,
                BASE_URL,
                "hosted Linux repository site artifact SHA-256 sidecar output must not be a symlink",
            )

        unsafe_bundle = temp / "unsafe-bundle"
        shutil.copytree(dist, unsafe_bundle)
        with zipfile.ZipFile(unsafe_bundle / HOSTED_BUNDLE, "w", compression=zipfile.ZIP_STORED) as archive:
            write_zip_bytes(archive, "../apt/Packages", b"Package: conu\n")
        write_checksum(unsafe_bundle / HOSTED_BUNDLE)
        write_signature(unsafe_bundle / HOSTED_BUNDLE)
        output = expect_failure(
            "unsafe hosted bundle member",
            unsafe_bundle,
            BASE_URL,
            "unsafe hosted repository zip path",
        )
        assert_member_failure_redacted(
            output,
            "unsafe hosted bundle member",
            "../apt/Packages",
            "apt/Packages",
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

        credential_url = temp / "credential-url"
        shutil.copytree(dist, credential_url)
        expect_failure(
            "base URL with credentials",
            credential_url,
            "https://token@example.com/conu",
            "must not include credentials",
        )

        for index, bad_url in enumerate((
            "https://packages.example.com:bad/conu",
            "https://packages.example.com:/conu",
            "https://:443/conu",
            "https://packages.example.com:443x/conu",
        )):
            malformed_url = temp / f"malformed-url-{index}"
            shutil.copytree(dist, malformed_url)
            expect_failure(
                "malformed base URL authority",
                malformed_url,
                bad_url,
                "authority",
            )

        for index, bad_url in enumerate((
            "https://packages.example.com%20.evil/conu",
            "https://packages.example.com%40evil.test/conu",
            "https://packages.example.com\\evil.test/conu",
        )):
            unsafe_url = temp / f"unsafe-authority-url-{index}"
            shutil.copytree(dist, unsafe_url)
            expect_failure(
                "unsafe base URL authority",
                unsafe_url,
                bad_url,
                "authority",
            )

        encoded_base_url = temp / "encoded-base-url"
        shutil.copytree(dist, encoded_base_url)
        expect_failure(
            "encoded base URL",
            encoded_base_url,
            f"{BASE_URL}/%2e%2e%2fother",
            "path must not contain encoded separators",
        )

        control_base_url = temp / "control-base-url"
        shutil.copytree(dist, control_base_url)
        expect_failure(
            "control base URL path",
            control_base_url,
            f"{BASE_URL}/%00",
            "whitespace or control characters",
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


def load_site_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_hosted_linux_repository_site",
        SITE_GENERATOR,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository site generator")
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


def expect_failure(description: str, dist: Path, base_url: str, expected: str) -> str:
    return expect_failure_at_output(description, dist, dist / "out", base_url, expected)


def expect_failure_at_output(
    description: str,
    dist: Path,
    output: Path,
    base_url: str,
    expected: str,
) -> str:
    failed = subprocess.run(
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
    return failed.stdout


def expect_zip_bound_failure(
    site_generator,
    archive: Path,
    constant_name: str,
    value: int,
    expected: str,
    label: str,
) -> None:
    original = getattr(site_generator, constant_name)
    setattr(site_generator, constant_name, value)
    try:
        message = expect_action_failure(
            lambda: site_generator.read_hosted_bundle(archive),
            expected,
            label,
        )
        assert_member_failure_redacted(message, label)
    finally:
        setattr(site_generator, constant_name, original)


def expect_action_failure(action, expected: str, label: str) -> str:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected in message:
            return message
        raise AssertionError(f"{label}: expected {expected!r}, got {message!r}") from exc
    raise AssertionError(f"{label}: expected failure containing {expected!r}")


def assert_member_failure_redacted(message: str, label: str, *forbidden_values: str) -> None:
    for marker in ("pathDisplayed=false", "contentsDisplayed=false"):
        if marker not in message:
            raise AssertionError(f"{label}: missing {marker}: {message!r}")
    for value in forbidden_values:
        if value and value in message:
            raise AssertionError(f"{label}: displayed archive member value {value!r}: {message!r}")


def assert_no_sentinel(output: str, label: str) -> None:
    if SENSITIVE_SENTINEL in output:
        raise AssertionError(f"{label} leaked duplicate-key shadow value")


def assert_not_displayed(message: str, label: str, *forbidden_values: str) -> None:
    for value in forbidden_values:
        if value and value in message:
            raise AssertionError(f"{label}: displayed forbidden value {value!r}: {message!r}")


def try_symlink(target: Path, link: Path, *, target_is_directory: bool = False) -> bool:
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        return False
    return True


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


def corrupt_zip_member_data(path: Path, member_name: str) -> None:
    data = bytearray(path.read_bytes())
    target = member_name.encode("utf-8")
    offset = 0
    while offset + 4 <= len(data):
        signature = int.from_bytes(data[offset : offset + 4], "little")
        if signature != 0x04034B50:
            offset += 1
            continue
        name_length = int.from_bytes(data[offset + 26 : offset + 28], "little")
        extra_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
        name_start = offset + 30
        name_end = name_start + name_length
        compressed_size = int.from_bytes(data[offset + 18 : offset + 22], "little")
        data_start = name_end + extra_length
        data_end = data_start + compressed_size
        if data[name_start:name_end] == target:
            if compressed_size == 0:
                raise AssertionError(f"{member_name} had no compressed data to corrupt")
            data[data_end - 1] ^= 0xFF
            path.write_bytes(data)
            return
        offset = data_end
    raise AssertionError(f"zip member not found for corruption: {member_name}")


if __name__ == "__main__":
    sys.exit(main())
