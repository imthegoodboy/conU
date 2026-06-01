#!/usr/bin/env python3
"""Regression checks for conU release update policy generation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate-release-update-policy.py"
VERSION = "0.1.0"
TAG = f"v{VERSION}"
REPO = "imthegoodboy/conU"
BASE_URL = "https://github.com/imthegoodboy/conU/releases/download/v0.1.0"
POLICY = f"conu-{VERSION}-update-policy.json"
PLATFORM_ARCHIVES = (
    f"conu-{VERSION}-windows-x64.zip",
    f"conu-{VERSION}-macos-x64.zip",
    f"conu-{VERSION}-macos-arm64.zip",
    f"conu-{VERSION}-linux-x64.tar.gz",
    f"conu-{VERSION}-linux-arm64.tar.gz",
)
STATIC_PACKAGE_MANAGER_ASSETS = (
    "conu.rb",
    "conu.json",
    "imthegoodboy.conU.yaml",
    "conu.spec",
    f"conu.{VERSION}.nupkg",
)
LINUX_PACKAGE_ASSETS = (
    f"conu_{VERSION}_amd64.deb",
    f"conu_{VERSION}_arm64.deb",
    f"conu-{VERSION}-1.x86_64.rpm",
    f"conu-{VERSION}-1.aarch64.rpm",
)
REPOSITORY_ASSETS = (
    f"conu-{VERSION}-apt-repository-metadata.zip",
    f"conu-{VERSION}-rpm-repository-metadata.zip",
    "conu-linux-gpg-key.asc",
    f"conu-{VERSION}-hosted-linux-repositories.zip",
    f"conu-{VERSION}-hosted-linux-repository-site.zip",
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="conu-update-policy-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        output = temp / "output"
        repeat = temp / "repeat"
        dist.mkdir()
        output.mkdir()
        repeat.mkdir()
        write_dist(dist)

        run_generator(dist, output)
        policy = output / POLICY
        assert_sha256_sidecar(policy)
        assert_policy_json(policy)

        run_generator(dist, repeat)
        if policy.read_bytes() != (repeat / POLICY).read_bytes():
            raise AssertionError("release update policy was not deterministic")

        generator = load_generator_module()
        expect_module_failure_with_limit(
            generator,
            "text asset size bound",
            "MAX_TEXT_ASSET_BYTES",
            1,
            lambda: build_policy(generator, dist),
            "is too large",
        )
        expect_module_failure_with_limit(
            generator,
            "checksum sidecar size bound",
            "MAX_CHECKSUM_BYTES",
            1,
            lambda: build_policy(generator, dist),
            "is too large",
        )
        expect_module_failure_with_limit(
            generator,
            "detached signature size bound",
            "MAX_SIGNATURE_BYTES",
            1,
            lambda: build_policy(generator, dist),
            "is too large",
        )
        expect_module_failure_with_limit(
            generator,
            "aggregate source size bound",
            "MAX_TOTAL_SOURCE_BYTES",
            1,
            lambda: build_policy(generator, dist),
            "source inputs exceed",
        )
        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_module_failure(
                "symlinked release dist directory",
                lambda: generator.validate_input_directory(
                    dist,
                    "release dist directory",
                ),
                "must not be a symlink",
            )
            expect_module_failure(
                "symlinked source asset",
                lambda: generator.validate_source_file(
                    dist / PLATFORM_ARCHIVES[0],
                    "release update policy asset fixture",
                    generator.MAX_SOURCE_ASSET_BYTES,
                    generator.SourceBudget(),
                ),
                "must not be a symlink",
            )
            expect_module_failure(
                "symlinked output directory",
                lambda: generator.prepare_output_directory(output),
                "output directory must not be a symlink",
            )
            expect_module_failure(
                "symlinked output file",
                lambda: generator.validate_output_file(output / POLICY, "release update policy"),
                "output must not be a symlink",
            )

        missing_signature = temp / "missing-signature"
        shutil.copytree(dist, missing_signature)
        (missing_signature / f"conu-{VERSION}-linux-x64.tar.gz.asc").unlink()
        expect_failure(
            "missing Linux archive signature",
            missing_signature,
            "missing detached signature",
        )

        private_key_signature = temp / "private-key-signature"
        shutil.copytree(dist, private_key_signature)
        (
            private_key_signature / f"conu-{VERSION}-linux-x64.tar.gz.asc"
        ).write_text(
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
            "private key Linux archive signature",
            private_key_signature,
            "private key material",
        )

        bad_checksum_name = temp / "bad-checksum-name"
        shutil.copytree(dist, bad_checksum_name)
        archive = bad_checksum_name / f"conu-{VERSION}-windows-x64.zip"
        archive.with_name(f"{archive.name}.sha256").write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  wrong.zip\n",
            encoding="ascii",
            newline="\n",
        )
        expect_failure(
            "checksum names wrong asset",
            bad_checksum_name,
            "names wrong file",
        )

        expect_failure(
            "insecure release base URL",
            dist,
            "absolute https URL",
            release_base_url="http://github.com/imthegoodboy/conU/releases/download/v0.1.0",
        )

        expect_failure(
            "release base URL with query",
            dist,
            "must not include params",
            release_base_url="https://github.com/imthegoodboy/conU/releases/download/v0.1.0?token=secret",
        )

        expect_failure(
            "release base URL with credentials",
            dist,
            "must not include credentials",
            release_base_url="https://token@github.com/imthegoodboy/conU/releases/download/v0.1.0",
        )

        for bad_url in (
            "https://github.com:bad/imthegoodboy/conU/releases/download/v0.1.0",
            "https://github.com:/imthegoodboy/conU/releases/download/v0.1.0",
            "https://:443/imthegoodboy/conU/releases/download/v0.1.0",
            "https://github.com:443x/imthegoodboy/conU/releases/download/v0.1.0",
        ):
            expect_failure(
                "malformed release base URL authority",
                dist,
                "authority",
                release_base_url=bad_url,
            )

        expect_failure(
            "release base URL with raw dot segment",
            dist,
            "path must not contain dot segments",
            release_base_url="https://github.com/imthegoodboy/conU/releases/download/../v0.1.0",
        )

        expect_failure(
            "release base URL with encoded dot segment",
            dist,
            "path must not contain dot segments",
            release_base_url="https://github.com/imthegoodboy/conU/releases/download/%2e%2e/v0.1.0",
        )

        expect_failure(
            "release base URL with encoded separator",
            dist,
            "path must not contain encoded separators",
            release_base_url="https://github.com/imthegoodboy/conU/releases/download/v0.1.0%2fother",
        )

        expect_failure(
            "tag mismatch",
            dist,
            "does not match version",
            tag="v0.2.0",
        )

        forbidden_text = temp / "forbidden-text"
        shutil.copytree(dist, forbidden_text)
        (forbidden_text / "conu.rb").write_text(
            "class Conu\n  TOKEN = 'do-not-print-this-secret-value'\nend\n",
            encoding="ascii",
            newline="\n",
        )
        expect_failure(
            "forbidden generated text",
            forbidden_text,
            "forbidden text",
        )

    print("Release update policy regression checks passed")
    return 0


def load_generator_module():
    spec = importlib.util.spec_from_file_location("generate_release_update_policy", GENERATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load release update policy generator module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_policy(generator, dist: Path) -> dict[str, object]:
    return generator.build_update_policy(
        dist=dist,
        version=VERSION,
        tag=TAG,
        repo=REPO,
        channel="stable",
        release_base_url=BASE_URL,
    )


def expect_module_failure(description: str, action, expected: str) -> None:
    try:
        action()
    except SystemExit as exc:
        rendered = str(exc)
        if expected not in rendered:
            raise AssertionError(
                f"{description} failed with {rendered!r}, expected {expected!r}"
            ) from exc
        return
    raise AssertionError(f"{description} unexpectedly passed")


def expect_module_failure_with_limit(
    generator,
    description: str,
    attr: str,
    value: int,
    action,
    expected: str,
) -> None:
    original = getattr(generator, attr)
    setattr(generator, attr, value)
    try:
        expect_module_failure(description, action, expected)
    finally:
        setattr(generator, attr, original)


def run_generator(dist: Path, output: Path) -> str:
    return subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            str(dist),
            "--output-dir",
            str(output),
            "--version",
            VERSION,
            "--tag",
            TAG,
            "--repo",
            REPO,
            "--release-base-url",
            BASE_URL,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def expect_failure(
    description: str,
    dist: Path,
    expected: str,
    *,
    release_base_url: str = BASE_URL,
    tag: str = TAG,
) -> None:
    failed = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            str(dist),
            "--output-dir",
            str(dist / "out"),
            "--version",
            VERSION,
            "--tag",
            tag,
            "--repo",
            REPO,
            "--release-base-url",
            release_base_url,
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


def write_dist(dist: Path) -> None:
    for name in PLATFORM_ARCHIVES:
        asset = dist / name
        asset.write_bytes(f"{name}\n".encode("ascii"))
        write_checksum(asset)
        if "-linux-" in name:
            write_signature(asset)
    for name in STATIC_PACKAGE_MANAGER_ASSETS:
        (dist / name).write_text(f"{name}\n", encoding="ascii", newline="\n")
    for name in LINUX_PACKAGE_ASSETS:
        asset = dist / name
        asset.write_bytes(f"{name}\n".encode("ascii"))
        write_checksum(asset)
        write_signature(asset)
    for name in REPOSITORY_ASSETS:
        asset = dist / name
        if name == "conu-linux-gpg-key.asc":
            asset.write_text(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n"
                "-----END PGP PUBLIC KEY BLOCK-----\n",
                encoding="ascii",
                newline="\n",
            )
        else:
            asset.write_bytes(f"{name}\n".encode("ascii"))
        write_checksum(asset)
        if name != "conu-linux-gpg-key.asc":
            write_signature(asset)


def write_checksum(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def write_signature(path: Path) -> None:
    path.with_name(f"{path.name}.asc").write_text(
        "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
        encoding="ascii",
        newline="\n",
    )


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash {path.name}")


def assert_policy_json(path: Path) -> None:
    policy = json.loads(path.read_text(encoding="ascii"))
    if policy["schema"] != "conu.releaseUpdatePolicy.v1":
        raise AssertionError("release update policy schema was wrong")
    if policy["version"] != VERSION or policy["releaseTag"] != TAG:
        raise AssertionError("release update policy version/tag was wrong")
    if policy["releaseBaseUrl"] != BASE_URL:
        raise AssertionError("release update policy base URL was wrong")
    if policy["channel"] != "stable":
        raise AssertionError("release update policy channel was wrong")
    if policy["apply"] != {
        "autoApply": False,
        "downgradeAllowed": False,
        "manualVerificationRequired": True,
        "operatorConsentRequired": True,
    }:
        raise AssertionError("release update policy apply rules were wrong")
    if policy["policyAsset"] != {
        "cacheControl": "no-cache",
        "filename": POLICY,
        "sha256Url": f"{BASE_URL}/{POLICY}.sha256",
        "signatureUrl": f"{BASE_URL}/{POLICY}.asc",
        "url": f"{BASE_URL}/{POLICY}",
    }:
        raise AssertionError("release update policy self asset metadata was wrong")
    if len(policy["platformArchives"]) != len(PLATFORM_ARCHIVES):
        raise AssertionError("release update policy platform archive count was wrong")
    if len(policy["packageManagerAssets"]) != len(STATIC_PACKAGE_MANAGER_ASSETS):
        raise AssertionError("release update policy package-manager count was wrong")
    if len(policy["linuxPackageAssets"]) != len(LINUX_PACKAGE_ASSETS):
        raise AssertionError("release update policy Linux package count was wrong")
    if len(policy["repositoryAssets"]) != len(REPOSITORY_ASSETS):
        raise AssertionError("release update policy repository asset count was wrong")
    linux_archives = {
        asset["filename"]: asset
        for asset in policy["platformArchives"]
        if "-linux-" in asset["filename"]
    }
    for name in (
        f"conu-{VERSION}-linux-x64.tar.gz",
        f"conu-{VERSION}-linux-arm64.tar.gz",
    ):
        if linux_archives[name]["signatureUrl"] != f"{BASE_URL}/{name}.asc":
            raise AssertionError(f"{name} missed detached signature URL")
    for guard in (
        "payloadDisplayed",
        "tokenDisplayed",
        "keyMaterialDisplayed",
        "ciphertextDisplayed",
        "contentsDisplayed",
    ):
        if policy[guard] is not False:
            raise AssertionError(f"release update policy expected {guard}=false")
    rendered = json.dumps(policy, sort_keys=True)
    for forbidden in (
        "BEGIN PGP PRIVATE KEY BLOCK",
        "NPM_TOKEN",
        "CONU_RELAY_TOKEN",
        "do-not-print-this-secret-value",
    ):
        if forbidden in rendered:
            raise AssertionError(f"release update policy leaked {forbidden!r}")


if __name__ == "__main__":
    raise SystemExit(main())
