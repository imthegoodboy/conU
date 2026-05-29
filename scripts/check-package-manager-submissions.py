#!/usr/bin/env python3
"""Regression checks for package-manager submission bundle preparation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREPARER_PATH = ROOT / "scripts" / "prepare-package-manager-submissions.py"
MANIFEST_CHECK_PATH = ROOT / "scripts" / "check-package-manager-manifests.py"
VERSION = "0.1.0"
DEBIAN_PACKAGES = (
    "conu_0.1.0_amd64.deb",
    "conu_0.1.0_arm64.deb",
)
RPM_PACKAGES = (
    "conu-0.1.0-1.x86_64.rpm",
    "conu-0.1.0-1.aarch64.rpm",
)
REPOSITORY_METADATA = (
    "conu-0.1.0-apt-repository-metadata.zip",
    "conu-0.1.0-rpm-repository-metadata.zip",
)
SENSITIVE_SENTINEL = "do-not-print-this-secret-value"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_sha256(path: Path) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(f"{path.name}.sha256").write_text(
        f"{digest}  {path.name}\n",
        encoding="ascii",
    )


def write_signature(path: Path) -> None:
    path.with_name(f"{path.name}.asc").write_text(
        "-----BEGIN PGP SIGNATURE-----\n"
        "Version: conU regression fixture\n\n"
        "ZmFrZS1zaWduYXR1cmU=\n"
        "-----END PGP SIGNATURE-----\n",
        encoding="ascii",
    )


def write_public_key(dist: Path) -> None:
    key = dist / "conu-linux-gpg-key.asc"
    key.write_text(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "Version: conU regression fixture\n\n"
        "ZmFrZS1wdWJsaWMta2V5\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n",
        encoding="ascii",
    )
    write_sha256(key)


def write_signed_release_extras(dist: Path) -> None:
    for package in RPM_PACKAGES:
        path = dist / package
        path.write_bytes(f"{package}\n".encode("ascii"))
        write_sha256(path)
        write_signature(path)

    rpm_metadata = dist / "conu-0.1.0-rpm-repository-metadata.zip"
    with zipfile.ZipFile(rpm_metadata, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("README.txt", "RPM metadata fixture\n")
        archive.writestr("repodata/repomd.xml", "<repomd />\n")
    write_sha256(rpm_metadata)
    write_signature(rpm_metadata)

    for name in (*DEBIAN_PACKAGES, "conu-0.1.0-apt-repository-metadata.zip"):
        write_signature(dist / name)
    write_public_key(dist)


def assert_bundle(preparer, dist: Path, output: Path) -> Path:
    report = preparer.prepare_submission_bundle(
        dist,
        output,
        VERSION,
        require_rpm_assets=True,
        require_repository_metadata=True,
        require_linux_signatures=True,
    )
    bundle = output / preparer.submission_bundle_filename(VERSION)
    if report.output != bundle or not bundle.exists():
        raise AssertionError("submission bundle was not written at the expected path")
    sidecar = bundle.with_name(f"{bundle.name}.sha256")
    expected_sidecar = f"{hashlib.sha256(bundle.read_bytes()).hexdigest()}  {bundle.name}\n"
    if sidecar.read_text(encoding="ascii") != expected_sidecar:
        raise AssertionError("submission bundle SHA-256 sidecar was not strict")

    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        required = {
            "README.txt",
            "homebrew-tap/Formula/conu.rb",
            "scoop-bucket/bucket/conu.json",
            "winget-pkgs/manifests/i/imthegoodboy/conU/0.1.0/imthegoodboy.conU.yaml",
            "chocolatey/conu.0.1.0.nupkg",
            "debian/conu_0.1.0_amd64.deb",
            "debian/conu_0.1.0_amd64.deb.sha256",
            "debian/conu_0.1.0_amd64.deb.asc",
            "debian/conu_0.1.0_arm64.deb",
            "debian/conu_0.1.0_arm64.deb.sha256",
            "debian/conu_0.1.0_arm64.deb.asc",
            "apt/conu-0.1.0-apt-repository-metadata.zip",
            "apt/conu-0.1.0-apt-repository-metadata.zip.sha256",
            "apt/conu-0.1.0-apt-repository-metadata.zip.asc",
            "rpm/conu.spec",
            "rpm/conu-0.1.0-1.x86_64.rpm",
            "rpm/conu-0.1.0-1.x86_64.rpm.sha256",
            "rpm/conu-0.1.0-1.x86_64.rpm.asc",
            "rpm/conu-0.1.0-1.aarch64.rpm",
            "rpm/conu-0.1.0-1.aarch64.rpm.sha256",
            "rpm/conu-0.1.0-1.aarch64.rpm.asc",
            "rpm/conu-0.1.0-rpm-repository-metadata.zip",
            "rpm/conu-0.1.0-rpm-repository-metadata.zip.sha256",
            "rpm/conu-0.1.0-rpm-repository-metadata.zip.asc",
            "linux-signing/conu-linux-gpg-key.asc",
            "linux-signing/conu-linux-gpg-key.asc.sha256",
        }
        missing = required - set(names)
        if missing:
            raise AssertionError(f"submission bundle missed expected entries: {sorted(missing)!r}")
        for info in archive.infolist():
            if info.date_time != (2020, 1, 1, 0, 0, 0):
                raise AssertionError(f"{info.filename} was not timestamp-normalized")
            mode = (info.external_attr >> 16) & 0o777
            if mode != 0o644:
                raise AssertionError(f"{info.filename} had mode {oct(mode)}")
        readme = archive.read("README.txt").decode("ascii")
        if "payload_displayed = false" not in readme:
            raise AssertionError("submission bundle README did not include display guards")
    rendered = json.dumps(report.as_json())
    if SENSITIVE_SENTINEL in rendered:
        raise AssertionError("submission bundle report leaked unrelated sentinel text")
    return bundle


def expect_failure(description: str, action, expected: str) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected not in message:
            raise AssertionError(
                f"{description} failed with {message!r}, expected {expected!r}"
            ) from exc
        return
    raise AssertionError(f"{description} unexpectedly passed")


def expect_failure_with_limit(
    module,
    limit_name: str,
    value: int,
    description: str,
    action,
    expected: str,
) -> None:
    original = getattr(module, limit_name)
    setattr(module, limit_name, value)
    try:
        expect_failure(description, action, expected)
    finally:
        setattr(module, limit_name, original)


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


def main() -> int:
    preparer = load_module(PREPARER_PATH, "prepare_package_manager_submissions")
    manifest_check = load_module(MANIFEST_CHECK_PATH, "check_package_manager_manifests")
    generator = manifest_check.load_generator()

    with tempfile.TemporaryDirectory(prefix="conu-package-submissions-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        generated = temp / "generated"
        output = temp / "bundle"
        repeat_output = temp / "repeat"
        dist.mkdir()
        manifest_check.write_dist(dist, rooted_windows=False)
        manifest_check.generate(
            generator,
            dist,
            generated,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(generated)

        first = assert_bundle(preparer, generated, output)
        second = assert_bundle(preparer, generated, repeat_output)
        if first.read_bytes() != second.read_bytes():
            raise AssertionError("package-manager submission bundle was not deterministic")

        expect_failure_with_limit(
            preparer,
            "MAX_TOTAL_SOURCE_BYTES",
            1,
            "submission source aggregate bound",
            lambda: preparer.prepare_submission_bundle(
                generated,
                temp / "total-source-bound-out",
                VERSION,
                require_rpm_assets=True,
                require_repository_metadata=True,
                require_linux_signatures=True,
            ),
            "package-manager submission sources exceed 1 bytes",
        )

        missing_signature = temp / "missing-signature"
        manifest_check.generate(
            generator,
            dist,
            missing_signature,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(missing_signature)
        (missing_signature / "conu_0.1.0_amd64.deb.asc").unlink()
        expect_failure(
            "missing Linux package signature",
            lambda: preparer.prepare_submission_bundle(
                missing_signature,
                temp / "missing-signature-out",
                VERSION,
                require_rpm_assets=True,
                require_repository_metadata=True,
                require_linux_signatures=True,
            ),
            "missing package-manager submission source",
        )

        wrong_checksum = temp / "wrong-checksum"
        manifest_check.generate(
            generator,
            dist,
            wrong_checksum,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(wrong_checksum)
        sidecar = wrong_checksum / "conu_0.1.0_amd64.deb.sha256"
        sidecar.write_text("0" * 64 + "  conu_0.1.0_amd64.deb\n", encoding="ascii")
        expect_failure(
            "wrong package checksum",
            lambda: preparer.prepare_submission_bundle(
                wrong_checksum,
                temp / "wrong-checksum-out",
                VERSION,
                require_rpm_assets=True,
                require_repository_metadata=True,
                require_linux_signatures=True,
            ),
            "SHA-256 mismatch",
        )

        orphan_signature = temp / "orphan-signature"
        manifest_check.generate(
            generator,
            dist,
            orphan_signature,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(orphan_signature)
        (orphan_signature / "conu-0.1.0-1.x86_64.rpm").unlink()
        (orphan_signature / "conu-0.1.0-1.x86_64.rpm.sha256").unlink()
        expect_failure(
            "orphan package signature",
            lambda: preparer.prepare_submission_bundle(
                orphan_signature,
                temp / "orphan-signature-out",
                VERSION,
            ),
            "signed target is missing",
        )

        encrypted_chocolatey = temp / "encrypted-chocolatey"
        manifest_check.generate(
            generator,
            dist,
            encrypted_chocolatey,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(encrypted_chocolatey)
        mark_zip_member_encrypted(encrypted_chocolatey / "conu.0.1.0.nupkg", "conu.nuspec")
        expect_failure(
            "encrypted Chocolatey package member",
            lambda: preparer.prepare_submission_bundle(
                encrypted_chocolatey,
                temp / "encrypted-chocolatey-out",
                VERSION,
                require_rpm_assets=True,
                require_repository_metadata=True,
                require_linux_signatures=True,
            ),
            "contains encrypted Chocolatey package member",
        )

        unsupported_chocolatey = temp / "unsupported-chocolatey"
        manifest_check.generate(
            generator,
            dist,
            unsupported_chocolatey,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(unsupported_chocolatey)
        with zipfile.ZipFile(
            unsupported_chocolatey / "conu.0.1.0.nupkg",
            "a",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            info = zipfile.ZipInfo("device")
            info.external_attr = stat.S_IFCHR << 16
            archive.writestr(info, b"device\n")
        expect_failure(
            "unsupported Chocolatey package member",
            lambda: preparer.prepare_submission_bundle(
                unsupported_chocolatey,
                temp / "unsupported-chocolatey-out",
                VERSION,
                require_rpm_assets=True,
                require_repository_metadata=True,
                require_linux_signatures=True,
            ),
            "contains unsupported Chocolatey package member",
        )

        forbidden = temp / "forbidden"
        manifest_check.generate(
            generator,
            dist,
            forbidden,
            build_apt_repository_metadata=True,
        )
        write_signed_release_extras(forbidden)
        (forbidden / "conu.rb").write_text(
            "class Conu < Formula\n"
            "homepage \"https://github.com/imthegoodboy/conU\"\n"
            "sha256 \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n"
            "# NPM_TOKEN\n",
            encoding="ascii",
        )
        expect_failure(
            "forbidden manifest text",
            lambda: preparer.prepare_submission_bundle(
                forbidden,
                temp / "forbidden-out",
                VERSION,
                require_rpm_assets=True,
                require_repository_metadata=True,
                require_linux_signatures=True,
            ),
            "forbidden literal",
        )

        no_optional = temp / "no-optional"
        manifest_check.generate(generator, dist, no_optional)
        preparer.prepare_submission_bundle(no_optional, temp / "no-optional-out", VERSION)
        expect_failure(
            "required optional rpm assets",
            lambda: preparer.prepare_submission_bundle(
                no_optional,
                temp / "require-rpm-out",
                VERSION,
                require_rpm_assets=True,
            ),
            "missing package-manager submission source",
        )

    print("package-manager submission bundle regression checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
