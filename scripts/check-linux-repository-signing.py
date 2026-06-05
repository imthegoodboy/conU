#!/usr/bin/env python3
"""Regression checks for signed APT/RPM repository metadata bundles."""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts" / "sign-linux-repository-metadata.py"
PASSPHRASE = "conu-repository-signing-regression-passphrase"
USER_ID = "conU Repository Signing Regression <noreply@github.com>"
WRONG_FINGERPRINT = "F" * 40
VERSION = "0.1.0"
APT_METADATA = f"conu-{VERSION}-apt-repository-metadata.zip"
RPM_METADATA = f"conu-{VERSION}-rpm-repository-metadata.zip"


def main() -> int:
    run_zip_ingestion_preflights()

    gpg = shutil.which("gpg")
    if gpg is None:
        print("Linux repository signing regression skipped: gpg is unavailable")
        return 0

    with tempfile.TemporaryDirectory(prefix="conu-repository-signing-check-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        key_home = temp / "key-home"
        verify_home = temp / "verify-home"
        dist.mkdir()
        key_home.mkdir(mode=0o700)
        verify_home.mkdir(mode=0o700)

        apt_zip = dist / APT_METADATA
        rpm_zip = dist / RPM_METADATA
        write_apt_metadata_zip(apt_zip)
        write_rpm_metadata_zip(rpm_zip)
        write_sha256_sidecar(apt_zip)
        write_sha256_sidecar(rpm_zip)
        unrelated = dist / "conu-0.1.0-linux-x64.tar.gz"
        unrelated.write_bytes(b"linux archive fixture\n")
        original_apt_digest = sha256_file(apt_zip)
        original_rpm_digest = sha256_file(rpm_zip)
        original_unrelated_digest = sha256_file(unrelated)

        key_id = create_test_key(gpg, key_home)
        private_key = export_secret_key(gpg, key_home, key_id)
        public_key = export_public_key(gpg, key_home, key_id)
        import_public_key(gpg, verify_home, public_key)

        env = os.environ.copy()
        env["CONU_LINUX_GPG_PRIVATE_KEY_BASE64"] = base64.b64encode(private_key).decode("ascii")
        env["CONU_LINUX_GPG_PASSPHRASE"] = PASSPHRASE
        env["CONU_LINUX_GPG_KEY_ID"] = key_id
        env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = key_id
        subprocess.run(
            [sys.executable, str(SIGNER), str(dist)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        if sha256_file(apt_zip) == original_apt_digest:
            raise AssertionError("APT metadata digest did not change after signing")
        if sha256_file(rpm_zip) == original_rpm_digest:
            raise AssertionError("RPM metadata digest did not change after signing")
        assert_sha256_sidecar(apt_zip)
        assert_sha256_sidecar(rpm_zip)
        if sha256_file(unrelated) != original_unrelated_digest:
            raise AssertionError("repository signer modified a non-repository release asset")
        if unrelated.with_name(f"{unrelated.name}.asc").exists():
            raise AssertionError("repository signer created a detached signature for a release asset")
        verify_apt_signatures(gpg, verify_home, apt_zip, temp)
        verify_rpm_signature(gpg, verify_home, rpm_zip, temp)

        missing_env = os.environ.copy()
        for name in (
            "CONU_LINUX_GPG_PRIVATE_KEY_BASE64",
            "CONU_LINUX_GPG_PASSPHRASE",
            "CONU_LINUX_GPG_KEY_ID",
            "CONU_LINUX_GPG_KEY_FINGERPRINT",
        ):
            missing_env.pop(name, None)
        failed = subprocess.run(
            [sys.executable, str(SIGNER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=missing_env,
        )
        if failed.returncode == 0 or "missing required environment variable" not in failed.stdout:
            raise AssertionError("repository signer did not fail closed with missing secrets")

        mismatch_env = env.copy()
        mismatch_env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = WRONG_FINGERPRINT
        failed = subprocess.run(
            [sys.executable, str(SIGNER), str(dist)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=mismatch_env,
        )
        if failed.returncode == 0 or "fingerprint mismatch" not in failed.stdout:
            raise AssertionError(
                "repository signer did not fail closed when the key fingerprint mismatched"
            )

    print("Linux repository signing regression checks passed")
    return 0


def run_zip_ingestion_preflights() -> None:
    signer = load_signer()
    run_source_file_preflights(signer)
    with tempfile.TemporaryDirectory(prefix="conu-repository-signing-zip-check-") as temp_text:
        temp = Path(temp_text)
        metadata = temp / APT_METADATA
        write_apt_metadata_zip(metadata)

        expect_zip_bound_failure(
            signer,
            metadata,
            "MAX_ZIP_MEMBER_BYTES",
            1,
            "zip member is too large",
            "repository signing member size bound",
        )
        expect_zip_bound_failure(
            signer,
            metadata,
            "MAX_ZIP_MEMBERS",
            1,
            "contains more than",
            "repository signing member count bound",
        )
        expect_zip_bound_failure(
            signer,
            metadata,
            "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
            1,
            "uncompressed ZIP contents exceed",
            "repository signing total size bound",
        )

        unreadable = temp / "unreadable.zip"
        unreadable_payload = "secret-unreadable-signing-zip-should-not-print"
        unreadable.write_text(unreadable_payload, encoding="ascii")
        message = expect_action_failure(
            lambda: signer.read_zip_members(unreadable),
            "not a readable zip archive",
            "repository signing unreadable zip",
        )
        assert_member_failure_redacted(
            message,
            "repository signing unreadable zip",
            unreadable_payload,
        )

        encrypted = temp / "encrypted.zip"
        shutil.copy2(metadata, encrypted)
        mark_zip_member_encrypted(encrypted, "Release")
        message = expect_action_failure(
            lambda: signer.read_zip_members(encrypted),
            "encrypted zip member",
            "repository signing encrypted member",
        )
        assert_member_failure_redacted(
            message,
            "repository signing encrypted member",
            "Release",
        )

        corrupt = temp / "corrupt.zip"
        shutil.copy2(metadata, corrupt)
        corrupt_zip_member_data(corrupt, "Release")
        message = expect_action_failure(
            lambda: signer.read_zip_members(corrupt),
            "could not read zip member",
            "repository signing corrupt member",
        )
        assert_member_failure_redacted(
            message,
            "repository signing corrupt member",
            "Release",
        )

        unsupported = temp / "unsupported.zip"
        with zipfile.ZipFile(unsupported, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("Release", (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFCHR | 0o644) << 16
            archive.writestr(info, b"device\n")
        message = expect_action_failure(
            lambda: signer.read_zip_members(unsupported),
            "unsupported zip member",
            "repository signing unsupported member",
        )
        assert_member_failure_redacted(
            message,
            "repository signing unsupported member",
            "Release",
        )

        unsafe = temp / "unsafe.zip"
        with zipfile.ZipFile(unsafe, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("../Release", b"escape\n")
        message = expect_action_failure(
            lambda: signer.read_zip_members(unsafe),
            "unsafe repository metadata zip path",
            "repository signing unsafe member",
        )
        assert_member_failure_redacted(
            message,
            "repository signing unsafe member",
            "../Release",
            "Release",
        )


def run_source_file_preflights(signer) -> None:
    with tempfile.TemporaryDirectory(prefix="conu-repository-signing-file-check-") as temp_text:
        temp = Path(temp_text)

        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_action_failure(
                lambda: signer.validate_input_directory(
                    temp / "dist",
                    "release dist directory",
                ),
                "must not be a symlink",
                "repository signing symlink dist directory",
            )

        valid = temp / "valid"
        valid.mkdir()
        apt = valid / APT_METADATA
        rpm = valid / RPM_METADATA
        write_apt_metadata_zip(apt)
        write_rpm_metadata_zip(rpm)
        write_sha256_sidecar(apt)
        write_sha256_sidecar(rpm)
        apt_bundles, rpm_bundles = signer.repository_metadata_assets(valid)
        if apt_bundles != (apt,) or rpm_bundles != (rpm,):
            raise AssertionError("repository signer did not select expected metadata bundles")

        directory_source = temp / "directory-source"
        directory_source.mkdir()
        (directory_source / APT_METADATA).mkdir()
        expect_action_failure(
            lambda: signer.repository_metadata_assets(directory_source),
            "must be a regular file",
            "repository signing directory source",
        )

        empty_source = temp / "empty-source"
        empty_source.mkdir()
        (empty_source / APT_METADATA).write_bytes(b"")
        expect_action_failure(
            lambda: signer.repository_metadata_assets(empty_source),
            "must not be empty",
            "repository signing empty source",
        )

        oversized_source = temp / "oversized-source"
        oversized_source.mkdir()
        oversized_metadata = oversized_source / APT_METADATA
        write_apt_metadata_zip(oversized_metadata)
        expect_constant_failure(
            signer,
            "MAX_REPOSITORY_METADATA_BUNDLE_BYTES",
            max(0, oversized_metadata.stat().st_size - 1),
            lambda: signer.repository_metadata_assets(oversized_source),
            "is too large",
            "repository signing source size bound",
        )

        aggregate_source = temp / "aggregate-source"
        aggregate_source.mkdir()
        aggregate_apt = aggregate_source / APT_METADATA
        aggregate_rpm = aggregate_source / RPM_METADATA
        write_apt_metadata_zip(aggregate_apt)
        write_rpm_metadata_zip(aggregate_rpm)
        expect_constant_failure(
            signer,
            "MAX_TOTAL_REPOSITORY_METADATA_BUNDLE_BYTES",
            aggregate_apt.stat().st_size,
            lambda: signer.repository_metadata_assets(aggregate_source),
            "repository metadata bundles exceed",
            "repository signing aggregate source size bound",
        )

        sidecar_directory = temp / "sidecar-directory"
        sidecar_directory.mkdir()
        sidecar_bundle = sidecar_directory / APT_METADATA
        write_apt_metadata_zip(sidecar_bundle)
        sidecar_bundle.with_name(f"{sidecar_bundle.name}.sha256").mkdir()
        expect_action_failure(
            lambda: signer.verify_sha256_sidecar(sidecar_bundle, "APT repository metadata bundle"),
            "must be a regular file",
            "repository signing sidecar directory",
        )

        sidecar_output_directory = temp / "sidecar-output-directory"
        sidecar_output_directory.mkdir()
        output_bundle = sidecar_output_directory / APT_METADATA
        write_apt_metadata_zip(output_bundle)
        output_bundle.with_name(f"{output_bundle.name}.sha256").mkdir()
        expect_action_failure(
            lambda: signer.write_sha256_sidecar(output_bundle),
            "must be a regular file",
            "repository signing sidecar output directory",
        )

        symlink_source = temp / "symlink-source"
        symlink_source.mkdir()
        real_source = symlink_source / "real.zip"
        linked_source = symlink_source / APT_METADATA
        write_apt_metadata_zip(real_source)
        if try_symlink(linked_source, real_source):
            expect_action_failure(
                lambda: signer.repository_metadata_assets(symlink_source),
                "must not be a symlink",
                "repository signing symlink source",
            )
            expect_action_failure(
                lambda: signer.sha256_file(linked_source),
                "must not be a symlink",
                "repository signing symlink hash source",
            )

        symlink_sidecar = temp / "symlink-sidecar"
        symlink_sidecar.mkdir()
        symlink_bundle = symlink_sidecar / APT_METADATA
        symlink_target = symlink_sidecar / "real.sha256"
        symlink_output = symlink_bundle.with_name(f"{symlink_bundle.name}.sha256")
        write_apt_metadata_zip(symlink_bundle)
        write_sha256_sidecar(symlink_bundle, sidecar=symlink_target)
        if try_symlink(symlink_output, symlink_target):
            expect_action_failure(
                lambda: signer.verify_sha256_sidecar(
                    symlink_bundle,
                    "APT repository metadata bundle",
                ),
                "must not be a symlink",
                "repository signing symlink sidecar",
            )
            expect_action_failure(
                lambda: signer.write_sha256_sidecar(symlink_bundle),
                "must not be a symlink",
                "repository signing symlink sidecar output",
            )

        symlink_output_bundle = temp / "symlink-output-bundle"
        symlink_output_bundle.mkdir()
        real_output_bundle = symlink_output_bundle / "real.zip"
        linked_output_bundle = symlink_output_bundle / APT_METADATA
        write_apt_metadata_zip(real_output_bundle)
        if try_symlink(linked_output_bundle, real_output_bundle):
            expect_action_failure(
                lambda: signer.write_zip_members(linked_output_bundle, {"Release": b"x\n"}),
                "must not be a symlink",
                "repository signing symlink bundle output",
            )


def load_signer():
    script_dir = ROOT / "scripts"
    sys.path.insert(0, str(script_dir))
    try:
        spec = importlib.util.spec_from_file_location(
            "sign_linux_repository_metadata",
            SIGNER,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load Linux repository metadata signer")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(str(script_dir))
        except ValueError:
            pass


def expect_zip_bound_failure(
    signer,
    archive: Path,
    constant_name: str,
    value: int,
    expected: str,
    label: str,
) -> None:
    original = getattr(signer, constant_name)
    setattr(signer, constant_name, value)
    try:
        message = expect_action_failure(
            lambda: signer.read_zip_members(archive),
            expected,
            label,
        )
        assert_member_failure_redacted(message, label)
    finally:
        setattr(signer, constant_name, original)


def expect_constant_failure(
    signer,
    constant_name: str,
    value: int,
    action,
    expected: str,
    label: str,
) -> None:
    original = getattr(signer, constant_name)
    setattr(signer, constant_name, value)
    try:
        expect_action_failure(action, expected, label)
    finally:
        setattr(signer, constant_name, original)


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


def try_symlink(link: Path, target: Path) -> bool:
    try:
        link.symlink_to(target)
        return True
    except (NotImplementedError, OSError):
        return False


def write_apt_metadata_zip(path: Path) -> None:
    packages = b"Package: conu\nVersion: 0.1.0\nArchitecture: amd64\n\n"
    packages_gz = deterministic_gzip(packages)
    release = (
        "Origin: conU\n"
        "Label: conU\n"
        "Suite: stable\n"
        "Codename: stable\n"
        "Version: 0.1.0\n"
        "Architectures: amd64 arm64\n"
        "Description: conU generated APT repository metadata\n"
        "Date: Wed, 01 Jan 2020 00:00:00 UTC\n"
        "SHA256:\n"
        f" {hashlib.sha256(packages).hexdigest()} {len(packages)} Packages\n"
        f" {hashlib.sha256(packages_gz).hexdigest()} {len(packages_gz)} Packages.gz\n"
    ).encode("ascii")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        write_zip_bytes(archive, "README.txt", b"APT repository metadata fixture.\n")
        write_zip_bytes(archive, "Packages", packages)
        write_zip_bytes(archive, "Packages.gz", packages_gz)
        write_zip_bytes(archive, "Release", release)


def write_rpm_metadata_zip(path: Path) -> None:
    primary = deterministic_gzip(b"<metadata packages=\"0\"></metadata>\n")
    repomd = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo">\n'
        '  <data type="primary">\n'
        "    <location href=\"repodata/primary.xml.gz\"/>\n"
        f"    <checksum type=\"sha256\">{hashlib.sha256(primary).hexdigest()}</checksum>\n"
        f"    <size>{len(primary)}</size>\n"
        "    <timestamp>1577836800</timestamp>\n"
        "  </data>\n"
        "</repomd>\n"
    ).encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        write_zip_bytes(archive, "README.txt", b"RPM repository metadata fixture.\n")
        write_zip_bytes(archive, "repodata/repomd.xml", repomd)
        write_zip_bytes(archive, "repodata/primary.xml.gz", primary)


def deterministic_gzip(data: bytes) -> bytes:
    import io

    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=1577836800) as gzip_file:
        gzip_file.write(data)
    return raw.getvalue()


def write_zip_bytes(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
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


def verify_apt_signatures(gpg: str, home: Path, bundle: Path, temp: Path) -> None:
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if "InRelease" not in names or "Release.gpg" not in names:
            raise AssertionError("APT metadata bundle is missing native signatures")
        for name in ("InRelease", "Release.gpg"):
            assert_zip_member_normalized(archive, name)
        release = temp / "Release"
        inrelease = temp / "InRelease"
        release_gpg = temp / "Release.gpg"
        release.write_bytes(archive.read("Release"))
        inrelease.write_bytes(archive.read("InRelease"))
        release_gpg.write_bytes(archive.read("Release.gpg"))
        if b"BEGIN PGP SIGNED MESSAGE" not in inrelease.read_bytes():
            raise AssertionError("InRelease was not clear-signed")
        if b"BEGIN PGP SIGNATURE" not in release_gpg.read_bytes():
            raise AssertionError("Release.gpg was not armored")
    run_gpg(gpg, home, ["--verify", str(inrelease)])
    run_gpg(gpg, home, ["--verify", str(release_gpg), str(release)])


def verify_rpm_signature(gpg: str, home: Path, bundle: Path, temp: Path) -> None:
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if "repodata/repomd.xml.asc" not in names:
            raise AssertionError("RPM metadata bundle is missing repomd.xml.asc")
        assert_zip_member_normalized(archive, "repodata/repomd.xml.asc")
        repomd = temp / "repomd.xml"
        signature = temp / "repomd.xml.asc"
        repomd.write_bytes(archive.read("repodata/repomd.xml"))
        signature.write_bytes(archive.read("repodata/repomd.xml.asc"))
        if b"BEGIN PGP SIGNATURE" not in signature.read_bytes():
            raise AssertionError("repomd.xml.asc was not armored")
    run_gpg(gpg, home, ["--verify", str(signature), str(repomd)])


def assert_zip_member_normalized(archive: zipfile.ZipFile, name: str) -> None:
    info = archive.getinfo(name)
    if info.date_time != (2020, 1, 1, 0, 0, 0):
        raise AssertionError(f"{name} was not timestamp-normalized")
    mode = (info.external_attr >> 16) & 0o777
    if mode != 0o644:
        raise AssertionError(f"{name} had mode {oct(mode)}")


def write_sha256_sidecar(path: Path, *, sidecar: Path | None = None) -> None:
    (sidecar or path.with_name(f"{path.name}.sha256")).write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{sha256_file(path)}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash the signed bundle")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes())
    return digest.hexdigest()


def create_test_key(gpg: str, home: Path) -> str:
    run_gpg(
        gpg,
        home,
        [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            PASSPHRASE,
            "--quick-gen-key",
            USER_ID,
            "rsa2048",
            "sign",
            "1d",
        ],
    )
    listing = run_gpg(gpg, home, ["--with-colons", "--list-secret-keys", USER_ID])
    for line in listing.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "fpr" and len(parts) > 9 and parts[9]:
            return parts[9]
    raise AssertionError("could not find generated test signing key fingerprint")


def export_secret_key(gpg: str, home: Path, key_id: str) -> bytes:
    return run_gpg_bytes(
        gpg,
        home,
        [
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            PASSPHRASE,
            "--armor",
            "--export-secret-keys",
            key_id,
        ],
    )


def export_public_key(gpg: str, home: Path, key_id: str) -> bytes:
    return run_gpg_bytes(gpg, home, ["--armor", "--export", key_id])


def import_public_key(gpg: str, home: Path, key_bytes: bytes) -> None:
    run_gpg_bytes(gpg, home, ["--import"], input_bytes=key_bytes)


def run_gpg(gpg: str, home: Path, args: list[str]) -> str:
    return run_gpg_bytes(gpg, home, args).decode("utf-8", errors="replace")


def run_gpg_bytes(
    gpg: str,
    home: Path,
    args: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    result = subprocess.run(
        [gpg, "--batch", "--yes", "--no-tty", *args],
        input=input_bytes,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    return result.stdout


if __name__ == "__main__":
    sys.exit(main())
