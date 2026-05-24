#!/usr/bin/env python3
"""Regression checks for signed APT/RPM repository metadata bundles."""

from __future__ import annotations

import base64
import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts" / "sign-linux-repository-metadata.py"
PASSPHRASE = "conu-repository-signing-regression-passphrase"
USER_ID = "conU Repository Signing Regression <noreply@github.com>"
VERSION = "0.1.0"
APT_METADATA = f"conu-{VERSION}-apt-repository-metadata.zip"
RPM_METADATA = f"conu-{VERSION}-rpm-repository-metadata.zip"


def main() -> int:
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

    print("Linux repository signing regression checks passed")
    return 0


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


def write_sha256_sidecar(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
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
