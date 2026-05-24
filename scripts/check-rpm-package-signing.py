#!/usr/bin/env python3
"""Regression checks for native RPM package payload signing."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate-package-manager-manifests.py"
SIGNER = ROOT / "scripts" / "sign-rpm-packages.py"
VERSION = "0.1.0"
PASSPHRASE = "conu-rpm-package-signing-regression-passphrase"
USER_ID = "conU RPM Package Signing Regression <noreply@github.com>"
TARGETS = {
    "macos-arm64": f"conu-{VERSION}-macos-arm64.zip",
    "macos-x64": f"conu-{VERSION}-macos-x64.zip",
    "linux-arm64": f"conu-{VERSION}-linux-arm64.tar.gz",
    "linux-x64": f"conu-{VERSION}-linux-x64.tar.gz",
    "windows-x64": f"conu-{VERSION}-windows-x64.zip",
}
WINDOWS_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
LINUX_BINARIES = ("conu", "conud", "conu-relay", "conu-mcp")
RPM_PACKAGES = (
    f"conu-{VERSION}-1.x86_64.rpm",
    f"conu-{VERSION}-1.aarch64.rpm",
)


def main() -> int:
    missing_tools = [
        name
        for name, available in (
            ("gpg", shutil.which("gpg")),
            ("rpmbuild", shutil.which("rpmbuild")),
            ("rpmsign or rpm", shutil.which("rpmsign") or shutil.which("rpm")),
            ("rpmkeys or rpm", shutil.which("rpmkeys") or shutil.which("rpm")),
        )
        if available is None
    ]
    if missing_tools:
        print(
            "RPM package signing regression skipped: "
            + ", ".join(missing_tools)
            + " unavailable"
        )
        return 0

    gpg = shutil.which("gpg")
    verifier = shutil.which("rpmkeys") or shutil.which("rpm")
    assert gpg is not None
    assert verifier is not None

    with tempfile.TemporaryDirectory(prefix="conu-rpm-package-signing-check-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        key_home = temp / "key-home"
        verify_home = temp / "verify-home"
        rpmdb = temp / "rpmdb"
        dist.mkdir()
        key_home.mkdir(mode=0o700)
        verify_home.mkdir(mode=0o700)
        rpmdb.mkdir(mode=0o700)
        write_dist(dist)

        subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                str(dist),
                "--output-dir",
                str(dist),
                "--version",
                VERSION,
                "--tag",
                f"v{VERSION}",
                "--build-rpm-packages",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        original_hashes = {name: sha256_file(dist / name) for name in RPM_PACKAGES}
        unrelated = dist / f"conu-{VERSION}-linux-x64.tar.gz"
        original_unrelated_digest = sha256_file(unrelated)

        key_id = create_test_key(gpg, key_home)
        private_key = export_secret_key(gpg, key_home, key_id)
        public_key = export_public_key(gpg, key_home, key_id)
        import_public_key(gpg, verify_home, public_key)
        rpm_public_key = temp / "public-key.asc"
        rpm_public_key.write_bytes(public_key)
        import_rpm_public_key(verifier, rpmdb, rpm_public_key)

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

        for name in RPM_PACKAGES:
            package = dist / name
            if sha256_file(package) == original_hashes[name]:
                raise AssertionError(f"{name} digest did not change after RPM package signing")
            assert_sha256_sidecar(package)
            verify_rpm_signature(verifier, rpmdb, package)
            if package.with_name(f"{package.name}.asc").exists():
                raise AssertionError(f"{package.name}.asc should not be created by RPM payload signing")

        if sha256_file(unrelated) != original_unrelated_digest:
            raise AssertionError("RPM package signer modified a non-RPM release asset")

        subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                str(dist),
                "--output-dir",
                str(dist),
                "--version",
                VERSION,
                "--tag",
                f"v{VERSION}",
                "--build-rpm-repository-metadata",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert_rpm_repository_metadata_uses_signed_packages(
            dist / f"conu-{VERSION}-rpm-repository-metadata.zip",
            dist,
        )

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
            raise AssertionError("RPM package signer did not fail closed with missing secrets")

    print("RPM package signing regression checks passed")
    return 0


def write_checksum(path: Path, archive_name: str | None = None) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(f"{path.name}.sha256").write_text(
        f"{digest}  {archive_name or path.name}\n",
        encoding="ascii",
        newline="\n",
    )
    return digest


def write_windows_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for binary in WINDOWS_BINARIES:
            package.writestr(f"bin/{binary}.exe", f"{binary}\n")
    write_checksum(path)


def write_linux_tar_gz(path: Path, target: str) -> None:
    with tarfile.open(path, "w:gz") as package:
        for binary in LINUX_BINARIES:
            data = f"{binary}-{target}\n".encode("ascii")
            info = tarfile.TarInfo(f"bin/{binary}")
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 1577836800
            package.addfile(info, io.BytesIO(data))
        for name, data in {
            "README.md": b"# conU\n\nRPM package fixture.\n",
            "docs/distribution-and-hosting.md": b"# Distribution\n\nRPM docs fixture.\n",
            "packaging/README.md": b"# Packaging\n\nRPM packaging fixture.\n",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 1577836800
            package.addfile(info, io.BytesIO(data))
    write_checksum(path)


def write_dist(root: Path) -> None:
    for target, filename in TARGETS.items():
        archive = root / filename
        if target == "windows-x64":
            write_windows_zip(archive)
        elif target.startswith("linux-"):
            write_linux_tar_gz(archive, target)
        else:
            archive.write_bytes(f"{target}\n".encode("ascii"))
            write_checksum(archive)


def import_rpm_public_key(verifier: str, rpmdb: Path, public_key: Path) -> None:
    subprocess.run(
        [verifier, "--define", f"_dbpath {rpmdb}", "--import", str(public_key)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def verify_rpm_signature(verifier: str, rpmdb: Path, package: Path) -> str:
    output = subprocess.run(
        [verifier, "--define", f"_dbpath {rpmdb}", "--checksig", "--verbose", str(package)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    lowered = output.lower()
    if "nokey" in lowered or "not ok" in lowered or "missing" in lowered:
        raise AssertionError(f"{package.name} RPM signature was not trusted:\n{output}")
    if not any(token in lowered for token in ("signature", "pgp", "rsa", "dsa", "openpgp")):
        raise AssertionError(f"{package.name} RPM verification did not report a signature:\n{output}")
    return output


def assert_rpm_repository_metadata_uses_signed_packages(metadata: Path, dist: Path) -> None:
    with zipfile.ZipFile(metadata) as archive:
        primary = gzip.decompress(archive.read("repodata/primary.xml.gz")).decode("utf-8")
    for name in RPM_PACKAGES:
        digest = sha256_file(dist / name)
        if digest not in primary:
            raise AssertionError(f"{metadata.name} did not use the signed digest for {name}")
    assert_sha256_sidecar(metadata)


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{sha256_file(path)}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash the signed RPM package")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
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
