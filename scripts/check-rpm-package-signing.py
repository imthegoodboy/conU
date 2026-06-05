#!/usr/bin/env python3
"""Regression checks for native RPM package payload signing."""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate-package-manager-manifests.py"
SIGNER = ROOT / "scripts" / "sign-rpm-packages.py"
VERSION = "0.1.0"
PASSPHRASE = "conu-rpm-package-signing-regression-passphrase"
USER_ID = "conU RPM Package Signing Regression <noreply@github.com>"
WRONG_FINGERPRINT = "F" * 40
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
    run_source_file_preflights()

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
        env["CONU_LINUX_GPG_KEY_FINGERPRINT"] = key_id
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
            raise AssertionError("RPM package signer did not fail closed with missing secrets")

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
                "RPM package signer did not fail closed when the key fingerprint mismatched"
            )

    print("RPM package signing regression checks passed")
    return 0


def run_source_file_preflights() -> None:
    signer = load_signer()
    with tempfile.TemporaryDirectory(prefix="conu-rpm-package-signing-file-check-") as temp_text:
        temp = Path(temp_text)

        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_action_failure(
                lambda: signer.validate_input_directory(
                    temp / "dist",
                    "release dist directory",
                ),
                "must not be a symlink",
                "RPM signing symlink dist directory",
            )

        valid = temp / "valid"
        valid.mkdir()
        rpm_x64 = valid / RPM_PACKAGES[0]
        rpm_arm64 = valid / RPM_PACKAGES[1]
        rpm_x64.write_bytes(b"rpm x64 fixture\n")
        rpm_arm64.write_bytes(b"rpm arm64 fixture\n")
        write_checksum(rpm_x64)
        write_checksum(rpm_arm64)
        packages = signer.rpm_package_assets(valid)
        if packages != (rpm_arm64, rpm_x64):
            raise AssertionError("RPM signer did not select expected package assets")

        directory_source = temp / "directory-source"
        directory_source.mkdir()
        (directory_source / RPM_PACKAGES[0]).mkdir()
        expect_action_failure(
            lambda: signer.rpm_package_assets(directory_source),
            "must be a regular file",
            "RPM signing directory source",
        )

        empty_source = temp / "empty-source"
        empty_source.mkdir()
        (empty_source / RPM_PACKAGES[0]).write_bytes(b"")
        expect_action_failure(
            lambda: signer.rpm_package_assets(empty_source),
            "must not be empty",
            "RPM signing empty source",
        )

        oversized_source = temp / "oversized-source"
        oversized_source.mkdir()
        oversized_package = oversized_source / RPM_PACKAGES[0]
        oversized_package.write_bytes(b"rpm fixture\n")
        expect_constant_failure(
            signer,
            "MAX_RPM_PACKAGE_BYTES",
            max(0, oversized_package.stat().st_size - 1),
            lambda: signer.rpm_package_assets(oversized_source),
            "is too large",
            "RPM signing source size bound",
            oversized_package.name,
        )

        aggregate_source = temp / "aggregate-source"
        aggregate_source.mkdir()
        aggregate_x64 = aggregate_source / RPM_PACKAGES[0]
        aggregate_arm64 = aggregate_source / RPM_PACKAGES[1]
        aggregate_x64.write_bytes(b"rpm x64 fixture\n")
        aggregate_arm64.write_bytes(b"rpm arm64 fixture\n")
        expect_constant_failure(
            signer,
            "MAX_TOTAL_RPM_PACKAGE_BYTES",
            aggregate_arm64.stat().st_size,
            lambda: signer.rpm_package_assets(aggregate_source),
            "RPM package assets exceed",
            "RPM signing aggregate source size bound",
        )

        sidecar_directory = temp / "sidecar-directory"
        sidecar_directory.mkdir()
        sidecar_package = sidecar_directory / RPM_PACKAGES[0]
        sidecar_package.write_bytes(b"rpm fixture\n")
        sidecar_package.with_name(f"{sidecar_package.name}.sha256").mkdir()
        expect_action_failure(
            lambda: signer.verify_sha256_sidecar(sidecar_package, "generated RPM package"),
            "must be a regular file",
            "RPM signing sidecar directory",
        )
        oversized_sidecar = temp / "oversized-sidecar"
        oversized_sidecar.mkdir()
        oversized_sidecar_package = oversized_sidecar / RPM_PACKAGES[0]
        oversized_sidecar_package.write_bytes(b"rpm fixture\n")
        oversized_sidecar_path = oversized_sidecar_package.with_name(
            f"{oversized_sidecar_package.name}.sha256"
        )
        oversized_sidecar_path.write_text(
            "0" * 64 + f"  {oversized_sidecar_package.name}\n",
            encoding="ascii",
            newline="\n",
        )
        expect_constant_failure(
            signer,
            "MAX_CHECKSUM_BYTES",
            max(0, oversized_sidecar_path.stat().st_size - 1),
            lambda: signer.verify_sha256_sidecar(
                oversized_sidecar_package,
                "generated RPM package",
            ),
            "is too large",
            "RPM signing sidecar size bound",
            oversized_sidecar_path.name,
            oversized_sidecar_package.name,
        )

        sidecar_output_directory = temp / "sidecar-output-directory"
        sidecar_output_directory.mkdir()
        output_package = sidecar_output_directory / RPM_PACKAGES[0]
        output_package.write_bytes(b"rpm fixture\n")
        output_package.with_name(f"{output_package.name}.sha256").mkdir()
        expect_action_failure(
            lambda: signer.write_sha256_sidecar(output_package),
            "must be a regular file",
            "RPM signing sidecar output directory",
        )
        oversized_sidecar_output = temp / "oversized-sidecar-output"
        oversized_sidecar_output.mkdir()
        oversized_output_package = oversized_sidecar_output / RPM_PACKAGES[0]
        oversized_output_package.write_bytes(b"rpm fixture\n")
        oversized_output_sidecar = oversized_output_package.with_name(
            f"{oversized_output_package.name}.sha256"
        )
        oversized_output_sidecar.write_bytes(b"existing sidecar\n")
        expect_constant_failure(
            signer,
            "MAX_CHECKSUM_BYTES",
            max(0, oversized_output_sidecar.stat().st_size - 1),
            lambda: signer.write_sha256_sidecar(oversized_output_package),
            "is too large",
            "RPM signing sidecar output size bound",
            oversized_output_sidecar.name,
            oversized_output_package.name,
        )

        symlink_source = temp / "symlink-source"
        symlink_source.mkdir()
        real_source = symlink_source / "real.rpm"
        linked_source = symlink_source / RPM_PACKAGES[0]
        real_source.write_bytes(b"rpm fixture\n")
        if try_symlink(linked_source, real_source):
            expect_action_failure(
                lambda: signer.rpm_package_assets(symlink_source),
                "must not be a symlink",
                "RPM signing symlink source",
            )
            expect_action_failure(
                lambda: signer.sha256_file(linked_source),
                "must not be a symlink",
                "RPM signing symlink hash source",
            )

        symlink_sidecar = temp / "symlink-sidecar"
        symlink_sidecar.mkdir()
        symlink_package = symlink_sidecar / RPM_PACKAGES[0]
        symlink_target = symlink_sidecar / "real.sha256"
        symlink_output = symlink_package.with_name(f"{symlink_package.name}.sha256")
        symlink_package.write_bytes(b"rpm fixture\n")
        write_checksum(symlink_package, sidecar=symlink_target)
        if try_symlink(symlink_output, symlink_target):
            expect_action_failure(
                lambda: signer.verify_sha256_sidecar(
                    symlink_package,
                    "generated RPM package",
                ),
                "must not be a symlink",
                "RPM signing symlink sidecar",
            )
            expect_action_failure(
                lambda: signer.write_sha256_sidecar(symlink_package),
                "must not be a symlink",
                "RPM signing symlink sidecar output",
            )

        non_ascii_sidecar = temp / "non-ascii-sidecar"
        non_ascii_sidecar.mkdir()
        non_ascii_package = non_ascii_sidecar / RPM_PACKAGES[0]
        non_ascii_package.write_bytes(b"rpm fixture\n")
        non_ascii_package.with_name(f"{non_ascii_package.name}.sha256").write_bytes(b"\xff\n")
        expect_action_failure(
            lambda: signer.verify_sha256_sidecar(
                non_ascii_package,
                "generated RPM package",
            ),
            "SHA-256 sidecar is not ASCII",
            "RPM signing non-ASCII sidecar",
            non_ascii_package.name,
        )

        invalid_sidecar = temp / "invalid-sidecar"
        invalid_sidecar.mkdir()
        invalid_package = invalid_sidecar / RPM_PACKAGES[0]
        invalid_package.write_bytes(b"rpm fixture\n")
        invalid_package.with_name(f"{invalid_package.name}.sha256").write_text(
            "not a strict checksum\n",
            encoding="ascii",
            newline="\n",
        )
        expect_action_failure(
            lambda: signer.verify_sha256_sidecar(
                invalid_package,
                "generated RPM package",
            ),
            "invalid format",
            "RPM signing invalid sidecar",
            invalid_package.name,
        )

        wrong_target_sidecar = temp / "wrong-target-sidecar"
        wrong_target_sidecar.mkdir()
        wrong_target_package = wrong_target_sidecar / RPM_PACKAGES[0]
        wrong_target_package.write_bytes(b"rpm fixture\n")
        malicious_target = "secret-rpm-signing-sidecar-target.rpm"
        write_checksum(wrong_target_package, archive_name=malicious_target)
        expect_action_failure(
            lambda: signer.verify_sha256_sidecar(
                wrong_target_package,
                "generated RPM package",
            ),
            "names wrong file",
            "RPM signing wrong sidecar target",
            wrong_target_package.name,
            malicious_target,
        )

        mismatched_sidecar = temp / "mismatched-sidecar"
        mismatched_sidecar.mkdir()
        mismatched_package = mismatched_sidecar / RPM_PACKAGES[0]
        mismatched_package.write_bytes(b"rpm fixture\n")
        mismatched_package.with_name(f"{mismatched_package.name}.sha256").write_text(
            f"{'0' * 64}  {mismatched_package.name}\n",
            encoding="ascii",
            newline="\n",
        )
        expect_action_failure(
            lambda: signer.verify_sha256_sidecar(
                mismatched_package,
                "generated RPM package",
            ),
            "SHA-256 mismatch",
            "RPM signing mismatched sidecar",
            mismatched_package.name,
        )


def load_signer():
    script_dir = ROOT / "scripts"
    sys.path.insert(0, str(script_dir))
    try:
        spec = importlib.util.spec_from_file_location("sign_rpm_packages", SIGNER)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load RPM package signer")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(str(script_dir))
        except ValueError:
            pass


def expect_constant_failure(
    signer,
    constant_name: str,
    value: int,
    action,
    expected: str,
    label: str,
    *forbidden_values: str,
) -> None:
    original = getattr(signer, constant_name)
    setattr(signer, constant_name, value)
    try:
        expect_action_failure(action, expected, label, *forbidden_values)
    finally:
        setattr(signer, constant_name, original)


def expect_action_failure(
    action,
    expected: str,
    label: str,
    *forbidden_values: str,
) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if expected not in message:
            raise AssertionError(f"{label}: expected {expected!r}, got {message!r}") from exc
        for value in forbidden_values:
            if value in message:
                raise AssertionError(
                    f"{label}: leaked forbidden value {value!r}: {message!r}"
                ) from exc
        return
    raise AssertionError(f"{label}: expected failure containing {expected!r}")


def try_symlink(link: Path, target: Path) -> bool:
    try:
        link.symlink_to(target)
        return True
    except (NotImplementedError, OSError):
        return False


def write_checksum(
    path: Path,
    archive_name: str | None = None,
    *,
    sidecar: Path | None = None,
) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (sidecar or path.with_name(f"{path.name}.sha256")).write_text(
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
