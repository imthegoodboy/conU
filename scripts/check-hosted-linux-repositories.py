#!/usr/bin/env python3
"""Regression checks for hosted Linux repository bundle generation."""

from __future__ import annotations

import gzip
import hashlib
import io
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate-hosted-linux-repositories.py"
VERSION = "0.1.0"
APT_METADATA = f"conu-{VERSION}-apt-repository-metadata.zip"
RPM_METADATA = f"conu-{VERSION}-rpm-repository-metadata.zip"
HOSTED_BUNDLE = f"conu-{VERSION}-hosted-linux-repositories.zip"
PUBLIC_KEY = "conu-linux-gpg-key.asc"
DEBIAN_PACKAGES = (
    f"conu_{VERSION}_amd64.deb",
    f"conu_{VERSION}_arm64.deb",
)
RPM_PACKAGES = (
    f"conu-{VERSION}-1.x86_64.rpm",
    f"conu-{VERSION}-1.aarch64.rpm",
)
ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
SENSITIVE_SENTINEL = "do-not-print-this-shadow-value"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="conu-hosted-linux-repository-") as temp_text:
        temp = Path(temp_text)
        dist = temp / "dist"
        output = temp / "output"
        repeat = temp / "repeat"
        dist.mkdir()
        output.mkdir()
        repeat.mkdir()
        write_signed_dist(dist)

        run_generator(dist, output)
        bundle = output / HOSTED_BUNDLE
        assert_sha256_sidecar(bundle)
        assert_hosted_bundle(bundle, dist)

        run_generator(dist, repeat)
        if bundle.read_bytes() != (repeat / HOSTED_BUNDLE).read_bytes():
            raise AssertionError("hosted Linux repository bundle was not deterministic")

        generator = load_generator()
        oversized_input = temp / "secret-hosted-repository-input-name-should-not-print.txt"
        oversized_input.write_bytes(b"oversized\n")
        message = expect_action_failure(
            lambda: generator.open_regular_file(
                oversized_input,
                "hosted repository input asset",
                max_bytes=1,
            ),
            "hosted repository input asset is too large",
            "oversized hosted repository input",
        )
        assert_not_displayed(
            message,
            "oversized hosted repository input",
            oversized_input.name,
        )

        original_open_regular_file = generator.open_regular_file
        try:
            generator.open_regular_file = lambda _path, _label, *, max_bytes: (
                io.BytesIO(b"xx"),
                2,
            )
            message = expect_action_failure(
                lambda: generator.read_regular_file(
                    Path("secret-hosted-repository-read-name-should-not-print.txt"),
                    "hosted repository read asset",
                    max_bytes=1,
                ),
                "hosted repository read asset is too large",
                "oversized hosted repository read",
            )
            assert_not_displayed(
                message,
                "oversized hosted repository read",
                "secret-hosted-repository-read-name-should-not-print.txt",
            )
        finally:
            generator.open_regular_file = original_open_regular_file

        oversized_output = temp / "secret-hosted-repository-output-name-should-not-print.txt"
        message = expect_action_failure(
            lambda: generator.write_text_output(
                oversized_output,
                "hosted repository output",
                "oversized",
                max_bytes=1,
            ),
            "hosted repository output is too large",
            "oversized hosted repository output",
        )
        assert_not_displayed(
            message,
            "oversized hosted repository output",
            oversized_output.name,
        )

        message = expect_action_failure(
            lambda: generator.parse_package_version(
                Path("package.json"),
                (
                    '{"version":"0.1.0",'
                    f'"version":"{SENSITIVE_SENTINEL}"}}\n'
                ).encode("utf-8"),
                "hosted Linux repositories regression",
            ),
            "not valid UTF-8 JSON",
            "duplicate package metadata JSON",
        )
        assert_no_sentinel(message, "duplicate package metadata JSON output")

        non_ascii_checksum = temp / "non-ascii-checksum"
        shutil.copytree(dist, non_ascii_checksum)
        (non_ascii_checksum / f"{DEBIAN_PACKAGES[0]}.sha256").write_bytes(b"\xff\n")
        output = expect_failure(
            "non-ASCII package checksum",
            non_ascii_checksum,
            "SHA-256 sidecar is not ASCII",
        )
        assert_not_displayed(output, "non-ASCII package checksum", DEBIAN_PACKAGES[0])

        invalid_checksum = temp / "invalid-checksum"
        shutil.copytree(dist, invalid_checksum)
        (invalid_checksum / f"{DEBIAN_PACKAGES[0]}.sha256").write_text(
            "not a strict checksum\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "invalid package checksum",
            invalid_checksum,
            "invalid format",
        )
        assert_not_displayed(output, "invalid package checksum", DEBIAN_PACKAGES[0])

        wrong_checksum_target = temp / "wrong-checksum-target"
        shutil.copytree(dist, wrong_checksum_target)
        malicious_target = "secret-hosted-bundle-sidecar-target.deb"
        package_asset = dist / DEBIAN_PACKAGES[0]
        (wrong_checksum_target / f"{DEBIAN_PACKAGES[0]}.sha256").write_text(
            f"{hashlib.sha256(package_asset.read_bytes()).hexdigest()}  {malicious_target}\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "wrong package checksum target",
            wrong_checksum_target,
            "names wrong file",
        )
        assert_not_displayed(
            output,
            "wrong package checksum target",
            DEBIAN_PACKAGES[0],
            malicious_target,
        )

        mismatched_checksum = temp / "mismatched-checksum"
        shutil.copytree(dist, mismatched_checksum)
        (mismatched_checksum / f"{DEBIAN_PACKAGES[0]}.sha256").write_text(
            f"{'0' * 64}  {DEBIAN_PACKAGES[0]}\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "mismatched package checksum",
            mismatched_checksum,
            "SHA-256 mismatch",
        )
        assert_not_displayed(output, "mismatched package checksum", DEBIAN_PACKAGES[0])

        missing_signature = temp / "missing-signature"
        shutil.copytree(dist, missing_signature)
        (missing_signature / f"{DEBIAN_PACKAGES[0]}.asc").unlink()
        expect_failure(
            "missing package signature",
            missing_signature,
            "missing detached signature",
        )

        non_ascii_signature = temp / "non-ascii-signature"
        shutil.copytree(dist, non_ascii_signature)
        (non_ascii_signature / f"{DEBIAN_PACKAGES[0]}.asc").write_bytes(b"\xff\n")
        output = expect_failure(
            "non-ASCII package signature",
            non_ascii_signature,
            "detached signature is not ASCII-armored",
        )
        assert_not_displayed(
            output,
            "non-ASCII package signature",
            f"{DEBIAN_PACKAGES[0]}.asc",
        )

        non_armored_signature = temp / "non-armored-signature"
        shutil.copytree(dist, non_armored_signature)
        (non_armored_signature / f"{DEBIAN_PACKAGES[0]}.asc").write_text(
            "not a signature\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "non-armored package signature",
            non_armored_signature,
            "detached signature is not ASCII-armored",
        )
        assert_not_displayed(
            output,
            "non-armored package signature",
            f"{DEBIAN_PACKAGES[0]}.asc",
        )

        private_key_signature = temp / "private-key-signature"
        shutil.copytree(dist, private_key_signature)
        (private_key_signature / f"{DEBIAN_PACKAGES[0]}.asc").write_text(
            "-----BEGIN PGP SIGNATURE-----\nfixture\n"
            "-----END PGP SIGNATURE-----\n"
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n",
            encoding="ascii",
            newline="\n",
        )
        output = expect_failure(
            "private key signature sidecar",
            private_key_signature,
            "private key material",
        )
        assert_not_displayed(
            output,
            "private key signature sidecar",
            f"{DEBIAN_PACKAGES[0]}.asc",
        )

        symlink_dist = temp / "symlink-dist"
        if try_symlink(dist, symlink_dist, target_is_directory=True):
            expect_failure_at_output(
                "symlinked dist directory",
                symlink_dist,
                temp / "symlink-dist-output",
                "release dist directory must not be a symlink",
            )

        symlink_asset = temp / "symlink-asset"
        shutil.copytree(dist, symlink_asset)
        asset_target = temp / "debian-package-target.deb"
        shutil.copy2(symlink_asset / DEBIAN_PACKAGES[0], asset_target)
        (symlink_asset / DEBIAN_PACKAGES[0]).unlink()
        if try_symlink(asset_target, symlink_asset / DEBIAN_PACKAGES[0]):
            expect_failure(
                "symlinked package asset",
                symlink_asset,
                "signed Debian package must not be a symlink",
            )

        symlink_checksum = temp / "symlink-checksum"
        shutil.copytree(dist, symlink_checksum)
        checksum_target = temp / "debian-package-target.deb.sha256"
        shutil.copy2(symlink_checksum / f"{DEBIAN_PACKAGES[0]}.sha256", checksum_target)
        (symlink_checksum / f"{DEBIAN_PACKAGES[0]}.sha256").unlink()
        if try_symlink(checksum_target, symlink_checksum / f"{DEBIAN_PACKAGES[0]}.sha256"):
            expect_failure(
                "symlinked package checksum",
                symlink_checksum,
                "SHA-256 sidecar for signed Debian package must not be a symlink",
            )

        symlink_signature = temp / "symlink-signature"
        shutil.copytree(dist, symlink_signature)
        signature_target = temp / "debian-package-target.deb.asc"
        shutil.copy2(symlink_signature / f"{DEBIAN_PACKAGES[0]}.asc", signature_target)
        (symlink_signature / f"{DEBIAN_PACKAGES[0]}.asc").unlink()
        if try_symlink(signature_target, symlink_signature / f"{DEBIAN_PACKAGES[0]}.asc"):
            expect_failure(
                "symlinked package signature",
                symlink_signature,
                "detached signature for hosted repository asset must not be a symlink",
            )

        symlink_output_target = temp / "output-target"
        symlink_output_target.mkdir()
        symlink_output = temp / "symlink-output"
        if try_symlink(symlink_output_target, symlink_output, target_is_directory=True):
            expect_failure_at_output(
                "symlinked output directory",
                dist,
                symlink_output,
                "hosted repository output directory must not be a symlink",
            )

        symlink_output_file = temp / "symlink-output-file"
        symlink_output_file.mkdir()
        output_file_target = temp / "hosted-bundle-target.zip"
        output_file_target.write_bytes(b"existing\n")
        if try_symlink(output_file_target, symlink_output_file / HOSTED_BUNDLE):
            expect_failure_at_output(
                "symlinked output bundle",
                dist,
                symlink_output_file,
                "hosted Linux repository bundle output must not be a symlink",
            )

        symlink_output_sidecar = temp / "symlink-output-sidecar"
        symlink_output_sidecar.mkdir()
        output_sidecar_target = temp / "hosted-bundle-target.zip.sha256"
        output_sidecar_target.write_text("", encoding="ascii")
        if try_symlink(output_sidecar_target, symlink_output_sidecar / f"{HOSTED_BUNDLE}.sha256"):
            expect_failure_at_output(
                "symlinked output checksum",
                dist,
                symlink_output_sidecar,
                "hosted Linux repository bundle SHA-256 sidecar output must not be a symlink",
            )

        missing_native_apt_signature = temp / "missing-native-apt-signature"
        shutil.copytree(dist, missing_native_apt_signature)
        write_apt_metadata_zip(
            missing_native_apt_signature / APT_METADATA,
            include_native_signatures=False,
        )
        write_checksum(missing_native_apt_signature / APT_METADATA)
        expect_failure(
            "missing native APT signature",
            missing_native_apt_signature,
            "missing signed APT member",
        )

        non_ascii_public_key = temp / "non-ascii-public-key"
        shutil.copytree(dist, non_ascii_public_key)
        (non_ascii_public_key / PUBLIC_KEY).write_bytes(b"\xff\n")
        write_checksum(non_ascii_public_key / PUBLIC_KEY)
        output = expect_failure(
            "non-ASCII public key asset",
            non_ascii_public_key,
            "Linux public key asset is not ASCII-armored",
        )
        assert_not_displayed(output, "non-ASCII public key asset", PUBLIC_KEY)

        non_armored_public_key = temp / "non-armored-public-key"
        shutil.copytree(dist, non_armored_public_key)
        (non_armored_public_key / PUBLIC_KEY).write_text(
            "not a public key\n",
            encoding="ascii",
            newline="\n",
        )
        write_checksum(non_armored_public_key / PUBLIC_KEY)
        output = expect_failure(
            "non-armored public key asset",
            non_armored_public_key,
            "not an armored public key",
        )
        assert_not_displayed(output, "non-armored public key asset", PUBLIC_KEY)

        private_key_asset = temp / "private-key-asset"
        shutil.copytree(dist, private_key_asset)
        (private_key_asset / PUBLIC_KEY).write_text(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n",
            encoding="ascii",
            newline="\n",
        )
        write_checksum(private_key_asset / PUBLIC_KEY)
        output = expect_failure(
            "private key asset",
            private_key_asset,
            "private key material",
        )
        assert_not_displayed(output, "private key asset", PUBLIC_KEY)

        unsafe_zip = temp / "unsafe-zip"
        shutil.copytree(dist, unsafe_zip)
        with zipfile.ZipFile(unsafe_zip / RPM_METADATA, "w", compression=zipfile.ZIP_STORED) as archive:
            write_zip_bytes(archive, "repodata/../repomd.xml", b"<repomd />\n")
        write_checksum(unsafe_zip / RPM_METADATA)
        output = expect_failure(
            "unsafe zip member",
            unsafe_zip,
            "unsafe repository metadata zip path",
        )
        assert_member_failure_redacted(
            output,
            "unsafe zip member",
            "repodata/../repomd.xml",
            "repomd.xml",
        )

        generator = load_generator()
        expect_zip_bound_failure(
            generator,
            dist / APT_METADATA,
            "MAX_ZIP_MEMBER_BYTES",
            1,
            "zip member is too large",
            "metadata zip member size bound",
        )
        expect_zip_bound_failure(
            generator,
            dist / APT_METADATA,
            "MAX_ZIP_MEMBERS",
            1,
            "contains more than",
            "metadata zip member count bound",
        )
        expect_zip_bound_failure(
            generator,
            dist / APT_METADATA,
            "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
            1,
            "uncompressed ZIP contents exceed",
            "metadata zip total size bound",
        )

        unreadable_zip = temp / "unreadable-zip"
        shutil.copytree(dist, unreadable_zip)
        unreadable_zip_payload = "secret-unreadable-repository-zip-should-not-print"
        (unreadable_zip / APT_METADATA).write_text(
            unreadable_zip_payload,
            encoding="ascii",
        )
        message = expect_action_failure(
            lambda: generator.read_zip_members(unreadable_zip / APT_METADATA),
            "not a readable zip archive",
            "unreadable repository metadata zip",
        )
        assert_member_failure_redacted(
            message,
            "unreadable repository metadata zip",
            unreadable_zip_payload,
        )

        encrypted_zip = temp / "encrypted-zip"
        shutil.copytree(dist, encrypted_zip)
        mark_zip_member_encrypted(encrypted_zip / APT_METADATA, "Packages")
        message = expect_action_failure(
            lambda: generator.read_zip_members(encrypted_zip / APT_METADATA),
            "encrypted zip member",
            "encrypted repository metadata member",
        )
        assert_member_failure_redacted(
            message,
            "encrypted repository metadata member",
            "Packages",
        )

        corrupt_zip = temp / "corrupt-zip"
        shutil.copytree(dist, corrupt_zip)
        corrupt_zip_member_data(corrupt_zip / APT_METADATA, "Packages")
        message = expect_action_failure(
            lambda: generator.read_zip_members(corrupt_zip / APT_METADATA),
            "could not read zip member",
            "corrupt repository metadata member",
        )
        assert_member_failure_redacted(
            message,
            "corrupt repository metadata member",
            "Packages",
        )

        unsupported_zip = temp / "unsupported-zip"
        shutil.copytree(dist, unsupported_zip)
        with zipfile.ZipFile(unsupported_zip / APT_METADATA, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("Packages", ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFCHR | 0o644) << 16
            archive.writestr(info, b"device\n")
        message = expect_action_failure(
            lambda: generator.read_zip_members(unsupported_zip / APT_METADATA),
            "unsupported zip member",
            "unsupported repository metadata member",
        )
        assert_member_failure_redacted(
            message,
            "unsupported repository metadata member",
            "Packages",
        )

    print("Hosted Linux repository regression checks passed")
    return 0


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_hosted_linux_repositories",
        GENERATOR,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hosted Linux repository generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def expect_failure(description: str, dist: Path, expected: str) -> str:
    return expect_failure_at_output(description, dist, dist / "out", expected)


def expect_failure_at_output(description: str, dist: Path, output: Path, expected: str) -> str:
    failed = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            str(dist),
            "--output-dir",
            str(output),
            "--version",
            VERSION,
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
    generator,
    archive: Path,
    constant_name: str,
    value: int,
    expected: str,
    label: str,
) -> None:
    original = getattr(generator, constant_name)
    setattr(generator, constant_name, value)
    try:
        message = expect_action_failure(
            lambda: generator.read_zip_members(archive),
            expected,
            label,
        )
        assert_member_failure_redacted(message, label)
    finally:
        setattr(generator, constant_name, original)


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


def write_signed_dist(dist: Path) -> None:
    for name in DEBIAN_PACKAGES:
        asset = dist / name
        asset.write_bytes(f"{name} package fixture\n".encode("ascii"))
        write_checksum(asset)
        write_signature(asset)
    for name in RPM_PACKAGES:
        asset = dist / name
        asset.write_bytes(f"{name} package fixture\n".encode("ascii"))
        write_checksum(asset)
        write_signature(asset)
    public_key = dist / PUBLIC_KEY
    public_key.write_text(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n",
        encoding="ascii",
        newline="\n",
    )
    write_checksum(public_key)
    write_apt_metadata_zip(dist / APT_METADATA, include_native_signatures=True)
    write_checksum(dist / APT_METADATA)
    write_rpm_metadata_zip(dist / RPM_METADATA)
    write_checksum(dist / RPM_METADATA)


def write_signature(path: Path) -> None:
    path.with_name(f"{path.name}.asc").write_text(
        "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
        encoding="ascii",
        newline="\n",
    )


def write_apt_metadata_zip(path: Path, *, include_native_signatures: bool) -> None:
    package_entries = []
    for name, architecture in zip(DEBIAN_PACKAGES, ("amd64", "arm64"), strict=True):
        package_bytes = path.with_name(name).read_bytes()
        package_entries.append(
            f"""Package: conu
Version: {VERSION}
Architecture: {architecture}
Filename: {name}
Size: {len(package_bytes)}
MD5sum: {md5_hex(package_bytes)}
SHA1: {sha1_hex(package_bytes)}
SHA256: {hashlib.sha256(package_bytes).hexdigest()}
Section: net
Priority: optional
Description: Agent-native encrypted communication layer

"""
        )
    packages = "".join(package_entries).encode("ascii")
    packages_gz = deterministic_gzip(packages)
    release = render_apt_release(
        {
            "Packages": packages,
            "Packages.gz": packages_gz,
        }
    ).encode("ascii")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        write_zip_bytes(archive, "README.txt", b"APT fixture.\n")
        write_zip_bytes(archive, "Packages", packages)
        write_zip_bytes(archive, "Packages.gz", packages_gz)
        write_zip_bytes(archive, "Release", release)
        if include_native_signatures:
            write_zip_bytes(
                archive,
                "InRelease",
                b"-----BEGIN PGP SIGNED MESSAGE-----\nfixture\n",
            )
            write_zip_bytes(
                archive,
                "Release.gpg",
                b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
            )


def render_apt_release(files: dict[str, bytes]) -> str:
    lines = [
        "Origin: conU",
        "Label: conU",
        "Suite: stable",
        "Codename: stable",
        f"Version: {VERSION}",
        "Architectures: amd64 arm64",
        "Date: Wed, 01 Jan 2020 00:00:00 UTC",
    ]
    for title, digest_fn in (
        ("MD5Sum", md5_hex),
        ("SHA1", sha1_hex),
        ("SHA256", lambda data: hashlib.sha256(data).hexdigest()),
    ):
        lines.append(f"{title}:")
        for name, content in files.items():
            lines.append(f" {digest_fn(content)} {len(content)} {name}")
    return "\n".join(lines) + "\n"


def write_rpm_metadata_zip(path: Path) -> None:
    primary_entries = []
    for name, arch in zip(RPM_PACKAGES, ("x86_64", "aarch64"), strict=True):
        package_bytes = path.with_name(name).read_bytes()
        primary_entries.append(
            f"""  <package type="rpm">
    <name>conu</name>
    <arch>{arch}</arch>
    <version epoch="0" ver="{VERSION}" rel="1"/>
    <checksum type="sha256" pkgid="YES">{hashlib.sha256(package_bytes).hexdigest()}</checksum>
    <size package="{len(package_bytes)}"/>
    <location href="{name}"/>
  </package>
"""
        )
    primary = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<metadata xmlns="http://linux.duke.edu/metadata/common" packages="{len(RPM_PACKAGES)}">\n'
        + "".join(primary_entries)
        + "</metadata>\n"
    ).encode("utf-8")
    primary_gz = deterministic_gzip(primary)
    filelists_gz = deterministic_gzip(
        b'<?xml version="1.0" encoding="UTF-8"?><filelists />\n'
    )
    other_gz = deterministic_gzip(b'<?xml version="1.0" encoding="UTF-8"?><otherdata />\n')
    repomd = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo">\n'
        '  <data type="primary">\n'
        '    <location href="repodata/primary.xml.gz"/>\n'
        f"    <checksum type=\"sha256\">{hashlib.sha256(primary_gz).hexdigest()}</checksum>\n"
        "  </data>\n"
        "</repomd>\n"
    ).encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        write_zip_bytes(archive, "README.txt", b"RPM fixture.\n")
        write_zip_bytes(archive, "repodata/filelists.xml.gz", filelists_gz)
        write_zip_bytes(archive, "repodata/other.xml.gz", other_gz)
        write_zip_bytes(archive, "repodata/primary.xml.gz", primary_gz)
        write_zip_bytes(archive, "repodata/repomd.xml", repomd)
        write_zip_bytes(
            archive,
            "repodata/repomd.xml.asc",
            b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
        )


def assert_hosted_bundle(bundle: Path, dist: Path) -> None:
    expected_members = sorted(
        [
            "README.txt",
            PUBLIC_KEY,
            f"{PUBLIC_KEY}.sha256",
            "apt/README.txt",
            f"apt/{PUBLIC_KEY}",
            f"apt/{PUBLIC_KEY}.sha256",
            "apt/InRelease",
            "apt/Packages",
            "apt/Packages.gz",
            "apt/Release",
            "apt/Release.gpg",
            "rpm/README.txt",
            f"rpm/{PUBLIC_KEY}",
            f"rpm/{PUBLIC_KEY}.sha256",
            "rpm/repodata/filelists.xml.gz",
            "rpm/repodata/other.xml.gz",
            "rpm/repodata/primary.xml.gz",
            "rpm/repodata/repomd.xml",
            "rpm/repodata/repomd.xml.asc",
            *[
                f"apt/{name}"
                for package in DEBIAN_PACKAGES
                for name in (package, f"{package}.sha256", f"{package}.asc")
            ],
            *[
                f"rpm/{name}"
                for package in RPM_PACKAGES
                for name in (package, f"{package}.sha256", f"{package}.asc")
            ],
        ]
    )
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if names != expected_members:
            raise AssertionError(f"{bundle.name} had members {names!r}")
        for name in names:
            info = archive.getinfo(name)
            if info.date_time != ZIP_TIMESTAMP:
                raise AssertionError(f"{bundle.name}:{name} was not timestamp-normalized")
            mode = (info.external_attr >> 16) & 0o777
            if mode != 0o644:
                raise AssertionError(f"{bundle.name}:{name} had mode {oct(mode)}")
        contents = {name: archive.read(name) for name in names}

    root_readme = contents["README.txt"].decode("ascii")
    if "does not contain signing secrets" not in root_readme:
        raise AssertionError("hosted bundle README missed payload/secret boundary")
    if contents[PUBLIC_KEY] != (dist / PUBLIC_KEY).read_bytes():
        raise AssertionError("hosted bundle root public key did not match release asset")
    if contents[f"apt/{PUBLIC_KEY}"] != contents[PUBLIC_KEY]:
        raise AssertionError("APT public key copy did not match root public key")
    if contents[f"rpm/{PUBLIC_KEY}"] != contents[PUBLIC_KEY]:
        raise AssertionError("RPM public key copy did not match root public key")

    packages = contents["apt/Packages"]
    if gzip.decompress(contents["apt/Packages.gz"]) != packages:
        raise AssertionError("hosted APT Packages.gz did not match Packages")
    packages_text = packages.decode("ascii")
    for name in DEBIAN_PACKAGES:
        if f"Filename: {name}\n" not in packages_text:
            raise AssertionError(f"hosted APT metadata missed {name}")
        for suffix in ("", ".sha256", ".asc"):
            if contents[f"apt/{name}{suffix}"] != (dist / f"{name}{suffix}").read_bytes():
                raise AssertionError(f"hosted APT {name}{suffix} did not match release asset")
    if b"BEGIN PGP SIGNED MESSAGE" not in contents["apt/InRelease"]:
        raise AssertionError("hosted APT InRelease was not bundled")
    if b"BEGIN PGP SIGNATURE" not in contents["apt/Release.gpg"]:
        raise AssertionError("hosted APT Release.gpg was not bundled")

    primary_text = gzip.decompress(contents["rpm/repodata/primary.xml.gz"]).decode("utf-8")
    for name in RPM_PACKAGES:
        if f'href="{name}"' not in primary_text:
            raise AssertionError(f"hosted RPM metadata missed {name}")
        for suffix in ("", ".sha256", ".asc"):
            if contents[f"rpm/{name}{suffix}"] != (dist / f"{name}{suffix}").read_bytes():
                raise AssertionError(f"hosted RPM {name}{suffix} did not match release asset")
    if b"BEGIN PGP SIGNATURE" not in contents["rpm/repodata/repomd.xml.asc"]:
        raise AssertionError("hosted RPM repomd.xml.asc was not bundled")


def assert_sha256_sidecar(path: Path) -> None:
    sidecar = path.with_name(f"{path.name}.sha256")
    expected = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
    if sidecar.read_text(encoding="ascii") != expected:
        raise AssertionError(f"{sidecar.name} did not name and hash {path.name}")


def write_checksum(path: Path) -> None:
    path.with_name(f"{path.name}.sha256").write_text(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


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


def deterministic_gzip(data: bytes) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=1577836800) as gzip_file:
        gzip_file.write(data)
    return raw.getvalue()


def md5_hex(data: bytes) -> str:
    try:
        digest = hashlib.md5(data, usedforsecurity=False)
    except TypeError:
        digest = hashlib.md5(data)
    return digest.hexdigest()


def sha1_hex(data: bytes) -> str:
    try:
        digest = hashlib.sha1(data, usedforsecurity=False)
    except TypeError:
        digest = hashlib.sha1(data)
    return digest.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
