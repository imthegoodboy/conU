#!/usr/bin/env python3
"""Regression checks for npm launcher local smoke binary preflight."""

from __future__ import annotations

import importlib.util
import stat
import tempfile
import zipfile
from pathlib import Path
from unittest import mock


def main() -> int:
    smoke = load_smoke_helpers()
    download_smoke = load_download_smoke_helpers()
    assert_safe_snippet_redacts(smoke)

    with fixture_dir() as root:
        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_action_failure(
                lambda: smoke.validate_input_directory(root / "dist", "release dist directory"),
                "must not be a symlink",
                "npm smoke symlink dist directory",
            )

    with fixture_dir() as root:
        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_action_failure(
                lambda: smoke.validate_package_directory(
                    root / "package",
                    "@conu/cli package directory",
                ),
                "must not be a symlink",
                "npm smoke symlink package directory",
            )

    with fixture_dir() as root:
        package_dir = root / "package"
        package_dir.mkdir()
        package_dir.joinpath("package.json").write_text("{}", encoding="utf-8")
        with mock.patch.object(
            Path,
            "is_symlink",
            lambda path: path.name == "package.json",
        ):
            expect_action_failure(
                lambda: smoke.validate_package_directory(
                    package_dir,
                    "@conu/cli package directory",
                ),
                "npm package manifest must not be a symlink",
                "npm smoke symlink package manifest",
            )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-linked.zip"
        with mock.patch.object(Path, "is_symlink", return_value=True):
            expect_action_failure(
                lambda: smoke.read_manifest_target(archive),
                "must not be a symlink",
                "npm smoke symlink archive",
            )

    with fixture_dir() as root:
        archive = root / "secret-npm-archive-name-should-not-print.zip"
        write_zip(archive, {"manifest.toml": 'target = "host"\n'})
        original_limit = smoke.MAX_ARCHIVE_BYTES
        smoke.MAX_ARCHIVE_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.read_manifest_target(archive),
                "release archive is too large",
                "oversized npm smoke archive",
                forbidden=archive.name,
            )
        finally:
            smoke.MAX_ARCHIVE_BYTES = original_limit

    with fixture_dir() as root:
        dist = root / "dist"
        dist.mkdir()
        dist.joinpath("conu-0.1.0-host.zip.sha256").write_text("checksum\n", encoding="utf-8")
        download_smoke.validate_served_dist_assets(dist)

    with fixture_dir() as root:
        dist = root / "dist"
        dist.mkdir()
        dist.joinpath("conu-0.1.0-host.zip.sha256").write_text("checksum\n", encoding="utf-8")
        with mock.patch.object(
            Path,
            "is_symlink",
            lambda path: path.name.endswith(".sha256"),
        ):
            expect_action_failure(
                lambda: download_smoke.validate_served_dist_assets(dist),
                "served asset must not be a symlink",
                "npm download smoke symlink served checksum",
            )

    with fixture_dir() as root:
        dist = root / "dist"
        dist.mkdir()
        nested = dist / "nested"
        nested.mkdir()
        nested.joinpath("asset.txt").write_text("asset\n", encoding="utf-8")
        with mock.patch.object(
            Path,
            "is_symlink",
            lambda path: path.name == "nested",
        ):
            expect_action_failure(
                lambda: download_smoke.validate_served_dist_assets(dist),
                "served asset must not be a symlink",
                "npm download smoke symlink served directory",
            )

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke)
        smoke.verify_archive_binaries(Path("fixture.zip"), bin_dir)

    with fixture_dir() as root:
        expect_failure(
            smoke,
            root / "missing-bin",
            "missing binary directory",
            "missing binary directory",
        )

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke, skip="conud")
        expect_failure(smoke, bin_dir, "missing executable(s): conud", "missing binary")

    with fixture_dir() as root:
        bin_dir = root / "bin"
        write_binaries(bin_dir, smoke, skip="conu-relay")
        bin_dir.joinpath(f"conu-relay{smoke.binary_suffix()}").mkdir()
        expect_failure(
            smoke,
            bin_dir,
            "not a regular file: conu-relay",
            "directory named as binary",
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-test.zip"
        write_zip(archive, {"conu-0.1.0-test/manifest.toml": 'target = "host"\n'})
        target = smoke.read_manifest_target(archive)
        if target != "host":
            raise SystemExit(f"rooted manifest target: expected host, got {target}")

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-duplicate-key.zip"
        secret_target = "secret-npm-target-should-not-print"
        write_zip(
            archive,
            {
                "manifest.toml": (
                    f'target = "host"\ntarget = "{secret_target}"\n'
                    "payload_contents_included = false\n"
                )
            },
        )
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "duplicate key target",
            "duplicate manifest target key",
            forbidden=secret_target,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-test.zip"
        write_zip(archive, {"conu-9.9.9-test/manifest.toml": 'target = "host"\n'})
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "unexpected archive root",
            "unexpected manifest root",
            forbidden="conu-9.9.9-test",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-mixed.zip"
        write_zip(
            archive,
            {
                "manifest.toml": 'target = "host"\n',
                "conu-0.1.0-mixed/bin/conu": "placeholder",
            },
        )
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "mixes rooted and rootless",
            "mixed manifest root style",
            forbidden="conu-0.1.0-mixed/bin/conu",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-duplicate.zip"
        write_zip_entries(
            archive,
            [
                ("manifest.toml", 'target = "host"\n'),
                ("bin/conu", "first"),
                ("bin/./conu", "second"),
            ],
        )
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "duplicate archive path",
            "duplicate path during manifest read",
            forbidden="bin/conu",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-too-large.zip"
        write_zip(archive, {"manifest.toml": 'target = "host"\n'})
        original_limit = smoke.MAX_MEMBER_BYTES
        smoke.MAX_MEMBER_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.read_manifest_target(archive),
                "member is too large",
                "oversized manifest read member",
                forbidden="manifest.toml",
                require_member_redaction=True,
            )
        finally:
            smoke.MAX_MEMBER_BYTES = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-too-many.zip"
        write_zip_entries(archive, [("manifest.toml", 'target = "host"\n'), ("bin/conu", "x")])
        original_limit = smoke.MAX_MEMBER_COUNT
        smoke.MAX_MEMBER_COUNT = 1
        try:
            expect_action_failure(
                lambda: smoke.read_manifest_target(archive),
                "contains more than",
                "manifest read member count bound",
                require_member_redaction=True,
            )
        finally:
            smoke.MAX_MEMBER_COUNT = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-total.zip"
        write_zip(archive, {"manifest.toml": 'target = "host"\n'})
        original_limit = smoke.MAX_TOTAL_UNCOMPRESSED_BYTES
        smoke.MAX_TOTAL_UNCOMPRESSED_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.read_manifest_target(archive),
                "uncompressed contents exceed",
                "manifest read total size bound",
                require_member_redaction=True,
            )
        finally:
            smoke.MAX_TOTAL_UNCOMPRESSED_BYTES = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-unsupported.zip"
        info = zipfile.ZipInfo("device")
        info.external_attr = (stat.S_IFCHR | 0o644) << 16
        write_zip_infos(
            archive,
            [
                (zipfile.ZipInfo("manifest.toml"), b'target = "host"\n'),
                (info, b"device"),
            ],
        )
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "unsupported zip member",
            "unsupported member during manifest read",
            forbidden="device",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-encrypted.zip"
        write_zip_entries(archive, [("manifest.toml", 'target = "host"\n'), ("bin/conu", "x")])
        mark_zip_member_encrypted(archive, "bin/conu")
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "encrypted zip member",
            "encrypted member during manifest read",
            forbidden="bin/conu",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-corrupt.zip"
        secret_member = "secret-npm-manifest-member-should-not-print.txt"
        write_zip_entries(archive, [(secret_member, "secret")])
        corrupt_zip_member_data(archive, secret_member)
        expect_action_failure(
            lambda: smoke.read_archive_member(archive, secret_member),
            "could not read zip member",
            "corrupt npm member during manifest read",
            forbidden=secret_member,
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-manifest-drive.zip"
        drive_member = "C:\\secret-manifest-path-should-not-print"
        write_zip_entries(archive, [(drive_member, "x")])
        expect_action_failure(
            lambda: smoke.read_manifest_target(archive),
            "unsafe archive path",
            "manifest read Windows drive path",
            forbidden="secret-manifest-path-should-not-print",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = Path("conu-0.1.0-test.zip")
        expected_root = root / "conu-0.1.0-test"
        expected_root.mkdir()
        expected_root.joinpath("manifest.toml").write_text('target = "host"\n', encoding="utf-8")
        resolved = smoke.find_package_root(archive, root)
        if resolved != expected_root:
            raise SystemExit(f"rooted package root: expected {expected_root}, got {resolved}")

    with fixture_dir() as root:
        wrong_root = root / "conu-9.9.9-test"
        wrong_root.mkdir()
        wrong_root.joinpath("manifest.toml").write_text('target = "host"\n', encoding="utf-8")
        expect_action_failure(
            lambda: smoke.find_package_root(Path("conu-0.1.0-test.zip"), root),
            "unexpected archive root",
            "unexpected extracted root",
            forbidden="conu-9.9.9-test",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-duplicate.zip"
        write_zip_entries(
            archive,
            [
                ("bin/conu", "first"),
                ("bin/./conu", "second"),
            ],
        )
        expect_action_failure(
            lambda: smoke.extract_archive(archive, root / "extract-duplicate"),
            "duplicate archive path",
            "duplicate extracted path",
            forbidden="bin/conu",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-too-large.zip"
        write_zip(archive, {"bin/conu": "too large"})
        original_limit = smoke.MAX_MEMBER_BYTES
        smoke.MAX_MEMBER_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.extract_archive(archive, root / "extract-large"),
                "member is too large",
                "oversized extracted member",
                forbidden="bin/conu",
                require_member_redaction=True,
            )
        finally:
            smoke.MAX_MEMBER_BYTES = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-too-many.zip"
        write_zip_entries(archive, [("one", "1"), ("two", "2")])
        original_limit = smoke.MAX_MEMBER_COUNT
        smoke.MAX_MEMBER_COUNT = 1
        try:
            expect_action_failure(
                lambda: smoke.extract_archive(archive, root / "extract-many"),
                "contains more than",
                "extracted entry count bound",
                require_member_redaction=True,
            )
        finally:
            smoke.MAX_MEMBER_COUNT = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-total.zip"
        write_zip_entries(archive, [("one", "1"), ("two", "2")])
        original_limit = smoke.MAX_TOTAL_UNCOMPRESSED_BYTES
        smoke.MAX_TOTAL_UNCOMPRESSED_BYTES = 1
        try:
            expect_action_failure(
                lambda: smoke.extract_archive(archive, root / "extract-total"),
                "uncompressed contents exceed",
                "extracted total size bound",
                require_member_redaction=True,
            )
        finally:
            smoke.MAX_TOTAL_UNCOMPRESSED_BYTES = original_limit

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-unsupported.zip"
        info = zipfile.ZipInfo("device")
        info.external_attr = (stat.S_IFCHR | 0o644) << 16
        write_zip_infos(archive, [(info, b"device")])
        expect_action_failure(
            lambda: smoke.extract_archive(archive, root / "extract-unsupported"),
            "unsupported zip member",
            "unsupported zip member type",
            forbidden="device",
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-corrupt-extract.zip"
        secret_member = "secret-npm-extract-member-should-not-print.txt"
        write_zip_entries(archive, [(secret_member, "secret")])
        corrupt_zip_member_data(archive, secret_member)
        expect_action_failure(
            lambda: smoke.extract_archive(archive, root / "extract-corrupt"),
            "could not read zip member",
            "corrupt npm member during extraction",
            forbidden=secret_member,
            require_member_redaction=True,
        )

    with fixture_dir() as root:
        archive = root / "conu-0.1.0-drive.zip"
        drive_member = "C:\\secret-extract-path-should-not-print"
        write_zip_entries(archive, [(drive_member, "x")])
        expect_action_failure(
            lambda: smoke.extract_archive(archive, root / "extract-drive"),
            "unsafe archive path",
            "extracted Windows drive path",
            forbidden="secret-extract-path-should-not-print",
            require_member_redaction=True,
        )

    print("npm launcher local smoke preflight check passed")
    return 0


def load_smoke_helpers():
    helper_path = Path(__file__).with_name("smoke-npm-launcher-local.py")
    spec = importlib.util.spec_from_file_location("conu_npm_launcher_local_smoke", helper_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load helper script {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_download_smoke_helpers():
    helper_path = Path(__file__).with_name("smoke-npm-launcher-download.py")
    spec = importlib.util.spec_from_file_location(
        "conu_npm_launcher_download_smoke",
        helper_path,
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load helper script {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class fixture_dir:
    def __enter__(self) -> Path:
        self.temp = tempfile.TemporaryDirectory(prefix="conu-npm-local-smoke-preflight-")
        return Path(self.temp.name)

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.temp.cleanup()


def write_binaries(bin_dir: Path, smoke, skip: str | None = None) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    suffix = smoke.binary_suffix()
    for name in smoke.REQUIRED_BINARIES:
        if name == skip:
            continue
        bin_dir.joinpath(f"{name}{suffix}").write_text(name, encoding="utf-8")


def write_zip(path: Path, members: dict[str, bytes | str]) -> None:
    write_zip_entries(path, list(members.items()))


def write_zip_entries(path: Path, entries: list[tuple[str, bytes | str]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in entries:
            if isinstance(content, str):
                content = content.encode("utf-8")
            package.writestr(name, content)


def write_zip_infos(path: Path, entries: list[tuple[zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for info, content in entries:
            package.writestr(info, content)


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
        data_start = name_end + extra_length
        compressed_size = int.from_bytes(data[offset + 18 : offset + 22], "little")
        data_end = data_start + compressed_size
        if data[name_start:name_end] == target:
            if compressed_size == 0:
                raise SystemExit(f"{member_name} had no compressed data to corrupt")
            data[data_end - 1] ^= 0xFF
            path.write_bytes(data)
            return
        offset = data_end
    raise SystemExit(f"zip member not found for corruption: {member_name}")


def assert_safe_snippet_redacts(smoke) -> None:
    sensitive_values = (
        "npm_fakeNpmSmokeOutputToken1234567890",
        "ghp_fakeNpmSmokeOutputToken1234567890",
        "fake-bearer-token-1234567890",
        "fake-basic-token-1234567890",
        "fake-node-auth-token-1234567890",
        "fake-url-password-1234567890",
        "fake-query-token-1234567890",
        "fake-private-key-1234567890",
    )
    raw = "\n".join(
        [
            f"npm ERR! auth token {sensitive_values[0]}",
            f"gh token {sensitive_values[1]}",
            f"Authorization: Bearer {sensitive_values[2]}",
            f"Authorization: Basic {sensitive_values[3]}",
            f"NODE_AUTH_TOKEN={sensitive_values[4]}",
            f"https://user:{sensitive_values[5]}@example.invalid/conu",
            f"https://example.invalid/conu?token={sensitive_values[6]}",
            f"PRIVATE_KEY={sensitive_values[7]}",
        ]
    )
    rendered = smoke.safe_snippet(raw)
    if "[redacted]" not in rendered:
        raise SystemExit("npm smoke safe snippet did not mark redacted output")
    for value in sensitive_values:
        if value in rendered:
            raise SystemExit("npm smoke safe snippet leaked sensitive command output")


def expect_failure(smoke, bin_dir: Path, expected: str, label: str) -> None:
    expect_action_failure(
        lambda: smoke.verify_archive_binaries(Path("fixture.zip"), bin_dir),
        expected,
        label,
    )


def expect_action_failure(
    action,
    expected: str,
    label: str,
    *,
    forbidden: str | None = None,
    require_member_redaction: bool = False,
) -> None:
    try:
        action()
    except SystemExit as exc:
        message = str(exc)
        if forbidden is not None and forbidden in message:
            raise SystemExit(f"{label}: error leaked forbidden value: {message}") from exc
        if require_member_redaction:
            for marker in ("pathDisplayed=false", "contentsDisplayed=false"):
                if marker not in message:
                    raise SystemExit(
                        f"{label}: error missing redaction marker {marker}: {message}"
                    ) from exc
        if expected in message:
            return
        raise SystemExit(f"{label}: expected {expected}, got: {message}") from exc
    raise SystemExit(f"{label}: expected smoke preflight failure")


if __name__ == "__main__":
    raise SystemExit(main())
